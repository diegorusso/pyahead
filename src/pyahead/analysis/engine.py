"""End-to-end M1 static-analysis pipeline."""

import hashlib
import io
import os
import stat
import tokenize
from collections import defaultdict
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import libcst as cst
from libcst.metadata import (
    ClassScope,
    CodeRange,
    ExpressionContext,
    ExpressionContextProvider,
    FunctionScope,
    GlobalScope,
    MetadataWrapper,
    ParentNodeProvider,
    PositionProvider,
    QualifiedNameProvider,
    QualifiedNameSource,
    ScopeProvider,
)
from libcst.metadata.scope_provider import Scope

from pyahead import __version__
from pyahead.analysis.discovery import (
    MAX_SOURCE_BYTES,
    DiscoveredFile,
    DiscoveryIncompleteError,
    DiscoveryIssue,
    discover_python_files,
    project_module_paths,
)
from pyahead.analysis.matchers import MatcherIndex, build_matcher_index
from pyahead.analysis.matchers.base import IndexedMatcher
from pyahead.analysis.matchers.builtins import matches_builtin_pattern
from pyahead.analysis.matchers.calls import (
    BUILTIN_IMPORT_FUNCTION,
    IMPORT_MODULE_FUNCTION,
    call_arguments,
    call_shape_matches,
    literal_dynamic_module,
)
from pyahead.analysis.matchers.imports import (
    ImportedModule,
    competing_project_paths,
    imported_modules,
    module_matches,
)
from pyahead.analysis.matchers.qualified import (
    QualifiedResolution,
    classify_reference_context,
    qualified_project_candidates,
    resolve_qualified_name,
    resolve_qualified_name_sources,
    terminal_name,
)
from pyahead.model import (
    AnalysisInference,
    BuiltinPatternMatcher,
    CallShapeMatcher,
    ChangeEventKind,
    Diagnostic,
    DiagnosticCategory,
    Finding,
    Impact,
    LiteralDynamicImportMatcher,
    MatchConfidence,
    ModuleImportMatcher,
    Policy,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    Registry,
    Rule,
    ScanCounts,
    ScanReport,
    SourceLocation,
    SourcePosition,
    SourceRegion,
    StaticMatch,
)
from pyahead.registry import load_registry
from pyahead.versions import PythonMinor

MAX_PARSE_NESTING = 200
MAX_CST_DEPTH = 256


@dataclass(frozen=True)
class ScanRequest:
    """Explicit inputs to the public M1 scan API."""

    root: Path
    baseline_python: str
    horizon_python: str
    paths: tuple[Path, ...] = ()
    registry_source: Path | None = None


def _scope_name(scope: Scope | None) -> str:
    names: list[str] = []
    current = scope
    while current is not None and not isinstance(current, GlobalScope):
        if isinstance(current, (FunctionScope, ClassScope)) and current.name:
            names.append(current.name)
        parent = current.parent
        if parent is current:
            break
        current = parent
    return ".".join(reversed(names)) if names else "<module>"


def _location(
    path: DiscoveredFile,
    code_range: CodeRange,
) -> SourceLocation:
    return SourceLocation(
        path=path.relative_path,
        region=SourceRegion(
            start=SourcePosition(
                line=code_range.start.line,
                column=code_range.start.column + 1,
            ),
            end=SourcePosition(
                line=code_range.end.line,
                column=code_range.end.column + 1,
            ),
        ),
    )


class _MatcherVisitor(cst.CSTVisitor):
    """Run all indexed M2 matchers in one metadata-aware traversal."""

    METADATA_DEPENDENCIES = (
        ExpressionContextProvider,
        ParentNodeProvider,
        PositionProvider,
        QualifiedNameProvider,
        ScopeProvider,
    )

    def __init__(
        self,
        path: DiscoveredFile,
        matcher_index: MatcherIndex,
        project_modules: dict[str, tuple[PurePosixPath, ...]],
    ) -> None:
        """Configure one coordinated read-only traversal."""
        self._path = path
        self._index = matcher_index
        self._project_modules = project_modules
        self._inference_keys: set[tuple[int, int, str]] = set()
        self.matches: list[StaticMatch] = []
        self.inferences: list[AnalysisInference] = []

    def _record_match(
        self,
        binding: IndexedMatcher,
        node: cst.CSTNode,
        confidence: MatchConfidence,
        evidence: tuple[tuple[str, str | tuple[str, ...]], ...],
    ) -> None:
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        scope = self.get_metadata(ScopeProvider, node)
        self.matches.append(
            StaticMatch(
                rule_id=binding.rule.id,
                matcher_kind=binding.matcher.kind.value,
                location=location,
                enclosing_scope=_scope_name(scope),
                subject=binding.rule.subject,
                confidence=confidence,
                evidence=evidence,
            )
        )

    def _record_import_inference(
        self,
        node: cst.Import | cst.ImportFrom,
        imported: ImportedModule,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        self.inferences.append(
            AnalysisInference(
                code="PYA2001",
                kind="module-resolution",
                message=(
                    f"did not classify import of {imported.module!r} as standard "
                    "library because a competing project module exists"
                ),
                location=location,
                evidence=(
                    ("bound_names", imported.bound_names),
                    (
                        "candidate_paths",
                        tuple(path.as_posix() for path in candidates),
                    ),
                    ("imported_module", imported.module),
                    ("resolution", "competing-project-module"),
                    ("source_roots", (".", "src")),
                    ("syntax", imported.syntax),
                ),
            )
        )

    def _record_qualified_inference(
        self,
        node: cst.CSTNode,
        qualified_name: str,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        key = (
            location.region.start.line,
            location.region.start.column,
            qualified_name,
        )
        if key in self._inference_keys:
            return
        self._inference_keys.add(key)
        self.inferences.append(
            AnalysisInference(
                code="PYA2001",
                kind="module-resolution",
                message=(
                    f"did not classify reference to {qualified_name!r} because a "
                    "competing project module exists"
                ),
                location=location,
                evidence=(
                    (
                        "candidate_paths",
                        tuple(path.as_posix() for path in candidates),
                    ),
                    ("qualified_name", qualified_name),
                    ("resolution", "competing-project-module"),
                    ("source_roots", (".", "src")),
                ),
            )
        )

    def _record_dynamic_import_inference(
        self,
        node: cst.Call,
        module: str,
        dynamic_function: str,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        self.inferences.append(
            AnalysisInference(
                code="PYA2001",
                kind="module-resolution",
                message=(
                    f"did not classify dynamic import of {module!r} as standard "
                    "library because a competing project module exists"
                ),
                location=location,
                evidence=(
                    (
                        "candidate_paths",
                        tuple(path.as_posix() for path in candidates),
                    ),
                    ("dynamic_function", dynamic_function),
                    ("imported_module", module),
                    ("resolution", "competing-project-module"),
                    ("source_roots", (".", "src")),
                ),
            )
        )

    def _record_import(
        self,
        node: cst.Import | cst.ImportFrom,
        imported: ImportedModule,
    ) -> None:
        bindings = tuple(
            binding
            for binding in self._index.module_imports.get(
                imported.module.partition(".")[0], ()
            )
            if isinstance(binding.matcher, ModuleImportMatcher)
            and module_matches(binding.matcher.module, imported.module)
        )
        if not bindings:
            return
        project_candidates = competing_project_paths(
            imported.module, self._project_modules
        )
        if project_candidates:
            self._record_import_inference(node, imported, project_candidates)
            return
        for binding in bindings:
            self._record_match(
                binding,
                node,
                MatchConfidence.HIGH,
                (
                    ("bound_names", imported.bound_names),
                    ("imported_module", imported.module),
                    ("resolution", "no-competing-project-module"),
                    ("source_roots", (".", "src")),
                    ("syntax", imported.syntax),
                ),
            )

    def visit_Import(self, node: cst.Import) -> None:  # noqa: N802
        """Match direct and aliased module imports."""
        for imported in imported_modules(node):
            self._record_import(node, imported)

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:  # noqa: N802
        """Match absolute from-import statements."""
        for imported in imported_modules(node):
            self._record_import(node, imported)

    def _resolution(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
        *,
        source: QualifiedNameSource = QualifiedNameSource.IMPORT,
    ) -> QualifiedResolution:
        names = self.get_metadata(QualifiedNameProvider, node, set())
        return resolve_qualified_name(names, qualified_name, source=source)

    def _resolution_sources(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
        sources: frozenset[QualifiedNameSource],
    ) -> QualifiedResolution:
        names = self.get_metadata(QualifiedNameProvider, node, set())
        return resolve_qualified_name_sources(names, qualified_name, sources)

    def _indexed_bindings(
        self,
        node: cst.BaseExpression,
        index: Mapping[str, tuple[IndexedMatcher, ...]],
    ) -> tuple[IndexedMatcher, ...]:
        terminals = set()
        if (syntax_terminal := terminal_name(node)) is not None:
            terminals.add(syntax_terminal)
        terminals.update(
            name.name.rpartition(".")[2]
            for name in self.get_metadata(QualifiedNameProvider, node, set())
        )
        bindings = {
            (binding.rule.id, repr(binding.matcher)): binding
            for terminal in terminals
            for binding in index.get(terminal, ())
        }
        return tuple(bindings[key] for key in sorted(bindings))

    def _import_resolution(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
    ) -> QualifiedResolution:
        resolution = self._resolution(node, qualified_name)
        return self._project_safe_resolution(node, qualified_name, resolution)

    def _project_safe_resolution(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
        resolution: QualifiedResolution,
    ) -> QualifiedResolution:
        if resolution.confidence is None:
            return resolution
        candidates = qualified_project_candidates(qualified_name, self._project_modules)
        if candidates:
            self._record_qualified_inference(node, qualified_name, candidates)
            return QualifiedResolution(
                confidence=None,
                qualified_names=resolution.qualified_names,
                resolution="competing-project-module",
            )
        return resolution

    def _visit_reference(self, node: cst.BaseExpression) -> None:
        if (
            self.get_metadata(ExpressionContextProvider, node, None)
            is not ExpressionContext.LOAD
        ):
            return
        reference_context = classify_reference_context(
            node,
            lambda child: self.get_metadata(ParentNodeProvider, child, None),
        )
        for binding in self._indexed_bindings(node, self._index.qualified_references):
            matcher = binding.matcher
            if not isinstance(matcher, QualifiedReferenceMatcher):
                continue
            if matcher.contexts and reference_context not in matcher.contexts:
                continue
            resolution = self._import_resolution(node, matcher.qualified_name)
            if resolution.confidence is None:
                continue
            self._record_match(
                binding,
                node,
                resolution.confidence,
                (
                    ("qualified_names", resolution.qualified_names),
                    ("reference_context", reference_context.value),
                    ("resolution", resolution.resolution),
                ),
            )

    def visit_Name(self, node: cst.Name) -> None:  # noqa: N802
        """Match unqualified imported references."""
        self._visit_reference(node)

    def visit_Attribute(self, node: cst.Attribute) -> None:  # noqa: N802
        """Match attribute references derived from imports."""
        self._visit_reference(node)

    def _record_qualified_call(
        self,
        binding: IndexedMatcher,
        matcher: QualifiedCallMatcher | CallShapeMatcher,
        node: cst.Call,
    ) -> None:
        if isinstance(matcher, CallShapeMatcher) and not call_shape_matches(
            node, matcher
        ):
            return
        resolution = self._import_resolution(node.func, matcher.qualified_name)
        if resolution.confidence is None:
            return
        evidence: tuple[tuple[str, str | tuple[str, ...]], ...] = (
            ("qualified_names", resolution.qualified_names),
            ("resolution", resolution.resolution),
        )
        if isinstance(matcher, CallShapeMatcher):
            arguments = call_arguments(node)
            evidence = (
                ("keyword_names", tuple(sorted(arguments.keywords))),
                ("positional_count", str(len(arguments.positional))),
                *evidence,
            )
        self._record_match(
            binding,
            node.func,
            resolution.confidence,
            evidence,
        )

    @staticmethod
    def _combined_confidence(
        authored: MatchConfidence,
        resolution: MatchConfidence,
    ) -> MatchConfidence:
        if MatchConfidence.MEDIUM in {authored, resolution}:
            return MatchConfidence.MEDIUM
        return authored

    def _dynamic_import_function(
        self,
        node: cst.Call,
    ) -> tuple[str, QualifiedResolution] | None:
        import_resolution = self._resolution(node.func, IMPORT_MODULE_FUNCTION)
        if import_resolution.confidence is not None:
            return IMPORT_MODULE_FUNCTION, import_resolution
        builtin_resolution = self._resolution_sources(
            node.func,
            BUILTIN_IMPORT_FUNCTION,
            frozenset({QualifiedNameSource.BUILTIN, QualifiedNameSource.IMPORT}),
        )
        if builtin_resolution.confidence is not None:
            return BUILTIN_IMPORT_FUNCTION, builtin_resolution
        return None

    def _record_dynamic_import(self, node: cst.Call) -> None:
        resolved_function = self._dynamic_import_function(node)
        if resolved_function is None:
            return
        dynamic_function, resolution = resolved_function
        module = literal_dynamic_module(node, dynamic_function)
        if module is None:
            return
        bindings = tuple(
            binding
            for binding in self._index.literal_dynamic_imports.get(
                module.partition(".")[0], ()
            )
            if isinstance(binding.matcher, LiteralDynamicImportMatcher)
            and module_matches(binding.matcher.module, module)
        )
        if not bindings:
            return
        if dynamic_function == IMPORT_MODULE_FUNCTION:
            resolution = self._project_safe_resolution(
                node.func,
                dynamic_function,
                resolution,
            )
        if resolution.confidence is None:
            return
        project_candidates = competing_project_paths(module, self._project_modules)
        if project_candidates:
            self._record_dynamic_import_inference(
                node,
                module,
                dynamic_function,
                project_candidates,
            )
            return
        for binding in bindings:
            matcher = binding.matcher
            if not isinstance(matcher, LiteralDynamicImportMatcher):
                continue
            self._record_match(
                binding,
                node,
                self._combined_confidence(matcher.confidence, resolution.confidence),
                (
                    ("dynamic_function", dynamic_function),
                    ("imported_module", module),
                    ("qualified_names", resolution.qualified_names),
                    ("resolution", resolution.resolution),
                ),
            )

    def visit_Call(self, node: cst.Call) -> None:  # noqa: N802
        """Match qualified calls, call shapes, and literal dynamic imports."""
        for binding in self._indexed_bindings(node.func, self._index.qualified_calls):
            matcher = binding.matcher
            if isinstance(matcher, QualifiedCallMatcher):
                self._record_qualified_call(binding, matcher, node)
        for binding in self._indexed_bindings(node.func, self._index.call_shapes):
            matcher = binding.matcher
            if isinstance(matcher, CallShapeMatcher):
                self._record_qualified_call(binding, matcher, node)
        self._record_dynamic_import(node)

    def visit_UnaryOperation(self, node: cst.UnaryOperation) -> None:  # noqa: N802
        """Dispatch syntax matchers through fixed visitor hooks."""
        for pattern, bindings in self._index.builtin_patterns.items():
            if not matches_builtin_pattern(pattern, node):
                continue
            for binding in bindings:
                if isinstance(binding.matcher, BuiltinPatternMatcher):
                    self._record_match(
                        binding,
                        node,
                        MatchConfidence.HIGH,
                        (("pattern", pattern.value),),
                    )


def _nesting_diagnostic(
    relative_path: PurePosixPath,
    structure: str,
    limit: int,
) -> Diagnostic:
    """Create one stable incomplete diagnostic for bounded parser depth."""
    return Diagnostic(
        code="PYA1003",
        category=DiagnosticCategory.PARSE,
        message=(
            f"unable to parse source: {structure} nesting exceeds "
            f"the {limit}-level analysis limit"
        ),
        location=_initial_location(relative_path),
        incomplete=True,
    )


def _parse_nesting_diagnostic(
    source: str,
    relative_path: PurePosixPath,
) -> Diagnostic | None:
    """Reject pathological delimiter depth before entering LibCST's C stack."""
    depth = 0

    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.OP:
                continue
            if token.string in {"(", "[", "{"}:
                depth += 1
                if depth > MAX_PARSE_NESTING:
                    return _nesting_diagnostic(
                        relative_path,
                        "delimiter",
                        MAX_PARSE_NESTING,
                    )
            elif token.string in {")", "]", "}"} and depth:
                depth -= 1
    except tokenize.TokenError:
        if depth >= MAX_PARSE_NESTING:
            return _nesting_diagnostic(
                relative_path,
                "delimiter",
                MAX_PARSE_NESTING,
            )
        return None
    except IndentationError:
        # LibCST produces the user-facing syntax diagnostic for malformed tokens.
        return None
    return None


def _cst_nesting_diagnostic(
    module: cst.Module,
    relative_path: PurePosixPath,
) -> Diagnostic | None:
    """Bound every CST shape iteratively before recursive metadata traversal."""
    stack: list[tuple[cst.CSTNode, int]] = [(module, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_CST_DEPTH:
            return _nesting_diagnostic(
                relative_path,
                "concrete syntax tree",
                MAX_CST_DEPTH,
            )
        stack.extend((child, depth + 1) for child in node.children)
    return None


def _parse_module(
    source: str,
    relative_path: PurePosixPath,
) -> tuple[cst.Module | None, Diagnostic | None]:
    """Parse one module after enforcing both parser depth boundaries."""
    nesting_diagnostic = _parse_nesting_diagnostic(source, relative_path)
    if nesting_diagnostic is not None:
        return None, nesting_diagnostic

    try:
        module = cst.parse_module(source)
    except cst.ParserSyntaxError as error:
        position = SourcePosition(
            line=error.raw_line,
            column=error.raw_column + 1,
        )
        return None, Diagnostic(
            code="PYA1003",
            category=DiagnosticCategory.PARSE,
            message=f"unable to parse source: {error.message}",
            location=SourceLocation(
                path=relative_path,
                region=SourceRegion(start=position, end=position),
            ),
            incomplete=True,
        )
    except RecursionError:
        return None, _nesting_diagnostic(
            relative_path,
            "concrete syntax tree",
            MAX_CST_DEPTH,
        )
    except cst.CSTValidationError:
        return None, Diagnostic(
            code="PYA1003",
            category=DiagnosticCategory.PARSE,
            message="unable to parse source: invalid concrete syntax tree",
            location=_initial_location(relative_path),
            incomplete=True,
        )

    return module, _cst_nesting_diagnostic(module, relative_path)


def _parse_file(
    path: DiscoveredFile,
    matcher_index: MatcherIndex,
    project_modules: dict[str, tuple[PurePosixPath, ...]],
) -> tuple[
    tuple[StaticMatch, ...],
    tuple[AnalysisInference, ...],
    Diagnostic | None,
]:
    source, read_diagnostic = _read_source(path)
    if read_diagnostic is not None:
        return (), (), read_diagnostic
    if source is None:  # pragma: no cover - guarded by the diagnostic result.
        msg = "source text is absent without a read diagnostic"
        raise RuntimeError(msg)

    module, parse_diagnostic = _parse_module(source, path.relative_path)
    if parse_diagnostic is not None:
        return (), (), parse_diagnostic
    if module is None:  # pragma: no cover - guarded by the diagnostic result.
        msg = "parsed module is absent without a parse diagnostic"
        raise RuntimeError(msg)

    visitor = _MatcherVisitor(path, matcher_index, project_modules)
    try:
        MetadataWrapper(module).visit(visitor)
    except (RecursionError, cst.CSTValidationError, SyntaxError, ValueError) as error:
        if isinstance(error, RecursionError):
            diagnostic = _nesting_diagnostic(
                path.relative_path,
                "concrete syntax tree",
                MAX_CST_DEPTH,
            )
        else:
            diagnostic = Diagnostic(
                code="PYA1003",
                category=DiagnosticCategory.PARSE,
                message="unable to parse source: invalid literal expression",
                location=_initial_location(path.relative_path),
                incomplete=True,
            )
        return (
            (),
            (),
            diagnostic,
        )
    return tuple(visitor.matches), tuple(visitor.inferences), None


def _initial_location(relative_path: PurePosixPath) -> SourceLocation:
    position = SourcePosition(line=1, column=1)
    return SourceLocation(
        path=relative_path,
        region=SourceRegion(start=position, end=position),
    )


def _read_failure(
    path: DiscoveredFile,
    code: str,
    category: DiagnosticCategory,
    message: str,
) -> tuple[None, Diagnostic]:
    return None, Diagnostic(
        code=code,
        category=category,
        message=message,
        location=_initial_location(path.relative_path),
        incomplete=True,
    )


def _read_source(path: DiscoveredFile) -> tuple[str | None, Diagnostic | None]:
    """Open without following links and read at most the configured byte limit."""
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    file_descriptor = -1
    try:
        file_descriptor = os.open(path.absolute_path, flags)
        file_status = os.fstat(file_descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            return _read_failure(
                path,
                "PYA1004",
                DiagnosticCategory.DISCOVERY,
                "source entry is not a regular file",
            )
        if file_status.st_size > MAX_SOURCE_BYTES:
            return _read_failure(
                path,
                "PYA1005",
                DiagnosticCategory.DISCOVERY,
                f"source file exceeds the {MAX_SOURCE_BYTES}-byte analysis limit",
            )

        data = bytearray()
        while len(data) <= MAX_SOURCE_BYTES:
            remaining = MAX_SOURCE_BYTES + 1 - len(data)
            chunk = os.read(file_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_SOURCE_BYTES:
            return _read_failure(
                path,
                "PYA1005",
                DiagnosticCategory.DISCOVERY,
                f"source file exceeds the {MAX_SOURCE_BYTES}-byte analysis limit",
            )
    except OSError as error:
        return _read_failure(
            path,
            "PYA1002",
            DiagnosticCategory.ENCODING,
            f"unable to read Python source ({type(error).__name__})",
        )
    finally:
        if file_descriptor >= 0:
            with suppress(OSError):
                os.close(file_descriptor)

    try:
        source_bytes = io.BytesIO(bytes(data))
        encoding, _ = tokenize.detect_encoding(source_bytes.readline)
        source_bytes.seek(0)
        with io.TextIOWrapper(source_bytes, encoding=encoding) as source_file:
            return source_file.read(), None
    except (LookupError, SyntaxError, UnicodeError) as error:
        return _read_failure(
            path,
            "PYA1002",
            DiagnosticCategory.ENCODING,
            f"unable to read Python source ({type(error).__name__})",
        )


def _impact_for_policy(
    rule: Rule,
    policy: Policy,
) -> tuple[Impact, PythonMinor] | None:
    applicable = [
        event for event in rule.events if event.python <= policy.horizon_python
    ]
    if not applicable:
        return None
    latest = max(
        applicable,
        key=lambda event: (
            event.python,
            event.kind is ChangeEventKind.REMOVED,
        ),
    )
    impact = rule.impact_for(latest.kind)
    action_version = max(latest.python, policy.baseline_python)
    return impact, action_version


def _fingerprint(match: StaticMatch, occurrence_ordinal: int) -> str:
    material = "\0".join(
        (
            "pyahead-fingerprint-v1",
            match.rule_id,
            match.location.path.as_posix(),
            match.enclosing_scope,
            match.subject,
            str(occurrence_ordinal),
        )
    )
    return hashlib.sha256(material.encode()).hexdigest()


_MATCH_KIND_PRIORITY = {
    "module-import": 0,
    "qualified-reference": 1,
    "qualified-call": 2,
    "literal-dynamic-import": 2,
    "builtin-pattern": 2,
    "call-shape": 3,
}
_CONFIDENCE_PRIORITY = {
    MatchConfidence.LOW: 0,
    MatchConfidence.MEDIUM: 1,
    MatchConfidence.HIGH: 2,
}


def _deduplicate_matches(matches: list[StaticMatch]) -> tuple[StaticMatch, ...]:
    """Merge matchers that identify the same rule, region, and subject."""
    deduplicated: dict[tuple[str, SourceLocation, str], StaticMatch] = {}
    for match in sorted(
        matches,
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.region.start,
            item.rule_id,
            item.matcher_kind,
        ),
    ):
        key = (match.rule_id, match.location, match.subject)
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = match
            continue
        existing_strength = (
            _CONFIDENCE_PRIORITY[existing.confidence],
            _MATCH_KIND_PRIORITY[existing.matcher_kind],
        )
        incoming_strength = (
            _CONFIDENCE_PRIORITY[match.confidence],
            _MATCH_KIND_PRIORITY[match.matcher_kind],
        )
        primary, secondary = (
            (match, existing)
            if incoming_strength > existing_strength
            else (existing, match)
        )
        evidence = list(primary.evidence)
        evidence_keys = {name for name, _value in evidence}
        evidence.extend(
            (name, value)
            for name, value in secondary.evidence
            if name not in evidence_keys
        )
        deduplicated[key] = StaticMatch(
            rule_id=primary.rule_id,
            matcher_kind=primary.matcher_kind,
            location=primary.location,
            enclosing_scope=primary.enclosing_scope,
            subject=primary.subject,
            confidence=primary.confidence,
            evidence=tuple(evidence),
        )
    return tuple(deduplicated.values())


def _findings(
    matches: list[StaticMatch], registry: Registry, policy: Policy
) -> tuple[Finding, ...]:
    rules = {rule.id: rule for rule in registry.rules}
    ordinals: defaultdict[tuple[str, str, str, str], int] = defaultdict(int)
    findings: list[Finding] = []
    for match in sorted(
        _deduplicate_matches(matches),
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.region.start,
            item.rule_id,
        ),
    ):
        rule = rules[match.rule_id]
        policy_impact = _impact_for_policy(rule, policy)
        if policy_impact is None:
            continue
        impact, action_version = policy_impact
        ordinal_key = (
            match.location.path.as_posix(),
            match.rule_id,
            match.enclosing_scope,
            match.subject,
        )
        occurrence_ordinal = ordinals[ordinal_key]
        ordinals[ordinal_key] += 1
        findings.append(
            Finding(
                fingerprint=_fingerprint(match, occurrence_ordinal),
                rule_id=rule.id,
                title=rule.title,
                location=match.location,
                enclosing_scope=match.enclosing_scope,
                subject=match.subject,
                match_kind=match.matcher_kind,
                match_confidence=match.confidence,
                match_evidence=match.evidence,
                impact=impact,
                action_version=action_version,
                events=tuple(
                    event
                    for event in rule.events
                    if event.python <= policy.horizon_python
                ),
                remediation=rule.remediation,
                sources=rule.sources,
                registry_revision=registry.revision,
            )
        )
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.action_version,
                finding.impact,
                finding.rule_id,
                finding.location,
            ),
        )
    )


def _discovery_issue_diagnostic(issue: DiscoveryIssue) -> Diagnostic:
    return Diagnostic(
        code=issue.code,
        category=DiagnosticCategory.DISCOVERY,
        message=issue.message,
        location=_initial_location(issue.relative_path),
        incomplete=True,
    )


def scan(request: ScanRequest) -> ScanReport:
    """Scan Python source without importing, executing, or networking."""
    policy = Policy.parse(request.baseline_python, request.horizon_python)
    registry = load_registry(request.registry_source)
    try:
        root_discovery = discover_python_files(request.root, ())
        discovery = (
            root_discovery
            if not request.paths or request.paths == (Path(),)
            else discover_python_files(request.root, request.paths)
        )
    except DiscoveryIncompleteError as error:
        return ScanReport(
            schema_version=1,
            tool_version=__version__,
            registry_release=registry.release,
            registry_revision=registry.revision,
            policy=policy,
            root_label=".",
            counts=ScanCounts(
                files_discovered=0,
                files_analyzed=0,
                files_incomplete=1,
            ),
            findings=(),
            diagnostics=(
                Diagnostic(
                    code="PYA1001",
                    category=DiagnosticCategory.DISCOVERY,
                    message=str(error),
                    incomplete=True,
                ),
            ),
            inferences=(),
        )
    project_modules = project_module_paths(
        root_discovery.files,
        root_discovery.issues,
    )
    matcher_index = build_matcher_index(registry)

    matches: list[StaticMatch] = []
    inferences: list[AnalysisInference] = []
    diagnostics = [_discovery_issue_diagnostic(issue) for issue in discovery.issues]
    analyzed = 0
    for path in discovery.files:
        file_matches, file_inferences, diagnostic = _parse_file(
            path,
            matcher_index,
            project_modules,
        )
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            continue
        analyzed += 1
        matches.extend(file_matches)
        inferences.extend(file_inferences)

    findings = _findings(
        [match for match in matches if match.confidence is MatchConfidence.HIGH],
        registry,
        policy,
    )
    return ScanReport(
        schema_version=1,
        tool_version=__version__,
        registry_release=registry.release,
        registry_revision=registry.revision,
        policy=policy,
        root_label=".",
        counts=ScanCounts(
            files_discovered=discovery.files_discovered,
            files_analyzed=analyzed,
            files_incomplete=len(diagnostics),
        ),
        findings=findings,
        diagnostics=tuple(
            sorted(
                diagnostics,
                key=lambda diagnostic: (
                    diagnostic.location.path.as_posix()
                    if diagnostic.location is not None
                    else "",
                    diagnostic.code,
                ),
            )
        ),
        inferences=tuple(
            sorted(
                inferences,
                key=lambda inference: (
                    inference.location.path.as_posix(),
                    inference.location.region.start,
                    inference.code,
                    inference.kind,
                    inference.message,
                ),
            )
        ),
    )
