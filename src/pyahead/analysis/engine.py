"""End-to-end M1 static-analysis pipeline."""

import hashlib
import io
import os
import stat
import tokenize
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import libcst as cst
from libcst.helpers import get_full_name_for_node
from libcst.metadata import (
    ClassScope,
    CodeRange,
    FunctionScope,
    GlobalScope,
    MetadataWrapper,
    PositionProvider,
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
from pyahead.model import (
    AnalysisInference,
    ChangeEventKind,
    Diagnostic,
    DiagnosticCategory,
    Finding,
    Impact,
    MatchConfidence,
    Policy,
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


class _ImportVisitor(cst.CSTVisitor):
    """Collect exact imports for indexed module rules."""

    METADATA_DEPENDENCIES = (PositionProvider, ScopeProvider)

    def __init__(
        self,
        path: DiscoveredFile,
        rules_by_module: dict[str, tuple[Rule, ...]],
        project_modules: dict[str, tuple[PurePosixPath, ...]],
    ) -> None:
        """Configure one coordinated read-only traversal."""
        self._path = path
        self._rules_by_module = rules_by_module
        self._project_modules = project_modules
        self.matches: list[StaticMatch] = []
        self.inferences: list[AnalysisInference] = []

    def _record(
        self,
        node: cst.Import | cst.ImportFrom,
        module: str,
        syntax: str,
        bound_names: tuple[str, ...],
    ) -> None:
        rules = self._rules_by_module.get(module, ())
        if not rules:
            return
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        scope = self.get_metadata(ScopeProvider, node)
        project_candidates = self._project_modules.get(module, ())
        if project_candidates:
            self.inferences.append(
                AnalysisInference(
                    code="PYA2001",
                    kind="module-resolution",
                    message=(
                        f"did not classify import of {module!r} as standard library "
                        "because a competing project module exists"
                    ),
                    location=location,
                    evidence=(
                        ("bound_names", bound_names),
                        (
                            "candidate_paths",
                            tuple(path.as_posix() for path in project_candidates),
                        ),
                        ("imported_module", module),
                        ("resolution", "competing-project-module"),
                        ("source_roots", (".", "src")),
                        ("syntax", syntax),
                    ),
                )
            )
            return
        for rule in rules:
            self.matches.append(
                StaticMatch(
                    rule_id=rule.id,
                    matcher_kind="module-import",
                    location=location,
                    enclosing_scope=_scope_name(scope),
                    subject=rule.subject,
                    confidence=MatchConfidence.HIGH,
                    evidence=(
                        ("bound_names", bound_names),
                        ("imported_module", module),
                        ("resolution", "no-competing-project-module"),
                        ("source_roots", (".", "src")),
                        ("syntax", syntax),
                    ),
                )
            )

    def visit_Import(self, node: cst.Import) -> None:  # noqa: N802
        """Match direct and aliased module imports."""
        bindings: dict[str, list[str]] = {}
        for alias in node.names:
            module = get_full_name_for_node(alias.name)
            if module is None:
                continue
            bound_name = (
                get_full_name_for_node(alias.asname.name)
                if alias.asname is not None
                else module.split(".", maxsplit=1)[0]
            )
            module_bindings = bindings.setdefault(module, [])
            if (resolved_binding := bound_name or module) not in module_bindings:
                module_bindings.append(resolved_binding)
        for module, module_bindings in bindings.items():
            self._record(node, module, "import", tuple(module_bindings))

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:  # noqa: N802
        """Match absolute ``from MODULE import ...`` statements."""
        if node.relative:
            return
        module = get_full_name_for_node(node.module) if node.module else None
        if module is None:
            return
        bound_names: tuple[str, ...]
        if isinstance(node.names, cst.ImportStar):
            bound_names = ("*",)
        else:
            bound_names = tuple(
                name
                for alias in node.names
                if (
                    name := get_full_name_for_node(
                        alias.asname.name if alias.asname is not None else alias.name
                    )
                )
                is not None
            )
        self._record(node, module, "from-import", bound_names)


def _parse_file(
    path: DiscoveredFile,
    rules_by_module: dict[str, tuple[Rule, ...]],
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

    try:
        module = cst.parse_module(source)
    except cst.ParserSyntaxError as error:
        position = SourcePosition(
            line=error.raw_line,
            column=error.raw_column + 1,
        )
        diagnostic = Diagnostic(
            code="PYA1003",
            category=DiagnosticCategory.PARSE,
            message=f"unable to parse source: {error.message}",
            location=SourceLocation(
                path=path.relative_path,
                region=SourceRegion(start=position, end=position),
            ),
            incomplete=True,
        )
        return (), (), diagnostic

    visitor = _ImportVisitor(path, rules_by_module, project_modules)
    MetadataWrapper(module).visit(visitor)
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


def _rules_by_module(registry: Registry) -> dict[str, tuple[Rule, ...]]:
    indexed: defaultdict[str, list[Rule]] = defaultdict(list)
    for rule in registry.rules:
        for matcher in rule.matchers:
            if matcher.kind == "module-import":
                indexed[matcher.module].append(rule)
    return {
        module: tuple(sorted(rules, key=lambda rule: rule.id))
        for module, rules in indexed.items()
    }


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
    impact = (
        rule.on_deprecation
        if latest.kind is ChangeEventKind.DEPRECATED
        else rule.on_removal
    )
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


def _findings(
    matches: list[StaticMatch], registry: Registry, policy: Policy
) -> tuple[Finding, ...]:
    rules = {rule.id: rule for rule in registry.rules}
    ordinals: defaultdict[tuple[str, str, str, str], int] = defaultdict(int)
    findings: list[Finding] = []
    for match in sorted(
        matches,
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
    rules_by_module = _rules_by_module(registry)

    matches: list[StaticMatch] = []
    inferences: list[AnalysisInference] = []
    diagnostics = [_discovery_issue_diagnostic(issue) for issue in discovery.issues]
    analyzed = 0
    for path in discovery.files:
        file_matches, file_inferences, diagnostic = _parse_file(
            path,
            rules_by_module,
            project_modules,
        )
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            continue
        analyzed += 1
        matches.extend(file_matches)
        inferences.extend(file_inferences)

    findings = _findings(matches, registry, policy)
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
