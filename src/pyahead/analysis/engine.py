"""End-to-end static-analysis pipeline."""

import io
import tokenize
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass, fields
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
    PositionProvider,
    QualifiedName,
    QualifiedNameSource,
    ScopeProvider,
)
from libcst.metadata.scope_provider import Scope

from pyahead import __version__
from pyahead._fs.errors import UnsafeEntryError
from pyahead._fs.rooted import RootedReadTooLargeError, read_rooted_bytes
from pyahead.analysis.discovery import (
    DiscoveredFile,
    DiscoveryError,
    DiscoveryIncompleteError,
    DiscoveryIssue,
    DiscoveryOptions,
    DiscoveryResult,
    discover_python_files,
    dynamic_path_module_paths,
    project_module_paths,
)
from pyahead.analysis.findings import (
    FindingContext,
    ImportPathMutation,
    build_findings,
    dynamic_path_adjustments,
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
from pyahead.analysis.reachability import (
    SYS_VERSION_INFO,
    BranchReachability,
    LexicalReachability,
    ReachabilityTracker,
    branch_reachability,
    import_fallback_versions,
)
from pyahead.analysis.suppressions import (
    InlineSuppressionIndex,
    bind_inline_suppressions,
    collect_inline_suppressions,
    index_inline_suppressions,
    resolve_per_file_ignores,
)
from pyahead.baseline import load_baseline
from pyahead.config import (
    ConfigurationOverrides,
    ResolvedConfiguration,
    _load_project_configuration_snapshot,
    _resolve_snapshot_configuration,
)
from pyahead.model import (
    AnalysisInference,
    BuiltinPatternMatcher,
    CallShapeMatcher,
    ChangeEventKind,
    ConfigurationError,
    Diagnostic,
    DiagnosticCategory,
    Finding,
    LiteralDynamicImportMatcher,
    MatchConfidence,
    ModuleImportMatcher,
    PerFileIgnore,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    ReferenceContext,
    Registry,
    ScanCounts,
    ScanReport,
    SourceLocation,
    SourcePosition,
    SourceRegion,
    StaticMatch,
    UsageContext,
)
from pyahead.registry import load_registry
from pyahead.versions import PythonMinor

MAX_PARSE_NESTING = 200
MAX_CST_DEPTH = 256
HASATTR_ARGUMENT_COUNT = 2


@dataclass(frozen=True)
class FileProgress:
    """One file the scan has just parsed, reported through ``ScanRequest.on_file``.

    ``index`` counts from one over the ``total`` files discovery handed to the
    parser, in the order they are analysed. ``incomplete`` is true when the file
    could not be fully analysed and is counted in ``files_incomplete``.
    """

    path: PurePosixPath
    index: int
    total: int
    incomplete: bool


@dataclass(frozen=True)
class ScanRequest:
    """Explicit inputs to the public scan API."""

    root: Path
    baseline_python: str | None = None
    horizon_python: str | None = None
    paths: tuple[Path, ...] = ()
    registry_source: Path | None = None
    config_path: Path | None = None
    include: tuple[str, ...] | None = None
    exclude: tuple[str, ...] | None = None
    source_roots: tuple[str, ...] | None = None
    respect_gitignore: bool | None = None
    minimum_confidence: str | MatchConfidence | None = None
    fail_on: str | None = None
    show_unscheduled: bool | None = None
    max_file_size_bytes: int | None = None
    per_file_ignores: tuple[PerFileIgnore, ...] = ()
    baseline_file: Path | None = None
    fail_new_only: bool = False
    show_suppressed: bool = False
    allow_incomplete: bool = False
    # Called once per parsed file, in order, with a FileProgress; it receives no
    # findings, so a progress display cannot become a second analysis path. An
    # exception it raises propagates out of scan().
    on_file: Callable[[FileProgress], None] | None = None


@dataclass(frozen=True)
class _FileAnalysisContext:
    root: Path
    matcher_index: MatcherIndex
    project_modules: dict[str, tuple[PurePosixPath, ...]]
    target_versions: frozenset[PythonMinor]
    source_roots: tuple[str, ...]
    max_file_size_bytes: int
    registry: Registry


@dataclass(frozen=True)
class _FileAnalysis:
    """What one file contributed: matches only when it was fully analysed."""

    suppressions: InlineSuppressionIndex
    diagnostics: tuple[Diagnostic, ...] = ()
    matches: tuple[StaticMatch, ...] = ()
    inferences: tuple[AnalysisInference, ...] = ()
    path_mutations: tuple[ImportPathMutation, ...] = ()

    @property
    def incomplete(self) -> bool:
        """Whether any diagnostic left this file unanalysed."""
        return any(diagnostic.incomplete for diagnostic in self.diagnostics)


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
    """Run all indexed matchers in one metadata-aware traversal."""

    # PositionProvider is not declared: it generates the code for the whole
    # module, and most files never record anything that needs a location.
    # _position resolves it through the wrapper the first time one does.
    METADATA_DEPENDENCIES = (
        ExpressionContextProvider,
        ScopeProvider,
    )

    def __init__(  # noqa: PLR0913 - one traversal's complete context.
        self,
        path: DiscoveredFile,
        matcher_index: MatcherIndex,
        project_modules: dict[str, tuple[PurePosixPath, ...]],
        target_versions: frozenset[PythonMinor],
        source_roots: tuple[str, ...],
        *,
        wrapper: MetadataWrapper | None = None,
    ) -> None:
        """Configure one coordinated read-only traversal."""
        self._wrapper = wrapper
        self._positions: Mapping[cst.CSTNode, CodeRange] | None = None
        self._path = path
        self._index = matcher_index
        self._project_modules = project_modules
        self._source_roots = source_roots
        self._inference_keys: set[tuple[int, int, str]] = set()
        self._guard_inference_keys: set[SourceLocation] = set()
        initial_contexts = (
            frozenset({UsageContext.TYPING})
            if path.relative_path.suffix == ".pyi"
            else frozenset({UsageContext.RUNTIME, UsageContext.TYPING})
        )
        self._tracker = ReachabilityTracker(
            LexicalReachability(
                versions=target_versions,
                usage_contexts=initial_contexts,
            )
        )
        # The nodes enclosing the one being visited, outermost first, and each
        # one's position in that list: every parent the visitor asks for is
        # on it or is the current node, so LibCST's ParentNodeProvider (a
        # whole-module map) is not needed.
        self._ancestors: list[cst.CSTNode] = []
        self._ancestor_positions: dict[int, int] = {}
        self._parents: dict[int, cst.CSTNode] | None = None
        self.matches: list[StaticMatch] = []
        self.inferences: list[AnalysisInference] = []
        self.path_mutations: list[ImportPathMutation] = []

    def on_visit(self, node: cst.CSTNode) -> bool:
        """Track ``node`` as the innermost ancestor while it is visited."""
        self._ancestor_positions[id(node)] = len(self._ancestors)
        self._ancestors.append(node)
        return super().on_visit(node)

    def on_leave(self, original_node: cst.CSTNode) -> None:
        """Stop tracking ``original_node`` once its subtree is done."""
        super().on_leave(original_node)
        self._ancestors.pop()
        del self._ancestor_positions[id(original_node)]

    def _parent(self, node: cst.CSTNode) -> cst.CSTNode | None:
        """Return the node whose children include ``node``, as LibCST would."""
        position = self._ancestor_positions.get(id(node))
        if position is not None and self._ancestors[position] is node:
            return self._ancestors[position - 1] if position else None
        if self._ancestors and any(
            child is node for child in self._ancestors[-1].children
        ):
            return self._ancestors[-1]
        return self._full_parent_map().get(id(node))

    def _full_parent_map(self) -> dict[int, cst.CSTNode]:
        """Map every node to its parent, built once if a lookup ever needs it."""
        if self._parents is None:
            self._parents = {}
            pending = list(self._ancestors[:1])
            while pending:
                parent = pending.pop()
                for child in parent.children:
                    self._parents[id(child)] = parent
                    pending.append(child)
        return self._parents

    def _position(self, node: cst.CSTNode) -> CodeRange:
        """Return where ``node`` is, resolving positions on first use."""
        if self._positions is None:
            if self._wrapper is None:
                message = "positions need the metadata wrapper being visited"
                raise RuntimeError(message)
            self._positions = self._wrapper.resolve(PositionProvider)
        return self._positions[node]

    @property
    def _reachability(self) -> LexicalReachability:
        return self._tracker.current

    def _qualified_names(self, node: cst.CSTNode) -> Collection[QualifiedName]:
        """Return the names LibCST's QualifiedNameProvider would give ``node``.

        The provider walks the whole module to attach a lazy value to every
        node, but only candidate nodes are ever asked; resolving through the
        node's scope on demand gives the same collection without that walk.
        """
        scope = self.get_metadata(ScopeProvider, node, None)
        if scope is None:
            return set()
        return scope.get_qualified_names_for(node)

    def _matches_guard_name(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
    ) -> bool:
        names = self._qualified_names(node)
        resolution = resolve_qualified_name(names, qualified_name)
        if resolution.confidence is not MatchConfidence.HIGH:
            return False
        if qualified_name == SYS_VERSION_INFO:
            # ``sys`` is initialized as a built-in module before normal import
            # path resolution, so a repository ``sys.py`` or ``sys`` package
            # cannot compete with an import-derived guard reference.
            return True
        return not qualified_project_candidates(qualified_name, self._project_modules)

    def _record_patch_guard_inference(self, node: cst.BaseExpression) -> None:
        location = _location(
            self._path,
            self._position(node),
        )
        if location in self._guard_inference_keys:
            return
        self._guard_inference_keys.add(location)
        self.inferences.append(
            AnalysisInference(
                code="PYA2002",
                kind="version-guard",
                message=(
                    "patch-level Python version guard is unsupported and was "
                    "treated as unknown"
                ),
                location=location,
                evidence=(
                    ("guard_granularity", "patch"),
                    ("reachability", "both-branches"),
                ),
            )
        )

    def _branches(self, node: cst.If) -> BranchReachability:
        branches = branch_reachability(
            node.test,
            self._reachability,
            self._matches_guard_name,
        )
        if branches.unsupported_patch:
            self._record_patch_guard_inference(node.test)
        return branches

    def _annotation_is_deferred(self, node: cst.BaseExpression) -> bool:
        """Whether an annotation reference is never evaluated at runtime.

        The annotation of a local variable inside a function body is never
        evaluated and never stored (PEP 526), so the reference cannot raise
        on any interpreter and is a typing-only use. Every other annotation
        stays a runtime use. Parameter, return, class-body and module-level
        annotations run at definition time up to Python 3.13, and when they
        are deferred instead, by ``from __future__ import annotations``
        (PEP 563) or by the lazy evaluation PEP 649 gives them from 3.14,
        runtime introspection such as ``typing.get_type_hints`` still
        evaluates them. Deferral alone is therefore no evidence that the
        reference never runs, and this rule errs toward reporting it.
        """
        current: cst.CSTNode = node
        while (parent := self._parent(current)) is not None:
            if isinstance(parent, cst.Annotation):
                owner = self._parent(parent)
                return isinstance(owner, cst.AnnAssign) and isinstance(
                    self.get_metadata(ScopeProvider, owner, None), FunctionScope
                )
            current = parent
        return False

    def visit_If(self, node: cst.If) -> None:  # noqa: N802
        """Assign conservative lexical states to ``if``/``elif`` branches."""
        self._tracker.enter_if(node)
        self._tracker.assign_if(node, self._branches(node))

    def leave_If(self, original_node: cst.If) -> None:  # noqa: N802
        """Restore the state active before an ``elif`` node."""
        self._tracker.leave(original_node)

    def _catches_only_import_errors(
        self,
        exception_type: cst.BaseExpression | None,
    ) -> bool:
        """Whether a handler catches only ``ImportError`` or its subclass."""
        if exception_type is None:
            return False
        if isinstance(exception_type, cst.Tuple):
            members = [element.value for element in exception_type.elements]
        else:
            members = [exception_type]
        if not members:
            return False
        return all(
            any(
                self._resolution(
                    member,
                    name,
                    source=QualifiedNameSource.BUILTIN,
                ).confidence
                is MatchConfidence.HIGH
                for name in ("builtins.ImportError", "builtins.ModuleNotFoundError")
            )
            for member in members
        )

    def visit_Try(self, node: cst.Try) -> None:  # noqa: N802
        """Narrow ``except ImportError`` handlers behind imports known to succeed.

        Design §11.1: when the ``try`` body is nothing but imports and every
        one of them is known to succeed on a target, a handler that catches
        only ``ImportError`` cannot run on that target. Any other body, handler
        type, or unknown import leaves the handler as reachable as before.
        """
        active = self._reachability
        known = import_fallback_versions(node, active.versions)
        if not known:
            return
        unreachable_free = LexicalReachability(
            versions=active.versions - known,
            usage_contexts=active.usage_contexts,
        )
        for handler in node.handlers:
            if self._catches_only_import_errors(handler.type):
                self._tracker.assign_import_fallback(handler.body, unreachable_free)

    def visit_IndentedBlock(self, node: cst.IndentedBlock) -> None:  # noqa: N802
        """Enter a multi-line branch suite."""
        self._tracker.enter(node)

    def leave_IndentedBlock(  # noqa: N802
        self,
        original_node: cst.IndentedBlock,
    ) -> None:
        """Leave a multi-line branch suite."""
        self._tracker.leave(original_node)

    def visit_SimpleStatementSuite(  # noqa: N802
        self,
        node: cst.SimpleStatementSuite,
    ) -> None:
        """Enter a one-line branch suite."""
        self._tracker.enter(node)

    def leave_SimpleStatementSuite(  # noqa: N802
        self,
        original_node: cst.SimpleStatementSuite,
    ) -> None:
        """Leave a one-line branch suite."""
        self._tracker.leave(original_node)

    def _record_match(  # noqa: PLR0913 - one override per independent match input.
        self,
        binding: IndexedMatcher,
        node: cst.CSTNode,
        confidence: MatchConfidence,
        evidence: tuple[tuple[str, str | tuple[str, ...]], ...],
        *,
        reachable_versions: frozenset[PythonMinor] | None = None,
        usage_contexts: frozenset[UsageContext] | None = None,
    ) -> None:
        reachability = self._reachability
        if self._tracker.in_import_fallback and not any(
            key == "reachability_guard" for key, _ in evidence
        ):
            evidence = (*evidence, ("reachability_guard", "import-fallback"))
        # Empty lexical states still count toward syntactic fingerprint ordinals.
        location = _location(
            self._path,
            self._position(node),
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
                reachable_versions=(
                    reachability.versions
                    if reachable_versions is None
                    else reachable_versions
                ),
                usage_contexts=(
                    reachability.usage_contexts
                    if usage_contexts is None
                    else usage_contexts
                ),
                evidence=evidence,
            )
        )

    def _exact_hasattr_guard(  # noqa: PLR0911 - strict guard grammar.
        self,
        expression: cst.BaseExpression,
        qualified_name: str,
    ) -> bool:
        """Recognize one exact ``hasattr(module, "attribute")`` predicate."""
        if isinstance(expression, cst.BooleanOperation) and isinstance(
            expression.operator, cst.And
        ):
            return self._exact_hasattr_guard(
                expression.left, qualified_name
            ) or self._exact_hasattr_guard(expression.right, qualified_name)
        if (
            not isinstance(expression, cst.Call)
            or len(expression.args) != HASATTR_ARGUMENT_COUNT
        ):
            return False
        if any(
            argument.keyword is not None or argument.star
            for argument in expression.args
        ):
            return False
        function = self._resolution(
            expression.func,
            "builtins.hasattr",
            source=QualifiedNameSource.BUILTIN,
        )
        if function.confidence is not MatchConfidence.HIGH:
            return False
        module_name, separator, attribute_name = qualified_name.rpartition(".")
        if not separator:
            return False
        attribute = expression.args[1].value
        if not isinstance(attribute, cst.SimpleString):
            return False
        if attribute.evaluated_value != attribute_name:
            return False
        module = self._import_resolution(expression.args[0].value, module_name)
        return module.confidence is MatchConfidence.HIGH

    def _hasattr_guarded_versions(
        self,
        binding: IndexedMatcher,
        node: cst.CSTNode,
        qualified_name: str,
    ) -> tuple[frozenset[PythonMinor], bool]:
        """Exclude versions where short-circuit ``hasattr`` prevents access."""
        current = node
        while (parent := self._parent(current)) is not None:
            if (
                isinstance(parent, cst.BooleanOperation)
                and isinstance(parent.operator, cst.And)
                and parent.right is current
                and self._exact_hasattr_guard(parent.left, qualified_name)
            ):
                removals = (
                    event.python
                    for event in binding.rule.events
                    if event.kind is ChangeEventKind.REMOVED
                )
                removal = min(removals, default=None)
                if removal is None:
                    return self._reachability.versions, False
                return (
                    frozenset(
                        version
                        for version in self._reachability.versions
                        if version < removal
                    ),
                    True,
                )
            if isinstance(parent, cst.BaseStatement):
                break
            current = parent
        return self._reachability.versions, False

    def _record_competing_module(
        self,
        location: SourceLocation,
        subject: str,
        candidates: tuple[PurePosixPath, ...],
        evidence: dict[str, str | tuple[str, ...]],
    ) -> None:
        """Say that ``subject`` was not classified because a project module competes."""
        self.inferences.append(
            AnalysisInference(
                code="PYA2001",
                kind="module-resolution",
                message=(
                    f"did not classify {subject} because a competing project "
                    "module exists"
                ),
                location=location,
                evidence=tuple(
                    sorted(
                        {
                            **evidence,
                            "candidate_paths": tuple(
                                path.as_posix() for path in candidates
                            ),
                            "resolution": "competing-project-module",
                            "source_roots": self._source_roots,
                        }.items()
                    )
                ),
            )
        )

    def _record_import_inference(
        self,
        node: cst.Import | cst.ImportFrom,
        imported: ImportedModule,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        self._record_competing_module(
            _location(self._path, self._position(node)),
            f"import of {imported.module!r} as standard library",
            candidates,
            {
                "bound_names": imported.bound_names,
                "imported_module": imported.module,
                "syntax": imported.syntax,
            },
        )

    def _record_qualified_inference(
        self,
        node: cst.CSTNode,
        qualified_name: str,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        location = _location(self._path, self._position(node))
        key = (
            location.region.start.line,
            location.region.start.column,
            qualified_name,
        )
        if key in self._inference_keys:
            return
        self._inference_keys.add(key)
        self._record_competing_module(
            location,
            f"reference to {qualified_name!r}",
            candidates,
            {"qualified_name": qualified_name},
        )

    def _record_dynamic_import_inference(
        self,
        node: cst.Call,
        module: str,
        dynamic_function: str,
        candidates: tuple[PurePosixPath, ...],
    ) -> None:
        self._record_competing_module(
            _location(self._path, self._position(node)),
            f"dynamic import of {module!r} as standard library",
            candidates,
            {"dynamic_function": dynamic_function, "imported_module": module},
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
                    ("source_roots", self._source_roots),
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
        names = self._qualified_names(node)
        return resolve_qualified_name(names, qualified_name, source=source)

    def _resolution_sources(
        self,
        node: cst.BaseExpression,
        qualified_name: str,
        sources: frozenset[QualifiedNameSource],
    ) -> QualifiedResolution:
        names = self._qualified_names(node)
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
            name.name.rpartition(".")[2] for name in self._qualified_names(node)
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
            self._parent,
        )
        deferred_annotation = (
            reference_context is ReferenceContext.ANNOTATION
            and self._annotation_is_deferred(node)
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
            reachable_versions, guarded = self._hasattr_guarded_versions(
                binding,
                node,
                matcher.qualified_name,
            )
            evidence: tuple[tuple[str, str | tuple[str, ...]], ...] = (
                ("qualified_names", resolution.qualified_names),
                ("reference_context", reference_context.value),
                ("resolution", resolution.resolution),
            )
            if guarded:
                evidence = (*evidence, ("reachability_guard", "hasattr-and"))
            usage_contexts: frozenset[UsageContext] | None = None
            if deferred_annotation:
                # Never evaluated at runtime: keep only the typing context so a
                # runtime-only rule no longer applies, and say why.
                usage_contexts = self._reachability.usage_contexts & {
                    UsageContext.TYPING
                }
                evidence = (*evidence, ("annotation_evaluation", "deferred"))
            self._record_match(
                binding,
                node,
                resolution.confidence,
                evidence,
                reachable_versions=reachable_versions,
                usage_contexts=usage_contexts,
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
        reachable_versions, guarded = self._hasattr_guarded_versions(
            binding,
            node.func,
            matcher.qualified_name,
        )
        if guarded:
            evidence = (*evidence, ("reachability_guard", "hasattr-and"))
        self._record_match(
            binding,
            node.func,
            resolution.confidence,
            evidence,
            reachable_versions=reachable_versions,
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
        operation = terminal_name(node.func)
        if operation in ("append", "insert"):
            resolution = self._resolution(node.func, f"sys.path.{operation}")
            if resolution.confidence is MatchConfidence.HIGH:
                self.path_mutations.append(
                    ImportPathMutation(
                        operation=operation,
                        location=_location(
                            self._path,
                            self._position(node),
                        ),
                    )
                )
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
                        (
                            ("pattern", pattern.value),
                            ("resolution", "builtin-pattern"),
                        ),
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


_RISKY_OPERATORS = frozenset(
    {"~", "**", "*", "/", "//", "%", "+", "-", "<<", ">>", "&", "^", "|"}
)
_LINE_TOKENS = frozenset(
    {tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT, tokenize.INDENT}
)


@dataclass
class _TokenNesting:
    """Delimiter depth and the longest run of operators seen so far."""

    depth: int = 0
    operators: int = 0
    operators_exceeded: bool = False

    def feed(self, token: tokenize.TokenInfo) -> bool:
        """Count one token; return whether delimiter depth passed its limit."""
        if token.type in _LINE_TOKENS or token.type != tokenize.OP:
            if token.type in _LINE_TOKENS:
                self.operators = 0
            return False
        if token.string in _RISKY_OPERATORS:
            self.operators += 1
            self.operators_exceeded |= self.operators > MAX_CST_DEPTH
            return False
        self.operators = 0
        if token.string in {"(", "[", "{"}:
            self.depth += 1
        elif token.string in {")", "]", "}"} and self.depth:
            self.depth -= 1
        return self.depth > MAX_PARSE_NESTING


def _token_nesting_diagnostic(
    source: str,
    relative_path: PurePosixPath,
) -> Diagnostic | None:
    """Reject pathological nesting before entering LibCST's C stack.

    One token stream bounds two shapes. Delimiter depth counts open
    brackets; past its limit, or at it when the stream ends inside them, the
    file is rejected, and this takes precedence over the operator bound.
    Operator nesting counts consecutive binary or unary operators between
    brackets and line breaks, which LibCST would otherwise parse into an
    equally deep tree. Malformed tokens are left for LibCST to report.
    """
    nesting = _TokenNesting()
    delimiter = _nesting_diagnostic(relative_path, "delimiter", MAX_PARSE_NESTING)
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if nesting.feed(token):
                return delimiter
    except tokenize.TokenError:
        if nesting.depth >= MAX_PARSE_NESTING:
            return delimiter
    except IndentationError:
        # LibCST produces the user-facing syntax diagnostic for malformed tokens.
        pass
    if nesting.operators_exceeded:
        return _nesting_diagnostic(relative_path, "concrete syntax tree", MAX_CST_DEPTH)
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
        stack.extend((child, depth + 1) for child in _child_nodes(node))
    return None


_NODE_FIELDS: dict[type[cst.CSTNode], tuple[str, ...]] = {}


def _child_nodes(node: cst.CSTNode) -> Iterator[cst.CSTNode]:
    """Yield the nodes ``node.children`` would, read straight from its fields.

    ``children`` runs a visitor on every call, which tripled the cost of this
    walk. Every CST node is a dataclass whose children are its node-valued
    fields and the nodes inside its sequence fields; only the order differs,
    and depth does not depend on order.
    """
    names = _NODE_FIELDS.get(type(node))
    if names is None:
        names = _NODE_FIELDS[type(node)] = tuple(item.name for item in fields(node))
    for name in names:
        value = getattr(node, name)
        if isinstance(value, cst.CSTNode):
            yield value
        elif isinstance(value, (tuple, list)):
            yield from (item for item in value if isinstance(item, cst.CSTNode))


def _parse_module(
    source: str,
    relative_path: PurePosixPath,
) -> tuple[cst.Module | None, Diagnostic | None]:
    """Parse one module after enforcing both parser depth boundaries."""
    nesting_diagnostic = _token_nesting_diagnostic(source, relative_path)
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


def _analyse_file(
    path: DiscoveredFile,
    context: _FileAnalysisContext,
) -> _FileAnalysis:
    source, read_diagnostic = _read_source(
        context.root,
        path,
        context.max_file_size_bytes,
    )
    if read_diagnostic is not None:
        return _FileAnalysis(
            suppressions=index_inline_suppressions(()),
            diagnostics=(read_diagnostic,),
        )
    if source is None:  # pragma: no cover - guarded by the diagnostic result.
        msg = "source text is absent without a read diagnostic"
        raise RuntimeError(msg)

    inline_directives, suppression_diagnostics = collect_inline_suppressions(
        source,
        path.relative_path,
        context.registry,
    )
    module, parse_diagnostic = _parse_module(source, path.relative_path)
    if parse_diagnostic is not None:
        return _FileAnalysis(
            suppressions=index_inline_suppressions(inline_directives),
            diagnostics=(*suppression_diagnostics, parse_diagnostic),
        )
    if module is None:  # pragma: no cover - guarded by the diagnostic result.
        msg = "parsed module is absent without a parse diagnostic"
        raise RuntimeError(msg)

    # The module was just parsed and is never modified, so every node is
    # already unique; the defensive deep copy would only double the work.
    wrapper = MetadataWrapper(module, unsafe_skip_copy=True)
    visitor = _MatcherVisitor(
        path,
        context.matcher_index,
        context.project_modules,
        context.target_versions,
        context.source_roots,
        wrapper=wrapper,
    )
    inline_suppressions = index_inline_suppressions(inline_directives)
    try:
        inline_suppressions = index_inline_suppressions(
            bind_inline_suppressions(
                inline_directives,
                wrapper,
            )
        )
        wrapper.visit(visitor)
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
        return _FileAnalysis(
            suppressions=inline_suppressions,
            diagnostics=(*suppression_diagnostics, diagnostic),
        )
    return _FileAnalysis(
        suppressions=inline_suppressions,
        diagnostics=suppression_diagnostics,
        matches=tuple(visitor.matches),
        inferences=tuple(visitor.inferences),
        path_mutations=tuple(visitor.path_mutations),
    )


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


def _read_source(
    root: Path,
    path: DiscoveredFile,
    max_file_size_bytes: int,
) -> tuple[str | None, Diagnostic | None]:
    """Read one stable source through its logical root-relative path."""
    try:
        data = read_rooted_bytes(
            root,
            Path(path.relative_path.as_posix()),
            max_file_size_bytes,
        )
    except RootedReadTooLargeError:
        return _read_failure(
            path,
            "PYA1005",
            DiagnosticCategory.DISCOVERY,
            f"source file exceeds the {max_file_size_bytes}-byte analysis limit",
        )
    except UnsafeEntryError:
        return _read_failure(
            path,
            "PYA1004",
            DiagnosticCategory.DISCOVERY,
            "source entry is not a stable regular file beneath real directories",
        )
    except OSError as error:
        return _read_failure(
            path,
            "PYA1002",
            DiagnosticCategory.ENCODING,
            f"unable to read Python source ({type(error).__name__})",
        )

    try:
        source_bytes = io.BytesIO(data)
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


def _discovery_issue_diagnostic(issue: DiscoveryIssue) -> Diagnostic:
    return Diagnostic(
        code=issue.code,
        category=DiagnosticCategory.DISCOVERY,
        message=issue.message,
        location=_initial_location(issue.relative_path),
        incomplete=True,
    )


def _discover_configured(
    root: Path,
    paths: tuple[Path, ...],
    options: DiscoveryOptions,
) -> DiscoveryResult:
    if options == DiscoveryOptions():
        return discover_python_files(root, paths)
    return discover_python_files(root, paths, options)


def _report_file_progress(request: ScanRequest, progress: FileProgress) -> None:
    if request.on_file is not None:
        request.on_file(progress)


def _overrides(request: ScanRequest) -> ConfigurationOverrides:
    """Every configuration override is a ScanRequest field of the same name."""
    return ConfigurationOverrides(
        **{
            field.name: getattr(request, field.name)
            for field in fields(ConfigurationOverrides)
        }
    )


def _scan_report(  # noqa: PLR0913 - one report assembly point.
    registry: Registry,
    resolved: ResolvedConfiguration,
    counts: ScanCounts,
    diagnostics: tuple[Diagnostic, ...],
    *,
    findings: tuple[Finding, ...] = (),
    inferences: tuple[AnalysisInference, ...] = (),
) -> ScanReport:
    """Assemble a report; only counts, findings and notes differ between exits."""
    return ScanReport(
        schema_version=1,
        tool_version=__version__,
        registry_release=registry.release,
        registry_revision=registry.revision,
        policy=resolved.policy,
        root_label=".",
        counts=counts,
        findings=findings,
        diagnostics=diagnostics,
        inferences=inferences,
        configuration=resolved.scan,
        policy_provenance=resolved.policy_provenance,
    )


def scan(request: ScanRequest) -> ScanReport:  # noqa: PLR0915 - pipeline coordinator.
    """Scan Python source without importing, executing, or networking."""
    if request.fail_new_only and request.baseline_file is None:
        message = "--fail-new-only requires --baseline-file"
        raise ConfigurationError(message)
    try:
        root = request.root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "scan root does not exist or cannot be resolved"
        raise DiscoveryError(message) from error
    if not root.is_dir():
        message = "scan root must be a directory"
        raise DiscoveryError(message)
    registry = load_registry(request.registry_source)
    project_snapshot = _load_project_configuration_snapshot(root, request.config_path)
    resolved = _resolve_snapshot_configuration(
        root,
        registry,
        project_snapshot,
        _overrides(request),
    )
    policy = resolved.policy
    baseline = (
        load_baseline(request.baseline_file, root)
        if request.baseline_file is not None
        else None
    )
    per_file_ignores, suppression_diagnostics = resolve_per_file_ignores(
        resolved.scan.per_file_ignores,
        registry,
    )
    discovery_options = DiscoveryOptions(
        include=resolved.scan.include,
        exclude=resolved.scan.exclude,
        respect_gitignore=resolved.scan.respect_gitignore,
        max_file_size_bytes=resolved.scan.max_file_size_bytes,
    )
    module_options = DiscoveryOptions(
        respect_gitignore=False,
        max_file_size_bytes=resolved.scan.max_file_size_bytes,
        allow_explicit_built_in_roots=True,
    )

    try:
        if resolved.source_roots_inferred:
            module_discovery = _discover_configured(root, (), module_options)
        elif resolved.scan.source_roots:
            module_discovery = _discover_configured(
                root,
                tuple(Path(path) for path in resolved.scan.source_roots),
                module_options,
            )
        else:
            module_discovery = DiscoveryResult(files=(), issues=())
        discovery = _discover_configured(root, request.paths, discovery_options)
    except DiscoveryIncompleteError as error:
        return _scan_report(
            registry,
            resolved,
            ScanCounts(files_discovered=0, files_analyzed=0, files_incomplete=1),
            (
                *suppression_diagnostics,
                Diagnostic(
                    code="PYA1001",
                    category=DiagnosticCategory.DISCOVERY,
                    message=str(error),
                    incomplete=True,
                ),
            ),
        )
    source_limit_issues = tuple(
        issue
        for issue in (*module_discovery.issues, *discovery.issues)
        if issue.code == "PYA1006"
    )
    if source_limit_issues:
        reported_issues = {
            (issue.relative_path, issue.code, issue.message): issue
            for issue in (*discovery.issues, *source_limit_issues)
        }
        return _scan_report(
            registry,
            resolved,
            ScanCounts(
                files_discovered=discovery.files_discovered,
                files_analyzed=0,
                files_incomplete=len(reported_issues),
            ),
            (
                *suppression_diagnostics,
                *(
                    _discovery_issue_diagnostic(reported_issues[key])
                    for key in sorted(reported_issues)
                ),
            ),
        )
    project_modules = project_module_paths(
        module_discovery.files,
        module_discovery.issues,
        None if resolved.source_roots_inferred else resolved.scan.source_roots,
    )
    dynamic_modules = dynamic_path_module_paths(module_discovery.files)
    matcher_index = build_matcher_index(registry)
    file_context = _FileAnalysisContext(
        root=root,
        matcher_index=matcher_index,
        project_modules=project_modules,
        target_versions=policy.target_versions,
        source_roots=resolved.scan.source_roots,
        max_file_size_bytes=resolved.scan.max_file_size_bytes,
        registry=registry,
    )

    matches: list[StaticMatch] = []
    inferences: list[AnalysisInference] = []
    path_mutations: list[ImportPathMutation] = []
    inline_suppressions: dict[PurePosixPath, InlineSuppressionIndex] = {}
    diagnostics = [
        *suppression_diagnostics,
        *(_discovery_issue_diagnostic(issue) for issue in discovery.issues),
    ]
    incomplete_files = len(discovery.issues)
    analyzed = 0
    for index, path in enumerate(discovery.files, start=1):
        analysis = _analyse_file(path, file_context)
        inline_suppressions[path.relative_path] = analysis.suppressions
        diagnostics.extend(analysis.diagnostics)
        _report_file_progress(
            request,
            FileProgress(
                path=path.relative_path,
                index=index,
                total=len(discovery.files),
                incomplete=analysis.incomplete,
            ),
        )
        if analysis.incomplete:
            incomplete_files += 1
            continue
        analyzed += 1
        matches.extend(analysis.matches)
        inferences.extend(analysis.inferences)
        path_mutations.extend(analysis.path_mutations)

    matches, path_inferences = dynamic_path_adjustments(
        matches,
        registry,
        dynamic_modules,
        path_mutations,
    )
    inferences.extend(path_inferences)

    findings = build_findings(
        matches,
        FindingContext(
            registry=registry,
            policy=policy,
            minimum_confidence=resolved.scan.minimum_confidence,
            show_unscheduled=resolved.scan.show_unscheduled,
            inline_suppressions=inline_suppressions,
            per_file_ignores=per_file_ignores,
            baseline_fingerprints=(
                baseline.fingerprints if baseline is not None else frozenset()
            ),
        ),
    )
    return _scan_report(
        registry,
        resolved,
        ScanCounts(
            files_discovered=discovery.files_discovered,
            files_analyzed=analyzed,
            files_incomplete=incomplete_files,
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
                    diagnostic.message,
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
