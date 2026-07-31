"""End-to-end M1 static-analysis pipeline."""

import hashlib
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

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
    DiscoveredFile,
    DiscoveryIncompleteError,
    discover_python_files,
    project_module_names,
)
from pyahead.model import (
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
        local_modules: frozenset[str],
    ) -> None:
        """Configure one coordinated read-only traversal."""
        self._path = path
        self._rules_by_module = rules_by_module
        self._local_modules = local_modules
        self.matches: list[StaticMatch] = []

    def _record(
        self,
        node: cst.Import | cst.ImportFrom,
        module: str,
        syntax: str,
        bound_name: str,
    ) -> None:
        if module in self._local_modules:
            return
        rules = self._rules_by_module.get(module, ())
        if not rules:
            return
        location = _location(
            self._path,
            self.get_metadata(PositionProvider, node),
        )
        scope = self.get_metadata(ScopeProvider, node)
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
                        ("bound_name", bound_name),
                        ("imported_module", module),
                        ("syntax", syntax),
                    ),
                )
            )

    def visit_Import(self, node: cst.Import) -> None:  # noqa: N802
        """Match direct and aliased module imports."""
        recorded_modules: set[str] = set()
        for alias in node.names:
            module = get_full_name_for_node(alias.name)
            if module is None or module in recorded_modules:
                continue
            recorded_modules.add(module)
            bound_name = (
                get_full_name_for_node(alias.asname.name)
                if alias.asname is not None
                else module.split(".", maxsplit=1)[0]
            )
            self._record(node, module, "import", bound_name or module)

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:  # noqa: N802
        """Match absolute ``from MODULE import ...`` statements."""
        if node.relative:
            return
        module = get_full_name_for_node(node.module) if node.module else None
        if module is None:
            return
        self._record(node, module, "from-import", module)


def _parse_file(
    path: DiscoveredFile,
    rules_by_module: dict[str, tuple[Rule, ...]],
    local_modules: frozenset[str],
) -> tuple[tuple[StaticMatch, ...], Diagnostic | None]:
    try:
        with tokenize.open(path.absolute_path) as source_file:
            source = source_file.read()
    except (OSError, SyntaxError, UnicodeError) as error:
        diagnostic = Diagnostic(
            code="PYA1002",
            category=DiagnosticCategory.ENCODING,
            message=f"unable to read Python source ({type(error).__name__})",
            location=SourceLocation(
                path=path.relative_path,
                region=SourceRegion(
                    start=SourcePosition(line=1, column=1),
                    end=SourcePosition(line=1, column=1),
                ),
            ),
            incomplete=True,
        )
        return (), diagnostic

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
        return (), diagnostic

    visitor = _ImportVisitor(path, rules_by_module, local_modules)
    MetadataWrapper(module).visit(visitor)
    return tuple(visitor.matches), None


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


def scan(request: ScanRequest) -> ScanReport:
    """Scan Python source without importing, executing, or networking."""
    policy = Policy.parse(request.baseline_python, request.horizon_python)
    registry = load_registry(request.registry_source)
    try:
        files = discover_python_files(request.root, request.paths)
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
        )
    local_modules = project_module_names(files)
    rules_by_module = _rules_by_module(registry)

    matches: list[StaticMatch] = []
    diagnostics: list[Diagnostic] = []
    analyzed = 0
    for path in files:
        file_matches, diagnostic = _parse_file(path, rules_by_module, local_modules)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
            continue
        analyzed += 1
        matches.extend(file_matches)

    findings = _findings(matches, registry, policy)
    return ScanReport(
        schema_version=1,
        tool_version=__version__,
        registry_release=registry.release,
        registry_revision=registry.revision,
        policy=policy,
        root_label=".",
        counts=ScanCounts(
            files_discovered=len(files),
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
    )
