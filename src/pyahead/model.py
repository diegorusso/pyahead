"""Immutable domain models for the static analyser and compatibility registry."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from typing import Self, TypeAlias

from pyahead.versions import PythonMinor, target_set

EvidenceValue: TypeAlias = str | tuple[str, ...]
LiteralValue: TypeAlias = bool | float | int | str | None


class ConfigurationError(ValueError):
    """Raised when an explicit scan policy is invalid."""


class ExitCode(IntEnum):
    """Stable process outcomes defined by the CLI contract."""

    SUCCESS = 0
    FINDINGS = 1
    INVALID_INPUT = 2
    INCOMPLETE = 3
    INTERNAL_ERROR = 4


class Impact(StrEnum):
    """What happens if affected code executes on a target version."""

    DEPRECATED = "deprecated"
    RISK = "risk"
    BREAKING = "breaking"
    INFORMATIONAL = "informational"


class FailOn(StrEnum):
    """Minimum finding impact that fails the CI gate."""

    NEVER = "never"
    BREAKING = "breaking"
    RISK = "risk"
    DEPRECATED = "deprecated"
    ANY = "any"


class BaselineStatus(StrEnum):
    """Whether a finding fingerprint existed in the selected baseline."""

    NEW = "new"
    EXISTING = "existing"


class SuppressionKind(StrEnum):
    """Supported origins for an explicit finding suppression."""

    INLINE = "inline"
    PER_FILE = "per-file"


class FindingState(StrEnum):
    """The compatibility state of one finding over target versions."""

    DEPRECATED = "deprecated"
    RISK = "risk"
    BREAKING = "breaking"
    INFORMATIONAL = "informational"


class MatchConfidence(StrEnum):
    """Strength of the static source-to-rule identification."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegistryCertainty(StrEnum):
    """Authority and settlement of a registry event."""

    RELEASED = "released"
    SCHEDULED = "scheduled"
    PROVISIONAL = "provisional"


class ChangeEventKind(StrEnum):
    """Compatibility event types represented by registry schema version 1."""

    DEPRECATED = "deprecated"
    REMOVED = "removed"
    SIGNATURE_CHANGED = "signature_changed"
    BEHAVIOR_CHANGED = "behavior_changed"
    SYNTAX_CHANGED = "syntax_changed"
    SUPPORT_DROPPED = "support_dropped"


class MatcherKind(StrEnum):
    """Closed set of declarative matcher implementations."""

    MODULE_IMPORT = "module-import"
    QUALIFIED_REFERENCE = "qualified-reference"
    QUALIFIED_CALL = "qualified-call"
    CALL_SHAPE = "call-shape"
    LITERAL_DYNAMIC_IMPORT = "literal-dynamic-import"
    BUILTIN_PATTERN = "builtin-pattern"


class ReferenceContext(StrEnum):
    """Supported syntactic contexts for qualified references."""

    READ = "read"
    DECORATOR = "decorator"
    BASE_CLASS = "base-class"
    ANNOTATION = "annotation"


class UsageContext(StrEnum):
    """Registry contexts supported by the static alpha."""

    RUNTIME = "runtime"
    TYPING = "typing"


class ReleaseStatus(StrEnum):
    """Presentation status for a Python release metadata record."""

    EOL = "eol"
    SECURITY = "security"
    STABLE = "stable"
    PRERELEASE = "prerelease"
    PLANNED = "planned"


class SubjectKind(StrEnum):
    """Kinds of source subjects a rule may describe."""

    MODULE = "module"
    FUNCTION = "function"
    CLASS = "class"
    ATTRIBUTE = "attribute"
    SYNTAX = "syntax"


class AutomationTool(StrEnum):
    """External tools whose verified automation may be documented."""

    RUFF = "ruff"
    PYUPGRADE = "pyupgrade"


class BuiltinPattern(StrEnum):
    """Whitelisted non-declarative matcher implementations."""

    BOOL_BITWISE_INVERSION = "bool-bitwise-inversion"


class DiagnosticCategory(StrEnum):
    """Diagnostic categories supported by the static scan path."""

    CONFIGURATION = "configuration"
    DISCOVERY = "discovery"
    ENCODING = "encoding"
    PARSE = "parse"
    REGISTRY = "registry"
    SUPPRESSION = "suppression"
    INTERNAL = "internal"


@dataclass(frozen=True, order=True)
class SourcePosition:
    """A one-indexed source position."""

    line: int
    column: int


@dataclass(frozen=True, order=True)
class SourceRegion:
    """A half-open source region."""

    start: SourcePosition
    end: SourcePosition


@dataclass(frozen=True, order=True)
class SourceLocation:
    """A repository-relative location and source region."""

    path: PurePosixPath
    region: SourceRegion


@dataclass(frozen=True)
class Policy:
    """An explicit inclusive baseline-to-horizon policy."""

    baseline_python: PythonMinor
    horizon_python: PythonMinor

    def __post_init__(self) -> None:
        """Require a non-decreasing policy range."""
        if self.horizon_python < self.baseline_python:
            message = "horizon Python must be greater than or equal to baseline Python"
            raise ConfigurationError(message)

    @classmethod
    def parse(cls, baseline_python: str, horizon_python: str) -> Self:
        """Build a policy from strict CLI version strings."""
        return cls(
            baseline_python=PythonMinor.parse(baseline_python),
            horizon_python=PythonMinor.parse(horizon_python),
        )

    @property
    def target_versions(self) -> frozenset[PythonMinor]:
        """Return every inclusive minor target in this policy."""
        return target_set(self.baseline_python, self.horizon_python)


@dataclass(frozen=True)
class PolicyProvenance:
    """Stable sources for the two effective policy boundaries."""

    baseline_python: str
    horizon_python: str
    requires_python: str | None = None


@dataclass(frozen=True)
class PerFileIgnore:
    """One configured path pattern and its ignored canonical rule IDs."""

    pattern: str
    rule_ids: tuple[str, ...]


@dataclass(frozen=True)
class EffectiveConfiguration:
    """Resolved M4 scan configuration exposed in every report."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    source_roots: tuple[str, ...] = (".", "src")
    source_roots_provenance: str = "inferred:conventional-root-and-src-layout"
    respect_gitignore: bool = True
    minimum_confidence: MatchConfidence = MatchConfidence.HIGH
    fail_on: FailOn = FailOn.BREAKING
    show_unscheduled: bool = True
    max_file_size_bytes: int = 2 * 1024 * 1024
    per_file_ignores: tuple[PerFileIgnore, ...] = ()
    fail_new_only: bool = False
    show_suppressed: bool = False
    allow_incomplete: bool = False


@dataclass(frozen=True)
class Diagnostic:
    """A stable scan diagnostic safe for all formatters."""

    code: str
    category: DiagnosticCategory
    message: str
    location: SourceLocation | None = None
    fatal: bool = False
    incomplete: bool = False


@dataclass(frozen=True)
class ModuleImportMatcher:
    """Match an import of a module or one of its submodules."""

    kind: MatcherKind
    module: str


@dataclass(frozen=True)
class QualifiedReferenceMatcher:
    """Match an exact import-derived reference."""

    kind: MatcherKind
    qualified_name: str
    contexts: tuple[ReferenceContext, ...]


@dataclass(frozen=True)
class QualifiedCallMatcher:
    """Match an exact import-derived callable used as ``Call.func``."""

    kind: MatcherKind
    qualified_name: str


@dataclass(frozen=True)
class LiteralArgumentPredicate:
    """Require one positional or keyword argument to equal a literal."""

    position: int | None
    keyword: str | None
    equals: LiteralValue


@dataclass(frozen=True)
class CallShapeMatcher:
    """Match a qualified call whose statically visible arguments fit a shape."""

    kind: MatcherKind
    qualified_name: str
    min_positional_args: int | None
    max_positional_args: int | None
    required_keywords: tuple[str, ...]
    forbidden_keywords: tuple[str, ...]
    literal_arguments: tuple[LiteralArgumentPredicate, ...]


@dataclass(frozen=True)
class LiteralDynamicImportMatcher:
    """Match a whitelisted dynamic-import function with a literal module name."""

    kind: MatcherKind
    module: str
    confidence: MatchConfidence


@dataclass(frozen=True)
class BuiltinPatternMatcher:
    """Dispatch to one whitelisted syntax-pattern implementation."""

    kind: MatcherKind
    pattern: BuiltinPattern


RuleMatcher: TypeAlias = (
    ModuleImportMatcher
    | QualifiedReferenceMatcher
    | QualifiedCallMatcher
    | CallShapeMatcher
    | LiteralDynamicImportMatcher
    | BuiltinPatternMatcher
)


@dataclass(frozen=True)
class RuleEvent:
    """A sourced compatibility change at a Python minor version."""

    kind: ChangeEventKind
    python: PythonMinor
    certainty: RegistryCertainty
    source_id: str


@dataclass(frozen=True)
class PythonRelease:
    """Informative presentation metadata for one Python minor release."""

    python: PythonMinor
    status: ReleaseStatus
    released_on: str | None
    expected_final_on: str | None
    source: str | None


@dataclass(frozen=True)
class SourceReference:
    """An authoritative source attached to a registry rule."""

    id: str
    title: str
    url: str


@dataclass(frozen=True)
class AutomationReference:
    """Metadata for an existing external transformation; never an invocation."""

    tool: AutomationTool
    rule: str


@dataclass(frozen=True)
class Remediation:
    """Human-reviewed migration guidance."""

    summary: str
    documentation_url: str | None = None
    automation: AutomationReference | None = None


@dataclass(frozen=True)
class Rule:
    """A strict reviewed compatibility-registry rule."""

    id: str
    aliases: tuple[str, ...]
    title: str
    summary: str
    ecosystem: str
    runtime: str
    subject_kind: SubjectKind
    subject: str
    contexts: tuple[UsageContext, ...]
    events: tuple[RuleEvent, ...]
    event_impacts: tuple[tuple[ChangeEventKind, Impact], ...]
    matchers: tuple[RuleMatcher, ...]
    remediation: Remediation
    sources: tuple[SourceReference, ...]
    tags: tuple[str, ...]

    def impact_for(self, event: ChangeEventKind) -> Impact:
        """Return the explicitly authored impact for one event kind."""
        for kind, impact in self.event_impacts:
            if kind is event:
                return impact
        message = f"rule {self.id} has no impact for {event.value}"
        raise ValueError(message)

    @property
    def on_deprecation(self) -> Impact:
        """Retain the M1 convenience accessor for deprecation impact."""
        return self.impact_for(ChangeEventKind.DEPRECATED)

    @property
    def on_removal(self) -> Impact:
        """Retain the M1 convenience accessor for removal impact."""
        return self.impact_for(ChangeEventKind.REMOVED)

    @property
    def removal_unscheduled(self) -> bool:
        """Whether a sourced deprecation has no authoritative removal event."""
        kinds = frozenset(event.kind for event in self.events)
        return (
            ChangeEventKind.DEPRECATED in kinds and ChangeEventKind.REMOVED not in kinds
        )


@dataclass(frozen=True)
class Registry:
    """An immutable registry snapshot."""

    release: str
    revision: str
    retired_ids: tuple[str, ...]
    rules: tuple[Rule, ...]
    releases: tuple[PythonRelease, ...] = ()

    def find_rule(self, identifier: str) -> Rule | None:
        """Resolve a canonical rule ID or an explicitly declared alias."""
        return next(
            (
                rule
                for rule in self.rules
                if identifier == rule.id or identifier in rule.aliases
            ),
            None,
        )


@dataclass(frozen=True)
class StaticMatch:
    """Structured static evidence produced by exact source matching."""

    rule_id: str
    matcher_kind: str
    location: SourceLocation
    enclosing_scope: str
    subject: str
    confidence: MatchConfidence
    reachable_versions: frozenset[PythonMinor]
    usage_contexts: frozenset[UsageContext]
    evidence: tuple[tuple[str, EvidenceValue], ...]


@dataclass(frozen=True)
class AnalysisInference:
    """Visible provenance for a conservative static-analysis decision."""

    code: str
    kind: str
    message: str
    location: SourceLocation
    evidence: tuple[tuple[str, EvidenceValue], ...]


@dataclass(frozen=True)
class Suppression:
    """An explicit inline or configuration suppression applied to a finding."""

    kind: SuppressionKind
    reason: str | None = None
    pattern: str | None = None


@dataclass(frozen=True)
class FindingStateRange:
    """One contiguous version range sharing a compatibility state."""

    from_python: PythonMinor
    through_python: PythonMinor
    state: FindingState


@dataclass(frozen=True)
class Finding:
    """A repository-specific match combined with rule and policy facts."""

    fingerprint: str
    rule_id: str
    title: str
    location: SourceLocation
    enclosing_scope: str
    subject: str
    match_kind: str
    match_confidence: MatchConfidence
    match_evidence: tuple[tuple[str, EvidenceValue], ...]
    usage_contexts: tuple[UsageContext, ...]
    reachable_versions: tuple[PythonMinor, ...]
    states: tuple[FindingStateRange, ...]
    impact: Impact
    action_version: PythonMinor
    events: tuple[RuleEvent, ...]
    remediation: Remediation
    sources: tuple[SourceReference, ...]
    registry_revision: str
    removal_unscheduled: bool
    suppression: Suppression | None = None
    baseline_status: BaselineStatus = BaselineStatus.NEW


@dataclass(frozen=True)
class ScanCounts:
    """Deterministic scan completion counts."""

    files_discovered: int
    files_analyzed: int
    files_incomplete: int


@dataclass(frozen=True)
class ScanReport:
    """Complete formatter-independent static scan result."""

    schema_version: int
    tool_version: str
    registry_release: str
    registry_revision: str
    policy: Policy
    root_label: str
    counts: ScanCounts
    findings: tuple[Finding, ...]
    diagnostics: tuple[Diagnostic, ...]
    inferences: tuple[AnalysisInference, ...]
    configuration: EffectiveConfiguration = EffectiveConfiguration()
    policy_provenance: PolicyProvenance = PolicyProvenance(
        baseline_python="command-line",
        horizon_python="command-line",
    )

    @property
    def visible_findings(self) -> tuple[Finding, ...]:
        """Return findings selected for normal formatter output."""
        if self.configuration.show_suppressed:
            return self.findings
        return tuple(
            finding for finding in self.findings if finding.suppression is None
        )

    @property
    def gate_failed(self) -> bool:
        """Evaluate unsuppressed findings against the configured M4 gate."""
        if self.configuration.fail_on is FailOn.NEVER:
            return False
        thresholds = {
            FailOn.ANY: 0,
            FailOn.DEPRECATED: 1,
            FailOn.RISK: 2,
            FailOn.BREAKING: 3,
        }
        impact_ranks = {
            Impact.INFORMATIONAL: 0,
            Impact.DEPRECATED: 1,
            Impact.RISK: 2,
            Impact.BREAKING: 3,
        }
        threshold = thresholds[self.configuration.fail_on]
        return any(
            finding.suppression is None
            and (
                not self.configuration.fail_new_only
                or finding.baseline_status is BaselineStatus.NEW
            )
            and impact_ranks[finding.impact] >= threshold
            for finding in self.findings
        )

    @property
    def exit_code(self) -> ExitCode:
        """Evaluate incomplete-analysis precedence and the configured gate."""
        if self.counts.files_incomplete and not self.configuration.allow_incomplete:
            return ExitCode.INCOMPLETE
        if self.gate_failed:
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS
