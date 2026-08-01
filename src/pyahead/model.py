"""Immutable domain models for the static analyser and compatibility registry."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from typing import Self, TypeAlias

from pyahead.versions import PythonMinor

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
    """Diagnostic categories needed by the M1 scan path."""

    CONFIGURATION = "configuration"
    DISCOVERY = "discovery"
    ENCODING = "encoding"
    PARSE = "parse"
    REGISTRY = "registry"
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


@dataclass(frozen=True)
class Registry:
    """An immutable registry snapshot."""

    release: str
    revision: str
    retired_ids: tuple[str, ...]
    rules: tuple[Rule, ...]

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
    impact: Impact
    action_version: PythonMinor
    events: tuple[RuleEvent, ...]
    remediation: Remediation
    sources: tuple[SourceReference, ...]
    registry_revision: str


@dataclass(frozen=True)
class ScanCounts:
    """Deterministic scan completion counts."""

    files_discovered: int
    files_analyzed: int
    files_incomplete: int


@dataclass(frozen=True)
class ScanReport:
    """Complete formatter-independent result of an M1 scan."""

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

    @property
    def gate_failed(self) -> bool:
        """Return whether a finding meets the fixed M1 breaking gate."""
        return any(finding.impact is Impact.BREAKING for finding in self.findings)

    @property
    def exit_code(self) -> ExitCode:
        """Evaluate the M1 default gate and incomplete-scan precedence."""
        if self.counts.files_incomplete:
            return ExitCode.INCOMPLETE
        if self.gate_failed:
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS
