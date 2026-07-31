"""Immutable domain models for the M1 vertical slice."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from typing import Self

from pyahead.versions import PythonMinor


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
    """Compatibility event types represented in the seed registry."""

    DEPRECATED = "deprecated"
    REMOVED = "removed"


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
class RuleMatcher:
    """A declarative matcher supported by the M1 engine."""

    kind: str
    module: str


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
class Remediation:
    """Human-reviewed migration guidance."""

    summary: str


@dataclass(frozen=True)
class Rule:
    """A minimal reviewed compatibility-registry rule."""

    id: str
    title: str
    summary: str
    subject: str
    contexts: tuple[str, ...]
    events: tuple[RuleEvent, ...]
    on_deprecation: Impact
    on_removal: Impact
    matchers: tuple[RuleMatcher, ...]
    remediation: Remediation
    sources: tuple[SourceReference, ...]
    tags: tuple[str, ...]


@dataclass(frozen=True)
class Registry:
    """An immutable registry snapshot."""

    release: str
    revision: str
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class StaticMatch:
    """Structured static evidence produced by exact source matching."""

    rule_id: str
    matcher_kind: str
    location: SourceLocation
    enclosing_scope: str
    subject: str
    confidence: MatchConfidence
    evidence: tuple[tuple[str, str], ...]


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
