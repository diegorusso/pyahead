"""Dependency evidence types, limits, errors and shared work budgets."""

from __future__ import annotations

import hashlib
import json
import re
import signal
import struct
import tarfile
import zipfile
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from functools import cached_property, wraps
from typing import (
    TYPE_CHECKING,
    NoReturn,
    ParamSpec,
    TypeAlias,
    TypeVar,
)

from packaging.requirements import InvalidRequirement, Requirement
from packaging.tags import Tag, parse_tag
from packaging.utils import (
    canonicalize_name,
)
from packaging.version import Version

from pyahead.model import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path, PurePosixPath


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


JsonScalar: TypeAlias = bool | float | int | str | None


JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


_P = ParamSpec("_P")


_R = TypeVar("_R")


_DEPENDENCY_KEYS = frozenset(
    {
        "extras",
        "index-url",
        "metadata",
        "network",
        "project-kind",
        "requirements",
        "resolve",
        "resolver",
        "targets",
        "timeout-seconds",
    }
)


_TARGET_REQUIRED_KEYS = frozenset(
    {
        "compatible-tags",
        "implementation-name",
        "implementation-version",
        "name",
        "os-name",
        "platform-machine",
        "platform-python-implementation",
        "platform-system",
        "python-full-version",
        "resolver-platform",
        "sys-platform",
    }
)


_TARGET_OPTIONAL_KEYS = frozenset({"platform-release", "platform-version"})


_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024


_MAX_METADATA_BYTES = 2 * 1024 * 1024


_MAX_CONFIGURATION_BYTES = 2 * 1024 * 1024


_MAX_ARCHIVE_MEMBERS = 10_000


_MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024


_MAX_TOTAL_ARCHIVE_EXPANDED_BYTES = 1024 * 1024 * 1024


_MAX_TAR_CONTROL_BYTES = 2 * 1024 * 1024


_POSIX_FORCE_KILL_SIGNAL = int(getattr(signal, "SIGKILL", 9))


_MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024


_MAX_TEXT_LENGTH = 4096


_MAX_REQUIREMENTS = 10_000


_MAX_TARGETS = 64


_MAX_EXTRAS = 256


_MAX_METADATA_INPUTS = 256


_MAX_METADATA_TOTAL_BYTES = 512 * 1024 * 1024


_MAX_METADATA_REQUIREMENTS = 100_000


_MAX_MARKER_EVALUATIONS = 1_000_000


_MAX_RESOLVER_STREAM_BYTES = 4 * 1024 * 1024


_MAX_RESOLVER_RESULT_BYTES = 8 * 1024 * 1024


_MAX_RESOLVER_PACKAGES = 10_000


_MAX_TIMEOUT_SECONDS = 86_400


_MAX_TAG_VALUES = 256


_MAX_EXPANDED_TAGS = 4096


_UV_RESOLUTION_FAILURE_EXIT = 1


_PROCESS_CLEANUP_SECONDS = 1.0


_CREATE_SUSPENDED = 0x00000004


_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


_JOB_OBJECT_LIMIT_KILL_ON_CLOSE = 0x2000


_TH32CS_SNAPTHREAD = 0x00000004


_THREAD_SUSPEND_RESUME = 0x0002


_INVALID_DWORD = (1 << 32) - 1


_VERSION_COMPONENTS = 3


_TAG_COMPONENTS = 3


_PYTHON_MAJOR = 3


_MIN_STABLE_ABI_MINOR = 2


_WHEEL_PATH_PARTS = 2


_ARTIFACT_SNAPSHOT_PARTS = 2


_DYNAMIC_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9-]*\Z")


_EXTRA_FIELD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")


_SAFE_RESOLVER_PLATFORM = re.compile(r"[A-Za-z0-9_.-]+\Z")


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


_RESOLVER_VERSION = re.compile(
    r"(?P<release>[0-9]+(?:\.[0-9]+)+)"
    r"(?: \([A-Za-z0-9][A-Za-z0-9 ._+\-]*\))?\Z"
)


_LINUX_RESOLVER_PLATFORM = re.compile(
    r"(?P<machine>x86_64|aarch64|riscv64)-(?:unknown-linux-(?:gnu|musl)|"
    r"manylinux(?:2014|_[0-9]+_[0-9]+)|linux-android)\Z"
)


_WINDOWS_RESOLVER_PLATFORMS = {
    "aarch64-pc-windows-msvc": ("ARM64", "win_arm64"),
    "i686-pc-windows-msvc": ("x86", "win32"),
    "x86_64-pc-windows-msvc": ("AMD64", "win_amd64"),
}


_MACOS_RESOLVER_PLATFORMS = {
    "aarch64-apple-darwin": ("arm64", "arm64"),
    "x86_64-apple-darwin": ("x86_64", "x86_64"),
}


_SUPPORTED_UV_UNSATISFIABLE_SERIES = frozenset({(0, 11), (0, 12)})


_LEGACY_IMPLICIT_DYNAMIC_FIELDS = (
    "provides-extra",
    "requires-dist",
    "requires-python",
)


_STATIC_SDIST_METADATA_VERSION = Version("2.2")


_UV_NO_SOLUTION_HEADER = (
    "\N{MULTIPLICATION SIGN} No solution found when resolving dependencies:"
)


# Later uv 0.12 releases (reviewed at 0.12.18) print the same solver proof under
# a plain header, with "cause: " where earlier releases drew "╰─▶ ". The proof
# sentences and hints are unchanged, so this form is rewritten to the one above
# and every check after that is shared.
_UV_PLAIN_NO_SOLUTION_HEADER = "error: No solution found when resolving dependencies"


_UV_PLAIN_CAUSE_PREFIX = "cause: "


_UV_TREE_CAUSE_PREFIX = "╰─▶ "


_MIN_UNSATISFIABLE_LINES = 2


_UV_NON_SOLVER_TERMS = (
    "authentication",
    "invalid target",
    "network",
    "tool error",
    "transport",
)


_UV_ARTIFACT_AVAILABILITY_TERMS = (
    "current python version",
    "does not satisfy python",
    "has no usable wheels",
    "has no wheels with a matching",
    "is not available in the package registry",
    "requires python",
    "there is no version of",
    "was not found in the package registry",
    "was not found in the provided package locations",
)


_REVIEWED_UV_ARTIFACT_AVAILABILITY_VERSIONS = frozenset({"0.11.21", "0.12.18"})


_UV_MISSING_PACKAGE_PROOF = re.compile(
    r"\A╰─▶ Because (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*) was not found in "
    r"the provided package locations and you require (?P<requirement>.+), we "
    r"can conclude that your requirements are unsatisfiable\.\Z"
)


_UV_MISSING_VERSION_PROOF = re.compile(
    r"\A╰─▶ Because there is no version of (?P<proof>.+) and you require "
    r"(?P<requirement>.+), we can conclude that your requirements are "
    r"unsatisfiable\.\Z"
)


_UV_WRONG_ABI_PROOF = re.compile(
    r"\A╰─▶ Because (?P<proof>.+) has no wheels with a matching Python ABI "
    r"tag \(e\.g\., `[^`]+`\) and you require (?P<requirement>.+), we can "
    r"conclude that your requirements are unsatisfiable\.\Z"
)


_UV_NO_USABLE_WHEELS_PROOF = re.compile(
    r"\A╰─▶ Because (?P<proof>.+) has no usable wheels and you require "
    r"(?P<requirement>.+), we can conclude that your requirements are "
    r"unsatisfiable\.\Z"
)


_UV_WRONG_ABI_HINT = re.compile(
    r"\Ahint: You require [^,]+ \(`[^`]+`\), but we only found wheels for "
    r"`(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)` \(v(?P<version>[^)]+)\) with "
    r"the following "
    r"Python ABI tag: `[^`]+`\Z"
)


_UV_NO_USABLE_WHEELS_HINT = re.compile(
    r"\Ahint: Wheels are required for "
    r"`(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)` because building from source is "
    r"disabled for all packages \(i\.e\., with `--no-build`\)\Z"
)


_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"


_ZIP_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"


_ZIP_EOCD = struct.Struct("<4s4H2LH")


_ZIP_EOCD_SIZE = _ZIP_EOCD.size


_ZIP_MAX_COMMENT_BYTES = (1 << 16) - 1


_ZIP_CENTRAL_DIRECTORY_HEADER_SIZE = 46


_ZIP_UINT16_SENTINEL = (1 << 16) - 1


_ZIP_UINT32_SENTINEL = (1 << 32) - 1


_SUPPORTED_ZIP_COMPRESSION = frozenset(
    {
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
    }
)


_TAR_BLOCK_SIZE = 512


_TAR_READ_CHUNK_BYTES = 64 * 1024


_TAR_CONTROL_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGLINK,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.SOLARIS_XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.XHDTYPE,
    }
)


class DependencyProjectKind(StrEnum):
    """Whether dependency evidence describes an application or a library."""

    APPLICATION = "application"
    LIBRARY = "library"


class MetadataKind(StrEnum):
    """Static artifact containers whose core metadata can be read directly."""

    WHEEL = "wheel"
    SDIST = "sdist"
    CORE_METADATA = "core-metadata"


class RequiresPythonStatus(StrEnum):
    """Evaluation of an exact version's declaration against one target."""

    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNSPECIFIED = "unspecified"
    UNVERIFIED = "unverified"


class ArtifactAvailability(StrEnum):
    """Availability of a directly supplied artifact for one target."""

    AVAILABLE = "available"
    SOURCE_BUILD_POSSIBLE = "source-build-possible"
    UNAVAILABLE = "unavailable"
    UNVERIFIED = "unverified"


class DependencyCompatibilityStatus(StrEnum):
    """Non-overlapping dependency compatibility result categories."""

    COMPATIBLE = "compatible"
    DECLARED_INCOMPATIBLE = "declared-incompatible"
    ARTIFACT_UNAVAILABLE = "artifact-unavailable"
    UNVERIFIED = "unverified"


class ResolutionStatus(StrEnum):
    """Outcomes from the isolated resolver boundary."""

    NOT_REQUESTED = "not-requested"
    SUCCEEDED = "succeeded"
    ARTIFACT_UNAVAILABLE = "artifact-unavailable"
    RESOLUTION_FAILED = "resolution-failed"
    TIMED_OUT = "timed-out"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class EnvironmentTarget:
    """A declared interpreter, marker environment, and wheel target."""

    name: str
    python_full_version: str
    implementation_name: str
    implementation_version: str
    os_name: str
    sys_platform: str
    platform_machine: str
    platform_python_implementation: str
    platform_system: str
    platform_release: str
    platform_version: str
    compatible_tags: tuple[str, ...]
    resolver_platform: str

    @property
    def python_version(self) -> str:
        """Return the marker-level major/minor version."""
        release = Version(self.python_full_version).release
        return f"{release[0]}.{release[1]}"

    @cached_property
    def tags(self) -> frozenset[Tag]:
        """Return the fully expanded configured wheel-tag set."""
        return _configured_tags(
            self.compatible_tags,
            "dependency target tags",
            compressed_input=False,
        )

    def marker_environment(self, *, extra: str) -> dict[str, str]:
        """Build PEP 508 values solely from this declared target."""
        return {
            "implementation_name": self.implementation_name,
            "implementation_version": self.implementation_version,
            "os_name": self.os_name,
            "platform_machine": self.platform_machine,
            "platform_python_implementation": (self.platform_python_implementation),
            "platform_release": self.platform_release,
            "platform_system": self.platform_system,
            "platform_version": self.platform_version,
            "python_full_version": self.python_full_version,
            "python_version": self.python_version,
            "sys_platform": self.sys_platform,
            "extra": extra,
        }


@dataclass(frozen=True)
class DependencyConfiguration:
    """Strict application/library dependency evidence configuration."""

    project_kind: DependencyProjectKind
    requirements: tuple[str, ...]
    extras: tuple[str, ...]
    metadata_paths: tuple[Path, ...]
    targets: tuple[EnvironmentTarget, ...]
    resolve: bool
    network: bool
    timeout_seconds: float
    resolver: str
    index_url: str | None


@dataclass(frozen=True)
class _CanonicalResolverTarget:
    """Marker and wheel dimensions faithfully represented by uv arguments."""

    python_full_version: str
    resolver_platform: str
    implementation_name: str
    implementation_version: str
    os_name: str
    sys_platform: str
    platform_machine: str
    platform_python_implementation: str
    platform_system: str
    wheel_platform: str


@dataclass(frozen=True)
class _ClosedArtifactUnavailability:
    """One exact application pin absent from a revalidated offline wheelhouse."""

    canonical_name: str
    version: str
    requirements: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class MetadataArtifact:
    """Directly inspected immutable core metadata and artifact identity."""

    artifact_id: str
    path: PurePosixPath
    kind: MetadataKind
    name: str
    canonical_name: str
    version: str
    metadata_version: str
    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    dynamic: tuple[str, ...]
    wheel_tags: tuple[str, ...]
    metadata_path: str
    sha256: str


def _metadata_artifact_document(artifact: MetadataArtifact) -> dict[str, JsonValue]:
    """Return the complete deterministic machine projection of one artifact."""
    return {
        "artifact_id": artifact.artifact_id,
        "canonical_name": artifact.canonical_name,
        "dynamic": list(artifact.dynamic),
        "kind": artifact.kind.value,
        "metadata_path": artifact.metadata_path,
        "metadata_version": artifact.metadata_version,
        "name": artifact.name,
        "path": artifact.path.as_posix(),
        "provides_extra": list(artifact.provides_extra),
        "requires_dist": list(artifact.requires_dist),
        "requires_python": artifact.requires_python,
        "sha256": artifact.sha256,
        "version": artifact.version,
        "wheel_tags": list(artifact.wheel_tags),
    }


def _metadata_artifact_snapshot(artifact: MetadataArtifact) -> tuple[str, str]:
    """Bind an artifact identity to every field emitted in machine reports."""
    encoded = json.dumps(
        _metadata_artifact_document(artifact),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return artifact.artifact_id, hashlib.sha256(encoded).hexdigest()


def _metadata_artifact_snapshots(
    artifacts: Sequence[MetadataArtifact],
) -> tuple[tuple[str, str], ...]:
    """Return a canonical immutable projection of a staged artifact inventory."""
    return tuple(sorted(_metadata_artifact_snapshot(item) for item in artifacts))


@dataclass(frozen=True)
class MetadataIssue:
    """Incomplete direct-inspection evidence for one configured input."""

    path: PurePosixPath
    message: str


@dataclass(frozen=True)
class EvaluatedRequirement:
    """One requirement marker evaluated for one declared target."""

    requirement: str
    applies: bool
    matching_extras: tuple[str, ...]
    matching_metadata: tuple[str, ...]
    resolved_versions: tuple[str, ...]
    verified: bool
    reason: str


@dataclass(frozen=True)
class TransitiveRequirementEvidence:
    """Coverage of one active ``Requires-Dist`` entry for a target."""

    requirement: str
    required_by: tuple[str, ...]
    locked_versions: tuple[str, ...]
    matching_metadata: tuple[str, ...]
    resolved_versions: tuple[str, ...]
    verified: bool
    reason: str


@dataclass(frozen=True)
class DependencyAssessment:
    """Compatibility distinctions for one exact package version."""

    package: str
    version: str
    status: DependencyCompatibilityStatus
    requires_python_status: RequiresPythonStatus
    artifact_availability: ArtifactAvailability
    source_build_possible: bool
    metadata_used: tuple[str, ...]
    applicable_requirements: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class ResolvedPackage:
    """One exact version selected by the isolated resolver."""

    name: str
    version: str
    metadata_used: tuple[str, ...]


@dataclass(frozen=True)
class ResolverResult:
    """Bounded evidence returned by one isolated uv invocation."""

    status: ResolutionStatus
    complete: bool
    resolver: str
    resolver_version: str | None
    packages: tuple[ResolvedPackage, ...]
    reason: str


@dataclass(frozen=True)
class _UvResolverResult(ResolverResult):
    """Private uv evidence retaining only the roots its diagnostic proved."""

    verified_failure_names: tuple[str, ...] = ()
    verified_failure_requirements: tuple[str, ...] | None = None
    verified_artifact_snapshots: tuple[tuple[str, str], ...] | None = None
    verified_target_snapshot: str | None = None


def _verified_failure_names(resolution: ResolverResult) -> frozenset[str]:
    """Return validated root identities carried only by internal uv results."""
    if not isinstance(resolution, _UvResolverResult):
        return frozenset()
    names = resolution.verified_failure_names
    if (
        not names
        or names != tuple(sorted(set(names)))
        or any(not name or canonicalize_name(name) != name for name in names)
    ):
        return frozenset()
    return frozenset(names)


def _verified_failure_artifact_snapshots(
    resolution: ResolverResult,
) -> tuple[tuple[str, str], ...] | None:
    """Return the exact staged artifact snapshots carried by internal uv evidence."""
    if not isinstance(resolution, _UvResolverResult):
        return None
    snapshots = resolution.verified_artifact_snapshots
    if (
        snapshots is None
        or snapshots != tuple(sorted(set(snapshots)))
        or any(
            not isinstance(item, tuple)
            or len(item) != _ARTIFACT_SNAPSHOT_PARTS
            or _SHA256.fullmatch(item[0]) is None
            or _SHA256.fullmatch(item[1]) is None
            for item in snapshots
        )
    ):
        return None
    artifact_ids = tuple(item[0] for item in snapshots)
    if len(artifact_ids) != len(set(artifact_ids)):
        return None
    return snapshots


def _verified_failure_target_snapshot(resolution: ResolverResult) -> str | None:
    """Return the exact target snapshot carried by internal uv evidence."""
    if not isinstance(resolution, _UvResolverResult):
        return None
    snapshot = resolution.verified_target_snapshot
    return snapshot if snapshot is not None and _SHA256.fullmatch(snapshot) else None


def _failure_requirement_identities(
    requirements: Sequence[str],
    names: frozenset[str],
) -> tuple[str, ...]:
    """Return canonical marker-free requirements for the corroborated roots."""
    identities = set()
    for value in requirements:
        requirement = Requirement(value.partition(";")[0].rstrip())
        if canonicalize_name(requirement.name) in names:
            identities.add(str(requirement))
    return tuple(sorted(identities))


def _verified_failure_requirements(
    resolution: ResolverResult,
) -> frozenset[str] | None:
    """Return the exact active requirement group carried by internal uv evidence."""
    if not isinstance(resolution, _UvResolverResult):
        return None
    requirements = resolution.verified_failure_requirements
    if requirements is None or requirements != tuple(sorted(set(requirements))):
        return None
    try:
        for value in requirements:
            requirement = Requirement(value)
            if (
                requirement.marker is not None
                or requirement.url is not None
                or str(requirement) != value
            ):
                return None
    except InvalidRequirement:
        return None
    return frozenset(requirements)


class _MetadataError(ValueError):
    """Raised when an artifact cannot provide trustworthy static metadata."""


class _ResolverOutputLimitError(RuntimeError):
    """Raised when resolver stdout or stderr exceeds its retained byte limit."""


class _MarkerEvaluationLimitError(ConfigurationError):
    """Raised when dependency evaluation exhausts its shared work budget."""


def _configuration_error(label: str, message: str) -> ConfigurationError:
    detail = f"{label}: {message}"
    return ConfigurationError(detail)


def _fail_metadata(message: str) -> NoReturn:
    raise _MetadataError(message)


def _error(label: str, message: str) -> NoReturn:
    raise _configuration_error(label, message)


@dataclass
class _WorkBudget:
    """Units of work shared by every step of one public operation.

    Exhaustion empties the budget before ``exhausted`` raises, so nothing
    later in the same operation can spend what is left.
    """

    remaining: int
    exhausted: Callable[[], NoReturn]

    def consume(self, amount: int) -> None:
        if amount > self.remaining:
            self.remaining = 0
            self.exhausted()
        self.remaining -= amount


def _marker_budget_exhausted() -> NoReturn:
    message = (
        "dependency marker evaluation: exceeds the aggregate marker-evaluation budget"
    )
    raise _MarkerEvaluationLimitError(message)


def _archive_budget_exhausted() -> NoReturn:
    _fail_metadata("aggregate archive expansion exceeds the size limit")


def _metadata_requirement_budget_exhausted() -> NoReturn:
    _error(
        "tool.pyahead.dependencies.metadata",
        "exceeds the aggregate Requires-Dist limit",
    )


_ACTIVE_MARKER_BUDGET: ContextVar[_WorkBudget | None] = ContextVar(
    "pyahead_dependency_marker_budget",
    default=None,
)


_ACTIVE_ARCHIVE_BUDGET: ContextVar[_WorkBudget | None] = ContextVar(
    "pyahead_dependency_archive_budget",
    default=None,
)


_ACTIVE_METADATA_REQUIREMENT_BUDGET: ContextVar[_WorkBudget | None] = ContextVar(
    "pyahead_dependency_metadata_requirement_budget",
    default=None,
)


def _scoped_budget(
    active: ContextVar[_WorkBudget | None],
    limit: Callable[[], int],
    exhausted: Callable[[], NoReturn],
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]:
    """Give the outermost decorated call a fresh budget that nested calls share."""

    def decorate(function: Callable[_P, _R]) -> Callable[_P, _R]:
        @wraps(function)
        def bounded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            if active.get() is not None:
                return function(*args, **kwargs)
            token = active.set(_WorkBudget(limit(), exhausted))
            try:
                return function(*args, **kwargs)
            finally:
                active.reset(token)

        return bounded

    return decorate


# Limits are read when an operation starts, so tests can lower them.
_with_marker_evaluation_budget = _scoped_budget(
    _ACTIVE_MARKER_BUDGET,
    lambda: _MAX_MARKER_EVALUATIONS,
    _marker_budget_exhausted,
)


_with_archive_expansion_budget = _scoped_budget(
    _ACTIVE_ARCHIVE_BUDGET,
    lambda: _MAX_TOTAL_ARCHIVE_EXPANDED_BYTES,
    _archive_budget_exhausted,
)


# Counts parsed Requires-Dist fields even when later validation rejects them.
_with_metadata_requirement_budget = _scoped_budget(
    _ACTIVE_METADATA_REQUIREMENT_BUDGET,
    lambda: _MAX_METADATA_REQUIREMENTS,
    _metadata_requirement_budget_exhausted,
)


def _consume_dependency_work(amount: int) -> None:
    """Charge non-marker Cartesian comparisons to the same operation budget."""
    if (budget := _ACTIVE_MARKER_BUDGET.get()) is not None:
        budget.consume(amount)


def _canonical_requested_extras(
    requirements: Sequence[Requirement],
) -> frozenset[str]:
    """Normalize requested extras after charging their complete iteration cost."""
    _consume_dependency_work(
        sum(len(requirement.extras) for requirement in requirements)
    )
    return frozenset(
        canonicalize_name(extra)
        for requirement in requirements
        for extra in requirement.extras
    )


def _consume_archive_expansion(amount: int) -> None:
    if (budget := _ACTIVE_ARCHIVE_BUDGET.get()) is not None:
        budget.consume(amount)


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in value)
    ):
        qualifier = "a string" if allow_empty else "a non-empty string"
        _error(label, f"must be {qualifier} without control characters")
    return value


def _tag_expansion_count(value: str) -> int:
    """Count a compressed wheel tag's Cartesian product before expanding it."""
    components = value.split("-")
    if len(components) != _TAG_COMPONENTS or any(
        not component for component in components
    ):
        raise ValueError
    result = 1
    for component in components:
        result *= component.count(".") + 1
    return result


def _configured_tags(
    values: Sequence[str], label: str, *, compressed_input: bool
) -> frozenset[Tag]:
    """Validate and expand a bounded set of configured compatibility tags."""
    if not values:
        _error(label, "must not be empty")
    value_limit = _MAX_TAG_VALUES if compressed_input else _MAX_EXPANDED_TAGS
    if len(values) > value_limit:
        _error(label, "contains too many compatibility tags")
    if len(values) != len(set(values)):
        _error(label, "must not contain duplicate compatibility tags")
    expanded: set[Tag] = set()
    expansion_count = 0
    for value in values:
        raw = _string(value, f"{label} item")
        try:
            expanded_count = _tag_expansion_count(raw)
        except ValueError:
            _error(label, "contains an invalid compatible tag")
        expansion_count += expanded_count
        if expansion_count > _MAX_EXPANDED_TAGS:
            _error(label, "expands to too many compatibility tags")
        expanded.update(parse_tag(raw))
    return frozenset(expanded)
