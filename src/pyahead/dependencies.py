"""Opt-in M8 dependency metadata and isolated resolver evidence."""

from __future__ import annotations

import ctypes
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import tarfile
import tempfile
import threading
import tomllib
import unicodedata
import zipfile
import zlib
from contextlib import ExitStack, suppress
from contextvars import ContextVar
from ctypes import wintypes
from dataclasses import dataclass, replace
from email import policy
from email.parser import BytesParser
from enum import StrEnum
from functools import cached_property, wraps
from io import BytesIO, RawIOBase
from pathlib import Path, PurePosixPath
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    NoReturn,
    ParamSpec,
    Protocol,
    TypeAlias,
    TypeVar,
    cast,
)
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.metadata import InvalidMetadata, Metadata
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import Tag, parse_tag
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from pyahead._windows_output import read_windows_rooted_file
from pyahead.model import ConfigurationError, ExitCode

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from email.message import Message
    from types import FrameType

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
    "has no wheels with a matching",
    "is not available in the package registry",
    "requires python",
    "there is no version of",
    "was not found in the package registry",
    "was not found in the provided package locations",
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
class _DependencyInputs:
    project_kind: DependencyProjectKind
    requirements: tuple[str, ...]
    extras: tuple[str, ...]
    metadata: tuple[Path, ...]
    targets: tuple[EnvironmentTarget, ...]


@dataclass(frozen=True)
class _DependencyControls:
    resolve: bool
    network: bool
    timeout: float
    resolver: str
    index_url: str | None


@dataclass(frozen=True)
class _ParsedCoreMetadata:
    name: str
    version: Version
    metadata_version: str
    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    dynamic: tuple[str, ...]


@dataclass(frozen=True)
class _ResolverWorkspace:
    executable: str
    directory: Path
    requirements: Path
    output: Path
    wheelhouse: Path


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
class _ResolverInterpretationContext:
    version: str
    workspace: _ResolverWorkspace
    artifacts: Sequence[MetadataArtifact]
    requirements: Sequence[str]


@dataclass(frozen=True)
class _ArtifactSelection:
    matching_wheels: tuple[MetadataArtifact, ...]
    wheels: tuple[MetadataArtifact, ...]
    sdists: tuple[MetadataArtifact, ...]
    raw_metadata: tuple[MetadataArtifact, ...]
    semantic_metadata: tuple[MetadataArtifact, ...]


@dataclass(frozen=True)
class _TransitiveCoverage:
    project_kind: DependencyProjectKind
    resolution: ResolverResult
    resolved_versions: tuple[str, ...]
    lock_requirements: tuple[Requirement, ...]
    common_lock_versions: frozenset[Version]
    matching_metadata: tuple[str, ...]


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


class ResolverAdapter(Protocol):
    """Replaceable dependency resolver boundary."""

    name: str

    def resolve(
        self,
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        """Resolve one explicitly declared environment target."""
        ...


@dataclass(frozen=True)
class TargetDependencyResult:
    """Metadata and resolver evidence for one environment target."""

    target: EnvironmentTarget
    declared_requirements: tuple[EvaluatedRequirement, ...]
    transitive_requirements: tuple[TransitiveRequirementEvidence, ...]
    assessments: tuple[DependencyAssessment, ...]
    resolution: ResolverResult


@dataclass(frozen=True)
class DependencyReport:
    """Deterministic M8 report independent from the static finding gate."""

    schema_version: int
    project_kind: DependencyProjectKind
    resolve: bool
    network: bool
    timeout_seconds: float
    resolver: str
    index_url: str | None
    requirements: tuple[str, ...]
    extras: tuple[str, ...]
    metadata: tuple[MetadataArtifact, ...]
    metadata_issues: tuple[MetadataIssue, ...]
    targets: tuple[TargetDependencyResult, ...]

    @property
    def exit_code(self) -> ExitCode:
        """Map compatibility and incomplete evidence to stable CLI outcomes."""
        incomplete = bool(self.metadata_issues)
        incompatible = False
        for result in self.targets:
            incomplete = incomplete or not result.resolution.complete
            incomplete = incomplete or any(
                item.applies and not item.verified
                for item in result.declared_requirements
            )
            incomplete = incomplete or any(
                not item.verified for item in result.transitive_requirements
            )
            incomplete = incomplete or result.resolution.status in {
                ResolutionStatus.TIMED_OUT,
                ResolutionStatus.UNVERIFIED,
            }
            incompatible = incompatible or result.resolution.status in {
                ResolutionStatus.ARTIFACT_UNAVAILABLE,
                ResolutionStatus.RESOLUTION_FAILED,
            }
            for assessment in result.assessments:
                incomplete = incomplete or assessment.status is (
                    DependencyCompatibilityStatus.UNVERIFIED
                )
                incompatible = incompatible or assessment.status in {
                    DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE,
                    DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE,
                }
        if incomplete:
            return ExitCode.INCOMPLETE
        if incompatible:
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS


class _MetadataError(ValueError):
    """Raised when an artifact cannot provide trustworthy static metadata."""


class _ResolverOutputLimitError(RuntimeError):
    """Raised when resolver stdout or stderr exceeds its retained byte limit."""


class _ResolverPipeError(OSError):
    """Raised when inherited resolver output pipes remain open after exit."""


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
class _MarkerEvaluationBudget:
    remaining: int

    def consume(self, amount: int) -> None:
        if amount > self.remaining:
            message = (
                "dependency marker evaluation: exceeds the aggregate "
                "marker-evaluation budget"
            )
            raise _MarkerEvaluationLimitError(message)
        self.remaining -= amount


_ACTIVE_MARKER_BUDGET: ContextVar[_MarkerEvaluationBudget | None] = ContextVar(
    "pyahead_dependency_marker_budget",
    default=None,
)


@dataclass
class _ArchiveExpansionBudget:
    remaining: int

    def consume(self, amount: int) -> None:
        if amount > self.remaining:
            self.remaining = 0
            _fail_metadata("aggregate archive expansion exceeds the size limit")
        self.remaining -= amount


_ACTIVE_ARCHIVE_BUDGET: ContextVar[_ArchiveExpansionBudget | None] = ContextVar(
    "pyahead_dependency_archive_budget",
    default=None,
)


@dataclass
class _MetadataRequirementBudget:
    remaining: int

    def consume(self, amount: int) -> None:
        if amount > self.remaining:
            self.remaining = 0
            _error(
                "tool.pyahead.dependencies.metadata",
                "exceeds the aggregate Requires-Dist limit",
            )
        self.remaining -= amount


_ACTIVE_METADATA_REQUIREMENT_BUDGET: ContextVar[_MetadataRequirementBudget | None] = (
    ContextVar(
        "pyahead_dependency_metadata_requirement_budget",
        default=None,
    )
)


def _with_marker_evaluation_budget(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Share one runtime marker budget across a complete public operation."""

    @wraps(function)
    def bounded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        if _ACTIVE_MARKER_BUDGET.get() is not None:
            return function(*args, **kwargs)
        token = _ACTIVE_MARKER_BUDGET.set(
            _MarkerEvaluationBudget(_MAX_MARKER_EVALUATIONS)
        )
        try:
            return function(*args, **kwargs)
        finally:
            _ACTIVE_MARKER_BUDGET.reset(token)

    return bounded


def _with_archive_expansion_budget(function: Callable[_P, _R]) -> Callable[_P, _R]:
    """Share one decompression budget across every artifact in an inspection."""

    @wraps(function)
    def bounded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        if _ACTIVE_ARCHIVE_BUDGET.get() is not None:
            return function(*args, **kwargs)
        token = _ACTIVE_ARCHIVE_BUDGET.set(
            _ArchiveExpansionBudget(_MAX_TOTAL_ARCHIVE_EXPANDED_BYTES)
        )
        try:
            return function(*args, **kwargs)
        finally:
            _ACTIVE_ARCHIVE_BUDGET.reset(token)

    return bounded


def _with_metadata_requirement_budget(
    function: Callable[_P, _R],
) -> Callable[_P, _R]:
    """Count parsed Requires-Dist fields even when later validation rejects."""

    @wraps(function)
    def bounded(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        if _ACTIVE_METADATA_REQUIREMENT_BUDGET.get() is not None:
            return function(*args, **kwargs)
        token = _ACTIVE_METADATA_REQUIREMENT_BUDGET.set(
            _MetadataRequirementBudget(_MAX_METADATA_REQUIREMENTS)
        )
        try:
            return function(*args, **kwargs)
        finally:
            _ACTIVE_METADATA_REQUIREMENT_BUDGET.reset(token)

    return bounded


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


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _error(label, "must be a TOML table")
    return value


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


def _runtime_version(value: object, label: str, *, python: bool) -> Version:
    """Parse a concrete interpreter version without impossible PEP 440 forms."""
    raw = _string(value, label)
    try:
        parsed = Version(raw)
    except InvalidVersion as error:
        _error(label, f"contains an invalid version: {error}")
    if (
        len(parsed.release) != _VERSION_COMPONENTS
        or parsed.epoch != 0
        or parsed.local is not None
        or parsed.post is not None
        or parsed.dev is not None
        or (python and parsed.release[0] != _PYTHON_MAJOR)
    ):
        qualifier = "Python " if python else ""
        _error(
            label,
            f"must be a concrete {qualifier}runtime version with three release "
            "components and no epoch, local, post, or dev segment",
        )
    return parsed


def _string_list(
    value: object,
    label: str,
    *,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _error(label, "must be an array")
    if max_items is not None and len(value) > max_items:
        _error(label, "contains too many items")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(result) != len(set(result)):
        _error(label, "must not contain duplicates")
    return result


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


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        _error(label, "must be a boolean")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        _error(label, "must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > _MAX_TIMEOUT_SECONDS:
        _error(
            label,
            f"must be a finite positive number no greater than {_MAX_TIMEOUT_SECONDS}",
        )
    return result


def _parse_target(value: object, index: int) -> EnvironmentTarget:
    label = f"tool.pyahead.dependencies.targets[{index}]"
    target = _table(value, label)
    keys = set(target)
    if not _TARGET_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        _TARGET_REQUIRED_KEYS | _TARGET_OPTIONAL_KEYS
    ):
        _error(label, "has unknown or missing keys")
    python_parsed = _runtime_version(
        target["python-full-version"],
        f"{label}.python-full-version",
        python=True,
    )
    implementation_parsed = _runtime_version(
        target["implementation-version"],
        f"{label}.implementation-version",
        python=False,
    )
    compatible_tags = _string_list(
        target["compatible-tags"],
        f"{label}.compatible-tags",
        max_items=_MAX_TAG_VALUES,
    )
    expanded_tags = {
        str(tag)
        for tag in _configured_tags(
            compatible_tags,
            f"{label}.compatible-tags",
            compressed_input=True,
        )
    }
    resolver_platform = _string(
        target["resolver-platform"], f"{label}.resolver-platform"
    )
    if _SAFE_RESOLVER_PLATFORM.fullmatch(resolver_platform) is None:
        _error(label, "resolver-platform contains unsupported characters")
    parsed_target = EnvironmentTarget(
        name=_string(target["name"], f"{label}.name"),
        python_full_version=str(python_parsed),
        implementation_name=_string(
            target["implementation-name"], f"{label}.implementation-name"
        ),
        implementation_version=str(implementation_parsed),
        os_name=_string(target["os-name"], f"{label}.os-name"),
        sys_platform=_string(target["sys-platform"], f"{label}.sys-platform"),
        platform_machine=_string(
            target["platform-machine"], f"{label}.platform-machine"
        ),
        platform_python_implementation=_string(
            target["platform-python-implementation"],
            f"{label}.platform-python-implementation",
        ),
        platform_system=_string(target["platform-system"], f"{label}.platform-system"),
        platform_release=_string(
            target.get("platform-release", ""),
            f"{label}.platform-release",
            allow_empty=True,
        ),
        platform_version=_string(
            target.get("platform-version", ""),
            f"{label}.platform-version",
            allow_empty=True,
        ),
        compatible_tags=tuple(sorted(expanded_tags)),
        resolver_platform=resolver_platform,
    )
    _ensure_target_coherence(parsed_target, label=label)
    return parsed_target


def _parse_requirements(
    values: tuple[str, ...], project_kind: DependencyProjectKind
) -> tuple[str, ...]:
    if len(values) > _MAX_REQUIREMENTS:
        _error("tool.pyahead.dependencies.requirements", "contains too many items")
    parsed: list[str] = []
    for value in values:
        try:
            requirement = Requirement(value)
        except InvalidRequirement as error:
            _error("tool.pyahead.dependencies.requirements", str(error))
        if len(requirement.extras) > _MAX_EXTRAS:
            _error(
                "tool.pyahead.dependencies.requirements",
                "a requirement requests too many extras",
            )
        if requirement.url is not None:
            _error(
                "tool.pyahead.dependencies.requirements",
                "direct URL requirements are outside the isolated index adapter",
            )
        if project_kind is DependencyProjectKind.APPLICATION:
            specifiers = tuple(requirement.specifier)
            if (
                len(specifiers) != 1
                or specifiers[0].operator != "=="
                or specifiers[0].version.endswith(".*")
            ):
                _error(
                    "tool.pyahead.dependencies.requirements",
                    "application requirements must use one exact == version pin",
                )
        parsed.append(str(requirement))
    return tuple(parsed)


def _marker_evaluation_units(requirements: Sequence[str], extras: Sequence[str]) -> int:
    """Return the maximum marker evaluations needed for one target and pass."""
    contexts = max(1, len(extras))
    marked = sum(Requirement(value).marker is not None for value in requirements)
    return len(requirements) + marked * (contexts - 1)


def _ensure_marker_evaluation_budget(
    requirement_groups: Sequence[tuple[Sequence[str], int]],
    *,
    extras: Sequence[str],
    target_count: int,
    label: str,
) -> None:
    """Reject valid-looking inputs whose Cartesian marker work is excessive."""
    evaluations = target_count * sum(
        passes * _marker_evaluation_units(requirements, extras)
        for requirements, passes in requirement_groups
    )
    if evaluations > _MAX_MARKER_EVALUATIONS:
        _error(label, "exceeds the aggregate marker-evaluation budget")


def _index_url(value: object) -> str | None:
    if value is None:
        return None
    url = _string(value, "tool.pyahead.dependencies.index-url")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        _error(
            "tool.pyahead.dependencies.index-url",
            "must be a valid HTTP(S) URL",
        )
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 0
        or parsed.netloc.endswith(":")
        or "\\" in url
        or any(character.isspace() for character in url)
    ):
        _error(
            "tool.pyahead.dependencies.index-url",
            "must be an HTTP(S) URL without embedded credentials, query, or fragment",
        )
    return url


def _rooted_directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _rooted_file_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _supports_rooted_descriptor_reads() -> bool:
    return bool(
        os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right)


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare identity and mutation-sensitive regular-file attributes."""
    return _same_file(left, right) and all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


@dataclass(frozen=True)
class _RootedReadChain:
    root: Path
    descriptors: tuple[int, ...]
    statuses: tuple[os.stat_result, ...]
    names: tuple[str, ...]

    def validate(
        self,
        leaf_name: str,
        leaf_status: os.stat_result,
        leaf_descriptor: int,
    ) -> None:
        """Reject any path binding changed while its descriptors were pinned."""
        current_root = self.root.lstat()
        if not stat.S_ISDIR(current_root.st_mode) or not _same_file(
            current_root, self.statuses[0]
        ):
            message = "input root changed while being read"
            raise OSError(message)
        for index, name in enumerate(self.names, start=1):
            current = os.stat(
                name,
                dir_fd=self.descriptors[index - 1],
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(current.st_mode) or not _same_file(
                current, self.statuses[index]
            ):
                message = "input parent changed while being read"
                raise OSError(message)
        current_leaf = os.stat(
            leaf_name,
            dir_fd=self.descriptors[-1],
            follow_symlinks=False,
        )
        opened_leaf = os.fstat(leaf_descriptor)
        if not stat.S_ISREG(current_leaf.st_mode) or not (
            _same_stable_file(current_leaf, leaf_status)
            and _same_stable_file(opened_leaf, leaf_status)
        ):
            message = "input file changed while being read"
            raise OSError(message)


def _read_posix_rooted_file(root: Path, relative: Path, limit: int) -> bytes:
    if not _supports_rooted_descriptor_reads():
        message = "secure root-bounded input APIs are unavailable"
        raise OSError(message)
    with ExitStack() as cleanup:
        descriptors: list[int] = []
        statuses: list[os.stat_result] = []
        names: list[str] = []
        expected_root = root.lstat()
        root_descriptor = os.open(root, _rooted_directory_flags())
        cleanup.callback(os.close, root_descriptor)
        descriptors.append(root_descriptor)
        opened_root = os.fstat(root_descriptor)
        if not stat.S_ISDIR(opened_root.st_mode) or not _same_file(
            expected_root, opened_root
        ):
            message = "input root changed while being opened"
            raise OSError(message)
        statuses.append(opened_root)
        for name in relative.parent.parts:
            descriptor = os.open(
                name,
                _rooted_directory_flags(),
                dir_fd=descriptors[-1],
            )
            cleanup.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode):
                message = "input parents must be real directories"
                raise OSError(message)
            descriptors.append(descriptor)
            statuses.append(opened)
            names.append(name)
        expected_leaf = os.stat(
            relative.name,
            dir_fd=descriptors[-1],
            follow_symlinks=False,
        )
        if not stat.S_ISREG(expected_leaf.st_mode):
            message = "input must be a real regular file"
            raise OSError(message)
        descriptor = os.open(
            relative.name,
            _rooted_file_flags(),
            dir_fd=descriptors[-1],
        )
        cleanup.callback(os.close, descriptor)
        opened_leaf = os.fstat(descriptor)
        if not stat.S_ISREG(opened_leaf.st_mode) or not _same_file(
            expected_leaf, opened_leaf
        ):
            message = "input file changed while being opened"
            raise OSError(message)
        remaining = limit + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(_TAR_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        chain = _RootedReadChain(
            root=root,
            descriptors=tuple(descriptors),
            statuses=tuple(statuses),
            names=tuple(names),
        )
        chain.validate(relative.name, opened_leaf, descriptor)
        return b"".join(chunks)


def _read_rooted_file(root: Path, relative: Path, limit: int) -> bytes:
    if relative.is_absolute() or relative == Path() or not relative.name:
        message = "input must name a file beneath the trusted root"
        raise OSError(message)
    if ".." in relative.parts:
        message = "input must remain beneath the trusted root"
        raise OSError(message)
    if _supports_rooted_descriptor_reads():
        return _read_posix_rooted_file(root, relative, limit)
    if os.name == "nt":
        return read_windows_rooted_file(root, relative, limit)
    message = "secure root-bounded input APIs are unavailable"
    raise OSError(message)


def _read_dependency_document(
    root: Path, relative: Path, label: str
) -> dict[str, object]:
    """Read one stable regular TOML file through a root-anchored descriptor."""
    try:
        raw_document = _read_rooted_file(root, relative, _MAX_CONFIGURATION_BYTES)
    except (OSError, RuntimeError, ValueError) as error:
        detail = str(error)
        if "regular file" in detail:
            message = "configuration is not a regular file"
        elif "changed while" in detail:
            message = "configuration changed while being read"
        else:
            message = "unable to read configuration"
        raise _configuration_error(label, message) from error
    if len(raw_document) > _MAX_CONFIGURATION_BYTES:
        _error(label, "configuration exceeds the size limit")
    try:
        return tomllib.loads(raw_document.decode("utf-8", errors="strict"))
    except RecursionError as error:
        raise _configuration_error(
            label, "configuration nesting is too deep"
        ) from error
    except UnicodeError as error:
        raise _configuration_error(
            label, "configuration is not valid UTF-8 TOML"
        ) from error
    except tomllib.TOMLDecodeError as error:
        raise _configuration_error(label, "configuration is not valid TOML") from error


def _read_dependency_table(
    root: Path,
    config_path: Path | None = None,
) -> dict[str, object]:
    label = "dependency configuration"
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        label = "dependency root"
        message = "does not exist"
        raise _configuration_error(label, message) from error
    selected = config_path or (resolved_root / "pyproject.toml")
    if not selected.is_absolute():
        selected = resolved_root / selected
    try:
        resolved = selected.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except FileNotFoundError as error:
        raise _configuration_error(label, "file does not exist") from error
    except (OSError, RuntimeError, ValueError) as error:
        raise _configuration_error(
            label, "unable to read configuration beneath the root"
        ) from error
    document = _read_dependency_document(
        resolved_root,
        resolved.relative_to(resolved_root),
        label,
    )

    tool = _table(document.get("tool", {}), f"{label}:tool")
    pyahead = _table(tool.get("pyahead", {}), f"{label}:tool.pyahead")
    raw = pyahead.get("dependencies")
    if raw is None:
        _error(label, "[tool.pyahead.dependencies] is required")
    table = _table(raw, f"{label}:tool.pyahead.dependencies")
    unknown = sorted(set(table).difference(_DEPENDENCY_KEYS))
    if unknown:
        _error(
            label,
            "unknown [tool.pyahead.dependencies] key(s): "
            + ", ".join(repr(item) for item in unknown),
        )
    return table


def _dependency_inputs(table: dict[str, object]) -> _DependencyInputs:
    try:
        project_kind = DependencyProjectKind(
            _string(
                table.get("project-kind"),
                "tool.pyahead.dependencies.project-kind",
            )
        )
    except ValueError:
        _error(
            "tool.pyahead.dependencies.project-kind",
            "must be 'application' or 'library'",
        )
    requirements = _parse_requirements(
        _string_list(
            table.get("requirements", []),
            "tool.pyahead.dependencies.requirements",
            max_items=_MAX_REQUIREMENTS,
        ),
        project_kind,
    )
    raw_extras = _string_list(
        table.get("extras", []),
        "tool.pyahead.dependencies.extras",
        max_items=_MAX_EXTRAS,
    )
    if len(raw_extras) > _MAX_EXTRAS:
        _error("tool.pyahead.dependencies.extras", "contains too many items")
    if any(_EXTRA_FIELD.fullmatch(extra) is None for extra in raw_extras):
        _error(
            "tool.pyahead.dependencies.extras",
            "contains an invalid normalized extra name",
        )
    extras = tuple(sorted(canonicalize_name(extra) for extra in raw_extras))
    if len(extras) != len(set(extras)):
        _error(
            "tool.pyahead.dependencies.extras",
            "must not contain duplicate normalized names",
        )
    metadata = tuple(
        Path(item)
        for item in _string_list(
            table.get("metadata", []),
            "tool.pyahead.dependencies.metadata",
            max_items=_MAX_METADATA_INPUTS,
        )
    )
    if len(metadata) > _MAX_METADATA_INPUTS:
        _error("tool.pyahead.dependencies.metadata", "contains too many items")
    targets_raw = table.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        _error("tool.pyahead.dependencies.targets", "must be a non-empty array")
    if len(targets_raw) > _MAX_TARGETS:
        _error("tool.pyahead.dependencies.targets", "contains too many items")
    targets = tuple(
        _parse_target(item, index) for index, item in enumerate(targets_raw)
    )
    target_names = tuple(target.name for target in targets)
    if len(target_names) != len(set(target_names)):
        _error("tool.pyahead.dependencies.targets", "names must be unique")
    if not requirements and not metadata:
        _error(
            "tool.pyahead.dependencies",
            "must declare requirements or metadata inputs",
        )
    return _DependencyInputs(
        project_kind=project_kind,
        requirements=requirements,
        extras=extras,
        metadata=metadata,
        targets=targets,
    )


def _dependency_controls(
    table: dict[str, object],
    inputs: _DependencyInputs,
    *,
    network_override: bool | None,
    resolve_override: bool | None,
    timeout_override: float | None,
) -> _DependencyControls:
    configured_network = _boolean(
        table.get("network", False), "tool.pyahead.dependencies.network"
    )
    network = configured_network if network_override is None else network_override
    configured_resolve = _boolean(
        table.get("resolve", False), "tool.pyahead.dependencies.resolve"
    )
    resolve = configured_resolve if resolve_override is None else resolve_override
    timeout = (
        _positive_number(
            table.get("timeout-seconds", 30),
            "tool.pyahead.dependencies.timeout-seconds",
        )
        if timeout_override is None
        else _positive_number(timeout_override, "--timeout-seconds")
    )
    resolver = _string(
        table.get("resolver", "uv"), "tool.pyahead.dependencies.resolver"
    )
    if resolver != "uv":
        _error("tool.pyahead.dependencies.resolver", "only 'uv' is supported")
    configured_index_url = _index_url(table.get("index-url"))
    if network and configured_index_url is None:
        _error(
            "tool.pyahead.dependencies.index-url",
            "is required when network access is enabled",
        )
    index_url = configured_index_url if network else None
    if resolve and not inputs.requirements:
        _error("tool.pyahead.dependencies.resolve", "requires requirements")
    if resolve and not network and not inputs.metadata:
        _error(
            "tool.pyahead.dependencies.resolve",
            "offline resolution requires an explicit metadata artifact set",
        )
    if not resolve and not inputs.metadata:
        _error(
            "tool.pyahead.dependencies.metadata",
            "is required when the resolver is not enabled",
        )
    return _DependencyControls(
        resolve=resolve,
        network=network,
        timeout=timeout,
        resolver=resolver,
        index_url=index_url,
    )


def load_dependency_configuration(
    root: Path,
    config_path: Path | None = None,
    *,
    network_override: bool | None = None,
    resolve_override: bool | None = None,
    timeout_override: float | None = None,
) -> DependencyConfiguration:
    """Load strict M8 configuration without using host environment defaults."""
    table = _read_dependency_table(root, config_path)
    inputs = _dependency_inputs(table)
    controls = _dependency_controls(
        table,
        inputs,
        network_override=network_override,
        resolve_override=resolve_override,
        timeout_override=timeout_override,
    )
    configuration = DependencyConfiguration(
        project_kind=inputs.project_kind,
        requirements=inputs.requirements,
        extras=inputs.extras,
        metadata_paths=inputs.metadata,
        targets=inputs.targets,
        resolve=controls.resolve,
        network=controls.network,
        timeout_seconds=controls.timeout,
        resolver=controls.resolver,
        index_url=controls.index_url,
    )
    return _validate_dependency_configuration(configuration)


def _resolved_dependency_root(root: object) -> Path:
    if not isinstance(root, Path):
        _error("dependency root", "must be a path to an existing directory")
    try:
        resolved = root.resolve(strict=True)
        status = resolved.stat()
    except (OSError, RuntimeError) as error:
        label = "dependency root"
        message = "must be a path to an existing directory"
        raise _configuration_error(label, message) from error
    if not stat.S_ISDIR(status.st_mode):
        _error("dependency root", "must be a path to an existing directory")
    return resolved


def _read_artifact(path: Path, root: Path) -> tuple[PurePosixPath, bytes]:
    label = "metadata input"
    selected = path if path.is_absolute() else root / path
    try:
        resolved = selected.resolve(strict=True)
        rooted_relative = resolved.relative_to(root)
        relative_text = rooted_relative.as_posix()
        _string(relative_text, "resolved metadata input path")
        relative = PurePosixPath(relative_text)
        if rooted_relative == Path() or not rooted_relative.name:
            _error(label, "is not a regular file")
        raw = _read_rooted_file(root, rooted_relative, _MAX_ARTIFACT_BYTES)
    except FileNotFoundError as error:
        raise _configuration_error(label, "does not exist") from error
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        raise _configuration_error(
            label, "must remain beneath the project root"
        ) from error
    except (OSError, RuntimeError) as error:
        message = (
            "metadata input changed while being read"
            if "changed while" in str(error)
            else "unable to read metadata input"
        )
        raise _configuration_error(label, message) from error
    if len(raw) > _MAX_ARTIFACT_BYTES:
        raise _configuration_error(
            label,
            f"exceeds {_MAX_ARTIFACT_BYTES} bytes",
        )
    return relative, raw


class _ExpandedArchiveReader(RawIOBase):
    """Cap bytes returned from an incrementally decompressed archive stream."""

    def __init__(self, stream: gzip.GzipFile) -> None:
        self._stream = stream
        self._read = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining_with_sentinel = _MAX_ARCHIVE_EXPANDED_BYTES - self._read + 1
        bounded_size = (
            remaining_with_sentinel
            if size < 0 or size > remaining_with_sentinel
            else size
        )
        if (budget := _ACTIVE_ARCHIVE_BUDGET.get()) is not None:
            bounded_size = min(bounded_size, budget.remaining + 1)
        payload = self._stream.read(bounded_size)
        self._read += len(payload)
        _consume_archive_expansion(len(payload))
        if self._read > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        return payload


def _read_exact_archive_bytes(stream: _ExpandedArchiveReader, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        payload = stream.read(min(remaining, _TAR_READ_CHUNK_BYTES))
        if not payload:
            _fail_metadata("invalid tar archive")
        chunks.append(payload)
        remaining -= len(payload)
    return b"".join(chunks)


def _discard_archive_bytes(stream: _ExpandedArchiveReader, size: int) -> None:
    remaining = size
    while remaining:
        payload = stream.read(min(remaining, _TAR_READ_CHUNK_BYTES))
        if not payload:
            _fail_metadata("invalid tar archive")
        remaining -= len(payload)


def _pax_uses_gnu_sparse(payload: bytes) -> bool:
    cursor = 0
    while cursor < len(payload):
        separator = payload.find(b" ", cursor)
        if separator <= cursor or not payload[cursor:separator].isdigit():
            _fail_metadata("invalid tar control metadata")
        record_size = int(payload[cursor:separator])
        record_end = cursor + record_size
        if (
            record_end <= separator + 1
            or record_end > len(payload)
            or payload[record_end - 1 : record_end] != b"\n"
        ):
            _fail_metadata("invalid tar control metadata")
        key, delimiter, _value = payload[separator + 1 : record_end - 1].partition(b"=")
        if not delimiter:
            _fail_metadata("invalid tar control metadata")
        if key.startswith(b"GNU.sparse."):
            return True
        cursor = record_end
    return False


def _tar_member_padded_size(member: tarfile.TarInfo) -> int:
    if member.type == tarfile.GNUTYPE_SPARSE:
        _fail_metadata("sparse tar members are unsupported")
    if member.size < 0:
        _fail_metadata("tar member has a negative size")
    if member.type in _TAR_CONTROL_TYPES and member.size > _MAX_TAR_CONTROL_BYTES:
        _fail_metadata("tar control metadata exceeds the size limit")
    return ((member.size + _TAR_BLOCK_SIZE - 1) // _TAR_BLOCK_SIZE) * _TAR_BLOCK_SIZE


def _discard_tar_member_payload(
    stream: _ExpandedArchiveReader,
    member: tarfile.TarInfo,
    padded_size: int,
) -> None:
    if member.type in {
        tarfile.SOLARIS_XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.XHDTYPE,
    }:
        control = _read_exact_archive_bytes(stream, member.size)
        if _pax_uses_gnu_sparse(control):
            _fail_metadata("GNU sparse tar metadata is unsupported")
        _discard_archive_bytes(stream, padded_size - member.size)
        return
    _discard_archive_bytes(stream, padded_size)


def _check_tar_archive_limits(raw: bytes) -> None:
    """Preflight physical tar headers before tarfile processes control records."""
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as decompressed:
            bounded = _ExpandedArchiveReader(decompressed)
            member_count = 0
            declared_bytes = 0
            while True:
                header = _read_exact_archive_bytes(bounded, _TAR_BLOCK_SIZE)
                if header == b"\0" * _TAR_BLOCK_SIZE:
                    return
                member = tarfile.TarInfo.frombuf(
                    header,
                    encoding="utf-8",
                    errors="surrogateescape",
                )
                member_count += 1
                if member_count > _MAX_ARCHIVE_MEMBERS:
                    _fail_metadata("archive contains too many members")
                padded_size = _tar_member_padded_size(member)
                declared_bytes += _TAR_BLOCK_SIZE + padded_size
                if declared_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
                    _fail_metadata("archive expanded data exceeds the size limit")
                _discard_tar_member_payload(bounded, member, padded_size)
    except _MetadataError:
        raise
    except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError, zlib.error):
        _fail_metadata("invalid tar archive")


def _zip_eocd(raw: bytes) -> tuple[int, tuple[int, ...]]:
    search_start = max(
        0,
        len(raw) - _ZIP_EOCD_SIZE - _ZIP_MAX_COMMENT_BYTES,
    )
    cursor = len(raw)
    while True:
        offset = raw.rfind(_ZIP_EOCD_SIGNATURE, search_start, cursor)
        if offset < 0:
            _fail_metadata("invalid ZIP archive")
        if offset + _ZIP_EOCD_SIZE <= len(raw):
            record = _ZIP_EOCD.unpack_from(raw, offset)
            comment_size = record[-1]
            if offset + _ZIP_EOCD_SIZE + comment_size == len(raw):
                return offset, tuple(record[1:])
        cursor = offset


def _check_zip_directory_budgets(total_entries: int, directory_size: int) -> None:
    if total_entries > _MAX_ARCHIVE_MEMBERS:
        _fail_metadata("archive contains too many members")
    if directory_size > _MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        _fail_metadata("ZIP central directory exceeds the size limit")


def _check_zip_archive_limits(raw: bytes) -> None:
    """Validate a bounded non-ZIP64 directory before ZipFile allocates entries."""
    eocd_offset, record = _zip_eocd(raw)
    (
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        _comment_size,
    ) = record
    if (
        disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or total_entries == _ZIP_UINT16_SENTINEL
        or _ZIP_UINT32_SENTINEL in {directory_size, directory_offset}
    ):
        _fail_metadata("unsupported multi-disk or ZIP64 archive")
    _check_zip_directory_budgets(total_entries, directory_size)
    directory_end = directory_offset + directory_size
    if directory_end != eocd_offset:
        _fail_metadata("invalid ZIP archive")

    cursor = directory_offset
    counted_entries = 0
    expanded_bytes = 0
    while cursor < directory_end:
        if (
            cursor + _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE > directory_end
            or raw[cursor : cursor + 4] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE
        ):
            _fail_metadata("invalid ZIP archive")
        compressed_size = struct.unpack_from("<L", raw, cursor + 20)[0]
        compression = struct.unpack_from("<H", raw, cursor + 10)[0]
        uncompressed_size, name_size, extra_size, comment_size = struct.unpack_from(
            "<L3H", raw, cursor + 24
        )
        disk_start = struct.unpack_from("<H", raw, cursor + 34)[0]
        local_header_offset = struct.unpack_from("<L", raw, cursor + 42)[0]
        if (
            _ZIP_UINT32_SENTINEL
            in {
                compressed_size,
                uncompressed_size,
                local_header_offset,
            }
            or disk_start != 0
        ):
            _fail_metadata("unsupported multi-disk or ZIP64 archive member")
        if compression not in _SUPPORTED_ZIP_COMPRESSION:
            _fail_metadata("unsupported ZIP compression method")
        counted_entries += 1
        if counted_entries > _MAX_ARCHIVE_MEMBERS:
            _fail_metadata("archive contains too many members")
        expanded_bytes += uncompressed_size
        if expanded_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        cursor += (
            _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + name_size + extra_size + comment_size
        )
    if cursor != directory_end or counted_entries != total_entries:
        _fail_metadata("invalid ZIP archive")


def _zip_metadata(raw: bytes, suffix: str) -> tuple[str, bytes]:
    _check_zip_archive_limits(raw)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                _fail_metadata("archive contains too many members")
            candidates = sorted(
                (
                    item
                    for item in members
                    if not item.is_dir() and item.filename.endswith(suffix)
                ),
                key=lambda item: item.filename,
            )
            if len(candidates) != 1:
                message = f"archive must contain exactly one {suffix}"
                _fail_metadata(message)
            selected = candidates[0]
            if selected.file_size > _MAX_METADATA_BYTES:
                _fail_metadata("core metadata exceeds the size limit")
            with archive.open(selected) as stream:
                payload = stream.read(_MAX_METADATA_BYTES + 1)
            _consume_archive_expansion(len(payload))
            if len(payload) > _MAX_METADATA_BYTES:
                _fail_metadata("core metadata exceeds the size limit")
            return selected.filename, payload
    except _MetadataError:
        raise
    except (
        EOFError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        _fail_metadata("invalid ZIP archive")


def _read_tar_metadata_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo
) -> bytes:
    if member.size > _MAX_METADATA_BYTES:
        _fail_metadata("core metadata exceeds the size limit")
    stream = archive.extractfile(member)
    if stream is None:
        _fail_metadata("unable to read PKG-INFO")
    payload = stream.read(_MAX_METADATA_BYTES + 1)
    if len(payload) > _MAX_METADATA_BYTES:
        _fail_metadata("core metadata exceeds the size limit")
    return payload


def _read_tar_metadata(archive: tarfile.TarFile) -> tuple[str, bytes]:
    selected_name: str | None = None
    selected_payload: bytes | None = None
    member_count = 0
    declared_bytes = 0
    while (member := archive.next()) is not None:
        archive.members.clear()  # type: ignore[attr-defined]
        member_count += 1
        if member_count > _MAX_ARCHIVE_MEMBERS:
            _fail_metadata("archive contains too many members")
        if member.size < 0:
            _fail_metadata("tar member has a negative size")
        declared_bytes += member.size
        if declared_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        if not member.isfile() or not member.name.endswith("/PKG-INFO"):
            continue
        if selected_name is not None:
            _fail_metadata("archive must contain exactly one PKG-INFO")
        selected_name = member.name
        selected_payload = _read_tar_metadata_member(archive, member)
    if selected_name is None or selected_payload is None:
        _fail_metadata("archive must contain exactly one PKG-INFO")
    return selected_name, selected_payload


def _tar_metadata(raw: bytes) -> tuple[str, bytes]:
    _check_tar_archive_limits(raw)
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as decompressed:
            bounded = _ExpandedArchiveReader(decompressed)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                return _read_tar_metadata(archive)
    except _MetadataError:
        raise
    except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError, zlib.error):
        _fail_metadata("invalid tar archive")


def _metadata_payload(
    path: PurePosixPath, raw: bytes
) -> tuple[MetadataKind, str, bytes]:
    name = path.name
    if name.endswith(".whl"):
        metadata_path, payload = _zip_metadata(raw, ".dist-info/METADATA")
        return MetadataKind.WHEEL, metadata_path, payload
    try:
        parse_sdist_filename(name)
    except InvalidSdistFilename:
        if len(raw) > _MAX_METADATA_BYTES:
            _fail_metadata("core metadata exceeds the size limit")
        return MetadataKind.CORE_METADATA, name, raw
    if name.endswith(".zip"):
        metadata_path, payload = _zip_metadata(raw, "/PKG-INFO")
    else:
        metadata_path, payload = _tar_metadata(raw)
    return MetadataKind.SDIST, metadata_path, payload


def _header(message: Message, name: str, *, required: bool) -> str | None:
    get_all = message.get_all
    values = get_all(name, [])
    if len(values) > 1:
        detail = f"core metadata repeats {name}"
        _fail_metadata(detail)
    if not values:
        if required:
            detail = f"core metadata omits {name}"
            _fail_metadata(detail)
        return None
    value = str(values[0])
    if (
        not value
        or len(value) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in value)
    ):
        detail = f"core metadata has invalid {name}"
        _fail_metadata(detail)
    return value


def _dynamic_fields(message: Message) -> tuple[str, ...]:
    values = tuple(str(value).strip() for value in message.get_all("Dynamic", []))
    dynamic: list[str] = []
    for value in values:
        if (
            not value
            or len(value) > _MAX_TEXT_LENGTH
            or _DYNAMIC_FIELD.fullmatch(value) is None
        ):
            _fail_metadata("core metadata has invalid Dynamic")
        normalized = value.casefold()
        if normalized in {"metadata-version", "name", "version"}:
            _fail_metadata(f"core metadata marks required field {value} as Dynamic")
        dynamic.append(normalized)
    if len(dynamic) != len(set(dynamic)):
        _fail_metadata("core metadata repeats a Dynamic field")
    return tuple(sorted(dynamic))


def _provides_extra_fields(message: Message) -> tuple[str, ...]:
    raw_values = tuple(message.get_all("Provides-Extra", []))
    if len(raw_values) > _MAX_EXTRAS:
        _fail_metadata("core metadata contains too many Provides-Extra fields")
    provides_extra: list[str] = []
    for raw_extra in raw_values:
        value = str(raw_extra)
        if len(value) > _MAX_TEXT_LENGTH or _EXTRA_FIELD.fullmatch(value) is None:
            _fail_metadata("core metadata has invalid Provides-Extra")
        provides_extra.append(canonicalize_name(value))
    if len(provides_extra) != len(set(provides_extra)):
        _fail_metadata("core metadata repeats a Provides-Extra value")
    return tuple(sorted(provides_extra))


def _requires_dist_fields(message: Message) -> tuple[str, ...]:
    raw_values = tuple(str(value) for value in message.get_all("Requires-Dist", []))
    if len(raw_values) > _MAX_REQUIREMENTS:
        _fail_metadata("core metadata contains too many Requires-Dist fields")
    if (budget := _ACTIVE_METADATA_REQUIREMENT_BUDGET.get()) is not None:
        budget.consume(len(raw_values))
    parsed: list[str] = []
    for value in raw_values:
        if (
            not value
            or len(value) > _MAX_TEXT_LENGTH
            or any(not character.isprintable() for character in value)
        ):
            _fail_metadata("core metadata has invalid Requires-Dist")
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            _fail_metadata("core metadata has invalid Requires-Dist")
        if len(requirement.extras) > _MAX_EXTRAS:
            _fail_metadata("core metadata Requires-Dist requests too many extras")
        if requirement.url is not None:
            _fail_metadata(
                "core metadata has a direct URL Requires-Dist outside the "
                "configured artifact and index policy"
            )
        parsed.append(str(requirement))
    return tuple(parsed)


def _validate_core_metadata_schema(raw: bytes) -> None:
    """Validate the supported schema and its version-specific field semantics."""
    try:
        Metadata.from_email(raw, validate=True)
    except ExceptionGroup as error:
        issues = tuple(
            item for item in error.exceptions if isinstance(item, InvalidMetadata)
        )
        if any(item.field == "metadata-version" for item in issues):
            _fail_metadata("core metadata has invalid or unsupported Metadata-Version")
        if any("introduced in metadata version" in str(item) for item in issues):
            _fail_metadata(
                "core metadata field is unavailable in the declared Metadata-Version"
            )
        _fail_metadata(
            "core metadata does not conform to its declared Metadata-Version"
        )


def _parse_core_metadata(raw: bytes) -> _ParsedCoreMetadata:
    if len(raw) > _MAX_METADATA_BYTES:
        _fail_metadata("core metadata exceeds the size limit")
    message = BytesParser(policy=policy.compat32).parsebytes(raw)
    if message.defects:
        _fail_metadata("core metadata contains malformed headers")
    name = _header(message, "Name", required=True)
    version = _header(message, "Version", required=True)
    metadata_version = _header(message, "Metadata-Version", required=True)
    if name is None or version is None or metadata_version is None:
        _fail_metadata("required core metadata identity is unavailable")
    try:
        parsed_version = Version(version)
    except InvalidVersion:
        _fail_metadata("core metadata has an invalid Version")
    requires_python = _header(message, "Requires-Python", required=False)
    if requires_python is not None:
        try:
            SpecifierSet(requires_python)
        except InvalidSpecifier:
            _fail_metadata("core metadata has invalid Requires-Python")
    requires_dist = _requires_dist_fields(message)
    provides_extra = _provides_extra_fields(message)
    dynamic = _dynamic_fields(message)
    _validate_core_metadata_schema(raw)
    return _ParsedCoreMetadata(
        name=name,
        version=parsed_version,
        metadata_version=metadata_version,
        requires_python=requires_python,
        requires_dist=requires_dist,
        provides_extra=provides_extra,
        dynamic=dynamic,
    )


def _wheel_dist_info_directory(
    metadata_path: str, metadata: _ParsedCoreMetadata
) -> str:
    metadata_member = PurePosixPath(metadata_path)
    if (
        len(metadata_member.parts) != _WHEEL_PATH_PARTS
        or metadata_member.name != "METADATA"
        or not metadata_member.parent.name.endswith(".dist-info")
        or metadata_member.as_posix() != metadata_path
        or "\\" in metadata_path
    ):
        _fail_metadata("wheel METADATA is not in a top-level dist-info directory")
    dist_info = metadata_member.parent.name
    identity = dist_info.removesuffix(".dist-info")
    distribution, separator, raw_version = identity.rpartition("-")
    try:
        dist_info_version = Version(raw_version)
    except InvalidVersion:
        _fail_metadata("wheel has an invalid dist-info directory identity")
    if (
        not separator
        or canonicalize_name(distribution) != canonicalize_name(metadata.name)
        or dist_info_version != metadata.version
    ):
        _fail_metadata("wheel dist-info directory and core metadata identity disagree")
    return dist_info


def _wheel_file_payload(raw: bytes, dist_info: str) -> bytes:
    _check_zip_archive_limits(raw)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            wheel_members = [
                item
                for item in members
                if not item.is_dir() and item.filename == f"{dist_info}/WHEEL"
            ]
            record_members = [
                item
                for item in members
                if not item.is_dir() and item.filename == f"{dist_info}/RECORD"
            ]
            if len(wheel_members) != 1:
                _fail_metadata(
                    "wheel dist-info directory must contain exactly one WHEEL"
                )
            if len(record_members) != 1:
                _fail_metadata(
                    "wheel dist-info directory must contain exactly one RECORD"
                )
            wheel_member = wheel_members[0]
            if wheel_member.file_size > _MAX_METADATA_BYTES:
                _fail_metadata("WHEEL metadata exceeds the size limit")
            with archive.open(wheel_member) as stream:
                payload = stream.read(_MAX_METADATA_BYTES + 1)
            _consume_archive_expansion(len(payload))
            if len(payload) > _MAX_METADATA_BYTES:
                _fail_metadata("WHEEL metadata exceeds the size limit")
            return payload
    except _MetadataError:
        raise
    except (
        EOFError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        _fail_metadata("invalid ZIP archive")


def _wheel_header(message: Message, name: str) -> str:
    values = message.get_all(name, [])
    if len(values) != 1:
        _fail_metadata(f"WHEEL metadata must contain exactly one {name}")
    value = str(values[0])
    if (
        not value
        or len(value) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in value)
    ):
        _fail_metadata(f"WHEEL metadata has invalid {name}")
    return value


def _validate_wheel_installation_headers(message: Message) -> None:
    """Require installer-critical WHEEL fields that PyAhead understands."""
    wheel_version = _wheel_header(message, "Wheel-Version")
    parsed_version = re.fullmatch(
        r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)", wheel_version
    )
    if parsed_version is None or int(parsed_version.group("major")) != 1:
        _fail_metadata("WHEEL metadata has an unsupported Wheel-Version")
    if _wheel_header(message, "Root-Is-Purelib") not in {"false", "true"}:
        _fail_metadata("WHEEL metadata has invalid Root-Is-Purelib")


def _wheel_file_tags(wheel_payload: bytes) -> tuple[str, ...]:
    message = BytesParser(policy=policy.compat32).parsebytes(wheel_payload)
    if message.defects:
        _fail_metadata("WHEEL metadata contains malformed headers")
    _validate_wheel_installation_headers(message)
    raw_tags = tuple(str(value) for value in message.get_all("Tag", []))
    if not raw_tags:
        _fail_metadata("WHEEL metadata omits Tag")
    if len(raw_tags) > _MAX_TAG_VALUES:
        _fail_metadata("WHEEL metadata contains too many Tag fields")
    internal_tags: set[str] = set()
    expansion_count = 0
    for value in raw_tags:
        if (
            not value
            or len(value) > _MAX_TEXT_LENGTH
            or any(not character.isprintable() for character in value)
        ):
            _fail_metadata("WHEEL metadata has invalid Tag")
        try:
            expanded_count = _tag_expansion_count(value)
        except ValueError:
            _fail_metadata("WHEEL metadata has invalid Tag")
        expansion_count += expanded_count
        if expansion_count > _MAX_EXPANDED_TAGS:
            _fail_metadata("WHEEL metadata Tag fields expand to too many tags")
        internal_tags.update(map(str, parse_tag(value)))
    return tuple(sorted(internal_tags))


def _wheel_structure_tags(
    raw: bytes,
    *,
    metadata_path: str,
    metadata: _ParsedCoreMetadata,
) -> tuple[str, ...]:
    dist_info = _wheel_dist_info_directory(metadata_path, metadata)
    return _wheel_file_tags(_wheel_file_payload(raw, dist_info))


def _validate_sdist_identity(
    path: PurePosixPath,
    metadata_path: str,
    metadata: _ParsedCoreMetadata,
) -> None:
    try:
        filename_name, filename_version = parse_sdist_filename(path.name)
    except InvalidSdistFilename:
        _fail_metadata("invalid source distribution filename")
    if (
        filename_name != canonicalize_name(metadata.name)
        or filename_version != metadata.version
    ):
        _fail_metadata("sdist filename and core metadata identity disagree")
    member = PurePosixPath(metadata_path)
    if len(member.parts) != _WHEEL_PATH_PARTS or member.name != "PKG-INFO":
        _fail_metadata("sdist PKG-INFO is not in its top-level identity directory")
    identity = member.parent.name
    distribution, separator, raw_version = identity.rpartition("-")
    try:
        member_version = Version(raw_version)
    except InvalidVersion:
        _fail_metadata("sdist has an invalid PKG-INFO directory identity")
    if (
        not separator
        or metadata_path != f"{identity}/PKG-INFO"
        or canonicalize_name(distribution) != filename_name
        or member_version != filename_version
    ):
        _fail_metadata(
            "sdist PKG-INFO directory, filename, and core metadata identity disagree"
        )


def _validate_wheel_filename_tag_expansion(filename: str) -> None:
    """Bound compressed filename tags before packaging expands their product."""
    components = filename.removesuffix(".whl").rsplit("-", maxsplit=3)
    if len(components) != _TAG_COMPONENTS + 1:
        _fail_metadata("invalid wheel filename")
    try:
        expanded_count = _tag_expansion_count("-".join(components[1:]))
    except ValueError:
        _fail_metadata("invalid wheel filename")
    if expanded_count > _MAX_EXPANDED_TAGS:
        _fail_metadata("wheel filename expands to too many compatibility tags")


def _validate_artifact_identity(
    path: PurePosixPath,
    kind: MetadataKind,
    metadata: _ParsedCoreMetadata,
    *,
    artifact_raw: bytes,
    metadata_path: str,
) -> tuple[str, ...]:
    if kind is MetadataKind.WHEEL:
        _validate_wheel_filename_tag_expansion(path.name)
        try:
            filename_name, filename_version, _build, tags = parse_wheel_filename(
                path.name
            )
        except InvalidWheelFilename:
            _fail_metadata("invalid wheel filename")
        if (
            filename_name != canonicalize_name(metadata.name)
            or filename_version != metadata.version
        ):
            _fail_metadata("wheel filename and core metadata identity disagree")
        filename_tags = tuple(sorted(map(str, tags)))
        internal_tags = _wheel_structure_tags(
            artifact_raw,
            metadata_path=metadata_path,
            metadata=metadata,
        )
        if internal_tags != filename_tags:
            _fail_metadata("wheel internal and filename tags disagree")
        return filename_tags
    if kind is MetadataKind.SDIST:
        _validate_sdist_identity(path, metadata_path, metadata)
    return ()


def _parse_metadata(
    path: PurePosixPath,
    raw: bytes,
    kind: MetadataKind,
    metadata_path: str,
    *,
    artifact_raw: bytes,
) -> MetadataArtifact:
    metadata = _parse_core_metadata(raw)
    if kind is MetadataKind.WHEEL and metadata.dynamic:
        _fail_metadata("wheel core metadata must not declare Dynamic fields")
    dynamic = metadata.dynamic
    if (
        kind is not MetadataKind.WHEEL
        and Version(metadata.metadata_version) < _STATIC_SDIST_METADATA_VERSION
    ):
        dynamic = _LEGACY_IMPLICIT_DYNAMIC_FIELDS
    wheel_tags = _validate_artifact_identity(
        path,
        kind,
        metadata,
        artifact_raw=artifact_raw,
        metadata_path=metadata_path,
    )
    digest = hashlib.sha256(raw).hexdigest()
    return MetadataArtifact(
        artifact_id=digest,
        path=path,
        kind=kind,
        name=metadata.name,
        canonical_name=canonicalize_name(metadata.name),
        version=str(metadata.version),
        metadata_version=metadata.metadata_version,
        requires_python=metadata.requires_python,
        requires_dist=metadata.requires_dist,
        provides_extra=metadata.provides_extra,
        dynamic=dynamic,
        wheel_tags=wheel_tags,
        metadata_path=metadata_path,
        sha256=digest,
    )


@_with_archive_expansion_budget
@_with_metadata_requirement_budget
def inspect_dependency_metadata(
    metadata_paths: Sequence[Path], *, root: Path
) -> tuple[tuple[MetadataArtifact, ...], tuple[MetadataIssue, ...]]:
    """Read static core metadata without importing code or running a backend."""
    if len(metadata_paths) > _MAX_METADATA_INPUTS:
        _error("dependency metadata inputs", "contains too many items")
    if not all(isinstance(path, Path) for path in metadata_paths):
        _error("dependency metadata inputs", "must contain only paths")
    resolved_root = _resolved_dependency_root(root)
    artifacts: list[MetadataArtifact] = []
    issues: list[MetadataIssue] = []
    selected_paths: set[PurePosixPath] = set()
    selected_artifact_ids: set[str] = set()
    total_artifact_bytes = 0
    for configured_path in metadata_paths:
        relative, artifact_bytes = _read_artifact(configured_path, resolved_root)
        total_artifact_bytes += len(artifact_bytes)
        if total_artifact_bytes > _MAX_METADATA_TOTAL_BYTES:
            _error(
                "tool.pyahead.dependencies.metadata",
                "exceeds the aggregate input byte limit",
            )
        if relative in selected_paths:
            _error("tool.pyahead.dependencies.metadata", "contains duplicate paths")
        selected_paths.add(relative)
        try:
            kind, metadata_path, payload = _metadata_payload(relative, artifact_bytes)
            artifact = _parse_metadata(
                relative,
                payload,
                kind,
                metadata_path,
                artifact_raw=artifact_bytes,
            )
            artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
            if artifact_digest in selected_artifact_ids:
                _error(
                    "tool.pyahead.dependencies.metadata",
                    "contains duplicate artifact content",
                )
            selected_artifact_ids.add(artifact_digest)
            artifacts.append(
                MetadataArtifact(
                    artifact_id=artifact_digest,
                    path=artifact.path,
                    kind=artifact.kind,
                    name=artifact.name,
                    canonical_name=artifact.canonical_name,
                    version=artifact.version,
                    metadata_version=artifact.metadata_version,
                    requires_python=artifact.requires_python,
                    requires_dist=artifact.requires_dist,
                    provides_extra=artifact.provides_extra,
                    dynamic=artifact.dynamic,
                    wheel_tags=artifact.wheel_tags,
                    metadata_path=artifact.metadata_path,
                    sha256=artifact_digest,
                )
            )
        except _MetadataError as error:
            issues.append(MetadataIssue(path=relative, message=str(error)))
    return (
        tuple(sorted(artifacts, key=lambda item: item.path.as_posix())),
        tuple(sorted(issues, key=lambda item: item.path.as_posix())),
    )


def _evaluate_requirement(
    value: str, target: EnvironmentTarget, extras: tuple[str, ...]
) -> EvaluatedRequirement:
    _consume_dependency_work(1)
    budget = _ACTIVE_MARKER_BUDGET.get()
    requirement = Requirement(value)
    if requirement.marker is None:
        return EvaluatedRequirement(
            requirement=value,
            applies=True,
            matching_extras=("base",),
            matching_metadata=(),
            resolved_versions=(),
            verified=False,
            reason="active requirement has not been correlated with evidence",
        )
    contexts = extras or ("",)
    if budget is not None and len(contexts) > 1:
        budget.consume(len(contexts) - 1)
    try:
        matching = [
            extra or "base"
            for extra in contexts
            if requirement.marker.evaluate(
                environment=target.marker_environment(extra=extra),
                context="metadata",
            )
        ]
    except (UndefinedComparison, UndefinedEnvironmentName) as error:
        message = f"environment marker cannot be evaluated for target {target.name!r}"
        raise ConfigurationError(message) from error
    return EvaluatedRequirement(
        requirement=value,
        applies=bool(matching),
        matching_extras=tuple(matching),
        matching_metadata=(),
        resolved_versions=(),
        verified=not matching,
        reason=(
            "active requirement has not been correlated with evidence"
            if matching
            else "requirement marker does not apply to the declared target"
        ),
    )


def _select_artifacts(
    group: tuple[MetadataArtifact, ...], target: EnvironmentTarget
) -> _ArtifactSelection:
    wheels = tuple(item for item in group if item.kind is MetadataKind.WHEEL)
    _consume_dependency_work(
        len(target.tags) + sum(len(item.wheel_tags) for item in wheels)
    )
    target_tags = frozenset(map(str, target.tags))
    matching_wheels = tuple(
        item for item in wheels if any(tag in target_tags for tag in item.wheel_tags)
    )
    sdists = tuple(item for item in group if item.kind is MetadataKind.SDIST)
    raw_metadata = tuple(
        item for item in group if item.kind is MetadataKind.CORE_METADATA
    )
    semantic_metadata = matching_wheels or sdists or raw_metadata or wheels
    return _ArtifactSelection(
        matching_wheels=matching_wheels,
        wheels=wheels,
        sdists=sdists,
        raw_metadata=raw_metadata,
        semantic_metadata=semantic_metadata,
    )


def _requires_python_status(
    artifacts: Sequence[MetadataArtifact], target: EnvironmentTarget
) -> tuple[RequiresPythonStatus, bool]:
    declarations = {
        item.requires_python
        for item in artifacts
        if "requires-python" not in item.dynamic
    }
    dynamic = any("requires-python" in item.dynamic for item in artifacts)
    if dynamic:
        return RequiresPythonStatus.UNVERIFIED, True
    if not declarations:
        return RequiresPythonStatus.UNSPECIFIED, False
    if len(declarations) != 1:
        return RequiresPythonStatus.UNVERIFIED, dynamic
    declaration = next(iter(declarations))
    if declaration is None:
        return RequiresPythonStatus.UNSPECIFIED, dynamic
    compatible = SpecifierSet(declaration).contains(
        Version(target.python_full_version), prereleases=True
    )
    status = (
        RequiresPythonStatus.COMPATIBLE
        if compatible
        else RequiresPythonStatus.INCOMPATIBLE
    )
    return status, dynamic


def _artifact_availability(selection: _ArtifactSelection) -> ArtifactAvailability:
    if selection.matching_wheels:
        return ArtifactAvailability.AVAILABLE
    if selection.sdists:
        return ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    if selection.wheels:
        return ArtifactAvailability.UNAVAILABLE
    return ArtifactAvailability.UNVERIFIED


def _assessment_outcome(
    requires_status: RequiresPythonStatus,
    availability: ArtifactAvailability,
    *,
    dynamic_requires_python: bool,
    source_build_possible: bool,
) -> tuple[DependencyCompatibilityStatus, str]:
    if requires_status is RequiresPythonStatus.INCOMPATIBLE:
        return (
            DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE,
            "Requires-Python excludes the declared target",
        )
    if requires_status is RequiresPythonStatus.UNVERIFIED:
        reason = (
            "candidate metadata marks Requires-Python as dynamic"
            if dynamic_requires_python
            else "candidate artifacts disagree on Requires-Python"
        )
        return DependencyCompatibilityStatus.UNVERIFIED, reason
    if availability is ArtifactAvailability.AVAILABLE:
        return (
            DependencyCompatibilityStatus.COMPATIBLE,
            (
                "Requires-Python does not exclude the target and a matching wheel "
                "is supplied"
            ),
        )
    if availability in {
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE,
        ArtifactAvailability.UNAVAILABLE,
    }:
        reason = (
            "no matching wheel is supplied; a source build may remain possible"
            if source_build_possible
            else "no matching wheel or source distribution is supplied"
        )
        return DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE, reason
    return (
        DependencyCompatibilityStatus.UNVERIFIED,
        "core metadata alone does not establish artifact availability",
    )


def _artifact_applicable_requirements(
    artifact: MetadataArtifact,
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> tuple[str, ...]:
    """Evaluate one candidate's dependency edges without blending candidates."""
    return tuple(
        sorted(
            {
                item.requirement
                for value in artifact.requires_dist
                if (item := _evaluate_requirement(value, target, extras)).applies
            }
        )
    )


def _assessment(
    group: tuple[MetadataArtifact, ...],
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> DependencyAssessment:
    first = group[0]
    selection = _select_artifacts(group, target)
    semantic_metadata = selection.semantic_metadata
    requires_status, dynamic_requires_python = _requires_python_status(
        semantic_metadata, target
    )
    fallback_metadata = (
        (*selection.sdists, *selection.raw_metadata)
        if selection.matching_wheels
        else selection.raw_metadata
        if selection.sdists
        else ()
    )
    if requires_status is RequiresPythonStatus.INCOMPATIBLE and fallback_metadata:
        combined_metadata = (*semantic_metadata, *fallback_metadata)
        combined_status, combined_dynamic = _requires_python_status(
            combined_metadata, target
        )
        semantic_metadata = combined_metadata
        requires_status = combined_status
        dynamic_requires_python = combined_dynamic
    metadata_used = tuple(sorted({item.artifact_id for item in semantic_metadata}))
    marker_issue: str | None = None
    dynamic_requires_dist = any(
        "requires-dist" in artifact.dynamic for artifact in semantic_metadata
    )
    requires_dist_disagreement = False
    try:
        candidate_requirements = tuple(
            _artifact_applicable_requirements(artifact, target, extras)
            for artifact in semantic_metadata
            if "requires-dist" not in artifact.dynamic
        )
        requires_dist_disagreement = len(set(candidate_requirements)) > 1
        requirements = (
            () if requires_dist_disagreement else next(iter(candidate_requirements), ())
        )
    except _MarkerEvaluationLimitError:
        raise
    except ConfigurationError:
        requirements = ()
        marker_issue = (
            "candidate Requires-Dist marker cannot be evaluated for the declared target"
        )
    availability = _artifact_availability(selection)
    status, reason = _assessment_outcome(
        requires_status,
        availability,
        dynamic_requires_python=dynamic_requires_python,
        source_build_possible=bool(selection.sdists),
    )
    if marker_issue is not None:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = marker_issue
    elif dynamic_requires_dist:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = (
            "candidate metadata declares Requires-Dist dynamic; dependency "
            "compatibility remains unverified"
        )
    elif requires_dist_disagreement:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = "candidate artifacts disagree on applicable Requires-Dist"
    return DependencyAssessment(
        package=first.name,
        version=first.version,
        status=status,
        requires_python_status=requires_status,
        artifact_availability=availability,
        source_build_possible=bool(selection.sdists),
        metadata_used=metadata_used,
        applicable_requirements=requirements,
        reason=reason,
    )


def _bounded_artifact_strings(
    value: object,
    *,
    label: str,
    limit: int,
    unique: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        _error(label, "must be a tuple")
    if len(value) > limit:
        _error(label, "contains too many items")
    result = tuple(_string(item, f"{label} item") for item in value)
    if unique and len(result) != len(set(result)):
        _error(label, "contains duplicates")
    return result


def _validate_artifact_relative_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, PurePosixPath):
        _error(label, "must be a relative POSIX path")
    text = _string(value.as_posix(), label)
    if value.is_absolute() or text == "." or ".." in value.parts or "\\" in text:
        _error(label, "must remain a relative traversal-free path")
    return value


def _validate_metadata_artifact_identity(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    artifact_id = _string(artifact.artifact_id, f"{label}.artifact-id")
    sha256 = _string(artifact.sha256, f"{label}.sha256")
    if _SHA256.fullmatch(artifact_id) is None or artifact_id != sha256:
        _error(label, "must have one matching lowercase SHA-256 identity")
    _validate_artifact_relative_path(artifact.path, label=f"{label}.path")
    if not isinstance(artifact.kind, MetadataKind):
        _error(f"{label}.kind", "is invalid")
    name = _string(artifact.name, f"{label}.name")
    try:
        expected_name = canonicalize_name(name, validate=True)
    except ValueError:
        _error(f"{label}.name", "is not a valid distribution name")
    if artifact.canonical_name != expected_name:
        _error(f"{label}.canonical-name", "does not match the distribution name")
    version = _string(artifact.version, f"{label}.version")
    try:
        parsed_version = Version(version)
    except InvalidVersion:
        _error(f"{label}.version", "is invalid")
    if str(parsed_version) != version:
        _error(f"{label}.version", "must use its canonical form")
    metadata_version = _string(
        artifact.metadata_version,
        f"{label}.metadata-version",
    )
    if re.fullmatch(r"[12]\.[0-9]+", metadata_version) is None:
        _error(f"{label}.metadata-version", "is invalid")
    raw_metadata_path = _string(
        artifact.metadata_path,
        f"{label}.metadata-path",
    )
    metadata_path = PurePosixPath(raw_metadata_path)
    if metadata_path.as_posix() != raw_metadata_path or "\\" in raw_metadata_path:
        _error(f"{label}.metadata-path", "must use one normalized POSIX spelling")
    _validate_artifact_relative_path(metadata_path, label=f"{label}.metadata-path")


def _validated_artifact_requirements(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> tuple[str, ...]:
    requirements = _bounded_artifact_strings(
        artifact.requires_dist,
        label=f"{label}.requires-dist",
        limit=_MAX_REQUIREMENTS,
        unique=False,
    )
    for value in requirements:
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            _error(f"{label}.requires-dist", "contains an invalid requirement")
        if len(requirement.extras) > _MAX_EXTRAS:
            _error(f"{label}.requires-dist", "requests too many extras")
        if requirement.url is not None or str(requirement) != value:
            _error(f"{label}.requires-dist", "contains an unsafe or noncanonical value")
    return requirements


def _validated_artifact_extras(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> tuple[str, ...]:
    extras = _bounded_artifact_strings(
        artifact.provides_extra,
        label=f"{label}.provides-extra",
        limit=_MAX_EXTRAS,
        unique=True,
    )
    if tuple(sorted(extras)) != extras or any(
        _EXTRA_FIELD.fullmatch(value) is None or canonicalize_name(value) != value
        for value in extras
    ):
        _error(f"{label}.provides-extra", "must contain sorted normalized names")
    return extras


def _validated_artifact_dynamic(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> tuple[str, ...]:
    dynamic = _bounded_artifact_strings(
        artifact.dynamic,
        label=f"{label}.dynamic",
        limit=_MAX_REQUIREMENTS,
        unique=True,
    )
    if tuple(sorted(dynamic)) != dynamic or any(
        _DYNAMIC_FIELD.fullmatch(value) is None or value.casefold() != value
        for value in dynamic
    ):
        _error(f"{label}.dynamic", "must contain sorted normalized fields")
    return dynamic


def _validated_artifact_tags(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> tuple[str, ...]:
    tags = _bounded_artifact_strings(
        artifact.wheel_tags,
        label=f"{label}.wheel-tags",
        limit=_MAX_EXPANDED_TAGS,
        unique=True,
    )
    if tuple(sorted(tags)) != tags or any(
        not _artifact_tag_is_expanded(value) for value in tags
    ):
        _error(f"{label}.wheel-tags", "must contain sorted expanded tags")
    if bool(tags) is not (artifact.kind is MetadataKind.WHEEL):
        _error(f"{label}.wheel-tags", "must agree with the artifact kind")
    return tags


def _validate_metadata_artifact_declarations(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    if artifact.requires_python is not None:
        requires_python = _string(
            artifact.requires_python,
            f"{label}.requires-python",
        )
        try:
            SpecifierSet(requires_python)
        except InvalidSpecifier:
            _error(f"{label}.requires-python", "is invalid")
    requirements = _validated_artifact_requirements(artifact, label=label)
    extras = _validated_artifact_extras(artifact, label=label)
    dynamic = _validated_artifact_dynamic(artifact, label=label)
    tags = _validated_artifact_tags(artifact, label=label)
    if sum(len(item) for item in (*requirements, *extras, *dynamic, *tags)) > (
        _MAX_METADATA_BYTES
    ):
        _error(label, "contains too much nested metadata text")


def _artifact_tag_is_expanded(value: str) -> bool:
    try:
        return _tag_expansion_count(value) == 1 and len(parse_tag(value)) == 1
    except ValueError:
        return False


def _validate_programmatic_wheel_binding(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    if artifact.dynamic:
        _error(label, "wheel metadata must not declare Dynamic fields")
    filename = artifact.path.name
    components = filename.removesuffix(".whl").rsplit("-", maxsplit=3)
    if len(components) != _TAG_COMPONENTS + 1:
        _error(label, "has an invalid wheel filename")
    try:
        expansion = _tag_expansion_count("-".join(components[1:]))
    except ValueError:
        _error(label, "has an invalid wheel filename")
    if expansion > _MAX_EXPANDED_TAGS:
        _error(label, "wheel filename expands to too many compatibility tags")
    try:
        filename_name, filename_version, _build, filename_tags = parse_wheel_filename(
            filename
        )
    except InvalidWheelFilename:
        _error(label, "has an invalid wheel filename")
    if (
        filename_name != artifact.canonical_name
        or filename_version != Version(artifact.version)
        or tuple(sorted(map(str, filename_tags))) != artifact.wheel_tags
    ):
        _error(label, "wheel filename and inspected identity disagree")
    member = PurePosixPath(artifact.metadata_path)
    if (
        len(member.parts) != _WHEEL_PATH_PARTS
        or member.name != "METADATA"
        or not member.parent.name.endswith(".dist-info")
    ):
        _error(label, "wheel metadata path is not a top-level dist-info member")
    distribution, separator, raw_version = member.parent.name.removesuffix(
        ".dist-info"
    ).rpartition("-")
    try:
        metadata_version = Version(raw_version)
    except InvalidVersion:
        _error(label, "wheel metadata path has an invalid identity")
    if (
        not separator
        or canonicalize_name(distribution) != artifact.canonical_name
        or metadata_version != Version(artifact.version)
    ):
        _error(label, "wheel metadata path and inspected identity disagree")


def _validate_programmatic_sdist_binding(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    try:
        filename_name, filename_version = parse_sdist_filename(artifact.path.name)
    except InvalidSdistFilename:
        _error(label, "has an invalid source distribution filename")
    if filename_name != artifact.canonical_name or filename_version != Version(
        artifact.version
    ):
        _error(label, "sdist filename and inspected identity disagree")
    member = PurePosixPath(artifact.metadata_path)
    if len(member.parts) != _WHEEL_PATH_PARTS or member.name != "PKG-INFO":
        _error(label, "sdist metadata path is not a top-level PKG-INFO member")
    distribution, separator, raw_version = member.parent.name.rpartition("-")
    try:
        metadata_version = Version(raw_version)
    except InvalidVersion:
        _error(label, "sdist metadata path has an invalid identity")
    if (
        not separator
        or canonicalize_name(distribution) != artifact.canonical_name
        or metadata_version != Version(artifact.version)
    ):
        _error(label, "sdist metadata path and inspected identity disagree")


def _validate_artifact_container_binding(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    """Re-establish loader-proven filename and member identity for public inputs."""
    if artifact.kind is MetadataKind.WHEEL:
        _validate_programmatic_wheel_binding(artifact, label=label)
        return
    if artifact.kind is MetadataKind.SDIST:
        _validate_programmatic_sdist_binding(artifact, label=label)
        return
    if artifact.metadata_path != artifact.path.name or artifact.path.name.endswith(
        ".whl"
    ):
        _error(label, "standalone metadata path and inspected identity disagree")
    try:
        parse_sdist_filename(artifact.path.name)
    except InvalidSdistFilename:
        return
    _error(label, "standalone metadata path is classified as a source distribution")


def _validate_programmatic_metadata_schema(
    artifact: MetadataArtifact,
    *,
    label: str,
) -> None:
    """Apply packaging's version-specific Core Metadata schema to public records."""
    lines = [
        f"Metadata-Version: {artifact.metadata_version}",
        f"Name: {artifact.name}",
        f"Version: {artifact.version}",
    ]
    if artifact.requires_python is not None:
        lines.append(f"Requires-Python: {artifact.requires_python}")
    lines.extend(f"Requires-Dist: {value}" for value in artifact.requires_dist)
    lines.extend(f"Provides-Extra: {value}" for value in artifact.provides_extra)
    implicit_dynamic = (
        _LEGACY_IMPLICIT_DYNAMIC_FIELDS
        if artifact.kind is not MetadataKind.WHEEL
        and Version(artifact.metadata_version) < _STATIC_SDIST_METADATA_VERSION
        else ()
    )
    if implicit_dynamic and artifact.dynamic != implicit_dynamic:
        _error(
            label,
            "legacy source metadata must preserve implicit dynamic field semantics",
        )
    lines.extend(
        f"Dynamic: {value}"
        for value in artifact.dynamic
        if value not in implicit_dynamic
    )
    try:
        _validate_core_metadata_schema(("\n".join(lines) + "\n\n").encode())
    except _MetadataError as error:
        _error(label, f"does not conform to Core Metadata: {error}")


def _validate_metadata_artifacts(artifacts: Sequence[MetadataArtifact]) -> None:
    if len(artifacts) > _MAX_METADATA_INPUTS:
        _error("dependency metadata", "contains too many items")
    paths: list[PurePosixPath] = []
    artifact_ids: list[str] = []
    total_requirements = 0
    for index, artifact in enumerate(artifacts):
        label = f"dependency metadata[{index}]"
        if not isinstance(artifact, MetadataArtifact):
            _error(label, "must be an inspected metadata artifact")
        if not isinstance(artifact.requires_dist, tuple):
            _error(f"{label}.requires-dist", "must be a tuple")
        total_requirements += len(artifact.requires_dist)
        if total_requirements > _MAX_METADATA_REQUIREMENTS:
            _error("dependency metadata", "exceeds the aggregate Requires-Dist limit")
        _validate_metadata_artifact_identity(artifact, label=label)
        _validate_metadata_artifact_declarations(artifact, label=label)
        _validate_programmatic_metadata_schema(artifact, label=label)
        _validate_artifact_container_binding(artifact, label=label)
        paths.append(artifact.path)
        artifact_ids.append(artifact.artifact_id)
    if len(paths) != len(set(paths)):
        _error("dependency metadata", "contains duplicate paths")
    if len(artifact_ids) != len(set(artifact_ids)):
        _error("dependency metadata", "contains duplicate artifact identities")


@_with_marker_evaluation_budget
def assess_dependency_metadata(
    artifacts: Sequence[MetadataArtifact],
    *,
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> tuple[DependencyAssessment, ...]:
    """Assess exact supplied versions for one fully declared target."""
    _validate_metadata_artifacts(artifacts)
    _ensure_target_coherence(target, label="dependency target")
    validated_extras = _validate_effective_extras(
        extras,
        label="dependency assessment extras",
    )
    _ensure_marker_evaluation_budget(
        (
            (
                tuple(
                    requirement
                    for artifact in artifacts
                    for requirement in artifact.requires_dist
                ),
                1,
            ),
        ),
        extras=validated_extras,
        target_count=1,
        label="dependency assessment",
    )
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        key = (artifact.canonical_name, Version(artifact.version))
        grouped.setdefault(key, []).append(artifact)
    return tuple(
        _assessment(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
            validated_extras,
        )
        for key in sorted(grouped, key=lambda item: (item[0], item[1]))
    )


def _unverify_library_artifact_sample(
    assessment: DependencyAssessment,
) -> DependencyAssessment:
    """Keep a finite library artifact sample from claiming universal absence."""
    if assessment.status is not DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE:
        return assessment
    return replace(
        assessment,
        status=DependencyCompatibilityStatus.UNVERIFIED,
        reason=(
            "supplied library artifacts do not establish target artifact "
            "availability; complete resolver evidence is required"
        ),
    )


def _requirement_accepts_version(requirement: Requirement, version: str) -> bool:
    _consume_dependency_work(1)
    return requirement.specifier.contains(Version(version), prereleases=True)


def _resolved_artifact_group(
    package: ResolvedPackage,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> tuple[MetadataArtifact, ...] | None:
    """Return only exact artifacts explicitly attributed to one resolver package."""
    if not package.metadata_used or len(package.metadata_used) != len(
        set(package.metadata_used)
    ):
        return None
    selected: list[MetadataArtifact] = []
    for artifact_id in package.metadata_used:
        artifact = artifacts_by_id.get(artifact_id)
        if (
            artifact is None
            or artifact.canonical_name != canonicalize_name(package.name)
            or Version(artifact.version) != Version(package.version)
        ):
            return None
        selected.append(artifact)
    return tuple(selected)


def _resolution_evidence_artifacts(
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
) -> tuple[MetadataArtifact, ...]:
    if not (resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete):
        return tuple(artifacts)
    selected_ids = {
        artifact_id
        for package in resolution.packages
        for artifact_id in package.metadata_used
    }
    return tuple(
        artifact for artifact in artifacts if artifact.artifact_id in selected_ids
    )


def _target_semantic_artifacts(
    artifacts: Sequence[MetadataArtifact], target: EnvironmentTarget
) -> tuple[MetadataArtifact, ...]:
    """Keep only artifacts whose metadata is selected for the declared target."""
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        key = (artifact.canonical_name, Version(artifact.version))
        grouped.setdefault(key, []).append(artifact)
    selected: list[MetadataArtifact] = []
    for key in sorted(grouped, key=lambda item: (item[0], item[1])):
        group = tuple(sorted(grouped[key], key=lambda item: item.path.as_posix()))
        selected.extend(_select_artifacts(group, target).semantic_metadata)
    return tuple(selected)


def _propagated_dependency_assessments(
    grouped: Mapping[tuple[str, Version], Sequence[MetadataArtifact]],
    ordered_keys: Sequence[tuple[str, Version]],
    *,
    target: EnvironmentTarget,
    initial_extras: Mapping[tuple[str, Version], set[str]],
    seed_keys: Sequence[tuple[str, Version]],
) -> dict[tuple[str, Version], DependencyAssessment]:
    """Assess reachable dependencies and requested extras to a fixed point."""
    extras_by_key = {key: set(initial_extras[key]) for key in ordered_keys}
    keys_by_name: dict[str, list[tuple[str, Version]]] = {}
    for key in ordered_keys:
        keys_by_name.setdefault(key[0], []).append(key)

    assessments: dict[tuple[str, Version], DependencyAssessment] = {}
    pending = list(seed_keys)
    queued = set(seed_keys)
    cursor = 0
    while cursor < len(pending):
        key = pending[cursor]
        cursor += 1
        queued.discard(key)
        assessment = _assessment(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
            tuple(sorted(extras_by_key[key])),
        )
        assessments[key] = assessment
        for value in assessment.applicable_requirements:
            requirement = Requirement(value)
            requested = _canonical_requested_extras((requirement,))
            name = canonicalize_name(requirement.name)
            candidate_keys = keys_by_name.get(name, [])
            _consume_dependency_work(len(candidate_keys))
            for candidate_key in candidate_keys:
                if not _requirement_accepts_version(requirement, str(candidate_key[1])):
                    continue
                candidate_group = _select_artifacts(
                    tuple(
                        sorted(
                            grouped[candidate_key],
                            key=lambda item: item.path.as_posix(),
                        )
                    ),
                    target,
                ).semantic_metadata
                _consume_dependency_work(len(candidate_group))
                eligible = bool(candidate_group) and all(
                    _artifact_satisfies_requirements(artifact, (requirement,))
                    if requested
                    else _artifact_satisfies_version_constraints(
                        artifact, (requirement,)
                    )
                    for artifact in candidate_group
                )
                if not eligible:
                    continue
                previous_size = len(extras_by_key[candidate_key])
                extras_by_key[candidate_key].update(requested)
                if (
                    candidate_key not in assessments
                    or len(extras_by_key[candidate_key]) != previous_size
                ) and candidate_key not in queued:
                    pending.append(candidate_key)
                    queued.add(candidate_key)
    return assessments


def _direct_dependency_groups(
    artifacts: Sequence[MetadataArtifact],
    active: Sequence[Requirement],
) -> dict[tuple[str, Version], list[MetadataArtifact]]:
    requirements_by_name: dict[str, list[Requirement]] = {}
    for requirement in active:
        requirements_by_name.setdefault(
            canonicalize_name(requirement.name),
            [],
        ).append(requirement)
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        candidates = requirements_by_name.get(artifact.canonical_name, [])
        _consume_dependency_work(len(candidates))
        if candidates and all(
            _requirement_accepts_version(requirement, artifact.version)
            for requirement in candidates
        ):
            key = (artifact.canonical_name, Version(artifact.version))
            grouped.setdefault(key, []).append(artifact)
    return grouped


def _resolver_dependency_groups(
    resolution: ResolverResult,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> dict[tuple[str, Version], list[MetadataArtifact]]:
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for package in resolution.packages:
        selected = _resolved_artifact_group(package, artifacts_by_id)
        if selected is not None:
            key = (canonicalize_name(package.name), Version(package.version))
            grouped[key] = list(selected)
    return grouped


def _resolver_root_keys(
    ordered_keys: Sequence[tuple[str, Version]],
    active_groups: Mapping[str, Sequence[Requirement]],
    resolution: ResolverResult,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> tuple[tuple[str, Version], ...]:
    _consume_dependency_work(len(ordered_keys) * len(resolution.packages))
    return tuple(
        key
        for key in ordered_keys
        if (requirements := active_groups.get(key[0])) is not None
        and any(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == key[0]
            and Version(package.version) == key[1]
        )
    )


def _initial_dependency_extras(
    ordered_keys: Sequence[tuple[str, Version]],
    active: Sequence[Requirement],
    grouped: Mapping[tuple[str, Version], Sequence[MetadataArtifact]],
    target: EnvironmentTarget,
) -> dict[tuple[str, Version], set[str]]:
    _consume_dependency_work(len(ordered_keys) * len(active))
    initial: dict[tuple[str, Version], set[str]] = {}
    for key in ordered_keys:
        matching = tuple(
            requirement
            for requirement in active
            if canonicalize_name(requirement.name) == key[0]
            and _requirement_accepts_version(requirement, str(key[1]))
        )
        requested = _canonical_requested_extras(matching)
        selected = _select_artifacts(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
        ).semantic_metadata
        initial[key] = {
            extra
            for extra in requested
            if all(
                "provides-extra" not in artifact.dynamic
                and extra in artifact.provides_extra
                for artifact in selected
            )
        }
    return initial


def _assess_declared_dependency_metadata(
    artifacts: Sequence[MetadataArtifact],
    *,
    target: EnvironmentTarget,
    configuration: DependencyConfiguration,
    declared: Sequence[EvaluatedRequirement],
    resolution: ResolverResult,
) -> tuple[DependencyAssessment, ...]:
    active = tuple(Requirement(item.requirement) for item in declared if item.applies)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    active_groups: dict[str, list[Requirement]] = {}
    for requirement in active:
        name = canonicalize_name(requirement.name)
        active_groups.setdefault(name, []).append(requirement)
    use_resolver_selection = (
        resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete
    )
    grouped = (
        _resolver_dependency_groups(resolution, artifacts_by_id)
        if use_resolver_selection
        else _direct_dependency_groups(artifacts, active)
    )
    ordered_keys = tuple(sorted(grouped, key=lambda item: (item[0], item[1])))
    ambiguous_names = {
        name
        for name in {key[0] for key in ordered_keys}
        if sum(key[0] == name for key in ordered_keys) > 1
    }
    seed_keys = (
        _resolver_root_keys(
            ordered_keys,
            active_groups,
            resolution,
            artifacts_by_id,
        )
        if use_resolver_selection
        else ordered_keys
    )
    initial_extras = _initial_dependency_extras(ordered_keys, active, grouped, target)
    raw_assessments = _propagated_dependency_assessments(
        grouped,
        ordered_keys,
        target=target,
        initial_extras=initial_extras,
        seed_keys=seed_keys,
    )
    assessments: list[DependencyAssessment] = []
    for key in ordered_keys:
        if key not in raw_assessments:
            continue
        matching_requirements = tuple(
            requirement
            for requirement in active_groups.get(key[0], ())
            if _requirement_accepts_version(requirement, str(key[1]))
        )
        assessment = raw_assessments[key]
        if configuration.project_kind is DependencyProjectKind.LIBRARY:
            assessment = _unverify_library_artifact_sample(assessment)
        if not use_resolver_selection and key[0] in ambiguous_names:
            assessment = replace(
                assessment,
                status=DependencyCompatibilityStatus.UNVERIFIED,
                reason=(
                    "active constraints match multiple supplied package versions; "
                    "exact resolver provenance is required"
                ),
            )
        if (
            configuration.project_kind is DependencyProjectKind.LIBRARY
            and assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
            and matching_requirements
            and not any(
                _requirement_is_singleton_pin(requirement)
                for requirement in matching_requirements
            )
        ):
            assessment = replace(
                assessment,
                status=DependencyCompatibilityStatus.UNVERIFIED,
                reason=(
                    "one sampled library version does not establish compatibility "
                    "for the declared range; complete resolver evidence is required"
                ),
            )
        assessments.append(assessment)
    return tuple(assessments)


def _artifact_satisfies_requirements(
    artifact: MetadataArtifact, requirements: Sequence[Requirement]
) -> bool:
    if not requirements:
        return False
    canonical_name = canonicalize_name(requirements[0].name)
    required_extras = _canonical_requested_extras(requirements)
    return (
        artifact.canonical_name == canonical_name
        and all(
            _requirement_accepts_version(requirement, artifact.version)
            for requirement in requirements
        )
        and "provides-extra" not in artifact.dynamic
        and required_extras.issubset(artifact.provides_extra)
    )


def _matching_metadata_artifact_ids(
    artifacts: Sequence[MetadataArtifact], requirements: Sequence[Requirement]
) -> tuple[str, ...]:
    """Return candidate groups whose every viable artifact proves the extras."""
    if not requirements:
        return ()
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        if _artifact_satisfies_version_constraints(artifact, requirements):
            key = artifact.canonical_name, Version(artifact.version)
            grouped.setdefault(key, []).append(artifact)
    matching = {
        artifact.artifact_id
        for group in grouped.values()
        if all(
            _artifact_satisfies_requirements(artifact, requirements)
            for artifact in group
        )
        for artifact in group
    }
    return tuple(sorted(matching))


def _artifact_satisfies_version_constraints(
    artifact: MetadataArtifact, requirements: Sequence[Requirement]
) -> bool:
    """Return whether one artifact matches only the named version constraints."""
    if not requirements:
        return False
    canonical_name = canonicalize_name(requirements[0].name)
    return artifact.canonical_name == canonical_name and all(
        _requirement_accepts_version(requirement, artifact.version)
        for requirement in requirements
    )


def _resolved_package_satisfies_requirements(
    package: ResolvedPackage,
    requirements: Sequence[Requirement],
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> bool:
    if (
        not package.metadata_used
        or len(package.metadata_used) != len(set(package.metadata_used))
        or not requirements
    ):
        return False
    selected = tuple(
        artifacts_by_id.get(artifact_id) for artifact_id in package.metadata_used
    )
    return (
        all(artifact is not None for artifact in selected)
        and all(
            canonicalize_name(package.name) == canonicalize_name(requirement.name)
            and _requirement_accepts_version(requirement, package.version)
            for requirement in requirements
        )
        and all(
            artifact is not None
            and artifact.canonical_name == canonicalize_name(package.name)
            and Version(artifact.version) == Version(package.version)
            and _artifact_satisfies_requirements(artifact, requirements)
            for artifact in selected
        )
    )


def _resolved_package_satisfies_version_constraints(
    package: ResolvedPackage,
    requirements: Sequence[Requirement],
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> bool:
    selected = _resolved_artifact_group(package, artifacts_by_id)
    return selected is not None and all(
        _artifact_satisfies_version_constraints(artifact, requirements)
        for artifact in selected
    )


def _active_requirement_groups(
    declared: Sequence[EvaluatedRequirement],
) -> dict[str, list[Requirement]]:
    groups: dict[str, list[Requirement]] = {}
    for item in declared:
        if item.applies:
            requirement = Requirement(item.requirement)
            groups.setdefault(canonicalize_name(requirement.name), []).append(
                requirement
            )
    return groups


@dataclass(frozen=True)
class _ResolverValidationContext:
    artifacts: Sequence[MetadataArtifact]
    declared: Sequence[EvaluatedRequirement]
    configuration: DependencyConfiguration
    target: EnvironmentTarget
    expected_resolver: str


def _resolver_result_header_is_valid(
    resolution: ResolverResult,
    expected_resolver: str,
) -> bool:
    try:
        _string(expected_resolver, "expected resolver adapter")
        _string(resolution.resolver, "resolver result adapter")
        _string(resolution.reason, "resolver result reason")
        if resolution.resolver_version is not None:
            version = _string(resolution.resolver_version, "resolver result version")
            if not _resolver_version_is_valid(version):
                return False
    except ConfigurationError:
        return False
    return (
        isinstance(resolution.status, ResolutionStatus)
        and type(resolution.complete) is bool
        and resolution.resolver == expected_resolver
    )


def _normalized_resolved_packages(
    packages: object,
) -> tuple[ResolvedPackage, ...] | None:
    if not isinstance(packages, tuple) or len(packages) > _MAX_RESOLVER_PACKAGES:
        return None
    normalized: list[ResolvedPackage] = []
    for package in packages:
        try:
            if not isinstance(package, ResolvedPackage):
                return None
            name = canonicalize_name(
                _string(package.name, "resolved package name"),
                validate=True,
            )
            version = _string(package.version, "resolved package version")
            canonical_version = str(Version(version))
            if (
                not isinstance(package.metadata_used, tuple)
                or len(package.metadata_used) > _MAX_METADATA_INPUTS
            ):
                return None
            metadata_used = tuple(
                _string(value, "resolved package metadata identity")
                for value in package.metadata_used
            )
            if len(metadata_used) != len(set(metadata_used)) or any(
                _SHA256.fullmatch(value) is None for value in metadata_used
            ):
                return None
        except (ConfigurationError, ValueError):
            return None
        normalized.append(
            replace(
                package,
                name=name,
                version=canonical_version,
                metadata_used=tuple(sorted(metadata_used)),
            )
        )
    ordered = tuple(
        sorted(
            normalized,
            key=lambda item: (
                item.name,
                Version(item.version),
            ),
        )
    )
    names = tuple(item.name for item in ordered)
    return ordered if len(names) == len(set(names)) else None


def _resolver_status_shape_is_valid(
    resolution: ResolverResult,
    *,
    requested: bool,
) -> bool:
    if not requested:
        return (
            resolution.status is ResolutionStatus.NOT_REQUESTED
            and resolution.complete
            and resolution.resolver_version is None
            and not resolution.packages
        )
    if resolution.status is ResolutionStatus.SUCCEEDED:
        return resolution.complete and resolution.resolver_version is not None
    if resolution.status in {
        ResolutionStatus.ARTIFACT_UNAVAILABLE,
        ResolutionStatus.RESOLUTION_FAILED,
    }:
        return (
            resolution.complete
            and resolution.resolver_version is not None
            and not resolution.packages
        )
    if resolution.status is ResolutionStatus.TIMED_OUT:
        return not resolution.complete and not resolution.packages
    return (
        resolution.status is ResolutionStatus.UNVERIFIED
        and not resolution.complete
        and (not resolution.packages or resolution.resolver_version is not None)
    )


def _partial_resolver_provenance_is_valid(
    resolution: ResolverResult,
    artifacts: Sequence[MetadataArtifact],
) -> bool:
    """Validate every artifact identity a partial resolver result chooses to cite."""
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    return all(
        not package.metadata_used
        or _resolved_artifact_group(package, artifacts_by_id) is not None
        for package in resolution.packages
    )


def _resolver_failure_is_corroborated(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> bool:
    active_requirements = tuple(
        item.requirement for item in context.declared if item.applies
    )
    if resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE:
        return bool(
            not context.configuration.network
            and _offline_artifact_unavailability(
                active_requirements,
                context.artifacts,
                context.target,
                context.configuration.project_kind,
            )
        )
    if resolution.status is ResolutionStatus.RESOLUTION_FAILED:
        return bool(_conflicting_requirement_names(active_requirements))
    return True


def _resolver_success_is_provenance_bound(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> bool:
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in context.artifacts}
    canonical_names = tuple(
        canonicalize_name(package.name) for package in resolution.packages
    )
    structurally_valid = len(canonical_names) == len(set(canonical_names)) and all(
        _resolved_artifact_group(package, artifacts_by_id) is not None
        for package in resolution.packages
    )
    active_groups = _active_requirement_groups(context.declared)
    _consume_dependency_work(len(active_groups) * len(resolution.packages))
    target_bound = structurally_valid and all(
        len(package.metadata_used) == 1
        and (selected := _resolved_artifact_group(package, artifacts_by_id)) is not None
        and (
            assessment := _assessment(
                selected,
                context.target,
                tuple(
                    sorted(
                        _canonical_requested_extras(
                            active_groups.get(canonicalize_name(package.name), ())
                        )
                    )
                ),
            )
        ).status
        is DependencyCompatibilityStatus.COMPATIBLE
        and frozenset(assessment.metadata_used) == frozenset(package.metadata_used)
        for package in resolution.packages
    )
    roots_covered = structurally_valid and all(
        sum(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == name
        )
        == 1
        for name, requirements in active_groups.items()
    )
    return structurally_valid and target_bound and roots_covered


def _validated_resolver_result(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> ResolverResult:
    """Fail closed when a replaceable resolver contradicts exact provenance."""
    if not isinstance(resolution, ResolverResult) or not (
        _resolver_result_header_is_valid(resolution, context.expected_resolver)
    ):
        return _resolver_unverified("resolver returned invalid structured evidence")
    packages = _normalized_resolved_packages(resolution.packages)
    if packages is None:
        return _resolver_unverified("resolver returned invalid structured evidence")
    resolution = replace(resolution, packages=packages)
    if (
        not _resolver_status_shape_is_valid(
            resolution,
            requested=context.configuration.resolve,
        )
        or not _resolver_failure_is_corroborated(resolution, context)
        or not _partial_resolver_provenance_is_valid(
            resolution,
            context.artifacts,
        )
    ):
        return _resolver_unverified(
            "resolver returned contradictory structured evidence"
        )
    if resolution.status is not ResolutionStatus.SUCCEEDED:
        return resolution
    if _resolver_success_is_provenance_bound(
        resolution,
        context,
    ):
        return resolution
    return replace(
        resolution,
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        reason=(
            "resolver success did not provide one exact, provenance-bound selection "
            "for every active requirement"
        ),
    )


def _correlate_declared_requirements(
    declared: Sequence[EvaluatedRequirement],
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
    project_kind: DependencyProjectKind,
) -> tuple[EvaluatedRequirement, ...]:
    active_groups = _active_requirement_groups(declared)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_artifacts = _resolution_evidence_artifacts(artifacts, resolution)
    correlations: dict[
        str,
        tuple[tuple[str, ...], tuple[str, ...], bool, str],
    ] = {}
    for name, active_group in active_groups.items():
        group = tuple(active_group)
        _consume_dependency_work(
            len(evidence_artifacts) + len(resolution.packages) + len(artifacts)
        )
        matching_metadata = _matching_metadata_artifact_ids(
            evidence_artifacts,
            group,
        )
        matching_versions = {
            Version(artifact.version)
            for artifact in evidence_artifacts
            if _artifact_satisfies_version_constraints(artifact, group)
        }
        resolved_versions = tuple(
            sorted(
                f"{canonicalize_name(package.name)}=={package.version}"
                for package in resolution.packages
                if _resolved_package_satisfies_requirements(
                    package,
                    group,
                    artifacts_by_id,
                )
            )
        )
        complete_selection = (
            resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete
        )
        if (
            project_kind is DependencyProjectKind.APPLICATION
            and not complete_selection
            and len(matching_versions) > 1
        ):
            verified = False
            reason = (
                "active application pin matches multiple supplied package versions; "
                "exact resolver provenance is required"
            )
        elif (
            project_kind is DependencyProjectKind.LIBRARY
            and not complete_selection
            and not any(_requirement_is_singleton_pin(item) for item in group)
        ):
            verified = False
            reason = (
                "a finite library artifact sample does not prove the complete "
                "declared version set"
            )
        elif matching_metadata:
            verified = True
            reason = "active requirement matches directly inspected metadata"
        elif (
            resolution.status is ResolutionStatus.SUCCEEDED
            and resolution.complete
            and resolved_versions
        ):
            verified = True
            reason = "active requirement matches complete resolver evidence"
        elif (
            resolution.status is ResolutionStatus.RESOLUTION_FAILED
            and resolution.complete
        ):
            verified = True
            reason = "complete resolver evidence proves the declared set unsatisfiable"
        elif (
            resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
            and resolution.complete
            and not any(
                _artifact_satisfies_version_constraints(artifact, group)
                for artifact in artifacts
            )
        ):
            verified = True
            reason = (
                "the complete offline artifact set contains no distribution "
                "satisfying the active requirement"
            )
        else:
            verified = False
            reason = (
                "simultaneously active constraints have no common exact metadata "
                "or complete resolver selection"
                if len(group) > 1
                else "active requirement has no matching exact metadata or complete "
                "resolver evidence"
            )
        correlations[name] = (
            matching_metadata,
            resolved_versions,
            verified,
            reason,
        )
    correlated: list[EvaluatedRequirement] = []
    for item in declared:
        if not item.applies:
            correlated.append(item)
            continue
        requirement = Requirement(item.requirement)
        matching_metadata, resolved_versions, verified, reason = correlations[
            canonicalize_name(requirement.name)
        ]
        correlated.append(
            EvaluatedRequirement(
                requirement=item.requirement,
                applies=True,
                matching_extras=item.matching_extras,
                matching_metadata=matching_metadata,
                resolved_versions=resolved_versions,
                verified=verified,
                reason=reason,
            )
        )
    return tuple(correlated)


def _exact_requirement_version(requirement: Requirement) -> str | None:
    specifiers = tuple(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator not in {"==", "==="}
        or specifiers[0].version.endswith(".*")
    ):
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


def _requirement_is_singleton_pin(requirement: Requirement) -> bool:
    """Return whether one specifier names a single distribution version."""
    specifiers = tuple(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].version.endswith(".*"):
        return False
    if specifiers[0].operator == "===":
        return True
    if specifiers[0].operator != "==":
        return False
    try:
        return Version(specifiers[0].version).local is not None
    except InvalidVersion:
        return False


def _transitive_occurrences(
    assessments: Sequence[DependencyAssessment],
) -> dict[str, dict[str, set[str]]]:
    occurrences: dict[str, dict[str, set[str]]] = {}
    for assessment in assessments:
        parent = f"{canonicalize_name(assessment.package)}=={assessment.version}"
        for value in assessment.applicable_requirements:
            requirement = Requirement(value)
            name = canonicalize_name(requirement.name)
            occurrences.setdefault(name, {}).setdefault(value, set()).add(parent)
    return occurrences


def _validated_resolver_closure(
    resolution: ResolverResult,
    assessments: Sequence[DependencyAssessment],
    artifacts: Sequence[MetadataArtifact],
) -> ResolverResult:
    """Reject successful selections that omit an active dependency package."""
    if not (resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete):
        return resolution
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    resolved_keys = {
        (canonicalize_name(package.name), Version(package.version))
        for package in resolution.packages
    }
    reachable_keys = {
        (canonicalize_name(assessment.package), Version(assessment.version))
        for assessment in assessments
    }
    if reachable_keys != resolved_keys:
        return replace(
            resolution,
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            reason=(
                "resolver success included a package outside the exact active "
                "dependency closure"
            ),
        )
    occurrences = _transitive_occurrences(assessments)
    _consume_dependency_work(len(occurrences) * len(resolution.packages))
    closure_complete = all(
        sum(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == name
        )
        == 1
        for name, values in occurrences.items()
        for requirements in (tuple(Requirement(value) for value in values),)
    )
    if closure_complete:
        return resolution
    return replace(
        resolution,
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        reason=(
            "resolver success omitted an exact provenance-bound package from the "
            "active selected dependency closure"
        ),
    )


def _transitive_coverage_verdict(
    coverage: _TransitiveCoverage,
) -> tuple[bool, str]:
    if (
        coverage.resolution.status is ResolutionStatus.RESOLUTION_FAILED
        and coverage.resolution.complete
    ):
        verdict = (
            True,
            "complete resolver evidence proves the declared set unsatisfiable",
        )
    elif coverage.project_kind is DependencyProjectKind.LIBRARY:
        verified = bool(
            coverage.resolution.status is ResolutionStatus.SUCCEEDED
            and coverage.resolution.complete
            and coverage.resolved_versions
        )
        reason = (
            "active library requirement matches complete resolver evidence"
            if verified
            else "active library transitive requirement requires complete resolver "
            "evidence"
        )
        verdict = verified, reason
    elif (
        coverage.resolution.status is ResolutionStatus.SUCCEEDED
        and coverage.resolution.complete
        and coverage.resolved_versions
    ):
        verdict = (
            True,
            "active transitive requirement matches complete resolver evidence",
        )
    elif not coverage.lock_requirements:
        verdict = (
            False,
            "active transitive requirement is missing from the application lock",
        )
    elif len(coverage.common_lock_versions) != 1:
        verdict = (
            False,
            (
                "simultaneously active Requires-Dist entries and application pins "
                "have no common exact version"
            ),
        )
    elif coverage.matching_metadata:
        verdict = (
            True,
            (
                "active transitive requirement matches the exact application lock "
                "and directly inspected metadata"
            ),
        )
    else:
        verdict = (
            False,
            (
                "active transitive requirement has an application pin but no "
                "matching exact metadata or complete resolver evidence"
            ),
        )
    return verdict


def _transitive_requirement_evidence(
    project_kind: DependencyProjectKind,
    assessments: Sequence[DependencyAssessment],
    declared: Sequence[EvaluatedRequirement],
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
) -> tuple[TransitiveRequirementEvidence, ...]:
    occurrences = _transitive_occurrences(assessments)
    active_lock = _active_requirement_groups(declared)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_artifacts = _resolution_evidence_artifacts(artifacts, resolution)
    _consume_dependency_work(
        len(occurrences) * (len(evidence_artifacts) + len(resolution.packages))
    )
    evidence: list[TransitiveRequirementEvidence] = []
    for name in sorted(occurrences):
        requirement_values = tuple(sorted(occurrences[name]))
        requirements = tuple(Requirement(value) for value in requirement_values)
        lock_requirements = tuple(active_lock.get(name, ()))
        raw_lock_versions = tuple(
            version
            for requirement in lock_requirements
            if (version := _exact_requirement_version(requirement)) is not None
        )
        lock_versions = tuple(
            sorted({f"{name}=={version}" for version in raw_lock_versions})
        )
        evidence_requirements = (
            requirements
            if project_kind is DependencyProjectKind.LIBRARY
            else (*lock_requirements, *requirements)
        )
        matching_metadata = _matching_metadata_artifact_ids(
            evidence_artifacts,
            evidence_requirements,
        )
        matching_ids = frozenset(matching_metadata)
        common_lock_versions = frozenset(
            Version(artifact.version)
            for artifact in evidence_artifacts
            if artifact.artifact_id in matching_ids
        )
        resolved_versions = tuple(
            sorted(
                f"{name}=={package.version}"
                for package in resolution.packages
                if _resolved_package_satisfies_requirements(
                    package, requirements, artifacts_by_id
                )
                and (
                    project_kind is DependencyProjectKind.LIBRARY
                    or not lock_requirements
                    or Version(package.version) in common_lock_versions
                )
            )
        )

        verified, reason = _transitive_coverage_verdict(
            _TransitiveCoverage(
                project_kind=project_kind,
                resolution=resolution,
                resolved_versions=resolved_versions,
                lock_requirements=lock_requirements,
                common_lock_versions=common_lock_versions,
                matching_metadata=matching_metadata,
            )
        )
        evidence.extend(
            TransitiveRequirementEvidence(
                requirement=value,
                required_by=tuple(sorted(occurrences[name][value])),
                locked_versions=lock_versions,
                matching_metadata=matching_metadata,
                resolved_versions=resolved_versions,
                verified=verified,
                reason=reason,
            )
            for value in requirement_values
        )
    return tuple(evidence)


def _active_resolver_requirements(
    requirements: Sequence[str], target: EnvironmentTarget, extras: tuple[str, ...]
) -> tuple[str, ...]:
    active: list[str] = []
    for value in requirements:
        evaluated = _evaluate_requirement(value, target, extras)
        if evaluated.applies:
            active.append(value.partition(";")[0].rstrip())
    return tuple(active)


def _resolver_requirement_groups(
    requirements: Sequence[str],
) -> dict[str, tuple[Requirement, ...]]:
    groups: dict[str, list[Requirement]] = {}
    for value in requirements:
        requirement = Requirement(value)
        groups.setdefault(canonicalize_name(requirement.name), []).append(requirement)
    return {
        name: tuple(sorted(group, key=str)) for name, group in sorted(groups.items())
    }


def _conflicting_requirement_names(requirements: Sequence[str]) -> tuple[str, ...]:
    """Name groups whose active constraints prove a direct contradiction."""
    conflicts: list[str] = []
    for name, group in _resolver_requirement_groups(requirements).items():
        exact_versions = tuple(
            sorted(
                {
                    Version(version)
                    for requirement in group
                    if (version := _exact_requirement_version(requirement)) is not None
                }
            )
        )
        _consume_dependency_work(len(exact_versions) * len(group))
        exact_conflict = bool(exact_versions) and not any(
            all(
                requirement.specifier.contains(candidate, prereleases=True)
                for requirement in group
            )
            for candidate in exact_versions
        )
        lower: tuple[Version, bool] | None = None
        upper: tuple[Version, bool] | None = None
        for requirement in group:
            for specifier in requirement.specifier:
                if specifier.operator not in {">", ">=", "<", "<="}:
                    continue
                try:
                    boundary = Version(specifier.version)
                except InvalidVersion:
                    continue
                inclusive = specifier.operator in {">=", "<="}
                if specifier.operator in {">", ">="} and (
                    lower is None
                    or boundary > lower[0]
                    or (boundary == lower[0] and not inclusive and lower[1])
                ):
                    lower = boundary, inclusive
                if specifier.operator in {"<", "<="} and (
                    upper is None
                    or boundary < upper[0]
                    or (boundary == upper[0] and not inclusive and upper[1])
                ):
                    upper = boundary, inclusive
        bounded_conflict = bool(
            lower is not None
            and upper is not None
            and (
                lower[0] > upper[0]
                or (lower[0] == upper[0] and not (lower[1] and upper[1]))
            )
        )
        if exact_conflict or bounded_conflict:
            conflicts.append(name)
    return tuple(conflicts)


def _offline_artifact_unavailability(
    requirements: Sequence[str],
    artifacts: Sequence[MetadataArtifact],
    target: EnvironmentTarget,
    project_kind: DependencyProjectKind,
) -> tuple[str, ...]:
    """Identify requirements the closed, revalidated wheelhouse cannot satisfy."""
    if project_kind is not DependencyProjectKind.APPLICATION:
        return ()
    conflicts = frozenset(_conflicting_requirement_names(requirements))
    unavailable: list[str] = []
    for name, group in _resolver_requirement_groups(requirements).items():
        if name in conflicts:
            continue
        _consume_dependency_work(len(artifacts))
        candidates = tuple(
            artifact
            for artifact in artifacts
            if _artifact_satisfies_version_constraints(artifact, group)
        )
        if not candidates:
            unavailable.append(" & ".join(str(requirement) for requirement in group))
            continue
        selected_extras = tuple(sorted(_canonical_requested_extras(group)))
        assessments = assess_dependency_metadata(
            candidates,
            target=target,
            extras=selected_extras,
        )
        if assessments and all(
            assessment.status is DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE
            for assessment in assessments
        ):
            unavailable.append(" & ".join(str(requirement) for requirement in group))
    return tuple(unavailable)


def _resolver_version_is_valid(value: str) -> bool:
    match = _RESOLVER_VERSION.fullmatch(value)
    if match is None:
        return False
    try:
        Version(match.group("release"))
    except InvalidVersion:
        return False
    return True


def _resolver_version(output: str, resolver: str) -> str | None:
    line = output.strip().splitlines()
    if len(line) != 1 or not line[0].startswith(f"{resolver} "):
        return None
    version = line[0][len(resolver) + 1 :].strip()
    if (
        not version
        or len(version) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in version)
        or not _resolver_version_is_valid(version)
    ):
        return None
    return version


def _safe_process_text(value: str, workspace: Path) -> str:
    variants = {str(workspace), workspace.as_posix()}
    try:
        uri = workspace.resolve().as_uri()
    except (OSError, RuntimeError, ValueError):
        uri = ""
    if uri:
        variants.add(uri)
        variants.add(urlsplit(uri).path)
    normalized = value
    for variant in sorted((item for item in variants if item), key=len, reverse=True):
        normalized = normalized.replace(variant, "<workspace>")
    lines = []
    for raw_line in normalized.splitlines():
        safe_line = "".join(
            character if character.isprintable() else " " for character in raw_line
        ).strip()
        if safe_line:
            lines.append(safe_line)
    return " ".join(lines)[:_MAX_TEXT_LENGTH]


def _selected_metadata(
    raw_wheels: object,
    *,
    package_name: str,
    package_version: str,
    artifacts_by_filename: dict[str, MetadataArtifact],
    wheelhouse: Path,
) -> tuple[str, ...]:
    if not isinstance(raw_wheels, list) or len(raw_wheels) != 1:
        return ()
    wheel = raw_wheels[0]
    url = wheel.get("url") if isinstance(wheel, dict) else None
    if (
        not isinstance(url, str)
        or len(url) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in url)
    ):
        return ()
    parsed = urlsplit(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        return ()
    try:
        selected = Path(url2pathname(unquote(parsed.path))).resolve()
    except (OSError, RuntimeError, ValueError):
        return ()
    artifact = artifacts_by_filename.get(selected.name)
    if (
        artifact is None
        or selected.parent != wheelhouse
        or artifact.canonical_name != package_name
        or Version(artifact.version) != Version(package_version)
        or artifact.kind is not MetadataKind.WHEEL
    ):
        return ()
    return (artifact.artifact_id,)


def _pylock_package(
    raw_package: object,
    *,
    artifacts_by_filename: dict[str, MetadataArtifact],
    wheelhouse: Path,
) -> ResolvedPackage:
    if not isinstance(raw_package, dict):
        _fail_metadata("resolver pylock.toml has an invalid package record")
    name = raw_package.get("name")
    raw_version = raw_package.get("version")
    if (
        not isinstance(name, str)
        or not isinstance(raw_version, str)
        or not name
        or len(name) > _MAX_TEXT_LENGTH
        or len(raw_version) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in name + raw_version)
    ):
        _fail_metadata("resolver pylock.toml omits an exact package identity")
    try:
        version = str(Version(raw_version))
    except InvalidVersion:
        _fail_metadata("resolver pylock.toml has an invalid package version")
    canonical_name = canonicalize_name(name)
    return ResolvedPackage(
        name=name,
        version=version,
        metadata_used=_selected_metadata(
            raw_package.get("wheels"),
            package_name=canonical_name,
            package_version=version,
            artifacts_by_filename=artifacts_by_filename,
            wheelhouse=wheelhouse,
        ),
    )


def _resolved_packages(
    output: str,
    artifacts: Sequence[MetadataArtifact],
    *,
    wheelhouse: Path,
) -> tuple[tuple[ResolvedPackage, ...], bool]:
    try:
        document = tomllib.loads(output)
    except tomllib.TOMLDecodeError:
        _fail_metadata("resolver produced invalid pylock.toml output")
    if document.get("lock-version") != "1.0" or document.get("created-by") != "uv":
        _fail_metadata("resolver produced an unsupported pylock.toml document")
    raw_packages = document.get("packages", [])
    if not isinstance(raw_packages, list):
        _fail_metadata("resolver pylock.toml omits its package list")
    if len(raw_packages) > _MAX_RESOLVER_PACKAGES:
        _fail_metadata("resolver pylock.toml contains too many packages")
    artifacts_by_filename = {artifact.path.name: artifact for artifact in artifacts}
    packages = tuple(
        _pylock_package(
            item,
            artifacts_by_filename=artifacts_by_filename,
            wheelhouse=wheelhouse.resolve(),
        )
        for item in raw_packages
    )
    canonical_names = tuple(canonicalize_name(item.name) for item in packages)
    if len(canonical_names) != len(set(canonical_names)):
        _fail_metadata("resolver pylock.toml repeats a package identity")
    return (
        tuple(
            sorted(
                packages,
                key=lambda item: (canonicalize_name(item.name), Version(item.version)),
            )
        ),
        all(item.metadata_used for item in packages),
    )


def _resolver_unverified(
    reason: str,
    version: str | None = None,
    packages: tuple[ResolvedPackage, ...] = (),
) -> ResolverResult:
    return ResolverResult(
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        resolver="uv",
        resolver_version=version,
        packages=packages,
        reason=reason,
    )


def _resolver_environment(workspace: Path) -> dict[str, str]:
    home = workspace / "home"
    temporary = workspace / "tmp"
    cache = workspace / "cache"
    for path in (home, temporary, cache):
        path.mkdir()
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "TMPDIR": str(temporary),
        "UV_CACHE_DIR": str(cache),
        "UV_NO_CONFIG": "1",
        "UV_NO_PROGRESS": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    if os.name == "nt":
        environment["USERPROFILE"] = str(home)
        if "SYSTEMROOT" in os.environ:
            environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _IoCounters(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    )


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _ThreadEntry32(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    )


class _CtypesFunction(Protocol):
    argtypes: object
    restype: object

    def __call__(self, *args: object) -> object: ...


def _windows_kernel32() -> object:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError
    return loader("kernel32", use_last_error=True)


def _windows_function(library: object, name: str) -> _CtypesFunction:
    return cast("_CtypesFunction", getattr(library, name))


def _create_windows_kill_job(process: subprocess.Popen[bytes]) -> int | None:
    if os.name != "nt":
        return None
    kernel32 = _windows_kernel32()
    create_job = _windows_function(kernel32, "CreateJobObjectW")
    set_information = _windows_function(kernel32, "SetInformationJobObject")
    assign_process = _windows_function(kernel32, "AssignProcessToJobObject")
    close_handle = _windows_function(kernel32, "CloseHandle")
    create_job.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    create_job.restype = wintypes.HANDLE
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    assign_process.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_process.restype = wintypes.BOOL
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_job = create_job(None, None)
    if not isinstance(raw_job, int) or not raw_job:
        return None
    job = raw_job
    information = _JobObjectExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_CLOSE
    configured = set_information(
        job,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    process_handle = getattr(process, "_handle", None)
    assigned = bool(
        configured
        and isinstance(process_handle, int)
        and assign_process(job, wintypes.HANDLE(process_handle))
    )
    if not assigned:
        close_handle(job)
        return None
    return int(job)


def _close_windows_job(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close_handle = _windows_function(kernel32, "CloseHandle")
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        message = "CloseHandle failed for resolver Job Object"
        raise OSError(message)


def _terminate_windows_job(handle: int) -> None:
    """Terminate every process assigned to one resolver Job Object."""
    kernel32 = _windows_kernel32()
    terminate_job = _windows_function(kernel32, "TerminateJobObject")
    terminate_job.argtypes = (wintypes.HANDLE, wintypes.UINT)
    terminate_job.restype = wintypes.BOOL
    if not terminate_job(wintypes.HANDLE(handle), wintypes.UINT(1)):
        message = "TerminateJobObject failed for resolver Job Object"
        raise OSError(message)


def _dispose_windows_job(handle: int) -> bool:
    """Close a Job, explicitly terminating its tree if close is not confirmed."""
    try:
        _close_windows_job(handle)
    except OSError:
        try:
            _terminate_windows_job(handle)
        except OSError:
            return False
        with suppress(OSError):
            _close_windows_job(handle)
    return True


def _windows_process_thread_ids(process_id: int) -> tuple[int, ...]:
    kernel32 = _windows_kernel32()
    create_snapshot = _windows_function(kernel32, "CreateToolhelp32Snapshot")
    thread_first = _windows_function(kernel32, "Thread32First")
    thread_next = _windows_function(kernel32, "Thread32Next")
    close_handle = _windows_function(kernel32, "CloseHandle")
    create_snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create_snapshot.restype = wintypes.HANDLE
    thread_first.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32))
    thread_first.restype = wintypes.BOOL
    thread_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32))
    thread_next.restype = wintypes.BOOL
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_snapshot = create_snapshot(_TH32CS_SNAPTHREAD, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if (
        not isinstance(raw_snapshot, int)
        or not raw_snapshot
        or raw_snapshot == invalid_handle
    ):
        return ()
    snapshot = raw_snapshot
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(_ThreadEntry32)
        identifiers: list[int] = []
        present = bool(thread_first(snapshot, ctypes.byref(entry)))
        while present:
            if int(entry.th32OwnerProcessID) == process_id:
                identifiers.append(int(entry.th32ThreadID))
            present = bool(thread_next(snapshot, ctypes.byref(entry)))
        return tuple(identifiers)
    finally:
        close_handle(wintypes.HANDLE(snapshot))


def _resume_windows_primary_thread(process_id: int) -> bool:
    identifiers = _windows_process_thread_ids(process_id)
    if len(identifiers) != 1:
        return False
    kernel32 = _windows_kernel32()
    open_thread = _windows_function(kernel32, "OpenThread")
    resume_thread = _windows_function(kernel32, "ResumeThread")
    close_handle = _windows_function(kernel32, "CloseHandle")
    open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_thread.restype = wintypes.HANDLE
    resume_thread.argtypes = (wintypes.HANDLE,)
    resume_thread.restype = wintypes.DWORD
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_thread = open_thread(_THREAD_SUSPEND_RESUME, wintypes.BOOL(), identifiers[0])
    if not isinstance(raw_thread, int) or not raw_thread:
        return False
    thread = raw_thread
    try:
        previous_count = resume_thread(wintypes.HANDLE(thread))
        return (
            isinstance(previous_count, int)
            and previous_count > 0
            and previous_count != _INVALID_DWORD
        )
    finally:
        close_handle(wintypes.HANDLE(thread))


class _ProcessContainment:
    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.windows_job: int | None = None
        self.lock = threading.Lock()
        self.terminated = False

    def attach_process(self, process: subprocess.Popen[bytes]) -> None:
        """Record process ownership before any later setup can be interrupted."""
        self.process = process

    def attach_windows_job(self, windows_job: int) -> None:
        """Record Job ownership before the suspended process is resumed."""
        self.windows_job = windows_job

    def terminate(self) -> None:
        """Kill the isolated process tree, retaining state for interrupted retries."""
        with self.lock:
            if self.terminated:
                return
            if self.windows_job is not None:
                job_terminated = _dispose_windows_job(self.windows_job)
                if job_terminated:
                    self.windows_job = None
                    self.terminated = True
                    return
            if self.process is None:
                self.terminated = self.windows_job is None
                return
            if os.name != "nt":
                try:
                    os.killpg(self.process.pid, _POSIX_FORCE_KILL_SIGNAL)
                except OSError:
                    pass
                else:
                    self.terminated = self.windows_job is None
                    return
            try:
                self.process.kill()
            except OSError:
                pass
            else:
                self.terminated = self.windows_job is None


def _retry_windows_job_disposal(
    windows_job: int,
) -> tuple[bool, BaseException | None]:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            terminated = _dispose_windows_job(windows_job)
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        if terminated:
            return True, interruption
    return False, interruption


def _terminate_uncontained_root(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            process.kill()
        except OSError:
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _retry_process_group_termination(
    process: subprocess.Popen[bytes],
) -> tuple[bool, BaseException | None]:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            os.killpg(process.pid, _POSIX_FORCE_KILL_SIGNAL)
        except OSError:
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        return True, interruption
    return False, interruption


def _finish_uncontained_cleanup(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption = _wait_for_process_cleanup(process)
    return _preserve_first_cleanup_error(
        interruption,
        _close_process_streams(process),
    )


def _cleanup_uncontained_process(
    process: subprocess.Popen[bytes], windows_job: int | None
) -> None:
    """Bound cleanup before ownership passes to ``_ProcessContainment``."""
    terminated = False
    interruption: BaseException | None = None
    if windows_job is not None:
        terminated, interruption = _retry_windows_job_disposal(windows_job)
    elif os.name != "nt":
        terminated, interruption = _retry_process_group_termination(process)
    if not terminated:
        root_interruption = _terminate_uncontained_root(process)
        if interruption is None:
            interruption = root_interruption
    finish_interruption = _finish_uncontained_cleanup(process)
    if interruption is None:
        interruption = finish_interruption
    if interruption is not None:
        raise interruption


def _replay_deferred_sigint(
    handler: object,
    signum: int,
    frame: FrameType | None,
) -> None:
    """Run the prior SIGINT disposition after process ownership is recorded."""
    if handler is signal.SIG_IGN:
        return
    if handler is signal.SIG_DFL or not callable(handler):
        signal.default_int_handler(signum, frame)
    else:
        handler(signum, frame)


def _popen_attached_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    creationflags: int,
    containment: _ProcessContainment,
) -> subprocess.Popen[bytes]:
    """Spawn and record ownership before replaying a main-thread SIGINT."""

    def spawn() -> subprocess.Popen[bytes]:
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        containment.attach_process(process)
        return process

    if threading.current_thread() is not threading.main_thread():
        return spawn()

    deferred_sigint: list[tuple[int, FrameType | None]] = []

    def record_sigint(signum: int, frame: FrameType | None) -> None:
        if not deferred_sigint:
            deferred_sigint.append((signum, frame))

    prior_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, record_sigint)
    try:
        process = spawn()
    finally:
        signal.signal(signal.SIGINT, prior_handler)
        if deferred_sigint:
            _replay_deferred_sigint(prior_handler, *deferred_sigint[0])
    return process


def _cleanup_failed_process_start(
    process: subprocess.Popen[bytes],
    windows_job: int | None,
    containment: _ProcessContainment,
) -> None:
    """Clean a failed start whether or not ownership was already recorded."""
    if containment.process is not process:
        _cleanup_uncontained_process(process, windows_job)
        return
    if windows_job is not None and containment.windows_job is None:
        containment.attach_windows_job(windows_job)
    interruption = _retry_containment_termination(containment)
    finish_interruption = _finish_uncontained_cleanup(process)
    if interruption is not None:
        raise interruption
    if finish_interruption is not None:
        raise finish_interruption


def _start_contained_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    containment: _ProcessContainment,
) -> subprocess.Popen[bytes]:
    creationflags = (
        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) | _CREATE_SUSPENDED
        if os.name == "nt"
        else 0
    )
    process: subprocess.Popen[bytes] | None = None
    windows_job: int | None = None
    try:
        process = _popen_attached_process(
            command,
            cwd=cwd,
            env=env,
            creationflags=creationflags,
            containment=containment,
        )
        windows_ready = os.name != "nt"
        if os.name == "nt":
            try:
                windows_job = _create_windows_kill_job(process)
                if windows_job is not None:
                    containment.attach_windows_job(windows_job)
                windows_ready = (
                    windows_job is not None
                    and _resume_windows_primary_thread(process.pid)
                )
            except OSError:
                windows_ready = False
        if not windows_ready:
            _fail_metadata("unable to contain isolated resolver process")
    except BaseException:
        owned_process = containment.process
        if owned_process is not None:
            _cleanup_failed_process_start(
                owned_process,
                windows_job,
                containment,
            )
        raise
    else:
        return process


def _read_process_pipe(
    stream: BinaryIO,
    retained: bytearray,
    overflow: threading.Event,
    containment: _ProcessContainment,
    errors: list[OSError],
) -> None:
    """Retain bounded bytes from one pipe and stop a flooding child."""
    try:
        while payload := stream.read(_TAR_READ_CHUNK_BYTES):
            remaining = _MAX_RESOLVER_STREAM_BYTES - len(retained)
            retained.extend(payload[:remaining])
            if len(payload) > remaining:
                overflow.set()
                containment.terminate()
                return
    except OSError as error:
        errors.append(error)


def _retry_containment_termination(
    containment: _ProcessContainment,
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            containment.terminate()
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        if containment.terminated:
            break
    return interruption


def _wait_for_process_cleanup(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _join_process_reader(reader: threading.Thread) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            reader.join(timeout=_PROCESS_CLEANUP_SECONDS)
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _close_process_streams(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            for _attempt in range(2):
                try:
                    stream.close()
                except (OSError, ValueError):
                    break
                except BaseException as error:  # noqa: BLE001
                    if interruption is None:
                        interruption = error
                    continue
                break
    return interruption


def _preserve_first_cleanup_error(
    current: BaseException | None,
    candidate: BaseException | None,
) -> BaseException | None:
    return current if current is not None else candidate


def _finish_process_readers(
    process: subprocess.Popen[bytes],
    containment: _ProcessContainment,
    readers: Sequence[threading.Thread],
) -> bool:
    """Terminate the process tree and report whether a pipe reader survived."""
    interruption = _retry_containment_termination(containment)
    interruption = _preserve_first_cleanup_error(
        interruption,
        _wait_for_process_cleanup(process),
    )
    started = tuple(reader for reader in readers if reader.ident is not None)
    for reader in started:
        interruption = _preserve_first_cleanup_error(
            interruption,
            _join_process_reader(reader),
        )
    if any(reader.is_alive() for reader in started):
        interruption = _preserve_first_cleanup_error(
            interruption,
            _close_process_streams(process),
        )
        for reader in started:
            interruption = _preserve_first_cleanup_error(
                interruption,
                _join_process_reader(reader),
            )
    interruption = _preserve_first_cleanup_error(
        interruption,
        _close_process_streams(process),
    )
    reader_survived = any(reader.is_alive() for reader in started)
    if interruption is not None:
        raise interruption
    return reader_survived


def _run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run one resolver command with bounded, separate UTF-8 output streams."""
    process: subprocess.Popen[bytes] | None = None
    containment = _ProcessContainment()
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    stdout_errors: list[OSError] = []
    stderr_errors: list[OSError] = []
    readers: tuple[threading.Thread, ...] = ()
    timed_out: subprocess.TimeoutExpired | None = None
    returncode = -1
    reader_survived = False
    try:
        process = _start_contained_process(
            command,
            cwd=cwd,
            env=env,
            containment=containment,
        )
        if process.stdout is None or process.stderr is None:
            _fail_metadata("unable to capture isolated resolver output")
        readers = (
            threading.Thread(
                target=_read_process_pipe,
                args=(
                    process.stdout,
                    stdout,
                    overflow,
                    containment,
                    stdout_errors,
                ),
                daemon=True,
            ),
            threading.Thread(
                target=_read_process_pipe,
                args=(
                    process.stderr,
                    stderr,
                    overflow,
                    containment,
                    stderr_errors,
                ),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = error
            containment.terminate()
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
            returncode = process.returncode if process.returncode is not None else -1
    finally:
        owned_process = containment.process
        if owned_process is not None:
            reader_survived = _finish_process_readers(
                owned_process,
                containment,
                readers,
            )
    if timed_out is not None:
        raise timed_out
    if reader_survived:
        raise _ResolverPipeError
    if stdout_errors or stderr_errors:
        raise (stdout_errors or stderr_errors)[0]
    if overflow.is_set():
        raise _ResolverOutputLimitError
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=returncode,
        stdout=bytes(stdout).decode("utf-8", errors="strict"),
        stderr=bytes(stderr).decode("utf-8", errors="strict"),
    )


def _linux_wheel_platform(resolver_platform: str, machine: str) -> str | None:
    suffix = resolver_platform.removeprefix(f"{machine}-")
    if suffix == "unknown-linux-gnu":
        return f"linux_{machine}"
    if suffix == "manylinux2014":
        return f"manylinux2014_{machine}"
    if suffix.startswith("manylinux_"):
        return f"{suffix}_{machine}"
    return None


def _resolver_platform_values(
    resolver_platform: str,
) -> tuple[str, str, str, str, str] | None:
    linux = _LINUX_RESOLVER_PLATFORM.fullmatch(resolver_platform)
    if linux is not None:
        machine = linux.group("machine")
        wheel_platform = _linux_wheel_platform(resolver_platform, machine)
        if wheel_platform is not None:
            return "posix", "linux", machine, "Linux", wheel_platform
    if resolver_platform in _WINDOWS_RESOLVER_PLATFORMS:
        machine, wheel_platform = _WINDOWS_RESOLVER_PLATFORMS[resolver_platform]
        return "nt", "win32", machine, "Windows", wheel_platform
    if resolver_platform in _MACOS_RESOLVER_PLATFORMS:
        machine, wheel_platform = _MACOS_RESOLVER_PLATFORMS[resolver_platform]
        return "posix", "darwin", machine, "Darwin", wheel_platform
    return None


def _canonical_resolver_target(
    target: EnvironmentTarget,
) -> tuple[_CanonicalResolverTarget | None, str | None]:
    issue: str | None = None
    if (
        target.implementation_name != "cpython"
        or target.platform_python_implementation != "CPython"
        or target.implementation_version != target.python_full_version
    ):
        issue = (
            "uv target arguments cannot faithfully represent the declared Python "
            "implementation"
        )
    elif target.platform_release or target.platform_version:
        issue = (
            "uv target arguments cannot faithfully represent platform-release or "
            "platform-version marker values"
        )

    marker_values = _resolver_platform_values(target.resolver_platform)
    if issue is None and marker_values is None:
        issue = "resolver-platform is not a faithfully represented uv marker target"
    elif issue is None and target.sys_platform == "win32":
        issue = (
            "uv target arguments cannot faithfully represent Windows "
            "platform-machine marker values"
        )
    if issue is not None or marker_values is None:
        return None, issue

    canonical = _CanonicalResolverTarget(
        python_full_version=target.python_full_version,
        resolver_platform=target.resolver_platform,
        implementation_name="cpython",
        implementation_version=target.python_full_version,
        os_name=marker_values[0],
        sys_platform=marker_values[1],
        platform_machine=marker_values[2],
        platform_python_implementation="CPython",
        platform_system=marker_values[3],
        wheel_platform=marker_values[4],
    )
    fields = (
        "implementation_name",
        "implementation_version",
        "os_name",
        "sys_platform",
        "platform_machine",
        "platform_python_implementation",
        "platform_system",
    )
    mismatches = tuple(
        field for field in fields if getattr(target, field) != getattr(canonical, field)
    )
    if mismatches:
        field = mismatches[0]
        return None, (
            f"declared {field.replace('_', '-')} conflicts with resolver-platform"
        )
    if not all(_tag_matches_resolver_target(tag, canonical) for tag in target.tags):
        return None, "compatible-tags conflict with the canonical resolver target"
    return canonical, None


def _tag_interpreter_matches(tag: Tag, target: _CanonicalResolverTarget) -> bool:
    release = Version(target.python_full_version).release
    target_interpreter = f"cp{release[0]}{release[1]}"
    target_python = f"py{release[0]}{release[1]}"
    if tag.interpreter in {f"py{release[0]}", target_python}:
        return tag.abi == "none"
    if tag.interpreter == target_interpreter:
        return tag.abi in {target_interpreter, "none"} or (
            tag.abi == "abi3" and release[1] >= _MIN_STABLE_ABI_MINOR
        )
    prefix = f"cp{release[0]}"
    minor = tag.interpreter.removeprefix(prefix)
    return (
        tag.interpreter.startswith(prefix)
        and minor.isdigit()
        and _MIN_STABLE_ABI_MINOR <= int(minor) <= release[1]
        and tag.abi == "abi3"
    )


def _linux_tag_platform_matches(tag: Tag, target: _CanonicalResolverTarget) -> bool:
    if not tag.platform.endswith(f"_{target.platform_machine}"):
        return False
    target_policy = target.wheel_platform.removesuffix(f"_{target.platform_machine}")
    policy = tag.platform.removesuffix(f"_{target.platform_machine}")
    legacy_minor = {"manylinux1": 5, "manylinux2010": 12, "manylinux2014": 17}
    manylinux = re.fullmatch(r"manylinux_2_(?P<minor>[0-9]+)", policy)
    if target_policy == "linux":
        return policy == "linux" or policy in legacy_minor or manylinux is not None
    target_minor = (
        17
        if target_policy == "manylinux2014"
        else int(target_policy.rpartition("_")[2])
    )
    if policy in legacy_minor:
        return legacy_minor[policy] <= target_minor
    return manylinux is not None and int(manylinux.group("minor")) <= target_minor


def _tag_matches_resolver_target(tag: Tag, target: _CanonicalResolverTarget) -> bool:
    if not _tag_interpreter_matches(tag, target):
        return False
    if tag.platform == "any":
        return True
    if target.sys_platform == "win32":
        return tag.platform == target.wheel_platform
    if target.sys_platform == "darwin":
        return tag.platform.startswith("macosx_") and tag.platform.endswith(
            (f"_{target.wheel_platform}", "_universal2")
        )
    return _linux_tag_platform_matches(tag, target)


def _tag_interpreter_matches_declared_target(
    tag: Tag, target: EnvironmentTarget
) -> bool:
    release = Version(target.python_full_version).release
    generic = {f"py{release[0]}", f"py{release[0]}{release[1]}"}
    if tag.interpreter in generic:
        return tag.abi == "none"
    if target.implementation_name == "cpython":
        synthetic = _CanonicalResolverTarget(
            python_full_version=target.python_full_version,
            resolver_platform=target.resolver_platform,
            implementation_name=target.implementation_name,
            implementation_version=target.implementation_version,
            os_name=target.os_name,
            sys_platform=target.sys_platform,
            platform_machine=target.platform_machine,
            platform_python_implementation=target.platform_python_implementation,
            platform_system=target.platform_system,
            wheel_platform="any",
        )
        return _tag_interpreter_matches(tag, synthetic)
    if target.implementation_name == "pypy":
        interpreter = f"pp{release[0]}{release[1]}"
        implementation_release = Version(target.implementation_version).release
        pypy_abi = (
            f"pypy{release[0]}{release[1]}_pp"
            f"{implementation_release[0]}{implementation_release[1]}"
        )
        return tag.interpreter == interpreter and tag.abi in {"none", pypy_abi}
    return False


def _tag_platform_matches_declared_target(
    tag: Tag,
    target: EnvironmentTarget,
    wheel_platform: str,
) -> bool:
    if tag.platform == "any":
        return True
    synthetic = _CanonicalResolverTarget(
        python_full_version=target.python_full_version,
        resolver_platform=target.resolver_platform,
        implementation_name=target.implementation_name,
        implementation_version=target.implementation_version,
        os_name=target.os_name,
        sys_platform=target.sys_platform,
        platform_machine=target.platform_machine,
        platform_python_implementation=target.platform_python_implementation,
        platform_system=target.platform_system,
        wheel_platform=wheel_platform,
    )
    if target.sys_platform == "win32":
        return tag.platform == wheel_platform
    if target.sys_platform == "darwin":
        return tag.platform.startswith("macosx_") and tag.platform.endswith(
            (f"_{wheel_platform}", "_universal2")
        )
    return _linux_tag_platform_matches(tag, synthetic)


def _target_implementation_issue(target: EnvironmentTarget) -> str | None:
    implementation_labels = {
        "cpython": "CPython",
        "pypy": "PyPy",
    }
    known_name = target.implementation_name.casefold()
    known_label = target.platform_python_implementation.casefold()
    if known_name in implementation_labels and target.implementation_name != known_name:
        return "implementation-name must use its canonical marker spelling"
    canonical_labels = {
        label.casefold(): label for label in implementation_labels.values()
    }
    if (
        known_label in canonical_labels
        and target.platform_python_implementation != canonical_labels[known_label]
    ):
        return "platform-python-implementation must use its canonical spelling"
    expected_implementation = implementation_labels.get(target.implementation_name)
    if (
        expected_implementation is not None
        and target.platform_python_implementation != expected_implementation
    ):
        return "implementation-name conflicts with platform-python-implementation"
    expected_name = {label: name for name, label in implementation_labels.items()}.get(
        target.platform_python_implementation
    )
    if expected_name is not None and target.implementation_name != expected_name:
        return "platform-python-implementation conflicts with implementation-name"
    if (
        target.implementation_name == "cpython"
        and target.implementation_version != target.python_full_version
    ):
        return "CPython implementation-version conflicts with python-full-version"
    return None


def _target_marker_issue(
    target: EnvironmentTarget, marker_values: tuple[str, str, str, str, str]
) -> str | None:
    expected_fields = {
        "os_name": marker_values[0],
        "sys_platform": marker_values[1],
        "platform_machine": marker_values[2],
        "platform_system": marker_values[3],
    }
    mismatches = tuple(
        field
        for field, expected in expected_fields.items()
        if getattr(target, field) != expected
    )
    if not mismatches:
        return None
    return (
        f"declared {mismatches[0].replace('_', '-')} conflicts with resolver-platform"
    )


def _target_tag_issue(
    target: EnvironmentTarget, marker_values: tuple[str, str, str, str, str]
) -> str | None:
    if not all(
        _tag_interpreter_matches_declared_target(tag, target) for tag in target.tags
    ):
        return (
            "compatible-tags conflict with the declared Python version or "
            "implementation"
        )
    if not all(
        _tag_platform_matches_declared_target(tag, target, marker_values[4])
        for tag in target.tags
    ):
        return "compatible-tags conflict with the declared platform"
    return None


def _target_coherence_issue(target: EnvironmentTarget) -> str | None:
    implementation_issue = _target_implementation_issue(target)
    if implementation_issue is not None:
        return implementation_issue
    marker_values = _resolver_platform_values(target.resolver_platform)
    if marker_values is None:
        return "resolver-platform is unsupported for a coherent target declaration"
    return _target_marker_issue(target, marker_values) or _target_tag_issue(
        target, marker_values
    )


def _validate_target_fields(target: EnvironmentTarget, *, label: str) -> None:
    python_version = _runtime_version(
        target.python_full_version, f"{label}.python-full-version", python=True
    )
    implementation_version = _runtime_version(
        target.implementation_version,
        f"{label}.implementation-version",
        python=False,
    )
    if str(python_version) != target.python_full_version:
        _error(f"{label}.python-full-version", "must use its canonical form")
    if str(implementation_version) != target.implementation_version:
        _error(f"{label}.implementation-version", "must use its canonical form")
    required_strings = {
        "name": target.name,
        "implementation-name": target.implementation_name,
        "os-name": target.os_name,
        "sys-platform": target.sys_platform,
        "platform-machine": target.platform_machine,
        "platform-python-implementation": target.platform_python_implementation,
        "platform-system": target.platform_system,
        "resolver-platform": target.resolver_platform,
    }
    for field, value in required_strings.items():
        _string(value, f"{label}.{field}")
    _string(target.platform_release, f"{label}.platform-release", allow_empty=True)
    _string(target.platform_version, f"{label}.platform-version", allow_empty=True)
    if not isinstance(target.compatible_tags, tuple):
        _error(f"{label}.compatible-tags", "must be a tuple")
    normalized_tags = tuple(
        sorted(
            map(
                str,
                _configured_tags(
                    target.compatible_tags,
                    f"{label}.compatible-tags",
                    compressed_input=False,
                ),
            )
        )
    )
    if normalized_tags != target.compatible_tags:
        _error(
            f"{label}.compatible-tags",
            "must contain sorted expanded compatibility tags",
        )
    if _SAFE_RESOLVER_PLATFORM.fullmatch(target.resolver_platform) is None:
        _error(f"{label}.resolver-platform", "contains unsupported characters")


def _ensure_target_coherence(target: EnvironmentTarget, *, label: str) -> None:
    _validate_target_fields(target, label=label)
    issue = _target_coherence_issue(target)
    if issue is not None:
        _error(label, issue)


def _validate_effective_extras(values: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        _error(label, "must be a tuple")
    if len(values) > _MAX_EXTRAS:
        _error(label, "contains too many items")
    raw = tuple(_string(value, f"{label} item") for value in values)
    if any(_EXTRA_FIELD.fullmatch(value) is None for value in raw):
        _error(label, "contains an invalid extra name")
    normalized = tuple(sorted(canonicalize_name(value) for value in raw))
    if len(normalized) != len(set(normalized)):
        _error(label, "contains duplicate normalized names")
    if normalized != raw:
        _error(label, "must contain sorted normalized names")
    return normalized


def _validated_configuration_requirements(
    configuration: DependencyConfiguration,
    *,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(configuration.requirements, tuple):
        _error(f"{label}.requirements", "must be a tuple")
    if len(configuration.requirements) > _MAX_REQUIREMENTS:
        _error(f"{label}.requirements", "contains too many items")
    requirements = tuple(
        _string(value, f"{label}.requirements item")
        for value in configuration.requirements
    )
    parsed = _parse_requirements(requirements, configuration.project_kind)
    if len(parsed) != len(set(parsed)):
        _error(f"{label}.requirements", "contains duplicates")
    return parsed


def _validate_configuration_metadata(
    configuration: DependencyConfiguration,
    *,
    label: str,
) -> None:
    if not isinstance(configuration.metadata_paths, tuple) or not all(
        isinstance(path, Path) for path in configuration.metadata_paths
    ):
        _error(f"{label}.metadata", "must be a tuple of paths")
    if len(configuration.metadata_paths) > _MAX_METADATA_INPUTS:
        _error(f"{label}.metadata", "contains too many items")
    for path in configuration.metadata_paths:
        _string(str(path), f"{label}.metadata path")
    if len(configuration.metadata_paths) != len(set(configuration.metadata_paths)):
        _error(f"{label}.metadata", "contains duplicate paths")


def _validate_configuration_targets(
    configuration: DependencyConfiguration,
    *,
    label: str,
) -> None:
    if not isinstance(configuration.targets, tuple) or not configuration.targets:
        _error(f"{label}.targets", "must be a non-empty tuple")
    if len(configuration.targets) > _MAX_TARGETS or not all(
        isinstance(target, EnvironmentTarget) for target in configuration.targets
    ):
        _error(f"{label}.targets", "contains invalid or too many targets")
    for target in configuration.targets:
        _ensure_target_coherence(target, label="dependency target")
    target_names = tuple(target.name for target in configuration.targets)
    if len(target_names) != len(set(target_names)):
        _error(f"{label}.targets", "names must be unique")


def _validate_configuration_controls(
    configuration: DependencyConfiguration,
    *,
    label: str,
) -> None:
    if (
        type(configuration.resolve) is not bool
        or type(configuration.network) is not bool
    ):
        _error(label, "resolve and network must be booleans")
    _positive_number(configuration.timeout_seconds, f"{label}.timeout-seconds")
    if _string(configuration.resolver, f"{label}.resolver") != "uv":
        _error(f"{label}.resolver", "only 'uv' is supported")
    index_url = _index_url(configuration.index_url)
    if configuration.network and index_url is None:
        _error(f"{label}.index-url", "is required when network access is enabled")
    if not configuration.network and index_url is not None:
        _error(f"{label}.index-url", "must be disabled when network access is disabled")


def _validate_configuration_relations(
    configuration: DependencyConfiguration,
    requirements: tuple[str, ...],
    *,
    label: str,
) -> None:
    if not requirements and not configuration.metadata_paths:
        _error(label, "must declare requirements or metadata inputs")
    if configuration.resolve and not requirements:
        _error(f"{label}.resolve", "requires requirements")
    if (
        configuration.resolve
        and not configuration.network
        and not configuration.metadata_paths
    ):
        _error(f"{label}.resolve", "offline resolution requires metadata artifacts")
    if not configuration.resolve and not configuration.metadata_paths:
        _error(f"{label}.metadata", "is required when the resolver is not enabled")


def _validate_dependency_configuration(
    configuration: DependencyConfiguration,
) -> DependencyConfiguration:
    """Return one normalized configuration after loader-equivalent validation."""
    label = "dependency configuration"
    if not isinstance(configuration, DependencyConfiguration):
        _error(label, "must be a dependency configuration")
    if not isinstance(configuration.project_kind, DependencyProjectKind):
        _error(f"{label}.project-kind", "is invalid")
    requirements = _validated_configuration_requirements(
        configuration,
        label=label,
    )
    extras = _validate_effective_extras(
        configuration.extras,
        label=f"{label}.extras",
    )
    _validate_configuration_metadata(configuration, label=label)
    _validate_configuration_targets(configuration, label=label)
    _validate_configuration_controls(configuration, label=label)
    _ensure_marker_evaluation_budget(
        ((requirements, 2 if configuration.resolve else 1),),
        extras=extras,
        target_count=len(configuration.targets),
        label=label,
    )
    _validate_configuration_relations(
        configuration,
        requirements,
        label=label,
    )
    return replace(configuration, requirements=requirements)


def _resolver_command(
    workspace: _ResolverWorkspace,
    configuration: DependencyConfiguration,
    target: _CanonicalResolverTarget,
    *,
    has_artifacts: bool,
) -> list[str]:
    command = [
        workspace.executable,
        "pip",
        "compile",
        str(workspace.requirements),
        "--output-file",
        str(workspace.output),
        "--format",
        "pylock.toml",
        "--no-header",
        "--no-annotate",
        "--only-binary",
        ":all:",
        "--keyring-provider",
        "disabled",
        "--no-sources",
        "--no-python-downloads",
        "--no-progress",
        "--color",
        "never",
        "--python-version",
        target.python_full_version,
        "--python-platform",
        target.resolver_platform,
        "--no-cache",
    ]
    if configuration.network:
        if configuration.index_url is None:
            _error("dependency resolver", "online resolution has no configured index")
        command.extend(["--default-index", configuration.index_url])
        if has_artifacts:
            command.extend(["--find-links", str(workspace.wheelhouse)])
    else:
        command.extend(
            [
                "--offline",
                "--no-index",
                "--find-links",
                str(workspace.wheelhouse),
            ]
        )
    return command


def _stage_resolver_artifacts(
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
    wheelhouse: Path,
) -> str | None:
    try:
        for artifact in artifacts:
            relative, raw = _read_artifact(Path(artifact.path), root)
            if relative != artifact.path or hashlib.sha256(raw).hexdigest() != (
                artifact.sha256
            ):
                return "metadata artifact changed after direct inspection"
            (wheelhouse / artifact.path.name).write_bytes(raw)
    except (ConfigurationError, OSError):
        return "unable to revalidate a metadata artifact for isolated resolution"
    return None


def _uv_reports_unsatisfiable(diagnostic: str, version: str) -> bool:
    parsed_version = re.fullmatch(r"(?P<version>[0-9]+(?:\.[0-9]+)+)(?: .*)?", version)
    if parsed_version is None:
        return False
    series = Version(parsed_version.group("version")).release[:2]
    if series not in _SUPPORTED_UV_UNSATISFIABLE_SERIES:
        return False
    lines = _stable_uv_diagnostic(diagnostic).splitlines()

    if len(lines) < _MIN_UNSATISFIABLE_LINES or lines[0] != _UV_NO_SOLUTION_HEADER:
        return False
    explanation = " ".join(lines[1:])
    normalized = explanation.casefold()
    return (
        explanation.startswith("╰─▶ Because ")
        and explanation.endswith("requirements are unsatisfiable.")
        and not any(term in normalized for term in _UV_NON_SOLVER_TERMS)
    )


def _stable_uv_diagnostic(diagnostic: str) -> str:
    """Remove uv's host-Python fallback warning from retained evidence."""
    lines = [line.strip() for line in diagnostic.splitlines() if line.strip()]
    if lines and re.fullmatch(
        r"warning: The requested Python version .+ is not available; .+ will be "
        r"used to build dependencies instead\.",
        lines[0],
    ):
        lines.pop(0)
    return "\n".join(lines)


def _uv_reports_constraint_conflict(
    diagnostic: str,
    version: str,
    requirements: Sequence[str],
) -> bool:
    """Accept reviewed solver grammar only with an independent contradiction."""
    if not _uv_reports_unsatisfiable(diagnostic, version):
        return False
    normalized = diagnostic.casefold()
    if any(term in normalized for term in _UV_ARTIFACT_AVAILABILITY_TERMS):
        return False
    groups = _resolver_requirement_groups(requirements)
    for name in _conflicting_requirement_names(requirements):
        constraints = {str(requirement).casefold() for requirement in groups[name]}
        if constraints and all(constraint in normalized for constraint in constraints):
            return True
    return False


def _read_resolver_result(path: Path) -> str:
    """Read one regular resolver result with identity and byte limits."""
    descriptor = -1
    try:
        expected_status = path.lstat()
        if not stat.S_ISREG(expected_status.st_mode):
            _fail_metadata("resolver output is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or not os.path.samestat(
            expected_status, status
        ):
            _fail_metadata("resolver output changed while being read")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(_MAX_RESOLVER_RESULT_BYTES + 1)
    except _MetadataError:
        raise
    except (OSError, RuntimeError, ValueError):
        _fail_metadata("unable to read resolver output")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > _MAX_RESOLVER_RESULT_BYTES:
        _fail_metadata("resolver output exceeds the size limit")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail_metadata("resolver output is not valid UTF-8")


def _interpret_resolver_process(
    process: subprocess.CompletedProcess[str],
    *,
    context: _ResolverInterpretationContext,
) -> ResolverResult:
    if process.returncode != 0:
        diagnostic = process.stderr or process.stdout
        stable_diagnostic = _stable_uv_diagnostic(diagnostic)
        detail = _safe_process_text(
            stable_diagnostic,
            context.workspace.directory,
        )
        failed = process.returncode > 0 and _uv_reports_constraint_conflict(
            diagnostic,
            context.version,
            context.requirements,
        )
        return ResolverResult(
            status=(
                ResolutionStatus.RESOLUTION_FAILED
                if failed
                else ResolutionStatus.UNVERIFIED
            ),
            complete=failed,
            resolver="uv",
            resolver_version=context.version,
            packages=(),
            reason=detail or f"resolver exited with status {process.returncode}",
        )
    try:
        output = _read_resolver_result(context.workspace.output)
        packages, provenance_complete = _resolved_packages(
            output,
            context.artifacts,
            wheelhouse=context.workspace.wheelhouse,
        )
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        _MetadataError,
        InvalidVersion,
    ) as error:
        return _resolver_unverified(
            str(error) or "unable to parse resolver output", context.version
        )
    if not provenance_complete:
        return _resolver_unverified(
            "resolver selected package metadata whose exact artifact provenance "
            "was not established",
            context.version,
            packages,
        )
    return ResolverResult(
        status=ResolutionStatus.SUCCEEDED,
        complete=True,
        resolver="uv",
        resolver_version=context.version,
        packages=packages,
        reason="resolution completed",
    )


def _prepare_resolver_workspace(
    workspace: _ResolverWorkspace,
    target: EnvironmentTarget,
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
) -> tuple[_CanonicalResolverTarget | None, str | None]:
    resolver_target, target_issue = _canonical_resolver_target(target)
    if resolver_target is None:
        return None, target_issue or "resolver target is unverified"
    filenames = tuple(artifact.path.name for artifact in artifacts)
    portable_filenames = tuple(
        unicodedata.normalize("NFC", filename).casefold() for filename in filenames
    )
    if len(portable_filenames) != len(set(portable_filenames)):
        return None, ("artifact filenames are not portably unique in the resolver set")
    workspace.wheelhouse.mkdir()
    staging_error = _stage_resolver_artifacts(
        artifacts,
        root=root,
        wheelhouse=workspace.wheelhouse,
    )
    return (
        (None, staging_error) if staging_error is not None else (resolver_target, None)
    )


def _resolve_in_workspace(
    workspace: _ResolverWorkspace,
    configuration: DependencyConfiguration,
    target: EnvironmentTarget,
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
) -> ResolverResult:
    resolver_target, preparation_issue = _prepare_resolver_workspace(
        workspace,
        target,
        artifacts,
        root=root,
    )
    if resolver_target is None:
        return _resolver_unverified(
            preparation_issue or "resolver preparation is unverified"
        )
    active_requirements = _active_resolver_requirements(
        configuration.requirements,
        target,
        configuration.extras,
    )
    workspace.requirements.write_text(
        "\n".join(active_requirements) + "\n",
        encoding="utf-8",
    )
    environment = _resolver_environment(workspace.directory)
    version: str | None = None
    try:
        version_process = _run_bounded_process(
            [workspace.executable, "--version"],
            cwd=workspace.directory,
            env=environment,
            timeout=configuration.timeout_seconds,
        )
        version = (
            _resolver_version(version_process.stdout, "uv")
            if version_process.returncode == 0
            else None
        )
        if version is None:
            return _resolver_unverified(
                "unable to identify the exact uv resolver version"
            )
        if not configuration.network:
            unavailable = _offline_artifact_unavailability(
                active_requirements,
                artifacts,
                target,
                configuration.project_kind,
            )
            if unavailable:
                return ResolverResult(
                    status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
                    complete=True,
                    resolver="uv",
                    resolver_version=version,
                    packages=(),
                    reason=(
                        "the complete offline artifact set has no usable wheel "
                        "for: " + ", ".join(unavailable)
                    ),
                )
        command = _resolver_command(
            workspace,
            configuration,
            resolver_target,
            has_artifacts=bool(artifacts),
        )
        process = _run_bounded_process(
            command,
            cwd=workspace.directory,
            env=environment,
            timeout=configuration.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ResolverResult(
            status=ResolutionStatus.TIMED_OUT,
            complete=False,
            resolver="uv",
            resolver_version=version,
            packages=(),
            reason=(
                "resolver exceeded the explicit timeout; compatibility "
                "remains unverified"
            ),
        )
    except (
        OSError,
        UnicodeError,
        _MetadataError,
        _ResolverOutputLimitError,
    ) as error:
        reason = (
            "isolated resolver output exceeded the size limit"
            if isinstance(error, _ResolverOutputLimitError)
            else "unable to execute or decode isolated resolver output"
        )
        return _resolver_unverified(reason, version)
    return _interpret_resolver_process(
        process,
        context=_ResolverInterpretationContext(
            version=version,
            workspace=workspace,
            artifacts=artifacts,
            requirements=active_requirements,
        ),
    )


def _trusted_resolver_executable(
    resolver: str,
    *,
    root: Path,
) -> tuple[Path | None, str | None]:
    executable = shutil.which(resolver)
    if executable is None:
        return None, "uv executable is unavailable"
    try:
        resolved = Path(executable).resolve(strict=True)
        status = resolved.stat()
    except (OSError, RuntimeError):
        return None, "unable to validate the uv executable"
    if not stat.S_ISREG(status.st_mode):
        return None, "uv executable is not a regular file"
    try:
        resolved.relative_to(root)
    except ValueError:
        return resolved, None
    return None, "refusing to execute a resolver from inside the scanned root"


class UvResolverAdapter:
    """Run uv in a temporary, configuration-free, build-disabled boundary."""

    name = "uv"

    @_with_marker_evaluation_budget
    def resolve(
        self,
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        """Resolve one target with explicit network and timeout controls."""
        configuration = _validate_dependency_configuration(configuration)
        _validate_metadata_artifacts(artifacts)
        resolved_root = _resolved_dependency_root(root)
        if target not in configuration.targets:
            _error("dependency resolver target", "is not declared in configuration")
        if not configuration.resolve:
            return ResolverResult(
                status=ResolutionStatus.NOT_REQUESTED,
                complete=True,
                resolver=self.name,
                resolver_version=None,
                packages=(),
                reason="resolver was not requested",
            )
        _validate_target_fields(target, label="dependency resolver target")
        _resolver_target, target_issue = _canonical_resolver_target(target)
        if _resolver_target is None:
            return _resolver_unverified(target_issue or "resolver target is unverified")
        resolved_executable, executable_issue = _trusted_resolver_executable(
            configuration.resolver,
            root=resolved_root,
        )
        if resolved_executable is None:
            return _resolver_unverified(
                executable_issue or "unable to validate the uv executable"
            )
        with tempfile.TemporaryDirectory(prefix="pyahead-resolver-") as temporary:
            directory = Path(temporary)
            return _resolve_in_workspace(
                _ResolverWorkspace(
                    executable=str(resolved_executable),
                    directory=directory,
                    requirements=directory / "requirements.in",
                    output=directory / "pylock.toml",
                    wheelhouse=directory / "artifacts",
                ),
                configuration,
                target,
                artifacts,
                root=resolved_root,
            )


@_with_marker_evaluation_budget
def collect_dependency_report(
    configuration: DependencyConfiguration,
    *,
    root: Path,
    resolver: ResolverAdapter | None = None,
) -> DependencyReport:
    """Collect deterministic direct metadata and optional resolver evidence."""
    configuration = _validate_dependency_configuration(configuration)
    resolved_root = _resolved_dependency_root(root)
    artifacts, issues = inspect_dependency_metadata(
        configuration.metadata_paths, root=resolved_root
    )
    _ensure_marker_evaluation_budget(
        (
            (configuration.requirements, 2 if configuration.resolve else 1),
            (
                tuple(
                    requirement
                    for artifact in artifacts
                    for requirement in artifact.requires_dist
                ),
                1,
            ),
        ),
        extras=configuration.extras,
        target_count=len(configuration.targets),
        label="dependency collection",
    )
    adapter = resolver or UvResolverAdapter()
    targets: list[TargetDependencyResult] = []
    for target in configuration.targets:
        _ensure_target_coherence(target, label="dependency target")
        declared = tuple(
            _evaluate_requirement(value, target, configuration.extras)
            for value in configuration.requirements
        )
        if not configuration.resolve:
            expected_resolver = configuration.resolver
            resolution = ResolverResult(
                status=ResolutionStatus.NOT_REQUESTED,
                complete=True,
                resolver="uv",
                resolver_version=None,
                packages=(),
                reason="resolver was not requested",
            )
        elif issues:
            expected_resolver = configuration.resolver
            resolution = _resolver_unverified(
                "resolver was not executed because configured metadata evidence "
                "is incomplete"
            )
        else:
            expected_resolver = adapter.name
            resolution = adapter.resolve(
                configuration,
                target,
                artifacts,
                root=resolved_root,
            )
        resolution = _validated_resolver_result(
            resolution,
            _ResolverValidationContext(
                artifacts=artifacts,
                declared=declared,
                configuration=configuration,
                target=target,
                expected_resolver=expected_resolver,
            ),
        )
        evidence_resolution = resolution
        if declared:
            assessments = _assess_declared_dependency_metadata(
                artifacts,
                target=target,
                configuration=configuration,
                declared=declared,
                resolution=resolution,
            )
        else:
            assessments = assess_dependency_metadata(
                artifacts,
                target=target,
                extras=configuration.extras,
            )
            if configuration.project_kind is DependencyProjectKind.LIBRARY:
                assessments = tuple(
                    _unverify_library_artifact_sample(assessment)
                    for assessment in assessments
                )
        resolution = _validated_resolver_closure(
            resolution,
            assessments,
            artifacts,
        )
        selected_evidence = _target_semantic_artifacts(
            _resolution_evidence_artifacts(
                artifacts,
                evidence_resolution,
            ),
            target,
        )
        correlated_declared = _correlate_declared_requirements(
            declared,
            selected_evidence,
            resolution,
            configuration.project_kind,
        )
        targets.append(
            TargetDependencyResult(
                target=target,
                declared_requirements=correlated_declared,
                transitive_requirements=_transitive_requirement_evidence(
                    configuration.project_kind,
                    assessments,
                    correlated_declared,
                    selected_evidence,
                    resolution,
                ),
                assessments=assessments,
                resolution=resolution,
            )
        )
    return DependencyReport(
        schema_version=1,
        project_kind=configuration.project_kind,
        resolve=configuration.resolve,
        network=configuration.network,
        timeout_seconds=configuration.timeout_seconds,
        resolver=configuration.resolver,
        index_url=configuration.index_url,
        requirements=configuration.requirements,
        extras=configuration.extras,
        metadata=artifacts,
        metadata_issues=issues,
        targets=tuple(targets),
    )


def _target_document(target: EnvironmentTarget) -> dict[str, JsonValue]:
    return {
        "compatible_tags": list(target.compatible_tags),
        "implementation_name": target.implementation_name,
        "implementation_version": target.implementation_version,
        "name": target.name,
        "os_name": target.os_name,
        "platform_machine": target.platform_machine,
        "platform_python_implementation": target.platform_python_implementation,
        "platform_release": target.platform_release,
        "platform_system": target.platform_system,
        "platform_version": target.platform_version,
        "python_full_version": target.python_full_version,
        "python_version": target.python_version,
        "resolver_platform": target.resolver_platform,
        "sys_platform": target.sys_platform,
    }


def dependency_report_document(report: DependencyReport) -> dict[str, JsonValue]:
    """Return the closed deterministic JSON representation of an M8 report."""
    return {
        "controls": {
            "index_url": report.index_url,
            "network": report.network,
            "resolve": report.resolve,
            "resolver": report.resolver,
            "timeout_seconds": report.timeout_seconds,
        },
        "extras": list(report.extras),
        "metadata": [
            {
                "artifact_id": item.artifact_id,
                "canonical_name": item.canonical_name,
                "dynamic": list(item.dynamic),
                "kind": item.kind.value,
                "metadata_path": item.metadata_path,
                "metadata_version": item.metadata_version,
                "name": item.name,
                "path": item.path.as_posix(),
                "provides_extra": list(item.provides_extra),
                "requires_dist": list(item.requires_dist),
                "requires_python": item.requires_python,
                "sha256": item.sha256,
                "version": item.version,
                "wheel_tags": list(item.wheel_tags),
            }
            for item in report.metadata
        ],
        "metadata_issues": [
            {"incomplete": True, "message": item.message, "path": item.path.as_posix()}
            for item in report.metadata_issues
        ],
        "project_kind": report.project_kind.value,
        "requirements": list(report.requirements),
        "schema_version": report.schema_version,
        "targets": [
            {
                "assessments": [
                    {
                        "applicable_requirements": list(item.applicable_requirements),
                        "artifact_availability": item.artifact_availability.value,
                        "metadata_used": list(item.metadata_used),
                        "package": item.package,
                        "reason": item.reason,
                        "requires_python_status": item.requires_python_status.value,
                        "source_build_possible": item.source_build_possible,
                        "status": item.status.value,
                        "version": item.version,
                    }
                    for item in result.assessments
                ],
                "declared_requirements": [
                    {
                        "applies": item.applies,
                        "matching_metadata": list(item.matching_metadata),
                        "matching_extras": list(item.matching_extras),
                        "reason": item.reason,
                        "requirement": item.requirement,
                        "resolved_versions": list(item.resolved_versions),
                        "verified": item.verified,
                    }
                    for item in result.declared_requirements
                ],
                "transitive_requirements": [
                    {
                        "locked_versions": list(item.locked_versions),
                        "matching_metadata": list(item.matching_metadata),
                        "reason": item.reason,
                        "requirement": item.requirement,
                        "required_by": list(item.required_by),
                        "resolved_versions": list(item.resolved_versions),
                        "verified": item.verified,
                    }
                    for item in result.transitive_requirements
                ],
                "resolution": {
                    "complete": result.resolution.complete,
                    "packages": [
                        {
                            "metadata_used": list(item.metadata_used),
                            "name": item.name,
                            "version": item.version,
                        }
                        for item in result.resolution.packages
                    ],
                    "reason": result.resolution.reason,
                    "resolver": result.resolution.resolver,
                    "resolver_version": result.resolution.resolver_version,
                    "status": result.resolution.status.value,
                },
                "target": _target_document(result.target),
            }
            for result in report.targets
        ],
    }


def render_dependency_json(report: DependencyReport) -> str:
    """Render byte-stable machine output."""
    return (
        json.dumps(dependency_report_document(report), indent=2, sort_keys=True) + "\n"
    )


def render_dependency_text(report: DependencyReport) -> str:
    """Render a concise compatibility distinction for each target."""
    mode = "online" if report.network else "offline"
    lines = [
        (
            f"Dependency compatibility ({report.project_kind.value}; {mode}; "
            f"timeout {report.timeout_seconds:g}s)"
        )
    ]
    lines.extend(
        (
            f"Metadata {item.artifact_id}: {item.name}=={item.version}; "
            f"Core Metadata {item.metadata_version}; "
            f"Requires-Python {item.requires_python or 'unspecified'}; "
            f"{item.path.as_posix()}!{item.metadata_path}; sha256={item.sha256}; "
            f"dynamic={','.join(item.dynamic) or 'none'}"
        )
        for item in report.metadata
    )
    lines.append(
        f"Resolver control: requested={str(report.resolve).lower()}; "
        f"adapter={report.resolver}; index={report.index_url or 'disabled'}"
    )
    for result in report.targets:
        lines.append(
            f"Target {result.target.name}: Python {result.target.python_full_version}; "
            f"{result.target.sys_platform}/{result.target.platform_machine}"
        )
        for requirement in result.declared_requirements:
            state = "verified" if requirement.verified else "unverified"
            lines.append(
                f"  Declared {requirement.requirement}: "
                f"{'active' if requirement.applies else 'inactive'}; {state}"
            )
            lines.append(f"    {requirement.reason}")
        for transitive in result.transitive_requirements:
            state = "verified" if transitive.verified else "unverified"
            lines.append(
                f"  Transitive {transitive.requirement}: {state}; required by "
                f"{', '.join(transitive.required_by)}"
            )
            lines.append(f"    {transitive.reason}")
        for assessment in result.assessments:
            lines.append(
                f"  {assessment.package}=={assessment.version}: "
                f"{assessment.status.value}; Requires-Python "
                f"{assessment.requires_python_status.value}; artifact "
                f"{assessment.artifact_availability.value}"
            )
            lines.append(f"    {assessment.reason}")
            lines.append(f"    Metadata: {', '.join(assessment.metadata_used)}")
            lines.append(
                "    Applicable requirements: "
                + (", ".join(assessment.applicable_requirements) or "none")
            )
        resolution = result.resolution
        lines.append(
            f"  Resolver: {resolution.status.value}; "
            f"complete={str(resolution.complete).lower()}; "
            f"version={resolution.resolver_version or 'unavailable'}"
        )
        lines.append(f"    {resolution.reason}")
        lines.extend(
            f"    {package.name}=={package.version}" for package in resolution.packages
        )
    lines.extend(
        f"Incomplete metadata {issue.path.as_posix()}: {issue.message}"
        for issue in report.metadata_issues
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "ArtifactAvailability",
    "DependencyAssessment",
    "DependencyCompatibilityStatus",
    "DependencyConfiguration",
    "DependencyProjectKind",
    "DependencyReport",
    "EnvironmentTarget",
    "EvaluatedRequirement",
    "MetadataArtifact",
    "MetadataIssue",
    "MetadataKind",
    "RequiresPythonStatus",
    "ResolutionStatus",
    "ResolvedPackage",
    "ResolverAdapter",
    "ResolverResult",
    "TargetDependencyResult",
    "TransitiveRequirementEvidence",
    "UvResolverAdapter",
    "assess_dependency_metadata",
    "collect_dependency_report",
    "dependency_report_document",
    "inspect_dependency_metadata",
    "load_dependency_configuration",
    "render_dependency_json",
    "render_dependency_text",
]
