"""Opt-in M8 dependency metadata and isolated resolver evidence."""

from __future__ import annotations

import gzip
import hashlib
import json
import lzma
import math
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
import zlib
from dataclasses import dataclass, replace
from email import policy
from email.parser import BytesParser
from enum import StrEnum
from io import BytesIO, RawIOBase
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NoReturn, Protocol, TypeAlias
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from packaging.markers import UndefinedEnvironmentName
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

from pyahead.model import ConfigurationError, ExitCode

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from email.message import Message

JsonScalar: TypeAlias = bool | float | int | str | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

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
_MAX_ARCHIVE_MEMBERS = 10_000
_MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024
_MAX_TAR_CONTROL_BYTES = 2 * 1024 * 1024
_MAX_ZIP_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
_MAX_TEXT_LENGTH = 4096
_MAX_REQUIREMENTS = 10_000
_MAX_TARGETS = 64
_VERSION_COMPONENTS = 3
_WHEEL_PATH_PARTS = 2
_DYNAMIC_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9-]*\Z")
_EXTRA_FIELD = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_SAFE_RESOLVER_PLATFORM = re.compile(r"[A-Za-z0-9_.-]+\Z")
_LINUX_RESOLVER_PLATFORM = re.compile(
    r"(?P<machine>x86_64|aarch64|riscv64)-(?:unknown-linux-(?:gnu|musl)|"
    r"manylinux(?:2014|_[0-9]+_[0-9]+)|linux-android)\Z"
)
_WINDOWS_RESOLVER_PLATFORMS = {
    "aarch64-pc-windows-msvc": ("aarch64", "win_arm64"),
    "i686-pc-windows-msvc": ("x86", "win32"),
    "x86_64-pc-windows-msvc": ("x86_64", "win_amd64"),
}
_MACOS_RESOLVER_PLATFORMS = {
    "aarch64-apple-darwin": ("arm64", "arm64"),
    "x86_64-apple-darwin": ("x86_64", "x86_64"),
}
_SUPPORTED_UV_UNSATISFIABLE_SERIES = frozenset({(0, 11), (0, 12)})
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
    "has no wheels with a matching",
    "is not available in the package registry",
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
        zipfile.ZIP_LZMA,
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

    @property
    def tags(self) -> frozenset[Tag]:
        """Return the fully expanded configured wheel-tag set."""
        tags: set[Tag] = set()
        for value in self.compatible_tags:
            tags.update(parse_tag(value))
        return frozenset(tags)

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
    common_lock_versions: frozenset[str]
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


def _configuration_error(label: str, message: str) -> ConfigurationError:
    detail = f"{label}: {message}"
    return ConfigurationError(detail)


def _fail_metadata(message: str) -> NoReturn:
    raise _MetadataError(message)


def _error(label: str, message: str) -> NoReturn:
    raise _configuration_error(label, message)


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _error(label, "must be a TOML table")
    return value


def _string(value: object, label: str, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > _MAX_TEXT_LENGTH
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        qualifier = "a string" if allow_empty else "a non-empty string"
        _error(label, f"must be {qualifier} without control characters")
    return value


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _error(label, "must be an array")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(result) != len(set(result)):
        _error(label, "must not contain duplicates")
    return result


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        _error(label, "must be a boolean")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        _error(label, "must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        _error(label, "must be a finite positive number")
    return result


def _parse_target(value: object, index: int) -> EnvironmentTarget:
    label = f"tool.pyahead.dependencies.targets[{index}]"
    target = _table(value, label)
    keys = set(target)
    if not _TARGET_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        _TARGET_REQUIRED_KEYS | _TARGET_OPTIONAL_KEYS
    ):
        _error(label, "has unknown or missing keys")
    python_full_version = _string(
        target["python-full-version"], f"{label}.python-full-version"
    )
    implementation_version = _string(
        target["implementation-version"], f"{label}.implementation-version"
    )
    try:
        python_parsed = Version(python_full_version)
        implementation_parsed = Version(implementation_version)
    except InvalidVersion as error:
        _error(label, f"contains an invalid version: {error}")
    if len(python_parsed.release) < _VERSION_COMPONENTS:
        _error(label, "python-full-version must include a patch release")
    if len(implementation_parsed.release) < _VERSION_COMPONENTS:
        _error(label, "implementation-version must include a patch release")
    compatible_tags = _string_list(
        target["compatible-tags"], f"{label}.compatible-tags"
    )
    if not compatible_tags:
        _error(label, "compatible-tags must not be empty")
    try:
        expanded_tags = {
            str(tag) for value in compatible_tags for tag in parse_tag(value)
        }
    except ValueError as error:
        _error(label, f"contains an invalid compatible tag: {error}")
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


def _index_url(value: object) -> str | None:
    if value is None:
        return None
    url = _string(value, "tool.pyahead.dependencies.index-url")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in url
        or any(character.isspace() for character in url)
    ):
        _error(
            "tool.pyahead.dependencies.index-url",
            "must be an HTTP(S) URL without embedded credentials, query, or fragment",
        )
    return url


def _read_dependency_table(
    root: Path,
    config_path: Path | None = None,
) -> dict[str, object]:
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
        if not stat.S_ISREG(resolved.stat().st_mode):
            _error(selected.name, "configuration is not a regular file")
        with resolved.open("rb") as stream:
            document = tomllib.load(stream)
    except FileNotFoundError as error:
        raise _configuration_error(
            selected.name, "configuration file does not exist"
        ) from error
    except tomllib.TOMLDecodeError as error:
        raise _configuration_error(
            selected.name, "configuration is not valid TOML"
        ) from error
    except (OSError, RuntimeError, ValueError) as error:
        if isinstance(error, ConfigurationError):
            raise
        raise _configuration_error(
            selected.name, "unable to read configuration beneath the root"
        ) from error

    tool = _table(document.get("tool", {}), f"{selected.name}:tool")
    pyahead = _table(tool.get("pyahead", {}), f"{selected.name}:tool.pyahead")
    raw = pyahead.get("dependencies")
    if raw is None:
        _error(selected.name, "[tool.pyahead.dependencies] is required")
    table = _table(raw, f"{selected.name}:tool.pyahead.dependencies")
    unknown = sorted(set(table).difference(_DEPENDENCY_KEYS))
    if unknown:
        _error(
            selected.name,
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
        ),
        project_kind,
    )
    extras = tuple(
        sorted(
            _string_list(table.get("extras", []), "tool.pyahead.dependencies.extras")
        )
    )
    metadata = tuple(
        Path(item)
        for item in _string_list(
            table.get("metadata", []), "tool.pyahead.dependencies.metadata"
        )
    )
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
    return DependencyConfiguration(
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


def _read_artifact(path: Path, root: Path) -> tuple[PurePosixPath, bytes]:
    selected = path if path.is_absolute() else root / path
    try:
        resolved = selected.resolve(strict=True)
        relative = PurePosixPath(resolved.relative_to(root).as_posix())
        expected_status = resolved.lstat()
        if not stat.S_ISREG(expected_status.st_mode):
            _error(path.name, "metadata input is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(resolved, flags)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                _error(path.name, "metadata input is not a regular file")
            if not os.path.samestat(expected_status, status):
                _error(path.name, "metadata input changed while being read")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = -1
                raw = stream.read(_MAX_ARTIFACT_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except FileNotFoundError as error:
        raise _configuration_error(
            path.name, "metadata input does not exist"
        ) from error
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        raise _configuration_error(
            path.name, "metadata input must remain beneath the project root"
        ) from error
    except (OSError, RuntimeError) as error:
        raise _configuration_error(
            path.name, "unable to read metadata input"
        ) from error
    if len(raw) > _MAX_ARTIFACT_BYTES:
        raise _configuration_error(
            path.name,
            f"metadata input exceeds {_MAX_ARTIFACT_BYTES} bytes",
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
        payload = self._stream.read(bounded_size)
        self._read += len(payload)
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
        lzma.LZMAError,
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
        or any(character in value for character in ("\x00", "\r", "\n"))
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
    provides_extra: list[str] = []
    for raw_extra in message.get_all("Provides-Extra", []):
        value = str(raw_extra)
        if len(value) > _MAX_TEXT_LENGTH or _EXTRA_FIELD.fullmatch(value) is None:
            _fail_metadata("core metadata has invalid Provides-Extra")
        provides_extra.append(canonicalize_name(value))
    if len(provides_extra) != len(set(provides_extra)):
        _fail_metadata("core metadata repeats a Provides-Extra value")
    return tuple(sorted(provides_extra))


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
    raw_requires_dist = tuple(
        str(value) for value in message.get_all("Requires-Dist", [])
    )
    parsed_requirements: list[str] = []
    for value in raw_requires_dist:
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            _fail_metadata("core metadata has invalid Requires-Dist")
        if requirement.url is not None:
            _fail_metadata(
                "core metadata has a direct URL Requires-Dist outside the "
                "configured artifact and index policy"
            )
        parsed_requirements.append(str(requirement))
    provides_extra = _provides_extra_fields(message)
    dynamic = _dynamic_fields(message)
    _validate_core_metadata_schema(raw)
    return _ParsedCoreMetadata(
        name=name,
        version=parsed_version,
        metadata_version=metadata_version,
        requires_python=requires_python,
        requires_dist=tuple(parsed_requirements),
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
        lzma.LZMAError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        _fail_metadata("invalid ZIP archive")


def _wheel_file_tags(wheel_payload: bytes) -> tuple[str, ...]:
    message = BytesParser(policy=policy.compat32).parsebytes(wheel_payload)
    if message.defects:
        _fail_metadata("WHEEL metadata contains malformed headers")
    _header(message, "Wheel-Version", required=True)
    raw_tags = tuple(str(value) for value in message.get_all("Tag", []))
    if not raw_tags:
        _fail_metadata("WHEEL metadata omits Tag")
    internal_tags: set[str] = set()
    for value in raw_tags:
        if (
            not value
            or len(value) > _MAX_TEXT_LENGTH
            or any(character in value for character in ("\x00", "\r", "\n"))
        ):
            _fail_metadata("WHEEL metadata has invalid Tag")
        try:
            internal_tags.update(map(str, parse_tag(value)))
        except ValueError:
            _fail_metadata("WHEEL metadata has invalid Tag")
    return tuple(sorted(internal_tags))


def _wheel_structure_tags(
    raw: bytes,
    *,
    metadata_path: str,
    metadata: _ParsedCoreMetadata,
) -> tuple[str, ...]:
    dist_info = _wheel_dist_info_directory(metadata_path, metadata)
    return _wheel_file_tags(_wheel_file_payload(raw, dist_info))


def _validate_artifact_identity(
    path: PurePosixPath,
    kind: MetadataKind,
    metadata: _ParsedCoreMetadata,
    *,
    artifact_raw: bytes,
    metadata_path: str,
) -> tuple[str, ...]:
    if kind is MetadataKind.WHEEL:
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
        try:
            filename_name, filename_version = parse_sdist_filename(path.name)
        except InvalidSdistFilename:
            _fail_metadata("invalid source distribution filename")
        if (
            filename_name != canonicalize_name(metadata.name)
            or filename_version != metadata.version
        ):
            _fail_metadata("sdist filename and core metadata identity disagree")
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
        dynamic=metadata.dynamic,
        wheel_tags=wheel_tags,
        metadata_path=metadata_path,
        sha256=digest,
    )


def inspect_dependency_metadata(
    metadata_paths: Sequence[Path], *, root: Path
) -> tuple[tuple[MetadataArtifact, ...], tuple[MetadataIssue, ...]]:
    """Read static core metadata without importing code or running a backend."""
    resolved_root = root.resolve(strict=True)
    artifacts: list[MetadataArtifact] = []
    issues: list[MetadataIssue] = []
    selected_paths: set[PurePosixPath] = set()
    for configured_path in metadata_paths:
        relative, artifact_bytes = _read_artifact(configured_path, resolved_root)
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
    contexts = ("", *extras)
    try:
        matching = [
            extra or "base"
            for extra in contexts
            if requirement.marker.evaluate(
                environment=target.marker_environment(extra=extra),
                context="metadata",
            )
        ]
    except UndefinedEnvironmentName as error:
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
    matching_wheels = tuple(
        item
        for item in wheels
        if any(target.tags.intersection(parse_tag(tag)) for tag in item.wheel_tags)
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
    if not declarations:
        status = (
            RequiresPythonStatus.UNVERIFIED
            if dynamic
            else RequiresPythonStatus.UNSPECIFIED
        )
        return status, dynamic
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


def _assessment(
    group: tuple[MetadataArtifact, ...],
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> DependencyAssessment:
    first = group[0]
    selection = _select_artifacts(group, target)
    metadata_used = tuple(sorted({item.artifact_id for item in group}))
    requirements = tuple(
        sorted(
            {
                item.requirement
                for artifact in selection.semantic_metadata
                if "requires-dist" not in artifact.dynamic
                for item in (
                    _evaluate_requirement(value, target, extras)
                    for value in artifact.requires_dist
                )
                if item.applies
            }
        )
    )
    requires_status, dynamic_requires_python = _requires_python_status(
        selection.semantic_metadata,
        target,
    )
    availability = _artifact_availability(selection)
    status, reason = _assessment_outcome(
        requires_status,
        availability,
        dynamic_requires_python=dynamic_requires_python,
        source_build_possible=bool(selection.sdists),
    )
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


def assess_dependency_metadata(
    artifacts: Sequence[MetadataArtifact],
    *,
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> tuple[DependencyAssessment, ...]:
    """Assess exact supplied versions for one fully declared target."""
    _ensure_target_coherence(target, label=f"dependency target {target.name!r}")
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        key = (artifact.canonical_name, Version(artifact.version))
        grouped.setdefault(key, []).append(artifact)
    return tuple(
        _assessment(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
            extras,
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
            or artifact.version != package.version
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
            requested = {canonicalize_name(extra) for extra in requirement.extras}
            name = canonicalize_name(requirement.name)
            for candidate_key in keys_by_name.get(name, []):
                if not _requirement_accepts_version(requirement, str(candidate_key[1])):
                    continue
                candidate_group = grouped[candidate_key]
                eligible = any(
                    (
                        _artifact_satisfies_requirements(artifact, (requirement,))
                        if requested
                        else _artifact_satisfies_version_constraints(
                            artifact, (requirement,)
                        )
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
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        if any(
            canonicalize_name(requirement.name) == artifact.canonical_name
            and _requirement_accepts_version(requirement, artifact.version)
            for requirement in active
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
) -> dict[tuple[str, Version], set[str]]:
    return {
        key: {
            canonicalize_name(extra)
            for requirement in active
            if canonicalize_name(requirement.name) == key[0]
            and _requirement_accepts_version(requirement, str(key[1]))
            for extra in requirement.extras
            if any(
                "provides-extra" not in artifact.dynamic
                and canonicalize_name(extra) in artifact.provides_extra
                for artifact in grouped[key]
            )
        }
        for key in ordered_keys
    }


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
    active_groups: dict[str, tuple[Requirement, ...]] = {}
    for requirement in active:
        name = canonicalize_name(requirement.name)
        active_groups[name] = (*active_groups.get(name, ()), requirement)
    use_resolver_selection = (
        resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete
    )
    grouped = (
        _resolver_dependency_groups(resolution, artifacts_by_id)
        if use_resolver_selection
        else _direct_dependency_groups(artifacts, active)
    )
    ordered_keys = tuple(sorted(grouped, key=lambda item: (item[0], item[1])))
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
    initial_extras = _initial_dependency_extras(ordered_keys, active, grouped)
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
            for requirement in active
            if canonicalize_name(requirement.name) == key[0]
            and _requirement_accepts_version(requirement, str(key[1]))
        )
        assessment = raw_assessments[key]
        if configuration.project_kind is DependencyProjectKind.LIBRARY:
            assessment = _unverify_library_artifact_sample(assessment)
        if (
            configuration.project_kind is DependencyProjectKind.LIBRARY
            and assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
            and matching_requirements
            and all(
                _exact_requirement_version(requirement) is None
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
    required_extras = {
        canonicalize_name(extra)
        for requirement in requirements
        for extra in requirement.extras
    }
    return (
        artifact.canonical_name == canonical_name
        and all(
            _requirement_accepts_version(requirement, artifact.version)
            for requirement in requirements
        )
        and "provides-extra" not in artifact.dynamic
        and required_extras.issubset(artifact.provides_extra)
    )


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
            and artifact.version == package.version
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


def _validated_resolver_result(
    resolution: ResolverResult,
    artifacts: Sequence[MetadataArtifact],
    declared: Sequence[EvaluatedRequirement],
) -> ResolverResult:
    """Fail closed when a replaceable resolver contradicts exact provenance."""
    if resolution.status is not ResolutionStatus.SUCCEEDED:
        return resolution
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    canonical_names = tuple(
        canonicalize_name(package.name) for package in resolution.packages
    )
    structurally_valid = resolution.complete and len(canonical_names) == len(
        set(canonical_names)
    )
    if structurally_valid:
        for package in resolution.packages:
            try:
                Version(package.version)
            except InvalidVersion:
                structurally_valid = False
                break
            if _resolved_artifact_group(package, artifacts_by_id) is None:
                structurally_valid = False
                break
    active_groups = _active_requirement_groups(declared)
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
    if structurally_valid and roots_covered:
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
) -> tuple[EvaluatedRequirement, ...]:
    active_groups = _active_requirement_groups(declared)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_artifacts = _resolution_evidence_artifacts(artifacts, resolution)
    correlated: list[EvaluatedRequirement] = []
    for item in declared:
        if not item.applies:
            correlated.append(item)
            continue
        requirement = Requirement(item.requirement)
        group = tuple(active_groups[canonicalize_name(requirement.name)])
        matching_metadata = tuple(
            sorted(
                artifact.artifact_id
                for artifact in evidence_artifacts
                if _artifact_satisfies_requirements(artifact, group)
            )
        )
        resolved_versions = tuple(
            sorted(
                f"{canonicalize_name(package.name)}=={package.version}"
                for package in resolution.packages
                if _resolved_package_satisfies_requirements(
                    package, group, artifacts_by_id
                )
            )
        )
        if matching_metadata:
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
        or specifiers[0].operator != "=="
        or specifiers[0].version.endswith(".*")
    ):
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


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
    occurrences = _transitive_occurrences(assessments)
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
        common_lock_versions = frozenset(
            version
            for version in raw_lock_versions
            if all(
                _requirement_accepts_version(requirement, version)
                for requirement in (*lock_requirements, *requirements)
            )
        )
        matching_metadata = tuple(
            sorted(
                artifact.artifact_id
                for artifact in evidence_artifacts
                if _artifact_satisfies_requirements(artifact, requirements)
                and (
                    project_kind is DependencyProjectKind.LIBRARY
                    or artifact.version in common_lock_versions
                )
            )
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
                    or package.version in common_lock_versions
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
        exact_versions = {
            Version(version)
            for requirement in group
            if (version := _exact_requirement_version(requirement)) is not None
        }
        if len(exact_versions) > 1:
            conflicts.append(name)
    return tuple(conflicts)


def _offline_artifact_unavailability(
    requirements: Sequence[str],
    artifacts: Sequence[MetadataArtifact],
    target: EnvironmentTarget,
    extras: tuple[str, ...],
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
        candidates = tuple(
            artifact
            for artifact in artifacts
            if _artifact_satisfies_version_constraints(artifact, group)
        )
        if not candidates:
            unavailable.append(" & ".join(str(requirement) for requirement in group))
            continue
        selected_extras = tuple(
            sorted(
                {canonicalize_name(extra) for extra in extras}
                | {
                    canonicalize_name(extra)
                    for requirement in group
                    for extra in requirement.extras
                }
            )
        )
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


def _resolver_version(output: str, resolver: str) -> str | None:
    line = output.strip().splitlines()
    if len(line) != 1 or not line[0].startswith(f"{resolver} "):
        return None
    return line[0][len(resolver) + 1 :].strip() or None


def _safe_process_text(value: str, workspace: Path) -> str:
    normalized = value.replace(str(workspace), "<workspace>")
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
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
    if not isinstance(url, str):
        return ()
    parsed = urlsplit(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        return ()
    selected = Path(url2pathname(unquote(parsed.path))).resolve()
    artifact = artifacts_by_filename.get(selected.name)
    if (
        artifact is None
        or selected.parent != wheelhouse
        or artifact.canonical_name != package_name
        or artifact.version != package_version
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
    if not isinstance(name, str) or not isinstance(raw_version, str):
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
    raw_packages = document.get("packages")
    if not isinstance(raw_packages, list):
        _fail_metadata("resolver pylock.toml omits its package list")
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
    if (
        target.implementation_name != "cpython"
        or target.platform_python_implementation != "CPython"
        or target.implementation_version != target.python_full_version
    ):
        return None, (
            "uv target arguments cannot faithfully represent the declared Python "
            "implementation"
        )
    if target.platform_release or target.platform_version:
        return None, (
            "uv target arguments cannot faithfully represent platform-release or "
            "platform-version marker values"
        )

    marker_values = _resolver_platform_values(target.resolver_platform)
    if marker_values is None:
        return None, (
            "resolver-platform is not a faithfully represented uv marker target"
        )

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
        return tag.abi in {target_interpreter, "abi3", "none"}
    prefix = f"cp{release[0]}"
    minor = tag.interpreter.removeprefix(prefix)
    return (
        tag.interpreter.startswith(prefix)
        and minor.isdigit()
        and int(minor) <= release[1]
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
        pypy_abi = re.fullmatch(
            rf"pypy{release[0]}{release[1]}_pp[0-9]+",
            tag.abi,
        )
        return tag.interpreter == interpreter and (
            tag.abi == "none" or pypy_abi is not None
        )
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
    expected_implementation = {
        "cpython": "CPython",
        "pypy": "PyPy",
    }.get(target.implementation_name)
    if (
        expected_implementation is not None
        and target.platform_python_implementation != expected_implementation
    ):
        return "implementation-name conflicts with platform-python-implementation"
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


def _ensure_target_coherence(target: EnvironmentTarget, *, label: str) -> None:
    issue = _target_coherence_issue(target)
    if issue is not None:
        _error(label, issue)


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
    lines = [line.strip() for line in diagnostic.splitlines() if line.strip()]
    if lines and re.fullmatch(
        r"warning: The requested Python version .+ is not available; .+ will be "
        r"used to build dependencies instead\.",
        lines[0],
    ):
        lines.pop(0)
    if len(lines) < _MIN_UNSATISFIABLE_LINES or lines[0] != _UV_NO_SOLUTION_HEADER:
        return False
    explanation = " ".join(lines[1:])
    normalized = explanation.casefold()
    return (
        explanation.startswith("╰─▶ Because ")
        and explanation.endswith("requirements are unsatisfiable.")
        and not any(term in normalized for term in _UV_NON_SOLVER_TERMS)
    )


def _uv_reports_constraint_conflict(
    diagnostic: str,
    version: str,
    requirements: Sequence[str],
) -> bool:
    """Accept only versioned uv output that names contradictory exact pins."""
    if not _uv_reports_unsatisfiable(diagnostic, version):
        return False
    normalized = diagnostic.casefold()
    if any(term in normalized for term in _UV_ARTIFACT_AVAILABILITY_TERMS):
        return False
    groups = _resolver_requirement_groups(requirements)
    for name in _conflicting_requirement_names(requirements):
        exact_pins = {
            f"{name}=={Version(version_value)}".casefold()
            for requirement in groups[name]
            if (version_value := _exact_requirement_version(requirement)) is not None
        }
        if len(exact_pins) > 1 and all(pin in normalized for pin in exact_pins):
            return True
    return False


def _interpret_resolver_process(
    process: subprocess.CompletedProcess[str],
    *,
    version: str,
    workspace: _ResolverWorkspace,
    artifacts: Sequence[MetadataArtifact],
    requirements: Sequence[str],
) -> ResolverResult:
    if process.returncode != 0:
        diagnostic = process.stderr or process.stdout
        detail = _safe_process_text(diagnostic, workspace.directory)
        failed = process.returncode > 0 and _uv_reports_constraint_conflict(
            diagnostic,
            version,
            requirements,
        )
        return ResolverResult(
            status=(
                ResolutionStatus.RESOLUTION_FAILED
                if failed
                else ResolutionStatus.UNVERIFIED
            ),
            complete=failed,
            resolver="uv",
            resolver_version=version,
            packages=(),
            reason=detail or f"resolver exited with status {process.returncode}",
        )
    try:
        output = workspace.output.read_text(encoding="utf-8")
        packages, provenance_complete = _resolved_packages(
            output,
            artifacts,
            wheelhouse=workspace.wheelhouse,
        )
    except (OSError, UnicodeError, _MetadataError, InvalidVersion) as error:
        return _resolver_unverified(
            str(error) or "unable to parse resolver output", version
        )
    if not provenance_complete:
        return _resolver_unverified(
            "resolver selected package metadata whose exact artifact provenance "
            "was not established",
            version,
            packages,
        )
    return ResolverResult(
        status=ResolutionStatus.SUCCEEDED,
        complete=True,
        resolver="uv",
        resolver_version=version,
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
    if len(filenames) != len(set(filenames)):
        return None, "artifact filenames are not unique in the resolver set"
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
        version_process = subprocess.run(  # noqa: S603
            [workspace.executable, "--version"],
            check=False,
            capture_output=True,
            cwd=workspace.directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
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
                configuration.extras,
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
        process = subprocess.run(  # noqa: S603
            command,
            check=False,
            capture_output=True,
            cwd=workspace.directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            text=True,
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
    except OSError:
        return _resolver_unverified("unable to execute the isolated resolver", version)
    return _interpret_resolver_process(
        process,
        version=version,
        workspace=workspace,
        artifacts=artifacts,
        requirements=active_requirements,
    )


class UvResolverAdapter:
    """Run uv in a temporary, configuration-free, build-disabled boundary."""

    name = "uv"

    def resolve(
        self,
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        """Resolve one target with explicit network and timeout controls."""
        if not configuration.resolve:
            return ResolverResult(
                status=ResolutionStatus.NOT_REQUESTED,
                complete=True,
                resolver=self.name,
                resolver_version=None,
                packages=(),
                reason="resolver was not requested",
            )
        _resolver_target, target_issue = _canonical_resolver_target(target)
        if _resolver_target is None:
            return _resolver_unverified(target_issue or "resolver target is unverified")
        executable = shutil.which(configuration.resolver)
        if executable is None:
            return _resolver_unverified("uv executable is unavailable")
        with tempfile.TemporaryDirectory(prefix="pyahead-resolver-") as temporary:
            directory = Path(temporary)
            return _resolve_in_workspace(
                _ResolverWorkspace(
                    executable=executable,
                    directory=directory,
                    requirements=directory / "requirements.in",
                    output=directory / "pylock.toml",
                    wheelhouse=directory / "artifacts",
                ),
                configuration,
                target,
                artifacts,
                root=root,
            )


def collect_dependency_report(
    configuration: DependencyConfiguration,
    *,
    root: Path,
    resolver: ResolverAdapter | None = None,
) -> DependencyReport:
    """Collect deterministic direct metadata and optional resolver evidence."""
    resolved_root = root.resolve(strict=True)
    artifacts, issues = inspect_dependency_metadata(
        configuration.metadata_paths, root=resolved_root
    )
    adapter = resolver or UvResolverAdapter()
    targets: list[TargetDependencyResult] = []
    for target in configuration.targets:
        _ensure_target_coherence(target, label=f"dependency target {target.name!r}")
        declared = tuple(
            _evaluate_requirement(value, target, configuration.extras)
            for value in configuration.requirements
        )
        resolution = (
            _resolver_unverified(
                "resolver was not executed because configured metadata evidence "
                "is incomplete"
            )
            if configuration.resolve and issues
            else adapter.resolve(configuration, target, artifacts, root=resolved_root)
        )
        resolution = _validated_resolver_result(resolution, artifacts, declared)
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
        selected_evidence = _resolution_evidence_artifacts(
            artifacts,
            evidence_resolution,
        )
        correlated_declared = _correlate_declared_requirements(
            declared,
            selected_evidence,
            resolution,
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
