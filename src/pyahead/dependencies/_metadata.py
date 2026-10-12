"""Core-metadata parsing and direct inspection of artifacts."""

from __future__ import annotations

import hashlib
import re
import zipfile
import zlib
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import (
    TYPE_CHECKING,
)

from packaging.metadata import InvalidMetadata, Metadata
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import parse_tag
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

if TYPE_CHECKING:
    from collections.abc import Sequence
    from email.message import Message
from pyahead.dependencies._archives import (
    _check_zip_archive_limits,
    _metadata_payload,
    _read_artifact,
)
from pyahead.dependencies._config import _resolved_dependency_root
from pyahead.dependencies._model import (
    _ACTIVE_METADATA_REQUIREMENT_BUDGET,
    _DYNAMIC_FIELD,
    _EXTRA_FIELD,
    _LEGACY_IMPLICIT_DYNAMIC_FIELDS,
    _MAX_EXPANDED_TAGS,
    _MAX_EXTRAS,
    _MAX_METADATA_BYTES,
    _MAX_METADATA_INPUTS,
    _MAX_METADATA_TOTAL_BYTES,
    _MAX_REQUIREMENTS,
    _MAX_TAG_VALUES,
    _MAX_TEXT_LENGTH,
    _STATIC_SDIST_METADATA_VERSION,
    _TAG_COMPONENTS,
    _WHEEL_PATH_PARTS,
    MetadataArtifact,
    MetadataIssue,
    MetadataKind,
    _consume_archive_expansion,
    _error,
    _fail_metadata,
    _MetadataError,
    _tag_expansion_count,
    _with_archive_expansion_budget,
    _with_metadata_requirement_budget,
)


@dataclass(frozen=True)
class _ParsedCoreMetadata:
    name: str
    version: Version
    metadata_version: str
    requires_python: str | None
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    dynamic: tuple[str, ...]


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
