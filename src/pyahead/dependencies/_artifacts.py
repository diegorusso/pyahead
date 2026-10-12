"""Validation of metadata artifacts supplied through the API."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import (
    TYPE_CHECKING,
)

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
from pyahead.dependencies._metadata import _validate_core_metadata_schema
from pyahead.dependencies._model import (
    _DYNAMIC_FIELD,
    _EXTRA_FIELD,
    _LEGACY_IMPLICIT_DYNAMIC_FIELDS,
    _MAX_EXPANDED_TAGS,
    _MAX_EXTRAS,
    _MAX_METADATA_BYTES,
    _MAX_METADATA_INPUTS,
    _MAX_METADATA_REQUIREMENTS,
    _MAX_REQUIREMENTS,
    _SHA256,
    _STATIC_SDIST_METADATA_VERSION,
    _TAG_COMPONENTS,
    _WHEEL_PATH_PARTS,
    MetadataArtifact,
    MetadataKind,
    _error,
    _MetadataError,
    _string,
    _tag_expansion_count,
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
