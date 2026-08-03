"""Safe loading for strict bundled and author-supplied registries."""

import hashlib
import json
import math
import os
import stat
from collections.abc import Iterator, Mapping
from contextlib import suppress
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import IO, Protocol, TypeAlias, cast

import yaml

from pyahead.model import (
    CoverageDisposition,
    CoverageManifest,
    PythonRelease,
    Registry,
    Rule,
)
from pyahead.registry.schema import (
    RegistryError,
    parse_coverage_manifest,
    parse_manifest,
    parse_release_metadata,
    parse_rule,
)

_MANIFEST_NAME = PurePosixPath("index.yaml")
MAX_REGISTRY_FILE_BYTES = 2 * 1024 * 1024
_MAX_YAML_DEPTH = 64
_MAX_YAML_NODES = 10_000
_READ_CHUNK_BYTES = 64 * 1024

CanonicalValue: TypeAlias = (
    bool
    | float
    | int
    | str
    | list["CanonicalValue"]
    | dict[str, "CanonicalValue"]
    | None
)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader reserved for strict registry construction."""


class _DuplicateKeyError(yaml.YAMLError):
    """Raised before a YAML mapping can overwrite an earlier key."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.nodes.MappingNode,
) -> Iterator[dict[object, object]]:
    """Construct one mapping while rejecting recursive duplicate keys."""
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    yield mapping
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        try:
            duplicate = key in mapping
        except TypeError as error:
            message = "mapping keys must be hashable"
            raise _DuplicateKeyError(message) from error
        if duplicate:
            message = f"duplicate mapping key {key!r}"
            raise _DuplicateKeyError(message)
        mapping[key] = loader.construct_object(value_node, deep=False)


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _RegistryFiles(Protocol):
    """Read registry files without depending on a concrete storage type."""

    def read_text(self, relative_path: PurePosixPath) -> str:
        """Read one validated repository-relative UTF-8 text file."""


def _read_error(relative_path: PurePosixPath) -> str:
    return f"unable to read registry file {relative_path.as_posix()!r}"


def _decode_registry_bytes(data: bytes, relative_path: PurePosixPath) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeError as error:
        raise RegistryError(_read_error(relative_path)) from error


def _read_bounded_stream(
    stream: IO[bytes],
    relative_path: PurePosixPath,
) -> str:
    data = bytearray()
    while len(data) <= MAX_REGISTRY_FILE_BYTES:
        chunk = stream.read(
            min(_READ_CHUNK_BYTES, MAX_REGISTRY_FILE_BYTES + 1 - len(data))
        )
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > MAX_REGISTRY_FILE_BYTES:
        message = (
            f"registry file {relative_path.as_posix()!r} exceeds the "
            f"{MAX_REGISTRY_FILE_BYTES}-byte limit"
        )
        raise RegistryError(message)
    return _decode_registry_bytes(bytes(data), relative_path)


def _validate_file_status(
    status: os.stat_result,
    relative_path: PurePosixPath,
) -> None:
    if not stat.S_ISREG(status.st_mode):
        message = "registry entries must be regular files"
        raise RegistryError(message)
    if status.st_size > MAX_REGISTRY_FILE_BYTES:
        message = (
            f"registry file {relative_path.as_posix()!r} exceeds the "
            f"{MAX_REGISTRY_FILE_BYTES}-byte limit"
        )
        raise RegistryError(message)


def _validate_opened_file(
    expected: os.stat_result,
    opened: os.stat_result,
    relative_path: PurePosixPath,
) -> None:
    _validate_file_status(opened, relative_path)
    if not os.path.samestat(expected, opened):
        message = "registry entry changed while it was being opened"
        raise RegistryError(message)


@dataclass(frozen=True)
class _PackageFiles:
    """Registry files installed as package resources."""

    root: Traversable

    def read_text(self, relative_path: PurePosixPath) -> str:
        """Read a bundled resource."""
        resource = self.root
        for part in relative_path.parts:
            resource = resource.joinpath(part)
        try:
            with resource.open("rb") as stream:
                return _read_bounded_stream(stream, relative_path)
        except RegistryError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise RegistryError(_read_error(relative_path)) from error


@dataclass(frozen=True)
class _PathFiles:
    """Registry files rooted at an explicit directory."""

    root: Path

    def _checked_status(self, candidate: Path) -> os.stat_result:
        """Reject every symlink component before opening a registry file."""
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as error:  # pragma: no cover - callers use validated paths.
            message = "registry path escapes its root"
            raise RegistryError(message) from error
        current = self.root
        parts = relative.parts
        for index, part in enumerate(parts):
            current = current / part
            try:
                status = current.lstat()
            except OSError as error:
                raise RegistryError(_read_error(PurePosixPath(*parts))) from error
            if stat.S_ISLNK(status.st_mode):
                message = "registry entries must not traverse symlinks"
                raise RegistryError(message)
            if index < len(parts) - 1 and not stat.S_ISDIR(status.st_mode):
                message = "registry path parents must be directories"
                raise RegistryError(message)
        return status

    @staticmethod
    def _read_descriptor(
        descriptor: int,
        relative_path: PurePosixPath,
    ) -> str:
        data = bytearray()
        while len(data) <= MAX_REGISTRY_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, MAX_REGISTRY_FILE_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_REGISTRY_FILE_BYTES:
            message = (
                f"registry file {relative_path.as_posix()!r} exceeds the "
                f"{MAX_REGISTRY_FILE_BYTES}-byte limit"
            )
            raise RegistryError(message)
        return _decode_registry_bytes(bytes(data), relative_path)

    def read_text(self, relative_path: PurePosixPath) -> str:
        """Read one bounded regular file through its verified descriptor."""
        candidate = self.root.joinpath(*relative_path.parts)
        descriptor = -1
        expected_status = self._checked_status(candidate)
        _validate_file_status(expected_status, relative_path)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.root)
            flags = os.O_RDONLY
            for name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
                flags |= cast("int", getattr(os, name, 0))
            descriptor = os.open(candidate, flags)
            opened_status = os.fstat(descriptor)
            _validate_opened_file(expected_status, opened_status, relative_path)
            return self._read_descriptor(descriptor, relative_path)
        except RegistryError:
            raise
        except (OSError, UnicodeError, ValueError) as error:
            raise RegistryError(_read_error(relative_path)) from error
        finally:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)


def _validate_yaml_graph(node: yaml.nodes.Node, context: str) -> None:
    """Bound YAML construction and reject aliases or recursive node graphs."""
    seen: set[int] = set()
    stack: list[tuple[yaml.nodes.Node, int]] = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        identity = id(current)
        if identity in seen:
            message = f"{context} must not contain YAML aliases or cycles"
            raise RegistryError(message)
        seen.add(identity)
        if len(seen) > _MAX_YAML_NODES:
            message = f"{context} exceeds the {_MAX_YAML_NODES}-node YAML limit"
            raise RegistryError(message)
        if depth > _MAX_YAML_DEPTH:
            message = f"{context} exceeds the {_MAX_YAML_DEPTH}-level YAML depth limit"
            raise RegistryError(message)
        if isinstance(current, yaml.nodes.MappingNode):
            children = [child for pair in current.value for child in pair]
        elif isinstance(current, yaml.nodes.SequenceNode):
            children = list(current.value)
        else:
            children = []
        stack.extend((child, depth + 1) for child in reversed(children))


def _load_mapping(text: str, context: str) -> Mapping[str, object]:
    loader = _UniqueKeySafeLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            loaded: object = None
        else:
            _validate_yaml_graph(node, context)
            loaded = cast(
                "object",
                loader.construct_document(node),  # type: ignore[no-untyped-call]
            )
    except RegistryError:
        raise
    except (OverflowError, RecursionError, ValueError, yaml.YAMLError) as error:
        message = f"{context} is not valid YAML"
        raise RegistryError(message) from error
    finally:
        loader.dispose()  # type: ignore[no-untyped-call]
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        message = f"{context} must be a mapping with string keys"
        raise RegistryError(message)
    return cast("dict[str, object]", loaded)


def _canonical_value(value: object, context: str) -> CanonicalValue:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            message = f"{context} contains an invalid Unicode surrogate"
            raise RegistryError(message) from error
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, list):
        return [
            _canonical_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        string_mapping = cast("dict[str, object]", value)
        canonical: dict[str, CanonicalValue] = {}
        for key, item in string_mapping.items():
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as error:
                message = f"{context} contains an invalid Unicode surrogate"
                raise RegistryError(message) from error
            canonical[key] = _canonical_value(item, f"{context}.{key}")
        return canonical
    message = f"{context} contains a value that cannot be canonicalized"
    raise RegistryError(message)


def _source_path_status(path: Path) -> os.stat_result:
    """Read explicit-source metadata without dereferencing the final entry."""
    try:
        status = path.lstat()
    except FileNotFoundError as error:
        message = "registry path does not exist"
        raise RegistryError(message) from error
    except OSError as error:
        message = "unable to resolve registry path"
        raise RegistryError(message) from error
    if stat.S_ISLNK(status.st_mode):
        message = "registry source path must not traverse symlinks"
        raise RegistryError(message)
    return status


def _checked_source_path(source: Path) -> tuple[Path, os.stat_result]:
    """Inspect every caller-supplied path component without following links."""
    candidate = source if source.is_absolute() else Path.cwd() / source
    current = Path(candidate.anchor)
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    status: os.stat_result | None = None
    for index, part in enumerate(parts):
        if part == "..":
            current = current.parent
            status = None
            continue
        current /= part
        status = _source_path_status(current)
        if index < len(parts) - 1 and not stat.S_ISDIR(status.st_mode):
            message = "registry source path parents must be directories"
            raise RegistryError(message)

    if status is None:
        status = _source_path_status(current)
    return current, status


def _source_from_path(source: Path) -> tuple[_PathFiles, PurePosixPath]:
    checked_path, checked_status = _checked_source_path(source)
    try:
        resolved = source.resolve(strict=True)
    except FileNotFoundError as error:
        message = "registry path does not exist"
        raise RegistryError(message) from error
    except OSError as error:
        message = "unable to resolve registry path"
        raise RegistryError(message) from error
    rechecked_path, rechecked_status = _checked_source_path(source)
    if (
        resolved != rechecked_path
        or checked_path != rechecked_path
        or not os.path.samestat(checked_status, rechecked_status)
    ):
        message = "registry source path changed while it was being resolved"
        raise RegistryError(message)
    if stat.S_ISDIR(rechecked_status.st_mode):
        return _PathFiles(resolved), _MANIFEST_NAME
    if not stat.S_ISREG(rechecked_status.st_mode):
        message = "registry path must be a directory or regular file"
        raise RegistryError(message)
    return _PathFiles(resolved.parent), PurePosixPath(resolved.name)


def _validate_identity(
    rule: Rule,
    path: PurePosixPath,
    identities: dict[str, str],
) -> None:
    if path.stem != rule.id:
        message = (
            f"registry rule filename {path.name!r} must match canonical ID {rule.id!r}"
        )
        raise RegistryError(message)
    for identifier in (rule.id, *rule.aliases):
        if existing := identities.get(identifier):
            message = (
                f"registry rule ID or alias {identifier} is already owned by {existing}"
            )
            raise RegistryError(message)
        identities[identifier] = rule.id


def _registry_digest(contents: Mapping[PurePosixPath, object]) -> str:
    digest = hashlib.sha256()
    for path in sorted(contents, key=PurePosixPath.as_posix):
        digest.update(path.as_posix().encode())
        digest.update(b"\0")
        digest.update(
            json.dumps(
                _canonical_value(contents[path], path.as_posix()),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        digest.update(b"\0")
    return digest.hexdigest()


def _validate_coverage(
    manifests: tuple[CoverageManifest, ...],
    rules: tuple[Rule, ...],
) -> None:
    """Resolve coverage references and require every curated rule to be owned."""
    source_ids = tuple(manifest.source.id for manifest in manifests)
    if len(set(source_ids)) != len(source_ids):
        message = "coverage manifests must use unique source IDs"
        raise RegistryError(message)

    canonical_ids = frozenset(rule.id for rule in rules)
    covered_ids: set[str] = set()
    for manifest in manifests:
        classified_keys = {entry.source_key for entry in manifest.entries}
        audited_keys = set(manifest.source_keys)
        unclassified = sorted(audited_keys.difference(classified_keys))
        unknown_entries = sorted(classified_keys.difference(audited_keys))
        if unclassified:
            message = (
                f"coverage source {manifest.source.id!r} has unclassified source "
                f"entries: {', '.join(unclassified)}"
            )
            raise RegistryError(message)
        if unknown_entries:
            message = (
                f"coverage source {manifest.source.id!r} classifies entries absent "
                f"from its audited source-key census: {', '.join(unknown_entries)}"
            )
            raise RegistryError(message)
        for entry in manifest.entries:
            unknown = sorted(set(entry.rules).difference(canonical_ids))
            if unknown:
                message = (
                    f"coverage source {manifest.source.id!r} entry "
                    f"{entry.source_key!r} references unknown canonical rule(s): "
                    f"{', '.join(unknown)}"
                )
                raise RegistryError(message)
            if entry.disposition in {
                CoverageDisposition.IMPLEMENTED,
                CoverageDisposition.PARTIAL,
            }:
                covered_ids.update(entry.rules)
    missing = sorted(canonical_ids.difference(covered_ids))
    if manifests and missing:
        message = (
            "canonical registry rule(s) lack implemented or partial source "
            f"coverage: {', '.join(missing)}"
        )
        raise RegistryError(message)


def load_registry(source: Path | None = None) -> Registry:
    """Load the bundled registry or an explicit registry index safely."""
    if source is None:
        files: _RegistryFiles = _PackageFiles(resources.files("pyahead.data.registry"))
        manifest_path = _MANIFEST_NAME
    else:
        files, manifest_path = _source_from_path(source)

    manifest_data = _load_mapping(
        files.read_text(manifest_path), manifest_path.as_posix()
    )
    manifest = parse_manifest(manifest_data, manifest_path.as_posix())
    contents: dict[PurePosixPath, object] = {manifest_path: manifest_data}
    releases: tuple[PythonRelease, ...]
    if manifest.release_path is None:
        releases = ()
    else:
        release_data = _load_mapping(
            files.read_text(manifest.release_path),
            manifest.release_path.as_posix(),
        )
        contents[manifest.release_path] = release_data
        releases = parse_release_metadata(
            release_data,
            manifest.release_path.as_posix(),
        )
    identities: dict[str, str] = {}
    rules: list[Rule] = []
    for path in manifest.rule_paths:
        rule_data = _load_mapping(files.read_text(path), path.as_posix())
        contents[path] = rule_data
        rule = parse_rule(rule_data, path.as_posix())
        _validate_identity(rule, path, identities)
        rules.append(rule)

    reused = sorted(set(manifest.retired_ids).intersection(identities))
    if reused:
        message = f"retired registry ID(s) cannot be reused: {', '.join(reused)}"
        raise RegistryError(message)

    coverage: list[CoverageManifest] = []
    for path in manifest.coverage_paths:
        coverage_data = _load_mapping(files.read_text(path), path.as_posix())
        contents[path] = coverage_data
        coverage.append(parse_coverage_manifest(coverage_data, path.as_posix()))
    _validate_coverage(tuple(coverage), tuple(rules))

    return Registry(
        release=manifest.release,
        revision=_registry_digest(contents),
        retired_ids=manifest.retired_ids,
        rules=tuple(rules),
        releases=releases,
        coverage=tuple(coverage),
    )
