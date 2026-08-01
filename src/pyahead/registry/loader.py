"""Safe loading for the bundled M1 YAML registry."""

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import Protocol, TypeAlias, cast

import yaml

from pyahead.model import (
    ChangeEventKind,
    Impact,
    Registry,
    RegistryCertainty,
    Remediation,
    Rule,
    RuleEvent,
    RuleMatcher,
    SourceReference,
)
from pyahead.versions import PythonMinor

_RULE_ID_PATTERN = re.compile(r"CPY[0-9]{4}\Z")
_MANIFEST_NAME = PurePosixPath("index.yaml")

CanonicalValue: TypeAlias = (
    bool
    | float
    | int
    | str
    | list["CanonicalValue"]
    | dict[str, "CanonicalValue"]
    | None
)


class RegistryError(ValueError):
    """Raised when registry data cannot be loaded safely."""


class _RegistryFiles(Protocol):
    """Read registry files without depending on a concrete storage type."""

    def read_text(self, relative_path: PurePosixPath) -> str:
        """Read one validated repository-relative UTF-8 text file."""


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
            return resource.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            message = f"unable to read registry file {relative_path.as_posix()!r}"
            raise RegistryError(message) from error


@dataclass(frozen=True)
class _PathFiles:
    """Registry files rooted at an explicit directory."""

    root: Path

    def read_text(self, relative_path: PurePosixPath) -> str:
        """Read a path after proving that it remains beneath the registry root."""
        candidate = self.root.joinpath(*relative_path.parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.root)
            if not resolved.is_file():
                message = "registry entries must be regular files"
                raise RegistryError(message)
            return resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError) as error:
            message = f"unable to read registry file {relative_path.as_posix()!r}"
            raise RegistryError(message) from error


def _as_mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        message = f"{context} must be a mapping with string keys"
        raise RegistryError(message)
    return cast("dict[str, object]", value)


def _as_sequence(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        message = f"{context} must be a list"
        raise RegistryError(message)
    return cast("list[object]", value)


def _required_string(data: Mapping[str, object], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        message = f"{context}.{key} must be a non-empty string"
        raise RegistryError(message)
    return value


def _string_tuple(value: object, context: str) -> tuple[str, ...]:
    values = _as_sequence(value, context)
    if not all(isinstance(item, str) and item for item in values):
        message = f"{context} must contain only non-empty strings"
        raise RegistryError(message)
    return tuple(cast("list[str]", values))


def _load_mapping(text: str, context: str) -> Mapping[str, object]:
    try:
        loaded = cast("object", yaml.safe_load(text))
    except yaml.YAMLError as error:
        message = f"{context} is not valid YAML"
        raise RegistryError(message) from error
    return _as_mapping(loaded, context)


def _canonical_value(value: object, context: str) -> CanonicalValue:
    if value is None or isinstance(value, (bool, int, str)):
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
        return {
            key: _canonical_value(item, f"{context}.{key}")
            for key, item in string_mapping.items()
        }
    message = f"{context} contains a value that cannot be canonicalized"
    raise RegistryError(message)


def _schema_version(data: Mapping[str, object], context: str) -> None:
    if data.get("schema_version") != 1:
        message = f"{context}.schema_version must equal 1"
        raise RegistryError(message)


def _safe_rule_path(value: object) -> PurePosixPath:
    if not isinstance(value, str):
        message = "registry index rule paths must be strings"
        raise RegistryError(message)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or path.suffix not in {".yaml", ".yml"}
    ):
        message = f"unsafe registry rule path {value!r}"
        raise RegistryError(message)
    return path


def _parse_event(value: object, context: str) -> RuleEvent:
    data = _as_mapping(value, context)
    try:
        kind = ChangeEventKind(_required_string(data, "event", context))
        python = PythonMinor.parse(_required_string(data, "python", context))
        certainty = RegistryCertainty(_required_string(data, "certainty", context))
    except ValueError as error:
        message = f"{context} contains an unsupported event value"
        raise RegistryError(message) from error
    return RuleEvent(
        kind=kind,
        python=python,
        certainty=certainty,
        source_id=_required_string(data, "source", context),
    )


def _parse_matcher(value: object, context: str) -> RuleMatcher:
    data = _as_mapping(value, context)
    kind = _required_string(data, "kind", context)
    if kind != "module-import":
        message = f"{context}.kind is not supported by the M1 engine"
        raise RegistryError(message)
    return RuleMatcher(
        kind=kind,
        module=_required_string(data, "module", context),
    )


def _parse_source(value: object, context: str) -> SourceReference:
    data = _as_mapping(value, context)
    url = _required_string(data, "url", context)
    if not url.startswith("https://"):
        message = f"{context}.url must use HTTPS"
        raise RegistryError(message)
    return SourceReference(
        id=_required_string(data, "id", context),
        title=_required_string(data, "title", context),
        url=url,
    )


def _parse_impact(value: object, context: str) -> Impact:
    if not isinstance(value, str):
        message = f"{context} must be a string"
        raise RegistryError(message)
    try:
        return Impact(value)
    except ValueError as error:
        message = f"{context} contains an unsupported impact"
        raise RegistryError(message) from error


def _parse_rule(text: str, path: PurePosixPath) -> Rule:
    context = path.as_posix()
    data = _load_mapping(text, context)
    _schema_version(data, context)

    rule_id = _required_string(data, "id", context)
    if _RULE_ID_PATTERN.fullmatch(rule_id) is None:
        message = f"{context}.id must use the CPY0000 format"
        raise RegistryError(message)

    scope = _as_mapping(data.get("scope"), f"{context}.scope")
    subject = _as_mapping(data.get("subject"), f"{context}.subject")
    if _required_string(subject, "kind", f"{context}.subject") != "module":
        message = f"{context}.subject.kind must equal 'module' in M1"
        raise RegistryError(message)

    events = tuple(
        _parse_event(item, f"{context}.timeline[{index}]")
        for index, item in enumerate(
            _as_sequence(data.get("timeline"), f"{context}.timeline")
        )
    )
    if not events:
        message = f"{context}.timeline must not be empty"
        raise RegistryError(message)

    impact = _as_mapping(data.get("impact"), f"{context}.impact")
    matchers = tuple(
        _parse_matcher(item, f"{context}.matchers[{index}]")
        for index, item in enumerate(
            _as_sequence(data.get("matchers"), f"{context}.matchers")
        )
    )
    if not matchers:
        message = f"{context}.matchers must not be empty"
        raise RegistryError(message)

    remediation_data = _as_mapping(data.get("remediation"), f"{context}.remediation")
    sources = tuple(
        _parse_source(item, f"{context}.sources[{index}]")
        for index, item in enumerate(
            _as_sequence(data.get("sources"), f"{context}.sources")
        )
    )
    source_ids = {source.id for source in sources}
    if not sources or any(event.source_id not in source_ids for event in events):
        message = f"{context} timeline sources must resolve within the rule"
        raise RegistryError(message)

    tags = _string_tuple(data.get("tags"), f"{context}.tags")
    contexts = _string_tuple(scope.get("contexts"), f"{context}.scope.contexts")

    return Rule(
        id=rule_id,
        title=_required_string(data, "title", context),
        summary=_required_string(data, "summary", context),
        subject=_required_string(subject, "name", f"{context}.subject"),
        contexts=contexts,
        events=events,
        on_deprecation=_parse_impact(
            impact.get("on_deprecation"), f"{context}.impact.on_deprecation"
        ),
        on_removal=_parse_impact(
            impact.get("on_removal"), f"{context}.impact.on_removal"
        ),
        matchers=matchers,
        remediation=Remediation(
            summary=_required_string(
                remediation_data, "summary", f"{context}.remediation"
            )
        ),
        sources=sources,
        tags=tags,
    )


def _source_from_path(source: Path) -> tuple[_PathFiles, PurePosixPath]:
    try:
        resolved = source.resolve(strict=True)
    except FileNotFoundError as error:
        message = "registry path does not exist"
        raise RegistryError(message) from error
    except OSError as error:
        message = "unable to resolve registry path"
        raise RegistryError(message) from error
    if resolved.is_dir():
        return _PathFiles(resolved), _MANIFEST_NAME
    if not resolved.is_file():
        message = "registry path must be a directory or regular file"
        raise RegistryError(message)
    return _PathFiles(resolved.parent), PurePosixPath(resolved.name)


def load_registry(source: Path | None = None) -> Registry:
    """Load the bundled registry or an explicit registry index safely."""
    if source is None:
        files: _RegistryFiles = _PackageFiles(resources.files("pyahead.data.registry"))
        manifest_path = _MANIFEST_NAME
    else:
        files, manifest_path = _source_from_path(source)

    manifest_text = files.read_text(manifest_path)
    manifest = _load_mapping(manifest_text, manifest_path.as_posix())
    _schema_version(manifest, manifest_path.as_posix())
    release = _required_string(manifest, "release", manifest_path.as_posix())
    rule_paths = tuple(
        _safe_rule_path(item)
        for item in _as_sequence(manifest.get("rules"), "index.yaml.rules")
    )
    if not rule_paths:
        message = "index.yaml.rules must not be empty"
        raise RegistryError(message)

    contents = {manifest_path: manifest}
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for path in rule_paths:
        text = files.read_text(path)
        contents[path] = _load_mapping(text, path.as_posix())
        rule = _parse_rule(text, path)
        if rule.id in seen_ids:
            message = f"duplicate registry rule ID {rule.id}"
            raise RegistryError(message)
        seen_ids.add(rule.id)
        rules.append(rule)

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

    return Registry(
        release=release,
        revision=digest.hexdigest(),
        rules=tuple(rules),
    )
