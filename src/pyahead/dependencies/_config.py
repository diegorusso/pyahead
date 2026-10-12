"""Dependency configuration: reading, target parsing and validation."""

from __future__ import annotations

import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    TYPE_CHECKING,
)
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    canonicalize_name,
)

from pyahead._fs.errors import EntryChangedError, NotRegularFileError
from pyahead._fs.rooted import (
    RootedReadTooLargeError,
    read_rooted_bytes,
    repository_relative_path,
)
from pyahead._toml import parse_toml_document

if TYPE_CHECKING:
    from collections.abc import Sequence
from pyahead.dependencies._model import (
    _DEPENDENCY_KEYS,
    _EXTRA_FIELD,
    _MAX_CONFIGURATION_BYTES,
    _MAX_EXTRAS,
    _MAX_MARKER_EVALUATIONS,
    _MAX_METADATA_INPUTS,
    _MAX_REQUIREMENTS,
    _MAX_TAG_VALUES,
    _MAX_TARGETS,
    _SAFE_RESOLVER_PLATFORM,
    _TARGET_OPTIONAL_KEYS,
    _TARGET_REQUIRED_KEYS,
    DependencyConfiguration,
    DependencyProjectKind,
    EnvironmentTarget,
    _configuration_error,
    _configured_tags,
    _error,
    _string,
)
from pyahead.dependencies._targets import _target_coherence_issue
from pyahead.dependencies._values import (
    _boolean,
    _positive_number,
    _runtime_version,
    _string_list,
    _table,
)


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


def _read_dependency_document(
    root: Path, relative: Path, label: str
) -> dict[str, object]:
    """Read one stable regular TOML file through a root-anchored descriptor."""
    try:
        raw_document = read_rooted_bytes(root, relative, _MAX_CONFIGURATION_BYTES)
    except FileNotFoundError as error:
        raise _configuration_error(
            label, "configuration file does not exist"
        ) from error
    except RootedReadTooLargeError as error:
        raise _configuration_error(
            label, "configuration exceeds the size limit"
        ) from error
    except NotRegularFileError as error:
        raise _configuration_error(
            label, "configuration is not a regular file"
        ) from error
    except EntryChangedError as error:
        raise _configuration_error(
            label, "configuration changed while being read"
        ) from error
    except (OSError, RuntimeError, ValueError) as error:
        raise _configuration_error(label, "unable to read configuration") from error
    if len(raw_document) > _MAX_CONFIGURATION_BYTES:
        _error(label, "configuration exceeds the size limit")
    return parse_toml_document(raw_document, label)


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
        relative = repository_relative_path(resolved_root, selected)
    except (OSError, RuntimeError, ValueError) as error:
        raise _configuration_error(
            label, "unable to read configuration beneath the root"
        ) from error
    document = _read_dependency_document(
        resolved_root,
        relative,
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
    """Load strict dependency configuration without host environment defaults."""
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
