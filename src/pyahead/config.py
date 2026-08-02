"""Strict project configuration and Python-policy inference."""

from __future__ import annotations

import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeVar

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from pyahead.model import (
    ConfigurationError,
    EffectiveConfiguration,
    FailOn,
    MatchConfidence,
    PerFileIgnore,
    Policy,
    PolicyProvenance,
    Registry,
    ReleaseStatus,
)
from pyahead.versions import InvalidPythonMinorError, PythonMinor

_CONFIG_KEYS = frozenset(
    {
        "baseline-python",
        "exclude",
        "fail-on",
        "horizon-python",
        "include",
        "max-file-size-bytes",
        "minimum-confidence",
        "per-file-ignores",
        "respect-gitignore",
        "show-unscheduled",
        "source-roots",
    }
)
_DEFAULT_MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024
_CONVENTIONAL_SOURCE_ROOTS = (".", "src")
_CONVENTIONAL_SOURCE_ROOTS_PROVENANCE = "inferred:conventional-root-and-src-layout"
_MINOR_RELEASE_COMPONENTS = 2
_PATCH_RELEASE_COMPONENTS = 3
_PYPROJECT_LABEL = "pyproject.toml"
_ACTIVE_RELEASE_STATUSES = frozenset({ReleaseStatus.STABLE, ReleaseStatus.PRERELEASE})
_ConfigurationEnum = TypeVar("_ConfigurationEnum", FailOn, MatchConfidence)


@dataclass(frozen=True)
class ProjectConfiguration:
    """Values explicitly declared in one ``[tool.pyahead]`` table."""

    baseline_python: str | None = None
    horizon_python: str | None = None
    include: tuple[str, ...] | None = None
    exclude: tuple[str, ...] | None = None
    source_roots: tuple[str, ...] | None = None
    respect_gitignore: bool | None = None
    minimum_confidence: MatchConfidence | None = None
    fail_on: FailOn | None = None
    show_unscheduled: bool | None = None
    max_file_size_bytes: int | None = None
    per_file_ignores: tuple[PerFileIgnore, ...] = ()
    label: str = "pyproject.toml"


@dataclass(frozen=True)
class ConfigurationOverrides:
    """Explicit library or command-line values that replace project config."""

    baseline_python: str | None = None
    horizon_python: str | None = None
    include: tuple[str, ...] | None = None
    exclude: tuple[str, ...] | None = None
    source_roots: tuple[str, ...] | None = None
    respect_gitignore: bool | None = None
    minimum_confidence: str | MatchConfidence | None = None
    fail_on: str | FailOn | None = None
    show_unscheduled: bool | None = None
    max_file_size_bytes: int | None = None
    per_file_ignores: tuple[PerFileIgnore, ...] = ()
    fail_new_only: bool = False
    show_suppressed: bool = False
    allow_incomplete: bool = False


@dataclass(frozen=True)
class ResolvedConfiguration:
    """Effective policy, provenance, and scan behaviour."""

    policy: Policy
    policy_provenance: PolicyProvenance
    scan: EffectiveConfiguration
    source_roots_inferred: bool


def _configuration_error(label: str, message: str) -> ConfigurationError:
    return ConfigurationError(f"{label}: {message}")


def _read_toml(path: Path, root: Path, label: str) -> dict[str, object]:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        status = resolved.stat()
        if not stat.S_ISREG(status.st_mode):
            raise _configuration_error(label, "configuration is not a regular file")
        with resolved.open("rb") as stream:
            document = tomllib.load(stream)
    except FileNotFoundError as error:
        raise _configuration_error(
            label, "configuration file does not exist"
        ) from error
    except tomllib.TOMLDecodeError as error:
        raise _configuration_error(label, "configuration is not valid TOML") from error
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        raise _configuration_error(
            label, "configuration must remain beneath the project root"
        ) from error
    except (OSError, RuntimeError) as error:
        raise _configuration_error(label, "unable to read configuration") from error
    return document


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _configuration_error(label, "expected a TOML table")
    return value


def _optional_string(table: dict[str, object], key: str, label: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise _configuration_error(label, f"{key!r} must be a non-empty string")
    return value


def _optional_bool(table: dict[str, object], key: str, label: str) -> bool | None:
    value = table.get(key)
    if value is None:
        return None
    if type(value) is not bool:
        raise _configuration_error(label, f"{key!r} must be a boolean")
    return value


def _string_list(
    table: dict[str, object], key: str, label: str
) -> tuple[str, ...] | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise _configuration_error(
            label, f"{key!r} must be an array of non-empty strings"
        )
    if len(value) != len(set(value)):
        raise _configuration_error(label, f"{key!r} must not contain duplicates")
    return tuple(value)


def _optional_positive_int(
    table: dict[str, object], key: str, label: str
) -> int | None:
    value = table.get(key)
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise _configuration_error(label, f"{key!r} must be a positive integer")
    return value


def _enum_value(
    value: str | _ConfigurationEnum | None,
    enum_type: type[_ConfigurationEnum],
    key: str,
    label: str,
) -> _ConfigurationEnum | None:
    if value is None:
        return None
    try:
        return enum_type(value)
    except ValueError as error:
        choices = ", ".join(item.value for item in enum_type)
        raise _configuration_error(
            label, f"{key!r} must be one of: {choices}"
        ) from error


def _normalize_source_roots(
    values: tuple[str, ...] | None, label: str
) -> tuple[str, ...] | None:
    if values is None:
        return None
    normalized: list[str] = []
    for value in values:
        if "\\" in value:
            raise _configuration_error(
                label, "source-roots entries must use POSIX separators"
            )
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise _configuration_error(
                label, "source-roots entries must be relative and remain in the root"
            )
        canonical = path.as_posix()
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


def _validate_source_roots(root: Path, values: tuple[str, ...]) -> None:
    for value in values:
        candidate = root / value
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as error:
            message = f"source root {value!r} does not resolve beneath the project"
            raise ConfigurationError(message) from error
        if not resolved.is_dir():
            message = f"source root {value!r} must be a directory"
            raise ConfigurationError(message)


def _per_file_ignores(
    table: dict[str, object], label: str
) -> tuple[PerFileIgnore, ...]:
    raw = table.get("per-file-ignores")
    if raw is None:
        return ()
    ignores = _table(raw, f"{label}:tool.pyahead.per-file-ignores")
    parsed: list[PerFileIgnore] = []
    for pattern, value in ignores.items():
        if not pattern:
            raise _configuration_error(
                label, "per-file ignore patterns cannot be empty"
            )
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise _configuration_error(
                label,
                f"per-file ignore {pattern!r} must be a non-empty array of rule IDs",
            )
        rule_ids = tuple(dict.fromkeys(value))
        parsed.append(PerFileIgnore(pattern=pattern, rule_ids=rule_ids))
    return tuple(parsed)


def _parse_project_configuration(
    document: dict[str, object], label: str
) -> ProjectConfiguration:
    tool_value = document.get("tool")
    if tool_value is None:
        return ProjectConfiguration(label=label)
    tool = _table(tool_value, f"{label}:tool")
    pyahead_value = tool.get("pyahead")
    if pyahead_value is None:
        return ProjectConfiguration(label=label)
    pyahead = _table(pyahead_value, f"{label}:tool.pyahead")
    unknown = sorted(set(pyahead).difference(_CONFIG_KEYS))
    if unknown:
        rendered = ", ".join(repr(key) for key in unknown)
        raise _configuration_error(label, f"unknown [tool.pyahead] key(s): {rendered}")

    minimum = _enum_value(
        _optional_string(pyahead, "minimum-confidence", label),
        MatchConfidence,
        "minimum-confidence",
        label,
    )
    if minimum is MatchConfidence.LOW:
        raise _configuration_error(
            label, "'minimum-confidence' supports only 'high' or 'medium'"
        )
    return ProjectConfiguration(
        baseline_python=_optional_string(pyahead, "baseline-python", label),
        horizon_python=_optional_string(pyahead, "horizon-python", label),
        include=_string_list(pyahead, "include", label),
        exclude=_string_list(pyahead, "exclude", label),
        source_roots=_normalize_source_roots(
            _string_list(pyahead, "source-roots", label), label
        ),
        respect_gitignore=_optional_bool(pyahead, "respect-gitignore", label),
        minimum_confidence=minimum,
        fail_on=_enum_value(
            _optional_string(pyahead, "fail-on", label),
            FailOn,
            "fail-on",
            label,
        ),
        show_unscheduled=_optional_bool(pyahead, "show-unscheduled", label),
        max_file_size_bytes=_optional_positive_int(
            pyahead, "max-file-size-bytes", label
        ),
        per_file_ignores=_per_file_ignores(pyahead, label),
        label=label,
    )


def load_project_configuration(
    root: Path, config_path: Path | None
) -> ProjectConfiguration:
    """Load only the selected root's strict ``[tool.pyahead]`` table."""
    resolved_root = root.resolve(strict=True)
    selected = config_path or (resolved_root / "pyproject.toml")
    if not selected.is_absolute():
        selected = resolved_root / selected
    if config_path is None and not selected.exists():
        return ProjectConfiguration()
    label = selected.name
    return _parse_project_configuration(
        _read_toml(selected, resolved_root, label), label
    )


def _project_requires_python(root: Path) -> str | None:
    path = root / "pyproject.toml"
    if not path.exists():
        return None
    document = _read_toml(path, root, _PYPROJECT_LABEL)
    project_value = document.get("project")
    if project_value is None:
        return None
    project = _table(project_value, "pyproject.toml:project")
    requires_python = project.get("requires-python")
    if requires_python is None:
        return None
    if not isinstance(requires_python, str) or not requires_python:
        raise _configuration_error(
            _PYPROJECT_LABEL,
            "project.requires-python must be a non-empty string",
        )
    return requires_python


def _registry_versions(registry: Registry) -> tuple[PythonMinor, ...]:
    versions = {release.python for release in registry.releases}
    versions.update(event.python for rule in registry.rules for event in rule.events)
    if not versions:
        return ()
    first = min(versions)
    last = max(versions)
    return tuple(
        PythonMinor(major=first.major, minor=minor)
        for minor in range(first.minor, last.minor + 1)
    )


def _specifier_patch_candidates(
    specifier: SpecifierSet, minor: PythonMinor
) -> tuple[Version, ...]:
    patches = {0, 1, 999_999}
    for item in specifier:
        raw = item.version.rstrip(".*")
        try:
            release = Version(raw).release
        except InvalidVersion:
            continue
        if len(release) >= _MINOR_RELEASE_COMPONENTS and release[
            :_MINOR_RELEASE_COMPONENTS
        ] == (minor.major, minor.minor):
            patch = release[2] if len(release) >= _PATCH_RELEASE_COMPONENTS else 0
            patches.update({max(0, patch - 1), patch, patch + 1})
    return tuple(
        Version(f"{minor.major}.{minor.minor}.{patch}") for patch in sorted(patches)
    )


def infer_baseline(
    declaration: str, supported_versions: tuple[PythonMinor, ...]
) -> PythonMinor:
    """Infer the lowest supported minor included by ``Requires-Python``."""
    try:
        specifier = SpecifierSet(declaration)
    except InvalidSpecifier as error:
        raise _configuration_error(
            _PYPROJECT_LABEL,
            "project.requires-python is not a valid specifier",
        ) from error
    for minor in supported_versions:
        try:
            if any(
                specifier.contains(candidate, prereleases=True)
                for candidate in _specifier_patch_candidates(specifier, minor)
            ):
                return minor
        except (InvalidSpecifier, InvalidVersion) as error:
            raise _configuration_error(
                _PYPROJECT_LABEL,
                "project.requires-python cannot be evaluated at minor granularity",
            ) from error
    raise _configuration_error(
        _PYPROJECT_LABEL,
        "project.requires-python includes no Python minor in the registry window",
    )


def _default_horizon(registry: Registry) -> PythonMinor:
    active = tuple(
        release.python
        for release in registry.releases
        if release.status in _ACTIVE_RELEASE_STATUSES
    )
    if active:
        return max(active)
    message = (
        "horizon Python is required because the registry has no stable or "
        "prerelease release metadata"
    )
    raise ConfigurationError(message)


def _validate_policy_window(
    policy: Policy,
    supported_versions: tuple[PythonMinor, ...],
) -> None:
    supported = frozenset(supported_versions)
    if policy.baseline_python in supported and policy.horizon_python in supported:
        return
    first = min(supported_versions)
    last = max(supported_versions)
    message = (
        "Python policy must remain within the registry analysis window "
        f"{first} through {last}"
    )
    raise ConfigurationError(message)


def _merge_per_file_ignores(
    configured: tuple[PerFileIgnore, ...],
    overrides: tuple[PerFileIgnore, ...],
) -> tuple[PerFileIgnore, ...]:
    patterns: list[str] = []
    rules: dict[str, list[str]] = {}
    for item in (*configured, *overrides):
        if item.pattern not in rules:
            patterns.append(item.pattern)
            rules[item.pattern] = []
        for rule_id in item.rule_ids:
            if rule_id not in rules[item.pattern]:
                rules[item.pattern].append(rule_id)
    return tuple(
        PerFileIgnore(pattern=pattern, rule_ids=tuple(rules[pattern]))
        for pattern in patterns
    )


def _parse_policy_value(value: str, source: str) -> PythonMinor:
    try:
        return PythonMinor.parse(value)
    except InvalidPythonMinorError as error:
        message = f"{source}: {error}"
        raise ConfigurationError(message) from error


def _resolve_source_roots(
    root: Path,
    project: ProjectConfiguration,
    overrides: ConfigurationOverrides,
) -> tuple[tuple[str, ...], str, bool]:
    if overrides.source_roots is not None:
        configured = _normalize_source_roots(
            overrides.source_roots,
            "command-line source roots",
        )
        provenance = "command-line"
    else:
        configured = _normalize_source_roots(
            project.source_roots,
            f"{project.label}:tool.pyahead.source-roots",
        )
        provenance = f"{project.label}:tool.pyahead.source-roots"
    if configured is None:
        return (
            _CONVENTIONAL_SOURCE_ROOTS,
            _CONVENTIONAL_SOURCE_ROOTS_PROVENANCE,
            True,
        )
    _validate_source_roots(root, configured)
    return configured, provenance, False


def resolve_configuration(
    root: Path,
    registry: Registry,
    project: ProjectConfiguration,
    overrides: ConfigurationOverrides,
) -> ResolvedConfiguration:
    """Apply CLI/config/default precedence and infer missing policy values."""
    supported_versions = _registry_versions(registry)
    if not supported_versions:
        message = "registry does not declare an analysis window"
        raise ConfigurationError(message)

    requires_python: str | None = None
    if overrides.baseline_python is not None:
        baseline = _parse_policy_value(
            overrides.baseline_python, "command-line baseline Python"
        )
        baseline_source = "command-line"
    elif project.baseline_python is not None:
        baseline = _parse_policy_value(
            project.baseline_python,
            f"{project.label}:tool.pyahead.baseline-python",
        )
        baseline_source = f"{project.label}:tool.pyahead.baseline-python"
    else:
        requires_python = _project_requires_python(root)
        if requires_python is None:
            message = (
                "baseline Python is required; pass --baseline-python, configure "
                "tool.pyahead.baseline-python, or declare project.requires-python"
            )
            raise ConfigurationError(message)
        baseline = infer_baseline(requires_python, supported_versions)
        baseline_source = "pyproject.toml:project.requires-python"

    if overrides.horizon_python is not None:
        horizon = _parse_policy_value(
            overrides.horizon_python, "command-line horizon Python"
        )
        horizon_source = "command-line"
    elif project.horizon_python is not None:
        horizon = _parse_policy_value(
            project.horizon_python,
            f"{project.label}:tool.pyahead.horizon-python",
        )
        horizon_source = f"{project.label}:tool.pyahead.horizon-python"
    else:
        horizon = _default_horizon(registry)
        horizon_source = "registry:newest-active-release"

    policy = Policy(baseline_python=baseline, horizon_python=horizon)
    _validate_policy_window(policy, supported_versions)
    source_roots, source_roots_provenance, source_roots_inferred = (
        _resolve_source_roots(root, project, overrides)
    )
    minimum_confidence = _enum_value(
        overrides.minimum_confidence
        if overrides.minimum_confidence is not None
        else project.minimum_confidence,
        MatchConfidence,
        "minimum-confidence",
        "command-line",
    )
    if minimum_confidence is MatchConfidence.LOW:
        message = "command-line: minimum-confidence supports only high or medium"
        raise ConfigurationError(message)
    fail_on = _enum_value(
        overrides.fail_on if overrides.fail_on is not None else project.fail_on,
        FailOn,
        "fail-on",
        "command-line",
    )
    scan = EffectiveConfiguration(
        include=(
            overrides.include
            if overrides.include is not None
            else project.include or ()
        ),
        exclude=(
            overrides.exclude
            if overrides.exclude is not None
            else project.exclude or ()
        ),
        source_roots=source_roots,
        source_roots_provenance=source_roots_provenance,
        respect_gitignore=(
            overrides.respect_gitignore
            if overrides.respect_gitignore is not None
            else (
                project.respect_gitignore
                if project.respect_gitignore is not None
                else True
            )
        ),
        minimum_confidence=minimum_confidence or MatchConfidence.HIGH,
        fail_on=fail_on or FailOn.BREAKING,
        show_unscheduled=(
            overrides.show_unscheduled
            if overrides.show_unscheduled is not None
            else (
                project.show_unscheduled
                if project.show_unscheduled is not None
                else True
            )
        ),
        max_file_size_bytes=(
            overrides.max_file_size_bytes
            if overrides.max_file_size_bytes is not None
            else project.max_file_size_bytes or _DEFAULT_MAX_FILE_SIZE_BYTES
        ),
        per_file_ignores=_merge_per_file_ignores(
            project.per_file_ignores, overrides.per_file_ignores
        ),
        fail_new_only=overrides.fail_new_only,
        show_suppressed=overrides.show_suppressed,
        allow_incomplete=overrides.allow_incomplete,
    )
    if type(scan.max_file_size_bytes) is not int or scan.max_file_size_bytes <= 0:
        message = "max-file-size-bytes must be a positive integer"
        raise ConfigurationError(message)
    return ResolvedConfiguration(
        policy=policy,
        policy_provenance=PolicyProvenance(
            baseline_python=baseline_source,
            horizon_python=horizon_source,
            requires_python=requires_python,
        ),
        scan=scan,
        source_roots_inferred=source_roots_inferred,
    )


def resolve_project_root(start: Path, explicit_root: Path | None = None) -> Path:
    """Resolve an explicit root or the nearest configured/worktree ancestor."""
    candidate = explicit_root if explicit_root is not None else start
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "project root does not exist or cannot be resolved"
        raise ConfigurationError(message) from error
    if not resolved.is_dir():
        message = "project root must be a directory"
        raise ConfigurationError(message)
    if explicit_root is not None:
        return resolved

    ancestors = (resolved, *resolved.parents)
    for ancestor in ancestors:
        if (ancestor / "pyproject.toml").is_file():
            return ancestor
    for ancestor in ancestors:
        git_control = ancestor / ".git"
        if (
            git_control.is_dir() and (git_control / "HEAD").is_file()
        ) or git_control.is_file():
            return ancestor
    return resolved


__all__ = [
    "ConfigurationOverrides",
    "ProjectConfiguration",
    "ResolvedConfiguration",
    "infer_baseline",
    "load_project_configuration",
    "resolve_configuration",
    "resolve_project_root",
]
