"""Matching environment targets with resolver platforms and tags."""

from __future__ import annotations

import re
from typing import (
    TYPE_CHECKING,
)

from packaging.version import Version

from pyahead.dependencies._model import (
    _LINUX_RESOLVER_PLATFORM,
    _MACOS_RESOLVER_PLATFORMS,
    _MIN_STABLE_ABI_MINOR,
    _WINDOWS_RESOLVER_PLATFORMS,
    _CanonicalResolverTarget,
)

if TYPE_CHECKING:
    from packaging.tags import Tag

    from pyahead.dependencies._model import EnvironmentTarget


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
