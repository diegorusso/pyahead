"""M8 dependency target, metadata, and resolver boundary tests."""

from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
from copy import deepcopy
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest
from jsonschema import Draft202012Validator
from packaging.requirements import Requirement

import pyahead._rooted_reader as rooted_reader_module
import pyahead._windows_output as windows_output_module
import pyahead.dependencies as dependency_module
from pyahead._human_text import escape_terminal_text
from pyahead.config import load_project_configuration
from pyahead.dependencies import (
    ArtifactAvailability,
    DependencyCompatibilityStatus,
    DependencyConfiguration,
    DependencyProjectKind,
    EnvironmentTarget,
    MetadataKind,
    RequiresPythonStatus,
    ResolutionStatus,
    ResolvedPackage,
    ResolverResult,
    UvResolverAdapter,
    assess_dependency_metadata,
    collect_dependency_report,
    inspect_dependency_metadata,
    load_dependency_configuration,
    render_dependency_json,
    render_dependency_text,
)
from pyahead.model import ConfigurationError, ExitCode

if TYPE_CHECKING:
    import threading
    from collections.abc import Sequence
    from types import FrameType

_ARTIFACT_COUNT = 2
_EXPANDED_TAG_COUNT = 300
_RESOLVER_PROCESS_COUNT = 2
_SHA256_HEX_LENGTH = 64
_TIMEOUT_SECONDS = 2.5
_PROCESS_TREE_DETECTION_SECONDS = 1.7
_PROCESS_TREE_BOUND_SECONDS = 3.0
_UNSATISFIABLE_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because you require demo==1.0 and demo==2.0, your requirements "
    "are unsatisfiable.\n"
)
_UV_012_MACOS_UNSATISFIABLE_DIAGNOSTIC = (
    "warning: The requested Python version 3.12.4 is not available; 3.12.10 will "
    "be used to build dependencies instead.\n"
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because you require demo==1.0 and demo==2.0, we can conclude "
    "that your requirements are unsatisfiable.\n"
)
_MISSING_DISTRIBUTION_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because missing was not found in the provided package locations and "
    "you require missing==1.0, we can conclude that your requirements are "
    "unsatisfiable.\n"
)
_MISSING_VERSION_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because there is no version of demo==1.0 and you require demo==1.0, "
    "we can conclude that your requirements are unsatisfiable.\n"
)
_WRONG_ABI_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because demo==1.0 has no wheels with a matching Python ABI tag "
    "(e.g., `cp312`) and you require demo==1.0, we can conclude that your "
    "requirements are unsatisfiable.\n"
    "  hint: You require CPython 3.12 (`cp312`), but we only found wheels for "
    "`demo` (v1.0) with the following Python ABI tag: `cp311`\n"
)
_NO_USABLE_WHEELS_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because demo==1.0 has no usable wheels and you require demo==1.0, "
    "we can conclude that your requirements are unsatisfiable.\n"
    "  hint: Wheels are required for `demo` because building from source is "
    "disabled for all packages (i.e., with `--no-build`)\n"
)
_MISSING_CONFLICT_DISTRIBUTION_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because demo was not found in the provided package locations and you "
    "require demo==1.0 and demo==2.0, your requirements are unsatisfiable.\n"
)


def _os_with_name(name: str) -> SimpleNamespace:
    """Override the dependency module's platform without mutating global ``os``."""
    return SimpleNamespace(**{**vars(os), "name": name})


def _metadata(  # noqa: PLR0913
    *,
    identity: tuple[str, str] = ("demo", "1.0"),
    metadata_version: str = "2.4",
    requires_python: str | None = ">=3.12",
    requires_dist: Sequence[str] = (),
    provides_extra: Sequence[str] = (),
    dynamic: Sequence[str] = (),
) -> bytes:
    name, version = identity
    lines = [
        f"Metadata-Version: {metadata_version}",
        f"Name: {name}",
        f"Version: {version}",
    ]
    if requires_python is not None:
        lines.append(f"Requires-Python: {requires_python}")
    lines.extend(f"Requires-Dist: {item}" for item in requires_dist)
    lines.extend(f"Provides-Extra: {item}" for item in provides_extra)
    lines.extend(f"Dynamic: {item}" for item in dynamic)
    return ("\n".join(lines) + "\n\n").encode()


def _pylock(*packages: tuple[str, str, str]) -> str:
    lines = [
        'lock-version = "1.0"',
        'created-by = "uv"',
        'requires-python = ">=3.12.4"',
    ]
    for name, version, url in packages:
        lines.extend(
            (
                "",
                "[[packages]]",
                f'name = "{name}"',
                f'version = "{version}"',
                f'wheels = [{{ url = "{url}", hashes = {{}} }}]',
            )
        )
    return "\n".join(lines) + "\n"


def _wheel(  # noqa: PLR0913
    path: Path,
    *,
    tag: str = "py3-none-any",
    metadata_version: str = "2.4",
    core_version: str | None = None,
    requires_python: str | None = ">=3.12",
    requires_dist: Sequence[str] = (),
    provides_extra: Sequence[str] = (),
) -> None:
    distribution = path.name.removesuffix(".whl").rsplit("-", maxsplit=3)[0]
    name, version = distribution.rsplit("-", maxsplit=1)
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            _metadata(
                identity=(name, core_version or version),
                metadata_version=metadata_version,
                requires_python=requires_python,
                requires_dist=requires_dist,
                provides_extra=provides_extra,
            ),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: pyahead-test\n"
                "Root-Is-Purelib: true\n"
                f"Tag: {tag}\n"
            ),
        )
        archive.writestr(f"{dist_info}/RECORD", "")


def _sdist(
    path: Path,
    *,
    requires_python: str | None = ">=3.12",
    metadata_version: str = "2.4",
    dynamic: Sequence[str] = (),
) -> None:
    name, version = path.name.removesuffix(".tar.gz").rsplit("-", maxsplit=1)
    payload = _metadata(
        identity=(name, version),
        metadata_version=metadata_version,
        requires_python=requires_python,
        dynamic=dynamic,
    )
    member = tarfile.TarInfo(f"{name}-{version}/PKG-INFO")
    member.size = len(payload)
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(member, io.BytesIO(payload))


def _tar_sdist(
    path: Path,
    members: Sequence[tuple[str, bytes]],
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n".encode()
    size = len(body) + 1
    while True:
        record = str(size).encode() + body
        if len(record) == size:
            return record
        size = len(record)


def _target(
    *,
    name: str = "cp312-linux",
    python: str = "3.12.4",
    sys_platform: str = "linux",
    tags: tuple[str, ...] = ("py3-none-any",),
) -> EnvironmentTarget:
    return EnvironmentTarget(
        name=name,
        python_full_version=python,
        implementation_name="cpython",
        implementation_version=python,
        os_name="nt" if sys_platform == "win32" else "posix",
        sys_platform=sys_platform,
        platform_machine="AMD64" if sys_platform == "win32" else "x86_64",
        platform_python_implementation="CPython",
        platform_system="Windows" if sys_platform == "win32" else "Linux",
        platform_release="",
        platform_version="",
        compatible_tags=tuple(sorted(tags)),
        resolver_platform=(
            "x86_64-pc-windows-msvc"
            if sys_platform == "win32"
            else "x86_64-manylinux_2_17"
        ),
    )


def _configuration(
    *,
    target: EnvironmentTarget | None = None,
    metadata_paths: tuple[Path, ...] = (),
    requirements: tuple[str, ...] = ("demo==1.0",),
    resolve: bool = False,
    network: bool = False,
) -> DependencyConfiguration:
    return DependencyConfiguration(
        project_kind=DependencyProjectKind.APPLICATION,
        requirements=requirements,
        extras=("speed",),
        metadata_paths=metadata_paths,
        targets=(target or _target(),),
        resolve=resolve,
        network=network,
        timeout_seconds=_TIMEOUT_SECONDS,
        resolver="uv",
        index_url="https://packages.example/simple" if network else None,
    )


def _configuration_toml(
    *,
    project_kind: str = "application",
    requirement: str = "demo==1.0",
    metadata: str = "demo-1.0-py3-none-any.whl",
    resolve: bool = False,
    network: bool = False,
) -> str:
    return f"""
[project]
name = "consumer"
version = "0"
requires-python = ">=3.11"

[tool.pyahead]

[tool.pyahead.dependencies]
project-kind = "{project_kind}"
requirements = ["{requirement}"]
extras = ["speed"]
metadata = ["{metadata}"]
resolve = {str(resolve).lower()}
network = {str(network).lower()}
timeout-seconds = 2.5
resolver = "uv"

[[tool.pyahead.dependencies.targets]]
name = "cp312-linux"
python-full-version = "3.12.4"
implementation-name = "cpython"
implementation-version = "3.12.4"
os-name = "posix"
sys-platform = "linux"
platform-machine = "x86_64"
platform-python-implementation = "CPython"
platform-system = "Linux"
compatible-tags = ["py3-none-any"]
resolver-platform = "x86_64-manylinux_2_17"
"""


def test_direct_inspection_never_runs_a_backend_and_records_exact_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wheel metadata is read directly even if every subprocess would fail."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(
        wheel,
        requires_dist=(
            'linux-only>=2; sys_platform == "linux"',
            'accelerator==3; extra == "speed"',
        ),
    )

    def forbidden_process(*_args: object, **_kwargs: object) -> None:
        message = "metadata inspection must not launch a process"
        raise AssertionError(message)

    monkeypatch.setattr(subprocess, "run", forbidden_process)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert issues == ()
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.kind is MetadataKind.WHEEL
    assert artifact.name == "demo"
    assert artifact.version == "1.0"
    assert artifact.metadata_version == "2.4"
    assert artifact.requires_python == ">=3.12"
    assert artifact.metadata_path == "demo-1.0.dist-info/METADATA"
    assert artifact.artifact_id == artifact.sha256
    assert len(artifact.sha256) == _SHA256_HEX_LENGTH

    assessment = assess_dependency_metadata(
        artifacts,
        target=_target(),
        extras=("speed",),
    )[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.requires_python_status is RequiresPythonStatus.COMPATIBLE
    assert assessment.artifact_availability is ArtifactAvailability.AVAILABLE
    assert assessment.applicable_requirements == (
        'accelerator==3; extra == "speed"',
        'linux-only>=2; sys_platform == "linux"',
    )
    assert assessment.metadata_used == (artifact.artifact_id,)


@pytest.mark.parametrize(
    "direct_url",
    [
        "file:///outside-policy/other-2.0-py3-none-any.whl",
        "https://unconfigured.example/other-2.0-py3-none-any.whl",
    ],
)
def test_direct_requires_dist_urls_stop_before_resolver_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direct_url: str,
) -> None:
    """Metadata direct URLs cannot escape the declared artifact/index policy."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=(f"other @ {direct_url}",))

    def forbidden_process(*_args: object, **_kwargs: object) -> None:
        message = "unsafe dependency metadata must stop before resolver execution"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.shutil, "which", forbidden_process)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", forbidden_process)
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,), resolve=True, network=True),
        root=tmp_path,
    )

    assert report.metadata == ()
    assert "direct URL Requires-Dist" in report.metadata_issues[0].message
    assert report.targets[0].resolution.status is ResolutionStatus.UNVERIFIED
    assert "not executed" in report.targets[0].resolution.reason
    assert report.exit_code is ExitCode.INCOMPLETE


def test_requires_python_markers_and_artifacts_use_only_the_declared_target(
    tmp_path: Path,
) -> None:
    """Host Python/platform values cannot affect target marker evaluation."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(
        wheel,
        requires_dist=('windows-only==4; sys_platform == "win32"',),
    )
    target = _target(
        name="cp311-windows",
        python="3.11.9",
        sys_platform="win32",
    )
    report = collect_dependency_report(
        _configuration(target=target, metadata_paths=(wheel,)),
        root=tmp_path,
    )
    assessment = report.targets[0].assessments[0]

    assert assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
    assert assessment.requires_python_status is RequiresPythonStatus.INCOMPATIBLE
    assert assessment.applicable_requirements == (
        'windows-only==4; sys_platform == "win32"',
    )
    assert report.exit_code is ExitCode.INCOMPLETE


def test_target_specific_wheel_metadata_excludes_other_platform_semantics(
    tmp_path: Path,
) -> None:
    """Wrong-platform wheel metadata cannot contradict the target candidate."""
    linux = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    windows = tmp_path / "demo-1.0-cp312-cp312-win_amd64.whl"
    _wheel(
        linux,
        tag="cp312-cp312-manylinux_2_17_x86_64",
        requires_python=">=3.12",
        requires_dist=("linux-dependency==1",),
    )
    _wheel(
        windows,
        tag="cp312-cp312-win_amd64",
        requires_python=">=9",
        requires_dist=("windows-dependency==1",),
    )
    artifacts, issues = inspect_dependency_metadata((linux, windows), root=tmp_path)
    assessment = assess_dependency_metadata(
        artifacts,
        target=_target(tags=("cp312-cp312-manylinux_2_17_x86_64",)),
        extras=(),
    )[0]

    assert issues == ()
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.requires_python_status is RequiresPythonStatus.COMPATIBLE
    assert assessment.applicable_requirements == ("linux-dependency==1",)


def test_missing_wheel_is_distinct_from_source_build_possibility(
    tmp_path: Path,
) -> None:
    """An sdist does not turn missing target wheels into compatible evidence."""
    wheel = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    _wheel(wheel, tag="cp312-cp312-manylinux_2_17_x86_64")
    _sdist(sdist)
    artifacts, issues = inspect_dependency_metadata((wheel, sdist), root=tmp_path)
    assessment = assess_dependency_metadata(
        artifacts,
        target=_target(
            name="cp313-linux",
            python="3.13.1",
            tags=("cp313-cp313-manylinux_2_17_x86_64",),
        ),
        extras=(),
    )[0]

    assert issues == ()
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.artifact_availability is (
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    )
    assert assessment.source_build_possible is True
    assert assessment.metadata_used == (
        next(item.artifact_id for item in artifacts if item.kind is MetadataKind.SDIST),
    )


def test_available_wheel_preserves_supplied_source_fallback(tmp_path: Path) -> None:
    """Wheel availability and the presence of a source fallback are independent."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    _wheel(wheel)
    _sdist(sdist)
    artifacts, issues = inspect_dependency_metadata((wheel, sdist), root=tmp_path)

    assessment = assess_dependency_metadata(
        artifacts,
        target=_target(),
        extras=(),
    )[0]

    assert issues == ()
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.artifact_availability is ArtifactAvailability.AVAILABLE
    assert assessment.source_build_possible is True


def test_malformed_metadata_is_visible_incomplete_evidence(tmp_path: Path) -> None:
    """Unreadable core metadata is retained instead of becoming compatibility."""
    invalid = tmp_path / "invalid.metadata"
    invalid.write_bytes(b"Metadata-Version: 2.4\nName: demo\n\n")

    report = collect_dependency_report(
        _configuration(metadata_paths=(invalid,)),
        root=tmp_path,
    )

    assert report.metadata == ()
    assert report.metadata_issues[0].path.as_posix() == "invalid.metadata"
    assert "omits Version" in report.metadata_issues[0].message
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            (
                b"Metadata-Version: garbage\nName: demo\nVersion: 1.0\n"
                b"Requires-Python: >=9\n\n"
            ),
            "invalid or unsupported Metadata-Version",
        ),
        (
            (
                b"Metadata-Version: 99.0\nName: demo\nVersion: 1.0\n"
                b"Requires-Python: >=9\n\n"
            ),
            "invalid or unsupported Metadata-Version",
        ),
        (
            (
                b"Metadata-Version: 1.1\nName: demo\nVersion: 1.0\n"
                b"Requires-Python: >=3.12\n\n"
            ),
            "field is unavailable in the declared Metadata-Version",
        ),
    ],
)
def test_core_metadata_schema_failures_are_incomplete_evidence(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    """Unsupported schemas cannot drive definitive compatibility evidence."""
    path = tmp_path / "demo.metadata"
    path.write_bytes(payload)
    configuration = replace(
        _configuration(metadata_paths=(path,)),
        requirements=(),
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assert report.metadata == ()
    assert report.metadata_issues[0].path == PurePosixPath("demo.metadata")
    assert message in report.metadata_issues[0].message
    assert report.targets[0].assessments == ()
    assert report.exit_code is ExitCode.INCOMPLETE


def test_configuration_separates_application_and_library_semantics(
    tmp_path: Path,
) -> None:
    """Applications require exact pins while libraries retain version ranges."""
    path = tmp_path / "pyproject.toml"
    path.write_text(_configuration_toml(requirement="demo>=1"), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="exact == version pin"):
        load_dependency_configuration(tmp_path)

    path.write_text(
        _configuration_toml(project_kind="library", requirement="demo>=1"),
        encoding="utf-8",
    )
    configuration = load_dependency_configuration(tmp_path)
    assert configuration.project_kind is DependencyProjectKind.LIBRARY
    assert configuration.requirements == ("demo>=1",)
    assert configuration.network is False
    assert configuration.resolve is False
    assert configuration.timeout_seconds == _TIMEOUT_SECONDS

    static_configuration = load_project_configuration(tmp_path, None)
    assert static_configuration.baseline_python is None


@pytest.mark.parametrize(
    ("project_kind", "requirement", "artifact_name"),
    [
        (DependencyProjectKind.APPLICATION, "demo==1.0", "other-1.0"),
        (DependencyProjectKind.APPLICATION, "demo==1.0", "demo-2.0"),
        (DependencyProjectKind.LIBRARY, "demo>=1,<2", "demo-2.0"),
    ],
)
def test_active_requirements_require_matching_names_and_versions(
    tmp_path: Path,
    project_kind: DependencyProjectKind,
    requirement: str,
    artifact_name: str,
) -> None:
    """Missing names and versions outside configured semantics are incomplete."""
    wheel = tmp_path / f"{artifact_name}-py3-none-any.whl"
    _wheel(wheel)
    configuration = replace(
        _configuration(metadata_paths=(wheel,)),
        project_kind=project_kind,
        requirements=(requirement,),
    )

    report = collect_dependency_report(configuration, root=tmp_path)
    declared = report.targets[0].declared_requirements[0]

    assert declared.applies is True
    assert declared.verified is False
    assert declared.matching_metadata == ()
    assert report.targets[0].assessments == ()
    assert report.exit_code is ExitCode.INCOMPLETE


def test_unrelated_extra_metadata_does_not_create_dependency_evidence(
    tmp_path: Path,
) -> None:
    """Only metadata joined to an active declared requirement is assessed."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    other = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(demo)
    _wheel(other)

    report = collect_dependency_report(
        _configuration(metadata_paths=(other, demo)), root=tmp_path
    )

    assert len(report.metadata) == _ARTIFACT_COUNT
    assert tuple(item.package for item in report.targets[0].assessments) == ("demo",)
    assert report.targets[0].declared_requirements[0].verified is True
    assert report.targets[0].assessments[0].status is (
        DependencyCompatibilityStatus.UNVERIFIED
    )
    assert report.exit_code is ExitCode.INCOMPLETE


def test_plain_application_pin_with_local_variants_is_not_a_false_finding(
    tmp_path: Path,
) -> None:
    """A public-version pin cannot choose among matching local versions alone."""
    public = tmp_path / "demo-1.0-py3-none-any.whl"
    local = tmp_path / "demo-1.0+cpu-py3-none-any.whl"
    _wheel(public, requires_python=">=9")
    _wheel(local, requires_python=">=3.12")
    configuration = _configuration(
        metadata_paths=(public, local),
        requirements=("demo==1.0",),
    )

    ambiguous = collect_dependency_report(configuration, root=tmp_path)
    target = ambiguous.targets[0]

    assert {item.version for item in target.assessments} == {"1.0", "1.0+cpu"}
    assert all(
        item.status is DependencyCompatibilityStatus.UNVERIFIED
        for item in target.assessments
    )
    assert target.declared_requirements[0].verified is False
    assert (
        "multiple supplied package versions" in target.declared_requirements[0].reason
    )
    assert ambiguous.exit_code is ExitCode.INCOMPLETE

    selected = collect_dependency_report(
        replace(configuration, requirements=("demo==1.0+cpu",)),
        root=tmp_path,
    )
    assert tuple(item.version for item in selected.targets[0].assessments) == (
        "1.0+cpu",
    )
    assert selected.targets[0].declared_requirements[0].verified is True
    assert selected.exit_code is ExitCode.INCOMPLETE


def test_pep440_equivalent_version_spellings_are_one_direct_candidate(
    tmp_path: Path,
) -> None:
    """Release spelling differences do not manufacture version ambiguity."""
    portable = tmp_path / "demo-1.0-py3-none-any.whl"
    specific = tmp_path / "demo-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    _wheel(portable)
    _wheel(specific, tag="cp312-cp312-manylinux_2_17_x86_64")
    target = _target(tags=("py3-none-any", "cp312-cp312-manylinux_2_17_x86_64"))

    report = collect_dependency_report(
        _configuration(
            target=target,
            metadata_paths=(portable, specific),
            requirements=("demo==1.0",),
        ),
        root=tmp_path,
    )

    assert len(report.targets[0].assessments) == 1
    assert report.targets[0].declared_requirements[0].verified is True
    assert report.exit_code is ExitCode.INCOMPLETE


def test_simultaneous_application_pins_use_their_constraint_intersection(
    tmp_path: Path,
) -> None:
    """A candidate must satisfy every active same-name application constraint."""
    public = tmp_path / "demo-1.0-py3-none-any.whl"
    local = tmp_path / "demo-1.0+cpu-py3-none-any.whl"
    _wheel(public, requires_python=">=9")
    _wheel(local, requires_python=">=3.12")

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(public, local),
            requirements=("demo==1.0", "demo==1.0+cpu"),
        ),
        root=tmp_path,
    )

    assert tuple(item.version for item in report.targets[0].assessments) == ("1.0+cpu",)
    assert all(item.verified for item in report.targets[0].declared_requirements)
    assert report.exit_code is ExitCode.INCOMPLETE


def test_transitive_application_lock_with_local_variants_is_unverified(
    tmp_path: Path,
) -> None:
    """A plain lock pin cannot prove one transitive version when locals coexist."""
    root_wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    public = tmp_path / "child-1.0-py3-none-any.whl"
    local = tmp_path / "child-1.0+cpu-py3-none-any.whl"
    _wheel(root_wheel, requires_dist=("child>=1",))
    _wheel(public)
    _wheel(local)

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(root_wheel, public, local),
            requirements=("demo==1.0", "child==1.0"),
        ),
        root=tmp_path,
    )

    transitive = report.targets[0].transitive_requirements[0]
    assert transitive.requirement == "child>=1"
    assert set(transitive.matching_metadata) == {
        artifact.artifact_id
        for artifact in report.metadata
        if artifact.canonical_name == "child"
    }
    assert transitive.verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_transitive_provenance_accepts_pep440_equivalent_version_spelling(
    tmp_path: Path,
) -> None:
    """A resolver's 1.0 selection binds metadata whose canonical text is 1.0.0."""
    root_wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    child_wheel = tmp_path / "child-1.0-py3-none-any.whl"
    _wheel(root_wheel, requires_dist=("child>=1",))
    _wheel(child_wheel, core_version="1.0.0")
    artifacts, issues = inspect_dependency_metadata(
        (root_wheel, child_wheel),
        root=tmp_path,
    )
    assert issues == ()
    by_name = {artifact.canonical_name: artifact for artifact in artifacts}

    class EquivalentVersionResolver:
        name = "equivalent-version-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            supplied: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, supplied, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(
                    ResolvedPackage(
                        name=name,
                        version="1.0",
                        metadata_used=(artifact.artifact_id,),
                    )
                    for name, artifact in sorted(by_name.items())
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(root_wheel, child_wheel),
            requirements=("demo==1.0", "child==1.0"),
            resolve=True,
        ),
        root=tmp_path,
        resolver=EquivalentVersionResolver(),
    )

    assert report.targets[0].resolution.status is ResolutionStatus.SUCCEEDED
    assert report.targets[0].transitive_requirements[0].verified is True
    assert report.exit_code is ExitCode.SUCCESS


def test_equivalent_application_locks_emit_schema_valid_transitive_evidence(
    tmp_path: Path,
) -> None:
    """Equivalent lock spellings remain distinct evidence rows in schema v1."""
    root_wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    child_wheel = tmp_path / "child-1.0-py3-none-any.whl"
    _wheel(root_wheel, requires_dist=("child>=1",))
    _wheel(child_wheel)

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(root_wheel, child_wheel),
            requirements=("demo==1.0", "child==1", "child==1.0"),
        ),
        root=tmp_path,
    )

    transitive = report.targets[0].transitive_requirements[0]
    assert transitive.locked_versions == ("child==1", "child==1.0")
    assert transitive.verified is True
    schema_path = Path(__file__).parents[2] / "docs/schema/dependency-report-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        dependency_module.dependency_report_document(report)
    )


def test_requirement_extras_are_correlated_with_declared_metadata(
    tmp_path: Path,
) -> None:
    """A requested package extra must be named by the inspected metadata."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    configuration = replace(
        _configuration(metadata_paths=(wheel,)),
        requirements=("demo[speed]==1.0",),
    )
    missing = collect_dependency_report(configuration, root=tmp_path)
    assert missing.targets[0].declared_requirements[0].verified is False
    assert missing.exit_code is ExitCode.INCOMPLETE

    _wheel(wheel, provides_extra=("speed",))
    matching = collect_dependency_report(configuration, root=tmp_path)
    assert matching.metadata[0].provides_extra == ("speed",)
    assert matching.targets[0].declared_requirements[0].verified is True
    assert matching.exit_code is ExitCode.INCOMPLETE


def test_complete_resolver_evidence_cannot_borrow_unknown_metadata(
    tmp_path: Path,
) -> None:
    """A resolver selection must name exact directly inspected metadata."""
    other = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(other)

    class CompleteResolver:
        name = "complete-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        name="demo",
                        version="1.0",
                        metadata_used=("resolver-selected-metadata",),
                    ),
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(metadata_paths=(other,), resolve=True),
        root=tmp_path,
        resolver=CompleteResolver(),
    )
    declared = report.targets[0].declared_requirements[0]

    assert declared.verified is False
    assert declared.resolved_versions == ()
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize("orphan_dependencies", [(), ("missing==1.0",)])
def test_complete_resolver_rejects_packages_outside_the_reachable_closure(
    tmp_path: Path,
    orphan_dependencies: tuple[str, ...],
) -> None:
    """Exact SHA provenance does not make an unrelated resolver package reachable."""
    root_wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    orphan_wheel = tmp_path / "orphan-1.0-py3-none-any.whl"
    _wheel(root_wheel)
    _wheel(orphan_wheel, requires_dist=orphan_dependencies)
    artifacts, issues = inspect_dependency_metadata(
        (root_wheel, orphan_wheel),
        root=tmp_path,
    )
    assert issues == ()
    by_name = {artifact.canonical_name: artifact for artifact in artifacts}

    class OrphanResolver:
        name = "orphan-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            supplied: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, supplied, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(
                    ResolvedPackage(
                        name=name,
                        version=artifact.version,
                        metadata_used=(artifact.artifact_id,),
                    )
                    for name, artifact in sorted(by_name.items())
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(root_wheel, orphan_wheel),
            resolve=True,
        ),
        root=tmp_path,
        resolver=OrphanResolver(),
    )

    resolution = report.targets[0].resolution
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert "outside the exact active dependency closure" in resolution.reason
    assert tuple(item.package for item in report.targets[0].assessments) == ("demo",)
    assert report.targets[0].assessments[0].status is (
        DependencyCompatibilityStatus.UNVERIFIED
    )
    schema_path = Path(__file__).parents[2] / "docs/schema/dependency-report-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        dependency_module.dependency_report_document(report)
    )
    assert report.exit_code is ExitCode.INCOMPLETE


def test_library_transitives_require_complete_resolver_evidence(
    tmp_path: Path,
) -> None:
    """A library artifact set is not a universal transitive solve by itself."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    other = tmp_path / "other-2.0-py3-none-any.whl"
    _wheel(demo, requires_dist=("other>=2",))
    _wheel(other)
    configuration = replace(
        _configuration(metadata_paths=(demo, other)),
        project_kind=DependencyProjectKind.LIBRARY,
        requirements=("demo>=1",),
    )

    direct = collect_dependency_report(configuration, root=tmp_path)
    transitive = direct.targets[0].transitive_requirements[0]
    assert transitive.matching_metadata
    assert transitive.verified is False
    assert "requires complete resolver evidence" in transitive.reason
    assert direct.exit_code is ExitCode.INCOMPLETE

    class CompleteLibraryResolver:
        name = "complete-library-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(
                    ResolvedPackage(
                        name=item.name,
                        version=item.version,
                        metadata_used=(item.artifact_id,),
                    )
                    for item in artifacts
                ),
                reason="resolution completed",
            )

    resolved = collect_dependency_report(
        replace(configuration, resolve=True),
        root=tmp_path,
        resolver=CompleteLibraryResolver(),
    )
    transitive = resolved.targets[0].transitive_requirements[0]
    assert transitive.resolved_versions == ("other==2.0",)
    assert transitive.verified is True
    assert resolved.exit_code is ExitCode.SUCCESS


def test_nested_dependency_extras_reach_a_fixed_point(
    tmp_path: Path,
) -> None:
    """A transitive requested extra cannot hide its own missing dependency."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    other = tmp_path / "other-2.0-py3-none-any.whl"
    child = tmp_path / "child-3.0-py3-none-any.whl"
    _wheel(demo, requires_dist=("other[feature]==2.0",))
    _wheel(
        other,
        requires_dist=('child==3.0; extra == "feature"',),
        provides_extra=("feature",),
    )
    configuration = replace(
        _configuration(metadata_paths=(demo, other)),
        requirements=("demo==1.0", "other==2.0"),
    )

    missing = collect_dependency_report(configuration, root=tmp_path)
    missing_transitives = {
        item.requirement: item for item in missing.targets[0].transitive_requirements
    }

    assert set(missing_transitives) == {
        'child==3.0; extra == "feature"',
        "other[feature]==2.0",
    }
    assert missing_transitives['child==3.0; extra == "feature"'].verified is False
    assert missing_transitives['child==3.0; extra == "feature"'].required_by == (
        "other==2.0",
    )
    assert missing.exit_code is ExitCode.INCOMPLETE

    _wheel(child)
    complete = collect_dependency_report(
        replace(
            configuration,
            metadata_paths=(demo, other, child),
            requirements=("demo==1.0", "other==2.0", "child==3.0"),
        ),
        root=tmp_path,
    )

    assert all(item.verified for item in complete.targets[0].transitive_requirements)
    assert complete.exit_code is ExitCode.INCOMPLETE


def test_nested_dependency_extras_reassess_earlier_packages(
    tmp_path: Path,
) -> None:
    """Extra propagation continues when a later edge activates an earlier group."""
    alpha = tmp_path / "alpha-1.0-py3-none-any.whl"
    root = tmp_path / "root-1.0-py3-none-any.whl"
    zeta = tmp_path / "zeta-1.0-py3-none-any.whl"
    _wheel(
        alpha,
        requires_dist=('leaf==4.0; extra == "deep"',),
        provides_extra=("deep",),
    )
    _wheel(root, requires_dist=("zeta[feature]==1.0",))
    _wheel(
        zeta,
        requires_dist=('alpha[deep]==1.0; extra == "feature"',),
        provides_extra=("feature",),
    )
    report = collect_dependency_report(
        replace(
            _configuration(metadata_paths=(alpha, root, zeta)),
            requirements=("alpha==1.0", "root==1.0", "zeta==1.0"),
        ),
        root=tmp_path,
    )

    transitive = {
        item.requirement: item for item in report.targets[0].transitive_requirements
    }
    assert 'leaf==4.0; extra == "deep"' in transitive
    assert transitive['leaf==4.0; extra == "deep"'].verified is False
    assert transitive['leaf==4.0; extra == "deep"'].required_by == ("alpha==1.0",)
    assert report.exit_code is ExitCode.INCOMPLETE


def test_root_project_extras_do_not_activate_dependency_extras(
    tmp_path: Path,
) -> None:
    """Root marker context does not request a same-named dependency extra."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(demo, requires_dist=('child==2.0; extra == "speed"',))

    base = collect_dependency_report(
        _configuration(metadata_paths=(demo,)),
        root=tmp_path,
    )

    assert base.targets[0].assessments[0].applicable_requirements == ()
    assert base.targets[0].transitive_requirements == ()
    assert base.exit_code is ExitCode.INCOMPLETE

    _wheel(
        demo,
        requires_dist=('child==2.0; extra == "speed"',),
        provides_extra=("speed",),
    )
    requested = collect_dependency_report(
        replace(
            _configuration(metadata_paths=(demo,)),
            requirements=("demo[speed]==1.0",),
        ),
        root=tmp_path,
    )

    assert tuple(
        item.requirement for item in requested.targets[0].transitive_requirements
    ) == ('child==2.0; extra == "speed"',)
    assert requested.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    ("project_kind", "root_requirement"),
    [
        (DependencyProjectKind.APPLICATION, "demo==1.0"),
        (DependencyProjectKind.LIBRARY, "demo>=1"),
    ],
)
def test_resolution_assesses_selected_transitive_closure(
    tmp_path: Path,
    project_kind: DependencyProjectKind,
    root_requirement: str,
) -> None:
    """Exact resolver metadata is followed through nested selected dependencies."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    other = tmp_path / "other-2.0-py3-none-any.whl"
    child = tmp_path / "child-3.0-py3-none-any.whl"
    _wheel(demo, requires_dist=("other[feature]==2.0",))
    _wheel(
        other,
        requires_dist=('child==3.0; extra == "feature"',),
        provides_extra=("feature",),
    )

    class SelectedResolver:
        name = "selected-closure-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(
                    ResolvedPackage(
                        name=item.name,
                        version=item.version,
                        metadata_used=(item.artifact_id,),
                    )
                    for item in artifacts
                ),
                reason="resolution completed",
            )

    configuration = replace(
        _configuration(
            metadata_paths=(demo, other),
            requirements=(root_requirement,),
            resolve=True,
        ),
        project_kind=project_kind,
    )
    missing = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=SelectedResolver(),
    )

    assert tuple(item.package for item in missing.targets[0].assessments) == (
        "demo",
        "other",
    )
    assert {
        item.requirement for item in missing.targets[0].transitive_requirements
    } == {'child==3.0; extra == "feature"', "other[feature]==2.0"}
    assert missing.exit_code is ExitCode.INCOMPLETE
    assert missing.targets[0].resolution.status is ResolutionStatus.UNVERIFIED
    assert missing.targets[0].resolution.complete is False

    _wheel(child)
    complete = collect_dependency_report(
        replace(configuration, metadata_paths=(demo, other, child)),
        root=tmp_path,
        resolver=SelectedResolver(),
    )

    assert tuple(item.package for item in complete.targets[0].assessments) == (
        "child",
        "demo",
        "other",
    )
    assert all(item.verified for item in complete.targets[0].transitive_requirements)
    assert complete.exit_code is ExitCode.SUCCESS


@pytest.mark.parametrize(
    ("addition", "match"),
    [
        (
            'index-url = "https://packages.example/simple?token=secret"\n',
            "query",
        ),
        ("unknown = true\n", "unknown.*dependencies"),
    ],
)
def test_configuration_fails_closed_for_network_and_unknown_keys(
    tmp_path: Path,
    addition: str,
    match: str,
) -> None:
    """Repository configuration cannot silently enable ambient behavior."""
    document = _configuration_toml().replace(
        'resolver = "uv"\n', f'resolver = "uv"\n{addition}'
    )
    (tmp_path / "pyproject.toml").write_text(document, encoding="utf-8")
    with pytest.raises(ConfigurationError, match=match):
        load_dependency_configuration(tmp_path)


@pytest.mark.parametrize(
    "index_url",
    [
        "http://[",
        "http://example.com:invalid/simple",
        "http://example.com:0/simple",
        "http://example.com:/simple",
        "http://example.com\uff0fvalue/simple",
    ],
)
def test_configuration_rejects_malformed_index_urls(
    tmp_path: Path,
    index_url: str,
) -> None:
    """URL parser edge cases remain configuration errors, not internal errors."""
    project = tmp_path / "pyproject.toml"
    document = _configuration_toml(network=True).replace(
        'resolver = "uv"\n',
        f'resolver = "uv"\nindex-url = "{index_url}"\n',
    )
    project.write_text(document, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="index-url"):
        load_dependency_configuration(tmp_path)


def test_resolver_timeout_is_incomplete_not_resolution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deadline produces explicit incomplete evidence and no incompatibility."""
    calls = 0

    def fake_run(*args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(args[0], 0, "uv 0.11.21\n", "")
        raise subprocess.TimeoutExpired(cast("list[str]", args[0]), timeout=2.5)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.TIMED_OUT
    assert result.complete is False
    assert result.resolver_version == "0.11.21"
    assert "remains unverified" in result.reason


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is unavailable")
def test_real_offline_adapter_accepts_an_empty_active_solution(tmp_path: Path) -> None:
    """Uv omits the packages table when every declared marker is inactive."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    configuration = _configuration(
        metadata_paths=(wheel,),
        requirements=('demo==1.0; python_version < "3"',),
        resolve=True,
    )

    result = UvResolverAdapter().resolve(
        configuration,
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.SUCCEEDED
    assert result.complete is True
    assert result.packages == ()


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is unavailable")
def test_real_offline_adapter_binds_pep440_equivalent_version_spellings(
    tmp_path: Path,
) -> None:
    """Uv's 1.0 selection retains provenance for equivalent metadata 1.0.0."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, core_version="1.0.0")
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    assert artifacts[0].version == "1.0.0"
    configuration = _configuration(
        metadata_paths=(wheel,),
        requirements=("demo==1.0",),
        resolve=True,
    )

    result = UvResolverAdapter().resolve(
        configuration,
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.SUCCEEDED
    assert result.packages[0].version == "1.0"
    assert result.packages[0].metadata_used == (artifacts[0].artifact_id,)


def test_timeout_remains_incomplete_in_the_aggregate_report(tmp_path: Path) -> None:
    """Report and CLI exit semantics cannot reinterpret a timeout as failure."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)

    class TimeoutResolver:
        name = "test-timeout"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.TIMED_OUT,
                complete=False,
                resolver=self.name,
                resolver_version="1.0",
                packages=(),
                reason="deadline expired",
            )

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,), resolve=True),
        root=tmp_path,
        resolver=TimeoutResolver(),
    )

    assert report.targets[0].assessments[0].status is (
        DependencyCompatibilityStatus.UNVERIFIED
    )
    assert report.targets[0].resolution.status is ResolutionStatus.TIMED_OUT
    assert report.exit_code is ExitCode.INCOMPLETE


def test_any_incomplete_target_takes_precedence_over_complete_findings(
    tmp_path: Path,
) -> None:
    """A finding on one target cannot hide incomplete evidence on another."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_python=">=3.13")
    first = _target(name="first")
    second = _target(name="second", python="3.13.1")

    class MixedResolver:
        name = "mixed-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, artifacts, root
            del target
            return ResolverResult(
                status=ResolutionStatus.TIMED_OUT,
                complete=False,
                resolver=self.name,
                resolver_version="1.0",
                packages=(),
                reason="target-specific evidence",
            )

    configuration = replace(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        targets=(first, second),
    )
    report = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=MixedResolver(),
    )

    assert report.targets[0].assessments[0].status is (
        DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
    )
    assert report.targets[1].resolution.status is ResolutionStatus.TIMED_OUT
    assert report.targets[1].assessments[0].status is (
        DependencyCompatibilityStatus.UNVERIFIED
    )
    assert report.exit_code is ExitCode.INCOMPLETE


def test_resolver_success_can_have_an_empty_inactive_marker_graph(
    tmp_path: Path,
) -> None:
    """A complete solve needs no package when every target marker is false."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)

    class EmptyResolver:
        name = "empty-test"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(),
                reason="empty target graph resolved",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(wheel,),
            requirements=('demo==1.0; python_version < "3"',),
            resolve=True,
        ),
        root=tmp_path,
        resolver=EmptyResolver(),
    )

    target = report.targets[0]
    assert target.declared_requirements[0].applies is False
    assert target.resolution.status is ResolutionStatus.SUCCEEDED
    assert target.resolution.complete is True
    assert target.resolution.packages == ()
    assert report.exit_code is ExitCode.SUCCESS


@pytest.mark.parametrize(
    "result",
    [
        ResolverResult(
            status=ResolutionStatus.NOT_REQUESTED,
            complete=True,
            resolver="uv",
            resolver_version=None,
            packages=(),
            reason="resolver was not requested",
        ),
        ResolverResult(
            status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
            complete=False,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="incomplete absence claim",
        ),
        ResolverResult(
            status=ResolutionStatus.SUCCEEDED,
            complete=False,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="incomplete success claim",
        ),
        ResolverResult(
            status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
            complete=True,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="uncorroborated absence claim",
        ),
        ResolverResult(
            status=ResolutionStatus.RESOLUTION_FAILED,
            complete=True,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="uncorroborated conflict claim",
        ),
        ResolverResult(
            status=ResolutionStatus.TIMED_OUT,
            complete=True,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="complete timeout claim",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=True,
            resolver="uv",
            resolver_version="1.0",
            packages=(),
            reason="complete unverified claim",
        ),
        ResolverResult(
            status=ResolutionStatus.SUCCEEDED,
            complete=True,
            resolver="uv",
            resolver_version=None,
            packages=(),
            reason="versionless success claim",
        ),
        ResolverResult(
            status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
            complete=True,
            resolver="uv",
            resolver_version="1.0",
            packages=(ResolvedPackage("demo", "1.0", ("a" * 64,)),),
            reason="negative result with packages",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="unexpected",
            resolver_version="1.0",
            packages=(),
            reason="wrong adapter identity",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="uv",
            resolver_version="banana",
            packages=(),
            reason="malformed version",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="uv",
            resolver_version="1.0",
            packages=(ResolvedPackage("demo", "1.0", ("bogus",)),),
            reason="malformed package evidence",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="uv",
            resolver_version="1.0",
            packages=(
                ResolvedPackage("Demo", "01.0", ()),
                ResolvedPackage("demo", "1.0", ()),
            ),
            reason="duplicate package identity",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="uv",
            resolver_version="1.0",
            packages=(ResolvedPackage("demo", "1.0", ("a" * 64,)),),
            reason="unbound package provenance",
        ),
        ResolverResult(
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            resolver="uv",
            resolver_version=None,
            packages=(ResolvedPackage("demo", "1.0", ()),),
            reason="versionless partial package evidence",
        ),
    ],
)
def test_contradictory_resolver_result_shapes_are_incomplete(
    tmp_path: Path,
    result: ResolverResult,
) -> None:
    """Replaceable adapters cannot manufacture complete evidence by contradiction."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)

    class ContradictoryResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return result

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,), resolve=True),
        root=tmp_path,
        resolver=ContradictoryResolver(),
    )

    assert report.targets[0].resolution.status is ResolutionStatus.UNVERIFIED
    assert report.targets[0].resolution.complete is False
    assert "structured evidence" in report.targets[0].resolution.reason
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    ("filename", "tag", "requires_python"),
    [
        (
            "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            "cp311-cp311-manylinux_2_17_x86_64",
            ">=3.11",
        ),
        ("demo-1.0-py3-none-any.whl", "py3-none-any", ">=9"),
    ],
)
def test_resolver_success_requires_target_compatible_provenance(
    tmp_path: Path,
    filename: str,
    tag: str,
    requires_python: str,
) -> None:
    """A resolver cannot call wrong-target selected artifacts complete evidence."""
    wheel = tmp_path / filename
    _wheel(wheel, tag=tag, requires_python=requires_python)

    class WrongTargetResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, root
            artifact = artifacts[0]
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        artifact.canonical_name,
                        artifact.version,
                        (artifact.artifact_id,),
                    ),
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,), resolve=True),
        root=tmp_path,
        resolver=WrongTargetResolver(),
    )

    resolution = report.targets[0].resolution
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert "provenance-bound" in resolution.reason
    assert report.exit_code is ExitCode.INCOMPLETE


def test_resolver_success_requires_one_exact_artifact_per_package(
    tmp_path: Path,
) -> None:
    """Multiple candidate wheels cannot masquerade as one selected artifact."""
    universal = tmp_path / "demo-1.0-py3-none-any.whl"
    platform = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    _wheel(universal)
    platform_tag = "cp312-cp312-manylinux_2_17_x86_64"
    _wheel(platform, tag=platform_tag)

    class MultipleSelectionResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        "demo",
                        "1.0",
                        tuple(artifact.artifact_id for artifact in artifacts),
                    ),
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(
            target=_target(tags=("py3-none-any", platform_tag)),
            metadata_paths=(universal, platform),
            resolve=True,
        ),
        root=tmp_path,
        resolver=MultipleSelectionResolver(),
    )

    assert report.targets[0].resolution.status is ResolutionStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_report_does_not_call_a_replaceable_resolver_when_disabled(
    tmp_path: Path,
) -> None:
    """The collector, not an adapter, owns the no-resolution trust boundary."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)

    class ForbiddenResolver:
        name = "uv"

        def resolve(self, *_args: object, **_kwargs: object) -> ResolverResult:
            message = "disabled resolver must not be called"
            raise AssertionError(message)

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
        resolver=ForbiddenResolver(),
    )

    assert report.targets[0].resolution.status is ResolutionStatus.NOT_REQUESTED
    assert report.targets[0].resolution.complete is True


def test_replaceable_resolver_order_is_canonicalized(tmp_path: Path) -> None:
    """Equivalent adapter ordering produces byte-identical public JSON."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    other = tmp_path / "other-2.0-py3-none-any.whl"
    _wheel(wheel)
    _sdist(sdist)
    _wheel(other)

    class OrderedResolver:
        name = "ordered-test"

        def __init__(self, *, reverse: bool, alternate_spellings: bool = False) -> None:
            self.reverse = reverse
            self.alternate_spellings = alternate_spellings

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, root
            groups: dict[tuple[str, str], list[str]] = {}
            for artifact in artifacts:
                groups.setdefault(
                    (artifact.canonical_name, artifact.version), []
                ).append(artifact.artifact_id)
            packages = tuple(
                ResolvedPackage(
                    name=(name.title() if self.alternate_spellings else name),
                    version=(f"0{version}" if self.alternate_spellings else version),
                    metadata_used=tuple(
                        reversed(identities) if self.reverse else identities
                    ),
                )
                for (name, version), identities in sorted(groups.items())
            )
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(reversed(packages)) if self.reverse else packages,
                reason="resolution completed",
            )

    configuration = _configuration(
        metadata_paths=(wheel, sdist, other),
        requirements=("demo==1.0", "other==2.0"),
        resolve=True,
    )
    forward = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=OrderedResolver(reverse=False),
    )
    reverse = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=OrderedResolver(reverse=True),
    )
    alternate = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=OrderedResolver(reverse=True, alternate_spellings=True),
    )

    assert render_dependency_json(forward) == render_dependency_json(reverse)
    assert render_dependency_json(forward) == render_dependency_json(alternate)


@pytest.mark.parametrize(
    "case",
    [
        (None, None, ("missing==1.0",), _MISSING_DISTRIBUTION_DIAGNOSTIC),
        (
            "demo-2.0-py3-none-any.whl",
            "py3-none-any",
            ("demo==1.0",),
            _MISSING_VERSION_DIAGNOSTIC,
        ),
        (
            "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            "cp311-cp311-manylinux_2_17_x86_64",
            ("demo==1.0",),
            _WRONG_ABI_DIAGNOSTIC,
        ),
        (
            "demo-1.0.tar.gz",
            None,
            ("demo==1.0",),
            _NO_USABLE_WHEELS_DIAGNOSTIC,
        ),
    ],
)
def test_closed_offline_artifact_absence_is_not_a_constraint_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str | None, str | None, tuple[str, ...], str],
) -> None:
    """Missing names, versions, target wheels, and wheels are availability."""
    artifact_name, artifact_tag, requirements, diagnostic = case
    metadata_paths: tuple[Path, ...] = ()
    artifacts: tuple[dependency_module.MetadataArtifact, ...] = ()
    if artifact_name is not None:
        wheel = tmp_path / artifact_name
        if artifact_tag is None:
            _sdist(wheel)
        else:
            _wheel(wheel, tag=artifact_tag)
        inspected, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
        assert issues == ()
        metadata_paths = (wheel,)
        artifacts = inspected
    else:
        wheel = tmp_path / "other-1.0-py3-none-any.whl"
        _wheel(wheel)
        artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
        assert issues == ()
        metadata_paths = (wheel,)
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    configuration = _configuration(
        metadata_paths=metadata_paths,
        requirements=requirements,
        resolve=True,
    )
    result = UvResolverAdapter().resolve(
        configuration,
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    assert result.complete is True
    assert result.resolver_version == "0.11.21"
    assert len(calls) == _RESOLVER_PROCESS_COUNT
    assert "pip" in calls[1]
    assert "compile" in calls[1]
    assert str(tmp_path) not in result.reason


@pytest.mark.parametrize(
    ("resolver_version", "returncode", "diagnostic"),
    [
        ("0.11.22", 1, _MISSING_DISTRIBUTION_DIAGNOSTIC),
        ("0.11.21.0", 1, _MISSING_DISTRIBUTION_DIAGNOSTIC),
        (
            "0.11.21",
            1,
            (
                "\N{MULTIPLICATION SIGN} No solution found when resolving "
                "dependencies:\n"
                "╰─▶ Because missing is absent and you require missing==1.0, "
                "we can conclude that your requirements are unsatisfiable.\n"
            ),
        ),
        (
            "0.11.21",
            1,
            _MISSING_DISTRIBUTION_DIAGNOSTIC + "hint: unreviewed advice\n",
        ),
        (
            "0.11.21",
            1,
            _MISSING_DISTRIBUTION_DIAGNOSTIC.replace("missing==1.0", "missing===1.0.0"),
        ),
        ("0.11.21", 1, _MISSING_VERSION_DIAGNOSTIC),
        ("0.11.21", 2, _MISSING_DISTRIBUTION_DIAGNOSTIC),
        ("0.11.21", -9, _MISSING_DISTRIBUTION_DIAGNOSTIC),
    ],
    ids=[
        "unreviewed-version",
        "noncanonical-reviewed-version",
        "unknown-grammar",
        "unknown-hint",
        "arbitrary-equality-spelling",
        "different-closed-requirement",
        "unreviewed-exit-code",
        "signal",
    ],
)
def test_closed_artifact_absence_rejects_unreviewed_uv_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resolver_version: str,
    returncode: int,
    diagnostic: str,
) -> None:
    """Only the exact reviewed uv proof for the independently absent pin closes."""
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(
                command,
                0,
                f"uv {resolver_version}\n",
                "",
            )
        return subprocess.CompletedProcess(command, returncode, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing==1.0",),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert calls == _RESOLVER_PROCESS_COUNT
    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_closed_artifact_absence_rejects_ambiguous_failure_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second non-empty stream prevents a complete negative conclusion."""
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "error: network transport failed\n",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing==1.0",),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [(_MISSING_DISTRIBUTION_DIAGNOSTIC, ""), (" \n", _MISSING_DISTRIBUTION_DIAGNOSTIC)],
    ids=["stdout-only-diagnostic", "whitespace-stdout"],
)
def test_closed_artifact_absence_rejects_nonempty_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
    stderr: str,
) -> None:
    """Reviewed uv failures require exactly empty stdout and non-empty stderr."""
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            stdout,
            stderr,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing==1.0",),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_resolver_version_rejects_stderr_contamination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Version identity requires exit zero, exact stdout, and empty stderr."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            command,
            0,
            "uv 0.11.21\n",
            "warning: unexpected version diagnostic\n",
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(requirements=("demo==1.0",), resolve=True, network=True),
        _target(),
        (),
        root=tmp_path,
    )

    assert calls == 1
    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False
    assert result.resolver_version is None


def test_closed_artifact_absence_binds_requested_extras(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A diagnostic for different extras cannot close the requested sample."""
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        diagnostic = _MISSING_DISTRIBUTION_DIAGNOSTIC.replace(
            "missing==1.0", "missing[other]==1.0"
        )
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing[speed]==1.0",),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_closed_wrong_abi_evidence_binds_hint_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong-version ABI hint cannot prove the exact pin unavailable."""
    wheel = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    _wheel(wheel, tag="cp311-cp311-manylinux_2_17_x86_64")
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _WRONG_ABI_DIAGNOSTIC.replace("(v1.0)", "(v9.9)"),
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_root_extras_do_not_activate_same_named_dependency_extras(
    tmp_path: Path,
) -> None:
    """Root-project marker contexts cannot manufacture complete artifact absence."""
    windows = tmp_path / "demo-1.0-cp311-cp311-win_amd64.whl"
    macos = tmp_path / "demo-1.0-cp311-cp311-macosx_11_0_x86_64.whl"
    _wheel(
        windows,
        tag="cp311-cp311-win_amd64",
        requires_dist=('child==1; extra != "speed"',),
    )
    _wheel(macos, tag="cp311-cp311-macosx_11_0_x86_64")

    class FalseAbsenceResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
                complete=True,
                resolver=self.name,
                resolver_version="0.11.21",
                packages=(),
                reason="claimed complete artifact absence",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(windows, macos),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        root=tmp_path,
        resolver=FalseAbsenceResolver(),
    )

    result = report.targets[0]
    assert result.resolution.status is ResolutionStatus.UNVERIFIED
    assert result.resolution.complete is False
    assert result.assessments[0].status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_missing_offline_distribution_is_a_complete_report_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed artifact inventory verifies the missing direct requirement."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing==1.0",),
            resolve=True,
        ),
        root=tmp_path,
    )

    target = report.targets[0]
    assert calls == _RESOLVER_PROCESS_COUNT
    assert target.resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    assert target.resolution.complete is True
    assert target.declared_requirements[0].verified is True
    assert report.exit_code is ExitCode.FINDINGS


def test_artifact_failure_closes_only_the_root_named_by_uv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing-root proof cannot close another unsuitable root or transitive."""
    other = tmp_path / "other-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    _wheel(
        other,
        tag="cp311-cp311-manylinux_2_17_x86_64",
        requires_dist=("child==1.0",),
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(other,),
            requirements=("absent==1.0", "missing==1.0", "other==1.0"),
            resolve=True,
        ),
        root=tmp_path,
    )

    target = report.targets[0]
    declared = {item.requirement: item for item in target.declared_requirements}
    assert target.resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    assert target.resolution.complete is True
    assert "missing==1.0" in target.resolution.reason
    assert "other==1.0" not in target.resolution.reason
    assert declared["absent==1.0"].verified is False
    assert declared["missing==1.0"].verified is True
    assert declared["other==1.0"].verified is True
    assert declared["other==1.0"].matching_metadata
    assert target.assessments[0].package == "other"
    assert target.assessments[0].status is DependencyCompatibilityStatus.UNVERIFIED
    assert target.transitive_requirements[0].requirement == "child==1.0"
    assert target.transitive_requirements[0].verified is False
    assert report.exit_code is ExitCode.INCOMPLETE
    schema_path = Path(__file__).parents[2] / "docs/schema/dependency-report-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        dependency_module.dependency_report_document(report)
    )


@pytest.mark.parametrize(
    "case",
    [
        (
            "0.11.21",
            1,
            _UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.RESOLUTION_FAILED,
            True,
        ),
        ("0.11.21", 1, "resolver crashed", ResolutionStatus.UNVERIFIED, False),
        (
            "0.11.21",
            1,
            _MISSING_CONFLICT_DISTRIBUTION_DIAGNOSTIC,
            ResolutionStatus.UNVERIFIED,
            False,
        ),
        (
            "0.12.6 (7938ca5d5 2026-08-25 aarch64-apple-darwin)",
            1,
            _UV_012_MACOS_UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.RESOLUTION_FAILED,
            True,
        ),
        (
            "0.13.0",
            1,
            _UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.UNVERIFIED,
            False,
        ),
        (
            "0.11.21",
            2,
            _UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.UNVERIFIED,
            False,
        ),
    ],
)
def test_resolver_requires_constraints_and_versioned_solver_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, int, str, ResolutionStatus, bool],
) -> None:
    """Only an identified solver contradiction is compatibility failure evidence."""
    resolver_version, returncode, stderr, status, complete = case
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 0, f"uv {resolver_version}\n", ""
            )
        return subprocess.CompletedProcess(command, returncode, "", stderr)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            requirements=("demo==1.0", "demo==2.0"),
            resolve=True,
            network=True,
        ),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is status
    assert result.complete is complete
    assert "--default-index" in calls[1]
    assert "--only-binary" in calls[1]
    assert ":all:" in calls[1]
    assert calls[1][calls[1].index("--keyring-provider") + 1] == "disabled"
    assert "--no-python-downloads" in calls[1]


def test_resolver_conflict_does_not_complete_unrelated_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One contradictory root cannot verify other roots or transitives."""
    other = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(other, requires_dist=("child==1.0",))
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _UNSATISFIABLE_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(other,),
            requirements=(
                "demo==1.0",
                "demo==2.0",
                "missing==1.0",
                "other==1.0",
            ),
            resolve=True,
            network=True,
        ),
        root=tmp_path,
    )

    target = report.targets[0]
    declared = {item.requirement: item for item in target.declared_requirements}
    assert target.resolution.status is ResolutionStatus.RESOLUTION_FAILED
    assert target.resolution.complete is True
    assert declared["demo==1.0"].verified is True
    assert declared["demo==2.0"].verified is True
    assert declared["missing==1.0"].verified is False
    assert declared["other==1.0"].verified is True
    assert target.assessments[0].status is DependencyCompatibilityStatus.UNVERIFIED
    assert target.transitive_requirements[0].requirement == "child==1.0"
    assert target.transitive_requirements[0].verified is False
    assert report.exit_code is ExitCode.INCOMPLETE
    schema_path = Path(__file__).parents[2] / "docs/schema/dependency-report-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        dependency_module.dependency_report_document(report)
    )


def test_resolver_conflict_closes_only_the_group_named_by_uv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reviewed diagnostic cannot verify a second contradictory root group."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _UNSATISFIABLE_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            requirements=(
                "demo==1.0",
                "demo==2.0",
                "other==1.0",
                "other==2.0",
            ),
            resolve=True,
            network=True,
        ),
        root=tmp_path,
    )

    declared = {
        item.requirement: item for item in report.targets[0].declared_requirements
    }
    assert report.targets[0].resolution.status is ResolutionStatus.RESOLUTION_FAILED
    assert declared["demo==1.0"].verified is True
    assert declared["demo==2.0"].verified is True
    assert declared["other==1.0"].verified is False
    assert declared["other==2.0"].verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    "diagnostic",
    [
        _UNSATISFIABLE_DIAGNOSTIC.replace("demo==", "notdemo=="),
        _UNSATISFIABLE_DIAGNOSTIC.replace(".0", ".0.post1"),
    ],
    ids=["name-prefix", "version-suffix"],
)
def test_constraint_evidence_rejects_requirement_token_collisions(
    diagnostic: str,
) -> None:
    """Longer names or versions cannot satisfy active-constraint correlation."""
    assert not dependency_module._uv_reports_constraint_conflict(  # noqa: SLF001
        diagnostic,
        "0.11.21",
        ("demo==1.0", "demo==2.0"),
    )


def test_offline_library_range_absence_remains_unverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A finite local artifact sample is not universal evidence for a library."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    configuration = replace(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("missing>=1",),
            resolve=True,
        ),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    result = UvResolverAdapter().resolve(
        configuration,
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert calls == _RESOLVER_PROCESS_COUNT
    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


@pytest.mark.parametrize(
    "requirements",
    [("demo==1.0",), ()],
    ids=["exact-requirement", "metadata-only"],
)
def test_library_artifact_sample_without_target_wheel_is_incomplete(
    tmp_path: Path,
    requirements: tuple[str, ...],
) -> None:
    """Neither an exact pin nor metadata-only mode closes a library inventory."""
    wheel = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    _wheel(wheel, tag="cp311-cp311-manylinux_2_17_x86_64")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=requirements),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.artifact_availability is ArtifactAvailability.UNAVAILABLE
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert "supplied artifact sample" in assessment.reason
    assert report.exit_code is ExitCode.INCOMPLETE


def test_library_sdist_sample_keeps_source_build_possibility_incomplete(
    tmp_path: Path,
) -> None:
    """A sampled library sdist is neither a wheel nor proof of unavailability."""
    sdist = tmp_path / "demo-1.0.tar.gz"
    _sdist(sdist)
    configuration = replace(
        _configuration(metadata_paths=(sdist,), requirements=("demo==1.0",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.artifact_availability is (
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    )
    assert assessment.source_build_possible is True
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_library_matching_artifact_sample_remains_incomplete(tmp_path: Path) -> None:
    """One matching library wheel is still only a partial artifact sample."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo>=1",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.artifact_availability is ArtifactAvailability.AVAILABLE
    assert assessment.requires_python_status is RequiresPythonStatus.COMPATIBLE
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_public_version_library_pin_does_not_close_local_version_inventory(
    tmp_path: Path,
) -> None:
    """A public equality still admits unseen local versions for a library."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_python=">=9")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo==1.0",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.requires_python_status is RequiresPythonStatus.INCOMPATIBLE
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.targets[0].declared_requirements[0].verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_explicit_local_library_pin_can_retain_declared_exclusion(
    tmp_path: Path,
) -> None:
    """An equality with a local segment names one distribution version."""
    wheel = tmp_path / "demo-1.0+cpu-py3-none-any.whl"
    _wheel(wheel, requires_python=">=9")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo==1.0+cpu",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
    assert report.targets[0].declared_requirements[0].verified is True
    assert report.exit_code is ExitCode.FINDINGS


def test_library_range_sample_without_target_wheel_is_incomplete(
    tmp_path: Path,
) -> None:
    """One unsuitable sampled version cannot fail an open library range."""
    wheel = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    _wheel(wheel, tag="cp311-cp311-manylinux_2_17_x86_64")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo>=1",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.artifact_availability is ArtifactAvailability.UNAVAILABLE
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_library_range_sample_with_excluding_requires_python_is_incomplete(
    tmp_path: Path,
) -> None:
    """One version's Python declaration cannot fail an open library range."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_python=">=9")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo>=1",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.requires_python_status is RequiresPythonStatus.INCOMPATIBLE
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_complete_library_resolution_ignores_unselected_unsuitable_sample(
    tmp_path: Path,
) -> None:
    """A selected compatible version accounts for an open library range."""
    unsuitable = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    selected = tmp_path / "demo-2.0-py3-none-any.whl"
    _wheel(unsuitable, tag="cp311-cp311-manylinux_2_17_x86_64")
    _wheel(selected)
    artifacts, issues = inspect_dependency_metadata(
        (unsuitable, selected),
        root=tmp_path,
    )
    assert issues == ()
    selected_artifact = next(item for item in artifacts if item.version == "2.0")

    class AlternativeResolver:
        name = "test-alternative"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        name="demo",
                        version="2.0",
                        metadata_used=(selected_artifact.artifact_id,),
                    ),
                ),
                reason="resolution completed",
            )

    configuration = replace(
        _configuration(
            metadata_paths=(unsuitable, selected),
            requirements=("demo>=1",),
            resolve=True,
        ),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    report = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=AlternativeResolver(),
    )

    assessments = report.targets[0].assessments
    assert tuple(item.version for item in assessments) == ("2.0",)
    assert assessments[0].status is DependencyCompatibilityStatus.COMPATIBLE
    assert report.exit_code is ExitCode.SUCCESS


@pytest.mark.parametrize(
    "project_kind",
    [DependencyProjectKind.APPLICATION, DependencyProjectKind.LIBRARY],
)
def test_complete_resolution_accepts_compatible_same_version_artifact(
    tmp_path: Path,
    project_kind: DependencyProjectKind,
) -> None:
    """A compatible selected wheel accounts for unsuitable same-version samples."""
    unsuitable = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    selected = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(unsuitable, tag="cp311-cp311-manylinux_2_17_x86_64")
    _wheel(selected)
    artifacts, issues = inspect_dependency_metadata(
        (unsuitable, selected),
        root=tmp_path,
    )
    assert issues == ()
    selected_artifact = next(
        item for item in artifacts if item.path == PurePosixPath(selected.name)
    )

    class SameVersionResolver:
        name = "test-same-version"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        name="demo",
                        version="1.0",
                        metadata_used=(selected_artifact.artifact_id,),
                    ),
                ),
                reason="resolution completed",
            )

    configuration = replace(
        _configuration(
            metadata_paths=(unsuitable, selected),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        project_kind=project_kind,
    )
    report = collect_dependency_report(
        configuration,
        root=tmp_path,
        resolver=SameVersionResolver(),
    )

    assessment = report.targets[0].assessments[0]
    assert assessment.artifact_availability is ArtifactAvailability.AVAILABLE
    assert assessment.status is DependencyCompatibilityStatus.COMPATIBLE
    assert report.exit_code is ExitCode.SUCCESS


def test_library_assessment_uses_only_selected_same_version_metadata(
    tmp_path: Path,
) -> None:
    """Unselected compatible wheels cannot inject dependency metadata."""
    selected = tmp_path / "demo-1.0-py3-none-any.whl"
    unselected = tmp_path / "demo-1.0-py2.py3-none-any.whl"
    _wheel(selected)
    _wheel(
        unselected,
        tag="py2.py3-none-any",
        requires_dist=("ghost==1.0",),
    )
    artifacts, issues = inspect_dependency_metadata(
        (unselected, selected),
        root=tmp_path,
    )
    assert issues == ()
    selected_artifact = next(
        item for item in artifacts if item.path == PurePosixPath(selected.name)
    )

    class ExactArtifactResolver:
        name = "test-exact-artifact"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        name="demo",
                        version="1.0",
                        metadata_used=(selected_artifact.artifact_id,),
                    ),
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        replace(
            _configuration(
                metadata_paths=(unselected, selected),
                requirements=("demo>=1",),
                resolve=True,
            ),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
        resolver=ExactArtifactResolver(),
    )

    assessment = report.targets[0].assessments[0]
    assert assessment.metadata_used == (selected_artifact.artifact_id,)
    assert assessment.applicable_requirements == ()
    assert report.targets[0].transitive_requirements == ()
    assert report.exit_code is ExitCode.SUCCESS


def test_declared_extra_cannot_borrow_unselected_same_version_metadata(
    tmp_path: Path,
) -> None:
    """Complete resolution scopes direct extra evidence to selected artifacts."""
    selected = tmp_path / "demo-1.0-py3-none-any.whl"
    unselected = tmp_path / "demo-1.0-py2.py3-none-any.whl"
    _wheel(selected)
    _wheel(unselected, tag="py2.py3-none-any", provides_extra=("speed",))
    artifacts, issues = inspect_dependency_metadata(
        (unselected, selected),
        root=tmp_path,
    )
    assert issues == ()
    selected_artifact = next(
        item for item in artifacts if item.path == PurePosixPath(selected.name)
    )

    class ExactArtifactResolver:
        name = "test-declared-exact-artifact"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=(
                    ResolvedPackage(
                        name="demo",
                        version="1.0",
                        metadata_used=(selected_artifact.artifact_id,),
                    ),
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(unselected, selected),
            requirements=("demo[speed]==1.0",),
            resolve=True,
        ),
        root=tmp_path,
        resolver=ExactArtifactResolver(),
    )

    declared = report.targets[0].declared_requirements[0]
    assert report.targets[0].resolution.status is ResolutionStatus.SUCCEEDED
    assert declared.matching_metadata == ()
    assert declared.resolved_versions == ()
    assert declared.verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_transitive_extra_cannot_borrow_unselected_application_metadata(
    tmp_path: Path,
) -> None:
    """An application lock cannot verify an extra from an unselected wheel."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    selected_other = tmp_path / "other-2.0-py3-none-any.whl"
    unselected_other = tmp_path / "other-2.0-py2.py3-none-any.whl"
    _wheel(demo, requires_dist=("other[speed]==2.0",))
    _wheel(selected_other)
    _wheel(
        unselected_other,
        tag="py2.py3-none-any",
        provides_extra=("speed",),
    )
    artifacts, issues = inspect_dependency_metadata(
        (unselected_other, demo, selected_other),
        root=tmp_path,
    )
    assert issues == ()
    selected_ids = {
        item.canonical_name: item.artifact_id
        for item in artifacts
        if item.path in {PurePosixPath(demo.name), PurePosixPath(selected_other.name)}
    }

    class ExactClosureResolver:
        name = "test-transitive-exact-artifact"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.SUCCEEDED,
                complete=True,
                resolver=self.name,
                resolver_version="1.0",
                packages=tuple(
                    ResolvedPackage(
                        name=name,
                        version="1.0" if name == "demo" else "2.0",
                        metadata_used=(artifact_id,),
                    )
                    for name, artifact_id in sorted(selected_ids.items())
                ),
                reason="resolution completed",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(unselected_other, demo, selected_other),
            requirements=("demo==1.0", "other==2.0"),
            resolve=True,
        ),
        root=tmp_path,
        resolver=ExactClosureResolver(),
    )

    transitive = report.targets[0].transitive_requirements[0]
    assert transitive.requirement == "other[speed]==2.0"
    assert transitive.matching_metadata == ()
    assert transitive.resolved_versions == ()
    assert transitive.verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    "diagnostic",
    [
        _MISSING_DISTRIBUTION_DIAGNOSTIC,
        _UNSATISFIABLE_DIAGNOSTIC,
        "error: network transport failed because only cached data was available",
        "error: authentication failed after no solution found from the index",
        "error: invalid target; requirements are unsatisfiable.",
        "tool crashed because only one worker remained",
        (
            "\N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
            "╰─▶ Because authentication failed, requirements are unsatisfiable."
        ),
    ],
)
def test_resolver_does_not_promote_broad_failure_text_to_unsatisfiable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    diagnostic: str,
) -> None:
    """Transport, authentication, target, and tool errors stay incomplete."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_resolver_success_names_exact_versions_and_matching_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful resolution records pins, resolver version, and known metadata."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, _issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    calls = 0
    environments: list[dict[str, str]] = []

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        environments.append(cast("dict[str, str]", kwargs["env"]))
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        output = Path(command[command.index("--output-file") + 1])
        selected = output.parent / "artifacts" / wheel.name
        output.write_text(_pylock(("demo", "1.0", selected.as_uri())), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(metadata_paths=(wheel,), resolve=True),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.SUCCEEDED
    assert result.complete is True
    assert result.resolver_version == "0.11.21"
    assert result.packages[0].name == "demo"
    assert result.packages[0].version == "1.0"
    assert result.packages[0].metadata_used == (artifacts[0].artifact_id,)
    assert set(environments[1]).isdisjoint({"PIP_INDEX_URL", "UV_INDEX_URL"})
    assert "pyahead-resolver-" in environments[1]["HOME"]
    assert environments[1]["UV_NO_CONFIG"] == "1"


def test_resolver_provenance_names_only_the_selected_platform_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same-version wheels cannot all be attributed to one selected package."""
    linux = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    windows = tmp_path / "demo-1.0-cp312-cp312-win_amd64.whl"
    _wheel(linux, tag="cp312-cp312-manylinux_2_17_x86_64")
    _wheel(windows, tag="cp312-cp312-win_amd64")
    artifacts, _issues = inspect_dependency_metadata((windows, linux), root=tmp_path)
    selected = next(
        item for item in artifacts if item.path == PurePosixPath(linux.name)
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        output = Path(command[command.index("--output-file") + 1])
        selected_path = output.parent / "artifacts" / linux.name
        output.write_text(
            _pylock(("demo", "1.0", selected_path.as_uri())), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            target=_target(tags=("cp312-cp312-manylinux_2_17_x86_64",)),
            metadata_paths=(linux, windows),
            resolve=True,
        ),
        _target(tags=("cp312-cp312-manylinux_2_17_x86_64",)),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.SUCCEEDED
    assert result.packages[0].metadata_used == (selected.artifact_id,)


def test_online_selection_is_not_attributed_to_same_version_local_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A remote index wheel cannot borrow provenance from a local artifact."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, _issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text(
            _pylock(
                (
                    "demo",
                    "1.0",
                    "https://packages.example/files/demo-1.0-py3-none-any.whl",
                )
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(metadata_paths=(wheel,), resolve=True, network=True),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False
    assert result.packages[0].metadata_used == ()
    assert "exact artifact provenance" in result.reason


def test_dependency_json_is_deterministic_and_contains_exact_identity(
    tmp_path: Path,
) -> None:
    """Machine output names exact versions, metadata digests, and controls."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    configuration = _configuration(metadata_paths=(wheel,))
    first = collect_dependency_report(configuration, root=tmp_path)
    second = collect_dependency_report(configuration, root=tmp_path)

    assert render_dependency_json(first) == render_dependency_json(second)
    document = cast(
        "dict[str, object]",
        dependency_module.dependency_report_document(first),
    )
    metadata = cast("list[dict[str, object]]", document["metadata"])
    controls = cast("dict[str, object]", document["controls"])
    assert metadata[0]["version"] == "1.0"
    assert metadata[0]["metadata_version"] == "2.4"
    assert metadata[0]["sha256"] == first.metadata[0].artifact_id
    assert controls == {
        "index_url": None,
        "network": False,
        "resolve": False,
        "resolver": "uv",
        "timeout_seconds": _TIMEOUT_SECONDS,
    }


def _target_table() -> dict[str, object]:
    document = tomllib.loads(_configuration_toml())
    tool = cast("dict[str, object]", document["tool"])
    pyahead = cast("dict[str, object]", tool["pyahead"])
    dependencies = cast("dict[str, object]", pyahead["dependencies"])
    return cast("list[dict[str, object]]", dependencies["targets"])[0]


@pytest.mark.parametrize(
    ("key", "value", "match"),
    [
        ("unknown", True, "unknown or missing"),
        ("python-full-version", "invalid", "invalid version"),
        ("python-full-version", "3.12", "three release components"),
        ("implementation-version", "3.12", "three release components"),
        ("compatible-tags", [], "must not be empty"),
        ("compatible-tags", ["invalid"], "invalid compatible tag"),
        (
            "compatible-tags",
            ["py3-cp311-any"],
            "Python version or implementation",
        ),
        (
            "compatible-tags",
            ["cp312-cp311-manylinux_2_17_x86_64"],
            "Python version or implementation",
        ),
        (
            "compatible-tags",
            ["py3-none-manylinux_2_x_x86_64"],
            "declared platform",
        ),
        ("resolver-platform", "../linux", "unsupported characters"),
        ("name", "bad\nname", "control characters"),
    ],
)
def test_target_model_rejects_incomplete_or_ambiguous_declarations(
    key: str,
    value: object,
    match: str,
) -> None:
    """Every marker and artifact target is explicit and strict."""
    target = deepcopy(_target_table())
    target[key] = value
    with pytest.raises(ConfigurationError, match=match):
        dependency_module._parse_target(target, 0)  # noqa: SLF001


def test_target_model_accepts_valid_generic_and_cpython_abi_tags() -> None:
    """Strict coherence retains ordinary pure-Python and CPython ABI tags."""
    target = deepcopy(_target_table())
    target["compatible-tags"] = [
        "py3-none-any",
        "py312-none-any",
        "cp312-cp312-manylinux_2_17_x86_64",
        "cp312-abi3-manylinux_2_17_x86_64",
        "cp311-abi3-manylinux_2_17_x86_64",
    ]

    parsed = dependency_module._parse_target(target, 0)  # noqa: SLF001

    assert set(parsed.compatible_tags) == set(target["compatible-tags"])


def test_target_model_validates_pypy_abi_tags() -> None:
    """PyPy targets reject CPython ABIs and retain native PyPy ABI tags."""
    target = deepcopy(_target_table())
    target["implementation-name"] = "pypy"
    target["implementation-version"] = "7.3.19"
    target["platform-python-implementation"] = "PyPy"
    target["compatible-tags"] = ["pp312-cp311-any"]

    with pytest.raises(ConfigurationError, match="Python version or implementation"):
        dependency_module._parse_target(target, 0)  # noqa: SLF001

    target["compatible-tags"] = [
        "pp312-none-any",
        "pp312-pypy312_pp73-manylinux_2_17_x86_64",
    ]

    parsed = dependency_module._parse_target(target, 0)  # noqa: SLF001

    assert set(parsed.compatible_tags) == set(target["compatible-tags"])

    for abi in ("pp99", "pp7319"):
        target["compatible-tags"] = [f"pp312-pypy312_{abi}-manylinux_2_17_x86_64"]
        with pytest.raises(
            ConfigurationError,
            match="Python version or implementation",
        ):
            dependency_module._parse_target(target, 0)  # noqa: SLF001


@pytest.mark.parametrize(
    "target",
    [
        replace(_target(), implementation_name="CPython"),
        replace(_target(), implementation_name="other"),
    ],
)
def test_known_implementation_labels_cannot_silence_target_markers(
    tmp_path: Path,
    target: EnvironmentTarget,
) -> None:
    """Case variants and reverse-label conflicts fail before marker evaluation."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(
        wheel,
        requires_dist=('child==1; implementation_name == "cpython"',),
    )
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()

    with pytest.raises(ConfigurationError, match="implementation"):
        assess_dependency_metadata(artifacts, target=target, extras=())


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        (
            replace(
                _target(),
                implementation_name="pypy",
                platform_python_implementation="PyPy",
            ),
            "implementation",
        ),
        (_target(sys_platform="win32"), "Windows platform-machine"),
        (replace(_target(), platform_release="6.8"), "platform-release"),
    ],
)
def test_resolver_rejects_targets_it_cannot_faithfully_represent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: EnvironmentTarget,
    reason: str,
) -> None:
    """Uv is not invoked for implementation, marker, or tag contradictions."""

    def forbidden_lookup(_name: str) -> None:
        message = "an inconsistent target must fail before resolver discovery"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.shutil, "which", forbidden_lookup)
    result = UvResolverAdapter().resolve(
        _configuration(target=target, resolve=True, network=True),
        target,
        (),
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False
    assert reason in result.reason


def test_target_model_and_scalar_validators_reject_closed_world_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrong table/list/bool/timeout/requirement shapes fail before evidence."""
    with pytest.raises(ConfigurationError, match="TOML table"):
        dependency_module._parse_target([], 0)  # noqa: SLF001
    missing = _target_table()
    del missing["name"]
    with pytest.raises(ConfigurationError, match="unknown or missing"):
        dependency_module._parse_target(missing, 0)  # noqa: SLF001
    duplicate_tags = _target_table()
    duplicate_tags["compatible-tags"] = ["py3-none-any", "py3-none-any"]
    with pytest.raises(ConfigurationError, match="duplicates"):
        dependency_module._parse_target(duplicate_tags, 0)  # noqa: SLF001
    with pytest.raises(ConfigurationError, match="must be an array"):
        dependency_module._string_list("bad", "value")  # noqa: SLF001
    with pytest.raises(ConfigurationError, match="must be a boolean"):
        dependency_module._boolean(1, "value")  # noqa: SLF001
    for value in (True, "one", 0, float("inf"), 1e308):
        with pytest.raises(ConfigurationError, match="finite positive"):
            dependency_module._positive_number(value, "value")  # noqa: SLF001
    with pytest.raises(ConfigurationError, match="Expected"):
        dependency_module._parse_requirements(  # noqa: SLF001
            ("not a requirement ???",), DependencyProjectKind.LIBRARY
        )
    with pytest.raises(ConfigurationError, match="direct URL"):
        dependency_module._parse_requirements(  # noqa: SLF001
            ("demo @ https://example.invalid/demo.whl",),
            DependencyProjectKind.LIBRARY,
        )
    with pytest.raises(ConfigurationError, match="exact == version pin"):
        dependency_module._parse_requirements(  # noqa: SLF001
            ("demo==1.*",), DependencyProjectKind.APPLICATION
        )
    monkeypatch.setattr(dependency_module, "_MAX_REQUIREMENTS", 1)
    with pytest.raises(ConfigurationError, match="too many"):
        dependency_module._parse_requirements(  # noqa: SLF001
            ("one>=1", "two>=2"), DependencyProjectKind.LIBRARY
        )


def test_index_control_rejects_ambient_or_credentialed_sources() -> None:
    """Network policy cannot inherit an index or persist credentials."""
    assert dependency_module._index_url(None) is None  # noqa: SLF001
    for value in (
        "ftp://example.invalid/simple",
        "https://user@host/simple",
        "https://example.invalid/simple?token=secret",
        "https://example.invalid/simple#fragment",
    ):
        with pytest.raises(ConfigurationError, match="without embedded credentials"):
            dependency_module._index_url(value)  # noqa: SLF001
    assert (
        dependency_module._index_url(  # noqa: SLF001
            "https://packages.example/simple"
        )
        == "https://packages.example/simple"
    )


def test_configuration_file_and_root_failures_are_bounded(tmp_path: Path) -> None:
    """Missing, malformed, and out-of-root config cannot become defaults."""
    missing_root = tmp_path / "missing-root"
    with pytest.raises(ConfigurationError, match="dependency root"):
        load_dependency_configuration(missing_root)
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_dependency_configuration(tmp_path)

    project = tmp_path / "pyproject.toml"
    project.write_text("not = [valid", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid TOML"):
        load_dependency_configuration(tmp_path)

    project.write_text("[project]\nname='demo'\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match=r"dependencies.*required"):
        load_dependency_configuration(tmp_path)

    outside = tmp_path.parent / f"{tmp_path.name}-outside.toml"
    outside.write_text(_configuration_toml(), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="beneath the root"):
        load_dependency_configuration(tmp_path, outside)


def test_configuration_open_failure_does_not_reflect_untrusted_path(
    tmp_path: Path,
) -> None:
    """Native configuration failures use a fixed, control-free label."""
    selected = Path("missing\nconfig.toml")

    with pytest.raises(ConfigurationError) as captured:
        load_dependency_configuration(tmp_path, selected)

    message = str(captured.value)
    assert message.startswith("dependency configuration: ")
    assert "\n" not in message
    assert selected.name not in message


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ('project-kind = "application"', 'project-kind = "service"', "application"),
        ("targets]]", 'targets]]\nname = "duplicate"', "TOML"),
        ('resolver = "uv"', 'resolver = "pip"', "only 'uv'"),
        ("network = false", 'network = "no"', "must be a boolean"),
        ("timeout-seconds = 2.5", "timeout-seconds = 0", "finite positive"),
        ("timeout-seconds = 2.5", "timeout-seconds = 1e308", "no greater than"),
    ],
)
def test_configuration_rejects_invalid_semantics(
    tmp_path: Path,
    old: str,
    new: str,
    match: str,
) -> None:
    """Strict dependency configuration reports semantic mistakes."""
    (tmp_path / "pyproject.toml").write_text(
        _configuration_toml().replace(old, new), encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match=match):
        load_dependency_configuration(tmp_path)


def test_configuration_controls_require_inputs_and_support_offline_override(
    tmp_path: Path,
) -> None:
    """Resolution and network overrides retain their explicit prerequisites."""
    path = tmp_path / "pyproject.toml"
    no_inputs = (
        _configuration_toml()
        .replace('requirements = ["demo==1.0"]', "requirements = []")
        .replace('metadata = ["demo-1.0-py3-none-any.whl"]', "metadata = []")
    )
    path.write_text(no_inputs, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="requirements or metadata"):
        load_dependency_configuration(tmp_path)

    metadata_only = no_inputs.replace("metadata = []", 'metadata = ["demo.metadata"]')
    path.write_text(metadata_only, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="requires requirements"):
        load_dependency_configuration(tmp_path, resolve_override=True)

    requirements_only = no_inputs.replace(
        "requirements = []", 'requirements = ["demo==1.0"]'
    )
    path.write_text(requirements_only, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="resolver is not enabled"):
        load_dependency_configuration(tmp_path)
    with pytest.raises(ConfigurationError, match="artifact set"):
        load_dependency_configuration(tmp_path, resolve_override=True)

    online = _configuration_toml(network=True).replace(
        'resolver = "uv"',
        'resolver = "uv"\nindex-url = "https://packages.example/simple"',
    )
    path.write_text(online, encoding="utf-8")
    configuration = load_dependency_configuration(
        tmp_path,
        network_override=False,
        resolve_override=False,
        timeout_override=1,
    )
    assert configuration.network is False
    assert configuration.index_url is None
    assert configuration.timeout_seconds == 1

    dormant_index = _configuration_toml().replace(
        'resolver = "uv"',
        'resolver = "uv"\nindex-url = "https://packages.example/simple"',
    )
    path.write_text(dormant_index, encoding="utf-8")
    offline = load_dependency_configuration(tmp_path)
    assert offline.network is False
    assert offline.index_url is None
    enabled = load_dependency_configuration(
        tmp_path,
        network_override=True,
        resolve_override=True,
    )
    assert enabled.network is True
    assert enabled.index_url == "https://packages.example/simple"


def _write_raw_wheel(
    path: Path,
    members: Sequence[tuple[str, bytes]],
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members:
            archive.writestr(name, payload)


@pytest.mark.parametrize(
    ("filename", "payload", "message"),
    [
        ("demo-1.0-py3-none-any.whl", b"not a zip", "invalid ZIP"),
        ("demo-1.0.tar.gz", b"not a tar", "invalid tar"),
        (
            "demo-1.0.metadata",
            b"Metadata-Version: 2.4\nName: demo\nVersion: invalid!\n\n",
            "invalid Version",
        ),
        (
            "demo-1.0.metadata",
            _metadata(requires_python="not a specifier"),
            "invalid Requires-Python",
        ),
        (
            "demo-1.0.metadata",
            _metadata(requires_dist=("not a requirement ???",)),
            "invalid Requires-Dist",
        ),
        (
            "demo-1.0.metadata",
            b"Metadata-Version: 2.4\nName: demo\nName: other\nVersion: 1.0\n\n",
            "repeats Name",
        ),
    ],
)
def test_direct_metadata_retains_malformed_artifacts_as_incomplete(
    tmp_path: Path,
    filename: str,
    payload: bytes,
    message: str,
) -> None:
    """Malformed archives and metadata become bounded incomplete evidence."""
    path = tmp_path / filename
    path.write_bytes(payload)
    artifacts, issues = inspect_dependency_metadata((path,), root=tmp_path)
    assert artifacts == ()
    assert message in issues[0].message


def test_wheel_archive_structure_and_identity_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wheel metadata must be unique, bounded, and match its filename."""
    missing = tmp_path / "demo-1.0-py3-none-any.whl"
    _write_raw_wheel(missing, [("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1")])
    _artifacts, issues = inspect_dependency_metadata((missing,), root=tmp_path)
    assert "exactly one" in issues[0].message

    duplicate = tmp_path / "duplicate-1.0-py3-none-any.whl"
    _write_raw_wheel(
        duplicate,
        [
            ("one.dist-info/METADATA", _metadata(identity=("duplicate", "1.0"))),
            ("two.dist-info/METADATA", _metadata(identity=("duplicate", "1.0"))),
        ],
    )
    _artifacts, issues = inspect_dependency_metadata((duplicate,), root=tmp_path)
    assert "exactly one" in issues[0].message

    mismatch = tmp_path / "other-1.0-py3-none-any.whl"
    _write_raw_wheel(
        mismatch,
        [("other-1.0.dist-info/METADATA", _metadata(identity=("demo", "1.0")))],
    )
    _artifacts, issues = inspect_dependency_metadata((mismatch,), root=tmp_path)
    assert "identity disagree" in issues[0].message

    oversized = tmp_path / "large-1.0-py3-none-any.whl"
    _write_raw_wheel(
        oversized,
        [("large-1.0.dist-info/METADATA", _metadata(identity=("large", "1.0")))],
    )
    monkeypatch.setattr(dependency_module, "_MAX_METADATA_BYTES", 8)
    _artifacts, issues = inspect_dependency_metadata((oversized,), root=tmp_path)
    assert "size limit" in issues[0].message


def test_zip_limits_are_checked_before_member_objects_are_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZIP central-directory limits preflight the stdlib object allocation."""
    archive_path = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(
        archive_path,
        [
            ("demo-1.0/first.txt", b"first"),
            ("demo-1.0/PKG-INFO", _metadata()),
        ],
    )
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_MEMBERS", 1)

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "member objects must not be created before the count preflight"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "too many members" in issues[0].message


def test_zip_expanded_size_is_checked_before_decompression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declared ZIP expansion cannot reach decompression before its budget."""
    archive_path = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(
        archive_path,
        [("demo-1.0/PKG-INFO", _metadata())],
    )
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_EXPANDED_BYTES", 1)

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "oversized expanded data must fail before decompression"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "expanded data" in issues[0].message


def test_zip_directory_size_is_checked_before_member_objects_are_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded entry count cannot hide an oversized central directory."""
    archive_path = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(
        archive_path,
        [("demo-1.0/PKG-INFO", _metadata())],
    )
    monkeypatch.setattr(dependency_module, "_MAX_ZIP_CENTRAL_DIRECTORY_BYTES", 1)

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "the central-directory byte cap must precede ZipFile"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "central directory" in issues[0].message


def test_zip64_is_conservatively_rejected_below_the_member_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The accepted member budget never ambiguously reaches a ZIP64 sentinel."""
    assert (
        dependency_module._MAX_ARCHIVE_MEMBERS  # noqa: SLF001
        < dependency_module._ZIP_UINT16_SENTINEL  # noqa: SLF001
    )
    archive_path = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(archive_path, [("demo-1.0/PKG-INFO", _metadata())])
    raw = bytearray(archive_path.read_bytes())
    eocd = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, eocd + 8, 0xFFFF, 0xFFFF)
    archive_path.write_bytes(raw)

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "ZIP64 must be rejected during preflight"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "ZIP64" in issues[0].message


def test_unknown_zip_compression_is_rejected_before_zipfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Version-specific ZIP methods cannot introduce uncaught decoders."""
    archive_path = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(archive_path, [("demo-1.0/PKG-INFO", _metadata())])
    raw = bytearray(archive_path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, central + 10, 93)
    archive_path.write_bytes(raw)

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "unsupported compression must fail during preflight"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "compression method" in issues[0].message


def test_zip_lzma_is_rejected_before_its_unbounded_decoder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attacker-controlled LZMA dictionaries never reach the stdlib decoder."""
    archive_path = tmp_path / "demo-1.0.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_LZMA) as archive:
        archive.writestr("demo-1.0/PKG-INFO", _metadata())

    def forbidden_zipfile(*_args: object, **_kwargs: object) -> None:
        message = "LZMA must be rejected from the central directory"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.zipfile, "ZipFile", forbidden_zipfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "compression method" in issues[0].message


def test_malformed_zip_names_and_deflate_are_incomplete_evidence(
    tmp_path: Path,
) -> None:
    """Untrusted decoding and decompressor errors never escape as internals."""
    invalid_name = tmp_path / "invalid-name-1.0.zip"
    _write_raw_wheel(invalid_name, [("invalid-name-1.0/PKG-INFO", _metadata())])
    raw_name = bytearray(invalid_name.read_bytes())
    central = raw_name.index(b"PK\x01\x02")
    flags = struct.unpack_from("<H", raw_name, central + 8)[0]
    struct.pack_into("<H", raw_name, central + 8, flags | 0x800)
    raw_name[central + 46] = 0xFF
    invalid_name.write_bytes(raw_name)

    invalid_deflate = tmp_path / "invalid-deflate-1.0.zip"
    with zipfile.ZipFile(
        invalid_deflate,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "invalid-deflate-1.0/PKG-INFO",
            _metadata(identity=("invalid-deflate", "1.0")) + bytes(range(256)) * 20,
        )
    raw_deflate = bytearray(invalid_deflate.read_bytes())
    local = raw_deflate.index(b"PK\x03\x04")
    name_size, extra_size = struct.unpack_from("<HH", raw_deflate, local + 26)
    compressed_payload = local + 30 + name_size + extra_size
    raw_deflate[compressed_payload] = 0x07  # Final block with reserved BTYPE=3.
    invalid_deflate.write_bytes(raw_deflate)

    for archive_path in (invalid_name, invalid_deflate):
        artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)
        assert artifacts == ()
        assert issues[0].message == "invalid ZIP archive"


def test_wheel_secondary_metadata_read_reuses_zip_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The WHEEL/RECORD validation path repeats the bounded ZIP preflight."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    original = dependency_module._check_zip_archive_limits  # noqa: SLF001
    checked: list[int] = []

    def record_preflight(raw: bytes) -> None:
        checked.append(len(raw))
        original(raw)

    monkeypatch.setattr(
        dependency_module,
        "_check_zip_archive_limits",
        record_preflight,
    )

    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert issues == ()
    assert len(artifacts) == 1
    assert checked == [wheel.stat().st_size, wheel.stat().st_size]


def test_tar_limits_are_incremental_and_bound_expanded_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tar inspection avoids getmembers and stops at count or expansion limits."""
    archive_path = tmp_path / "demo-1.0.tar.gz"
    _tar_sdist(
        archive_path,
        [
            ("demo-1.0/first.txt", b"first"),
            ("demo-1.0/PKG-INFO", _metadata()),
        ],
    )

    def forbidden_getmembers(*_args: object, **_kwargs: object) -> None:
        message = "tar members must be consumed incrementally"
        raise AssertionError(message)

    monkeypatch.setattr(tarfile.TarFile, "getmembers", forbidden_getmembers)
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_MEMBERS", 1)
    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)
    assert artifacts == ()
    assert "too many members" in issues[0].message

    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_MEMBERS", 100)
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_EXPANDED_BYTES", 512)
    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)
    assert artifacts == ()
    assert "expanded data" in issues[0].message


def test_tar_expansion_budget_is_shared_across_all_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many individually small compressed inputs share one decompression cap."""
    first = tmp_path / "first-1.0.tar.gz"
    second = tmp_path / "second-1.0.tar.gz"
    _sdist(first)
    _sdist(second)
    monkeypatch.setattr(
        dependency_module,
        "_MAX_TOTAL_ARCHIVE_EXPANDED_BYTES",
        20_000,
    )

    artifacts, issues = inspect_dependency_metadata((first, second), root=tmp_path)

    assert len(artifacts) == 1
    assert len(issues) == 1
    assert "aggregate archive expansion" in issues[0].message


def test_tar_stream_does_not_retain_processed_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Python 3.11 streaming API cannot grow its internal member cache."""
    archive_path = tmp_path / "demo-1.0.tar.gz"
    _tar_sdist(
        archive_path,
        [
            ("demo-1.0/first.txt", b"first"),
            ("demo-1.0/second.txt", b"second"),
            ("demo-1.0/PKG-INFO", _metadata()),
        ],
    )
    original_next = tarfile.TarFile.next
    cached_counts: list[int] = []

    def monitored_next(archive: tarfile.TarFile) -> tarfile.TarInfo | None:
        member = original_next(archive)
        cached_counts.append(len(archive.members))
        return member

    monkeypatch.setattr(tarfile.TarFile, "next", monitored_next)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert issues == ()
    assert len(artifacts) == 1
    assert max(cached_counts) <= 1


def test_tar_declared_and_control_sizes_fail_before_payload_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Huge members and control records are rejected from their headers."""
    oversized_member = tarfile.TarInfo("demo-1.0/payload.bin")
    oversized_member.size = 2_048
    member_archive = tmp_path / "member-1.0.tar.gz"
    member_archive.write_bytes(gzip.compress(oversized_member.tobuf() + b"\0" * 1_024))
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_EXPANDED_BYTES", 1_024)

    artifacts, issues = inspect_dependency_metadata((member_archive,), root=tmp_path)

    assert artifacts == ()
    assert "expanded data" in issues[0].message

    control = tarfile.TarInfo("././@PaxHeader")
    control.type = tarfile.XHDTYPE
    control.size = 65
    control_archive = tmp_path / "control-1.0.tar.gz"
    control_archive.write_bytes(gzip.compress(control.tobuf() + b"\0" * 1_024))
    monkeypatch.setattr(dependency_module, "_MAX_ARCHIVE_EXPANDED_BYTES", 4_096)
    monkeypatch.setattr(dependency_module, "_MAX_TAR_CONTROL_BYTES", 64)

    artifacts, issues = inspect_dependency_metadata((control_archive,), root=tmp_path)

    assert artifacts == ()
    assert "control metadata" in issues[0].message


@pytest.mark.parametrize("control_type", [tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE])
def test_pax_gnu_sparse_is_rejected_before_tarfile_processing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_type: bytes,
) -> None:
    """PAX sparse directives cannot trigger tarfile's external map parser."""
    control_payload = _pax_record("GNU.sparse.major", "1")
    control = tarfile.TarInfo("././@PaxHeader")
    control.type = control_type
    control.size = len(control_payload)
    padding = (-len(control_payload)) % 512
    archive_path = tmp_path / "sparse-1.0.tar.gz"
    archive_path.write_bytes(
        gzip.compress(
            control.tobuf() + control_payload + b"\0" * padding + b"\0" * 1_024
        )
    )

    def forbidden_tarfile(*_args: object, **_kwargs: object) -> None:
        message = "GNU sparse PAX data must fail during physical preflight"
        raise AssertionError(message)

    monkeypatch.setattr(tarfile, "open", forbidden_tarfile)

    artifacts, issues = inspect_dependency_metadata((archive_path,), root=tmp_path)

    assert artifacts == ()
    assert "GNU sparse" in issues[0].message


@pytest.mark.parametrize(
    ("members", "message"),
    [
        (
            [
                ("demo-1.0.dist-info/METADATA", _metadata()),
                ("demo-1.0.dist-info/RECORD", b""),
            ],
            "exactly one WHEEL",
        ),
        (
            [
                ("demo-1.0.dist-info/METADATA", _metadata()),
                (
                    "demo-1.0.dist-info/WHEEL",
                    b"Wheel-Version: 1.0\nTag: py3-none-any\n",
                ),
            ],
            "exactly one RECORD",
        ),
        (
            [
                ("wrong-1.0.dist-info/METADATA", _metadata()),
                (
                    "wrong-1.0.dist-info/WHEEL",
                    b"Wheel-Version: 1.0\nTag: py3-none-any\n",
                ),
                ("wrong-1.0.dist-info/RECORD", b""),
            ],
            "dist-info directory and core metadata identity disagree",
        ),
        (
            [
                ("demo-1.0.dist-info/METADATA", _metadata()),
                (
                    "demo-1.0.dist-info/WHEEL",
                    (
                        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
                        b"Tag: cp312-cp312-win_amd64\n"
                    ),
                ),
                ("demo-1.0.dist-info/RECORD", b""),
            ],
            "internal and filename tags disagree",
        ),
    ],
)
def test_wheel_minimum_structure_and_internal_tags_are_required(
    tmp_path: Path,
    members: Sequence[tuple[str, bytes]],
    message: str,
) -> None:
    """Malformed wheel containers cannot establish artifact availability."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _write_raw_wheel(wheel, members)

    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert artifacts == ()
    assert message in issues[0].message


@pytest.mark.parametrize(
    ("wheel_payload", "message"),
    [
        (
            b"Wheel-Version: 99.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "unsupported Wheel-Version",
        ),
        (
            b"Wheel-Version: 1.0\nTag: py3-none-any\n",
            "exactly one Root-Is-Purelib",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: yes\nTag: py3-none-any\n",
            "invalid Root-Is-Purelib",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n",
            "omits Tag",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            + b"Tag: py3-none-any\n" * 257,
            "too many Tag fields",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-\x1b\n",
            "invalid Tag",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none\n",
            "invalid Tag",
        ),
        (
            b"Wheel-Version: 1.0\x07\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            "invalid Wheel-Version",
        ),
        (
            (
                b"not-a-header\nWheel-Version: 1.0\nRoot-Is-Purelib: true\n"
                b"Tag: py3-none-any\n"
            ),
            "malformed headers",
        ),
    ],
)
def test_wheel_installation_metadata_must_be_supported(
    tmp_path: Path,
    wheel_payload: bytes,
    message: str,
) -> None:
    """A wheel an installer must reject cannot establish availability."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _write_raw_wheel(
        wheel,
        [
            ("demo-1.0.dist-info/METADATA", _metadata()),
            ("demo-1.0.dist-info/WHEEL", wheel_payload),
            ("demo-1.0.dist-info/RECORD", b""),
        ],
    )

    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert artifacts == ()
    assert len(issues) == 1
    assert message in issues[0].message


def test_metadata_input_paths_and_duplicate_selection_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metadata inputs are unique, regular, root-bounded, and byte-bounded."""
    missing = tmp_path / "missing.metadata"
    with pytest.raises(ConfigurationError, match="does not exist"):
        inspect_dependency_metadata((missing,), root=tmp_path)

    with pytest.raises(ConfigurationError, match="regular file"):
        inspect_dependency_metadata((tmp_path,), root=tmp_path)

    outside = tmp_path.parent / f"{tmp_path.name}-outside.metadata"
    outside.write_bytes(_metadata())
    with pytest.raises(ConfigurationError, match="beneath the project root"):
        inspect_dependency_metadata((outside,), root=tmp_path)

    selected = tmp_path / "demo.metadata"
    selected.write_bytes(_metadata())
    with pytest.raises(ConfigurationError, match="duplicate paths"):
        inspect_dependency_metadata((selected, selected), root=tmp_path)

    monkeypatch.setattr(dependency_module, "_MAX_ARTIFACT_BYTES", 1)
    with pytest.raises(ConfigurationError, match="exceeds"):
        inspect_dependency_metadata((selected,), root=tmp_path)


def test_metadata_input_replacement_during_open_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opened descriptor must identify the regular file that was checked."""
    if not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("requires POSIX directory-relative descriptor reads")
    selected = tmp_path / "demo.metadata"
    replacement = tmp_path / "replacement.metadata"
    selected.write_bytes(_metadata())
    replacement.write_bytes(_metadata(identity=("replacement", "2.0")))
    selected_resolved = selected.resolve()
    real_open = rooted_reader_module.os.open

    def replace_before_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if (
            path == selected_resolved.name
            and dir_fd is not None
            and replacement.exists()
        ):
            replacement.replace(selected)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", replace_before_open)
    monkeypatch.setattr(
        rooted_reader_module, "supports_rooted_descriptor_reads", lambda: True
    )

    with pytest.raises(ConfigurationError, match="changed while being read"):
        inspect_dependency_metadata((selected,), root=tmp_path)


def test_metadata_input_mutation_during_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One report cannot combine bytes from two in-place file states."""
    if not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("secure directory-relative reads are unavailable")
    selected = tmp_path / "demo.metadata"
    selected.write_bytes(b"A" * 70_000)
    original_read = rooted_reader_module.os.read
    mutated = False

    def mutate_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        payload = original_read(descriptor, size)
        if payload and not mutated:
            mutated = True
            selected.write_bytes(b"B" * 70_000)
        return payload

    monkeypatch.setattr(rooted_reader_module.os, "read", mutate_after_first_chunk)

    with pytest.raises(ConfigurationError, match="changed while being read"):
        inspect_dependency_metadata((selected,), root=tmp_path)

    assert mutated is True


def test_metadata_input_ancestor_swap_cannot_escape_pinned_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every repository ancestor is opened relative to the pinned root."""
    if not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("secure directory-relative reads are unavailable")
    project = tmp_path / "project"
    selected_parent = project / "sub"
    archived_parent = project / "sub-before-swap"
    outside = tmp_path / "outside"
    selected_parent.mkdir(parents=True)
    outside.mkdir()
    (selected_parent / "demo.metadata").write_bytes(_metadata())
    (outside / "demo.metadata").write_bytes(
        _metadata(identity=("outside-secret", "9.0"))
    )
    probe = project / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")
    probe.unlink()
    real_open = rooted_reader_module.os.open
    swapped = False

    def swap_parent_before_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "sub" and dir_fd is not None and not swapped:
            selected_parent.rename(archived_parent)
            selected_parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", swap_parent_before_open)
    monkeypatch.setattr(
        rooted_reader_module, "supports_rooted_descriptor_reads", lambda: True
    )

    with pytest.raises(ConfigurationError, match="unable to read metadata input"):
        inspect_dependency_metadata(
            (Path("sub/demo.metadata"),),
            root=project,
        )

    assert swapped is True


def test_dependency_configuration_ancestor_swap_cannot_escape_pinned_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dependency TOML uses the same descriptor-anchored repository reader."""
    if not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("secure directory-relative reads are unavailable")
    project = tmp_path / "project"
    selected_parent = project / "config"
    archived_parent = project / "config-before-swap"
    outside = tmp_path / "outside"
    selected_parent.mkdir(parents=True)
    outside.mkdir()
    (selected_parent / "pyproject.toml").write_text(
        _configuration_toml(), encoding="utf-8"
    )
    (outside / "pyproject.toml").write_text(
        _configuration_toml(requirement="outside-secret==9.0"),
        encoding="utf-8",
    )
    probe = project / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")
    probe.unlink()
    real_open = rooted_reader_module.os.open
    swapped = False

    def swap_parent_before_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == "config" and dir_fd is not None and not swapped:
            selected_parent.rename(archived_parent)
            selected_parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", swap_parent_before_open)
    monkeypatch.setattr(
        rooted_reader_module, "supports_rooted_descriptor_reads", lambda: True
    )

    with pytest.raises(ConfigurationError, match="unable to read configuration"):
        load_dependency_configuration(project, Path("config/pyproject.toml"))

    assert swapped is True


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_metadata_ancestor_reparse_swap_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows opens every input parent relative to a pinned root handle."""
    project = tmp_path / "project"
    selected_parent = project / "sub"
    archived_parent = project / "sub-before-swap"
    outside = tmp_path / "outside"
    selected_parent.mkdir(parents=True)
    outside.mkdir()
    (selected_parent / "demo.metadata").write_bytes(_metadata())
    (outside / "demo.metadata").write_bytes(
        _metadata(identity=("outside-secret", "9.0"))
    )
    probe = project / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the Windows runner cannot create directory symlinks")
    probe.unlink()
    original_open_chain = windows_output_module._open_directory_chain  # noqa: SLF001
    swapped = False

    def swap_parent_before_open(
        api: windows_output_module._WindowsAPI,
        root: Path,
        relative_parent: Path,
        *,
        for_write: bool,
    ) -> windows_output_module._WindowsDirectoryChain:
        nonlocal swapped
        selected_parent.rename(archived_parent)
        selected_parent.symlink_to(outside, target_is_directory=True)
        swapped = True
        return original_open_chain(
            api,
            root,
            relative_parent,
            for_write=for_write,
        )

    monkeypatch.setattr(
        windows_output_module,
        "_open_directory_chain",
        swap_parent_before_open,
    )

    with pytest.raises(ConfigurationError, match="unable to read metadata input"):
        inspect_dependency_metadata(
            (Path("sub/demo.metadata"),),
            root=project,
        )

    assert swapped is True


def test_core_metadata_and_wheel_only_results_keep_availability_distinct(
    tmp_path: Path,
) -> None:
    """Standalone metadata and wrong-target wheels never imply availability."""
    raw = tmp_path / "demo.metadata"
    raw.write_bytes(_metadata(requires_python=None))
    artifacts, _issues = inspect_dependency_metadata((raw,), root=tmp_path)
    assessment = assess_dependency_metadata(artifacts, target=_target(), extras=())[0]
    assert assessment.requires_python_status is RequiresPythonStatus.UNSPECIFIED
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.artifact_availability is ArtifactAvailability.UNVERIFIED

    wheel = tmp_path / "demo-1.0-cp311-cp311-win_amd64.whl"
    _wheel(wheel, tag="cp311-cp311-win_amd64")
    artifacts, _issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assessment = assess_dependency_metadata(artifacts, target=_target(), extras=())[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.artifact_availability is ArtifactAvailability.UNAVAILABLE
    assert assessment.source_build_possible is False


def test_conflicting_metadata_is_unverified_and_false_markers_are_excluded(
    tmp_path: Path,
) -> None:
    """Metadata disagreement and non-target marker branches remain visible."""
    first = tmp_path / "first.metadata"
    second = tmp_path / "second.metadata"
    first.write_bytes(
        _metadata(
            requires_python=">=3.11",
            requires_dist=('windows-only==1; sys_platform == "win32"',),
        )
    )
    second.write_bytes(_metadata(requires_python=">=3.12"))
    artifacts, _issues = inspect_dependency_metadata((first, second), root=tmp_path)
    assessment = assess_dependency_metadata(artifacts, target=_target(), extras=())[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.requires_python_status is RequiresPythonStatus.UNVERIFIED
    assert assessment.applicable_requirements == ()
    assert "disagree" in assessment.reason


def test_sdist_zip_metadata_is_inspected_without_extraction(tmp_path: Path) -> None:
    """ZIP sdists use their one PKG-INFO member without running a backend."""
    sdist = tmp_path / "demo-1.0.zip"
    _write_raw_wheel(
        sdist,
        [("demo-1.0/PKG-INFO", _metadata(requires_python=">=3.11"))],
    )
    artifacts, issues = inspect_dependency_metadata((sdist,), root=tmp_path)
    assert issues == ()
    assert artifacts[0].kind is MetadataKind.SDIST
    assert artifacts[0].metadata_path == "demo-1.0/PKG-INFO"


def test_dynamic_sdist_metadata_cannot_claim_requires_python_compatibility(
    tmp_path: Path,
) -> None:
    """Dynamic sdist fields stay incomplete without executing a backend."""
    sdist = tmp_path / "demo-1.0.tar.gz"
    _sdist(
        sdist,
        requires_python=">=9",
        dynamic=("Requires-Python",),
    )
    report = collect_dependency_report(
        _configuration(metadata_paths=(sdist,)),
        root=tmp_path,
    )
    artifact = report.metadata[0]
    assessment = report.targets[0].assessments[0]

    assert artifact.dynamic == ("requires-python",)
    assert assessment.requires_python_status is RequiresPythonStatus.UNVERIFIED
    assert assessment.artifact_availability is (
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    )
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert report.exit_code is ExitCode.INCOMPLETE


def test_legacy_source_metadata_fields_are_implicitly_dynamic(
    tmp_path: Path,
) -> None:
    """Pre-2.2 non-wheel metadata cannot make final compatibility claims."""
    sdist = tmp_path / "demo-1.0.tar.gz"
    standalone = tmp_path / "demo.metadata"
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _sdist(sdist, metadata_version="2.1", requires_python="<3")
    standalone.write_bytes(
        _metadata(
            metadata_version="2.1",
            requires_python="<3",
            requires_dist=("child==1",),
            provides_extra=("speed",),
        )
    )
    _wheel(wheel, metadata_version="2.1", requires_python="<3")

    for path in (sdist, standalone):
        report = collect_dependency_report(
            _configuration(metadata_paths=(path,)),
            root=tmp_path,
        )
        artifact = report.metadata[0]
        assessment = report.targets[0].assessments[0]
        assert artifact.dynamic == (
            "provides-extra",
            "requires-dist",
            "requires-python",
        )
        assert assessment.requires_python_status is RequiresPythonStatus.UNVERIFIED
        assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
        assert report.exit_code is ExitCode.INCOMPLETE

    wheel_report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
    )
    assert wheel_report.metadata[0].dynamic == ()
    assert (
        wheel_report.targets[0].assessments[0].status
        is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
    )
    assert wheel_report.exit_code is ExitCode.FINDINGS


def test_dynamic_wheel_metadata_is_rejected_as_incomplete(tmp_path: Path) -> None:
    """Built wheel metadata cannot retain source-only Dynamic declarations."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _write_raw_wheel(
        wheel,
        [
            (
                "demo-1.0.dist-info/METADATA",
                _metadata(dynamic=("Requires-Dist",)),
            )
        ],
    )
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert artifacts == ()
    assert "must not declare Dynamic" in issues[0].message


def test_resolver_unavailable_identity_and_execution_failures_are_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adapter/tool failures never become resolution incompatibility."""
    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: None)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "unavailable" in result.reason

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(
        dependency_module,
        "_run_bounded_process",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", ""),
    )
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "identify" in result.reason

    def os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(dependency_module, "_run_bounded_process", os_error)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "execute" in result.reason

    def decoding_error(*_args: object, **_kwargs: object) -> None:
        codec = "utf-8"
        reason = "invalid start byte"
        raise UnicodeDecodeError(codec, b"\xff", 0, 1, reason)

    monkeypatch.setattr(dependency_module, "_run_bounded_process", decoding_error)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "decode" in result.reason


@pytest.mark.parametrize("output", ["not a requirement", "demo>=1"])
def test_resolver_malformed_success_output_is_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output: str,
) -> None:
    """A zero resolver exit must still contain exact parseable pins."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 1.0\n", "")
        selected = Path(command[command.index("--output-file") + 1])
        selected.write_text(output + "\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False


def test_resolver_revalidates_artifact_bytes_before_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolution never substitutes bytes that differ from reported metadata."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, _issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    wheel.write_bytes(b"changed after inspection")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)

    def forbidden_process(*_args: object, **_kwargs: object) -> None:
        message = "changed artifacts must fail before resolver execution"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module, "_run_bounded_process", forbidden_process)
    result = UvResolverAdapter().resolve(
        _configuration(metadata_paths=(wheel,), resolve=True),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False
    assert "changed after direct inspection" in result.reason


def test_resolver_duplicate_filenames_and_online_local_artifacts_are_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolver staging rejects collisions and includes explicit local candidates."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, _issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    duplicate = replace(
        artifacts[0], path=PurePosixPath("nested/demo-1.0-py3-none-any.whl")
    )
    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    with pytest.raises(ConfigurationError, match="duplicate artifact identities"):
        UvResolverAdapter().resolve(
            _configuration(resolve=True, network=True),
            _target(),
            (*artifacts, duplicate),
            root=tmp_path,
        )

    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(command, 0, "uv 1.0\n", "")
        output = Path(command[command.index("--output-file") + 1])
        selected = output.parent / "artifacts" / wheel.name
        output.write_text(_pylock(("demo", "1.0", selected.as_uri())), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        artifacts,
        root=tmp_path,
    )
    assert result.status is ResolutionStatus.SUCCEEDED
    assert "--default-index" in calls[1]
    assert "--find-links" in calls[1]


def test_report_text_and_incomplete_precedence_are_visible(tmp_path: Path) -> None:
    """Human output retains exact metadata and incomplete evidence wins exits."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)), root=tmp_path
    )
    text = render_dependency_text(report)
    assert "Dependency compatibility (application; offline" in text
    assert "demo==1.0: unverified" in text
    assert report.metadata[0].artifact_id in text
    assert "Core Metadata 2.4" in text
    assert "demo-1.0-py3-none-any.whl!demo-1.0.dist-info/METADATA" in text
    assert "Resolver: not-requested" in text
    assert "resolver was not requested" in text
    assert "Resolver control: requested=false; adapter=uv; index=disabled" in text
    assert "Applicable requirements: none" in text

    invalid = tmp_path / "invalid.metadata"
    invalid.write_bytes(b"invalid")
    incomplete = collect_dependency_report(
        _configuration(metadata_paths=(invalid,)), root=tmp_path
    )
    assert "Incomplete metadata invalid.metadata" in render_dependency_text(incomplete)
    assert incomplete.exit_code is ExitCode.INCOMPLETE


def test_dependency_human_output_escapes_diagnostics_without_changing_json(
    tmp_path: Path,
) -> None:
    """Dependency diagnostics cannot inject lines or alter machine evidence."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
    )
    hostile = "line\nINJECT\x1b[2J\r\u202e\u2028\u2029"
    target = report.targets[0]
    target = replace(
        target,
        declared_requirements=(
            replace(target.declared_requirements[0], reason=hostile),
        ),
        assessments=(replace(target.assessments[0], reason=hostile),),
        resolution=replace(target.resolution, reason=hostile),
    )
    report = replace(
        report,
        targets=(target,),
        metadata_issues=(
            dependency_module.MetadataIssue(
                path=PurePosixPath(f"{hostile}.metadata"),
                message=hostile,
            ),
        ),
    )

    text = render_dependency_text(report)
    document = cast("dict[str, object]", json.loads(render_dependency_json(report)))

    assert escape_terminal_text(hostile) in text
    assert hostile not in text
    assert "\nINJECT" not in text
    for control in ("\r", "\x1b", "\u202e", "\u2028", "\u2029"):
        assert control not in text
    metadata_issues = cast("list[dict[str, object]]", document["metadata_issues"])
    assert metadata_issues == [
        {
            "incomplete": True,
            "message": hostile,
            "path": f"{hostile}.metadata",
        }
    ]
    targets = cast("list[dict[str, object]]", document["targets"])
    resolution = cast("dict[str, object]", targets[0]["resolution"])
    assert resolution["reason"] == hostile


def test_resolver_version_and_command_validation_helpers(tmp_path: Path) -> None:
    """Resolver identity and impossible online state fail closed."""
    assert dependency_module._resolver_version("two\nlines\n", "uv") is None  # noqa: SLF001
    assert dependency_module._resolver_version("pip 1.0\n", "uv") is None  # noqa: SLF001
    assert dependency_module._resolver_version("uv banana\n", "uv") is None  # noqa: SLF001
    workspace = dependency_module._ResolverWorkspace(  # noqa: SLF001
        executable="uv",
        directory=tmp_path,
        requirements=tmp_path / "requirements.in",
        output=tmp_path / "requirements.txt",
        wheelhouse=tmp_path / "wheelhouse",
    )
    broken = replace(_configuration(network=True), index_url=None)
    with pytest.raises(ConfigurationError, match="no configured index"):
        dependency_module._resolver_command(  # noqa: SLF001
            workspace, broken, _target(), has_artifacts=False
        )


def test_direct_extra_evidence_cannot_borrow_a_wrong_target_wheel(
    tmp_path: Path,
) -> None:
    """A same-version foreign wheel cannot prove an extra for this target."""
    portable = tmp_path / "demo-1.0-py3-none-any.whl"
    foreign = tmp_path / "demo-1.0-cp312-cp312-win_amd64.whl"
    _wheel(portable)
    _wheel(foreign, tag="cp312-cp312-win_amd64", provides_extra=("speed",))

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(portable, foreign),
            requirements=("demo[speed]==1.0",),
        ),
        root=tmp_path,
    )

    target = report.targets[0]
    portable_id = next(
        item.artifact_id for item in report.metadata if item.path.name == portable.name
    )
    assert target.declared_requirements[0].verified is False
    assert target.assessments[0].status is DependencyCompatibilityStatus.UNVERIFIED
    assert target.assessments[0].metadata_used == (portable_id,)
    assert report.exit_code is ExitCode.INCOMPLETE


def test_direct_extra_evidence_requires_all_viable_wheels_to_agree(
    tmp_path: Path,
) -> None:
    """One of several equally viable wheels cannot prove distribution extras."""
    portable = tmp_path / "demo-1.0-py3-none-any.whl"
    specific = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    _wheel(portable, provides_extra=("speed",))
    _wheel(specific, tag="cp312-cp312-manylinux_2_17_x86_64")
    target = _target(tags=("py3-none-any", "cp312-cp312-manylinux_2_17_x86_64"))

    report = collect_dependency_report(
        _configuration(
            target=target,
            metadata_paths=(portable, specific),
            requirements=("demo[speed]==1.0",),
        ),
        root=tmp_path,
    )

    declared = report.targets[0].declared_requirements[0]
    assert declared.matching_metadata == ()
    assert declared.verified is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_viable_wheels_with_different_dependencies_are_unverified(
    tmp_path: Path,
) -> None:
    """Direct evidence never blends dependency edges from rival wheel candidates."""
    portable = tmp_path / "demo-1.0-py3-none-any.whl"
    specific = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    _wheel(portable, requires_dist=("portable-child==1",))
    _wheel(
        specific,
        tag="cp312-cp312-manylinux_2_17_x86_64",
        requires_dist=("specific-child==1",),
    )
    target = _target(tags=("py3-none-any", "cp312-cp312-manylinux_2_17_x86_64"))
    artifacts, issues = inspect_dependency_metadata(
        (portable, specific),
        root=tmp_path,
    )

    assessment = assess_dependency_metadata(
        artifacts,
        target=target,
        extras=(),
    )[0]

    assert issues == ()
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.applicable_requirements == ()
    assert "disagree on applicable Requires-Dist" in assessment.reason


def test_disagreeing_wheel_dependencies_do_not_create_transitive_findings(
    tmp_path: Path,
) -> None:
    """A synthetic union of viable wheel metadata cannot become report evidence."""
    portable = tmp_path / "demo-1.0-py3-none-any.whl"
    specific = tmp_path / "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    _wheel(portable, requires_dist=("portable-child==1",))
    _wheel(
        specific,
        tag="cp312-cp312-manylinux_2_17_x86_64",
        requires_dist=("specific-child==1",),
    )
    target = _target(tags=("py3-none-any", "cp312-cp312-manylinux_2_17_x86_64"))

    report = collect_dependency_report(
        _configuration(
            target=target,
            metadata_paths=(portable, specific),
            requirements=("demo==1.0",),
        ),
        root=tmp_path,
    )

    assert report.targets[0].assessments[0].status is (
        DependencyCompatibilityStatus.UNVERIFIED
    )
    assert report.targets[0].transitive_requirements == ()
    assert report.exit_code is ExitCode.INCOMPLETE


def test_transitive_extra_propagation_uses_only_target_selected_metadata(
    tmp_path: Path,
) -> None:
    """A foreign wheel cannot activate or verify a selected dependency extra."""
    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    portable_other = tmp_path / "other-2.0-py3-none-any.whl"
    foreign_other = tmp_path / "other-2.0-cp312-cp312-win_amd64.whl"
    _wheel(demo, requires_dist=("other[speed]==2.0",))
    _wheel(portable_other)
    _wheel(
        foreign_other,
        tag="cp312-cp312-win_amd64",
        provides_extra=("speed",),
    )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(demo, portable_other, foreign_other),
            requirements=("demo==1.0", "other==2.0"),
        ),
        root=tmp_path,
    )

    transitive = report.targets[0].transitive_requirements[0]
    assert transitive.requirement == "other[speed]==2.0"
    assert transitive.matching_metadata == ()
    assert transitive.verified is False
    assert "Transitive other[speed]==2.0" in render_dependency_text(report)
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    "value",
    [
        "1!3.12.4",
        "3.12.4.1",
        "3.12.4+vendor",
        "3.12.4.post1",
        "3.12.4.dev1",
        "2.7.18",
    ],
)
def test_target_rejects_impossible_python_marker_versions(value: str) -> None:
    """PEP 440 forms that no Python runtime reports cannot invert constraints."""
    target = deepcopy(_target_table())
    target["python-full-version"] = value
    target["implementation-version"] = value

    with pytest.raises(ConfigurationError, match="concrete Python runtime version"):
        dependency_module._parse_target(target, 0)  # noqa: SLF001


def test_programmatic_target_cannot_bypass_runtime_version_validation(
    tmp_path: Path,
) -> None:
    """The public assessment API applies the same target rules as TOML loading."""
    target = replace(
        _target(),
        python_full_version="1!3.12.4",
        implementation_version="1!3.12.4",
    )

    with pytest.raises(ConfigurationError, match="concrete Python runtime version"):
        assess_dependency_metadata((), target=target, extras=())
    with pytest.raises(ConfigurationError, match="concrete Python runtime version"):
        UvResolverAdapter().resolve(
            _configuration(target=target, resolve=True),
            target,
            (),
            root=tmp_path,
        )


@pytest.mark.parametrize(
    "target",
    [
        replace(
            _target(),
            python_full_version="3.12.04",
            implementation_version="3.12.04",
        ),
        replace(_target(), implementation_version="3.12.04"),
        replace(_target(), resolver_platform="not-a-platform"),
        replace(_target(), compatible_tags=("cp311-cp311-linux_x86_64",)),
    ],
)
def test_programmatic_target_requires_canonical_coherent_fields(
    target: EnvironmentTarget,
) -> None:
    """Constructing the public dataclass cannot bypass closed target semantics."""
    with pytest.raises(ConfigurationError):
        assess_dependency_metadata((), target=target, extras=())


@pytest.mark.parametrize(
    ("python", "tag"),
    [
        ("3.12.4", "cp30-abi3-manylinux_2_17_x86_64"),
        ("3.0.1", "cp30-abi3-manylinux_2_17_x86_64"),
        ("3.1.1", "cp31-abi3-manylinux_2_17_x86_64"),
    ],
)
def test_impossible_pre_stable_abi_tag_cannot_prove_wheel_compatibility(
    tmp_path: Path,
    python: str,
    tag: str,
) -> None:
    """The CPython stable ABI starts at 3.2, not syntactically valid cp30/cp31."""
    wheel = tmp_path / f"demo-1.0-{tag}.whl"
    _wheel(wheel, tag=tag)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()

    with pytest.raises(ConfigurationError, match="compatible-tags"):
        assess_dependency_metadata(
            artifacts,
            target=_target(python=python, tags=(tag,)),
            extras=(),
        )


def test_compressed_compatibility_tag_expansion_is_bounded(tmp_path: Path) -> None:
    """Configured, internal, and filename tags are capped before expansion."""
    explosive = f"{'.'.join(['py3'] * 65)}-{'.'.join(['none'] * 65)}-any"
    target = deepcopy(_target_table())
    target["compatible-tags"] = [explosive]
    with pytest.raises(ConfigurationError, match="expands to too many"):
        dependency_module._parse_target(target, 0)  # noqa: SLF001

    internal = tmp_path / "internal" / "demo-1.0-py3-none-any.whl"
    internal.parent.mkdir()
    _wheel(internal, tag=explosive)
    artifacts, issues = inspect_dependency_metadata((internal,), root=tmp_path)
    assert artifacts == ()
    assert len(issues) == 1
    assert "expand to too many" in issues[0].message

    filename_tag = (
        f"{'.'.join(['py3'] * 17)}-{'.'.join(['none'] * 17)}-{'.'.join(['any'] * 15)}"
    )
    filename = tmp_path / f"demo-1.0-{filename_tag}.whl"
    _wheel(filename)
    artifacts, issues = inspect_dependency_metadata((filename,), root=tmp_path)
    assert artifacts == ()
    assert len(issues) == 1
    assert "expands to too many" in issues[0].message


def test_valid_compressed_tags_may_expand_beyond_the_raw_value_limit() -> None:
    """The 256-value input cap is distinct from the 4,096 expanded-tag cap."""
    target = deepcopy(_target_table())
    target["resolver-platform"] = "x86_64-unknown-linux-gnu"
    platforms = ".".join(f"manylinux_2_{index}_x86_64" for index in range(150))
    target["compatible-tags"] = [f"py3.py312-none-{platforms}"]

    parsed = dependency_module._parse_target(target, 0)  # noqa: SLF001

    assert len(parsed.compatible_tags) == _EXPANDED_TAG_COUNT


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ([f"py3-none-platform{index}" for index in range(257)], "too many"),
        (["py3-none-any", "py3-none-any"], "duplicate"),
        (["py3-none"], "invalid compatible tag"),
    ],
)
def test_configured_compatibility_tag_collection_is_strictly_bounded(
    values: list[str],
    message: str,
) -> None:
    """Raw count, uniqueness, and shape fail before target-tag expansion."""
    target = deepcopy(_target_table())
    target["compatible-tags"] = values

    with pytest.raises(ConfigurationError, match=message):
        dependency_module._parse_target(target, 0)  # noqa: SLF001

    if "duplicate" in message:
        manual = replace(_target(), compatible_tags=tuple(values))
        with pytest.raises(ConfigurationError, match="duplicate"):
            assess_dependency_metadata((), target=manual, extras=())


@pytest.mark.parametrize(
    "filename",
    ["invalid.whl", "demo-1.0-py3--any.whl"],
)
def test_wheel_filename_tag_shape_is_bounded_before_packaging(
    filename: str,
) -> None:
    """Malformed compressed filename tags do not reach packaging expansion."""
    with pytest.raises(ValueError, match="invalid wheel filename"):
        dependency_module._validate_wheel_filename_tag_expansion(  # noqa: SLF001
            filename
        )


def test_selected_extra_does_not_also_evaluate_the_base_marker_context(
    tmp_path: Path,
) -> None:
    """The base marker context is used only when no project extra is selected."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=('child==2; extra != "speed"',))
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    selected = assess_dependency_metadata(
        artifacts,
        target=_target(),
        extras=("speed",),
    )[0]
    base = assess_dependency_metadata(artifacts, target=_target(), extras=())[0]

    assert issues == ()
    assert selected.applicable_requirements == ()
    assert base.applicable_requirements == ('child==2; extra != "speed"',)


def test_undefined_metadata_marker_comparison_is_incomplete_evidence(
    tmp_path: Path,
) -> None:
    """A parseable but undefined marker comparison never escapes as exit 4."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=('child==1; os_name ~= "posix"',))

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
    )

    assessment = report.targets[0].assessments[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert "cannot be evaluated" in assessment.reason
    assert report.exit_code is ExitCode.INCOMPLETE


def test_candidate_distribution_requires_python_disagreement_is_unverified(
    tmp_path: Path,
) -> None:
    """An excluding wheel cannot hide a viable conflicting source candidate."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    _wheel(wheel, requires_python=">=9")
    _sdist(sdist, requires_python=">=3.11")

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel, sdist)),
        root=tmp_path,
    )

    assessment = report.targets[0].assessments[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert assessment.requires_python_status is RequiresPythonStatus.UNVERIFIED
    assert assessment.artifact_availability is ArtifactAvailability.AVAILABLE
    assert len(assessment.metadata_used) == _ARTIFACT_COUNT
    assert report.exit_code is ExitCode.INCOMPLETE


def test_dynamic_sdist_requires_dist_is_incomplete_evidence(tmp_path: Path) -> None:
    """Unknown source dependencies cannot produce a complete compatibility claim."""
    sdist = tmp_path / "demo-1.0.tar.gz"
    _sdist(sdist, dynamic=("Requires-Dist",))

    report = collect_dependency_report(
        _configuration(metadata_paths=(sdist,)),
        root=tmp_path,
    )

    assessment = report.targets[0].assessments[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert (
        assessment.artifact_availability is ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    )
    assert "Requires-Dist dynamic" in assessment.reason
    assert report.exit_code is ExitCode.INCOMPLETE


def test_sdist_metadata_member_must_match_the_distribution_identity(
    tmp_path: Path,
) -> None:
    """Nested, traversal, and unrelated PKG-INFO members are not exact evidence."""
    payload = _metadata()
    paths = (
        "unrelated/nested/PKG-INFO",
        "../demo-1.0/PKG-INFO",
        "other-1.0/PKG-INFO",
    )
    for index, member_path in enumerate(paths):
        sdist = tmp_path / f"case-{index}" / "demo-1.0.tar.gz"
        sdist.parent.mkdir()
        _tar_sdist(sdist, ((member_path, payload),))
        artifacts, issues = inspect_dependency_metadata((sdist,), root=tmp_path)
        assert artifacts == ()
        assert len(issues) == 1
        assert "PKG-INFO" in issues[0].message


def test_control_characters_are_rejected_or_sanitized(tmp_path: Path) -> None:
    """Configured labels and untrusted child diagnostics cannot control a terminal."""
    target = deepcopy(_target_table())
    target["name"] = "unsafe-\x1b[31mred"
    with pytest.raises(ConfigurationError, match="control characters"):
        dependency_module._parse_target(target, 0)  # noqa: SLF001

    workspace = tmp_path / "resolver space"
    diagnostic = f"\x1b[31mfailed\x1b[0m at {workspace.as_uri()}\x07"
    safe = dependency_module._safe_process_text(  # noqa: SLF001
        diagnostic, workspace
    )
    assert "\x1b" not in safe
    assert "\x07" not in safe
    assert str(workspace) not in safe
    assert workspace.as_uri() not in safe
    assert "<workspace>" in safe


@pytest.mark.parametrize("control", ["\x1b[31m", "\x07"])
def test_core_metadata_marker_controls_cannot_reach_text_output(
    tmp_path: Path,
    control: str,
) -> None:
    """Parseable marker strings remain untrusted terminal-facing metadata."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=(f'child==1; os_name != "{control}"',))

    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
    )

    assert report.metadata == ()
    assert len(report.metadata_issues) == 1
    assert "invalid Requires-Dist" in report.metadata_issues[0].message
    assert control not in render_dependency_text(report)
    assert report.exit_code is ExitCode.INCOMPLETE


def test_malformed_pylock_file_url_is_unverified_not_an_internal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid URL-to-path conversion cannot escape the resolver boundary."""
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.12.0\n", "")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text(
            _pylock(("demo", "1.0", "file:///tmp/%00bad.whl")),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert result.complete is False
    assert "provenance" in result.reason


def test_dependency_configuration_rejects_an_input_changed_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stable-read failures retain a deterministic configuration diagnostic."""
    project = tmp_path / "pyproject.toml"
    project.write_text(_configuration_toml(), encoding="utf-8")

    def changed_input(*_args: object) -> bytes:
        message = "input file changed while being read"
        raise OSError(message)

    monkeypatch.setattr(dependency_module, "read_rooted_bytes", changed_input)

    with pytest.raises(ConfigurationError, match="changed while being read"):
        load_dependency_configuration(tmp_path)


def test_dependency_input_and_resolver_resources_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Counts, aggregate bytes, child streams, and pylock size all fail closed."""
    project = tmp_path / "pyproject.toml"
    project.write_text(_configuration_toml(), encoding="utf-8")
    monkeypatch.setattr(dependency_module, "_MAX_CONFIGURATION_BYTES", 1)
    with pytest.raises(ConfigurationError, match="configuration exceeds"):
        load_dependency_configuration(tmp_path)

    monkeypatch.setattr(dependency_module, "_MAX_CONFIGURATION_BYTES", 2 * 1024 * 1024)
    project.write_text("value = " + "[" * 500 + "0" + "]" * 500, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="nesting is too deep"):
        load_dependency_configuration(tmp_path)
    project.write_text(_configuration_toml(), encoding="utf-8")

    config_directory = tmp_path / "config-directory"
    config_directory.mkdir()
    with pytest.raises(ConfigurationError, match="not a regular file"):
        load_dependency_configuration(tmp_path, config_directory)

    monkeypatch.setattr(dependency_module, "_MAX_METADATA_INPUTS", 0)
    with pytest.raises(ConfigurationError, match="too many"):
        load_dependency_configuration(tmp_path)

    monkeypatch.setattr(dependency_module, "_MAX_METADATA_INPUTS", 1)
    project.write_text(
        _configuration_toml().replace(
            'extras = ["speed"]',
            "extras = [" + ", ".join(f'"extra{index}"' for index in range(257)) + "]",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match=r"extras.*too many"):
        load_dependency_configuration(tmp_path)

    project.write_text(_configuration_toml(), encoding="utf-8")
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    monkeypatch.setattr(dependency_module, "_MAX_METADATA_TOTAL_BYTES", 1)
    with pytest.raises(ConfigurationError, match="aggregate input byte"):
        inspect_dependency_metadata((wheel,), root=tmp_path)

    result_path = tmp_path / "pylock.toml"
    result_path.write_text("too large", encoding="utf-8")
    monkeypatch.setattr(dependency_module, "_MAX_RESOLVER_RESULT_BYTES", 1)
    with pytest.raises(ValueError, match="size limit"):
        dependency_module._read_resolver_result(result_path)  # noqa: SLF001

    monkeypatch.setattr(dependency_module, "_MAX_RESOLVER_PACKAGES", 0)
    with pytest.raises(ValueError, match="too many packages"):
        dependency_module._resolved_packages(  # noqa: SLF001
            _pylock(("demo", "1.0", "file:///demo.whl")),
            (),
            wheelhouse=tmp_path,
        )

    empty_pylock = (
        'lock-version = "1.0"\ncreated-by = "uv"\nrequires-python = ">=3.12"\n'
    )
    assert dependency_module._resolved_packages(  # noqa: SLF001
        empty_pylock,
        (),
        wheelhouse=tmp_path,
    ) == ((), True)
    with pytest.raises(ValueError, match="package list"):
        dependency_module._resolved_packages(  # noqa: SLF001
            empty_pylock + 'packages = "invalid"\n',
            (),
            wheelhouse=tmp_path,
        )

    monkeypatch.setattr(dependency_module, "_MAX_RESOLVER_STREAM_BYTES", 16)
    with pytest.raises(RuntimeError):
        dependency_module._run_bounded_process(  # noqa: SLF001
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * 4096)",
            ],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=5,
        )


def test_bounded_process_decodes_each_stream_as_strict_utf8(tmp_path: Path) -> None:
    """Malformed child bytes are explicit incomplete evidence on every locale."""
    with pytest.raises(UnicodeDecodeError):
        dependency_module._run_bounded_process(  # noqa: SLF001
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.buffer.write(bytes([255]))",
            ],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=5,
        )


def test_bounded_process_timeout_kills_the_child_without_waiting_unbounded(
    tmp_path: Path,
) -> None:
    """The explicit deadline also bounds post-timeout process cleanup."""
    with pytest.raises(subprocess.TimeoutExpired):
        dependency_module._run_bounded_process(  # noqa: SLF001
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=0.01,
        )


@pytest.mark.skipif(os.name != "nt", reason="requires Windows Job Objects")
def test_windows_resolver_stays_suspended_until_job_assignment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolver code cannot spawn before its kill-on-close Job is assigned."""
    sentinel = tmp_path / "resolver-started"
    real_create_job = dependency_module._create_windows_kill_job  # noqa: SLF001
    assignment_observed = False

    def delayed_assignment(process: subprocess.Popen[bytes]) -> int | None:
        nonlocal assignment_observed
        time.sleep(0.25)
        assert not sentinel.exists()
        job = real_create_job(process)
        assignment_observed = job is not None
        return job

    monkeypatch.setattr(
        dependency_module,
        "_create_windows_kill_job",
        delayed_assignment,
    )
    command = f"from pathlib import Path; Path({str(sentinel)!r}).write_text('started')"

    result = dependency_module._run_bounded_process(  # noqa: SLF001
        [sys.executable, "-c", command],
        cwd=tmp_path,
        env=dict(os.environ),
        timeout=5,
    )

    assert result.returncode == 0
    assert assignment_observed is True
    assert sentinel.read_text(encoding="utf-8") == "started"


def test_interruption_before_containment_cleans_the_suspended_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real SIGINT is replayed only after process ownership is recorded."""

    class FakeProcess:
        pid = 42

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.killed = False
            self.waited = False

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            self.waited = True
            return -1

    process = FakeProcess()
    creationflags: list[int] = []

    def fake_popen(
        _command: Sequence[str], **kwargs: object
    ) -> subprocess.Popen[bytes]:
        creationflags.append(cast("int", kwargs["creationflags"]))
        dependency_module.signal.raise_signal(dependency_module.signal.SIGINT)
        return cast("subprocess.Popen[bytes]", process)

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(dependency_module.subprocess, "Popen", fake_popen)

    containment = dependency_module._ProcessContainment()  # noqa: SLF001
    with pytest.raises(KeyboardInterrupt):
        dependency_module._start_contained_process(  # noqa: SLF001
            ["resolver"],
            cwd=tmp_path,
            env={},
            containment=containment,
        )

    assert creationflags[0] & dependency_module._CREATE_SUSPENDED  # noqa: SLF001
    assert containment.process is process
    assert process.killed is True
    assert process.waited is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_interruption_during_containment_handoff_closes_the_assigned_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caller owns cleanup even when the start helper cannot return."""

    class FakeProcess:
        pid = 43

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.waited = False

        def kill(self) -> None:
            message = "assigned Job should own termination"
            raise AssertionError(message)

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            self.waited = True
            return -1

    process = FakeProcess()
    assigned_job = 99
    closed_jobs: list[int] = []

    def fake_popen(
        _command: Sequence[str], **_kwargs: object
    ) -> subprocess.Popen[bytes]:
        return cast("subprocess.Popen[bytes]", process)

    def interrupt_return(frame: FrameType, event: str, _argument: object) -> object:
        if (
            event == "return"
            and frame.f_code is dependency_module._start_contained_process.__code__  # noqa: SLF001
        ):
            raise KeyboardInterrupt
        return interrupt_return

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(dependency_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        dependency_module,
        "_create_windows_kill_job",
        lambda _process: assigned_job,
    )
    monkeypatch.setattr(
        dependency_module,
        "_resume_windows_primary_thread",
        lambda _process_id: True,
    )

    def close_job(handle: int) -> None:
        closed_jobs.append(handle)

    monkeypatch.setattr(
        dependency_module,
        "_close_windows_job",
        close_job,
    )

    previous_trace = sys.gettrace()
    sys.settrace(interrupt_return)
    try:
        with pytest.raises(KeyboardInterrupt):
            dependency_module._run_bounded_process(  # noqa: SLF001
                ["resolver"],
                cwd=tmp_path,
                env={},
                timeout=1,
            )
    finally:
        sys.settrace(previous_trace)

    assert closed_jobs == [assigned_job]
    assert process.waited is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


@pytest.mark.parametrize("failure", ["post-start-interrupt", "thread-start"])
def test_bounded_process_setup_failures_terminate_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """The caller owns containment immediately and across reader startup."""

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            return -1

    class FakeContainment:
        def __init__(self) -> None:
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

    process = FakeProcess()
    containment = FakeContainment()
    armed = False

    def fake_start(
        _command: Sequence[str],
        *,
        cwd: Path,
        env: object,
        containment: dependency_module._ProcessContainment,
    ) -> subprocess.Popen[bytes]:
        nonlocal armed
        del cwd, env
        armed = True
        containment.process = cast("subprocess.Popen[bytes]", process)
        return cast("subprocess.Popen[bytes]", process)

    def interrupt_after_start(
        frame: FrameType, event: str, _argument: object
    ) -> object:
        if (
            armed
            and event == "line"
            and frame.f_code is dependency_module._run_bounded_process.__code__  # noqa: SLF001
        ):
            raise KeyboardInterrupt
        return interrupt_after_start

    monkeypatch.setattr(dependency_module, "_start_contained_process", fake_start)
    monkeypatch.setattr(
        dependency_module,
        "_ProcessContainment",
        lambda: containment,
    )
    previous_trace = sys.gettrace()
    expected_error: type[BaseException]
    if failure == "post-start-interrupt":
        expected_error = KeyboardInterrupt
        sys.settrace(interrupt_after_start)
    else:
        expected_error = RuntimeError

        def fail_thread_start(_thread: threading.Thread) -> None:
            message = "simulated thread startup failure"
            raise RuntimeError(message)

        monkeypatch.setattr(
            dependency_module.threading.Thread, "start", fail_thread_start
        )
    try:
        with pytest.raises(expected_error):
            dependency_module._run_bounded_process(  # noqa: SLF001
                ["resolver"],
                cwd=tmp_path,
                env={},
                timeout=1,
            )
    finally:
        sys.settrace(previous_trace)

    assert containment.terminated is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_windows_job_and_suspended_thread_apis_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Job assignment and primary-thread resume use checked Windows handles."""
    calls: list[str] = []
    process_id = 123
    thread_id = 456
    job_handle = 70
    process_handle = 80
    snapshot_handle = 90
    thread_handle = 91

    class FakeFunction:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *arguments: object) -> object:
            calls.append(self.name)
            result: object = 1
            if self.name == "CreateJobObjectW":
                result = job_handle
            elif self.name == "CreateToolhelp32Snapshot":
                result = snapshot_handle
            elif self.name == "Thread32First":
                pointer_type = dependency_module.ctypes.POINTER(
                    dependency_module._ThreadEntry32  # noqa: SLF001
                )
                entry = dependency_module.ctypes.cast(
                    arguments[1], pointer_type
                ).contents
                entry.th32OwnerProcessID = process_id
                entry.th32ThreadID = thread_id
            elif self.name == "Thread32Next":
                result = 0
            elif self.name == "OpenThread":
                result = thread_handle
            return result

    class FakeKernel:
        pass

    kernel = FakeKernel()
    for name in (
        "AssignProcessToJobObject",
        "CloseHandle",
        "CreateJobObjectW",
        "CreateToolhelp32Snapshot",
        "OpenThread",
        "ResumeThread",
        "SetInformationJobObject",
        "TerminateJobObject",
        "Thread32First",
        "Thread32Next",
    ):
        setattr(kernel, name, FakeFunction(name))

    class FakeProcess:
        pid = process_id
        _handle = process_handle

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(dependency_module, "_windows_kernel32", lambda: kernel)
    process = cast("subprocess.Popen[bytes]", FakeProcess())

    created_job = dependency_module._create_windows_kill_job(process)  # noqa: SLF001
    identifiers = dependency_module._windows_process_thread_ids(  # noqa: SLF001
        process_id
    )
    resumed = dependency_module._resume_windows_primary_thread(  # noqa: SLF001
        process_id
    )
    dependency_module._close_windows_job(job_handle)  # noqa: SLF001
    dependency_module._terminate_windows_job(job_handle)  # noqa: SLF001

    assert created_job == job_handle
    assert identifiers == (thread_id,)
    assert resumed is True
    assert "AssignProcessToJobObject" in calls
    assert "ResumeThread" in calls
    assert "TerminateJobObject" in calls
    expected_close_calls = 3
    assert calls.count("CloseHandle") >= expected_close_calls


@pytest.mark.parametrize("mode", ["parent-exits", "timeout"])
def test_bounded_process_terminates_descendants_that_inherit_output_pipes(
    tmp_path: Path,
    mode: str,
) -> None:
    """Normal exit and timeout both close the complete resolver process tree."""
    sentinel = tmp_path / f"survived-{mode}"
    child_code = (
        "import time; from pathlib import Path; "
        f"time.sleep(1.5); Path({str(sentinel)!r}).write_text('alive')"
    )
    parent_code = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        + ("time.sleep(30)" if mode == "timeout" else "")
    )
    started = time.monotonic()

    if mode == "timeout":
        with pytest.raises(subprocess.TimeoutExpired):
            dependency_module._run_bounded_process(  # noqa: SLF001
                [sys.executable, "-c", parent_code],
                cwd=tmp_path,
                env=dict(os.environ),
                timeout=0.75,
            )
    else:
        result = dependency_module._run_bounded_process(  # noqa: SLF001
            [sys.executable, "-c", parent_code],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=5,
        )
        assert result.returncode == 0

    assert time.monotonic() - started < _PROCESS_TREE_BOUND_SECONDS
    time.sleep(_PROCESS_TREE_DETECTION_SECONDS)
    assert not sentinel.exists()


def test_range_conflicts_are_proven_but_solver_only_transitive_text_is_not(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only independently reproduced constraints complete a solver failure."""
    assert dependency_module._conflicting_requirement_names(  # noqa: SLF001
        ("demo<1", "demo>=2")
    ) == ("demo",)
    assert (
        dependency_module._conflicting_requirement_names(  # noqa: SLF001
            ("demo==1", "demo==1+cpu")
        )
        == ()
    )
    assert (
        dependency_module._conflicting_requirement_names(  # noqa: SLF001
            ("demo==1.0", "demo===1.0+cpu")
        )
        == ()
    )
    assert dependency_module._conflicting_requirement_names(  # noqa: SLF001
        ("demo==1+cpu", "demo==1+gpu")
    ) == ("demo",)

    range_diagnostic = (
        "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
        "  ╰─▶ Because you require demo<1 and demo>=2, your requirements are "
        "unsatisfiable.\n"
    )
    transitive_diagnostic = (
        "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
        "  ╰─▶ Because demo==1.0 depends on other<2 and you require other==2.0, "
        "your requirements are unsatisfiable.\n"
    )

    def resolve_with(diagnostic: str) -> None:
        calls = 0

        def fake_run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return subprocess.CompletedProcess(command, 0, "uv 0.12.0\n", "")
            return subprocess.CompletedProcess(command, 1, "", diagnostic)

        monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    resolve_with(range_diagnostic)
    library = replace(
        _configuration(
            requirements=("demo<1", "demo>=2"),
            resolve=True,
            network=True,
        ),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    range_result = UvResolverAdapter().resolve(library, _target(), (), root=tmp_path)
    assert range_result.status is ResolutionStatus.RESOLUTION_FAILED
    assert range_result.complete is True

    demo = tmp_path / "demo-1.0-py3-none-any.whl"
    other = tmp_path / "other-2.0-py3-none-any.whl"
    _wheel(demo, requires_dist=("other<2",))
    _wheel(other)
    artifacts, issues = inspect_dependency_metadata((demo, other), root=tmp_path)
    assert issues == ()
    resolve_with(transitive_diagnostic)
    application = _configuration(
        metadata_paths=(demo, other),
        requirements=("demo==1.0", "other==2.0"),
        resolve=True,
    )
    transitive_result = UvResolverAdapter().resolve(
        application, _target(), artifacts, root=tmp_path
    )
    assert transitive_result.status is ResolutionStatus.UNVERIFIED
    assert transitive_result.complete is False


def test_arbitrary_equality_spelling_retains_a_common_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PEP 440 equality normalization cannot create an ``===`` contradiction."""
    assert (
        dependency_module._conflicting_requirement_names(  # noqa: SLF001
            ("demo==1.0", "demo===1.0.0")
        )
        == ()
    )
    diagnostic = _UNSATISFIABLE_DIAGNOSTIC.replace(
        "demo==1.0 and demo==2.0",
        "demo==1.0 and demo===1.0.0",
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        replace(
            _configuration(
                requirements=("demo==1.0", "demo===1.0.0"),
                resolve=True,
                network=True,
            ),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
    )

    target = report.targets[0]
    assert target.resolution.status is ResolutionStatus.UNVERIFIED
    assert target.resolution.complete is False
    assert all(not item.verified for item in target.declared_requirements)
    assert report.exit_code is ExitCode.INCOMPLETE


def test_complete_library_range_conflict_is_a_report_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A named, independently contradictory library group closes its rows."""
    diagnostic = (
        "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
        "  ╰─▶ Because you require demo<1 and demo>=2, your requirements are "
        "unsatisfiable.\n"
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.12.0\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    configuration = replace(
        _configuration(
            requirements=("demo<1", "demo>=2"),
            resolve=True,
            network=True,
        ),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    report = collect_dependency_report(configuration, root=tmp_path)

    target = report.targets[0]
    assert target.resolution.status is ResolutionStatus.RESOLUTION_FAILED
    assert target.resolution.complete is True
    assert all(item.verified for item in target.declared_requirements)
    assert report.exit_code is ExitCode.FINDINGS
    schema_path = Path(__file__).parents[2] / "docs/schema/dependency-report-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(
        dependency_module.dependency_report_document(report)
    )
    partial = replace(
        report,
        targets=(
            replace(
                target,
                declared_requirements=(
                    replace(target.declared_requirements[0], verified=False),
                    *target.declared_requirements[1:],
                ),
            ),
        ),
    )
    with pytest.raises(
        ConfigurationError,
        match="complete negative contains contradictory declared evidence",
    ):
        dependency_module.dependency_report_document(partial)


@pytest.mark.parametrize(
    "requirements",
    [
        ("alpha>=1", "beta>=1"),
        ("demo>=1,<2",),
    ],
    ids=["unrelated-ranges", "satisfiable-bounds"],
)
def test_machine_document_rejects_forged_solver_contradictions(
    tmp_path: Path,
    requirements: tuple[str, ...],
) -> None:
    """Structural rows cannot replace semantic PEP 440 contradiction proof."""
    seed = tmp_path / "seed-1.0-py3-none-any.whl"
    _wheel(seed)
    configuration = replace(
        _configuration(metadata_paths=(seed,), requirements=requirements),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    report = collect_dependency_report(configuration, root=tmp_path)
    target = report.targets[0]
    failure_name = "alpha" if requirements[0].startswith("alpha") else "demo"
    forged = replace(
        report,
        resolve=True,
        targets=(
            replace(
                target,
                declared_requirements=tuple(
                    replace(item, verified=True)
                    for item in target.declared_requirements
                ),
                resolution=dependency_module._UvResolverResult(  # noqa: SLF001
                    status=ResolutionStatus.RESOLUTION_FAILED,
                    complete=True,
                    resolver="uv",
                    resolver_version="0.11.21",
                    packages=(),
                    reason="claimed contradictory roots",
                    verified_failure_names=(failure_name,),
                    verified_failure_requirements=(
                        dependency_module._failure_requirement_identities(  # noqa: SLF001
                            report.requirements,
                            frozenset({failure_name}),
                        )
                    ),
                    verified_artifact_snapshots=(
                        dependency_module._metadata_artifact_snapshots(  # noqa: SLF001
                            report.metadata
                        )
                    ),
                    verified_target_snapshot=dependency_module._target_snapshot(  # noqa: SLF001
                        target.target
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative contains contradictory declared evidence",
    ):
        dependency_module.dependency_report_document(forged)


def test_machine_document_recomputes_unrelated_rows_beside_a_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A carried conflict cannot turn an evidence-free sibling root complete."""
    diagnostic = (
        "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
        "  ╰─▶ Because you require alpha<1 and alpha>=2, your requirements are "
        "unsatisfiable.\n"
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.12.0\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        replace(
            _configuration(
                requirements=("alpha<1", "alpha>=2", "beta>=1"),
                resolve=True,
                network=True,
            ),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    assert [item.verified for item in target.declared_requirements] == [
        True,
        True,
        False,
    ]
    assert report.exit_code is ExitCode.INCOMPLETE
    dependency_module.dependency_report_document(report)
    forged = replace(
        report,
        targets=(
            replace(
                target,
                declared_requirements=(
                    *target.declared_requirements[:2],
                    replace(target.declared_requirements[2], verified=True),
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative contains contradictory declared evidence",
    ):
        dependency_module.dependency_report_document(forged)


def test_machine_document_recomputes_inactive_conflict_markers(
    tmp_path: Path,
) -> None:
    """Caller-supplied applies flags cannot activate target-inactive roots."""
    seed = tmp_path / "seed-1.0-py3-none-any.whl"
    _wheel(seed)
    requirements = (
        'alpha<1; python_version < "3"',
        'alpha>=2; python_version < "3"',
    )
    report = collect_dependency_report(
        replace(
            _configuration(metadata_paths=(seed,), requirements=requirements),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    forged = replace(
        report,
        resolve=True,
        targets=(
            replace(
                target,
                declared_requirements=tuple(
                    replace(
                        item,
                        applies=True,
                        matching_extras=("base",),
                        verified=True,
                    )
                    for item in target.declared_requirements
                ),
                resolution=dependency_module._UvResolverResult(  # noqa: SLF001
                    status=ResolutionStatus.RESOLUTION_FAILED,
                    complete=True,
                    resolver="uv",
                    resolver_version="0.12.0",
                    packages=(),
                    reason="claimed inactive contradiction",
                    verified_failure_names=("alpha",),
                    verified_failure_requirements=("alpha<1", "alpha>=2"),
                    verified_artifact_snapshots=(
                        dependency_module._metadata_artifact_snapshots(  # noqa: SLF001
                            report.metadata
                        )
                    ),
                    verified_target_snapshot=dependency_module._target_snapshot(  # noqa: SLF001
                        target.target
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative requirement identity changed after uv review",
    ):
        dependency_module.dependency_report_document(forged)


@pytest.mark.parametrize("secondary_kind", ["sdist", "metadata"])
def test_machine_document_uses_target_selected_mixed_root_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    secondary_kind: str,
) -> None:
    """Serialization uses the same semantic artifact selection as collection."""
    wheel = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(wheel)
    if secondary_kind == "sdist":
        secondary = tmp_path / "other-1.0.tar.gz"
        _sdist(secondary)
    else:
        secondary = tmp_path / "other-1.0.metadata"
        secondary.write_bytes(_metadata(identity=("other", "1.0")))
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(wheel, secondary),
            requirements=("missing==1.0", "other==1.0"),
            resolve=True,
        ),
        root=tmp_path,
    )
    declared = {
        item.requirement: item for item in report.targets[0].declared_requirements
    }

    assert declared["missing==1.0"].verified is True
    assert declared["other==1.0"].matching_metadata == (
        report.targets[0].assessments[0].metadata_used[0],
    )
    assert declared["other==1.0"].verified is True
    assert report.exit_code is ExitCode.INCOMPLETE
    dependency_module.dependency_report_document(report)


def test_machine_document_rejects_changed_failed_root_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reviewed missing-root evidence cannot be transplanted to another pin."""
    other = tmp_path / "other-1.0-py3-none-any.whl"
    _wheel(other)
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(
            command,
            1,
            "",
            _MISSING_DISTRIBUTION_DIAGNOSTIC,
        )

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(other,),
            requirements=("missing==1.0",),
            resolve=True,
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    assert target.resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    dependency_module.dependency_report_document(report)
    changed_target = _target(
        name="cp313-windows",
        python="3.13.1",
        sys_platform="win32",
        tags=("cp313-cp313-win_amd64",),
    )
    transplanted_target = replace(
        report,
        targets=(replace(target, target=changed_target),),
    )
    with pytest.raises(
        ConfigurationError,
        match="complete negative target changed after uv review",
    ):
        dependency_module.dependency_report_document(transplanted_target)

    forged = replace(
        report,
        requirements=("missing==2.0",),
        targets=(
            replace(
                target,
                declared_requirements=(
                    replace(
                        target.declared_requirements[0],
                        requirement="missing==2.0",
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative requirement identity changed after uv review",
    ):
        dependency_module.dependency_report_document(forged)


def test_machine_document_rejects_changed_conflict_constraints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reviewed contradictory constraints cannot prove a different group."""
    diagnostic = (
        "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
        "  ╰─▶ Because you require demo<1 and demo>=2, your requirements are "
        "unsatisfiable.\n"
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(command, 1, "", diagnostic)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        replace(
            _configuration(
                requirements=("demo<1", "demo>=2"),
                resolve=True,
                network=True,
            ),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    assert target.resolution.status is ResolutionStatus.RESOLUTION_FAILED
    dependency_module.dependency_report_document(report)
    forged = replace(
        report,
        requirements=("demo<1", "demo>=3"),
        targets=(
            replace(
                target,
                declared_requirements=tuple(
                    replace(item, requirement="demo>=3")
                    if item.requirement == "demo>=2"
                    else item
                    for item in target.declared_requirements
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative requirement identity changed after uv review",
    ):
        dependency_module.dependency_report_document(forged)


def test_machine_document_validates_nonnegative_metadata_models(
    tmp_path: Path,
) -> None:
    """Serialization rejects metadata models collection could never produce."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)),
        root=tmp_path,
    )
    forged = replace(
        report,
        metadata=(replace(report.metadata[0], version="2.0"),),
    )

    with pytest.raises(
        ConfigurationError,
        match="wheel filename and inspected identity disagree",
    ):
        dependency_module.dependency_report_document(forged)


def test_machine_document_recomputes_disagreeing_artifact_assessments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One candidate cannot be removed to conceal same-version disagreement."""
    first = tmp_path / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    second = tmp_path / "demo-1.0-cp311-abi3-manylinux_2_17_x86_64.whl"
    _wheel(
        first,
        tag="cp311-cp311-manylinux_2_17_x86_64",
    )
    _wheel(
        second,
        tag="cp311-abi3-manylinux_2_17_x86_64",
        requires_dist=("other==1.0",),
    )
    calls = 0

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")
        return subprocess.CompletedProcess(command, 1, "", _WRONG_ABI_DIAGNOSTIC)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(first, second),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    assessment = target.assessments[0]
    assert assessment.status is DependencyCompatibilityStatus.UNVERIFIED
    assert len(assessment.metadata_used) == _ARTIFACT_COUNT
    assert report.exit_code is ExitCode.INCOMPLETE
    dependency_module.dependency_report_document(report)

    changed_snapshot = replace(
        report,
        metadata=(
            replace(report.metadata[0], requires_python=">=9"),
            *report.metadata[1:],
        ),
    )
    assert changed_snapshot.metadata[0].artifact_id == report.metadata[0].artifact_id
    with pytest.raises(
        ConfigurationError,
        match="complete negative artifact snapshot changed after uv review",
    ):
        dependency_module.dependency_report_document(changed_snapshot)

    duplicate_identity = replace(
        report,
        metadata=(
            report.metadata[0],
            replace(
                report.metadata[1],
                artifact_id=report.metadata[0].artifact_id,
                sha256=report.metadata[0].sha256,
            ),
        ),
    )
    with pytest.raises(ConfigurationError, match="duplicate artifact identities"):
        dependency_module.dependency_report_document(duplicate_identity)

    for metadata_used in (assessment.metadata_used, assessment.metadata_used[:1]):
        forged = replace(
            report,
            targets=(
                replace(
                    target,
                    assessments=(
                        replace(
                            assessment,
                            status=DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE,
                            metadata_used=metadata_used,
                            reason="concealed candidate disagreement",
                        ),
                    ),
                ),
            ),
        )
        with pytest.raises(
            ConfigurationError,
            match="complete negative contains contradictory assessment evidence",
        ):
            dependency_module.dependency_report_document(forged)

    calls = 0
    single = collect_dependency_report(
        _configuration(
            metadata_paths=(first,),
            requirements=("demo==1.0",),
            resolve=True,
        ),
        root=tmp_path,
    )
    single_target = single.targets[0]
    assert single_target.resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    assert single.exit_code is ExitCode.FINDINGS
    dependency_module.dependency_report_document(single)
    removed_reviewed_artifact = replace(
        report,
        metadata=single.metadata,
        targets=(replace(single_target, resolution=target.resolution),),
    )
    assert removed_reviewed_artifact.exit_code is ExitCode.FINDINGS

    with pytest.raises(
        ConfigurationError,
        match="complete negative artifact inventory changed after uv review",
    ):
        dependency_module.dependency_report_document(removed_reviewed_artifact)


def test_verified_failure_snapshots_reject_reused_artifact_identity() -> None:
    """One artifact ID cannot carry two different reviewed projections."""
    artifact_id = "a" * 64
    resolution = dependency_module._UvResolverResult(  # noqa: SLF001
        status=ResolutionStatus.RESOLUTION_FAILED,
        complete=True,
        resolver="uv",
        resolver_version="0.11.21",
        packages=(),
        reason="contradictory roots",
        verified_artifact_snapshots=(
            (artifact_id, "b" * 64),
            (artifact_id, "c" * 64),
        ),
    )

    assert (
        dependency_module._verified_failure_artifact_snapshots(  # noqa: SLF001
            resolution
        )
        is None
    )


def test_machine_document_rejects_arbitrary_equality_application_closure(
    tmp_path: Path,
) -> None:
    """A forged ``===`` root cannot bypass the application's ``==`` contract."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,), requirements=("demo==1.0",)),
        root=tmp_path,
    )
    target = report.targets[0]
    forged = replace(
        report,
        resolve=True,
        requirements=("demo===1.0",),
        targets=(
            replace(
                target,
                declared_requirements=(
                    replace(
                        target.declared_requirements[0],
                        requirement="demo===1.0",
                        verified=True,
                    ),
                ),
                resolution=ResolverResult(
                    status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
                    complete=True,
                    resolver="uv",
                    resolver_version="0.11.21",
                    packages=(),
                    reason="claimed closed application inventory",
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="application requirements must use one exact == version pin",
    ):
        dependency_module.dependency_report_document(forged)


@pytest.mark.parametrize(
    ("assessment_package", "assessment_version"),
    [("other", "1.0"), ("demo", "2.0"), ("demo", "1.0")],
    ids=["different-package", "different-version", "different-metadata"],
)
def test_machine_document_binds_artifact_assessment_to_failed_root(
    tmp_path: Path,
    assessment_package: str,
    assessment_version: str,
) -> None:
    """A negative assessment cannot borrow closure from another package root."""
    other = tmp_path / "other-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
    _wheel(other, tag="cp311-cp311-manylinux_2_17_x86_64")
    report = collect_dependency_report(
        _configuration(
            metadata_paths=(other,),
            requirements=("demo==1.0", "other==1.0"),
        ),
        root=tmp_path,
    )
    target = report.targets[0]
    declared = tuple(
        replace(item, verified=True) if item.requirement == "demo==1.0" else item
        for item in target.declared_requirements
    )
    forged_assessment = replace(
        target.assessments[0],
        package=assessment_package,
        status=DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE,
        version=assessment_version,
        reason="borrowed another root's closure",
    )
    forged = replace(
        report,
        resolve=True,
        targets=(
            replace(
                target,
                assessments=(forged_assessment,),
                declared_requirements=declared,
                resolution=dependency_module._UvResolverResult(  # noqa: SLF001
                    status=ResolutionStatus.ARTIFACT_UNAVAILABLE,
                    complete=True,
                    resolver="uv",
                    resolver_version="0.11.21",
                    packages=(),
                    reason="closed inventory lacks demo==1.0",
                    verified_failure_names=("demo",),
                    verified_failure_requirements=("demo==1.0",),
                    verified_artifact_snapshots=(
                        dependency_module._metadata_artifact_snapshots(  # noqa: SLF001
                            report.metadata
                        )
                    ),
                    verified_target_snapshot=dependency_module._target_snapshot(  # noqa: SLF001
                        target.target
                    ),
                ),
            ),
        ),
    )

    with pytest.raises(
        ConfigurationError,
        match="complete negative contains contradictory assessment evidence",
    ):
        dependency_module.dependency_report_document(forged)


def test_local_version_witness_downgrades_false_adapter_conflict(
    tmp_path: Path,
) -> None:
    """A public exact pin and its local build have a common PEP 440 witness."""
    wheel = tmp_path / "demo-1+cpu-py3-none-any.whl"
    _wheel(wheel)

    class FalseConflictResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.RESOLUTION_FAILED,
                complete=True,
                resolver=self.name,
                resolver_version="0.12.0",
                packages=(),
                reason="claimed direct constraint conflict",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(wheel,),
            requirements=("demo==1", "demo==1+cpu"),
            resolve=True,
        ),
        root=tmp_path,
        resolver=FalseConflictResolver(),
    )

    resolution = report.targets[0].resolution
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_replaceable_adapter_cannot_claim_a_complete_constraint_conflict(
    tmp_path: Path,
) -> None:
    """Reviewed uv diagnostics cannot be replaced by a structured adapter claim."""
    first = tmp_path / "demo-1.0-py3-none-any.whl"
    second = tmp_path / "demo-2.0-py3-none-any.whl"
    _wheel(first)
    _wheel(second)

    class UnreviewedConflictResolver:
        name = "uv"

        def resolve(
            self,
            configuration: DependencyConfiguration,
            target: EnvironmentTarget,
            artifacts: Sequence[dependency_module.MetadataArtifact],
            *,
            root: Path,
        ) -> ResolverResult:
            del configuration, target, artifacts, root
            return ResolverResult(
                status=ResolutionStatus.RESOLUTION_FAILED,
                complete=True,
                resolver=self.name,
                resolver_version="0.11.21",
                packages=(),
                reason="claimed direct constraint conflict",
            )

    report = collect_dependency_report(
        _configuration(
            metadata_paths=(first, second),
            requirements=("demo==1.0", "demo==2.0"),
            resolve=True,
        ),
        root=tmp_path,
        resolver=UnreviewedConflictResolver(),
    )

    resolution = report.targets[0].resolution
    assert dependency_module._conflicting_requirement_names(  # noqa: SLF001
        ("demo==1.0", "demo==2.0")
    ) == ("demo",)
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert report.exit_code is ExitCode.INCOMPLETE


def test_injected_exact_uv_instance_cannot_claim_a_negative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the adapter constructed inside collection may carry reviewed proof."""
    adapter = UvResolverAdapter()

    def false_conflict(
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[dependency_module.MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        del configuration, target, artifacts, root
        return ResolverResult(
            status=ResolutionStatus.RESOLUTION_FAILED,
            complete=True,
            resolver="uv",
            resolver_version="0.11.21",
            packages=(),
            reason="claimed direct constraint conflict",
        )

    monkeypatch.setattr(adapter, "resolve", false_conflict)
    report = collect_dependency_report(
        _configuration(
            requirements=("demo==1.0", "demo==2.0"),
            resolve=True,
            network=True,
        ),
        root=tmp_path,
        resolver=adapter,
    )

    resolution = report.targets[0].resolution
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize("stale_field", ["requirements", "artifacts"])
def test_internal_uv_negative_requires_exact_reviewed_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stale_field: str,
) -> None:
    """Collection rejects private proof for different roots or staged artifacts."""

    def stale_negative(
        _self: UvResolverAdapter,
        _configuration: DependencyConfiguration,
        _target: EnvironmentTarget,
        _artifacts: Sequence[dependency_module.MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        del root
        return dependency_module._UvResolverResult(  # noqa: SLF001
            status=ResolutionStatus.RESOLUTION_FAILED,
            complete=True,
            resolver="uv",
            resolver_version="0.11.21",
            packages=(),
            reason="reviewed different resolver inputs",
            verified_failure_names=("demo",),
            verified_failure_requirements=(
                ("demo<1", "demo>=3")
                if stale_field == "requirements"
                else ("demo<1", "demo>=2")
            ),
            verified_artifact_snapshots=(
                (("f" * 64, "e" * 64),) if stale_field == "artifacts" else ()
            ),
            verified_target_snapshot=dependency_module._target_snapshot(  # noqa: SLF001
                _target
            ),
        )

    monkeypatch.setattr(UvResolverAdapter, "resolve", stale_negative)
    report = collect_dependency_report(
        replace(
            _configuration(
                requirements=("demo<1", "demo>=2"),
                resolve=True,
                network=True,
            ),
            project_kind=DependencyProjectKind.LIBRARY,
        ),
        root=tmp_path,
    )

    resolution = report.targets[0].resolution
    assert resolution.status is ResolutionStatus.UNVERIFIED
    assert resolution.complete is False
    assert resolution.reason == "resolver returned contradictory structured evidence"
    assert report.exit_code is ExitCode.INCOMPLETE


def test_dependency_text_names_the_raw_requires_python_declaration(
    tmp_path: Path,
) -> None:
    """Human output retains the exact declaration promised by the user guide."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_python=">=3.12")
    report = collect_dependency_report(
        _configuration(metadata_paths=(wheel,)), root=tmp_path
    )

    assert "Requires-Python >=3.12" in render_dependency_text(report)


def test_programmatic_configuration_cannot_bypass_loader_invariants(
    tmp_path: Path,
) -> None:
    """Every exported report boundary enforces the same closed configuration."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    valid = _configuration(metadata_paths=(wheel,))
    invalid = (
        replace(valid, requirements=("demo>=1",)),
        replace(valid, requirements=("demo==1.0", "demo==1.0")),
        replace(valid, metadata_paths=(wheel, wheel)),
        replace(valid, targets=()),
        replace(valid, timeout_seconds=float("inf")),
        replace(valid, timeout_seconds=86_400.1),
        replace(valid, resolver="custom"),
        replace(valid, index_url="https://packages.example/simple"),
    )

    for configuration in invalid:
        with pytest.raises(ConfigurationError):
            collect_dependency_report(configuration, root=tmp_path)

    normalized = collect_dependency_report(
        replace(valid, requirements=("Demo == 1.0",)),
        root=tmp_path,
    )
    assert normalized.requirements == ("Demo==1.0",)


@pytest.mark.parametrize(
    "tags",
    [
        ["cp312-cp312-manylinux_2_17_x86_64", "py3-none-any"],
        frozenset({"cp312-cp312-manylinux_2_17_x86_64", "py3-none-any"}),
        ("py3-none-any", "cp312-cp312-manylinux_2_17_x86_64"),
    ],
)
def test_programmatic_target_tags_require_canonical_tuple_order(
    tmp_path: Path,
    tags: object,
) -> None:
    """Mutable, hash-ordered, and reversed tag collections fail deterministically."""
    target = replace(
        _target(tags=("cp312-cp312-manylinux_2_17_x86_64", "py3-none-any")),
        compatible_tags=cast("tuple[str, ...]", tags),
    )

    with pytest.raises(ConfigurationError, match="compatible-tags"):
        collect_dependency_report(
            _configuration(target=target),
            root=tmp_path,
        )


def test_direct_dependency_operations_enforce_resource_caps_first(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public dataclass callers cannot bypass bounded collection or extras."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_METADATA_INPUTS", 0)
        with pytest.raises(ConfigurationError, match="too many"):
            assess_dependency_metadata(artifacts, target=_target(), extras=())

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_EXTRAS", 0)
        with pytest.raises(ConfigurationError, match="too many"):
            assess_dependency_metadata(
                (),
                target=_target(),
                extras=("unsafe\nvalue",),
            )

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_REQUIREMENTS", 0)
        invalid = replace(
            _configuration(metadata_paths=(wheel,)),
            requirements=("not a requirement",),
        )
        with pytest.raises(ConfigurationError, match="too many"):
            collect_dependency_report(invalid, root=tmp_path)


def test_marker_evaluation_products_and_aggregate_declarations_are_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Individually valid dimensions cannot multiply into unbounded marker work."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=('child==1; extra == "first"',))
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 1)
        configuration = replace(
            _configuration(
                metadata_paths=(wheel,),
                requirements=('demo==1.0; extra == "first"',),
            ),
            extras=("first", "second"),
        )
        with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
            collect_dependency_report(configuration, root=tmp_path)

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 2)
        configuration = replace(
            _configuration(metadata_paths=(wheel,)),
            extras=("first", "second"),
        )
        with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
            collect_dependency_report(configuration, root=tmp_path)

    with monkeypatch.context() as context:
        context.setattr(dependency_module, "_MAX_METADATA_REQUIREMENTS", 0)
        with pytest.raises(ConfigurationError, match="aggregate Requires-Dist"):
            assess_dependency_metadata(artifacts, target=_target(), extras=())
        with pytest.raises(ConfigurationError, match="aggregate Requires-Dist"):
            inspect_dependency_metadata((wheel,), root=tmp_path)


def test_rejected_containers_still_consume_the_aggregate_requirement_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Late identity failures cannot reset the cost of parsed Requires-Dist fields."""
    paths = tuple(tmp_path / f"demo{index}-1.0.tar.gz" for index in range(2))
    for index, path in enumerate(paths):
        identity = path.name.removesuffix(".tar.gz")
        _tar_sdist(
            path,
            [
                (
                    f"{identity}/PKG-INFO",
                    _metadata(
                        identity=(f"wrong{index}", "1.0"),
                        requires_dist=("child==1",),
                    ),
                )
            ],
        )
    monkeypatch.setattr(dependency_module, "_MAX_METADATA_REQUIREMENTS", 1)

    with pytest.raises(ConfigurationError, match="aggregate Requires-Dist"):
        inspect_dependency_metadata(paths, root=tmp_path)


def test_transitive_extra_fixed_point_shares_the_runtime_marker_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-propagating extras cannot multiply repeated marker evaluation."""
    wheel = tmp_path / "a-1.0-py3-none-any.whl"
    _wheel(
        wheel,
        provides_extra=("e0", "e1", "e2"),
        requires_dist=(
            'a[e1]==1.0; extra == "e0"',
            'a[e2]==1.0; extra == "e1"',
            'child==1.0; extra == "e2"',
        ),
    )
    monkeypatch.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 4)

    with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
        collect_dependency_report(
            _configuration(
                metadata_paths=(wheel,),
                requirements=("a[e0]==1.0",),
            ),
            root=tmp_path,
        )


def test_dependency_correlation_products_share_the_runtime_work_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Artifact-by-constraint scans cannot bypass the evaluation work cap."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    monkeypatch.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 3)

    with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
        collect_dependency_report(
            _configuration(
                metadata_paths=(wheel,),
                requirements=("demo==1.0", "demo==2.0"),
            ),
            root=tmp_path,
        )


def test_requirement_requested_extras_are_bounded_at_every_input_boundary(
    tmp_path: Path,
) -> None:
    """A single dependency edge cannot amplify work through unbounded extras."""
    extras = ",".join(f"e{index}" for index in range(257))
    requirement = f"demo[{extras}]==1.0"
    with pytest.raises(ConfigurationError, match="requests too many extras"):
        collect_dependency_report(
            replace(_configuration(), requirements=(requirement,)),
            root=tmp_path,
        )

    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_dist=(requirement,))
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert artifacts == ()
    assert len(issues) == 1
    assert "requests too many extras" in issues[0].message

    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    forged = replace(
        artifacts[0],
        requires_dist=(str(Requirement(requirement)),),
    )
    with pytest.raises(ConfigurationError, match="requests too many extras"):
        assess_dependency_metadata((forged,), target=_target(), extras=())


def test_direct_resolver_calls_share_the_runtime_work_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public adapter cannot bypass bounded conflict correlation."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "uv 0.12.6\n", "")

    monkeypatch.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 5)
    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)

    with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
        UvResolverAdapter().resolve(
            _configuration(
                metadata_paths=(wheel,),
                requirements=("demo==1.0", "demo==2.0"),
                resolve=True,
            ),
            _target(),
            artifacts,
            root=tmp_path,
        )

    assert len(calls) == 1


def test_aggregate_requested_extras_share_the_runtime_work_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many individually valid requested extras cannot amplify offline checks."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "uv 0.12.6\n", "")

    def forbidden_assessment(*_args: object, **_kwargs: object) -> None:
        message = "requested-extra work must fail before artifact assessment"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", 7)
    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: sys.executable)
    monkeypatch.setattr(dependency_module, "_run_bounded_process", fake_run)
    monkeypatch.setattr(
        dependency_module,
        "assess_dependency_metadata",
        forbidden_assessment,
    )

    with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
        UvResolverAdapter().resolve(
            _configuration(
                metadata_paths=(wheel,),
                requirements=("demo[e0,e1,e2,e3]==1.0",),
                resolve=True,
            ),
            _target(),
            artifacts,
            root=tmp_path,
        )

    assert len(calls) == 1


def test_wheel_tag_selection_shares_the_runtime_work_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated artifact-by-target tag scans cannot bypass the work cap."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    tags = tuple(f"py3-none-manylinux_2_{minor}_x86_64" for minor in range(5, 18))
    monkeypatch.setattr(dependency_module, "_MAX_MARKER_EVALUATIONS", len(tags))

    with pytest.raises(ConfigurationError, match="marker-evaluation budget"):
        assess_dependency_metadata(
            artifacts,
            target=_target(tags=tags),
            extras=(),
        )


def test_exported_metadata_boundaries_reject_invalid_roots_and_records(
    tmp_path: Path,
) -> None:
    """Malformed programmatic inputs remain closed configuration failures."""
    root_file = tmp_path / "not-a-directory"
    root_file.write_text("data", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="existing directory"):
        inspect_dependency_metadata((), root=root_file)
    with pytest.raises(ConfigurationError, match="only paths"):
        inspect_dependency_metadata(
            cast("Sequence[Path]", ("not-a-path",)),
            root=tmp_path,
        )

    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel)
    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
    assert issues == ()
    invalid_records = (
        replace(artifacts[0], version="bad!"),
        replace(artifacts[0], artifact_id="bogus", sha256="bogus"),
        replace(artifacts[0], requires_dist=("not a requirement",)),
    )
    for artifact in invalid_records:
        with pytest.raises(ConfigurationError):
            assess_dependency_metadata((artifact,), target=_target(), extras=())


def test_programmatic_artifact_container_identity_cannot_be_forged(
    tmp_path: Path,
) -> None:
    """Public assessment accepts only records the direct inspector could produce."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    sdist = tmp_path / "demo-1.0.tar.gz"
    metadata = tmp_path / "demo.metadata"
    _wheel(wheel)
    _sdist(sdist)
    metadata.write_bytes(_metadata())
    artifacts, issues = inspect_dependency_metadata(
        (wheel, sdist, metadata),
        root=tmp_path,
    )
    assert issues == ()
    by_kind = {artifact.kind: artifact for artifact in artifacts}
    wheel_artifact = by_kind[MetadataKind.WHEEL]
    sdist_artifact = by_kind[MetadataKind.SDIST]
    metadata_artifact = by_kind[MetadataKind.CORE_METADATA]

    forged = (
        replace(wheel_artifact, path=PurePosixPath("not-a-wheel.txt")),
        replace(wheel_artifact, metadata_path="unrelated/METADATA"),
        replace(
            wheel_artifact,
            metadata_path="demo-1.0.dist-info//METADATA",
        ),
        replace(
            wheel_artifact,
            metadata_path="demo-1.0.dist-info/./METADATA",
        ),
        replace(wheel_artifact, wheel_tags=("cp311-cp311-win_amd64",)),
        replace(wheel_artifact, dynamic=("requires-dist",)),
        replace(wheel_artifact, metadata_version="2.99"),
        replace(sdist_artifact, path=PurePosixPath("other-1.0.tar.gz")),
        replace(sdist_artifact, metadata_path="unrelated/PKG-INFO"),
        replace(sdist_artifact, metadata_path="demo-1.0//PKG-INFO"),
        replace(sdist_artifact, metadata_path=r"demo-1.0\PKG-INFO"),
        replace(metadata_artifact, metadata_path="unrelated.metadata"),
        replace(
            metadata_artifact,
            path=PurePosixPath("demo-1.0.tar.gz"),
            metadata_path="demo-1.0.tar.gz",
        ),
    )
    for artifact in forged:
        with pytest.raises(ConfigurationError):
            assess_dependency_metadata((artifact,), target=_target(), extras=())


def test_core_metadata_provides_extra_count_is_bounded_before_propagation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A large transitive-extra surface cannot amplify marker evaluation."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, provides_extra=("first", "second"))
    monkeypatch.setattr(dependency_module, "_MAX_EXTRAS", 1)

    artifacts, issues = inspect_dependency_metadata((wheel,), root=tmp_path)

    assert artifacts == ()
    assert len(issues) == 1
    assert "too many Provides-Extra" in issues[0].message


def test_resolver_executable_inside_the_scanned_root_is_never_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repository content cannot replace the trusted external resolver."""
    executable = tmp_path / "uv"
    executable.write_text("not executable", encoding="utf-8")
    monkeypatch.setattr(
        dependency_module.shutil, "which", lambda _name: str(executable)
    )

    def forbidden_process(*_args: object, **_kwargs: object) -> None:
        message = "repository-local resolver must not execute"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module, "_run_bounded_process", forbidden_process)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert "inside the scanned root" in result.reason


def test_resolver_wheelhouse_rejects_portable_filename_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case-insensitive filesystems cannot overwrite flattened artifacts."""
    upper = tmp_path / "upper" / "Demo-1.0-py3-none-any.whl"
    lower = tmp_path / "lower" / "demo-1.0-py3-none-any.whl"
    upper.parent.mkdir()
    lower.parent.mkdir()
    _wheel(upper)
    _wheel(lower)
    artifacts, issues = inspect_dependency_metadata((upper, lower), root=tmp_path)
    assert issues == ()
    monkeypatch.setattr(
        dependency_module.shutil,
        "which",
        lambda _name: sys.executable,
    )

    result = UvResolverAdapter().resolve(
        _configuration(
            metadata_paths=(upper, lower),
            resolve=True,
        ),
        _target(),
        artifacts,
        root=tmp_path,
    )

    assert result.status is ResolutionStatus.UNVERIFIED
    assert "portably unique" in result.reason


def test_metadata_open_failure_does_not_reflect_untrusted_path(
    tmp_path: Path,
) -> None:
    """Native open failures use a fixed label rather than an unsafe path."""
    selected = tmp_path / "missing\nname.metadata"

    with pytest.raises(ConfigurationError) as captured:
        inspect_dependency_metadata((selected,), root=tmp_path)

    message = str(captured.value)
    assert message.startswith("metadata input: ")
    assert "\n" not in message
    assert selected.name not in message


def test_metadata_symlink_is_rejected_without_reading_its_control_named_target(
    tmp_path: Path,
) -> None:
    """A stable input symlink is opaque even when its target stays in the root."""
    target = tmp_path / "evil\nname.metadata"
    try:
        target.write_bytes(_metadata())
    except OSError:
        pytest.skip("control-character filenames are unavailable")
    link = tmp_path / "safe.metadata"
    try:
        link.symlink_to(target.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ConfigurationError, match="unable to read metadata input"):
        inspect_dependency_metadata((link,), root=tmp_path)


def test_uv_host_python_fallback_warning_is_not_retained() -> None:
    """Host interpreter inventory does not make an offline reason nondeterministic."""
    warning = (
        "warning: The requested Python version 3.12.4 is not available; "
        "3.12.10 will be used to build dependencies instead.\n"
    )
    diagnostic = _UNSATISFIABLE_DIAGNOSTIC

    assert dependency_module._stable_uv_diagnostic(  # noqa: SLF001
        warning + diagnostic
    ) == dependency_module._stable_uv_diagnostic(diagnostic)  # noqa: SLF001


def test_windows_resolver_environment_and_kernel_loader_are_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows-only resolver state is isolated and loader absence fails closed."""
    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")

    environment = dependency_module._resolver_environment(tmp_path)  # noqa: SLF001

    assert environment["USERPROFILE"] == str(tmp_path / "home")
    assert environment["SYSTEMROOT"] == r"C:\Windows"
    assert (tmp_path / "home").is_dir()
    assert (tmp_path / "tmp").is_dir()
    assert (tmp_path / "cache").is_dir()

    monkeypatch.setattr(dependency_module.ctypes, "WinDLL", None, raising=False)
    with pytest.raises(OSError, match=r"^$"):
        dependency_module._windows_kernel32()  # noqa: SLF001

    sentinel = object()
    calls: list[tuple[str, bool]] = []

    def fake_loader(name: str, *, use_last_error: bool) -> object:
        calls.append((name, use_last_error))
        return sentinel

    monkeypatch.setattr(dependency_module.ctypes, "WinDLL", fake_loader)
    assert dependency_module._windows_kernel32() is sentinel  # noqa: SLF001
    assert calls == [("kernel32", True)]


def test_windows_job_creation_rejects_invalid_or_unassigned_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every failed Job setup closes its handle and refuses containment."""
    calls: list[str] = []
    results: dict[str, object] = {
        "CreateJobObjectW": 0,
        "SetInformationJobObject": 1,
        "AssignProcessToJobObject": 1,
        "CloseHandle": 1,
        "TerminateJobObject": 1,
    }

    class FakeFunction:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *_arguments: object) -> object:
            calls.append(self.name)
            return results[self.name]

    class FakeKernel:
        pass

    kernel = FakeKernel()
    for name in results:
        setattr(kernel, name, FakeFunction(name))

    class FakeProcess:
        def __init__(self, handle: object) -> None:
            self.__dict__["_handle"] = handle

    process = cast("subprocess.Popen[bytes]", FakeProcess(80))
    monkeypatch.setattr(dependency_module, "_windows_kernel32", lambda: kernel)
    monkeypatch.setattr(dependency_module, "os", _os_with_name("posix"))
    assert dependency_module._create_windows_kill_job(process) is None  # noqa: SLF001

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    assert dependency_module._create_windows_kill_job(process) is None  # noqa: SLF001
    assert "CloseHandle" not in calls

    results["CreateJobObjectW"] = 70
    results["SetInformationJobObject"] = 0
    assert dependency_module._create_windows_kill_job(process) is None  # noqa: SLF001
    assert calls[-1] == "CloseHandle"

    results["SetInformationJobObject"] = 1
    results["AssignProcessToJobObject"] = 0
    assert dependency_module._create_windows_kill_job(process) is None  # noqa: SLF001
    assert calls[-1] == "CloseHandle"

    results["AssignProcessToJobObject"] = 1
    invalid_process = cast("subprocess.Popen[bytes]", FakeProcess("not-a-handle"))
    assert dependency_module._create_windows_kill_job(invalid_process) is None  # noqa: SLF001
    assert calls[-1] == "CloseHandle"

    results["CloseHandle"] = 0
    with pytest.raises(OSError, match="CloseHandle failed"):
        dependency_module._close_windows_job(70)  # noqa: SLF001
    results["CloseHandle"] = 1
    dependency_module._close_windows_job(70)  # noqa: SLF001

    results["TerminateJobObject"] = 0
    with pytest.raises(OSError, match="TerminateJobObject failed"):
        dependency_module._terminate_windows_job(70)  # noqa: SLF001
    results["TerminateJobObject"] = 1
    dependency_module._terminate_windows_job(70)  # noqa: SLF001


def test_windows_thread_discovery_and_resume_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Snapshot, ownership, open, and resume failures cannot release a child."""
    process_id = 123
    calls: list[str] = []
    snapshot_result = 0
    next_calls = 0
    open_result = 0
    resume_result = 1

    class FakeFunction:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *arguments: object) -> object:
            nonlocal next_calls
            calls.append(self.name)
            result: object = 1
            if self.name == "CreateToolhelp32Snapshot":
                result = snapshot_result
            elif self.name in {"Thread32First", "Thread32Next"}:
                pointer_type = dependency_module.ctypes.POINTER(
                    dependency_module._ThreadEntry32  # noqa: SLF001
                )
                entry = dependency_module.ctypes.cast(
                    arguments[1], pointer_type
                ).contents
                if self.name == "Thread32First":
                    entry.th32OwnerProcessID = process_id + 1
                    entry.th32ThreadID = 10
                else:
                    next_calls += 1
                    if next_calls == 1:
                        entry.th32OwnerProcessID = process_id
                        entry.th32ThreadID = 20
                    else:
                        result = 0
            elif self.name == "OpenThread":
                result = open_result
            elif self.name == "ResumeThread":
                result = resume_result
            return result

    class FakeKernel:
        pass

    kernel = FakeKernel()
    for name in (
        "CloseHandle",
        "CreateToolhelp32Snapshot",
        "OpenThread",
        "ResumeThread",
        "Thread32First",
        "Thread32Next",
    ):
        setattr(kernel, name, FakeFunction(name))
    monkeypatch.setattr(dependency_module, "_windows_kernel32", lambda: kernel)

    assert dependency_module._windows_process_thread_ids(process_id) == ()  # noqa: SLF001
    assert "Thread32First" not in calls

    snapshot_result = 90
    assert dependency_module._windows_process_thread_ids(  # noqa: SLF001
        process_id
    ) == (20,)
    assert calls[-1] == "CloseHandle"

    monkeypatch.setattr(
        dependency_module,
        "_windows_process_thread_ids",
        lambda _process_id: (),
    )
    assert dependency_module._resume_windows_primary_thread(process_id) is False  # noqa: SLF001

    monkeypatch.setattr(
        dependency_module,
        "_windows_process_thread_ids",
        lambda _process_id: (20,),
    )
    assert dependency_module._resume_windows_primary_thread(process_id) is False  # noqa: SLF001

    open_result = 91
    resume_result = dependency_module._INVALID_DWORD  # noqa: SLF001
    assert dependency_module._resume_windows_primary_thread(process_id) is False  # noqa: SLF001
    assert calls[-1] == "CloseHandle"


class _FakeCleanupProcess:
    pid = 42

    def __init__(self) -> None:
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.kills = 0
        self.waits = 0

    def kill(self) -> None:
        self.kills += 1

    def wait(self, *, timeout: float) -> int:
        assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
        self.waits += 1
        return -1


def test_process_containment_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every owned process state terminates once without orphaning a Job tree."""
    empty = dependency_module._ProcessContainment()  # noqa: SLF001
    empty.terminate()
    empty.terminate()
    assert empty.terminated is True

    def close_failure(_handle: int) -> None:
        raise OSError

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(dependency_module, "_close_windows_job", close_failure)
    terminated_jobs: list[int] = []
    monkeypatch.setattr(
        dependency_module,
        "_terminate_windows_job",
        terminated_jobs.append,
    )
    process = _FakeCleanupProcess()
    job_owned = dependency_module._ProcessContainment()  # noqa: SLF001
    job_owned.attach_process(cast("subprocess.Popen[bytes]", process))
    job_owned.attach_windows_job(70)
    job_owned.terminate()
    assert job_owned.windows_job is None
    assert terminated_jobs == [70]
    assert process.kills == 0
    job_owned.terminate()
    assert terminated_jobs == [70]
    assert process.kills == 0

    def terminate_failure(_handle: int) -> None:
        raise OSError

    monkeypatch.setattr(
        dependency_module,
        "_terminate_windows_job",
        terminate_failure,
    )
    process = _FakeCleanupProcess()
    job_fallback = dependency_module._ProcessContainment()  # noqa: SLF001
    job_fallback.attach_process(cast("subprocess.Popen[bytes]", process))
    job_fallback.attach_windows_job(73)
    job_fallback.terminate()
    assert process.kills == 1

    process = _FakeCleanupProcess()

    def failed_killpg(_process_id: int, _signal: int) -> None:
        raise OSError

    monkeypatch.setattr(dependency_module, "os", _os_with_name("posix"))
    monkeypatch.setattr(
        dependency_module.os,
        "killpg",
        failed_killpg,
        raising=False,
    )
    process_owned = dependency_module._ProcessContainment()  # noqa: SLF001
    process_owned.attach_process(cast("subprocess.Popen[bytes]", process))
    process_owned.terminate()
    assert process.kills == 1


def test_process_containment_retries_after_interrupted_job_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupted Job disposal cannot poison the later cleanup retry."""
    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    process = _FakeCleanupProcess()
    containment = dependency_module._ProcessContainment()  # noqa: SLF001
    containment.attach_process(cast("subprocess.Popen[bytes]", process))
    job_handle = 70
    expected_attempts = 2
    containment.attach_windows_job(job_handle)
    attempts = 0

    def interrupted_once(handle: int) -> bool:
        nonlocal attempts
        attempts += 1
        assert handle == job_handle
        if attempts == 1:
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(
        dependency_module,
        "_dispose_windows_job",
        interrupted_once,
    )

    with pytest.raises(KeyboardInterrupt):
        containment.terminate()
    assert containment.terminated is False
    assert containment.windows_job == job_handle
    assert process.kills == 0

    containment.terminate()

    assert attempts == expected_attempts
    assert containment.terminated is True
    assert containment.windows_job is None
    assert process.kills == 0


def test_preownership_cleanup_terminates_and_closes_process_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pre-handoff cleanup terminates the Job tree and closes process streams."""
    closed_jobs: list[int] = []
    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(
        dependency_module,
        "_close_windows_job",
        closed_jobs.append,
    )
    unowned = _FakeCleanupProcess()
    dependency_module._cleanup_uncontained_process(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", unowned), 71
    )
    assert closed_jobs == [71]
    assert unowned.kills == 0
    assert unowned.waits == 1
    assert unowned.stdout.closed is True
    assert unowned.stderr.closed is True

    def close_failure(_handle: int) -> None:
        raise OSError

    monkeypatch.setattr(dependency_module, "_close_windows_job", close_failure)
    terminated_jobs: list[int] = []
    terminated_jobs.clear()
    monkeypatch.setattr(
        dependency_module,
        "_terminate_windows_job",
        terminated_jobs.append,
    )
    fallback = _FakeCleanupProcess()
    dependency_module._cleanup_uncontained_process(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", fallback), 72
    )
    assert terminated_jobs == [72]
    assert fallback.kills == 0
    assert fallback.waits == 1
    assert fallback.stdout.closed is True
    assert fallback.stderr.closed is True


def test_preownership_cleanup_finishes_after_interrupted_job_disposal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Interrupted Job disposal is retried before re-raising the signal."""
    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    process = _FakeCleanupProcess()
    expected_attempts = 2
    attempts = 0

    def interrupted_disposal(_handle: int) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(
        dependency_module,
        "_dispose_windows_job",
        interrupted_disposal,
    )

    with pytest.raises(KeyboardInterrupt):
        dependency_module._cleanup_uncontained_process(  # noqa: SLF001
            cast("subprocess.Popen[bytes]", process),
            74,
        )

    assert attempts == expected_attempts
    assert process.kills == 0
    assert process.waits == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_preownership_cleanup_retries_an_interrupted_root_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An interrupted root kill is retried before streams are closed."""

    class InterruptedKillProcess(_FakeCleanupProcess):
        def kill(self) -> None:
            self.kills += 1
            if self.kills == 1:
                raise KeyboardInterrupt

    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    process = InterruptedKillProcess()
    expected_kills = 2

    with pytest.raises(KeyboardInterrupt):
        dependency_module._cleanup_uncontained_process(  # noqa: SLF001
            cast("subprocess.Popen[bytes]", process),
            None,
        )

    assert process.kills == expected_kills
    assert process.waits == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_preownership_cleanup_retries_an_interrupted_process_group_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POSIX interruption cannot skip the second process-group kill."""
    process = _FakeCleanupProcess()
    attempts = 0
    expected_attempts = 2

    def interrupted_killpg(_process_id: int, _signal: int) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt

    fake_os = _os_with_name("posix")
    fake_os.killpg = interrupted_killpg
    monkeypatch.setattr(dependency_module, "os", fake_os)

    with pytest.raises(KeyboardInterrupt):
        dependency_module._cleanup_uncontained_process(  # noqa: SLF001
            cast("subprocess.Popen[bytes]", process),
            None,
        )

    assert attempts == expected_attempts
    assert process.kills == 0
    assert process.waits == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_preownership_cleanup_retries_interrupted_wait_and_close() -> None:
    """Wait and stream cleanup finish before their first interruption is replayed."""

    class InterruptingStream(io.BytesIO):
        def __init__(self) -> None:
            super().__init__()
            self.close_attempts = 0

        def close(self) -> None:
            self.close_attempts += 1
            if self.close_attempts == 1:
                raise KeyboardInterrupt
            super().close()

    class InterruptingProcess(_FakeCleanupProcess):
        def __init__(self) -> None:
            super().__init__()
            self.stdout = InterruptingStream()

        def wait(self, *, timeout: float) -> int:
            super().wait(timeout=timeout)
            if self.waits == 1:
                raise KeyboardInterrupt
            return -1

    process = InterruptingProcess()
    expected_attempts = 2

    interruption = dependency_module._finish_uncontained_cleanup(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", process)
    )

    assert isinstance(interruption, KeyboardInterrupt)
    assert process.waits == expected_attempts
    assert process.stdout.close_attempts == expected_attempts
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_failed_process_start_cleans_before_and_after_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The startup cleanup helper handles both sides of the ownership handoff."""

    class FakeProcess:
        pid = 43

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.waits = 0

        def kill(self) -> None:
            message = "the Windows Job owns termination"
            raise AssertionError(message)

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            self.waits += 1
            return -1

    process = FakeProcess()
    cleanups: list[tuple[object, int | None]] = []
    containment = dependency_module._ProcessContainment()  # noqa: SLF001
    monkeypatch.setattr(
        dependency_module,
        "_cleanup_uncontained_process",
        lambda candidate, job: cleanups.append((candidate, job)),
    )
    dependency_module._cleanup_failed_process_start(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", process), 70, containment
    )
    assert cleanups == [(process, 70)]

    closed_jobs: list[int] = []
    monkeypatch.setattr(dependency_module, "_close_windows_job", closed_jobs.append)
    containment.attach_process(cast("subprocess.Popen[bytes]", process))
    dependency_module._cleanup_failed_process_start(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", process), 71, containment
    )
    assert closed_jobs == [71]
    assert process.waits == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


@pytest.mark.parametrize("job_result", [None, "error", 70])
def test_windows_contained_start_rejects_uncontained_or_unresumable_children(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    job_result: int | str | None,
) -> None:
    """A suspended child is cleaned when Job setup or thread resume fails."""
    assigned_job = 70

    class FakeProcess:
        pid = 44

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.killed = False
            self.waited = False

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            self.waited = True
            return -1

    process = FakeProcess()

    def create_job(_process: subprocess.Popen[bytes]) -> int | None:
        if job_result == "error":
            raise OSError
        return cast("int | None", job_result)

    closed_jobs: list[int] = []
    monkeypatch.setattr(dependency_module, "os", _os_with_name("nt"))
    monkeypatch.setattr(
        dependency_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: cast("subprocess.Popen[bytes]", process),
    )
    monkeypatch.setattr(dependency_module, "_create_windows_kill_job", create_job)
    monkeypatch.setattr(
        dependency_module,
        "_resume_windows_primary_thread",
        lambda _process_id: False,
    )
    monkeypatch.setattr(dependency_module, "_close_windows_job", closed_jobs.append)

    with pytest.raises(ValueError, match="unable to contain"):
        dependency_module._start_contained_process(  # noqa: SLF001
            ["resolver"],
            cwd=tmp_path,
            env={},
            containment=dependency_module._ProcessContainment(),  # noqa: SLF001
        )

    if job_result == assigned_job:
        assert closed_jobs == [assigned_job]
    else:
        assert process.killed is True
    assert process.waited is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_pipe_reader_and_reader_shutdown_failure_paths_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pipe read errors and surviving readers remain explicit bounded failures."""
    read_failure = "simulated read failure"
    expected_reader_joins = 2

    class BrokenStream:
        def read(self, _size: int) -> bytes:
            raise OSError(read_failure)

    containment = dependency_module._ProcessContainment()  # noqa: SLF001
    errors: list[OSError] = []
    dependency_module._read_process_pipe(  # noqa: SLF001
        cast("io.BufferedIOBase", BrokenStream()),
        bytearray(),
        dependency_module.threading.Event(),
        containment,
        errors,
    )
    assert str(errors[0]) == read_failure

    class FakeReader:
        ident = 1

        def __init__(self) -> None:
            self.joins = 0

        def join(self, *, timeout: float) -> None:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            self.joins += 1

        def is_alive(self) -> bool:
            return self.joins < expected_reader_joins

    class FakeProcess:
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        def wait(self, *, timeout: float) -> int:
            assert timeout == dependency_module._PROCESS_CLEANUP_SECONDS  # noqa: SLF001
            return -1

    reader = FakeReader()
    monkeypatch.setattr(containment, "terminate", lambda: None)
    survived = dependency_module._finish_process_readers(  # noqa: SLF001
        cast("subprocess.Popen[bytes]", FakeProcess()),
        containment,
        cast("Sequence[threading.Thread]", (reader,)),
    )
    assert survived is False
    assert reader.joins == expected_reader_joins
    assert FakeProcess.stdout.closed is True
    assert FakeProcess.stderr.closed is True


def test_reader_shutdown_retries_interrupted_containment_before_reraising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Final cleanup cannot abandon a tree when its first termination is interrupted."""

    class InterruptingContainment:
        def __init__(self) -> None:
            self.attempts = 0

        def terminate(self) -> None:
            self.attempts += 1
            if self.attempts == 1:
                raise KeyboardInterrupt

    interrupting = InterruptingContainment()
    containment = dependency_module._ProcessContainment()  # noqa: SLF001
    monkeypatch.setattr(containment, "terminate", interrupting.terminate)
    process = _FakeCleanupProcess()
    expected_attempts = 2

    with pytest.raises(KeyboardInterrupt):
        dependency_module._finish_process_readers(  # noqa: SLF001
            cast("subprocess.Popen[bytes]", process),
            containment,
            (),
        )

    assert interrupting.attempts == expected_attempts
    assert process.waits == 1
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_bounded_process_requires_both_output_pipes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subprocess missing either requested pipe is rejected and cleaned."""

    class FakeProcess:
        stdout = None
        stderr = io.BytesIO()

    process = cast("subprocess.Popen[bytes]", FakeProcess())

    def fake_start(
        _command: Sequence[str],
        *,
        cwd: Path,
        env: object,
        containment: dependency_module._ProcessContainment,
    ) -> subprocess.Popen[bytes]:
        del cwd, env
        containment.attach_process(process)
        return process

    cleaned: list[object] = []
    monkeypatch.setattr(dependency_module, "_start_contained_process", fake_start)
    monkeypatch.setattr(
        dependency_module,
        "_finish_process_readers",
        lambda owned, *_args: not cleaned.append(owned),
    )

    with pytest.raises(ValueError, match="unable to capture"):
        dependency_module._run_bounded_process(  # noqa: SLF001
            ["resolver"], cwd=tmp_path, env={}, timeout=1
        )
    assert cleaned == [process]
