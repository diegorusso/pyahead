"""M8 dependency target, metadata, and resolver boundary tests."""

from __future__ import annotations

import gzip
import io
import struct
import subprocess
import tarfile
import tomllib
import zipfile
from copy import deepcopy
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, cast

import pytest

import pyahead.dependencies as dependency_module
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
    from collections.abc import Sequence

_ARTIFACT_COUNT = 2
_RESOLVER_PROCESS_COUNT = 2
_SHA256_HEX_LENGTH = 64
_TIMEOUT_SECONDS = 2.5
_UNSATISFIABLE_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because you require demo==1.0 and demo==2.0, your requirements "
    "are unsatisfiable.\n"
)
_MISSING_DISTRIBUTION_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because missing was not found in the provided package locations and "
    "you require missing==1.0, we can conclude that your requirements are "
    "unsatisfiable.\n"
)
_MISSING_CONFLICT_DISTRIBUTION_DIAGNOSTIC = (
    "  \N{MULTIPLICATION SIGN} No solution found when resolving dependencies:\n"
    "  ╰─▶ Because demo was not found in the provided package locations and you "
    "require demo==1.0 and demo==2.0, your requirements are unsatisfiable.\n"
)


def _metadata(
    *,
    identity: tuple[str, str] = ("demo", "1.0"),
    requires_python: str | None = ">=3.12",
    requires_dist: Sequence[str] = (),
    provides_extra: Sequence[str] = (),
    dynamic: Sequence[str] = (),
) -> bytes:
    name, version = identity
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
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


def _wheel(
    path: Path,
    *,
    tag: str = "py3-none-any",
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
                identity=(name, version),
                requires_python=requires_python,
                requires_dist=requires_dist,
                provides_extra=provides_extra,
            ),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            f"Wheel-Version: 1.0\nTag: {tag}\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")


def _sdist(
    path: Path,
    *,
    requires_python: str | None = ">=3.12",
    dynamic: Sequence[str] = (),
) -> None:
    name, version = path.name.removesuffix(".tar.gz").rsplit("-", maxsplit=1)
    payload = _metadata(
        identity=(name, version),
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
        platform_machine="x86_64",
        platform_python_implementation="CPython",
        platform_system="Windows" if sys_platform == "win32" else "Linux",
        platform_release="",
        platform_version="",
        compatible_tags=tags,
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
    assert assessment.status is DependencyCompatibilityStatus.COMPATIBLE
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
    monkeypatch.setattr(dependency_module.subprocess, "run", forbidden_process)
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
    assert assessment.status is DependencyCompatibilityStatus.COMPATIBLE
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
    assert assessment.status is DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE
    assert assessment.artifact_availability is (
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    )
    assert assessment.source_build_possible is True
    assert len(assessment.metadata_used) == _ARTIFACT_COUNT


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
    assert report.exit_code is ExitCode.SUCCESS


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
    assert matching.exit_code is ExitCode.SUCCESS


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
    assert complete.exit_code is ExitCode.SUCCESS


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
    assert base.exit_code is ExitCode.SUCCESS

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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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
        DependencyCompatibilityStatus.COMPATIBLE
    )
    assert report.targets[0].resolution.status is ResolutionStatus.TIMED_OUT
    assert report.exit_code is ExitCode.INCOMPLETE


@pytest.mark.parametrize(
    ("artifact_name", "artifact_tag", "requirements"),
    [
        (None, None, ("missing==1.0",)),
        ("demo-2.0-py3-none-any.whl", "py3-none-any", ("demo==1.0",)),
        (
            "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            "cp311-cp311-manylinux_2_17_x86_64",
            ("demo==1.0",),
        ),
    ],
)
def test_closed_offline_artifact_absence_is_not_a_constraint_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    artifact_name: str | None,
    artifact_tag: str | None,
    requirements: tuple[str, ...],
) -> None:
    """Missing names, versions, and target wheels are artifact availability."""
    metadata_paths: tuple[Path, ...] = ()
    artifacts: tuple[dependency_module.MetadataArtifact, ...] = ()
    if artifact_name is not None and artifact_tag is not None:
        wheel = tmp_path / artifact_name
        _wheel(wheel, tag=artifact_tag)
        inspected, issues = inspect_dependency_metadata((wheel,), root=tmp_path)
        assert issues == ()
        metadata_paths = (wheel,)
        artifacts = inspected
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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
    assert len(calls) == 1
    assert str(tmp_path) not in result.reason


def test_missing_offline_distribution_is_a_complete_report_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed artifact inventory verifies the missing direct requirement."""

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "uv 0.11.21\n", "")

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
    report = collect_dependency_report(
        _configuration(requirements=("missing==1.0",), resolve=True),
        root=tmp_path,
    )

    target = report.targets[0]
    assert target.resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
    assert target.resolution.complete is True
    assert target.declared_requirements[0].verified is True
    assert report.exit_code is ExitCode.FINDINGS


@pytest.mark.parametrize(
    "case",
    [
        (
            "0.11.21",
            _UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.RESOLUTION_FAILED,
            True,
        ),
        ("0.11.21", "resolver crashed", ResolutionStatus.UNVERIFIED, False),
        (
            "0.11.21",
            _MISSING_CONFLICT_DISTRIBUTION_DIAGNOSTIC,
            ResolutionStatus.UNVERIFIED,
            False,
        ),
        (
            "0.12.0",
            _UNSATISFIABLE_DIAGNOSTIC,
            ResolutionStatus.UNVERIFIED,
            False,
        ),
    ],
)
def test_resolver_requires_constraints_and_versioned_solver_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, str, ResolutionStatus, bool],
) -> None:
    """Only an identified solver contradiction is compatibility failure evidence."""
    resolver_version, stderr, status, complete = case
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                command, 0, f"uv {resolver_version}\n", ""
            )
        return subprocess.CompletedProcess(command, 1, "", stderr)

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
    result = UvResolverAdapter().resolve(
        _configuration(
            requirements=("demo==1.0", "demo==2.0"),
            resolve=True,
            network=False,
        ),
        _target(),
        (),
        root=tmp_path,
    )

    assert result.status is status
    assert result.complete is complete
    assert "--offline" in calls[1]
    assert "--no-index" in calls[1]
    assert "--only-binary" in calls[1]
    assert ":all:" in calls[1]
    assert calls[1][calls[1].index("--keyring-provider") + 1] == "disabled"
    assert "--no-python-downloads" in calls[1]


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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
    configuration = replace(
        _configuration(requirements=("missing>=1",), resolve=True),
        project_kind=DependencyProjectKind.LIBRARY,
    )
    result = UvResolverAdapter().resolve(
        configuration,
        _target(),
        (),
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
    assert "library artifacts" in assessment.reason
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


def test_exact_library_requires_python_exclusion_remains_a_finding(
    tmp_path: Path,
) -> None:
    """Exact version metadata can definitively exclude a library target."""
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _wheel(wheel, requires_python=">=9")
    configuration = replace(
        _configuration(metadata_paths=(wheel,), requirements=("demo==1.0",)),
        project_kind=DependencyProjectKind.LIBRARY,
    )

    report = collect_dependency_report(configuration, root=tmp_path)

    assessment = report.targets[0].assessments[0]
    assert assessment.requires_python_status is RequiresPythonStatus.INCOMPATIBLE
    assert assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
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


def test_complete_library_resolution_accepts_compatible_same_version_artifact(
    tmp_path: Path,
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
        project_kind=DependencyProjectKind.LIBRARY,
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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
        ("python-full-version", "3.12", "include a patch"),
        ("implementation-version", "3.12", "include a patch"),
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
        (replace(_target(), sys_platform="win32"), "sys-platform"),
        (replace(_target(), platform_release="6.8"), "platform-release"),
        (
            replace(_target(), compatible_tags=("cp311-cp311-linux_x86_64",)),
            "compatible-tags",
        ),
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
    for value in (True, "one", 0, float("inf")):
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


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ('project-kind = "application"', 'project-kind = "service"', "application"),
        ("targets]]", 'targets]]\nname = "duplicate"', "TOML"),
        ('resolver = "uv"', 'resolver = "pip"', "only 'uv'"),
        ("network = false", 'network = "no"', "must be a boolean"),
        ("timeout-seconds = 2.5", "timeout-seconds = 0", "finite positive"),
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
                    b"Wheel-Version: 1.0\nTag: cp312-cp312-win_amd64\n",
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
    assert assessment.status is DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(
        dependency_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", ""),
    )
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "identify" in result.reason

    def os_error(*_args: object, **_kwargs: object) -> None:
        raise OSError

    monkeypatch.setattr(dependency_module.subprocess, "run", os_error)
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True), _target(), (), root=tmp_path
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "execute" in result.reason


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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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

    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")

    def forbidden_process(*_args: object, **_kwargs: object) -> None:
        message = "changed artifacts must fail before resolver execution"
        raise AssertionError(message)

    monkeypatch.setattr(dependency_module.subprocess, "run", forbidden_process)
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
    monkeypatch.setattr(dependency_module.shutil, "which", lambda _name: "/bin/uv")
    result = UvResolverAdapter().resolve(
        _configuration(resolve=True, network=True),
        _target(),
        (*artifacts, duplicate),
        root=tmp_path,
    )
    assert result.status is ResolutionStatus.UNVERIFIED
    assert "not unique" in result.reason

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

    monkeypatch.setattr(dependency_module.subprocess, "run", fake_run)
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
    assert "demo==1.0: compatible" in text
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


def test_resolver_version_and_command_validation_helpers(tmp_path: Path) -> None:
    """Resolver identity and impossible online state fail closed."""
    assert dependency_module._resolver_version("two\nlines\n", "uv") is None  # noqa: SLF001
    assert dependency_module._resolver_version("pip 1.0\n", "uv") is None  # noqa: SLF001
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
