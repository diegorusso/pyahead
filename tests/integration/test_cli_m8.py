"""End-to-end CLI tests for M8 dependency compatibility evidence."""

import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import cast

import pytest

from pyahead.cli import main
from pyahead.model import ExitCode


def _write_wheel(
    path: Path,
    *,
    tag: str = "py3-none-any",
    requires_python: str = ">=3.12",
    requires_dist: tuple[str, ...] = (),
    provides_extra: tuple[str, ...] = (),
) -> None:
    distribution = path.name.removesuffix(".whl").rsplit("-", maxsplit=3)[0]
    name, version = distribution.rsplit("-", maxsplit=1)
    metadata = [
        "Metadata-Version: 2.4",
        f"Name: {name}",
        f"Version: {version}",
        f"Requires-Python: {requires_python}",
    ]
    metadata.extend(f"Requires-Dist: {item}" for item in requires_dist)
    metadata.extend(f"Provides-Extra: {item}" for item in provides_extra)
    members = {
        f"{name}-{version}.dist-info/METADATA": "\n".join(metadata) + "\n\n",
        f"{name}-{version}.dist-info/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: pyahead-test\n"
            "Root-Is-Purelib: true\n"
            f"Tag: {tag}\n"
        ),
        f"{name}-{version}.dist-info/RECORD": "",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for member, payload in members.items():
            info = zipfile.ZipInfo(member, date_time=(2020, 1, 1, 0, 0, 0))
            archive.writestr(info, payload)


def _write_sdist(path: Path) -> None:
    payload = b"".join(
        (
            b"Metadata-Version: 2.4\n",
            b"Name: demo\n",
            b"Version: 1.0\n",
            b"Requires-Python: >=3.12\n\n",
        )
    )
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w") as archive:
        member = tarfile.TarInfo("demo-1.0/PKG-INFO")
        member.size = len(payload)
        member.mtime = 0
        archive.addfile(member, io.BytesIO(payload))
    path.write_bytes(gzip.compress(raw_tar.getvalue(), mtime=0))


def _write_project(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        """
[project]
name = "consumer"
version = "0"
requires-python = ">=3.11"

[tool.pyahead.dependencies]
project-kind = "application"
requirements = ["demo==1.0"]
metadata = ["wheelhouse/demo-1.0-py3-none-any.whl"]
resolve = false
network = false
timeout-seconds = 5
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
""",
        encoding="utf-8",
    )
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    _write_wheel(wheelhouse / "demo-1.0-py3-none-any.whl")


def test_dependencies_command_emits_exact_offline_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public command reports exact package and metadata identity."""
    _write_project(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INCOMPLETE)
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    metadata = cast("list[dict[str, object]]", document["metadata"])
    targets = cast("list[dict[str, object]]", document["targets"])
    assessment = cast("list[dict[str, object]]", targets[0]["assessments"])[0]

    assert captured.err == ""
    assert document["project_kind"] == "application"
    assert cast("dict[str, object]", document["controls"])["network"] is False
    assert metadata[0]["version"] == "1.0"
    assert metadata[0]["metadata_version"] == "2.4"
    assert assessment["status"] == "unverified"
    assert assessment["artifact_availability"] == "available"
    assert assessment["metadata_used"] == [metadata[0]["artifact_id"]]


def test_missing_transitive_lock_and_metadata_is_incomplete_cli_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An application cannot omit an active transitive dependency from its lock."""
    _write_project(tmp_path)
    _write_wheel(
        tmp_path / "wheelhouse" / "demo-1.0-py3-none-any.whl",
        requires_dist=("other==2.0",),
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    transitive = cast("list[dict[str, object]]", target["transitive_requirements"])

    assert transitive[0]["requirement"] == "other==2.0"
    assert transitive[0]["required_by"] == ["demo==1.0"]
    assert transitive[0]["verified"] is False
    assert "application lock" in cast("str", transitive[0]["reason"])


def test_conflicting_active_transitive_pins_are_incomplete_cli_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Individually satisfiable pins cannot hide a simultaneous contradiction."""
    _write_project(tmp_path)
    wheelhouse = tmp_path / "wheelhouse"
    _write_wheel(
        wheelhouse / "demo-1.0-py3-none-any.whl",
        requires_dist=("other==1.0", "other==2.0"),
    )
    _write_wheel(wheelhouse / "other-1.0-py3-none-any.whl")
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace(
            'requirements = ["demo==1.0"]',
            'requirements = ["demo==1.0", "other==1.0"]',
        )
        .replace(
            'metadata = ["wheelhouse/demo-1.0-py3-none-any.whl"]',
            'metadata = ["wheelhouse/demo-1.0-py3-none-any.whl", '
            '"wheelhouse/other-1.0-py3-none-any.whl"]',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    transitive = cast("list[dict[str, object]]", target["transitive_requirements"])

    assert {item["requirement"] for item in transitive} == {
        "other==1.0",
        "other==2.0",
    }
    assert all(item["verified"] is False for item in transitive)
    assert all(
        "simultaneously active" in cast("str", item["reason"]) for item in transitive
    )


def test_metadata_only_requires_python_exclusion_is_a_cli_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Metadata-only mode assesses supplied versions without requirement filters."""
    _write_project(tmp_path)
    _write_wheel(
        tmp_path / "wheelhouse" / "demo-1.0-py3-none-any.whl",
        requires_python=">=9",
    )
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            'requirements = ["demo==1.0"]', "requirements = []"
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.FINDINGS)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    metadata = cast("list[dict[str, object]]", document["metadata"])
    target = cast("list[dict[str, object]]", document["targets"])[0]
    assessments = cast("list[dict[str, object]]", target["assessments"])

    assert target["declared_requirements"] == []
    assert assessments == [
        {
            "applicable_requirements": [],
            "artifact_availability": "available",
            "metadata_used": [metadata[0]["artifact_id"]],
            "package": "demo",
            "reason": "Requires-Python excludes the declared target",
            "requires_python_status": "incompatible",
            "source_build_possible": False,
            "status": "declared-incompatible",
            "version": "1.0",
        }
    ]


def test_metadata_only_unavailable_wheel_is_incomplete_cli_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Metadata-only mode reports a supplied version without a target wheel."""
    _write_project(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace('requirements = ["demo==1.0"]', "requirements = []")
        .replace(
            'compatible-tags = ["py3-none-any"]',
            'compatible-tags = ["cp312-cp312-manylinux_2_17_x86_64"]',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    metadata = cast("list[dict[str, object]]", document["metadata"])
    target = cast("list[dict[str, object]]", document["targets"])[0]
    assessments = cast("list[dict[str, object]]", target["assessments"])

    assert target["declared_requirements"] == []
    assert assessments == [
        {
            "applicable_requirements": [],
            "artifact_availability": "unavailable",
            "metadata_used": [metadata[0]["artifact_id"]],
            "package": "demo",
            "reason": (
                "the supplied artifact sample does not establish complete target "
                "compatibility; complete resolver evidence is required"
            ),
            "requires_python_status": "compatible",
            "source_build_possible": False,
            "status": "unverified",
            "version": "1.0",
        }
    ]


def test_dependencies_command_requires_an_explicit_network_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A CLI network override cannot fall back to an ambient default index."""
    _write_project(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--network"]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "index-url" in captured.err
    assert "required when network access is enabled" in captured.err


@pytest.mark.parametrize(
    ("replacement", "match"),
    [
        (
            ('sys-platform = "linux"', 'sys-platform = "win32"'),
            "sys-platform",
        ),
        (
            (
                'implementation-name = "cpython"',
                'implementation-name = "pypy"',
            ),
            "implementation",
        ),
        (
            (
                'compatible-tags = ["py3-none-any"]',
                'compatible-tags = ["cp313-cp313-manylinux_2_17_x86_64"]',
            ),
            "Python version",
        ),
    ],
)
def test_metadata_only_rejects_incoherent_target_dimensions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    replacement: tuple[str, str],
    match: str,
) -> None:
    """Direct assessment validates platform, interpreter, and tag coherence."""
    _write_project(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(*replacement),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert match in captured.err


def test_dependencies_command_resolves_from_the_isolated_offline_wheelhouse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fresh real offline resolutions produce identical exact evidence."""
    outputs: list[str] = []
    for name in ("first", "second"):
        root = tmp_path / name
        root.mkdir()
        _write_project(root)
        project = root / "pyproject.toml"
        project.write_text(
            project.read_text(encoding="utf-8").replace(
                "resolve = false", "resolve = true"
            ),
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        assert main(["dependencies", "--format", "json"]) == int(ExitCode.SUCCESS)
        captured = capsys.readouterr()
        assert captured.err == ""
        outputs.append(captured.out)

    assert outputs[0] == outputs[1]
    document = cast("dict[str, object]", json.loads(outputs[0]))
    metadata = cast("list[dict[str, object]]", document["metadata"])
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    packages = cast("list[dict[str, object]]", resolution["packages"])

    assert resolution["status"] == "succeeded"
    assert resolution["complete"] is True
    assert cast("str", resolution["resolver_version"])
    assert packages[0]["name"] == "demo"
    assert packages[0]["version"] == "1.0"
    assert packages[0]["metadata_used"] == [metadata[0]["artifact_id"]]


@pytest.mark.parametrize(
    "provides_extra",
    [(), ("speed",)],
    ids=["missing-extra", "provided-extra"],
)
def test_offline_resolver_correlates_root_extras_with_selected_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    provides_extra: tuple[str, ...],
) -> None:
    """A resolver-selected base wheel cannot invent a requested package extra."""
    expected_verified = bool(provides_extra)
    expected_exit = ExitCode.SUCCESS if expected_verified else ExitCode.INCOMPLETE
    _write_project(tmp_path)
    wheel = tmp_path / "wheelhouse" / "demo-1.0-py3-none-any.whl"
    _write_wheel(wheel, provides_extra=provides_extra)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace('requirements = ["demo==1.0"]', 'requirements = ["demo[speed]==1.0"]')
        .replace("resolve = false", "resolve = true"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(expected_exit)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    declared = cast("list[dict[str, object]]", target["declared_requirements"])[0]

    assert resolution["status"] == "succeeded"
    assert resolution["complete"] is True
    assert declared["verified"] is expected_verified
    assert declared["resolved_versions"] == (["demo==1.0"] if expected_verified else [])


@pytest.mark.parametrize(
    "provides_extra",
    [(), ("speed",)],
    ids=["missing-extra", "provided-extra"],
)
def test_offline_resolver_correlates_transitive_extras_with_selected_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    provides_extra: tuple[str, ...],
) -> None:
    """Transitive extra evidence comes from the exact resolver-selected wheel."""
    expected_verified = bool(provides_extra)
    expected_exit = ExitCode.SUCCESS if expected_verified else ExitCode.INCOMPLETE
    _write_project(tmp_path)
    wheelhouse = tmp_path / "wheelhouse"
    _write_wheel(
        wheelhouse / "demo-1.0-py3-none-any.whl",
        requires_dist=("other[speed]==2.0",),
    )
    _write_wheel(
        wheelhouse / "other-2.0-py3-none-any.whl",
        provides_extra=provides_extra,
    )
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace(
            'requirements = ["demo==1.0"]',
            'requirements = ["demo==1.0", "other==2.0"]',
        )
        .replace(
            'metadata = ["wheelhouse/demo-1.0-py3-none-any.whl"]',
            "metadata = [\n"
            '  "wheelhouse/demo-1.0-py3-none-any.whl",\n'
            '  "wheelhouse/other-2.0-py3-none-any.whl",\n'
            "]",
        )
        .replace("resolve = false", "resolve = true"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(expected_exit)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    transitive = cast("list[dict[str, object]]", target["transitive_requirements"])[0]

    assert resolution["status"] == "succeeded"
    assert resolution["complete"] is True
    assert transitive["requirement"] == "other[speed]==2.0"
    assert transitive["verified"] is expected_verified
    assert transitive["resolved_versions"] == (
        ["other==2.0"] if expected_verified else []
    )


@pytest.mark.parametrize(
    "case",
    [
        "missing-package",
        "missing-version",
        "missing-platform-wheel",
        "sdist-only",
    ],
)
def test_offline_artifact_unavailability_is_deterministic_after_path_redaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: str,
) -> None:
    """A closed wheelhouse proves absent names, versions, and target wheels."""
    outputs: list[str] = []
    for name in ("first-failure", "second-failure"):
        root = tmp_path / f"{case}-{name}"
        root.mkdir()
        _write_project(root)
        project = root / "pyproject.toml"
        document = project.read_text(encoding="utf-8")
        if case == "missing-package":
            document = document.replace(
                'requirements = ["demo==1.0"]',
                'requirements = ["missing==1.0"]',
            )
        elif case == "missing-version":
            document = document.replace(
                'requirements = ["demo==1.0"]',
                'requirements = ["demo==2.0"]',
            )
        elif case == "missing-platform-wheel":
            portable = root / "wheelhouse" / "demo-1.0-py3-none-any.whl"
            portable.unlink()
            platform_wheel = (
                root / "wheelhouse" / "demo-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
            )
            _write_wheel(
                platform_wheel,
                tag="cp311-cp311-manylinux_2_17_x86_64",
            )
            document = document.replace(portable.name, platform_wheel.name)
        else:
            portable = root / "wheelhouse" / "demo-1.0-py3-none-any.whl"
            portable.unlink()
            sdist = root / "wheelhouse" / "demo-1.0.tar.gz"
            _write_sdist(sdist)
            document = document.replace(portable.name, sdist.name)
        project.write_text(
            document.replace("resolve = false", "resolve = true"),
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        assert main(["dependencies", "--format", "json"]) == int(ExitCode.FINDINGS)
        captured = capsys.readouterr()
        assert captured.err == ""
        outputs.append(captured.out)

    assert outputs[0] == outputs[1]
    assert "pyahead-resolver-" not in outputs[0]
    document = cast("dict[str, object]", json.loads(outputs[0]))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    declared = cast("list[dict[str, object]]", target["declared_requirements"])[0]
    assert resolution["status"] == "artifact-unavailable"
    assert resolution["complete"] is True
    assert declared["verified"] is True


def test_real_offline_constraint_conflict_is_resolution_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Versioned uv evidence plus contradictory exact pins proves a conflict."""
    _write_project(tmp_path)
    second = tmp_path / "wheelhouse" / "demo-2.0-py3-none-any.whl"
    _write_wheel(second)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace(
            'requirements = ["demo==1.0"]',
            'requirements = ["demo==1.0", "demo==2.0"]',
        )
        .replace(
            'metadata = ["wheelhouse/demo-1.0-py3-none-any.whl"]',
            "metadata = [\n"
            '  "wheelhouse/demo-1.0-py3-none-any.whl",\n'
            '  "wheelhouse/demo-2.0-py3-none-any.whl",\n'
            "]",
        )
        .replace("resolve = false", "resolve = true"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.FINDINGS)
    captured = capsys.readouterr()
    assert captured.err == ""
    document = cast("dict[str, object]", json.loads(captured.out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    declared = cast("list[dict[str, object]]", target["declared_requirements"])
    assert resolution["status"] == "resolution-failed"
    assert resolution["complete"] is True
    assert all(item["verified"] is True for item in declared)


def test_real_offline_library_range_conflict_is_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A corroborated library range contradiction is complete failure evidence."""
    _write_project(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace('project-kind = "application"', 'project-kind = "library"')
        .replace(
            'requirements = ["demo==1.0"]',
            'requirements = ["demo<1", "demo>=2"]',
        )
        .replace("resolve = false", "resolve = true"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.FINDINGS)
    captured = capsys.readouterr()
    assert captured.err == ""
    document = cast("dict[str, object]", json.loads(captured.out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    declared = cast("list[dict[str, object]]", target["declared_requirements"])
    assert resolution["status"] == "resolution-failed"
    assert resolution["complete"] is True
    assert [item["verified"] for item in declared] == [True, True]


@pytest.mark.parametrize(
    "case",
    [
        (
            {},
            {
                "cpython-only",
                "demo",
                "impl-label-only",
                "implementation-version-only",
                "linux-only",
                "linux-system-only",
                "machine-only",
                "posix-only",
                "release-empty-only",
                "version-empty-only",
            },
            "succeeded",
            ExitCode.SUCCESS,
        ),
        (
            {
                'os-name = "posix"': 'os-name = "nt"',
                'sys-platform = "linux"': 'sys-platform = "win32"',
                'platform-machine = "x86_64"': 'platform-machine = "AMD64"',
                'platform-system = "Linux"': 'platform-system = "Windows"',
                'resolver-platform = "x86_64-manylinux_2_17"': (
                    'resolver-platform = "x86_64-pc-windows-msvc"'
                ),
            },
            {
                "cpython-only",
                "demo",
                "impl-label-only",
                "implementation-version-only",
                "nt-only",
                "release-empty-only",
                "version-empty-only",
                "windows-only",
                "windows-machine-only",
                "windows-system-only",
            },
            "unverified",
            ExitCode.INCOMPLETE,
        ),
    ],
)
def test_offline_resolution_uses_declared_transitive_marker_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[dict[str, str], set[str], str, ExitCode],
) -> None:
    """Direct markers stay exact when uv cannot represent a declared target."""
    target_changes, expected_packages, expected_resolution, expected_exit = case
    _write_project(tmp_path)
    wheelhouse = tmp_path / "wheelhouse"
    _write_wheel(
        wheelhouse / "demo-1.0-py3-none-any.whl",
        requires_dist=(
            'linux-only==1.0; sys_platform == "linux"',
            'windows-only==1.0; sys_platform == "win32"',
            'cpython-only==1.0; implementation_name == "cpython"',
            'pypy-only==1.0; implementation_name == "pypy"',
            'implementation-version-only==1.0; implementation_version == "3.12.4"',
            'posix-only==1.0; os_name == "posix"',
            'nt-only==1.0; os_name == "nt"',
            'machine-only==1.0; platform_machine == "x86_64"',
            'windows-machine-only==1.0; platform_machine == "AMD64"',
            'impl-label-only==1.0; platform_python_implementation == "CPython"',
            'linux-system-only==1.0; platform_system == "Linux"',
            'windows-system-only==1.0; platform_system == "Windows"',
            'release-empty-only==1.0; platform_release == ""',
            'version-empty-only==1.0; platform_version == ""',
        ),
    )
    dependency_names = (
        "linux-only",
        "windows-only",
        "cpython-only",
        "pypy-only",
        "implementation-version-only",
        "posix-only",
        "nt-only",
        "machine-only",
        "windows-machine-only",
        "impl-label-only",
        "linux-system-only",
        "windows-system-only",
        "release-empty-only",
        "version-empty-only",
    )
    for name in dependency_names:
        distribution = name.replace("-", "_")
        _write_wheel(wheelhouse / f"{distribution}-1.0-py3-none-any.whl")
    project = tmp_path / "pyproject.toml"
    configured = (
        project.read_text(encoding="utf-8")
        .replace(
            'metadata = ["wheelhouse/demo-1.0-py3-none-any.whl"]',
            "metadata = ["
            + ", ".join(
                f'"wheelhouse/{name}-1.0-py3-none-any.whl"'
                for name in (
                    "demo",
                    *(item.replace("-", "_") for item in dependency_names),
                )
            )
            + "]",
        )
        .replace("resolve = false", "resolve = true")
    )
    for old, new in target_changes.items():
        configured = configured.replace(old, new)
    project.write_text(configured, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(expected_exit)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    packages = cast("list[dict[str, object]]", resolution["packages"])
    transitive = cast("list[dict[str, object]]", target["transitive_requirements"])
    transitive_names = {
        cast("str", item["requirement"]).partition("==")[0].replace("_", "-")
        for item in transitive
    }

    assert resolution["status"] == expected_resolution
    assert transitive_names == expected_packages - {"demo"}
    if expected_resolution == "succeeded":
        assert {cast("str", item["name"]) for item in packages} == expected_packages
    else:
        assert packages == []
        assert "Windows platform-machine" in cast("str", resolution["reason"])


def test_pypy_target_is_unverified_before_transitive_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The uv adapter does not silently resolve PyPy markers as CPython."""
    _write_project(tmp_path)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8")
        .replace('implementation-name = "cpython"', 'implementation-name = "pypy"')
        .replace(
            'platform-python-implementation = "CPython"',
            'platform-python-implementation = "PyPy"',
        )
        .replace("resolve = false", "resolve = true"),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["dependencies", "--format", "json"]) == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    target = cast("list[dict[str, object]]", document["targets"])[0]
    resolution = cast("dict[str, object]", target["resolution"])
    assert resolution["status"] == "unverified"
    assert "implementation" in cast("str", resolution["reason"])
