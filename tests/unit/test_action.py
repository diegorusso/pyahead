"""The repository's GitHub Action keeps its safety and gate contracts."""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import venv
from pathlib import Path
from typing import cast

import pytest
import yaml

from pyahead.analysis import ScanRequest, scan

ACTION = Path(__file__).parents[2] / "action.yml"


def _action() -> dict[str, object]:
    document = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return cast("dict[str, object]", document)


def _steps() -> list[dict[str, object]]:
    runs = cast("dict[str, object]", _action()["runs"])
    assert runs["using"] == "composite"
    return cast("list[dict[str, object]]", runs["steps"])


def test_no_input_is_interpolated_into_a_shell_script() -> None:
    """Inputs reach scripts through the environment, never as code."""
    for step in _steps():
        script = step.get("run")
        if script is None:
            continue
        assert isinstance(script, str)
        assert "${{" not in script, step["name"]


def test_every_documented_input_reaches_the_steps() -> None:
    """An input nobody reads would be a silent no-op for the user."""
    inputs = cast("dict[str, object]", _action()["inputs"])
    used = ACTION.read_text(encoding="utf-8")
    for name in inputs:
        assert f"inputs.{name}" in used, name


def test_the_gate_runs_after_the_upload() -> None:
    """Findings reach code scanning even when they fail the job."""
    names = [step["name"] for step in _steps()]
    assert names.index("Scan") < names.index("Upload to code scanning")
    assert names.index("Upload to code scanning") < names.index("Apply the gate")
    scan = next(step for step in _steps() if step["name"] == "Scan")
    script = cast("str", scan["run"])
    assert "set +e" in script
    assert script.rstrip().endswith("exit 0")
    assert "--root ." in script


def test_used_actions_are_first_party_and_version_pinned() -> None:
    """Only GitHub's own actions, each at an explicit major or commit."""
    for step in _steps():
        uses = step.get("uses")
        if uses is None:
            continue
        assert isinstance(uses, str)
        owner_and_ref = re.fullmatch(r"(?P<owner>[^/]+)/[^@]+@(?P<ref>.+)", uses)
        assert owner_and_ref is not None, uses
        assert owner_and_ref.group("owner") in {"actions", "github"}, uses
        assert re.fullmatch(r"v\d+|[0-9a-f]{40}", owner_and_ref.group("ref")), uses


def _run_scan_step(
    root: Path,
    report: str,
    *,
    baseline: str = "3.11",
    workspace: Path | None = None,
    sarif_python: Path | None = None,
) -> str:
    bash = shutil.which("bash")
    if bash is None or sys.platform == "win32":
        pytest.skip("the composite action runs under POSIX bash")
    workspace = workspace or root.parent
    launcher = root.parent / "pyahead"
    launcher.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I -m pyahead "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o700)
    output = root.parent / "outputs"
    script = next(step["run"] for step in _steps() if step["name"] == "Scan")
    result = subprocess.run(  # noqa: S603 - repository script and controlled inputs.
        [bash, "-e", "-c", cast("str", script)],
        cwd=root,
        env={
            **os.environ,
            "PYAHEAD_BIN": str(launcher),
            "PYAHEAD_PYTHON": str(sarif_python or sys.executable),
            "PYAHEAD_BASELINE": baseline,
            "PYAHEAD_HORIZON": "3.13",
            "PYAHEAD_FAIL_ON": "",
            "PYAHEAD_CONFIDENCE": "",
            "PYAHEAD_SARIF": report,
            "PYAHEAD_PATH": root.relative_to(workspace).as_posix(),
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return output.read_text(encoding="utf-8")


@pytest.mark.parametrize("destination", ["../outside.sarif", "linked/outside.sarif"])
def test_invalid_output_preserves_files_outside_the_project(
    tmp_path: Path, destination: str
) -> None:
    """Rejected destinations cannot delete or publish an outside file."""
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.sarif"
    outside.write_text("keep me", encoding="utf-8")
    if destination.startswith("linked/"):
        if sys.platform == "win32":
            pytest.skip("symlink fixture requires POSIX")
        (root / "linked").symlink_to(tmp_path, target_is_directory=True)

    assert _run_scan_step(root, destination) == "exit-code=2\n"
    assert outside.read_text(encoding="utf-8") == "keep me"


@pytest.mark.parametrize("destination", ["old.sarif", "-"])
def test_invalid_scan_does_not_publish_a_stale_report(
    tmp_path: Path, destination: str
) -> None:
    """A failed scan or stdout destination cannot publish an older file."""
    root = tmp_path / "project"
    root.mkdir()
    old = root / destination
    old.write_text("old report", encoding="utf-8")

    outputs = _run_scan_step(
        root, destination, baseline="invalid" if destination != "-" else "3.11"
    )

    assert outputs == "exit-code=2\n"
    assert old.read_text(encoding="utf-8") == "old report"


@pytest.mark.parametrize(
    ("source", "exit_code"),
    [("VALUE = 1\n", 0), ("import imp\n", 1), ("def broken(\n", 3)],
)
def test_scan_publishes_fresh_reports_before_applying_the_gate(
    tmp_path: Path, source: str, exit_code: int
) -> None:
    """Clean, gated and incomplete scans all replace and publish their reports."""
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text(source, encoding="utf-8")
    report = root / "report.sarif"
    report.write_text("old report", encoding="utf-8")

    assert _run_scan_step(root, "report.sarif") == (
        f"exit-code={exit_code}\nsarif-file=project/report.sarif\n"
    )
    assert '"version": "2.1.0"' in report.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("project", "prefix"),
    [
        (".", ""),
        ("packages/demo", "packages/demo/"),
        ("packages/a # demo", "packages/a%20%23%20demo/"),
    ],
)
def test_report_locations_are_relative_to_the_checkout(
    tmp_path: Path, project: str, prefix: str
) -> None:
    """Results and diagnostics point into nested projects without changing identity."""
    workspace = tmp_path / "workspace"
    root = workspace / project
    root.mkdir(parents=True)
    (root / "main.py").write_text("import imp\n", encoding="utf-8")
    (root / "broken.py").write_text("def broken(\n", encoding="utf-8")
    (root / "json.py").write_text(
        "raise RuntimeError('scanned code must not execute')\n", encoding="utf-8"
    )
    original = scan(
        ScanRequest(root=root, baseline_python="3.11", horizon_python="3.13")
    )

    outputs = _run_scan_step(root, "report.sarif", workspace=workspace)

    assert outputs.startswith("exit-code=3\n")
    document = json.loads((root / "report.sarif").read_text(encoding="utf-8"))
    run = document["runs"][0]
    finding = run["results"][0]
    notification = run["invocations"][0]["toolExecutionNotifications"][0]
    assert (
        finding["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == prefix + "main.py"
    )
    assert (
        notification["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == prefix + "broken.py"
    )
    assert original.findings[0].fingerprint in finding["partialFingerprints"].values()


def test_report_outside_the_checkout_is_not_published(tmp_path: Path) -> None:
    """A project symlink cannot claim locations belong to a different checkout."""
    if sys.platform == "win32":
        pytest.skip("symlink fixture requires POSIX")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "main.py").write_text("import imp\n", encoding="utf-8")
    root = workspace / "project"
    root.symlink_to(outside, target_is_directory=True)

    assert _run_scan_step(root, "report.sarif", workspace=workspace) == "exit-code=2\n"


@pytest.mark.parametrize("project", [".", "packages/demo"])
def test_sarif_adjustment_does_not_require_installed_scanner_helpers(
    tmp_path: Path, project: str
) -> None:
    """Older scanner releases need not contain the Action's private helpers."""
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    workspace = tmp_path / "workspace"
    root = workspace / project
    root.mkdir(parents=True)
    (root / "main.py").write_text("import imp\n", encoding="utf-8")
    (root / "json.py").write_text("raise RuntimeError\n", encoding="utf-8")

    outputs = _run_scan_step(
        root,
        "report.sarif",
        workspace=workspace,
        sarif_python=environment / "bin/python",
    )

    assert outputs == f"exit-code=1\nsarif-file={project}/report.sarif\n"
    document = json.loads((root / "report.sarif").read_text(encoding="utf-8"))
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == (
        "main.py" if project == "." else f"{project}/main.py"
    )


def test_sarif_adjustment_imports_only_the_standard_library() -> None:
    """The rewrite runs under any installed release, so it cannot import PyAhead."""
    scan_step = next(step for step in _steps() if step["name"] == "Scan")
    script = cast("str", scan_step["run"])
    assert "import pyahead" not in script
    assert "from pyahead" not in script
    assert "sys.path" not in script
