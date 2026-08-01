"""End-to-end tests for M1 CLI reports and exit codes."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, cast

import pytest

from pyahead.cli import main
from pyahead.model import ExitCode


def _check_args(output_format: str = "text") -> list[str]:
    return [
        "check",
        ".",
        "--baseline-python",
        "3.11",
        "--horizon-python",
        "3.13",
        "--format",
        output_format,
    ]


def test_check_exit_zero_for_complete_clean_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A complete scan with no gated finding succeeds."""
    (tmp_path / "clean.py").write_text("import pathlib\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(_check_args()) == 0
    captured = capsys.readouterr()
    assert "No known compatibility findings" in captured.out
    assert captured.err == ""


def test_check_exit_one_for_breaking_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The default breaking gate returns exit code one."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(_check_args()) == 1
    captured = capsys.readouterr()
    assert "CPY0001" in captured.out
    assert str(tmp_path) not in captured.out
    assert captured.err == ""


def test_invalid_yaml_exits_two_without_machine_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid registry input is concise and never corrupts JSON stdout."""
    registry = tmp_path / "registry"
    registry.mkdir()
    (registry / "index.yaml").write_text("rules: [", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    arguments = [*_check_args("json"), "--registry", str(registry)]

    assert main(arguments) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not valid YAML" in captured.err
    assert str(tmp_path) not in captured.err


def test_unparseable_included_source_exits_three(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Incomplete analysis outranks otherwise gated findings."""
    (tmp_path / "broken.py").write_text("if:\n", encoding="utf-8")
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(_check_args("json")) == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    scan = cast("dict[str, int]", document["scan"])
    gate = cast("dict[str, bool]", document["gate"])
    assert scan["files_incomplete"] == 1
    assert gate["failed"] is True


def test_unexpected_failure_exits_four_without_exception_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The process boundary reserves exit four for internal failures."""

    def fail(_request: object) -> NoReturn:
        message = "sensitive implementation detail"
        raise RuntimeError(message)

    monkeypatch.setattr("pyahead.cli.scan", fail)

    assert main(_check_args("json")) == int(ExitCode.INTERNAL_ERROR)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "pyahead: PYA9000: unexpected internal error\n"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_non_regular_source_exits_three_without_blocking(tmp_path: Path) -> None:
    """A repository FIFO is diagnosed in a bounded subprocess scan."""
    os.mkfifo(tmp_path / "pipe.py")
    command = [sys.executable, "-m", "pyahead", *_check_args("json")]

    completed = subprocess.run(  # noqa: S603
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        timeout=5,
    )

    assert completed.returncode == int(ExitCode.INCOMPLETE)
    document = cast("dict[str, object]", json.loads(completed.stdout))
    diagnostics = cast("list[dict[str, object]]", document["diagnostics"])
    assert [diagnostic["code"] for diagnostic in diagnostics] == ["PYA1004"]
    assert completed.stderr == b""


def test_json_is_byte_deterministic_across_roots_and_processes(
    tmp_path: Path,
) -> None:
    """Equivalent roots emit identical bytes in separate interpreter runs."""
    roots = [tmp_path / "one", tmp_path / "two"]
    for root in roots:
        root.mkdir()
        (root / "legacy.py").write_text("import cgi\n", encoding="utf-8")

    command = [sys.executable, "-m", "pyahead", *_check_args("json")]
    environment = os.environ.copy()
    first = subprocess.run(  # noqa: S603
        command,
        cwd=roots[0],
        env=environment,
        check=False,
        capture_output=True,
    )
    second = subprocess.run(  # noqa: S603
        command,
        cwd=roots[1],
        env=environment,
        check=False,
        capture_output=True,
    )

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == b""
    assert str(tmp_path).encode() not in first.stdout


def test_inference_json_is_byte_deterministic_across_roots(
    tmp_path: Path,
) -> None:
    """Resolution provenance contains only stable repository-relative data."""
    roots = [tmp_path / "one", tmp_path / "two"]
    for root in roots:
        root.mkdir()
        (root / "cgi.py").write_text("VALUE = 'local'\n", encoding="utf-8")
        (root / "consumer.py").write_text("import cgi\n", encoding="utf-8")

    arguments = _check_args("json")
    arguments[1] = "consumer.py"
    command = [sys.executable, "-m", "pyahead", *arguments]
    outputs = [
        subprocess.run(  # noqa: S603
            command,
            cwd=root,
            check=False,
            capture_output=True,
        )
        for root in roots
    ]

    assert [output.returncode for output in outputs] == [0, 0]
    assert outputs[0].stdout == outputs[1].stdout
    assert outputs[0].stderr == outputs[1].stderr == b""
    assert str(tmp_path).encode() not in outputs[0].stdout
