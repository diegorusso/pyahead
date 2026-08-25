"""End-to-end CLI ingestion tests for M7 warning evidence."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.cli import main
from pyahead.model import ExitCode

CURRENT_COMMIT = "a" * 40


def _write_evidence(path: Path, *, commit: str = CURRENT_COMMIT) -> None:
    document = {
        "environment": {
            "implementation": "cpython",
            "platform": "linux",
            "python_version": "3.11.9",
        },
        "provider": {"name": "pytest-warnings", "version": "0.1.0a2"},
        "run": {
            "exit_code": 0,
            "framework": "pytest",
            "framework_version": "9.1.1",
            "tests_collected": 1,
            "warnings_complete": True,
            "warnings_dropped": 0,
        },
        "schema_version": 1,
        "source": {"commit": commit},
        "warnings": [
            {
                "category": "builtins.DeprecationWarning",
                "kind": "deprecation-warning",
                "location": {"line": 1, "path": "legacy.py"},
                "message": "cgi is deprecated",
                "occurrences": 1,
                "phase": "runtest",
                "test_node": "tests/test_legacy.py::test_legacy",
            }
        ],
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _arguments(output_format: str = "json") -> list[str]:
    return [
        "check",
        ".",
        "--baseline-python",
        "3.11",
        "--horizon-python",
        "3.13",
        "--format",
        output_format,
        "--evidence",
        "warnings.json",
        "--source-commit",
        CURRENT_COMMIT,
    ]


def test_cli_ingests_and_links_current_warning_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public options produce linked observed evidence without a second finding."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    _write_evidence(tmp_path / "warnings.json")
    monkeypatch.chdir(tmp_path)

    assert main(_arguments()) == int(ExitCode.FINDINGS)
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    evidence = cast("dict[str, object]", document["evidence"])
    findings = cast("list[dict[str, object]]", document["findings"])

    assert captured.err == ""
    assert len(findings) == 1
    assert len(cast("list[object]", evidence["observations"])) == 1
    assert cast("dict[str, int]", document["summary"])["observed_unmatched"] == 0


def test_cli_rejects_unverifiable_or_unsupported_evidence_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing commit identity and unsupported SARIF never emit partial output."""
    (tmp_path / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write_evidence(tmp_path / "warnings.json")
    monkeypatch.chdir(tmp_path)
    for name in ("PYAHEAD_COMMIT", "GITHUB_SHA", "CI_COMMIT_SHA"):
        monkeypatch.delenv(name, raising=False)

    without_commit = _arguments()[:-2]
    assert main(without_commit) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "provide --source-commit" in captured.err

    assert main(_arguments("sarif")) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "supported with text or JSON, not SARIF" in captured.err


def test_cli_uses_ci_commit_environment_when_option_is_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A standard CI commit variable is sufficient for freshness comparison."""
    (tmp_path / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write_evidence(tmp_path / "warnings.json")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_SHA", CURRENT_COMMIT)
    arguments = _arguments()[:-2]

    assert main(arguments) == int(ExitCode.SUCCESS)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    evidence = cast("dict[str, object]", document["evidence"])
    assert evidence["source_commit"] == CURRENT_COMMIT
