"""Terminal-safety tests for maintenance-script human output."""

# ruff: noqa: SLF001

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from pyahead.registry import schema as registry_schema
from scripts import benchmark, corpus, install_smoke

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from collections.abc import Callable
    from pathlib import Path

_BENCHMARK_ERROR = 2
_CONTROL_TEXT = "line\nansi\x1b[31mcr\rend\u202ebidi\u2028ls\u2029ps"
_ESCAPED_CONTROL_TEXT = (
    "line\\u000aansi\\u001b[31mcr\\u000dend\\u202ebidi\\u2028ls\\u2029ps"
)


def test_corpus_escapes_progress_without_changing_result_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A repository URL is safe on stderr and unchanged in machine evidence."""
    repository_url = f"https://example.invalid/{_CONTROL_TEXT}"
    spec = corpus.RepositorySpec(
        repository_url=repository_url,
        commit="a" * 40,
        checkout=tmp_path / "checkout",
        baseline_python="3.11",
        horizon_python="3.14",
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    output = tmp_path / "result.json"
    worksheet = tmp_path / "review.csv"
    writes: dict[Path, str] = {}

    monkeypatch.setattr(corpus, "_load_manifest", lambda _path: (spec,))
    monkeypatch.setattr(corpus, "_validate_destinations", lambda *_args: None)
    monkeypatch.setattr(corpus, "_git_executable", lambda: "git")
    monkeypatch.setattr(corpus, "_verify_checkout", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        corpus,
        "_repository_result",
        lambda item, *, timeout: {
            "commit": item.commit,
            "findings": [],
            "metrics": {"duration_seconds": timeout},
            "repository_url": item.repository_url,
        },
    )
    monkeypatch.setattr(corpus, "_worksheet_rows", lambda *_args, **_kwargs: [])

    def record_write(path: Path, content: str) -> None:
        writes[path] = content

    monkeypatch.setattr(corpus, "_write_atomic", record_write)

    result = corpus.main(
        [
            "--manifest",
            str(manifest),
            "--output",
            str(output),
            "--worksheet",
            str(worksheet),
        ]
    )

    assert result == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == f"[1/1] scanning https://example.invalid/{_ESCAPED_CONTROL_TEXT}\n"
    )
    document: Any = json.loads(writes[output])
    assert document["repositories"][0]["repository_url"] == repository_url


def test_corpus_escapes_untrusted_failure_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Corpus exceptions cannot add terminal controls or forged log lines."""

    def fail(_path: Path | None) -> Path:
        raise corpus.CorpusError(_CONTROL_TEXT)

    monkeypatch.setattr(corpus, "_require_manifest", fail)

    result = corpus.main(["--output", "result.json", "--worksheet", "review.csv"])

    assert result == 1
    assert capsys.readouterr().err == f"corpus run failed: {_ESCAPED_CONTROL_TEXT}\n"


def test_benchmark_escapes_untrusted_failure_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Benchmark configuration cannot inject controls into stderr."""

    def fail(_path: Path) -> tuple[benchmark.Budget, ...]:
        raise benchmark.BenchmarkError(_CONTROL_TEXT)

    monkeypatch.setattr(benchmark, "_load_budgets", fail)

    assert benchmark.main([]) == _BENCHMARK_ERROR
    assert capsys.readouterr().err == f"benchmark failed: {_ESCAPED_CONTROL_TEXT}\n"


@pytest.mark.parametrize(
    ("parser_factory", "arguments"),
    [
        (benchmark._parser, (_CONTROL_TEXT,)),
        (
            corpus._parser,
            ("--output", "result.json", "--worksheet", "review.csv", _CONTROL_TEXT),
        ),
        (install_smoke._parser, ("--kind", "wheel", _CONTROL_TEXT)),
        (registry_schema._parser, ("schemas", _CONTROL_TEXT)),
    ],
    ids=("benchmark", "corpus", "install-smoke", "registry-schema"),
)
def test_maintenance_script_argument_errors_are_terminal_safe(
    parser_factory: Callable[[], ArgumentParser],
    arguments: tuple[str, ...],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Invalid caller values cannot forge argparse usage or error records."""
    parser = parser_factory()

    with pytest.raises(SystemExit) as raised:
        parser.parse_args(arguments)

    assert raised.value.code == _BENCHMARK_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _CONTROL_TEXT not in captured.err
    assert _ESCAPED_CONTROL_TEXT in captured.err
    assert "\nansi" not in captured.err


def test_install_smoke_redacts_then_escapes_child_diagnostics() -> None:
    """Credential and terminal-safety handling share one retained-text boundary."""
    credential = "synthetic-user:synthetic-password"
    detail = install_smoke._error_detail(
        f"{_CONTROL_TEXT} https://{credential}@example.invalid/simple"
    )

    assert detail == (
        f"{_ESCAPED_CONTROL_TEXT} https://[REDACTED]@example.invalid/simple"
    )
    assert credential not in detail


def test_install_smoke_rechecks_retained_error_at_stderr_boundary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Even nominally sanitized exceptions cross the final shared boundary."""

    def fail(_repository: Path) -> str:
        raise install_smoke._SanitizedInstallSmokeError(_CONTROL_TEXT)

    monkeypatch.setattr(install_smoke, "_project_version", fail)

    assert install_smoke.main(["--kind", "wheel"]) == 1
    assert capsys.readouterr().err == f"install smoke failed: {_ESCAPED_CONTROL_TEXT}\n"
