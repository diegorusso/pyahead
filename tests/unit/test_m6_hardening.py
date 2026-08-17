"""Contract tests for M6 public-alpha hardening assets."""

# ruff: noqa: SLF001

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest
import yaml

from scripts import benchmark, corpus, install_smoke

_CORPUS_SIZE = 100
_DETERMINISM_RUNS = 2
_GIBIBYTE = 1_073_741_824
_SAMPLE_SIZE = 2


def _high_confidence_finding(path: str = "legacy.py") -> dict[str, object]:
    return {
        "action_version": "3.13",
        "fingerprint": "a" * 64,
        "impact": "breaking",
        "location": {
            "path": path,
            "region": {
                "end": {"column": 10, "line": 1},
                "start": {"column": 0, "line": 1},
            },
        },
        "match": {
            "confidence": "high",
            "evidence": {"resolved_names": ["cgi"]},
            "kind": "module-import",
        },
        "reachable_versions": ["3.11", "3.12", "3.13"],
        "rule_id": "CPY0001",
        "sources": [
            {
                "id": "pep-0594",
                "title": "PEP 594",
                "url": "https://peps.python.org/pep-0594/",
            }
        ],
        "states": [{"from": "3.13", "state": "breaking", "through": "3.13"}],
        "subject": "cgi",
        "timeline": [
            {
                "certainty": "released",
                "event": "removed",
                "python": "3.13",
                "source": "pep-0594",
            }
        ],
        "title": "The cgi module is removed",
        "usage_contexts": ["runtime"],
    }


def _scan_report() -> dict[str, object]:
    return {
        "diagnostics": [],
        "findings": [_high_confidence_finding()],
        "policy": {
            "baseline_python": "3.11",
            "horizon_python": "3.13",
            "provenance": {},
            "versions": ["3.11", "3.12", "3.13"],
        },
        "registry": {"release": "test", "revision": "b" * 64},
        "scan": {
            "files_analyzed": 1,
            "files_discovered": 1,
            "files_incomplete": 0,
            "root": ".",
        },
        "summary": {
            "breaking": 1,
            "deprecated": 0,
            "informational": 0,
            "new": 1,
            "risk": 0,
            "suppressed": 0,
        },
    }


def test_install_smoke_selects_only_the_current_artifact(tmp_path: Path) -> None:
    """Stale distributions cannot be mistaken for the current candidate."""
    current = tmp_path / "pyahead-0.1.0a2-py3-none-any.whl"
    current.touch()
    (tmp_path / "pyahead-0.1.0a1-py3-none-any.whl").touch()

    assert install_smoke._select_artifact(tmp_path, "wheel", "0.1.0a2") == current

    duplicate = tmp_path / "pyahead-0.1.0a2-py2-none-any.whl"
    duplicate.touch()
    with pytest.raises(install_smoke.InstallSmokeError, match="exactly one"):
        install_smoke._select_artifact(tmp_path, "wheel", "0.1.0a2")


def test_install_smoke_requires_registry_backed_sample_behavior() -> None:
    """The installed scan must prove launcher, package data, and one exact match."""
    install_smoke._validate_scan(_scan_report())

    invalid = _scan_report()
    invalid["findings"] = []
    with pytest.raises(install_smoke.InstallSmokeError, match="exactly one finding"):
        install_smoke._validate_scan(invalid)


def test_install_smoke_accepts_a_resolved_environment_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Temporary-directory aliases cannot make an isolated install look external."""
    actual = tmp_path / "actual"
    installed = actual / "lib" / "pyahead" / "__init__.py"
    installed.parent.mkdir(parents=True)
    installed.touch()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=f"{installed.resolve()}\n",
        stderr="",
    )
    monkeypatch.setattr(
        install_smoke.subprocess,
        "run",
        lambda *_args, **_kwargs: result,
    )

    install_smoke._validate_installed_origin(alias, timeout=1.0)


def test_performance_targets_and_regression_ceilings_are_versioned() -> None:
    """Design targets remain visible while current regressions fail closed."""
    path = Path(benchmark.__file__).with_name("performance-budgets.json")
    budgets = benchmark._load_budgets(path)

    assert [(item.name, item.files, item.max_seconds) for item in budgets] == [
        ("one-file", 1, 0.5),
        ("1k-files", 1_000, 5.0),
        ("10k-files", 10_000, 30.0),
    ]
    assert all(item.max_regression_seconds >= item.max_seconds for item in budgets)
    assert budgets[-1].max_peak_rss_bytes == _GIBIBYTE


def test_single_timing_repeat_still_compares_two_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fast verification run cannot claim determinism from one report."""
    calls = 0

    def fake_run_once(
        _root: Path,
        *,
        timeout: float,
        expected_files: int,
    ) -> tuple[float, int, str]:
        nonlocal calls
        calls += 1
        assert timeout > 0
        assert expected_files == 1
        return 0.1, 1, f"digest-{calls}"

    monkeypatch.setattr(benchmark, "_run_once", fake_run_once)
    result = benchmark._measure(
        benchmark.Budget(
            name="determinism",
            files=1,
            max_seconds=1.0,
            max_regression_seconds=2.0,
        ),
        repeat=1,
    )

    assert calls == _DETERMINISM_RUNS
    assert result["determinism_runs"] == _DETERMINISM_RUNS
    assert result["measurements"]["duration_seconds"] == [0.1]
    assert result["deterministic"] is False
    assert result["passed"] is False


def test_corpus_manifest_requires_100_unique_public_repositories(
    tmp_path: Path,
) -> None:
    """The production runner cannot silently shrink the Gate C corpus."""
    repositories: list[dict[str, str]] = []
    for index in range(_CORPUS_SIZE):
        checkout = tmp_path / f"checkout-{index:03d}"
        checkout.mkdir()
        repositories.append(
            {
                "baseline_python": "3.11",
                "checkout": checkout.name,
                "commit": f"{index + 1:040x}",
                "horizon_python": "3.14",
                "repository_url": f"https://example.com/project-{index:03d}",
            }
        )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"repositories": repositories, "schema_version": 1}),
        encoding="utf-8",
    )

    loaded = corpus._load_manifest(manifest)

    assert len(loaded) == _CORPUS_SIZE
    assert len({item.repository_url for item in loaded}) == _CORPUS_SIZE
    with pytest.raises(corpus.CorpusError, match="outside every scanned checkout"):
        corpus._validate_destinations(
            manifest,
            loaded,
            (loaded[0].checkout / "results.json", tmp_path / "review.csv"),
        )

    repositories.pop()
    manifest.write_text(
        json.dumps({"repositories": repositories, "schema_version": 1}),
        encoding="utf-8",
    )
    with pytest.raises(corpus.CorpusError, match="exactly 100"):
        corpus._load_manifest(manifest)


def test_corpus_result_retains_only_minimal_review_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Checkout paths, source, stderr, and Git metadata never enter results."""
    spec = corpus.RepositorySpec(
        repository_url="https://example.com/project",
        commit="1" * 40,
        checkout=tmp_path,
        baseline_python="3.11",
        horizon_python="3.13",
    )
    report = _scan_report()
    monkeypatch.setattr(
        corpus,
        "_run_scan",
        lambda _spec, *, timeout: (0, timeout / 100, report),
    )

    result = corpus._repository_result(spec, timeout=30.0)

    assert set(result) == {"commit", "findings", "metrics", "repository_url"}
    assert str(tmp_path) not in json.dumps(result)
    findings = cast("list[dict[str, object]]", result["findings"])
    assert len(findings) == 1
    assert set(findings[0]) == {
        "action_version",
        "fingerprint",
        "impact",
        "location",
        "match",
        "reachable_versions",
        "rule_id",
        "sources",
        "states",
        "subject",
        "timeline",
        "title",
        "usage_contexts",
    }
    rendered = json.dumps(result).lower()
    for forbidden in ("checkout", "source_text", "snippet", "stderr"):
        assert forbidden not in rendered


def test_corpus_git_verification_disables_ambient_execution_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-only checkout checks disable prompts, fsmonitor, and ambient config."""
    observed: dict[str, object] = {}

    def fake_run(
        command: list[str], **options: object
    ) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["environment"] = options["env"]
        return subprocess.CompletedProcess(command, 0, stdout="verified\n", stderr="")

    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_ASKPASS", str(tmp_path / "credential-helper"))
    monkeypatch.setenv("SSH_ASKPASS", str(tmp_path / "ssh-helper"))
    monkeypatch.setattr(corpus.subprocess, "run", fake_run)

    assert corpus._git_output("/usr/bin/git", tmp_path, ["rev-parse", "HEAD"]) == (
        "verified"
    )
    command = cast("list[str]", observed["command"])
    environment = cast("dict[str, str]", observed["environment"])
    assert "core.fsmonitor=false" in command
    assert "submodule.recurse=false" in command
    assert "credential.interactive=false" in command
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_ASKPASS" not in environment
    assert "SSH_ASKPASS" not in environment


def test_corpus_rejects_non_relative_finding_paths() -> None:
    """Persistent corpus locations cannot reveal checkout paths."""
    finding = _high_confidence_finding("/private/legacy.py")

    with pytest.raises(corpus.CorpusError, match="repository relative"):
        corpus._review_finding(finding)


def test_false_positive_sample_is_deterministic_and_bounded() -> None:
    """Sampling cannot be manually reordered to prefer favorable findings."""
    findings = []
    for index in range(3):
        finding = _high_confidence_finding(f"module-{index}.py")
        finding["fingerprint"] = f"{index + 1:064x}"
        findings.append(corpus._review_finding(finding))
    repository = {
        "commit": "1" * 40,
        "findings": findings,
        "metrics": {},
        "repository_url": "https://example.com/project",
    }

    result_digest = "b" * 64
    first = corpus._worksheet_rows(
        [repository],
        sample_size=_SAMPLE_SIZE,
        corpus_result_sha256=result_digest,
    )
    second = corpus._worksheet_rows(
        [repository],
        sample_size=_SAMPLE_SIZE,
        corpus_result_sha256=result_digest,
    )

    assert first == second
    assert len(first) == _SAMPLE_SIZE
    assert all(row["classification"] == "" for row in first)
    assert all(row["corpus_result_sha256"] == result_digest for row in first)


def test_corpus_worksheet_identity_rejects_a_different_result(
    tmp_path: Path,
) -> None:
    """A review worksheet cannot silently move between corpus result files."""
    result = tmp_path / "corpus-results.json"
    worksheet = tmp_path / "false-positive-review.csv"
    result.write_text('{"repositories":[],"schema_version":1}\n', encoding="utf-8")
    result_digest = corpus._sha256_path(result)
    worksheet.write_text(
        corpus._render_worksheet([], result_digest=result_digest),
        encoding="utf-8",
    )

    corpus._verify_worksheet_identity(result, worksheet)

    result.write_text('{"repositories":[{}],"schema_version":1}\n', encoding="utf-8")
    with pytest.raises(corpus.CorpusError, match="does not match"):
        corpus._verify_worksheet_identity(result, worksheet)


def test_ci_declares_exact_host_and_artifact_job_matrix() -> None:
    """Hosted candidate evidence can bind every frozen required job name."""
    workflow_path = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"
    document = cast(
        "dict[str, object]",
        yaml.safe_load(workflow_path.read_text(encoding="utf-8")),
    )
    assert document["name"] == "CI"
    assert document["run-name"] == (
        "PyAhead autopilot ${{ inputs.pyahead_autopilot_token }}"
    )
    assert document["env"] == {"PYO3_USE_ABI3_FORWARD_COMPATIBILITY": "1"}
    triggers = cast("dict[str, object]", document[True])
    dispatch = cast("dict[str, object]", triggers["workflow_dispatch"])
    inputs = cast("dict[str, object]", dispatch["inputs"])
    assert set(inputs) == {"pyahead_autopilot_token"}

    jobs = cast("dict[str, dict[str, object]]", document["jobs"])
    assert jobs["quality"]["name"] == "Quality and Gate B / Linux / Python 3.11"
    assert jobs["build"]["name"] == "Build wheel and sdist"
    assert jobs["tests"]["name"] == (
        "Tests / ${{ matrix.os }} / Python ${{ matrix.python }}"
    )
    assert jobs["install"]["name"] == (
        "Install wheel and sdist / ${{ matrix.os }} / Python ${{ matrix.python }}"
    )

    test_strategy = cast("dict[str, object]", jobs["tests"]["strategy"])
    test_matrix = cast("dict[str, object]", test_strategy["matrix"])
    test_includes = cast("list[dict[str, str]]", test_matrix["include"])
    assert {(item["os"], item["python"]) for item in test_includes} == {
        ("ubuntu-latest", "3.12"),
        ("ubuntu-latest", "3.13"),
        ("ubuntu-latest", "3.14"),
        ("macos-latest", "3.11"),
        ("macos-latest", "3.14"),
        ("windows-latest", "3.11"),
        ("windows-latest", "3.14"),
    }

    install_strategy = cast("dict[str, object]", jobs["install"]["strategy"])
    install_matrix = cast("dict[str, object]", install_strategy["matrix"])
    install_includes = cast("list[dict[str, str]]", install_matrix["include"])
    assert {(item["os"], item["python"]) for item in install_includes} == {
        (host, python)
        for host in ("ubuntu-latest", "macos-latest", "windows-latest")
        for python in ("3.11", "3.14")
    }


def test_readme_leads_with_limitations_and_links_public_alpha_docs() -> None:
    """Users see non-claims before the feature and installation narrative."""
    repository = Path(__file__).parents[2]
    readme = (repository / "README.md").read_text(encoding="utf-8")

    assert readme.index("## Limitations — read before use") < readme.index("## Status")
    assert "not proof of compatibility" in readme
    for path in (
        "CHANGELOG.md",
        "SECURITY.md",
        "docs/usage.md",
        "docs/releasing.md",
        "docs/security-and-privacy.md",
        "docs/corpus-review.md",
        "docs/false-positive-review.csv",
    ):
        assert (repository / path).is_file()
