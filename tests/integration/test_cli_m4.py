"""End-to-end acceptance tests for M4 configuration and CI reports."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.cli import main
from pyahead.model import ExitCode

_UNSCHEDULED_RULE_ID = "CPY9002"


def _explicit_check(output_format: str = "json") -> list[str]:
    return [
        "check",
        "--baseline-python",
        "3.11",
        "--horizon-python",
        "3.13",
        "--format",
        output_format,
    ]


def _write_unscheduled_registry(root: Path) -> Path:
    registry = root / "registry"
    rules = registry / "cpython"
    rules.mkdir(parents=True)
    (registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "retired_ids: []\n"
            "rules:\n"
            f"  - cpython/{_UNSCHEDULED_RULE_ID}.yaml\n"
        ),
        encoding="utf-8",
    )
    (rules / f"{_UNSCHEDULED_RULE_ID}.yaml").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": _UNSCHEDULED_RULE_ID,
                "title": "Synthetic unscheduled deprecation",
                "summary": "A deprecated module with no removal event.",
                "scope": {
                    "ecosystem": "python",
                    "runtime": "cpython",
                    "contexts": ["runtime"],
                },
                "subject": {"kind": "module", "name": "legacy_api"},
                "timeline": [
                    {
                        "event": "deprecated",
                        "python": "3.11",
                        "certainty": "released",
                        "source": "test-source",
                    }
                ],
                "impact": {"on_deprecation": "deprecated"},
                "matchers": [{"kind": "module-import", "module": "legacy_api"}],
                "remediation": {"summary": "Use the supported API."},
                "sources": [
                    {
                        "id": "test-source",
                        "title": "Synthetic source",
                        "url": "https://example.com/unscheduled",
                    }
                ],
                "tags": ["unscheduled-test"],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return registry


def _write_unscheduled_project(root: Path, *, show_unscheduled: bool) -> None:
    rendered = str(show_unscheduled).lower()
    (root / "pyproject.toml").write_text(
        (
            "[tool.pyahead]\n"
            'baseline-python = "3.11"\n'
            'horizon-python = "3.11"\n'
            f"show-unscheduled = {rendered}\n"
        ),
        encoding="utf-8",
    )
    (root / "legacy.py").write_text("import legacy_api\n", encoding="utf-8")


def test_cli_overrides_config_and_inference_is_exposed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Machine reports expose exact policy/config provenance and CLI precedence."""
    (tmp_path / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "demo"\n'
            'version = "0"\n'
            'requires-python = ">=3.11.4"\n'
            "\n[tool.pyahead]\n"
            'horizon-python = "3.14"\n'
            'fail-on = "breaking"\n'
            "respect-gitignore = true\n"
            "show-unscheduled = true\n"
        ),
        encoding="utf-8",
    )
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert (
        main(
            [
                "check",
                "--horizon-python",
                "3.13",
                "--fail-on",
                "never",
                "--no-respect-gitignore",
                "--no-show-unscheduled",
                "--format",
                "json",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    policy = cast("dict[str, object]", document["policy"])
    provenance = cast("dict[str, object]", policy["provenance"])
    configuration = cast("dict[str, object]", document["configuration"])

    assert policy["baseline_python"] == "3.11"
    assert policy["horizon_python"] == "3.13"
    assert provenance == {
        "baseline_python": "pyproject.toml:project.requires-python",
        "horizon_python": "command-line",
        "requires_python": ">=3.11.4",
    }
    assert configuration["respect_gitignore"] is False
    assert configuration["show_unscheduled"] is False
    assert configuration["source_roots"] == [".", "src"]
    assert (
        configuration["source_roots_provenance"]
        == "inferred:conventional-root-and-src-layout"
    )
    assert configuration["fail_on"] == "never"
    assert configuration["fail_new_only"] is False
    assert configuration["show_suppressed"] is False
    assert configuration["allow_incomplete"] is False
    assert document["gate"] == {
        "fail_on": "never",
        "failed": False,
        "new_only": False,
    }
    assert captured.err == ""


def test_cli_adapter_exhaustively_replaces_config_and_merges_per_file_ignores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Argparse values exercise every scalar, list, and positive Boolean merge."""
    (tmp_path / "configured-src").mkdir()
    (tmp_path / "override-src").mkdir()
    selected = tmp_path / "override/keep.py"
    selected.parent.mkdir()
    selected.write_text("import pathlib\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        (
            "[tool.pyahead]\n"
            'baseline-python = "3.11"\n'
            'horizon-python = "3.14"\n'
            'include = ["configured/**/*.py"]\n'
            'exclude = ["configured/generated/**"]\n'
            'source-roots = ["configured-src"]\n'
            "respect-gitignore = false\n"
            'minimum-confidence = "high"\n'
            'fail-on = "breaking"\n'
            "show-unscheduled = false\n"
            "max-file-size-bytes = 64\n"
            "\n[tool.pyahead.per-file-ignores]\n"
            '"tests/**" = ["CPY0001"]\n'
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "check",
            "--baseline-python",
            "3.12",
            "--horizon-python",
            "3.13",
            "--include",
            "override/**/*.py",
            "--include",
            "extra/**/*.py",
            "--exclude",
            "override/generated/**",
            "--exclude",
            "ignored/**",
            "--source-root",
            "override-src",
            "--respect-gitignore",
            "--minimum-confidence",
            "medium",
            "--fail-on",
            "never",
            "--show-unscheduled",
            "--max-file-size-bytes",
            "1024",
            "--per-file-ignore",
            "tests/**=CPY0001,UNKNOWN",
            "--per-file-ignore",
            "vendor/**=CPY0001",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    configuration = cast("dict[str, object]", document["configuration"])
    policy = cast("dict[str, object]", document["policy"])
    diagnostics = cast("list[dict[str, object]]", document["diagnostics"])
    scan = cast("dict[str, object]", document["scan"])

    assert result == int(ExitCode.SUCCESS)
    assert policy["baseline_python"] == "3.12"
    assert policy["horizon_python"] == "3.13"
    assert configuration == {
        "allow_incomplete": False,
        "exclude": ["override/generated/**", "ignored/**"],
        "fail_new_only": False,
        "fail_on": "never",
        "include": ["override/**/*.py", "extra/**/*.py"],
        "max_file_size_bytes": 1024,
        "minimum_confidence": "medium",
        "per_file_ignores": {
            "tests/**": ["CPY0001", "UNKNOWN"],
            "vendor/**": ["CPY0001"],
        },
        "respect_gitignore": True,
        "show_suppressed": False,
        "show_unscheduled": True,
        "source_roots": ["override-src"],
        "source_roots_provenance": "command-line",
    }
    assert scan["files_analyzed"] == 1
    assert [item["code"] for item in diagnostics] == ["PYA3001"]
    assert captured.err == ""


def test_explicit_empty_source_roots_are_reported_and_disable_shadow_inference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An authoritative empty list is distinct from absent conventional roots."""
    (tmp_path / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "demo"\n'
            'version = "0"\n'
            'requires-python = ">=3.11"\n'
            "\n[tool.pyahead]\n"
            'horizon-python = "3.13"\n'
            'fail-on = "never"\n'
            "source-roots = []\n"
        ),
        encoding="utf-8",
    )
    (tmp_path / "cgi.py").write_text("", encoding="utf-8")
    (tmp_path / "consumer.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["check", "--format", "json"]) == int(ExitCode.SUCCESS)
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    configuration = cast("dict[str, object]", document["configuration"])
    findings = cast("list[dict[str, object]]", document["findings"])
    inferences = cast("list[dict[str, object]]", document["inferences"])

    assert configuration["source_roots"] == []
    assert configuration["source_roots_provenance"] == (
        "pyproject.toml:tool.pyahead.source-roots"
    )
    assert [finding["rule_id"] for finding in findings] == ["CPY0001"]
    assert inferences == []
    assert captured.err == ""


def test_unknown_config_key_leaves_machine_stdout_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Configuration errors never emit a partial JSON or SARIF document."""
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pyahead]\nfail-onn = "breaking"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "--format", "sarif"]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()

    assert captured.out == ""
    assert "unknown [tool.pyahead] key" in captured.err


def test_sarif_output_file_is_atomic_and_verbose_stays_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """File output has no stdout progress and verbose policy is stderr-only."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            *_explicit_check("sarif"),
            "--output",
            "pyahead.sarif",
            "--verbose",
        ]
    )
    captured = capsys.readouterr()
    document = json.loads((tmp_path / "pyahead.sarif").read_text(encoding="utf-8"))

    assert result == int(ExitCode.FINDINGS)
    assert captured.out == ""
    assert captured.err.startswith("pyahead: configuration:")
    assert "include=[]" in captured.err
    assert "max-file-size-bytes=2097152" in captured.err
    assert "fail-new-only=false" in captured.err
    assert document["version"] == "2.1.0"
    assert list(tmp_path.glob(".pyahead.sarif.*.tmp")) == []


def test_verbose_json_stdout_is_parseable_and_uncontaminated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Progress/config messages cannot share stdout with a machine document."""
    (tmp_path / "clean.py").write_text("import pathlib\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main([*_explicit_check(), "--verbose"]) == 0
    captured = capsys.readouterr()

    document = cast("dict[str, object]", json.loads(captured.out))
    configuration = cast("dict[str, object]", document["configuration"])

    assert document["schema_version"] == 1
    assert configuration["source_roots"] == [".", "src"]
    assert (
        configuration["source_roots_provenance"]
        == "inferred:conventional-root-and-src-layout"
    )
    assert "configuration:" not in captured.out
    assert "configuration:" in captured.err
    assert (
        "source-roots=['.', 'src'] (inferred:conventional-root-and-src-layout)"
        in captured.err
    )


def test_show_unscheduled_cli_overrides_false_config_and_all_formats_label_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deprecation-only rules are opt-in when config disables their display."""
    registry = _write_unscheduled_registry(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    _write_unscheduled_project(project, show_unscheduled=False)
    monkeypatch.chdir(project)
    base = ["check", "--registry", str(registry)]

    assert main([*base, "--format", "json"]) == int(ExitCode.SUCCESS)
    hidden = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    assert hidden["findings"] == []

    assert main([*base, "--show-unscheduled", "--format", "json"]) == 0
    shown = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    findings = cast("list[dict[str, object]]", shown["findings"])
    configuration = cast("dict[str, object]", shown["configuration"])
    assert configuration["show_unscheduled"] is True
    assert findings[0]["rule_id"] == _UNSCHEDULED_RULE_ID
    assert findings[0]["removal_unscheduled"] is True
    assert findings[0]["timeline"] == [
        {
            "certainty": "released",
            "event": "deprecated",
            "python": "3.11",
            "source": "test-source",
        }
    ]

    assert main([*base, "--show-unscheduled", "--format", "text"]) == 0
    assert "Removal schedule: unscheduled" in capsys.readouterr().out

    assert main([*base, "--show-unscheduled", "--format", "sarif"]) == 0
    sarif = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    runs = cast("list[dict[str, object]]", sarif["runs"])
    results = cast("list[dict[str, object]]", runs[0]["results"])
    properties = cast("dict[str, object]", results[0]["properties"])
    assert properties["removalUnscheduled"] is True


def test_no_show_unscheduled_cli_overrides_true_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The explicit negative Boolean direction hides unscheduled findings."""
    registry = _write_unscheduled_registry(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    _write_unscheduled_project(project, show_unscheduled=True)
    monkeypatch.chdir(project)
    base = ["check", "--registry", str(registry), "--format", "json"]

    assert main(base) == 0
    shown = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    assert len(cast("list[object]", shown["findings"])) == 1

    assert main([*base, "--no-show-unscheduled"]) == 0
    hidden = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    configuration = cast("dict[str, object]", hidden["configuration"])
    assert configuration["show_unscheduled"] is False
    assert hidden["findings"] == []


def test_baseline_create_then_line_shift_passes_fail_new_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The complete CLI baseline workflow preserves line-stable identity."""
    source = tmp_path / "legacy.py"
    source.write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert (
        main(
            [
                "baseline",
                "create",
                "--baseline-python",
                "3.11",
                "--horizon-python",
                "3.13",
                "--output",
                ".pyahead-baseline.json",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    source.write_text("\n\nimport cgi\n", encoding="utf-8")

    assert (
        main(
            [
                *_explicit_check(),
                "--baseline-file",
                ".pyahead-baseline.json",
                "--fail-new-only",
            ]
        )
        == 0
    )
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    findings = cast("list[dict[str, object]]", document["findings"])
    gate = cast("dict[str, object]", document["gate"])
    assert findings[0]["baseline_status"] == "existing"
    assert gate["failed"] is False


@pytest.mark.parametrize("explicit_root", [False, True])
def test_baseline_round_trip_uses_selected_root_from_another_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    explicit_root: bool,
) -> None:
    """Relative baseline paths consistently use the selected project root."""
    project = tmp_path / "project"
    nested = project / "nested"
    outside = tmp_path / "outside"
    nested.mkdir(parents=True)
    outside.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )
    (project / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    working_directory = outside if explicit_root else nested
    monkeypatch.chdir(working_directory)
    root_options = ["--root", str(project)] if explicit_root else []

    assert main(
        [
            "baseline",
            "create",
            *root_options,
            "--horizon-python",
            "3.13",
        ]
    ) == int(ExitCode.SUCCESS)
    assert capsys.readouterr().out == ""
    assert (project / ".pyahead-baseline.json").is_file()
    assert not (working_directory / ".pyahead-baseline.json").exists()

    assert main(
        [
            "check",
            *root_options,
            "--horizon-python",
            "3.13",
            "--baseline-file",
            ".pyahead-baseline.json",
            "--fail-new-only",
            "--format",
            "json",
        ]
    ) == int(ExitCode.SUCCESS)
    document = cast("dict[str, object]", json.loads(capsys.readouterr().out))
    findings = cast("list[dict[str, object]]", document["findings"])
    assert findings[0]["baseline_status"] == "existing"


def test_baseline_create_rejects_output_outside_selected_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A relative baseline destination cannot escape the selected root."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(project)

    assert main(
        [
            "baseline",
            "create",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--output",
            "../escaped-baseline.json",
        ]
    ) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "baseline output must remain beneath the project root" in captured.err


def test_check_output_uses_selected_root_and_rejects_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Report destinations are rooted in the project and cannot escape it."""
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(outside)

    result = main(
        [
            *_explicit_check("json"),
            "--root",
            str(project),
            "--output",
            "report.json",
        ]
    )

    assert result == int(ExitCode.FINDINGS)
    assert json.loads((project / "report.json").read_text(encoding="utf-8"))["findings"]
    assert not (outside / "report.json").exists()
    assert capsys.readouterr().out == ""

    result = main(
        [
            *_explicit_check("json"),
            "--root",
            str(project),
            "--output",
            "../outside/report.json",
        ]
    )
    captured = capsys.readouterr()

    assert result == int(ExitCode.INVALID_INPUT)
    assert captured.out == ""
    assert "report output must remain beneath the project root" in captured.err


def test_check_output_rejects_symlink_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An in-root output alias cannot redirect the atomic write outside."""
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (project / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    try:
        (project / "reports").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")
    monkeypatch.chdir(project)

    result = main(
        [
            *_explicit_check("json"),
            "--output",
            "reports/report.json",
        ]
    )
    captured = capsys.readouterr()

    assert result == int(ExitCode.INVALID_INPUT)
    assert captured.out == ""
    assert "report output must remain beneath the project root" in captured.err
    assert not (outside / "report.json").exists()
    assert not (tmp_path / "escaped-baseline.json").exists()


def test_incomplete_baseline_creation_preserves_existing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Baseline creation fails closed before replacing output."""
    (tmp_path / "broken.py").write_text("if:\n", encoding="utf-8")
    destination = tmp_path / "baseline.json"
    destination.write_text("old\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "baseline",
            "create",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--output",
            "baseline.json",
        ]
    )
    captured = capsys.readouterr()

    assert result == int(ExitCode.INCOMPLETE)
    assert destination.read_text(encoding="utf-8") == "old\n"
    assert captured.out == ""
    assert "incomplete scan" in captured.err


def test_baseline_create_reports_unknown_suppression_without_corrupting_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Baseline stdout stays valid while suppression diagnostics use stderr."""
    (tmp_path / "legacy.py").write_text(
        "import cgi  # pyahead: ignore[CPY0001, UNKNOWN]\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "baseline",
            "create",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--output",
            "-",
        ]
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))

    assert result == int(ExitCode.SUCCESS)
    assert document["findings"] == []
    assert "PYA3001" in captured.err
    assert "legacy.py" in captured.err
    assert "UNKNOWN" in captured.err


def test_allowed_incomplete_baseline_reports_every_diagnostic_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Opting in preserves valid baseline JSON and states scan incompleteness."""
    (tmp_path / "broken_a.py").write_text("if:\n", encoding="utf-8")
    (tmp_path / "broken_b.py").write_text("else:\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "baseline",
            "create",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--allow-incomplete",
            "--output",
            "-",
        ]
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))

    assert result == int(ExitCode.SUCCESS)
    assert document["findings"] == []
    assert captured.err.count("PYA1003") == len(("broken_a.py", "broken_b.py"))
    assert "broken_a.py" in captured.err
    assert "broken_b.py" in captured.err
    assert "[incomplete analysis]" in captured.err
    assert "source scan is incomplete" in captured.err


def test_quiet_text_keeps_summary_on_stdout_and_errors_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Quiet text remains concise without hiding incomplete analysis."""
    (tmp_path / "broken.py").write_text("if:\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main([*_explicit_check("text"), "--quiet"])
    captured = capsys.readouterr()

    assert result == int(ExitCode.INCOMPLETE)
    assert captured.out.startswith("Result: ")
    assert captured.out.count("\n") == 1
    assert "PYA1003" in captured.err
    assert "broken.py" in captured.err
    assert "incomplete analysis" in captured.err


@pytest.mark.parametrize("output_format", ["json", "sarif"])
def test_quiet_does_not_contaminate_machine_output_with_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    output_format: str,
) -> None:
    """Machine formats retain structured diagnostics and an empty stderr."""
    (tmp_path / "broken.py").write_text("if:\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main([*_explicit_check(output_format), "--quiet"])
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))

    assert result == int(ExitCode.INCOMPLETE)
    assert captured.err == ""
    if output_format == "json":
        diagnostics = cast("list[dict[str, object]]", document["diagnostics"])
        assert [item["code"] for item in diagnostics] == ["PYA1003"]
    else:
        runs = cast("list[dict[str, object]]", document["runs"])
        invocations = cast("list[dict[str, object]]", runs[0]["invocations"])
        notifications = cast(
            "list[dict[str, object]]",
            invocations[0]["toolExecutionNotifications"],
        )
        assert [item["descriptor"]["id"] for item in notifications] == ["PYA1003"]


def test_per_file_suppression_unknown_rule_diagnostic_is_machine_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Known configured ignores apply while unknown IDs remain diagnostics."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "demo"\n'
            'version = "0"\n'
            'requires-python = ">=3.11"\n'
            "\n[tool.pyahead]\n"
            'horizon-python = "3.13"\n'
            "\n[tool.pyahead.per-file-ignores]\n"
            '"tests/**" = ["UNKNOWN", "CPY0001"]\n'
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["check", "--format", "json", "--show-suppressed"]) == 0
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    diagnostics = cast("list[dict[str, object]]", document["diagnostics"])
    findings = cast("list[dict[str, object]]", document["findings"])

    assert [item["code"] for item in diagnostics] == ["PYA3001"]
    assert findings[0]["suppressed"] is True
    assert captured.err == ""


def test_fail_new_only_requires_a_baseline_without_machine_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing comparison file cannot silently make every result look new."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main([*_explicit_check(), "--fail-new-only"])
    captured = capsys.readouterr()

    assert result == int(ExitCode.INVALID_INPUT)
    assert captured.out == ""
    assert "requires --baseline-file" in captured.err
