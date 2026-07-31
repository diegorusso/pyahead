"""Unit and fixture tests for the M1 exact-import analysis."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import DiscoveryIncompleteError
from pyahead.model import ExitCode, Impact, MatchConfidence, ScanReport

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures/rules/CPY0001"
_TWO_FILES = 2


def _scan(root: Path, *paths: str, horizon: str = "3.13") -> ScanReport:
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python=horizon,
            paths=tuple(Path(path) for path in paths),
        )
    )


@pytest.mark.parametrize(
    "fixture",
    [
        "positive/import_direct.py",
        "positive/import_alias.py",
        "positive/from_import.py",
    ],
)
def test_positive_import_fixtures_have_one_high_confidence_finding(
    fixture: str,
) -> None:
    """Direct, alias, and from imports all identify the module exactly."""
    report = _scan(FIXTURE_ROOT, fixture)

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.rule_id == "CPY0001"
    assert finding.match_confidence is MatchConfidence.HIGH
    assert finding.impact is Impact.BREAKING
    assert str(finding.action_version) == "3.13"
    assert report.exit_code is ExitCode.FINDINGS


def test_fixture_manifest_and_negative_fixtures_are_consistent() -> None:
    """Every declared positive and negative fixture has its expected result."""
    expected = cast(
        "dict[str, object]",
        json.loads((FIXTURE_ROOT / "expected.json").read_text(encoding="utf-8")),
    )
    positives = cast("dict[str, str]", expected["positive"])
    negatives = cast("list[str]", expected["negative"])

    assert all(len(_scan(FIXTURE_ROOT, path).findings) == 1 for path in positives)
    assert all(not _scan(FIXTURE_ROOT, path).findings for path in negatives[1:])


def test_local_module_resolution_prevents_stdlib_false_positive() -> None:
    """A proven project-root cgi module suppresses the stdlib interpretation."""
    local_project = FIXTURE_ROOT / "negative/local_module"

    report = _scan(local_project)

    assert report.counts.files_analyzed == _TWO_FILES
    assert report.findings == ()
    assert report.exit_code is ExitCode.SUCCESS


def test_policy_before_removal_reports_deprecation_without_failing() -> None:
    """A horizon before removal retains the earlier sourced deprecation fact."""
    report = _scan(FIXTURE_ROOT, "positive/import_direct.py", horizon="3.12")

    assert len(report.findings) == 1
    assert report.findings[0].impact is Impact.DEPRECATED
    assert str(report.findings[0].action_version) == "3.11"
    assert [event.kind.value for event in report.findings[0].events] == ["deprecated"]
    assert report.exit_code is ExitCode.SUCCESS


def test_policy_before_all_events_has_no_finding(tmp_path: Path) -> None:
    """A policy horizon earlier than the rule timeline is unaffected."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.9",
            horizon_python="3.10",
        )
    )

    assert report.findings == ()
    assert report.exit_code is ExitCode.SUCCESS


def test_blank_lines_do_not_change_fingerprint(tmp_path: Path) -> None:
    """Fingerprint identity excludes physical source positions."""
    source = tmp_path / "legacy.py"
    source.write_text("import cgi\n", encoding="utf-8")
    before = _scan(tmp_path).findings[0].fingerprint

    source.write_text("\n\nimport cgi\n", encoding="utf-8")
    after = _scan(tmp_path).findings[0].fingerprint

    assert after == before


def test_fingerprint_changes_with_scope_path_and_ordinal(tmp_path: Path) -> None:
    """Documented identity inputs deliberately change fingerprints."""
    source = tmp_path / "legacy.py"
    source.write_text("def first():\n    import cgi\n", encoding="utf-8")
    first = _scan(tmp_path).findings[0].fingerprint

    source.write_text("def renamed():\n    import cgi\n", encoding="utf-8")
    renamed = _scan(tmp_path).findings[0].fingerprint
    source.rename(tmp_path / "moved.py")
    moved = _scan(tmp_path).findings[0].fingerprint

    assert renamed != first
    assert moved != renamed

    moved_source = tmp_path / "moved.py"
    moved_source.write_text("import cgi\nimport cgi\n", encoding="utf-8")
    findings = _scan(tmp_path).findings
    assert findings[0].fingerprint != findings[1].fingerprint


def test_unparseable_source_marks_scan_incomplete(tmp_path: Path) -> None:
    """One parse failure does not erase analyzed findings but takes precedence."""
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")

    report = _scan(tmp_path)

    assert len(report.findings) == 1
    assert report.counts.files_discovered == _TWO_FILES
    assert report.counts.files_analyzed == 1
    assert report.counts.files_incomplete == 1
    assert report.diagnostics[0].code == "PYA1003"
    assert report.exit_code is ExitCode.INCOMPLETE


def test_invalid_encoding_marks_scan_incomplete(tmp_path: Path) -> None:
    """Unreadable declared encodings produce a safe relative diagnostic."""
    (tmp_path / "encoded.py").write_bytes(b"# coding: missing-codec\n")

    report = _scan(tmp_path)

    assert report.diagnostics[0].code == "PYA1002"
    assert str(tmp_path) not in report.diagnostics[0].message
    assert report.exit_code is ExitCode.INCOMPLETE


def test_incomplete_discovery_is_not_reported_as_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repository enumeration failure becomes an incomplete report."""

    def fail_discovery(_root: Path, _paths: tuple[Path, ...]) -> None:
        message = "unable to enumerate a source directory"
        raise DiscoveryIncompleteError(message)

    monkeypatch.setattr("pyahead.analysis.engine.discover_python_files", fail_discovery)

    report = _scan(tmp_path)

    assert report.findings == ()
    assert report.diagnostics[0].code == "PYA1001"
    assert report.exit_code is ExitCode.INCOMPLETE
