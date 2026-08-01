"""Unit and fixture tests for the M1 exact-import analysis."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import MAX_SOURCE_BYTES, DiscoveryIncompleteError
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


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast("dict[str, object]", value)


def _sequence(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast("list[object]", value)


def _string(value: object) -> str:
    assert isinstance(value, str)
    return value


def _string_list(value: object) -> list[str]:
    values = _sequence(value)
    assert all(isinstance(item, str) for item in values)
    return cast("list[str]", values)


def _finding_fixture_record(report: ScanReport) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for finding in report.findings:
        evidence = dict(finding.match_evidence)
        resolution = evidence.get("resolution")
        assert isinstance(resolution, str)
        records.append(
            {
                "action_version": str(finding.action_version),
                "confidence": finding.match_confidence.value,
                "impact": finding.impact.value,
                "resolution": resolution,
                "rule_id": finding.rule_id,
            }
        )
    return records


@pytest.mark.parametrize(
    ("fixture", "bound_names"),
    [
        ("positive/import_direct.py", ("cgi",)),
        ("positive/import_alias.py", ("legacy_cgi",)),
        ("positive/from_import.py", ("FieldStorage",)),
    ],
)
def test_positive_import_fixtures_have_one_high_confidence_finding(
    fixture: str,
    bound_names: tuple[str, ...],
) -> None:
    """Direct, alias, and from imports all identify the module exactly."""
    report = _scan(FIXTURE_ROOT, fixture)

    assert len(report.findings) == 1
    finding = report.findings[0]
    evidence = dict(finding.match_evidence)
    assert finding.rule_id == "CPY0001"
    assert finding.match_confidence is MatchConfidence.HIGH
    assert evidence["bound_names"] == bound_names
    assert evidence["resolution"] == "no-competing-project-module"
    assert finding.impact is Impact.BREAKING
    assert str(finding.action_version) == "3.13"
    assert report.exit_code is ExitCode.FINDINGS


def test_one_import_statement_retains_every_binding(tmp_path: Path) -> None:
    """Deduplication keeps deterministic evidence for repeated module aliases."""
    (tmp_path / "legacy.py").write_text(
        "import cgi as first, cgi as second\n",
        encoding="utf-8",
    )

    report = _scan(tmp_path)

    assert len(report.findings) == 1
    assert dict(report.findings[0].match_evidence)["bound_names"] == (
        "first",
        "second",
    )


def test_fixture_manifest_and_negative_fixtures_are_consistent() -> None:
    """Every manifest value is schema-checked and compared with scan output."""
    manifest = _mapping(
        json.loads((FIXTURE_ROOT / "expected.json").read_text(encoding="utf-8"))
    )
    assert set(manifest) == {"cases", "policy", "rule_id", "schema_version"}
    assert type(manifest["schema_version"]) is int
    assert manifest["schema_version"] == 1
    rule_id = _string(manifest["rule_id"])
    policy = _mapping(manifest["policy"])
    assert set(policy) == {"baseline_python", "horizon_python"}
    baseline = _string(policy["baseline_python"])
    horizon = _string(policy["horizon_python"])

    case_names: set[str] = set()
    for raw_case in _sequence(manifest["cases"]):
        case = _mapping(raw_case)
        assert set(case) == {
            "expected_findings",
            "expected_inference_codes",
            "name",
            "paths",
            "root",
        }
        name = _string(case["name"])
        assert name not in case_names
        case_names.add(name)
        case_root = FIXTURE_ROOT / _string(case["root"])
        paths = _string_list(case["paths"])
        assert case_root.is_dir()
        assert all((case_root / path).is_file() for path in paths)

        report = scan(
            ScanRequest(
                root=case_root,
                baseline_python=baseline,
                horizon_python=horizon,
                paths=tuple(Path(path) for path in paths),
            )
        )
        expected_findings: list[dict[str, str]] = []
        for raw_finding in _sequence(case["expected_findings"]):
            finding = _mapping(raw_finding)
            assert set(finding) == {
                "action_version",
                "confidence",
                "impact",
                "resolution",
                "rule_id",
            }
            record = {key: _string(value) for key, value in finding.items()}
            assert record["rule_id"] == rule_id
            expected_findings.append(record)

        assert _finding_fixture_record(report) == expected_findings
        assert [inference.code for inference in report.inferences] == _string_list(
            case["expected_inference_codes"]
        )


def test_local_module_resolution_prevents_stdlib_false_positive() -> None:
    """A narrowed scan still indexes project modules from the complete root."""
    local_project = FIXTURE_ROOT / "negative/local_module"

    report = _scan(local_project, "consumer.py")

    assert report.counts.files_analyzed == 1
    assert report.findings == ()
    assert [inference.code for inference in report.inferences] == ["PYA2001"]
    assert dict(report.inferences[0].evidence)["candidate_paths"] == ("cgi.py",)
    assert report.exit_code is ExitCode.SUCCESS


def test_type_stub_does_not_suppress_runtime_stdlib_finding() -> None:
    """A .pyi candidate cannot prove that a runtime import is project-local."""
    stub_project = FIXTURE_ROOT / "resolution/stub_only"

    report = _scan(stub_project, "consumer.py")

    assert len(report.findings) == 1
    assert report.findings[0].match_confidence is MatchConfidence.HIGH
    assert report.inferences == ()
    assert report.exit_code is ExitCode.FINDINGS


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


def test_oversized_source_is_incomplete_without_being_read(tmp_path: Path) -> None:
    """The default byte limit skips source and cannot return a false clean scan."""
    (tmp_path / "large.py").write_bytes(b"#" * (MAX_SOURCE_BYTES + 1))

    report = _scan(tmp_path)

    assert report.counts.files_discovered == 1
    assert report.counts.files_analyzed == 0
    assert report.counts.files_incomplete == 1
    assert report.diagnostics[0].code == "PYA1005"
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
