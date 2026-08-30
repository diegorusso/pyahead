"""Closed public schema and typed API tests for static reports."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
from jsonschema import Draft202012Validator, ValidationError

from pyahead.analysis import ScanReport, ScanRequest, scan
from pyahead.model import (
    AnalysisInference,
    BaselineStatus,
    Diagnostic,
    DiagnosticCategory,
    EvidenceArtifact,
    EvidenceEnvironment,
    EvidenceFreshness,
    ScanCounts,
    Suppression,
    SuppressionKind,
)
from pyahead.registry import Registry, load_registry
from pyahead.reporting.json import report_document
from pyahead.reporting.schema import render_report_schema, report_json_schema

ROOT = Path(__file__).parents[2]
SCHEMA_PATH = ROOT / "docs/schema/report-v1.json"
PACKAGE_SCHEMA_PATH = ROOT / "src/pyahead/data/schema/report-v1.json"
REGENERATE_HINT = (
    "The published schema no longer matches its generator. Regenerate both "
    "copies as described in docs/contributing.md."
)


def _scan(root: Path, source: str = "VALUE = 1\n") -> ScanReport:
    root.mkdir(parents=True, exist_ok=True)
    (root / "sample.py").write_text(source, encoding="utf-8")
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )


def _representative_documents(tmp_path: Path) -> tuple[dict[str, object], ...]:
    empty = _scan(tmp_path / "empty")

    incomplete_root = tmp_path / "incomplete"
    incomplete_root.mkdir()
    incomplete = _scan(incomplete_root)
    location = incomplete.findings[0].location if incomplete.findings else None
    assert location is None
    synthetic_location = (
        scan(
            ScanRequest(
                root=ROOT / "tests/golden/project",
                baseline_python="3.11",
                horizon_python="3.13",
            )
        )
        .findings[0]
        .location
    )
    incomplete = replace(
        incomplete,
        counts=ScanCounts(files_discovered=1, files_analyzed=0, files_incomplete=1),
        diagnostics=(
            Diagnostic(
                code="PYA1003",
                category=DiagnosticCategory.PARSE,
                message="analysis incomplete",
                location=synthetic_location,
                incomplete=True,
            ),
        ),
        inferences=(
            AnalysisInference(
                code="PYA2001",
                kind="module-resolution",
                message="ambiguous import",
                location=synthetic_location,
                evidence=(("candidate_paths", ("cgi.py",)),),
            ),
        ),
    )

    suppressed_root = tmp_path / "suppressed"
    suppressed_root.mkdir()
    suppressed = _scan(suppressed_root, "import cgi\n")
    finding = replace(
        suppressed.findings[0],
        baseline_status=BaselineStatus.EXISTING,
        suppression=Suppression(
            kind=SuppressionKind.PER_FILE,
            reason="accepted migration debt",
            pattern="sample.py",
        ),
    )
    suppressed = replace(
        suppressed,
        findings=(finding,),
        configuration=replace(suppressed.configuration, show_suppressed=True),
    )

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    evidence = _scan(evidence_root, "import cgi\n")
    commit = "a" * 40
    evidence = replace(
        evidence,
        source_commit=commit,
        evidence_artifacts=(
            EvidenceArtifact(
                artifact_id="b" * 64,
                path=PurePosixPath("warnings.json"),
                provider="pytest-warnings",
                provider_version="0.1.0a2",
                source_commit=commit,
                freshness=EvidenceFreshness.CURRENT,
                environment=EvidenceEnvironment(
                    implementation="cpython",
                    python_version="3.13.5",
                    platform="linux",
                ),
                framework="pytest",
                framework_version="9.1.1",
                tests_collected=1,
                exit_code=0,
                warning_count=0,
                warnings_complete=True,
                warnings_dropped=0,
            ),
        ),
    )

    golden = cast(
        "dict[str, object]",
        json.loads((ROOT / "tests/golden/report.json").read_text(encoding="utf-8")),
    )
    return (
        golden,
        cast("dict[str, object]", report_document(empty)),
        cast("dict[str, object]", report_document(incomplete)),
        cast("dict[str, object]", report_document(suppressed)),
        cast("dict[str, object]", report_document(evidence)),
    )


def test_checked_in_and_packaged_report_schema_are_generated_and_closed() -> None:
    """Both published copies exactly match one valid deterministic source."""
    generated = report_json_schema()
    checked_in = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    packaged = json.loads(PACKAGE_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(generated)

    validator.check_schema(generated)
    assert checked_in == generated == packaged, REGENERATE_HINT
    assert render_report_schema() == SCHEMA_PATH.read_text(encoding="utf-8"), (
        REGENERATE_HINT
    )

    def assert_closed(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
            for nested in value.values():
                assert_closed(nested)
        elif isinstance(value, list):
            for nested in value:
                assert_closed(nested)

    assert_closed(generated)


def test_open_key_spaces_are_specifically_documented() -> None:
    """Each object left open for extension explains why it is not enumerated."""
    generated = report_json_schema()
    open_spaces: dict[str, str] = {}

    def collect(value: object, path: str = "#") -> None:
        if isinstance(value, dict):
            if "patternProperties" in value:
                open_spaces[path] = str(value.get("description", ""))
            for key, nested in value.items():
                collect(nested, f"{path}/{key}")
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                collect(nested, f"{path}[{index}]")

    collect(generated)

    assert set(open_spaces) == {
        "#/$defs/configuration/properties/per_file_ignores",
        "#/$defs/evidenceMap",
    }
    for path, description in open_spaces.items():
        assert description, f"{path} is open for extension but undocumented"
        assert "not enumerated" in description, path


def test_every_representative_and_golden_report_validates(tmp_path: Path) -> None:
    """Ordinary, empty, incomplete, suppressed, and M7 reports stay covered."""
    validator = Draft202012Validator(report_json_schema())

    for document in _representative_documents(tmp_path):
        validator.validate(document)


def test_unknown_report_properties_are_rejected(tmp_path: Path) -> None:
    """Schema version 1 is structurally closed at top and nested levels."""
    validator = Draft202012Validator(report_json_schema())
    report = _representative_documents(tmp_path)[0]
    top_level = deepcopy(report)
    top_level["unexpected"] = True
    finding = deepcopy(report)
    findings = cast("list[dict[str, object]]", finding["findings"])
    findings[0]["unexpected"] = True

    with pytest.raises(ValidationError):
        validator.validate(top_level)
    with pytest.raises(ValidationError):
        validator.validate(finding)


def test_public_types_and_packaged_marker_are_available() -> None:
    """The documented alpha surface resolves to concrete typed classes."""
    assert ScanRequest.__module__ == "pyahead.analysis.engine"
    assert ScanReport.__module__ == "pyahead.model"
    assert Registry.__module__ == "pyahead.model"
    assert isinstance(load_registry(), Registry)
    assert resources.files("pyahead").joinpath("py.typed").is_file()
    assert resources.files("pyahead.data.schema").joinpath("report-v1.json").is_file()
