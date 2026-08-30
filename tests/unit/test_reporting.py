"""Tests for console-only report branches."""

import json
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import cast

import pytest

import pyahead.reporting.console as console_reporting
from pyahead._human_text import escape_terminal_text
from pyahead.analysis import ScanRequest, scan
from pyahead.model import (
    AnalysisInference,
    AutomationReference,
    AutomationTool,
    Diagnostic,
    DiagnosticCategory,
    EvidenceArtifact,
    EvidenceEnvironment,
    EvidenceFreshness,
    EvidenceLocation,
    EvidenceRelationship,
    EvidenceRelationshipKind,
    ObservedWarning,
    Remediation,
    SourceReference,
    Suppression,
    SuppressionKind,
)
from pyahead.reporting import render_json, render_quiet_text, render_sarif, render_text


def test_quiet_report_computes_the_exact_result_line_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quiet output stays byte-identical without rendering discarded detail."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    expected = render_text(report).splitlines()[-1] + "\n"

    def fail_if_rendered(_report: object) -> str:
        message = "quiet mode rendered the full report"
        raise AssertionError(message)

    monkeypatch.setattr(console_reporting, "render_text", fail_if_rendered)

    assert render_quiet_text(report).encode() == expected.encode()


def test_text_report_renders_multiple_findings_and_diagnostics(
    tmp_path: Path,
) -> None:
    """Human output keeps each finding and incomplete diagnostic visible."""
    (tmp_path / "legacy.py").write_text(
        "import cgi\n\ndef use():\n    import cgi\n",
        encoding="utf-8",
    )
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    report = replace(
        report,
        diagnostics=(
            Diagnostic(
                code="PYA1001",
                category=DiagnosticCategory.DISCOVERY,
                message="analysis scope was incomplete",
                incomplete=True,
            ),
        ),
    )

    rendered = render_text(report)

    assert rendered.count("CPY0001") == len(report.findings)
    assert "Match evidence: bound_names=[cgi]" in rendered
    assert "Incomplete analysis:\n  PYA1001: analysis scope was incomplete" in rendered
    assert "2 findings" in rendered


def test_module_resolution_inference_is_visible_in_both_reports(
    tmp_path: Path,
) -> None:
    """A suppressed high-confidence interpretation retains its provenance."""
    (tmp_path / "cgi.py").write_text("VALUE = 'local'\n", encoding="utf-8")
    (tmp_path / "consumer.py").write_text("import cgi\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("consumer.py"),),
        )
    )

    text = render_text(report)
    document = cast("dict[str, object]", json.loads(render_json(report)))
    inferences = cast("list[dict[str, object]]", document["inferences"])

    assert "Analysis inferences:\n  PYA2001 consumer.py:1:1" in text
    assert "candidate_paths=[cgi.py]" in text
    assert inferences[0]["code"] == "PYA2001"
    assert inferences[0]["location"] == {
        "path": "consumer.py",
        "region": {
            "end": {"column": 11, "line": 1},
            "start": {"column": 1, "line": 1},
        },
    }


def test_remediation_links_and_automation_are_inert_report_metadata(
    tmp_path: Path,
) -> None:
    """Both report formats expose, but never execute, external automation."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    finding = replace(
        report.findings[0],
        remediation=Remediation(
            summary="Use the supported replacement.",
            documentation_url="https://example.com/remediation",
            automation=AutomationReference(tool=AutomationTool.RUFF, rule="UP999"),
        ),
    )
    report = replace(report, findings=(finding,))

    text = render_text(report)
    document = cast("dict[str, object]", json.loads(render_json(report)))
    findings = cast("list[dict[str, object]]", document["findings"])
    remediation = cast("dict[str, object]", findings[0]["remediation"])

    assert "Remediation documentation: https://example.com/remediation" in text
    assert "Automation metadata: ruff UP999 (not invoked)" in text
    assert remediation == {
        "automation": {"rule": "UP999", "tool": "ruff"},
        "documentation_url": "https://example.com/remediation",
        "summary": "Use the supported replacement.",
    }


def test_text_report_distinguishes_unproven_capture_from_dropped_warnings(
    tmp_path: Path,
) -> None:
    """Zero known drops do not falsely explain why capture is incomplete."""
    (tmp_path / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    source_commit = "a" * 40
    artifact = EvidenceArtifact(
        artifact_id="b" * 64,
        path=PurePosixPath("warnings.json"),
        provider="pytest-warnings",
        provider_version="0.1.0a2",
        source_commit=source_commit,
        freshness=EvidenceFreshness.CURRENT,
        environment=EvidenceEnvironment(
            implementation="cpython",
            python_version="3.11.9",
            platform="linux",
        ),
        framework="pytest",
        framework_version="9.1.1",
        tests_collected=1,
        exit_code=0,
        warning_count=0,
        warnings_complete=False,
        warnings_dropped=0,
    )
    rendered = render_text(
        replace(
            report,
            source_commit=source_commit,
            evidence_artifacts=(artifact,),
        )
    )

    assert "warnings incomplete; capture completeness unproven" in rendered
    assert "0 occurrences omitted" not in rendered


def test_human_report_escapes_untrusted_values_without_changing_machine_data(
    tmp_path: Path,
) -> None:
    """Hostile model text cannot inject terminal structure or drift JSON/SARIF."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    hostile = "line\nINJECT\x1b[2J\r\u202e\u2028\u2029"
    escaped = escape_terminal_text(hostile)
    hostile_path = PurePosixPath(f"{hostile}.py")
    finding = replace(
        report.findings[0],
        title=hostile,
        subject=hostile,
        location=replace(report.findings[0].location, path=hostile_path),
        match_evidence=((hostile, hostile), ("tuple", (hostile,))),
        remediation=Remediation(
            summary=hostile,
            documentation_url=hostile,
            automation=AutomationReference(
                tool=AutomationTool.RUFF,
                rule=hostile,
            ),
        ),
        sources=(SourceReference(id="source", title=hostile, url=hostile),),
        suppression=Suppression(
            kind=SuppressionKind.PER_FILE,
            reason=hostile,
            pattern=hostile,
        ),
    )
    location = finding.location
    diagnostic = Diagnostic(
        code=hostile,
        category=DiagnosticCategory.DISCOVERY,
        message=hostile,
        location=location,
        incomplete=True,
    )
    inference = AnalysisInference(
        code=hostile,
        kind=hostile,
        message=hostile,
        location=location,
        evidence=((hostile, hostile),),
    )
    source_commit = "a" * 40
    artifact_id = "b" * 64
    environment = EvidenceEnvironment(
        implementation="cpython",
        python_version=hostile,
        platform=hostile,
    )
    artifact = EvidenceArtifact(
        artifact_id=artifact_id,
        path=hostile_path,
        provider=hostile,
        provider_version=hostile,
        source_commit=source_commit,
        freshness=EvidenceFreshness.CURRENT,
        environment=environment,
        framework="pytest",
        framework_version="9.1.1",
        tests_collected=1,
        exit_code=0,
        warning_count=1,
        warnings_complete=True,
        warnings_dropped=0,
    )
    observation_id = "observe\n\x1b\u2028ZZ"
    observation = ObservedWarning(
        observation_id=observation_id,
        artifact_id=artifact_id,
        provider=hostile,
        kind="warning",
        category=hostile,
        message=hostile,
        phase="runtime",
        location=EvidenceLocation(path=hostile_path, line=1),
        test_node=None,
        occurrences=1,
        environment=environment,
        source_commit=source_commit,
        freshness=EvidenceFreshness.CURRENT,
        relationships=(
            EvidenceRelationship(
                finding_fingerprint=finding.fingerprint,
                rule_id=hostile,
                subject=hostile,
                kind=EvidenceRelationshipKind.CORROBORATES,
                reasons=(hostile,),
            ),
        ),
    )
    report = replace(
        report,
        registry_release=hostile,
        configuration=replace(report.configuration, show_suppressed=True),
        policy_provenance=replace(
            report.policy_provenance,
            baseline_python=hostile,
            horizon_python=hostile,
            requires_python=hostile,
        ),
        findings=(finding,),
        diagnostics=(diagnostic,),
        inferences=(inference,),
        source_commit=source_commit,
        evidence_artifacts=(artifact,),
        observed_warnings=(observation,),
    )

    text = render_text(report)
    document = cast("dict[str, object]", json.loads(render_json(report)))
    sarif = cast("dict[str, object]", json.loads(render_sarif(report)))

    assert escaped in text
    assert hostile not in text
    assert "\nINJECT" not in text
    for control in ("\r", "\x1b", "\u202e", "\u2028", "\u2029"):
        assert control not in text

    findings = cast("list[dict[str, object]]", document["findings"])
    machine_finding = findings[0]
    assert machine_finding["title"] == hostile
    assert machine_finding["subject"] == hostile
    assert cast("dict[str, object]", machine_finding["location"])["path"] == str(
        hostile_path
    )
    assert (
        cast("dict[str, object]", machine_finding["remediation"])["summary"] == hostile
    )
    diagnostics = cast("list[dict[str, object]]", document["diagnostics"])
    assert diagnostics[0]["message"] == hostile
    inferences = cast("list[dict[str, object]]", document["inferences"])
    assert inferences[0]["message"] == hostile
    evidence = cast("dict[str, object]", document["evidence"])
    observations = cast("list[dict[str, object]]", evidence["observations"])
    assert observations[0]["message"] == hostile

    runs = cast("list[dict[str, object]]", sarif["runs"])
    driver = cast(
        "dict[str, object]",
        cast("dict[str, object]", runs[0]["tool"])["driver"],
    )
    rules = cast("list[dict[str, object]]", driver["rules"])
    assert cast("dict[str, object]", rules[0]["shortDescription"])["text"] == hostile
    invocations = cast("list[dict[str, object]]", runs[0]["invocations"])
    notifications = cast(
        "list[dict[str, object]]", invocations[0]["toolExecutionNotifications"]
    )
    assert cast("dict[str, object]", notifications[0]["message"])["text"] == hostile


def test_stale_evidence_escapes_artifact_observation_and_scan_commits(
    tmp_path: Path,
) -> None:
    """Direct model construction cannot bypass stale-commit text sanitization."""
    (tmp_path / "clean.py").write_text("VALUE = 1\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    scan_commit = "scan\ncommit\x1bZZ"
    artifact_commit = "artifact\r\u2028ZZ"
    observation_commit = "observe\u202e\u2029ZZ"
    observation_id = "observe\n\x1b\u2028ZZ"
    artifact_id = "b" * 64
    environment = EvidenceEnvironment(
        implementation="cpython",
        python_version="3.11.9",
        platform="linux",
    )
    artifact = EvidenceArtifact(
        artifact_id=artifact_id,
        path=PurePosixPath("warnings.json"),
        provider="pytest-warnings",
        provider_version="0.1.0a2",
        source_commit=artifact_commit,
        freshness=EvidenceFreshness.STALE,
        environment=environment,
        framework="pytest",
        framework_version="9.1.1",
        tests_collected=1,
        exit_code=0,
        warning_count=1,
        warnings_complete=True,
        warnings_dropped=0,
    )
    observation = ObservedWarning(
        observation_id=observation_id,
        artifact_id=artifact_id,
        provider="pytest-warnings",
        kind="warning",
        category="DeprecationWarning",
        message="deprecated API",
        phase="runtime",
        location=None,
        test_node=None,
        occurrences=1,
        environment=environment,
        source_commit=observation_commit,
        freshness=EvidenceFreshness.STALE,
        relationships=(),
    )

    rendered = render_text(
        replace(
            report,
            source_commit=scan_commit,
            evidence_artifacts=(artifact,),
            observed_warnings=(observation,),
        )
    )

    assert escape_terminal_text(scan_commit[:12]) in rendered
    assert escape_terminal_text(artifact_commit[:12]) in rendered
    assert escape_terminal_text(observation_commit[:12]) in rendered
    assert escape_terminal_text(observation_id[:12]) in rendered
    for control in ("\ncommit", "\r", "\x1b", "\u202e", "\u2028", "\u2029"):
        assert control not in rendered
