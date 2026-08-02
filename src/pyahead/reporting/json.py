"""Deterministic JSON serialization for static scan reports."""

import json
from typing import TypeAlias

from pyahead.model import (
    AnalysisInference,
    Diagnostic,
    EvidenceValue,
    Finding,
    Impact,
    ScanReport,
    SourceLocation,
)

JsonScalar: TypeAlias = bool | int | str | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def _position(line: int, column: int) -> dict[str, JsonValue]:
    return {"column": column, "line": line}


def _location(location: SourceLocation) -> dict[str, JsonValue]:
    return {
        "path": location.path.as_posix(),
        "region": {
            "end": _position(
                location.region.end.line,
                location.region.end.column,
            ),
            "start": _position(
                location.region.start.line,
                location.region.start.column,
            ),
        },
    }


def _evidence(
    evidence: tuple[tuple[str, EvidenceValue], ...],
) -> dict[str, JsonValue]:
    return {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in evidence
    }


def _finding(finding: Finding) -> dict[str, JsonValue]:
    remediation: dict[str, JsonValue] = {"summary": finding.remediation.summary}
    if finding.remediation.documentation_url is not None:
        remediation["documentation_url"] = finding.remediation.documentation_url
    if finding.remediation.automation is not None:
        automation = finding.remediation.automation
        remediation["automation"] = {
            "rule": automation.rule,
            "tool": automation.tool.value,
        }
    return {
        "action_version": str(finding.action_version),
        "enclosing_scope": finding.enclosing_scope,
        "fingerprint": finding.fingerprint,
        "impact": finding.impact.value,
        "location": _location(finding.location),
        "match": {
            "confidence": finding.match_confidence.value,
            "evidence": _evidence(finding.match_evidence),
            "kind": finding.match_kind,
        },
        "registry_revision": finding.registry_revision,
        "reachable_versions": [str(version) for version in finding.reachable_versions],
        "remediation": remediation,
        "rule_id": finding.rule_id,
        "sources": [
            {"id": source.id, "title": source.title, "url": source.url}
            for source in finding.sources
        ],
        "subject": finding.subject,
        "states": [
            {
                "from": str(state.from_python),
                "state": state.state.value,
                "through": str(state.through_python),
            }
            for state in finding.states
        ],
        "timeline": [
            {
                "certainty": event.certainty.value,
                "event": event.kind.value,
                "python": str(event.python),
                "source": event.source_id,
            }
            for event in finding.events
        ],
        "title": finding.title,
        "usage_contexts": [context.value for context in finding.usage_contexts],
    }


def _inference(inference: AnalysisInference) -> dict[str, JsonValue]:
    return {
        "code": inference.code,
        "evidence": _evidence(inference.evidence),
        "kind": inference.kind,
        "location": _location(inference.location),
        "message": inference.message,
    }


def _diagnostic(diagnostic: Diagnostic) -> dict[str, JsonValue]:
    return {
        "category": diagnostic.category.value,
        "code": diagnostic.code,
        "fatal": diagnostic.fatal,
        "incomplete": diagnostic.incomplete,
        "location": (
            _location(diagnostic.location) if diagnostic.location is not None else None
        ),
        "message": diagnostic.message,
    }


def _versions(report: ScanReport) -> list[JsonValue]:
    return [str(version) for version in sorted(report.policy.target_versions)]


def _summary(report: ScanReport) -> dict[str, JsonValue]:
    counts = {impact.value: 0 for impact in Impact}
    for finding in report.findings:
        counts[finding.impact.value] += 1
    return {
        "breaking": counts[Impact.BREAKING.value],
        "deprecated": counts[Impact.DEPRECATED.value],
        "informational": counts[Impact.INFORMATIONAL.value],
        "new": len(report.findings),
        "risk": counts[Impact.RISK.value],
        "suppressed": 0,
    }


def report_document(report: ScanReport) -> dict[str, JsonValue]:
    """Build the JSON document without timestamps or absolute paths."""
    return {
        "diagnostics": [_diagnostic(item) for item in report.diagnostics],
        "findings": [_finding(item) for item in report.findings],
        "gate": {
            "fail_on": "breaking",
            "failed": report.gate_failed,
            "new_only": False,
        },
        "inferences": [_inference(item) for item in report.inferences],
        "policy": {
            "baseline_python": str(report.policy.baseline_python),
            "horizon_python": str(report.policy.horizon_python),
            "provenance": {
                "baseline_python": "command-line",
                "horizon_python": "command-line",
            },
            "versions": _versions(report),
        },
        "registry": {
            "release": report.registry_release,
            "revision": report.registry_revision,
        },
        "scan": {
            "files_analyzed": report.counts.files_analyzed,
            "files_discovered": report.counts.files_discovered,
            "files_incomplete": report.counts.files_incomplete,
            "root": report.root_label,
        },
        "schema_version": report.schema_version,
        "summary": _summary(report),
        "tool": {"name": "pyahead", "version": report.tool_version},
    }


def render_json(report: ScanReport) -> str:
    """Render byte-stable UTF-8 JSON for a scan report."""
    return (
        json.dumps(
            report_document(report),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
