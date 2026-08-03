"""Deterministic SARIF 2.1.0 reporting."""

import json
import re
from urllib.parse import quote

from pyahead.model import (
    AnalysisInference,
    BaselineStatus,
    Diagnostic,
    EvidenceValue,
    Finding,
    Impact,
    ScanReport,
    SourceLocation,
    SuppressionKind,
)
from pyahead.reporting.json import JsonValue

_LEVELS = {
    Impact.BREAKING: "error",
    Impact.RISK: "warning",
    Impact.DEPRECATED: "note",
    Impact.INFORMATIONAL: "note",
}
_PEP_440_ALPHA = re.compile(r"(?P<base>\d+\.\d+\.\d+)(?P<kind>a|b|rc)(?P<number>\d+)\Z")


def _semantic_version(version: str) -> str:
    match = _PEP_440_ALPHA.fullmatch(version)
    if match is None:
        return version
    labels = {"a": "alpha", "b": "beta", "rc": "rc"}
    return (
        f"{match.group('base')}-{labels[match.group('kind')]}.{match.group('number')}"
    )


def _rule_descriptor(finding: Finding) -> dict[str, JsonValue]:
    descriptor: dict[str, JsonValue] = {
        "fullDescription": {"text": finding.remediation.summary},
        "helpUri": finding.sources[0].url,
        "id": finding.rule_id,
        "properties": {
            "registryRevision": finding.registry_revision,
            "tags": ["pyahead", *sorted({finding.match_kind})],
        },
        "shortDescription": {"text": finding.title},
    }
    return descriptor


def _physical_location(location: SourceLocation) -> dict[str, JsonValue]:
    region = location.region
    return {
        "artifactLocation": {
            "uri": quote(location.path.as_posix(), safe="/-._~"),
            "uriBaseId": "%SRCROOT%",
        },
        "region": {
            "endColumn": region.end.column,
            "endLine": region.end.line,
            "startColumn": region.start.column,
            "startLine": region.start.line,
        },
    }


def _result(
    finding: Finding,
    rule_index: int,
) -> dict[str, JsonValue]:
    states: list[JsonValue] = [
        {
            "from": str(state.from_python),
            "state": state.state.value,
            "through": str(state.through_python),
        }
        for state in finding.states
    ]
    result: dict[str, JsonValue] = {
        "baselineState": (
            "unchanged" if finding.baseline_status is BaselineStatus.EXISTING else "new"
        ),
        "level": _LEVELS[finding.impact],
        "locations": [
            {
                "physicalLocation": _physical_location(finding.location),
            }
        ],
        "message": {
            "text": (
                f"{finding.title}: {finding.subject} is "
                f"{finding.impact.value} for the configured Python policy."
            )
        },
        "partialFingerprints": {"pyahead/v1": finding.fingerprint},
        "properties": {
            "impact": finding.impact.value,
            "matchConfidence": finding.match_confidence.value,
            "registryCertaintyByEvent": [
                {
                    "certainty": event.certainty.value,
                    "event": event.kind.value,
                    "python": str(event.python),
                }
                for event in finding.events
            ],
            "registryRevision": finding.registry_revision,
            "removalUnscheduled": finding.removal_unscheduled,
            "suppressed": finding.suppression is not None,
            "usageContexts": [context.value for context in finding.usage_contexts],
            "versionStates": states,
        },
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
    }
    if finding.suppression is not None:
        suppression: dict[str, JsonValue] = {
            "kind": (
                "inSource"
                if finding.suppression.kind is SuppressionKind.INLINE
                else "external"
            )
        }
        if finding.suppression.reason is not None:
            suppression["justification"] = finding.suppression.reason
        result["suppressions"] = [suppression]
    return result


def _notification_descriptor(
    notification: Diagnostic | AnalysisInference,
) -> dict[str, JsonValue]:
    """Describe one stable diagnostic or inference code."""
    description = (
        f"PyAhead {notification.category.value} diagnostic."
        if isinstance(notification, Diagnostic)
        else f"PyAhead {notification.kind} analysis inference."
    )
    return {
        "id": notification.code,
        "shortDescription": {"text": description},
    }


def _notification(
    diagnostic: Diagnostic,
    descriptor_index: int,
) -> dict[str, JsonValue]:
    """Represent one scan diagnostic as a SARIF tool notification."""
    notification: dict[str, JsonValue] = {
        "descriptor": {"id": diagnostic.code, "index": descriptor_index},
        "level": "error" if diagnostic.fatal else "warning",
        "message": {"text": diagnostic.message},
        "properties": {
            "category": diagnostic.category.value,
            "code": diagnostic.code,
            "fatal": diagnostic.fatal,
            "incomplete": diagnostic.incomplete,
        },
    }
    if diagnostic.location is not None:
        notification["locations"] = [
            {"physicalLocation": _physical_location(diagnostic.location)}
        ]
    return notification


def _evidence(
    evidence: tuple[tuple[str, EvidenceValue], ...],
) -> dict[str, JsonValue]:
    return {
        key: list(value) if isinstance(value, tuple) else value
        for key, value in evidence
    }


def _inference_notification(
    inference: AnalysisInference,
    descriptor_index: int,
) -> dict[str, JsonValue]:
    """Represent conservative analysis provenance as a note notification."""
    return {
        "descriptor": {"id": inference.code, "index": descriptor_index},
        "level": "note",
        "locations": [{"physicalLocation": _physical_location(inference.location)}],
        "message": {"text": inference.message},
        "properties": {
            "code": inference.code,
            "evidence": _evidence(inference.evidence),
            "kind": inference.kind,
        },
    }


def sarif_document(report: ScanReport) -> dict[str, JsonValue]:
    """Build one valid deterministic SARIF run."""
    findings = report.visible_findings
    representative_by_rule = {finding.rule_id: finding for finding in findings}
    rule_ids = tuple(sorted(representative_by_rule))
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    representative_by_notification: dict[str, Diagnostic | AnalysisInference] = {}
    for diagnostic in report.diagnostics:
        representative_by_notification.setdefault(diagnostic.code, diagnostic)
    for inference in report.inferences:
        representative_by_notification.setdefault(inference.code, inference)
    notification_codes = tuple(sorted(representative_by_notification))
    notification_indexes = {
        code: index for index, code in enumerate(notification_codes)
    }
    tool_notifications: list[JsonValue] = [
        _notification(
            diagnostic,
            notification_indexes[diagnostic.code],
        )
        for diagnostic in report.diagnostics
    ]
    tool_notifications.extend(
        _inference_notification(
            inference,
            notification_indexes[inference.code],
        )
        for inference in report.inferences
    )
    scan_complete = report.counts.files_incomplete == 0
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "columnKind": "unicodeCodePoints",
                "invocations": [
                    {
                        "executionSuccessful": (
                            not any(item.fatal for item in report.diagnostics)
                            and (scan_complete or report.configuration.allow_incomplete)
                        ),
                        "properties": {
                            "filesAnalyzed": report.counts.files_analyzed,
                            "filesDiscovered": report.counts.files_discovered,
                            "filesIncomplete": report.counts.files_incomplete,
                            "scanComplete": scan_complete,
                        },
                        "toolExecutionNotifications": tool_notifications,
                    }
                ],
                "results": [
                    _result(finding, rule_indexes[finding.rule_id])
                    for finding in findings
                ],
                "tool": {
                    "driver": {
                        "name": "pyahead",
                        "notifications": [
                            _notification_descriptor(
                                representative_by_notification[code]
                            )
                            for code in notification_codes
                        ],
                        "rules": [
                            _rule_descriptor(representative_by_rule[rule_id])
                            for rule_id in rule_ids
                        ],
                        "semanticVersion": _semantic_version(report.tool_version),
                        "version": report.tool_version,
                    }
                },
            }
        ],
        "version": "2.1.0",
    }


def render_sarif(report: ScanReport) -> str:
    """Serialize byte-stable SARIF without terminal output."""
    return (
        json.dumps(
            sarif_document(report),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = ["render_sarif", "sarif_document"]
