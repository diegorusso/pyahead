"""Deterministic JSON serialization for static scan reports."""

import json
from typing import TypeAlias

from pyahead.model import (
    AnalysisInference,
    Diagnostic,
    EvidenceArtifact,
    EvidenceValue,
    Finding,
    Impact,
    ObservedWarning,
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


def _finding(
    finding: Finding,
    *,
    observations: tuple[ObservedWarning, ...] = (),
    include_evidence: bool = False,
) -> dict[str, JsonValue]:
    remediation: dict[str, JsonValue] = {"summary": finding.remediation.summary}
    if finding.remediation.documentation_url is not None:
        remediation["documentation_url"] = finding.remediation.documentation_url
    if finding.remediation.automation is not None:
        automation = finding.remediation.automation
        remediation["automation"] = {
            "rule": automation.rule,
            "tool": automation.tool.value,
        }
    document: dict[str, JsonValue] = {
        "action_version": str(finding.action_version),
        "baseline_status": finding.baseline_status.value,
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
        "removal_unscheduled": finding.removal_unscheduled,
        "reachable_versions": [str(version) for version in finding.reachable_versions],
        "remediation": remediation,
        "rule_id": finding.rule_id,
        "sources": [
            {"id": source.id, "title": source.title, "url": source.url}
            for source in finding.sources
        ],
        "subject": finding.subject,
        "suppressed": finding.suppression is not None,
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
    if finding.suppression is not None:
        suppression: dict[str, JsonValue] = {"kind": finding.suppression.kind.value}
        if finding.suppression.reason is not None:
            suppression["reason"] = finding.suppression.reason
        if finding.suppression.pattern is not None:
            suppression["pattern"] = finding.suppression.pattern
        document["suppression"] = suppression
    if include_evidence:
        document["evidence"] = {
            "inferred": {
                "details": _evidence(finding.match_evidence),
                "kind": "static-match",
            },
            "observed": [item.observation_id for item in observations],
        }
    return document


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
    suppressed = 0
    new = 0
    for finding in report.findings:
        if finding.suppression is not None:
            suppressed += 1
            continue
        counts[finding.impact.value] += 1
        if finding.baseline_status.value == "new":
            new += 1
    summary: dict[str, JsonValue] = {
        "breaking": counts[Impact.BREAKING.value],
        "deprecated": counts[Impact.DEPRECATED.value],
        "informational": counts[Impact.INFORMATIONAL.value],
        "new": new,
        "risk": counts[Impact.RISK.value],
        "suppressed": suppressed,
    }
    if report.has_evidence:
        summary.update(
            {
                "observed": len(report.observed_warnings),
                "observed_stale": sum(
                    item.freshness.value == "stale" for item in report.observed_warnings
                ),
                "observed_unmatched": len(report.unmatched_observations),
            }
        )
    return summary


def _artifact(artifact: EvidenceArtifact) -> dict[str, JsonValue]:
    """Serialize one validated evidence artifact summary."""
    return {
        "artifact_id": artifact.artifact_id,
        "environment": {
            "implementation": artifact.environment.implementation,
            "platform": artifact.environment.platform,
            "python_version": artifact.environment.python_version,
        },
        "freshness": artifact.freshness.value,
        "path": artifact.path.as_posix(),
        "provider": {
            "name": artifact.provider,
            "version": artifact.provider_version,
        },
        "run": {
            "exit_code": artifact.exit_code,
            "framework": artifact.framework,
            "framework_version": artifact.framework_version,
            "tests_collected": artifact.tests_collected,
            "warnings_complete": artifact.warnings_complete,
            "warnings_dropped": artifact.warnings_dropped,
        },
        "source_commit": artifact.source_commit,
        "warning_count": artifact.warning_count,
    }


def _observation(observation: ObservedWarning) -> dict[str, JsonValue]:
    """Serialize one normalized warning and its static-finding links."""
    document: dict[str, JsonValue] = {
        "artifact_id": observation.artifact_id,
        "category": observation.category,
        "environment": {
            "implementation": observation.environment.implementation,
            "platform": observation.environment.platform,
            "python_version": observation.environment.python_version,
        },
        "freshness": observation.freshness.value,
        "kind": observation.kind,
        "linked_fingerprints": list(observation.linked_fingerprints),
        "message": observation.message,
        "observation_id": observation.observation_id,
        "occurrences": observation.occurrences,
        "phase": observation.phase,
        "provider": observation.provider,
        "relationships": [
            {
                "finding_fingerprint": relationship.finding_fingerprint,
                "kind": relationship.kind.value,
                "reasons": list(relationship.reasons),
                "rule_id": relationship.rule_id,
                "subject": relationship.subject,
            }
            for relationship in observation.relationships
        ],
        "source_commit": observation.source_commit,
    }
    if observation.location is not None:
        document["location"] = {
            "line": observation.location.line,
            "path": observation.location.path.as_posix(),
        }
    if observation.test_node is not None:
        document["test_node"] = observation.test_node
    return document


def _configuration(report: ScanReport) -> dict[str, JsonValue]:
    configuration = report.configuration
    return {
        "allow_incomplete": configuration.allow_incomplete,
        "exclude": list(configuration.exclude),
        "fail_new_only": configuration.fail_new_only,
        "fail_on": configuration.fail_on.value,
        "include": list(configuration.include),
        "max_file_size_bytes": configuration.max_file_size_bytes,
        "minimum_confidence": configuration.minimum_confidence.value,
        "per_file_ignores": {
            item.pattern: list(item.rule_ids) for item in configuration.per_file_ignores
        },
        "respect_gitignore": configuration.respect_gitignore,
        "show_suppressed": configuration.show_suppressed,
        "show_unscheduled": configuration.show_unscheduled,
        "source_roots": list(configuration.source_roots),
        "source_roots_provenance": configuration.source_roots_provenance,
    }


def _policy_provenance(report: ScanReport) -> dict[str, JsonValue]:
    provenance: dict[str, JsonValue] = {
        "baseline_python": report.policy_provenance.baseline_python,
        "horizon_python": report.policy_provenance.horizon_python,
    }
    if report.policy_provenance.requires_python is not None:
        provenance["requires_python"] = report.policy_provenance.requires_python
    return provenance


def report_document(report: ScanReport) -> dict[str, JsonValue]:
    """Build the JSON document without timestamps or absolute paths."""
    observations_by_fingerprint = report.observations_by_fingerprint
    document: dict[str, JsonValue] = {
        "configuration": _configuration(report),
        "diagnostics": [_diagnostic(item) for item in report.diagnostics],
        "findings": [
            _finding(
                item,
                observations=observations_by_fingerprint.get(item.fingerprint, ()),
                include_evidence=report.has_evidence,
            )
            for item in report.visible_findings
        ],
        "gate": {
            "fail_on": report.configuration.fail_on.value,
            "failed": report.gate_failed,
            "new_only": report.configuration.fail_new_only,
        },
        "inferences": [_inference(item) for item in report.inferences],
        "policy": {
            "baseline_python": str(report.policy.baseline_python),
            "horizon_python": str(report.policy.horizon_python),
            "provenance": _policy_provenance(report),
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
    if report.has_evidence:
        document["evidence"] = {
            "artifacts": [_artifact(item) for item in report.evidence_artifacts],
            "observations": [_observation(item) for item in report.observed_warnings],
            "source_commit": report.source_commit,
        }
    return document


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
