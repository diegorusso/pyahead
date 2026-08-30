"""Deterministic JSON Schema for the public static report contract."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from enum import StrEnum
    from pathlib import Path

from pyahead.model import (
    AutomationTool,
    BaselineStatus,
    ChangeEventKind,
    DiagnosticCategory,
    EvidenceFreshness,
    EvidenceRelationshipKind,
    FailOn,
    FindingState,
    Impact,
    MatchConfidence,
    RegistryCertainty,
    SuppressionKind,
    UsageContext,
)

Schema = dict[str, object]


def _reference(name: str) -> Schema:
    return {"$ref": f"#/$defs/{name}"}


def _array(items: Schema) -> Schema:
    return {"items": items, "type": "array"}


def _object(
    properties: Mapping[str, object],
    *,
    required: tuple[str, ...] | None = None,
    pattern_properties: Mapping[str, object] | None = None,
    description: str | None = None,
) -> Schema:
    document: Schema = {
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required if required is not None else properties),
        "type": "object",
    }
    if pattern_properties is not None:
        document["patternProperties"] = dict(pattern_properties)
    if description is not None:
        document["description"] = description
    return document


def _string_enum(values: Iterable[StrEnum]) -> Schema:
    return {"enum": [item.value for item in values], "type": "string"}


def _nullable(schema: Schema) -> Schema:
    return {"anyOf": [schema, {"type": "null"}]}


def _definitions() -> dict[str, object]:
    non_negative_integer: Schema = {"minimum": 0, "type": "integer"}
    positive_integer: Schema = {"minimum": 1, "type": "integer"}
    string: Schema = {"type": "string"}
    string_array = _array(string)
    position = _object(
        {"column": positive_integer, "line": positive_integer},
    )
    region = _object(
        {"end": _reference("position"), "start": _reference("position")},
    )
    location = _object(
        {"path": string, "region": _reference("region")},
    )
    evidence_value: Schema = {
        "oneOf": [string, string_array],
    }
    evidence_map = _object(
        {},
        required=(),
        pattern_properties={"^.*$": evidence_value},
        description=(
            "Matcher-defined evidence keys. Matchers own this key space, so the "
            "keys are deliberately not enumerated and this object stays open; "
            "every value is a string or an array of strings."
        ),
    )
    automation = _object(
        {
            "rule": string,
            "tool": _string_enum(AutomationTool),
        },
    )
    remediation = _object(
        {
            "automation": _reference("automation"),
            "documentation_url": string,
            "summary": string,
        },
        required=("summary",),
    )
    source = _object(
        {"id": string, "title": string, "url": string},
    )
    state = _object(
        {
            "from": string,
            "state": _string_enum(FindingState),
            "through": string,
        },
    )
    timeline_event = _object(
        {
            "certainty": _string_enum(RegistryCertainty),
            "event": _string_enum(ChangeEventKind),
            "python": string,
            "source": string,
        },
    )
    suppression = _object(
        {
            "kind": _string_enum(SuppressionKind),
            "pattern": string,
            "reason": string,
        },
        required=("kind",),
    )
    inferred_evidence = _object(
        {"details": _reference("evidenceMap"), "kind": {"const": "static-match"}},
    )
    finding_evidence = _object(
        {
            "inferred": _reference("inferredEvidence"),
            "observed": string_array,
        },
    )
    match = _object(
        {
            "confidence": _string_enum(MatchConfidence),
            "evidence": _reference("evidenceMap"),
            "kind": string,
        },
    )
    finding = _object(
        {
            "action_version": string,
            "baseline_status": _string_enum(BaselineStatus),
            "enclosing_scope": string,
            "evidence": _reference("findingEvidence"),
            "fingerprint": string,
            "impact": _string_enum(Impact),
            "location": _reference("location"),
            "match": _reference("match"),
            "reachable_versions": string_array,
            "registry_revision": string,
            "remediation": _reference("remediation"),
            "removal_unscheduled": {"type": "boolean"},
            "rule_id": string,
            "sources": _array(_reference("source")),
            "states": _array(_reference("state")),
            "subject": string,
            "suppressed": {"type": "boolean"},
            "suppression": _reference("suppression"),
            "timeline": _array(_reference("timelineEvent")),
            "title": string,
            "usage_contexts": _array(_string_enum(UsageContext)),
        },
        required=(
            "action_version",
            "baseline_status",
            "enclosing_scope",
            "fingerprint",
            "impact",
            "location",
            "match",
            "reachable_versions",
            "registry_revision",
            "remediation",
            "removal_unscheduled",
            "rule_id",
            "sources",
            "states",
            "subject",
            "suppressed",
            "timeline",
            "title",
            "usage_contexts",
        ),
    )
    diagnostic = _object(
        {
            "category": _string_enum(DiagnosticCategory),
            "code": string,
            "fatal": {"type": "boolean"},
            "incomplete": {"type": "boolean"},
            "location": _nullable(_reference("location")),
            "message": string,
        },
    )
    inference = _object(
        {
            "code": string,
            "evidence": _reference("evidenceMap"),
            "kind": string,
            "location": _reference("location"),
            "message": string,
        },
    )
    configuration = _object(
        {
            "allow_incomplete": {"type": "boolean"},
            "exclude": string_array,
            "fail_new_only": {"type": "boolean"},
            "fail_on": _string_enum(FailOn),
            "include": string_array,
            "max_file_size_bytes": non_negative_integer,
            "minimum_confidence": _string_enum(MatchConfidence),
            "per_file_ignores": _object(
                {},
                required=(),
                pattern_properties={"^.*$": string_array},
                description=(
                    "Project-defined path patterns. The project owns this key "
                    "space, so the patterns are deliberately not enumerated and "
                    "this object stays open; every value is the list of rule "
                    "identifiers ignored for the matching files."
                ),
            ),
            "respect_gitignore": {"type": "boolean"},
            "show_suppressed": {"type": "boolean"},
            "show_unscheduled": {"type": "boolean"},
            "source_roots": string_array,
            "source_roots_provenance": string,
        },
    )
    provenance = _object(
        {
            "baseline_python": string,
            "horizon_python": string,
            "requires_python": string,
        },
        required=("baseline_python", "horizon_python"),
    )
    policy = _object(
        {
            "baseline_python": string,
            "horizon_python": string,
            "provenance": _reference("provenance"),
            "versions": string_array,
        },
    )
    registry = _object({"release": string, "revision": string})
    scan = _object(
        {
            "files_analyzed": non_negative_integer,
            "files_discovered": non_negative_integer,
            "files_incomplete": non_negative_integer,
            "root": string,
        },
    )
    summary = _object(
        {
            "breaking": non_negative_integer,
            "deprecated": non_negative_integer,
            "informational": non_negative_integer,
            "new": non_negative_integer,
            "observed": non_negative_integer,
            "observed_stale": non_negative_integer,
            "observed_unmatched": non_negative_integer,
            "risk": non_negative_integer,
            "suppressed": non_negative_integer,
        },
        required=(
            "breaking",
            "deprecated",
            "informational",
            "new",
            "risk",
            "suppressed",
        ),
    )
    tool = _object(
        {"name": {"const": "pyahead"}, "version": string},
    )
    gate = _object(
        {
            "fail_on": _string_enum(FailOn),
            "failed": {"type": "boolean"},
            "new_only": {"type": "boolean"},
        },
    )
    evidence_environment = _object(
        {"implementation": string, "platform": string, "python_version": string},
    )
    artifact_provider = _object({"name": string, "version": string})
    artifact_run = _object(
        {
            "exit_code": non_negative_integer,
            "framework": string,
            "framework_version": string,
            "tests_collected": non_negative_integer,
            "warnings_complete": {"type": "boolean"},
            "warnings_dropped": non_negative_integer,
        },
    )
    artifact = _object(
        {
            "artifact_id": string,
            "environment": _reference("evidenceEnvironment"),
            "freshness": _string_enum(EvidenceFreshness),
            "path": string,
            "provider": _reference("artifactProvider"),
            "run": _reference("artifactRun"),
            "source_commit": string,
            "warning_count": non_negative_integer,
        },
    )
    relationship = _object(
        {
            "finding_fingerprint": string,
            "kind": _string_enum(EvidenceRelationshipKind),
            "reasons": string_array,
            "rule_id": string,
            "subject": string,
        },
    )
    observation_location = _object(
        {"line": positive_integer, "path": string},
    )
    observation = _object(
        {
            "artifact_id": string,
            "category": string,
            "environment": _reference("evidenceEnvironment"),
            "freshness": _string_enum(EvidenceFreshness),
            "kind": string,
            "linked_fingerprints": string_array,
            "location": _reference("observationLocation"),
            "message": string,
            "observation_id": string,
            "occurrences": positive_integer,
            "phase": string,
            "provider": string,
            "relationships": _array(_reference("relationship")),
            "source_commit": string,
            "test_node": string,
        },
        required=(
            "artifact_id",
            "category",
            "environment",
            "freshness",
            "kind",
            "linked_fingerprints",
            "message",
            "observation_id",
            "occurrences",
            "phase",
            "provider",
            "relationships",
            "source_commit",
        ),
    )
    report_evidence = _object(
        {
            "artifacts": _array(_reference("artifact")),
            "observations": _array(_reference("observation")),
            "source_commit": string,
        },
    )
    return {
        "artifact": artifact,
        "artifactProvider": artifact_provider,
        "artifactRun": artifact_run,
        "automation": automation,
        "configuration": configuration,
        "diagnostic": diagnostic,
        "evidenceEnvironment": evidence_environment,
        "evidenceMap": evidence_map,
        "finding": finding,
        "findingEvidence": finding_evidence,
        "gate": gate,
        "inference": inference,
        "inferredEvidence": inferred_evidence,
        "location": location,
        "match": match,
        "observation": observation,
        "observationLocation": observation_location,
        "policy": policy,
        "position": position,
        "provenance": provenance,
        "region": region,
        "registry": registry,
        "relationship": relationship,
        "remediation": remediation,
        "reportEvidence": report_evidence,
        "scan": scan,
        "source": source,
        "state": state,
        "summary": summary,
        "suppression": suppression,
        "timelineEvent": timeline_event,
        "tool": tool,
    }


def report_json_schema() -> Schema:
    """Return the closed public JSON Schema for report schema version 1."""
    properties: dict[str, object] = {
        "configuration": _reference("configuration"),
        "diagnostics": _array(_reference("diagnostic")),
        "evidence": _reference("reportEvidence"),
        "findings": _array(_reference("finding")),
        "gate": _reference("gate"),
        "inferences": _array(_reference("inference")),
        "policy": _reference("policy"),
        "registry": _reference("registry"),
        "scan": _reference("scan"),
        "schema_version": {"const": 1, "type": "integer"},
        "summary": _reference("summary"),
        "tool": _reference("tool"),
    }
    schema = _object(
        properties,
        required=tuple(key for key in properties if key != "evidence"),
    )
    schema.update(
        {
            "$comment": (
                "Matcher and inference evidence are intentionally extensible "
                "string-keyed maps whose values remain closed to strings or "
                "string arrays; every structural report object is closed."
            ),
            "$defs": _definitions(),
            "$id": (
                "https://github.com/diegorusso/pyahead/blob/main/"
                "docs/schema/report-v1.json"
            ),
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "PyAhead static scan report schema version 1",
        }
    )
    return schema


def render_report_schema() -> str:
    """Serialize the report schema deterministically."""
    return json.dumps(report_json_schema(), indent=2, sort_keys=True) + "\n"


def write_report_schema(*destinations: Path) -> None:
    """Write identical checked-in documentation and package schema copies."""
    rendered = render_report_schema()
    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")


__all__ = ["render_report_schema", "report_json_schema", "write_report_schema"]
