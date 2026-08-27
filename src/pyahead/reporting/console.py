"""Deterministic plain-text rendering for static scan reports."""

from collections import Counter
from itertools import groupby
from unicodedata import category as unicode_category

from pyahead.model import (
    AnalysisInference,
    Diagnostic,
    EvidenceArtifact,
    EvidenceValue,
    Finding,
    ObservedWarning,
    ScanReport,
)

_UNICODE_BMP_MAX = 0xFFFF


def _artifact_text(value: str) -> str:
    """Escape controls that could manipulate a terminal or split a CI log."""
    rendered: list[str] = []
    for character in value:
        codepoint = ord(character)
        category = unicode_category(character)
        if category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            escape = (
                f"\\u{codepoint:04x}"
                if codepoint <= _UNICODE_BMP_MAX
                else f"\\U{codepoint:08x}"
            )
            rendered.append(escape)
        else:
            rendered.append(character)
    return "".join(rendered)


def _evidence_text(evidence: tuple[tuple[str, EvidenceValue], ...]) -> str:
    def render(value: EvidenceValue) -> str:
        return f"[{', '.join(value)}]" if isinstance(value, tuple) else value

    return "; ".join(f"{key}={render(value)}" for key, value in evidence)


def _observed_warning_line(
    observation: ObservedWarning,
    *,
    source_commit: str,
) -> str:
    if observation.location is None:
        where = "external or unavailable location"
    else:
        path = _artifact_text(observation.location.path.as_posix())
        where = f"{path}:{observation.location.line}"
    occurrence = (
        f"; {observation.occurrences} occurrences"
        if observation.occurrences != 1
        else ""
    )
    stale = (
        f"; stale for {observation.source_commit[:12]} (scan {source_commit[:12]})"
        if observation.freshness.value == "stale"
        else "; current commit"
    )
    relationships = ""
    if observation.relationships:
        rendered_relationships = ", ".join(
            f"{relationship.rule_id}={relationship.kind.value} "
            f"({', '.join(relationship.reasons)})"
            for relationship in observation.relationships
        )
        relationships = f"; relationships: {rendered_relationships}"
    return (
        f"{observation.observation_id[:12]} "
        f"{_artifact_text(observation.provider)} {where} "
        f"[{_artifact_text(observation.category)}]: "
        f"{_artifact_text(observation.message)} "
        f"(Python {_artifact_text(observation.environment.python_version)}"
        f"{occurrence}{stale}"
        f"{relationships})"
    )


def _artifact_line(artifact: EvidenceArtifact, *, source_commit: str) -> str:
    stale = (
        f"stale for {artifact.source_commit[:12]} (scan {source_commit[:12]})"
        if artifact.freshness.value == "stale"
        else "current commit"
    )
    if artifact.warnings_complete:
        completeness = "warnings complete"
    elif artifact.warnings_dropped:
        completeness = (
            f"warnings incomplete; {artifact.warnings_dropped} occurrences omitted"
        )
    else:
        completeness = "warnings incomplete; capture completeness unproven"
    return (
        f"  {_artifact_text(artifact.path.as_posix())}: "
        f"{_artifact_text(artifact.provider)} "
        f"{_artifact_text(artifact.provider_version)}; "
        f"Python {_artifact_text(artifact.environment.python_version)}; "
        f"{_plural(artifact.tests_collected, 'test')} collected; "
        f"{_plural(artifact.warning_count, 'warning')} captured; "
        f"pytest exit code {artifact.exit_code}; {completeness}; {stale}"
    )


def _finding_lines(
    finding: Finding,
    *,
    observations: tuple[ObservedWarning, ...] = (),
    source_commit: str | None = None,
) -> list[str]:
    start = finding.location.region.start
    path = finding.location.path.as_posix()
    timeline = "; ".join(
        f"{event.kind.value} in {event.python} ({event.certainty.value})"
        for event in finding.events
    )
    states = "; ".join(
        (
            f"{state.state.value} on {state.from_python}"
            if state.from_python == state.through_python
            else (
                f"{state.state.value} on {state.from_python} through "
                f"{state.through_python}"
            )
        )
        for state in finding.states
    )
    annotations: list[str] = []
    if finding.baseline_status.value == "existing":
        annotations.append("baseline existing")
    if finding.suppression is not None:
        annotations.append(f"suppressed {finding.suppression.kind.value}")
    annotation = f"; {'; '.join(annotations)}" if annotations else ""
    lines = [
        (
            f"  {finding.rule_id}  {path}:{start.line}:{start.column}  "
            f"{finding.subject} ({finding.impact.value}; "
            f"{finding.match_confidence.value} confidence{annotation})"
        ),
        f"    {finding.title}",
        (
            "    Inferred evidence: "
            if source_commit is not None
            else "    Match evidence: "
        )
        + _evidence_text(finding.match_evidence),
        f"    Reachable targets: {', '.join(map(str, finding.reachable_versions))}",
        (
            "    Usage contexts: "
            f"{', '.join(context.value for context in finding.usage_contexts)}"
        ),
        f"    States: {states}",
        f"    Timeline: {timeline}",
        f"    Guidance: {finding.remediation.summary}",
    ]
    if finding.removal_unscheduled:
        lines.insert(
            -1,
            "    Removal schedule: unscheduled (no authoritative removal event)",
        )
    if finding.remediation.documentation_url is not None:
        lines.append(
            f"    Remediation documentation: {finding.remediation.documentation_url}"
        )
    if finding.remediation.automation is not None:
        automation = finding.remediation.automation
        lines.append(
            f"    Automation metadata: {automation.tool.value} {automation.rule} "
            "(not invoked)"
        )
    if finding.suppression is not None:
        if finding.suppression.reason is not None:
            lines.append(f"    Suppression reason: {finding.suppression.reason}")
        if finding.suppression.pattern is not None:
            lines.append(f"    Suppression pattern: {finding.suppression.pattern}")
    if source_commit is not None and observations:
        lines.append("    Observed evidence:")
        lines.extend(
            "      "
            + _observed_warning_line(
                observation,
                source_commit=source_commit,
            )
            for observation in observations
        )
    lines.extend(
        f"    Source: {source.title} — {source.url}" for source in finding.sources
    )
    return lines


def _diagnostic_lines(diagnostic: Diagnostic) -> list[str]:
    if diagnostic.location is None:
        where = ""
    else:
        start = diagnostic.location.region.start
        where = f" {diagnostic.location.path.as_posix()}:{start.line}:{start.column}"
    return [f"  {diagnostic.code}{where}: {diagnostic.message}"]


def _inference_lines(inference: AnalysisInference) -> list[str]:
    start = inference.location.region.start
    path = inference.location.path.as_posix()
    return [
        f"  {inference.code} {path}:{start.line}:{start.column}: {inference.message}",
        f"    Evidence: {_evidence_text(inference.evidence)}",
    ]


def _plural(count: int, noun: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {noun}{suffix}"


def _timeline_group_summary(findings: tuple[Finding, ...]) -> str:
    impacts = {finding.impact for finding in findings}
    if len(impacts) != 1:
        return _plural(len(findings), "compatibility finding")
    impact = next(iter(impacts))
    nouns = {
        "breaking": "upgrade blocker",
        "deprecated": "deprecation debt item",
        "informational": "informational finding",
        "risk": "compatibility risk",
    }
    return _plural(len(findings), nouns[impact.value])


def _timeline_lines(report: ScanReport) -> list[str]:
    findings = report.visible_findings
    observations_by_fingerprint = report.observations_by_fingerprint
    lines: list[str] = []
    for group_index, (version, grouped) in enumerate(
        groupby(findings, key=lambda finding: finding.action_version)
    ):
        group = tuple(grouped)
        if group_index:
            lines.append("")
        lines.append(f"Python {version} — {_timeline_group_summary(group)}")
        for finding_index, finding in enumerate(group):
            if finding_index:
                lines.append("")
            lines.extend(
                _finding_lines(
                    finding,
                    observations=observations_by_fingerprint.get(
                        finding.fingerprint,
                        (),
                    ),
                    source_commit=report.source_commit,
                )
            )
    return lines


def _observed_evidence_lines(report: ScanReport) -> list[str]:
    source_commit = report.source_commit
    if source_commit is None:
        return []
    lines = ["", "Observed evidence artifacts:"]
    lines.extend(
        _artifact_line(artifact, source_commit=source_commit)
        for artifact in report.evidence_artifacts
    )
    if report.unmatched_observations:
        lines.extend(["", "Unmatched observed warnings:"])
        lines.extend(
            "  "
            + _observed_warning_line(
                observation,
                source_commit=source_commit,
            )
            for observation in report.unmatched_observations
        )
    return lines


def _observed_evidence_summary(report: ScanReport) -> str:
    if not report.has_evidence:
        return ""
    unmatched_count = len(report.unmatched_observations)
    linked_count = len(report.observed_warnings) - unmatched_count
    stale_count = sum(
        observation.freshness.value == "stale"
        for observation in report.observed_warnings
    )
    return (
        f"; {_plural(len(report.observed_warnings), 'observed warning')} "
        f"({linked_count} linked, {unmatched_count} unmatched, {stale_count} stale)"
    )


def render_text(report: ScanReport) -> str:
    """Render a stable, colour-free human report."""
    lines = [
        f"PyAhead {report.tool_version}",
        (
            f"Policy: Python {report.policy.baseline_python} through "
            f"{report.policy.horizon_python}"
        ),
        (f"Registry: {report.registry_release} ({report.registry_revision[:12]})"),
    ]
    provenance = report.policy_provenance
    if (
        provenance.baseline_python != "command-line"
        or provenance.horizon_python != "command-line"
    ):
        lines.append(
            "Policy provenance: "
            f"baseline={provenance.baseline_python}; "
            f"horizon={provenance.horizon_python}"
        )
        if provenance.requires_python is not None:
            lines.append(
                "Requires-Python declaration evaluated at minor granularity: "
                f"{provenance.requires_python}"
            )
    lines.append("")

    visible_findings = report.visible_findings
    if visible_findings:
        lines.extend(_timeline_lines(report))
    else:
        lines.extend(
            [
                (
                    "No known static compatibility findings for this registry "
                    "and policy."
                    if report.has_evidence
                    else (
                        "No known compatibility findings for this registry and policy."
                    )
                ),
                "This is not proof of compatibility.",
            ]
        )

    if report.diagnostics:
        heading = (
            "Incomplete analysis:"
            if all(item.incomplete for item in report.diagnostics)
            else "Diagnostics:"
        )
        lines.extend(["", heading])
        for diagnostic in report.diagnostics:
            lines.extend(_diagnostic_lines(diagnostic))

    if report.inferences:
        lines.extend(["", "Analysis inferences:"])
        for inference in report.inferences:
            lines.extend(_inference_lines(inference))

    lines.extend(_observed_evidence_lines(report))

    active_findings = tuple(
        finding for finding in report.findings if finding.suppression is None
    )
    impact_counts = Counter(finding.impact.value for finding in active_findings)
    impact_summary = ", ".join(
        f"{impact_counts[impact]} {impact}"
        for impact in ("breaking", "risk", "deprecated", "informational")
        if impact_counts[impact]
    )
    if not impact_summary:
        impact_summary = "none"
    suppressed_count = len(report.findings) - len(active_findings)
    suppression_summary = (
        f"; {_plural(suppressed_count, 'finding')} suppressed"
        if suppressed_count
        else ""
    )
    evidence_summary = _observed_evidence_summary(report)
    lines.extend(
        [
            "",
            (
                f"Result: {_plural(len(active_findings), 'finding')} "
                f"({impact_summary}); "
                f"{_plural(report.counts.files_analyzed, 'file')} analyzed; "
                f"{_plural(report.counts.files_incomplete, 'file')} incomplete"
                f"{suppression_summary}{evidence_summary}."
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def render_quiet_text(report: ScanReport) -> str:
    """Render only the deterministic final result line."""
    return render_text(report).splitlines()[-1] + "\n"
