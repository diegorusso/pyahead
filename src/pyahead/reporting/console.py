"""Deterministic plain-text rendering for static scan reports."""

from collections import Counter
from itertools import groupby

from pyahead.model import (
    AnalysisInference,
    Diagnostic,
    EvidenceValue,
    Finding,
    ScanReport,
)


def _evidence_text(evidence: tuple[tuple[str, EvidenceValue], ...]) -> str:
    def render(value: EvidenceValue) -> str:
        return f"[{', '.join(value)}]" if isinstance(value, tuple) else value

    return "; ".join(f"{key}={render(value)}" for key, value in evidence)


def _finding_lines(finding: Finding) -> list[str]:
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
    lines = [
        (
            f"  {finding.rule_id}  {path}:{start.line}:{start.column}  "
            f"{finding.subject} ({finding.impact.value}; "
            f"{finding.match_confidence.value} confidence)"
        ),
        f"    {finding.title}",
        f"    Match evidence: {_evidence_text(finding.match_evidence)}",
        f"    Reachable targets: {', '.join(map(str, finding.reachable_versions))}",
        (
            "    Usage contexts: "
            f"{', '.join(context.value for context in finding.usage_contexts)}"
        ),
        f"    States: {states}",
        f"    Timeline: {timeline}",
        f"    Guidance: {finding.remediation.summary}",
    ]
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


def _timeline_lines(findings: tuple[Finding, ...]) -> list[str]:
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
            lines.extend(_finding_lines(finding))
    return lines


def render_text(report: ScanReport) -> str:
    """Render a stable, colour-free human report."""
    lines = [
        f"PyAhead {report.tool_version}",
        (
            f"Policy: Python {report.policy.baseline_python} through "
            f"{report.policy.horizon_python}"
        ),
        (f"Registry: {report.registry_release} ({report.registry_revision[:12]})"),
        "",
    ]

    if report.findings:
        lines.extend(_timeline_lines(report.findings))
    else:
        lines.extend(
            [
                "No known compatibility findings for this registry and policy.",
                "This is not proof of compatibility.",
            ]
        )

    if report.diagnostics:
        lines.extend(["", "Incomplete analysis:"])
        for diagnostic in report.diagnostics:
            lines.extend(_diagnostic_lines(diagnostic))

    if report.inferences:
        lines.extend(["", "Analysis inferences:"])
        for inference in report.inferences:
            lines.extend(_inference_lines(inference))

    impact_counts = Counter(finding.impact.value for finding in report.findings)
    impact_summary = ", ".join(
        f"{impact_counts[impact]} {impact}"
        for impact in ("breaking", "risk", "deprecated", "informational")
        if impact_counts[impact]
    )
    if not impact_summary:
        impact_summary = "none"
    lines.extend(
        [
            "",
            (
                f"Result: {_plural(len(report.findings), 'finding')} "
                f"({impact_summary}); "
                f"{_plural(report.counts.files_analyzed, 'file')} analyzed; "
                f"{_plural(report.counts.files_incomplete, 'file')} incomplete."
            ),
        ]
    )
    return "\n".join(lines) + "\n"
