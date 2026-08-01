"""Deterministic plain-text rendering for M1 scan reports."""

from collections import Counter

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
    lines = [
        f"Python {finding.action_version} — {finding.impact.value}",
        (
            f"  {finding.rule_id}  {path}:{start.line}:{start.column}  "
            f"{finding.subject} ({finding.match_confidence.value} confidence)"
        ),
        f"    {finding.title}",
        f"    Match evidence: {_evidence_text(finding.match_evidence)}",
        f"    Timeline: {timeline}",
        f"    Guidance: {finding.remediation.summary}",
    ]
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
        for index, finding in enumerate(report.findings):
            if index:
                lines.append("")
            lines.extend(_finding_lines(finding))
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
