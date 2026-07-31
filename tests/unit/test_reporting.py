"""Tests for console-only report branches."""

from dataclasses import replace
from pathlib import Path

from pyahead.analysis import ScanRequest, scan
from pyahead.model import Diagnostic, DiagnosticCategory
from pyahead.reporting import render_text


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
    assert "Incomplete analysis:\n  PYA1001: analysis scope was incomplete" in rendered
    assert "2 findings" in rendered
