"""Tests for console-only report branches."""

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

from pyahead.analysis import ScanRequest, scan
from pyahead.model import Diagnostic, DiagnosticCategory
from pyahead.reporting import render_json, render_text


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
