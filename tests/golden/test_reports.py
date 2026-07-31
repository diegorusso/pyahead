"""Golden tests for deterministic M1 text and JSON reports."""

from collections.abc import Callable
from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import ScanReport
from pyahead.reporting import render_json, render_text

GOLDEN_ROOT = Path(__file__).parent
PROJECT_ROOT = GOLDEN_ROOT / "project"


@pytest.mark.parametrize(
    ("renderer", "expected_name"),
    [
        (render_text, "report.txt"),
        (render_json, "report.json"),
    ],
)
def test_report_matches_golden_output(
    renderer: Callable[[ScanReport], str],
    expected_name: str,
) -> None:
    """One seed rule flows through every public M1 report format."""
    report = scan(
        ScanRequest(
            root=PROJECT_ROOT,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )

    expected = (GOLDEN_ROOT / expected_name).read_text(encoding="utf-8")
    assert renderer(report) == expected
