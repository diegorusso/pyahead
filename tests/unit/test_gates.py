"""Tests for M4 gate thresholds and precedence."""

from dataclasses import replace
from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import (
    BaselineStatus,
    EffectiveConfiguration,
    ExitCode,
    FailOn,
    Impact,
    ScanCounts,
    ScanReport,
    Suppression,
    SuppressionKind,
)


def _report(tmp_path: Path) -> ScanReport:
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    return scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )


@pytest.mark.parametrize(
    ("impact", "fail_on", "expected"),
    [
        (
            impact,
            fail_on,
            int(fail_on is not FailOn.NEVER and impact_rank >= threshold),
        )
        for impact, impact_rank in (
            (Impact.INFORMATIONAL, 0),
            (Impact.DEPRECATED, 1),
            (Impact.RISK, 2),
            (Impact.BREAKING, 3),
        )
        for fail_on, threshold in (
            (FailOn.NEVER, 4),
            (FailOn.BREAKING, 3),
            (FailOn.RISK, 2),
            (FailOn.DEPRECATED, 1),
            (FailOn.ANY, 0),
        )
    ],
)
def test_gate_impact_ordering(
    tmp_path: Path,
    impact: Impact,
    fail_on: FailOn,
    expected: int,
) -> None:
    """Every threshold implements informational < deprecated < risk < breaking."""
    report = _report(tmp_path)
    report = replace(
        report,
        findings=(replace(report.findings[0], impact=impact),),
        configuration=replace(report.configuration, fail_on=fail_on),
    )

    assert report.gate_failed is bool(expected)


def test_fail_new_only_and_suppression_filter_gate_candidates(
    tmp_path: Path,
) -> None:
    """Existing and explicitly suppressed debt stays visible but cannot fail."""
    report = _report(tmp_path)
    existing = replace(
        report.findings[0],
        baseline_status=BaselineStatus.EXISTING,
    )
    report = replace(
        report,
        findings=(existing,),
        configuration=replace(report.configuration, fail_new_only=True),
    )
    assert report.gate_failed is False

    suppressed = replace(
        existing,
        baseline_status=BaselineStatus.NEW,
        suppression=Suppression(kind=SuppressionKind.INLINE),
    )
    report = replace(report, findings=(suppressed,))
    assert report.gate_failed is False


def test_incomplete_precedence_can_be_explicitly_allowed(tmp_path: Path) -> None:
    """Exit 3 outranks findings unless the operator permits incomplete output."""
    report = _report(tmp_path)
    report = replace(
        report,
        counts=ScanCounts(
            files_discovered=2,
            files_analyzed=1,
            files_incomplete=1,
        ),
    )
    assert report.exit_code is ExitCode.INCOMPLETE

    report = replace(
        report,
        configuration=replace(report.configuration, allow_incomplete=True),
    )
    assert report.exit_code is ExitCode.FINDINGS


def test_default_effective_configuration_retains_m1_gate() -> None:
    """The model default remains a breaking gate for API compatibility."""
    configuration = EffectiveConfiguration()

    assert configuration.fail_on is FailOn.BREAKING
