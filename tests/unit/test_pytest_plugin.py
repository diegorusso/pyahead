"""Focused unit tests for bounded pytest warning collection."""

# ruff: noqa: SLF001 -- bounds are private implementation invariants.

import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import pyahead.pytest_plugin as plugin_module
from pyahead.evidence import parse_evidence_document

CURRENT_COMMIT = "a" * 40


@pytest.mark.parametrize(
    ("record_limit", "text_byte_limit", "expected_retained"),
    [
        (2, plugin_module._MAX_MESSAGE_LENGTH * 10, 2),
        (4, plugin_module._MAX_MESSAGE_LENGTH + 1_024, 1),
    ],
)
def test_warning_collection_is_bounded_before_rendering(
    tmp_path: Path,
    record_limit: int,
    text_byte_limit: int,
    expected_retained: int,
) -> None:
    """Maximum-size unique warnings are discarded without being retained."""
    warning_count = 100
    collector = plugin_module._WarningCollector(
        tmp_path,
        tmp_path / "warnings.json",
        CURRENT_COMMIT,
        limits=plugin_module._WarningLimits(record_limit, text_byte_limit),
    )
    for index in range(warning_count):
        message = f"{index:04d}" + ("x" * plugin_module._MAX_MESSAGE_LENGTH)
        collector.pytest_warning_recorded(
            warnings.WarningMessage(
                DeprecationWarning(message),
                DeprecationWarning,
                str(tmp_path / "test_mass.py"),
                index + 1,
            ),
            "runtest",
            f"test_mass.py::test_{index:04d}",
            None,
        )

    # A repeated warning that was already discarded remains an exact dropped
    # occurrence without requiring the collector to remember its full text.
    collector.pytest_warning_recorded(
        warnings.WarningMessage(
            DeprecationWarning(
                f"{warning_count - 1:04d}" + ("x" * plugin_module._MAX_MESSAGE_LENGTH)
            ),
            DeprecationWarning,
            str(tmp_path / "test_mass.py"),
            warning_count,
        ),
        "runtest",
        f"test_mass.py::test_{warning_count - 1:04d}",
        None,
    )

    session = cast("pytest.Session", SimpleNamespace(testscollected=warning_count))
    parsed = parse_evidence_document(collector._document(session, 0))
    retained = sum(warning.occurrences for warning in parsed.warnings)
    assert len(collector._warnings) == expected_retained
    assert collector._retained_warning_text_bytes <= text_byte_limit
    assert retained + parsed.warnings_dropped == warning_count + 1
    assert parsed.warnings_complete is False
    assert parsed.warnings_dropped == warning_count + 1 - expected_retained


def test_zero_drops_do_not_override_unproven_warning_capture(tmp_path: Path) -> None:
    """Completeness includes capture proof independently of retention."""
    collector = plugin_module._WarningCollector(
        tmp_path,
        tmp_path / "warnings.json",
        CURRENT_COMMIT,
        capture_proven=False,
    )
    session = cast("pytest.Session", SimpleNamespace(testscollected=0))

    parsed = parse_evidence_document(collector._document(session, 0))

    assert parsed.warnings_dropped == 0
    assert parsed.warnings_complete is False
