"""Real pytest-plugin execution tests for M7 warning collection."""

# ruff: noqa: SLF001 -- bounded-state assertions intentionally exercise internals.

import json
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import pyahead.pytest_plugin as plugin_module
from pyahead.evidence import parse_evidence_document, render_evidence_document

pytest_plugins = ("pytester",)

CURRENT_COMMIT = "a" * 40


def test_explicit_pytest_plugin_collects_only_deprecation_warnings(
    pytester: pytest.Pytester,
) -> None:
    """User pytest execution writes normalized evidence, including on failure."""
    pytester.makepyfile(
        test_warnings="""
        import warnings

        def test_warning_collection():
            warnings.warn("deprecated API", DeprecationWarning, stacklevel=1)
            warnings.warn("pending API", PendingDeprecationWarning, stacklevel=1)
            warnings.warn("ordinary warning", UserWarning, stacklevel=1)
            assert False
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "default::DeprecationWarning",
        "-W",
        "default::PendingDeprecationWarning",
    )

    result.assert_outcomes(failed=1)
    document = cast(
        "dict[str, object]",
        json.loads(artifact.read_text(encoding="utf-8")),
    )
    run = cast("dict[str, object]", document["run"])
    warnings = cast("list[dict[str, object]]", document["warnings"])

    assert document["schema_version"] == 1
    assert document["source"] == {"commit": CURRENT_COMMIT}
    assert run["framework"] == "pytest"
    assert run["tests_collected"] == 1
    assert run["exit_code"] == 1
    assert run["warnings_complete"] is True
    assert run["warnings_dropped"] == 0
    assert [warning["kind"] for warning in warnings] == [
        "deprecation-warning",
        "pending-deprecation-warning",
    ]
    assert all(
        cast("dict[str, object]", warning["location"])["path"]
        == Path("test_warnings.py").as_posix()
        for warning in warnings
    )
    assert "ordinary warning" not in artifact.read_text(encoding="utf-8")


def test_pytest_plugin_finalizes_after_session_warning_and_status_hooks(
    pytester: pytest.Pytester,
) -> None:
    """Session-finish warnings and final process status reach the artifact."""
    pytester.makepyfile("def test_ok():\n    assert True\n")
    pytester.makeconftest(
        """
        import warnings

        import pytest

        @pytest.hookimpl(tryfirst=True)
        def pytest_sessionfinish(session):
            warnings.warn(
                "session-final deprecation",
                DeprecationWarning,
                stacklevel=1,
            )
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "default::DeprecationWarning",
    )

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    document = cast(
        "dict[str, object]",
        json.loads(artifact.read_text(encoding="utf-8")),
    )
    run = cast("dict[str, object]", document["run"])
    captured = cast("list[dict[str, object]]", document["warnings"])

    assert run["exit_code"] == int(result.ret)
    assert any(
        warning["message"] == "session-final deprecation"
        and cast("dict[str, object]", warning["location"])["path"] == "conftest.py"
        for warning in captured
    )


def test_pytest_plugin_requires_output_when_commit_is_explicit(
    pytester: pytest.Pytester,
) -> None:
    """A commit option alone is a configuration error rather than a no-op."""
    pytester.makepyfile("def test_ok():\n    assert True\n")

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.ret != 0
    result.stderr.fnmatch_lines(
        ["*--pyahead-source-commit requires --pyahead-evidence*"]
    )


@pytest.mark.parametrize(
    ("warning_record_limit", "warning_text_byte_limit", "expected_retained"),
    [
        (2, plugin_module._MAX_MESSAGE_LENGTH * 10, 2),
        (4, plugin_module._MAX_MESSAGE_LENGTH + 1_024, 1),
    ],
)
def test_warning_collection_is_bounded_before_rendering(
    tmp_path: Path,
    warning_record_limit: int,
    warning_text_byte_limit: int,
    expected_retained: int,
) -> None:
    """Many maximum-size unique warnings are discarded without being retained."""
    warning_count = 100
    collector = plugin_module._WarningCollector(
        tmp_path,
        tmp_path / "warnings.json",
        CURRENT_COMMIT,
        warning_record_limit=warning_record_limit,
        warning_text_byte_limit=warning_text_byte_limit,
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
    document = collector._document(session, 0)
    rendered = render_evidence_document(document)
    parsed = parse_evidence_document(cast("dict[str, object]", json.loads(rendered)))
    retained_occurrences = sum(warning.occurrences for warning in parsed.warnings)

    assert len(collector._warnings) == expected_retained
    assert collector._retained_warning_text_bytes <= collector._warning_text_byte_limit
    assert retained_occurrences + parsed.warnings_dropped == warning_count + 1
    assert parsed.warnings_complete is False
    assert parsed.warnings_dropped == warning_count + 1 - expected_retained
