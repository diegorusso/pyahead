"""End-to-end acceptance tests for M3 timelines and reachability."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import ExitCode, FindingState, Impact, ScanReport, UsageContext
from pyahead.reporting import render_json, render_text

_TWO_FINDINGS = 2


def _scan(
    root: Path,
    source: str,
    *,
    filename: str = "source.py",
    baseline: str = "3.11",
    horizon: str = "3.15",
) -> ScanReport:
    (root / filename).write_text(source, encoding="utf-8")
    return scan(
        ScanRequest(
            root=root,
            baseline_python=baseline,
            horizon_python=horizon,
        )
    )


def _versions(report: ScanReport, index: int = 0) -> tuple[str, ...]:
    return tuple(str(version) for version in report.findings[index].reachable_versions)


def test_pep_594_import_guarded_before_removal_is_debt_not_a_blocker(
    tmp_path: Path,
) -> None:
    """A ``<3.13`` compatibility branch cannot block 3.13 and later."""
    report = _scan(
        tmp_path,
        (
            "from sys import version_info as py_version\n"
            "if py_version < (3, 13):\n"
            "    import cgi\n"
        ),
    )

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert _versions(report) == ("3.11", "3.12")
    assert finding.usage_contexts == (UsageContext.RUNTIME,)
    assert finding.impact is Impact.DEPRECATED
    assert str(finding.action_version) == "3.11"
    assert [state.state for state in finding.states] == [FindingState.DEPRECATED]
    assert str(finding.states[0].through_python) == "3.12"
    assert report.exit_code is ExitCode.SUCCESS


@pytest.mark.parametrize(
    "source",
    [
        "import sys\nif sys.version_info < (3, 13):\n    import cgi\n",
        ("import sys as runtime\nif runtime.version_info < (3, 13):\n    import cgi\n"),
        (
            "from sys import version_info as py_version\n"
            "if py_version < (3, 13):\n"
            "    import cgi\n"
        ),
    ],
    ids=("direct", "aliased", "from-import"),
)
@pytest.mark.parametrize("project_sys", ["module", "package"])
def test_project_sys_candidate_cannot_shadow_builtin_version_guard(
    tmp_path: Path,
    source: str,
    project_sys: str,
) -> None:
    """Built-in ``sys`` keeps guards precise despite project lookalikes."""
    if project_sys == "module":
        (tmp_path / "sys.py").write_text("", encoding="utf-8")
    else:
        package = tmp_path / "sys"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")

    report = _scan(tmp_path, source)

    assert len(report.findings) == 1
    assert _versions(report) == ("3.11", "3.12")
    assert report.findings[0].impact is Impact.DEPRECATED
    assert report.exit_code is ExitCode.SUCCESS


def test_lexical_sys_shadowing_still_makes_version_guard_unknown(
    tmp_path: Path,
) -> None:
    """Built-in precedence does not override a local rebinding."""
    report = _scan(
        tmp_path,
        (
            "import sys\n"
            "sys = runtime_sys\n"
            "if sys.version_info < (3, 13):\n"
            "    import cgi\n"
        ),
        horizon="3.13",
    )

    assert _versions(report) == ("3.11", "3.12", "3.13")
    assert report.findings[0].impact is Impact.BREAKING
    assert report.exit_code is ExitCode.FINDINGS


def test_unknown_condition_enters_both_lexical_branches(tmp_path: Path) -> None:
    """An unknown feature predicate retains findings on both sides."""
    report = _scan(
        tmp_path,
        ("if feature_enabled:\n    import cgi\nelse:\n    import cgi\n"),
        horizon="3.13",
    )

    assert len(report.findings) == _TWO_FINDINGS
    assert {_versions(report, index) for index in range(len(report.findings))} == {
        ("3.11", "3.12", "3.13")
    }


def test_nested_and_elif_guards_receive_sequential_target_sets(
    tmp_path: Path,
) -> None:
    """Each elif sees only targets not definitely handled before it."""
    report = _scan(
        tmp_path,
        (
            "import sys\n"
            "if sys.version_info < (3, 12):\n"
            "    import cgi\n"
            "elif sys.version_info < (3, 14):\n"
            "    if sys.version_info[:2] != (3, 13):\n"
            "        import cgi\n"
            "    else:\n"
            "        import cgi\n"
            "else:\n"
            "    import cgi\n"
        ),
    )

    by_line = {
        finding.location.region.start.line: tuple(
            str(version) for version in finding.reachable_versions
        )
        for finding in report.findings
    }
    assert by_line == {
        3: ("3.11",),
        6: ("3.12",),
        8: ("3.13",),
        10: ("3.14", "3.15"),
    }


def test_import_derived_minor_slice_reaches_only_equal_target(tmp_path: Path) -> None:
    """Qualified-name metadata and the documented ``[:2]`` form cooperate."""
    report = _scan(
        tmp_path,
        (
            "import sys as runtime\n"
            "if runtime.version_info[:2] == (3, 12):\n"
            "    import cgi\n"
        ),
        horizon="3.14",
    )

    assert _versions(report) == ("3.12",)


def test_unsliced_not_equal_keeps_matching_minor_blocker(tmp_path: Path) -> None:
    """Full version info is longer than a matching two-component tuple."""
    report = _scan(
        tmp_path,
        ("import sys\nif sys.version_info != (3, 13):\n    import cgi\n"),
        baseline="3.13",
        horizon="3.13",
    )

    assert _versions(report) == ("3.13",)
    assert report.findings[0].impact is Impact.BREAKING


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("not (sys.version_info >= (3, 13))", ("3.11", "3.12")),
        (
            "sys.version_info >= (3, 13) and feature_enabled",
            ("3.13", "3.14"),
        ),
        (
            "sys.version_info >= (3, 13) or feature_enabled",
            ("3.11", "3.12", "3.13", "3.14"),
        ),
    ],
)
def test_boolean_guards_propagate_three_valued_results(
    tmp_path: Path,
    condition: str,
    expected: tuple[str, ...],
) -> None:
    """Not, and, and or retain precisely the targets allowed by their tables."""
    report = _scan(
        tmp_path,
        f"import sys\nif {condition}:\n    import cgi\n",
        horizon="3.14",
    )

    assert _versions(report) == expected


@pytest.mark.parametrize(
    "source",
    [
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import cgi\n",
        "import typing as t\nif t.TYPE_CHECKING:\n    import cgi\n",
    ],
)
def test_runtime_rule_is_not_emitted_inside_type_checking(
    tmp_path: Path,
    source: str,
) -> None:
    """Import-derived direct TYPE_CHECKING branches are typing-only."""
    report = _scan(tmp_path, source)

    assert report.findings == ()
    assert report.exit_code is ExitCode.SUCCESS


def test_not_type_checking_true_branch_is_runtime_only(tmp_path: Path) -> None:
    """Direct negation reverses the typing/runtime context split."""
    report = _scan(
        tmp_path,
        ("from typing import TYPE_CHECKING\nif not TYPE_CHECKING:\n    import cgi\n"),
        horizon="3.13",
    )

    assert len(report.findings) == 1
    assert report.findings[0].usage_contexts == (UsageContext.RUNTIME,)


def test_runtime_rule_is_not_emitted_from_stub_file(tmp_path: Path) -> None:
    """A .pyi module begins in typing-only context."""
    report = _scan(tmp_path, "import cgi\n", filename="source.pyi")

    assert report.findings == ()
    assert report.exit_code is ExitCode.SUCCESS


def test_uncertain_type_checking_name_does_not_suppress_runtime_finding(
    tmp_path: Path,
) -> None:
    """A local lookalike remains unknown and therefore retains runtime use."""
    report = _scan(
        tmp_path,
        "TYPE_CHECKING = feature_enabled\nif TYPE_CHECKING:\n    import cgi\n",
        horizon="3.13",
    )

    assert len(report.findings) == 1
    assert report.findings[0].usage_contexts == (UsageContext.RUNTIME,)


def test_patch_guard_is_diagnosed_and_both_branches_remain_reachable(
    tmp_path: Path,
) -> None:
    """A patch tuple is unknown, visible, and never rounded to 3.13."""
    report = _scan(
        tmp_path,
        (
            "import sys\n"
            "if sys.version_info >= (3, 13, 2):\n"
            "    import cgi\n"
            "else:\n"
            "    import cgi\n"
        ),
        horizon="3.14",
    )

    assert len(report.findings) == _TWO_FINDINGS
    assert all(
        tuple(str(version) for version in finding.reachable_versions)
        == ("3.11", "3.12", "3.13", "3.14")
        for finding in report.findings
    )
    assert [inference.code for inference in report.inferences] == ["PYA2002"]
    assert "treated as unknown" in report.inferences[0].message


@pytest.mark.parametrize(
    "condition",
    [
        "sys.version_info[:3] >= (3, 13, 2)",
        "(3, 13, 2) <= sys.version_info[:3]",
    ],
)
def test_patch_slice_guard_is_diagnosed_with_either_operand_order(
    tmp_path: Path,
    condition: str,
) -> None:
    """Patch slices remain visible and retain both lexical branches."""
    report = _scan(
        tmp_path,
        (f"import sys\nif {condition}:\n    import cgi\nelse:\n    import cgi\n"),
        horizon="3.14",
    )

    assert len(report.findings) == _TWO_FINDINGS
    assert all(
        tuple(str(version) for version in finding.reachable_versions)
        == ("3.11", "3.12", "3.13", "3.14")
        for finding in report.findings
    )
    assert [inference.code for inference in report.inferences] == ["PYA2002"]
    assert "treated as unknown" in report.inferences[0].message


def test_one_finding_carries_its_entire_timeline_in_text_and_json(
    tmp_path: Path,
) -> None:
    """An unguarded call site is not duplicated for each affected version."""
    report = _scan(tmp_path, "import cgi\n")

    assert len(report.findings) == 1
    assert [state.state for state in report.findings[0].states] == [
        FindingState.DEPRECATED,
        FindingState.BREAKING,
    ]
    text = render_text(report)
    document = cast("dict[str, object]", json.loads(render_json(report)))
    findings = cast("list[dict[str, object]]", document["findings"])
    states = cast("list[dict[str, str]]", findings[0]["states"])

    assert text.count("CPY0001") == 1
    assert "deprecated on 3.11 through 3.12; breaking on 3.13 through 3.15" in text
    assert states == [
        {"from": "3.11", "state": "deprecated", "through": "3.12"},
        {"from": "3.13", "state": "breaking", "through": "3.15"},
    ]


def test_console_groups_findings_by_action_version(tmp_path: Path) -> None:
    """A timeline heading is shared by findings with the same action target."""
    report = _scan(tmp_path, "import cgi\ndef use():\n    import cgi\n", horizon="3.13")

    text = render_text(report)

    assert text.count("Python 3.13 — 2 upgrade blockers") == 1
    assert text.count("CPY0001") == _TWO_FINDINGS
