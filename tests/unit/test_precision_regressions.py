"""Regression contracts from the M6 public-corpus precision review."""

from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import Finding, MatchConfidence, ScanReport

_FAIL2BAN_AMBIGUOUS_IMPORTS = 3


def _scan(root: Path, *, minimum_confidence: str = "high") -> ScanReport:
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.16",
            minimum_confidence=minimum_confidence,
        )
    )


def _write_project(root: Path, files: dict[str, str]) -> None:
    for relative_path, source in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


def _rule_findings(report: ScanReport, *rule_ids: str) -> list[Finding]:
    return [finding for finding in report.findings if finding.rule_id in rule_ids]


def test_appended_compat_modules_do_not_create_post_removal_breaking_findings(
    tmp_path: Path,
) -> None:
    """The reviewed Fail2Ban layout retains debt without a false blocker."""
    _write_project(
        tmp_path,
        {
            "helpers.py": (
                "import sys\n"
                "def extend_compat_path():\n"
                "    sys.path.append('compat')\n"
                "extend_compat_path()\n"
            ),
            "compat/asynchat.py": "import asyncore\n",
            "compat/asyncore.py": "value = True\n",
            "server.py": (
                "import helpers\n"
                "import asynchat\n"
                "if asynchat.asyncore:\n"
                "    asyncore = asynchat.asyncore\n"
                "else:\n"
                "    import asyncore\n"
            ),
        },
    )

    report = _scan(tmp_path)
    findings = _rule_findings(report, "CPY0003", "CPY0004")

    assert [(item.rule_id, item.location.path.as_posix()) for item in findings] == [
        ("CPY0003", "server.py"),
        ("CPY0004", "compat/asynchat.py"),
        ("CPY0004", "server.py"),
    ]
    assert {item.impact.value for item in findings} == {"deprecated"}
    assert {str(item.action_version) for item in findings} == {"3.11"}
    assert {
        tuple(str(version) for version in item.reachable_versions) for item in findings
    } == {("3.11",)}
    assert {dict(item.match_evidence)["resolution"] for item in findings} == {
        "stdlib-before-appended-project-module"
    }
    assert [item.code for item in report.inferences].count("PYA2001") == (
        _FAIL2BAN_AMBIGUOUS_IMPORTS
    )


def test_inserted_compat_module_is_medium_confidence_ambiguity(tmp_path: Path) -> None:
    """Prepending a matching nested module cannot remain an exact origin."""
    _write_project(
        tmp_path,
        {
            "consumer.py": (
                "import sys\nsys.path.insert(0, 'compat')\nimport asynchat\n"
            ),
            "compat/asynchat.py": "value = True\n",
        },
    )

    high_report = _scan(tmp_path)
    medium_report = _scan(tmp_path, minimum_confidence="medium")

    assert _rule_findings(high_report, "CPY0003") == []
    finding = _rule_findings(medium_report, "CPY0003")[0]
    assert finding.match_confidence is MatchConfidence.MEDIUM
    assert dict(finding.match_evidence)["resolution"] == ("dynamic-sys-path-ambiguity")
    assert [item.code for item in high_report.inferences] == ["PYA2001"]


def test_irrelevant_nested_module_preserves_exact_import(tmp_path: Path) -> None:
    """A path mutation alone does not reduce unrelated module confidence."""
    _write_project(
        tmp_path,
        {
            "consumer.py": "import sys\nsys.path.append('compat')\nimport asynchat\n",
            "compat/not_asynchat.py": "value = True\n",
        },
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0003")[0]

    assert finding.impact.value == "breaking"
    assert dict(finding.match_evidence)["resolution"] == ("no-competing-project-module")


def test_shadowed_sys_path_call_preserves_exact_import(tmp_path: Path) -> None:
    """Lexical lookalikes do not invent a repository path mutation."""
    _write_project(
        tmp_path,
        {
            "consumer.py": (
                "import asynchat\ndef mutate(sys):\n    sys.path.insert(0, 'compat')\n"
            ),
            "compat/asynchat.py": "value = True\n",
        },
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0003")[0]

    assert finding.match_confidence is MatchConfidence.HIGH
    assert finding.impact.value == "breaking"
    assert dict(finding.match_evidence)["resolution"] == ("no-competing-project-module")


def test_exact_hasattr_and_guard_removes_only_post_removal_reachability(
    tmp_path: Path,
) -> None:
    """Short-circuiting prevents access after the guarded alias disappears."""
    _write_project(
        tmp_path,
        {
            "source.py": (
                "import ast\n"
                "if hasattr(ast, 'NameConstant') and object() is ast.NameConstant:\n"
                "    pass\n"
            )
        },
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0064")[0]

    assert finding.impact.value == "deprecated"
    assert str(finding.action_version) == "3.12"
    assert tuple(str(version) for version in finding.reachable_versions) == (
        "3.11",
        "3.12",
        "3.13",
    )
    assert dict(finding.match_evidence)["reachability_guard"] == "hasattr-and"


@pytest.mark.parametrize(
    "source",
    [
        (
            "import ast\n"
            "def hasattr(*args): return True\n"
            "if hasattr(ast, 'NameConstant') and ast.NameConstant:\n"
            "    pass\n"
        ),
        ("import ast\nif hasattr(ast, 'Num') and ast.NameConstant:\n    pass\n"),
        (
            "import ast\n"
            "if hasattr(ast, 'NameConstant') or ast.NameConstant:\n"
            "    pass\n"
        ),
    ],
    ids=("shadowed-hasattr", "different-attribute", "or-does-not-guard"),
)
def test_hasattr_lookalikes_do_not_hide_breaking_reachability(
    tmp_path: Path,
    source: str,
) -> None:
    """Only the exact builtin short-circuit grammar narrows a finding."""
    _write_project(tmp_path, {"source.py": source})

    finding = _rule_findings(_scan(tmp_path), "CPY0064")[0]

    assert finding.impact.value == "breaking"
    assert str(finding.action_version) == "3.14"
    assert "reachability_guard" not in dict(finding.match_evidence)
