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


# --- PyPI top-1000 triage (docs/evidence/pypi-top-1000.md) --------------------


def test_major_version_index_guard_hides_a_python2_only_import(tmp_path: Path) -> None:
    """distlib: ``if sys.version_info[0] < 3: import imp`` is unreachable on 3.x."""
    _write_project(
        tmp_path,
        {
            "wheel.py": (
                "import sys\n"
                "if sys.version_info[0] < 3:\n"
                "    import imp\n"
                "else:\n"
                "    imp = None\n"
            )
        },
    )

    report = _scan(tmp_path, minimum_confidence="medium")

    assert _rule_findings(report, "CPY0024") == []


@pytest.mark.parametrize(
    "condition",
    [
        "sys.version_info[0] >= 3",
        "3 <= sys.version_info[0]",
        "sys.version_info[0] == 3",
    ],
)
def test_major_version_index_guard_keeps_the_python3_branch(
    tmp_path: Path, condition: str
) -> None:
    """The major-only index narrows nothing when the branch is live on 3.x."""
    _write_project(
        tmp_path, {"wheel.py": f"import sys\nif {condition}:\n    import imp\n"}
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0024")[0]

    assert finding.impact.value == "breaking"
    assert tuple(str(version) for version in finding.reachable_versions) == (
        "3.11",
        "3.12",
        "3.13",
        "3.14",
        "3.15",
        "3.16",
    )


def test_major_version_index_against_a_non_integer_stays_unknown(
    tmp_path: Path,
) -> None:
    """Only a bare integer literal decides the major-only comparison."""
    _write_project(
        tmp_path,
        {"wheel.py": "import sys\nif sys.version_info[0] < (3,):\n    import imp\n"},
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0024")[0]

    assert finding.impact.value == "breaking"


def test_local_variable_annotation_is_never_evaluated(tmp_path: Path) -> None:
    """anyio: a function-local ``x: asyncio.AbstractChildWatcher | None`` never runs.

    PEP 526 leaves local-variable annotations unevaluated and unstored, so
    the reference cannot raise at import or call time on any interpreter.
    The sweep's binding oracle does not observe evaluation: it refuted the
    row at 3.14 only because the walk from the real ``asyncio`` module
    failed on ``AbstractChildWatcher`` itself (oracle defect 3), and the
    fixed oracle confirms the binding, so this classification rests on
    PEP 526 alone.
    """
    _write_project(
        tmp_path,
        {
            "backend.py": (
                "import asyncio\n"
                "def shutdown():\n"
                "    watcher: asyncio.AbstractChildWatcher | None = None\n"
                "    return watcher\n"
            )
        },
    )

    report = _scan(tmp_path, minimum_confidence="medium")

    assert _rule_findings(report, "CPY0043") == []


def test_future_annotations_do_not_defer_evaluated_annotations(
    tmp_path: Path,
) -> None:
    """PEP 563 only stringifies annotations; introspection still evaluates them.

    ``typing.get_type_hints`` and the libraries built on it (dataclasses,
    pydantic, attrs) evaluate stringified parameter, return, class-body and
    module-level annotations at runtime, so a removed subject named there
    still breaks. Only the local-variable annotation, which is never
    evaluated or stored, is deferred.
    """
    _write_project(
        tmp_path,
        {
            "backend.py": (
                "from __future__ import annotations\n"
                "import asyncio\n"
                "def shutdown(\n"
                "    watcher: asyncio.AbstractChildWatcher,\n"
                ") -> asyncio.AbstractChildWatcher: ...\n"
                "class Pool:\n"
                "    watcher: asyncio.AbstractChildWatcher\n"
                "default: asyncio.AbstractChildWatcher | None = None\n"
                "def local():\n"
                "    watcher: asyncio.AbstractChildWatcher | None = None\n"
                "    return watcher\n"
            )
        },
    )

    findings = _rule_findings(_scan(tmp_path, minimum_confidence="medium"), "CPY0043")

    assert sorted(finding.location.region.start.line for finding in findings) == [
        4,
        5,
        7,
        8,
    ]
    for finding in findings:
        assert finding.impact.value == "breaking"
        assert dict(finding.match_evidence)["reference_context"] == "annotation"
        assert "annotation_evaluation" not in dict(finding.match_evidence)


def test_deferred_annotation_keeps_a_typing_context_finding(tmp_path: Path) -> None:
    """A deferred annotation is still a typing use, with the deferral as evidence.

    Only the runtime context is dropped: a rule that applies in typing
    context (CPY0091 ``typing.ByteString``) still reports the reference,
    narrowed to typing-only and tagged so triage can see why.
    """
    _write_project(
        tmp_path,
        {
            "shapes.py": (
                "import typing\n"
                "def size(data):\n"
                "    buffer: typing.ByteString = data\n"
                "    return len(buffer)\n"
            )
        },
    )

    finding = _rule_findings(_scan(tmp_path), "CPY0091")[0]

    assert tuple(context.value for context in finding.usage_contexts) == ("typing",)
    assert dict(finding.match_evidence)["annotation_evaluation"] == "deferred"


@pytest.mark.parametrize(
    "source",
    [
        "import asyncio\ndef shutdown(watcher: asyncio.AbstractChildWatcher): ...\n",
        "import asyncio\ndef watcher() -> asyncio.AbstractChildWatcher: ...\n",
        "import asyncio\nclass Pool:\n    watcher: asyncio.AbstractChildWatcher\n",
        "import asyncio\nwatcher: asyncio.AbstractChildWatcher | None = None\n",
    ],
    ids=("parameter", "return", "class-body", "module-level"),
)
def test_evaluated_annotations_still_report(tmp_path: Path, source: str) -> None:
    """Parameter, return, class-body and module-level annotations are runtime uses."""
    _write_project(tmp_path, {"backend.py": source})

    finding = _rule_findings(_scan(tmp_path), "CPY0043")[0]

    assert finding.impact.value == "breaking"
    assert dict(finding.match_evidence)["reference_context"] == "annotation"
    assert "annotation_evaluation" not in dict(finding.match_evidence)
