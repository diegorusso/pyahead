"""Tests for rule-specific inline and per-file suppressions."""

import json
from pathlib import Path
from typing import cast

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import PerFileIgnore, SuppressionKind
from pyahead.reporting import render_json

_CALL_RULE_ID = "CPY9001"
_CALL_LINE = 2
_STRESS_FINDING_COUNT = 3_000


def _request(root: Path, **overrides: object) -> ScanRequest:
    values: dict[str, object] = {
        "root": root,
        "baseline_python": "3.11",
        "horizon_python": "3.13",
    }
    values.update(overrides)
    return ScanRequest(**values)  # type: ignore[arg-type]


def _write_call_registry(root: Path, matcher: dict[str, object]) -> Path:
    registry = root / "registry"
    rules = registry / "cpython"
    rules.mkdir(parents=True)
    (registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "retired_ids: []\n"
            "rules:\n"
            f"  - cpython/{_CALL_RULE_ID}.yaml\n"
        ),
        encoding="utf-8",
    )
    (rules / f"{_CALL_RULE_ID}.yaml").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": _CALL_RULE_ID,
                "title": "Synthetic removed call",
                "summary": "A synthetic rule for statement suppression tests.",
                "scope": {
                    "ecosystem": "python",
                    "runtime": "cpython",
                    "contexts": ["runtime"],
                },
                "subject": {"kind": "function", "name": "targetpkg.old_call"},
                "timeline": [
                    {
                        "event": "deprecated",
                        "python": "3.11",
                        "certainty": "released",
                        "source": "test-source",
                    },
                    {
                        "event": "removed",
                        "python": "3.13",
                        "certainty": "released",
                        "source": "test-source",
                    },
                ],
                "impact": {
                    "on_deprecation": "deprecated",
                    "on_removal": "breaking",
                },
                "matchers": [matcher],
                "remediation": {"summary": "Use the supported call."},
                "sources": [
                    {
                        "id": "test-source",
                        "title": "Synthetic source",
                        "url": "https://example.com/suppression-test",
                    }
                ],
                "tags": ["suppression-test"],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return registry


def test_inline_suppression_is_rule_specific_and_hidden_by_default(
    tmp_path: Path,
) -> None:
    """A matching trailing directive suppresses the gate without erasing data."""
    (tmp_path / "legacy.py").write_text(
        "import cgi  # pyahead: ignore[CPY0001] -- tracked in issue 42\n",
        encoding="utf-8",
    )

    report = scan(_request(tmp_path))
    document = cast("dict[str, object]", json.loads(render_json(report)))

    assert report.findings[0].suppression is not None
    assert report.findings[0].suppression.kind is SuppressionKind.INLINE
    assert report.findings[0].suppression.reason == "tracked in issue 42"
    assert report.visible_findings == ()
    assert report.gate_failed is False
    assert document["findings"] == []


def test_show_suppressed_retains_structured_json_metadata(tmp_path: Path) -> None:
    """Suppressed findings are opt-in and visibly marked in machine output."""
    (tmp_path / "legacy.py").write_text(
        "import cgi  # pyahead: ignore[CPY0001]\n",
        encoding="utf-8",
    )
    report = scan(_request(tmp_path, show_suppressed=True))
    document = cast("dict[str, object]", json.loads(render_json(report)))
    findings = cast("list[dict[str, object]]", document["findings"])

    assert findings[0]["suppressed"] is True
    assert findings[0]["suppression"] == {"kind": "inline"}


def test_unknown_and_malformed_inline_ids_produce_diagnostics(
    tmp_path: Path,
) -> None:
    """Typos and missing mandatory IDs never silently suppress a finding."""
    (tmp_path / "legacy.py").write_text(
        (
            "import cgi  # pyahead: ignore[UNKNOWN]\n"
            "import cgi  # pyahead: ignore[]\n"
            "import cgi  # pyahead: malformed\n"
        ),
        encoding="utf-8",
    )

    report = scan(_request(tmp_path))

    assert [item.code for item in report.diagnostics] == [
        "PYA3001",
        "PYA3002",
        "PYA3002",
    ]
    assert all(finding.suppression is None for finding in report.findings)
    assert report.gate_failed is True


def test_unknown_inline_id_survives_later_tokenization_failure(
    tmp_path: Path,
) -> None:
    """Earlier suppression diagnostics remain beside an incomplete parse result."""
    (tmp_path / "broken.py").write_text(
        "# pyahead: ignore[UNKNOWN]\n(\n",
        encoding="utf-8",
    )

    report = scan(_request(tmp_path))

    assert [item.code for item in report.diagnostics] == ["PYA1003", "PYA3001"]
    assert report.findings == ()
    assert report.counts.files_incomplete == 1


def test_directive_text_inside_a_string_is_not_a_suppression(
    tmp_path: Path,
) -> None:
    """Tokenization prevents source strings from acting as comments."""
    (tmp_path / "legacy.py").write_text(
        'message = "# pyahead: ignore[CPY0001]"\nimport cgi\n',
        encoding="utf-8",
    )

    report = scan(_request(tmp_path))

    assert report.diagnostics == ()
    assert report.findings[0].suppression is None


def test_multiline_statement_comment_touches_the_primary_region(
    tmp_path: Path,
) -> None:
    """A directive on a continued logical import applies to that import."""
    (tmp_path / "legacy.py").write_text(
        ("from cgi import (\n    FieldStorage,  # pyahead: ignore[CPY0001]\n)\n"),
        encoding="utf-8",
    )

    report = scan(_request(tmp_path))

    assert report.findings[0].suppression is not None


@pytest.mark.parametrize(
    ("matcher", "source", "match_kind"),
    [
        pytest.param(
            {
                "kind": "qualified-call",
                "qualified_name": "targetpkg.old_call",
            },
            (
                "import targetpkg\n"
                "targetpkg.old_call(\n"
                '    "payload",  # pyahead: ignore[CPY9001] -- tracked\n'
                ")\n"
            ),
            "qualified-call",
            id="qualified-call-argument-line",
        ),
        pytest.param(
            {
                "kind": "call-shape",
                "qualified_name": "targetpkg.old_call",
                "required_keywords": ["mode"],
            },
            (
                "import targetpkg\n"
                "targetpkg.old_call(\n"
                '    "payload",\n'
                '    mode="legacy",\n'
                ")  # pyahead: ignore[CPY9001] -- tracked\n"
            ),
            "call-shape",
            id="call-shape-closing-line",
        ),
    ],
)
def test_multiline_call_suppression_uses_the_logical_statement(
    tmp_path: Path,
    matcher: dict[str, object],
    source: str,
    match_kind: str,
) -> None:
    """A directive can touch a call statement without widening its region."""
    registry = _write_call_registry(tmp_path, matcher)
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(source, encoding="utf-8")

    report = scan(_request(project, registry_source=registry))
    finding = report.findings[0]

    assert finding.match_kind == match_kind
    assert finding.location.region.start.line == _CALL_LINE
    assert finding.location.region.end.line == _CALL_LINE
    assert finding.suppression is not None
    assert finding.suppression.kind is SuppressionKind.INLINE


@pytest.mark.parametrize(
    "decorator",
    [
        pytest.param(
            "@targetpkg.old_call(1)  # pyahead: ignore[CPY9001] -- reviewed\n",
            id="single-line",
        ),
        pytest.param(
            (
                "@targetpkg.old_call(\n"
                "    1,  # pyahead: ignore[CPY9001] -- reviewed\n"
                ")\n"
            ),
            id="multiline-argument",
        ),
        pytest.param(
            (
                "@targetpkg.old_call(\n"
                "    1,\n"
                ")  # pyahead: ignore[CPY9001] -- reviewed\n"
            ),
            id="multiline-closing-line",
        ),
    ],
)
def test_inline_suppression_applies_to_decorator_expression(
    tmp_path: Path,
    decorator: str,
) -> None:
    """A decorator is one logical statement for inline suppression."""
    registry = _write_call_registry(
        tmp_path,
        {
            "kind": "qualified-call",
            "qualified_name": "targetpkg.old_call",
        },
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(
        f"import targetpkg\n{decorator}def decorated():\n    pass\n",
        encoding="utf-8",
    )

    report = scan(_request(project, registry_source=registry))

    assert len(report.findings) == 1
    assert report.findings[0].suppression is not None
    assert report.findings[0].suppression.kind is SuppressionKind.INLINE


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            (
                "import targetpkg\n"
                "@targetpkg.old_call(1)\n"
                "@staticmethod  # pyahead: ignore[CPY9001] -- adjacent only\n"
                "def decorated():\n"
                "    pass\n"
            ),
            id="adjacent-decorator",
        ),
        pytest.param(
            (
                "import targetpkg\n"
                "@targetpkg.old_call(1)\n"
                "def decorated(\n"
                "    value=1,\n"
                "):  # pyahead: ignore[CPY9001] -- header only\n"
                "    pass\n"
            ),
            id="decorated-function-header",
        ),
        pytest.param(
            (
                "import targetpkg\n"
                "@targetpkg.old_call(1)\n"
                "def decorated():\n"
                "    marker = 1  # pyahead: ignore[CPY9001] -- body only\n"
            ),
            id="decorated-function-body",
        ),
    ],
)
def test_adjacent_directive_does_not_suppress_decorator_expression(
    tmp_path: Path,
    source: str,
) -> None:
    """Decorator suppression never widens into adjacent logical statements."""
    registry = _write_call_registry(
        tmp_path,
        {
            "kind": "qualified-call",
            "qualified_name": "targetpkg.old_call",
        },
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(source, encoding="utf-8")

    report = scan(_request(project, registry_source=registry))

    assert len(report.findings) == 1
    assert report.findings[0].suppression is None


def test_inline_suppression_on_an_adjacent_statement_does_not_apply(
    tmp_path: Path,
) -> None:
    """A nearby directive is limited to its own logical statement."""
    registry = _write_call_registry(
        tmp_path,
        {
            "kind": "qualified-call",
            "qualified_name": "targetpkg.old_call",
        },
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(
        (
            "import targetpkg\n"
            "targetpkg.old_call(\n"
            '    "payload",\n'
            ")\n"
            "marker = 1  # pyahead: ignore[CPY9001] -- unrelated\n"
        ),
        encoding="utf-8",
    )

    report = scan(_request(project, registry_source=registry))

    assert len(report.findings) == 1
    assert report.findings[0].suppression is None


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            (
                "import targetpkg\n"
                "class Child(\n"
                "    targetpkg.old_call,\n"
                "):  # pyahead: ignore[CPY9001] -- reviewed\n"
                "    pass\n"
            ),
            id="multiline-class-base",
        ),
        pytest.param(
            (
                "import targetpkg\n"
                "def build(\n"
                "    implementation=targetpkg.old_call,\n"
                "):  # pyahead: ignore[CPY9001] -- reviewed\n"
                "    pass\n"
            ),
            id="multiline-function-default",
        ),
        pytest.param(
            (
                "import targetpkg\n"
                "if (\n"
                "    targetpkg.old_call\n"
                "):  # pyahead: ignore[CPY9001] -- reviewed\n"
                "    pass\n"
            ),
            id="multiline-condition",
        ),
    ],
)
def test_inline_suppression_applies_to_compound_statement_header(
    tmp_path: Path,
    source: str,
) -> None:
    """A directive on a compound header applies only to that logical header."""
    registry = _write_call_registry(
        tmp_path,
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old_call",
        },
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(source, encoding="utf-8")

    report = scan(_request(project, registry_source=registry))

    assert len(report.findings) == 1
    assert report.findings[0].suppression is not None
    assert report.findings[0].suppression.kind is SuppressionKind.INLINE


def test_inline_suppression_in_compound_body_does_not_apply_to_header(
    tmp_path: Path,
) -> None:
    """A body directive cannot suppress a finding in its compound header."""
    registry = _write_call_registry(
        tmp_path,
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old_call",
        },
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "legacy.py").write_text(
        (
            "import targetpkg\n"
            "class Child(\n"
            "    targetpkg.old_call,\n"
            "):\n"
            "    marker = 1  # pyahead: ignore[CPY9001] -- body only\n"
        ),
        encoding="utf-8",
    )

    report = scan(_request(project, registry_source=registry))

    assert len(report.findings) == 1
    assert report.findings[0].suppression is None


def test_one_line_compound_body_suppression_does_not_cross_into_header(
    tmp_path: Path,
) -> None:
    """Same-line header and suite findings retain separate logical regions."""
    (tmp_path / "legacy.py").write_text(
        ('if __import__("cgi"): import cgi  # pyahead: ignore[CPY0001] -- body only\n'),
        encoding="utf-8",
    )

    report = scan(
        _request(
            tmp_path,
            minimum_confidence="medium",
            show_suppressed=True,
        )
    )
    findings = {finding.match_kind: finding for finding in report.findings}

    assert set(findings) == {"literal-dynamic-import", "module-import"}
    assert findings["literal-dynamic-import"].suppression is None
    body_suppression = findings["module-import"].suppression
    assert body_suppression is not None
    assert body_suppression.kind is SuppressionKind.INLINE
    assert report.gate_failed is True


def test_many_inline_directives_and_findings_use_bounded_indexed_lookup(
    tmp_path: Path,
) -> None:
    """Repository-sized valid directives do not trigger pairwise rescans."""
    source = "".join(
        "import cgi  # pyahead: ignore[CPY0001] -- tracked\n"
        for _ in range(_STRESS_FINDING_COUNT)
    )
    assert len(source.encode()) < 2 * 1024 * 1024
    (tmp_path / "legacy.py").write_text(source, encoding="utf-8")

    report = scan(_request(tmp_path))

    assert len(report.findings) == _STRESS_FINDING_COUNT
    assert report.visible_findings == ()
    assert report.gate_failed is False


def test_per_file_ignores_merge_known_rules_and_diagnose_unknown_ids(
    tmp_path: Path,
) -> None:
    """Configuration suppressions remain visible and typo diagnostics survive."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "legacy.py").write_text("import cgi\n", encoding="utf-8")

    report = scan(
        _request(
            tmp_path,
            per_file_ignores=(
                PerFileIgnore(
                    pattern="tests/**",
                    rule_ids=("UNKNOWN", "CPY0001"),
                ),
            ),
            show_suppressed=True,
        )
    )

    assert [item.code for item in report.diagnostics] == ["PYA3001"]
    suppression = report.findings[0].suppression
    assert suppression is not None
    assert suppression.kind is SuppressionKind.PER_FILE
    assert suppression.pattern == "tests/**"
    assert report.gate_failed is False
