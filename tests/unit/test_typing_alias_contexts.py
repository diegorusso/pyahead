"""Characterize static evidence used by the binding-not-visible investigation."""

from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan


@pytest.mark.parametrize(
    ("rule_id", "name"),
    [
        ("CPY0096", "Hashable"),
        ("CPY0096", "Sized"),
        ("CPY0104", "AnyStr"),
        ("CPY0126", "Text"),
    ],
)
@pytest.mark.parametrize("future_annotations", [False, True])
@pytest.mark.parametrize("aliased", [False, True])
def test_typing_alias_reference_context_is_distinct_from_usage_contexts(
    tmp_path: Path,
    rule_id: str,
    name: str,
    *,
    future_annotations: bool,
    aliased: bool,
) -> None:
    """Annotation sites and ordinary reads share contexts, including with PEP 563."""
    imported = f"from typing import {name} as Alias" if aliased else "import typing"
    reference = "Alias" if aliased else f"typing.{name}"
    prefix = "from __future__ import annotations\n" if future_annotations else ""
    lines = [
        imported,
        "from typing import TYPE_CHECKING",
        f"value: {reference}",
        f"def identity(arg: {reference}) -> {reference}:",
        f"    local: {reference} = arg",
        "    return local",
        "class Container:",
        f"    member: {reference}",
        f"alias = {reference}",
        f"class Derived({reference}): ...",
        "if TYPE_CHECKING:",
        f"    type_alias = {reference}",
        f"    annotation: {reference}",
        "else:",
        f"    runtime_alias = {reference}",
        f"literal = '{reference}'",
        f"quoted: '{reference}'",
    ]
    (tmp_path / "uses.py").write_text(prefix + "\n".join(lines) + "\n")
    (tmp_path / "uses.pyi").write_text(
        f"{imported}\nvalue: {reference}\nalias = {reference}\n"
    )
    report = scan(
        ScanRequest(root=tmp_path, baseline_python="3.11", horizon_python="3.16")
    )
    findings = [item for item in report.findings if item.rule_id == rule_id]
    assert report.counts.files_incomplete == 0
    both = ("runtime", "typing")
    expected = [
        (3, "annotation", both, None),
        (4, "annotation", both, None),
        (4, "annotation", both, None),
        (5, "annotation", ("typing",), "deferred"),
        (8, "annotation", both, None),
        (9, "read", both, None),
        (10, "base-class", both, None),
        (12, "read", ("typing",), None),
        (13, "annotation", ("typing",), None),
        (15, "read", ("runtime",), None),
    ]
    actual = []
    for finding in findings:
        assert finding.match_confidence.value == "high"
        assert finding.match_kind == "qualified-reference"
        assert finding.impact.value == "deprecated"
        evidence = dict(finding.match_evidence)
        assert evidence["qualified_names"] == (f"typing.{name}",)
        if finding.location.path.suffix == ".py":
            actual.append(
                (
                    finding.location.region.start.line - int(future_annotations),
                    evidence["reference_context"],
                    tuple(context.value for context in finding.usage_contexts),
                    evidence.get("annotation_evaluation"),
                )
            )
    assert actual == expected
    assert [
        (
            dict(finding.match_evidence)["reference_context"],
            tuple(context.value for context in finding.usage_contexts),
        )
        for finding in findings
        if finding.location.path.suffix == ".pyi"
    ] == [("annotation", ("typing",)), ("read", ("typing",))]
