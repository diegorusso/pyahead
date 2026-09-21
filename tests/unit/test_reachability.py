"""Unit tests for three-valued version-guard evaluation."""

from itertools import product

import libcst as cst
import pytest

from pyahead.analysis.reachability import (
    SYS_VERSION_INFO,
    TYPING_TYPE_CHECKING,
    LexicalReachability,
    TruthValue,
    branch_reachability,
    evaluate_guard,
    import_fallback_versions,
    truth_and,
    truth_not,
    truth_or,
    try_body_imports,
)
from pyahead.model import UsageContext
from pyahead.versions import PythonMinor

_TARGET = PythonMinor.parse("3.12")


def _matches_name(node: cst.BaseExpression, expected: str) -> bool:
    if expected == SYS_VERSION_INFO:
        return isinstance(node, cst.Name) and node.value == "version"
    if expected == TYPING_TYPE_CHECKING:
        return isinstance(node, cst.Name) and node.value == "TYPE_CHECKING"
    return False


@pytest.mark.parametrize(
    ("operator", "expected"),
    [
        ("<", TruthValue.TRUE),
        ("<=", TruthValue.TRUE),
        (">", TruthValue.FALSE),
        (">=", TruthValue.FALSE),
        ("==", TruthValue.FALSE),
        ("!=", TruthValue.TRUE),
    ],
)
def test_every_comparison_operator_is_decidable_when_the_minor_differs(
    operator: str,
    expected: TruthValue,
) -> None:
    """All six documented operators are decided by a differing minor prefix."""
    expression = cst.parse_expression(f"version {operator} (3, 13)")

    assert evaluate_guard(expression, _TARGET, _matches_name).truth is expected


@pytest.mark.parametrize(
    (
        "operator",
        "unsliced_left",
        "unsliced_right",
        "sliced_left",
        "sliced_right",
    ),
    [
        (
            "<",
            TruthValue.FALSE,
            TruthValue.TRUE,
            TruthValue.FALSE,
            TruthValue.FALSE,
        ),
        (
            "<=",
            TruthValue.FALSE,
            TruthValue.TRUE,
            TruthValue.TRUE,
            TruthValue.TRUE,
        ),
        (
            ">",
            TruthValue.TRUE,
            TruthValue.FALSE,
            TruthValue.FALSE,
            TruthValue.FALSE,
        ),
        (
            ">=",
            TruthValue.TRUE,
            TruthValue.FALSE,
            TruthValue.TRUE,
            TruthValue.TRUE,
        ),
        (
            "==",
            TruthValue.FALSE,
            TruthValue.FALSE,
            TruthValue.TRUE,
            TruthValue.TRUE,
        ),
        (
            "!=",
            TruthValue.TRUE,
            TruthValue.TRUE,
            TruthValue.FALSE,
            TruthValue.FALSE,
        ),
    ],
)
def test_matching_minor_preserves_unsliced_sequence_semantics(
    operator: str,
    unsliced_left: TruthValue,
    unsliced_right: TruthValue,
    sliced_left: TruthValue,
    sliced_right: TruthValue,
) -> None:
    """Matching prefixes distinguish full version info from its minor slice."""
    cases = (
        (f"version {operator} (3, 12)", unsliced_left),
        (f"(3, 12) {operator} version", unsliced_right),
        (f"version[:2] {operator} (3, 12)", sliced_left),
        (f"(3, 12) {operator} version[:2]", sliced_right),
    )

    for source, expected in cases:
        evaluation = evaluate_guard(
            cst.parse_expression(source),
            _TARGET,
            _matches_name,
        )

        assert evaluation.truth is expected, source


def test_comparison_supports_reversed_operands_and_minor_slice() -> None:
    """Literal-first guards and the documented ``[:2]`` form are recognized."""
    reversed_expression = cst.parse_expression("(3, 12) <= version")
    sliced_expression = cst.parse_expression("version[:2] == (3, 12)")

    assert (
        evaluate_guard(reversed_expression, _TARGET, _matches_name).truth
        is TruthValue.TRUE
    )
    assert (
        evaluate_guard(sliced_expression, _TARGET, _matches_name).truth
        is TruthValue.TRUE
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (TruthValue.TRUE, TruthValue.FALSE),
        (TruthValue.FALSE, TruthValue.TRUE),
        (TruthValue.UNKNOWN, TruthValue.UNKNOWN),
    ],
)
def test_three_valued_not(value: TruthValue, expected: TruthValue) -> None:
    """Negation preserves uncertainty."""
    assert truth_not(value) is expected


_AND_RESULTS = {
    (TruthValue.TRUE, TruthValue.TRUE): TruthValue.TRUE,
    (TruthValue.TRUE, TruthValue.FALSE): TruthValue.FALSE,
    (TruthValue.TRUE, TruthValue.UNKNOWN): TruthValue.UNKNOWN,
    (TruthValue.FALSE, TruthValue.TRUE): TruthValue.FALSE,
    (TruthValue.FALSE, TruthValue.FALSE): TruthValue.FALSE,
    (TruthValue.FALSE, TruthValue.UNKNOWN): TruthValue.FALSE,
    (TruthValue.UNKNOWN, TruthValue.TRUE): TruthValue.UNKNOWN,
    (TruthValue.UNKNOWN, TruthValue.FALSE): TruthValue.FALSE,
    (TruthValue.UNKNOWN, TruthValue.UNKNOWN): TruthValue.UNKNOWN,
}
_OR_RESULTS = {
    (TruthValue.TRUE, TruthValue.TRUE): TruthValue.TRUE,
    (TruthValue.TRUE, TruthValue.FALSE): TruthValue.TRUE,
    (TruthValue.TRUE, TruthValue.UNKNOWN): TruthValue.TRUE,
    (TruthValue.FALSE, TruthValue.TRUE): TruthValue.TRUE,
    (TruthValue.FALSE, TruthValue.FALSE): TruthValue.FALSE,
    (TruthValue.FALSE, TruthValue.UNKNOWN): TruthValue.UNKNOWN,
    (TruthValue.UNKNOWN, TruthValue.TRUE): TruthValue.TRUE,
    (TruthValue.UNKNOWN, TruthValue.FALSE): TruthValue.UNKNOWN,
    (TruthValue.UNKNOWN, TruthValue.UNKNOWN): TruthValue.UNKNOWN,
}


@pytest.mark.parametrize(("left", "right"), tuple(product(TruthValue, repeat=2)))
def test_three_valued_and_or_truth_tables(
    left: TruthValue,
    right: TruthValue,
) -> None:
    """Every Boolean input combination follows conservative truth tables."""
    assert truth_and(left, right) is _AND_RESULTS[(left, right)]
    assert truth_or(left, right) is _OR_RESULTS[(left, right)]


def test_unknown_condition_enters_both_branches() -> None:
    """An unsupported predicate can never suppress either lexical branch."""
    versions = frozenset({PythonMinor.parse("3.11"), PythonMinor.parse("3.12")})
    active = LexicalReachability(
        versions=versions,
        usage_contexts=frozenset({UsageContext.RUNTIME, UsageContext.TYPING}),
    )

    branches = branch_reachability(
        cst.parse_expression("feature_enabled"),
        active,
        _matches_name,
    )

    assert branches.if_true.versions == versions
    assert branches.if_false.versions == versions
    assert branches.if_true.usage_contexts == active.usage_contexts
    assert branches.if_false.usage_contexts == active.usage_contexts


def test_type_checking_splits_contexts_but_mixed_conditions_do_not() -> None:
    """Only a direct TYPE_CHECKING guard may narrow runtime versus typing use."""
    active = LexicalReachability(
        versions=frozenset({_TARGET}),
        usage_contexts=frozenset({UsageContext.RUNTIME, UsageContext.TYPING}),
    )

    direct = branch_reachability(
        cst.parse_expression("TYPE_CHECKING"), active, _matches_name
    )
    negated = branch_reachability(
        cst.parse_expression("not TYPE_CHECKING"), active, _matches_name
    )
    mixed = branch_reachability(
        cst.parse_expression("TYPE_CHECKING and version >= (3, 12)"),
        active,
        _matches_name,
    )

    assert direct.if_true.usage_contexts == frozenset({UsageContext.TYPING})
    assert direct.if_false.usage_contexts == frozenset({UsageContext.RUNTIME})
    assert negated.if_true.usage_contexts == frozenset({UsageContext.RUNTIME})
    assert negated.if_false.usage_contexts == frozenset({UsageContext.TYPING})
    assert mixed.if_true == mixed.if_false == active


def test_patch_guard_is_explicitly_unsupported() -> None:
    """Patch literals remain unknown instead of being rounded to a minor."""
    evaluation = evaluate_guard(
        cst.parse_expression("version >= (3, 12, 1)"),
        _TARGET,
        _matches_name,
    )

    assert evaluation.truth is TruthValue.UNKNOWN
    assert evaluation.unsupported_patch is True


@pytest.mark.parametrize(
    "source",
    [
        "version[:3] >= (3, 12, 1)",
        "(3, 12, 1) <= version[:3]",
    ],
)
def test_patch_slice_guard_is_explicitly_unsupported(source: str) -> None:
    """Patch slices are visible and unknown with either operand ordering."""
    evaluation = evaluate_guard(
        cst.parse_expression(source),
        _TARGET,
        _matches_name,
    )

    assert evaluation.truth is TruthValue.UNKNOWN
    assert evaluation.unsupported_patch is True


@pytest.mark.parametrize(
    "source",
    [
        "version >= value",
        "version >= (*parts,)",
        'version >= (3, "12")',
        "version >= (3,)",
        "version[0, 1] == (3, 12)",
        "version[0] == (3, 12)",
        "version[:minor] == (3, 12)",
        "version < (3, 13) < (3, 14)",
        "value < (3, 12)",
        "version < version",
        "version is (3, 12)",
    ],
)
def test_unsupported_comparison_shapes_remain_unknown(source: str) -> None:
    """Malformed and out-of-grammar shapes never imply unreachability."""
    evaluation = evaluate_guard(
        cst.parse_expression(source),
        _TARGET,
        _matches_name,
    )

    assert evaluation.truth is TruthValue.UNKNOWN


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("version[0] < 3", TruthValue.FALSE),
        ("version[0] >= 3", TruthValue.TRUE),
        ("version[0] == 2", TruthValue.FALSE),
        ("version[0] != 2", TruthValue.TRUE),
        ("2 < version[0]", TruthValue.TRUE),
        ("version[0] < (3,)", TruthValue.UNKNOWN),
        ("version[1] < 3", TruthValue.UNKNOWN),
        ("version[0] < 3.0", TruthValue.UNKNOWN),
    ],
)
def test_major_index_guard_compares_the_major_component_only(
    source: str, expected: TruthValue
) -> None:
    """``version[0]`` against a bare integer is the Python 2/3 split."""
    expression = cst.parse_expression(source)

    assert evaluate_guard(expression, _TARGET, _matches_name).truth is expected


def _try(source: str) -> cst.Try:
    statement = cst.parse_module(source).body[0]
    assert isinstance(statement, cst.Try)
    return statement


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("import threading", ("threading",)),
        ("import xml.etree.ElementTree as ET", ("xml.etree.ElementTree",)),
        ("import os, sys", ("os", "sys")),
        (
            "from collections.abc import Mapping, Sequence",
            ("collections.abc.Mapping", "collections.abc.Sequence"),
        ),
        ("import re._constants as sre_constants", ("re._constants",)),
        ("from . import helpers", None),
        ("from .. import helpers", None),
        ("from collections.abc import *", None),
        ("import threading; value = 1", ("threading",)),
        (
            (
                "import re._constants as sre\n    ATOMIC = sre.ATOMIC_GROUP\n"
                "    NOTHING = None"
            ),
            ("re._constants",),
        ),
        (
            "import xml.etree.ElementTree\n    E = xml.etree.ElementTree.Element",
            ("xml.etree.ElementTree",),
        ),
        (
            "from re import _constants\n    A = _constants.ATOMIC_GROUP",
            ("re._constants",),
        ),
        ("import threading\n    threading.current_thread()", None),
        ("import threading\n    value = compute()", None),
        ("import threading\n    value = os.sep", None),
        ("import threading\n    value = threading.stack_size()", None),
        ("import threading\n    value = threading.__dict__['x']", None),
        ("import threading\n    value = threading.TIMEOUT_MAX + 1", None),
        ("import threading\n    threading.x = 1", None),
        ("import threading\n    value: int = 1", None),
        ("value = 1", None),
        ("if True:\n        import threading", None),
    ],
    ids=(
        "module",
        "dotted-module",
        "two-modules",
        "from-attributes",
        "private-submodule",
        "relative",
        "relative-parent",
        "star",
        "literal-assignment",
        "attribute-read-assignments",
        "dotted-import-attribute-read",
        "from-import-attribute-read",
        "call-after-import",
        "call-assignment",
        "read-of-an-outside-name",
        "method-call-assignment",
        "subscript-assignment",
        "operator-assignment",
        "attribute-target",
        "annotated-assignment",
        "no-import",
        "compound-statement",
    ),
)
def test_try_body_imports_names_only_pure_import_bodies(
    body: str,
    expected: tuple[str, ...] | None,
) -> None:
    """The fallback grammar covers a body made only of absolute imports."""
    node = _try(f"try:\n    {body}\nexcept ImportError:\n    pass\n")

    assert try_body_imports(node.body) == expected


def test_try_body_imports_reads_a_one_line_suite() -> None:
    """``try: import x`` on one line is the same body."""
    node = _try("try: import threading\nexcept ImportError: pass\n")

    assert try_body_imports(node.body) == ("threading",)


def _versions(*minors: str) -> frozenset[PythonMinor]:
    return frozenset(PythonMinor.parse(minor) for minor in minors)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("import threading", _versions("3.8", "3.9", "3.10", "3.11", "3.12")),
        ("import _imp as imp", _versions("3.8", "3.9", "3.10", "3.11", "3.12")),
        (
            "from collections.abc import Mapping",
            _versions("3.8", "3.9", "3.10", "3.11", "3.12"),
        ),
        ("import zoneinfo", _versions("3.9", "3.10", "3.11", "3.12")),
        ("import re._constants as sre_constants", _versions("3.11", "3.12")),
        ("import threading, zoneinfo", _versions("3.9", "3.10", "3.11", "3.12")),
        ("import numpy", frozenset()),
        ("import threading, numpy", frozenset()),
        ("from collections.abc import Frobnicate", frozenset()),
        ("import ssl", frozenset()),
        ("import imp", frozenset()),
        ("from . import helpers", frozenset()),
        ("import threading; value = compute()", frozenset()),
    ],
    ids=(
        "always-present",
        "builtin-private",
        "known-attribute",
        "added-in-3.9",
        "added-in-3.11",
        "latest-of-two",
        "third-party",
        "one-unknown-spoils-all",
        "unknown-attribute",
        "optional-build",
        "removed-module",
        "relative",
        "call-in-body",
    ),
)
def test_import_fallback_versions_follow_the_known_import_table(
    body: str,
    expected: frozenset[PythonMinor],
) -> None:
    """Only imports the table knows narrow a handler, and only from their version."""
    node = _try(f"try:\n    {body}\nexcept ImportError:\n    pass\n")
    active = _versions("3.8", "3.9", "3.10", "3.11", "3.12")

    assert import_fallback_versions(node, active) == expected
