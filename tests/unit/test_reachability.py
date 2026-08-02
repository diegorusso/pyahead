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
    truth_and,
    truth_not,
    truth_or,
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
