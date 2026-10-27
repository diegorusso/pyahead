"""Conservative guards for newly detected symbol-import failures."""

from collections.abc import Callable

import libcst as cst

from pyahead.analysis.reachability import (
    TYPING_TYPE_CHECKING,
    QualifiedNameMatcher,
    TruthValue,
    evaluate_guard,
    truth_and,
    truth_not,
    truth_or,
)
from pyahead.versions import PythonMinor

GuardAlias = Callable[[cst.Name], cst.BaseExpression | None]
_PATCH_COMPONENTS = 3


def evaluate_import_guard(
    expression: cst.BaseExpression,
    target: PythonMinor,
    matches_name: QualifiedNameMatcher,
    alias_value: GuardAlias,
) -> TruthValue:
    """Follow proven constants, retaining unknown guards as uncertain imports."""
    if matches_name(expression, TYPING_TYPE_CHECKING):
        return TruthValue.FALSE
    if isinstance(expression, cst.Name):
        if expression.value in {"True", "False"}:
            return TruthValue.TRUE if expression.value == "True" else TruthValue.FALSE
        value = alias_value(expression)
        if value is not None:
            return evaluate_import_guard(value, target, matches_name, alias_value)
    if isinstance(expression, cst.UnaryOperation) and isinstance(
        expression.operator, cst.Not
    ):
        return truth_not(
            evaluate_import_guard(
                expression.expression, target, matches_name, alias_value
            )
        )
    if isinstance(expression, cst.BooleanOperation):
        left = evaluate_import_guard(expression.left, target, matches_name, alias_value)
        right = evaluate_import_guard(
            expression.right, target, matches_name, alias_value
        )
        return (
            truth_and(left, right)
            if isinstance(expression.operator, cst.And)
            else truth_or(left, right)
        )
    result = evaluate_guard(expression, target, matches_name)
    return (
        _patch_comparison(expression, target, matches_name)
        if result.unsupported_patch and isinstance(expression, cst.Comparison)
        else result.truth
    )


def _patch_comparison(
    expression: cst.Comparison,
    target: PythonMinor,
    matches_name: QualifiedNameMatcher,
) -> TruthValue:
    """Decide only comparisons whose major/minor prefix settles the result."""
    # A different major/minor decides the comparison regardless of the patch.
    comparison = expression.comparisons[0]
    for literal in (expression.left, comparison.comparator):
        if (
            not isinstance(literal, cst.Tuple)
            or len(literal.elements) != _PATCH_COMPONENTS
        ):
            continue
        if not all(
            isinstance(element, cst.Element) and isinstance(element.value, cst.Integer)
            for element in literal.elements
        ):
            continue
        prefix = literal.with_changes(elements=literal.elements[:2])
        projected = expression.with_changes(
            left=prefix if expression.left is literal else expression.left,
            comparisons=(
                comparison.with_changes(
                    comparator=(
                        prefix
                        if comparison.comparator is literal
                        else comparison.comparator
                    )
                ),
            ),
        )
        version = (
            projected.left if expression.left is not literal else comparison.comparator
        )
        if isinstance(version, cst.Subscript):
            return TruthValue.UNKNOWN
        if not matches_name(version, "sys.version_info"):
            continue
        values = [
            element.value.evaluated_value
            for element in literal.elements
            if isinstance(element, cst.Element)
            and isinstance(element.value, cst.Integer)
        ]
        if tuple(values[:2]) == (target.major, target.minor):
            return TruthValue.UNKNOWN
        return evaluate_guard(projected, target, matches_name).truth
    return TruthValue.UNKNOWN
