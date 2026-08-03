"""Conservative minor-version and usage-context guard evaluation."""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

import libcst as cst

from pyahead.model import UsageContext
from pyahead.versions import PythonMinor

SYS_VERSION_INFO = "sys.version_info"
TYPING_TYPE_CHECKING = "typing.TYPE_CHECKING"
_MINOR_COMPONENTS = 2
_PATCH_COMPONENTS = 3

QualifiedNameMatcher = Callable[[cst.BaseExpression, str], bool]


class TruthValue(StrEnum):
    """A result in the guard evaluator's three-valued logic."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class _VersionInfoShape(StrEnum):
    """Recognized sequence shapes for ``sys.version_info`` guards."""

    UNSLICED = "unsliced"
    MINOR_SLICE = "minor-slice"
    PATCH_SLICE = "patch-slice"


@dataclass(frozen=True)
class GuardEvaluation:
    """One guard result plus unsupported syntax observed while deriving it."""

    truth: TruthValue
    unsupported_patch: bool = False


@dataclass(frozen=True)
class LexicalReachability:
    """Target versions and usage contexts active at one lexical location."""

    versions: frozenset[PythonMinor]
    usage_contexts: frozenset[UsageContext]


@dataclass(frozen=True)
class BranchReachability:
    """Conservative true and false states for one ``if`` condition."""

    if_true: LexicalReachability
    if_false: LexicalReachability
    unsupported_patch: bool


def truth_not(value: TruthValue) -> TruthValue:
    """Negate one three-valued result."""
    if value is TruthValue.TRUE:
        return TruthValue.FALSE
    if value is TruthValue.FALSE:
        return TruthValue.TRUE
    return TruthValue.UNKNOWN


def truth_and(left: TruthValue, right: TruthValue) -> TruthValue:
    """Combine two values with conservative three-valued conjunction."""
    if TruthValue.FALSE in {left, right}:
        return TruthValue.FALSE
    if left is right is TruthValue.TRUE:
        return TruthValue.TRUE
    return TruthValue.UNKNOWN


def truth_or(left: TruthValue, right: TruthValue) -> TruthValue:
    """Combine two values with conservative three-valued disjunction."""
    if TruthValue.TRUE in {left, right}:
        return TruthValue.TRUE
    if left is right is TruthValue.FALSE:
        return TruthValue.FALSE
    return TruthValue.UNKNOWN


def _integer(node: cst.BaseExpression) -> int | None:
    if not isinstance(node, cst.Integer):
        return None
    try:
        return int(node.value.replace("_", ""), 0)
    except ValueError:  # pragma: no cover - LibCST accepts only valid integers.
        return None


def _version_literal(
    node: cst.BaseExpression,
) -> tuple[tuple[int, int] | None, bool]:
    if not isinstance(node, cst.Tuple):
        return None, False
    values: list[int] = []
    for element in node.elements:
        if not isinstance(element, cst.Element):
            return None, False
        value = _integer(element.value)
        if value is None:
            return None, False
        values.append(value)
    if len(values) > _MINOR_COMPONENTS:
        return None, True
    if len(values) != _MINOR_COMPONENTS:
        return None, False
    return (values[0], values[1]), False


def _prefix_slice(node: cst.Subscript, components: int) -> bool:
    if len(node.slice) != 1:
        return False
    subscript = node.slice[0]
    if not isinstance(subscript.slice, cst.Slice):
        return False
    slice_value = subscript.slice
    upper = _integer(slice_value.upper) if slice_value.upper is not None else None
    return (
        slice_value.lower is None and upper == components and slice_value.step is None
    )


def _version_info_shape(
    node: cst.BaseExpression,
    matches_qualified_name: QualifiedNameMatcher,
) -> _VersionInfoShape | None:
    if isinstance(node, cst.Subscript):
        if not matches_qualified_name(node.value, SYS_VERSION_INFO):
            return None
        if _prefix_slice(node, _MINOR_COMPONENTS):
            return _VersionInfoShape.MINOR_SLICE
        if _prefix_slice(node, _PATCH_COMPONENTS):
            return _VersionInfoShape.PATCH_SLICE
        return None
    if matches_qualified_name(node, SYS_VERSION_INFO):
        return _VersionInfoShape.UNSLICED
    return None


def _comparison_truth(
    left: tuple[int, ...],
    right: tuple[int, ...],
    operator: cst.BaseCompOp,
) -> TruthValue:
    result: bool
    if isinstance(operator, cst.LessThan):
        result = left < right
    elif isinstance(operator, cst.LessThanEqual):
        result = left <= right
    elif isinstance(operator, cst.GreaterThan):
        result = left > right
    elif isinstance(operator, cst.GreaterThanEqual):
        result = left >= right
    elif isinstance(operator, cst.Equal):
        result = left == right
    elif isinstance(operator, cst.NotEqual):
        result = left != right
    else:
        return TruthValue.UNKNOWN
    return TruthValue.TRUE if result else TruthValue.FALSE


def _evaluate_comparison(
    expression: cst.Comparison,
    target: PythonMinor,
    matches_qualified_name: QualifiedNameMatcher,
) -> GuardEvaluation:
    if len(expression.comparisons) != 1:
        return GuardEvaluation(TruthValue.UNKNOWN)
    comparison = expression.comparisons[0]
    left_shape = _version_info_shape(expression.left, matches_qualified_name)
    right_shape = _version_info_shape(
        comparison.comparator,
        matches_qualified_name,
    )
    unsupported_patch = _VersionInfoShape.PATCH_SLICE in (left_shape, right_shape)
    if left_shape is not None and right_shape is None:
        version_shape = left_shape
        version_on_left = True
        literal_node = comparison.comparator
    elif left_shape is None and right_shape is not None:
        version_shape = right_shape
        version_on_left = False
        literal_node = expression.left
    else:
        return GuardEvaluation(
            TruthValue.UNKNOWN,
            unsupported_patch=unsupported_patch,
        )

    literal, literal_unsupported_patch = _version_literal(literal_node)
    unsupported_patch = unsupported_patch or literal_unsupported_patch
    if unsupported_patch:
        return GuardEvaluation(TruthValue.UNKNOWN, unsupported_patch=True)
    if literal is None:
        return GuardEvaluation(TruthValue.UNKNOWN)
    target_value: tuple[int, ...] = (target.major, target.minor)
    if version_shape is _VersionInfoShape.UNSLICED:
        # The literal has exactly two fields, so one arbitrary tail field models
        # the guaranteed-longer struct sequence without inventing patch semantics.
        target_value = (*target_value, 0)
    left = target_value if version_on_left else literal
    right = literal if version_on_left else target_value
    return GuardEvaluation(
        _comparison_truth(left, right, comparison.operator),
        unsupported_patch=unsupported_patch,
    )


def evaluate_guard(
    expression: cst.BaseExpression,
    target: PythonMinor,
    matches_qualified_name: QualifiedNameMatcher,
) -> GuardEvaluation:
    """Evaluate the supported guard grammar for one target minor."""
    if isinstance(expression, cst.Comparison):
        return _evaluate_comparison(expression, target, matches_qualified_name)
    if isinstance(expression, cst.UnaryOperation) and isinstance(
        expression.operator, cst.Not
    ):
        inner = evaluate_guard(expression.expression, target, matches_qualified_name)
        return GuardEvaluation(
            truth_not(inner.truth),
            unsupported_patch=inner.unsupported_patch,
        )
    if isinstance(expression, cst.BooleanOperation):
        left = evaluate_guard(expression.left, target, matches_qualified_name)
        right = evaluate_guard(expression.right, target, matches_qualified_name)
        if isinstance(expression.operator, cst.And):
            truth = truth_and(left.truth, right.truth)
        elif isinstance(expression.operator, cst.Or):
            truth = truth_or(left.truth, right.truth)
        else:  # pragma: no cover - LibCST's BooleanOperation is closed.
            truth = TruthValue.UNKNOWN
        return GuardEvaluation(
            truth,
            unsupported_patch=left.unsupported_patch or right.unsupported_patch,
        )
    return GuardEvaluation(TruthValue.UNKNOWN)


def _is_type_checking(
    expression: cst.BaseExpression,
    matches_qualified_name: QualifiedNameMatcher,
) -> bool:
    return matches_qualified_name(expression, TYPING_TYPE_CHECKING)


def type_checking_polarity(
    expression: cst.BaseExpression,
    matches_qualified_name: QualifiedNameMatcher,
) -> bool | None:
    """Return direct ``TYPE_CHECKING`` polarity, or ``None`` when unsupported."""
    if _is_type_checking(expression, matches_qualified_name):
        return True
    if (
        isinstance(expression, cst.UnaryOperation)
        and isinstance(expression.operator, cst.Not)
        and _is_type_checking(expression.expression, matches_qualified_name)
    ):
        return False
    return None


def _contains_type_checking(
    expression: cst.BaseExpression,
    matches_qualified_name: QualifiedNameMatcher,
) -> bool:
    stack: list[cst.CSTNode] = [expression]
    while stack:
        node = stack.pop()
        if isinstance(node, cst.BaseExpression) and _is_type_checking(
            node, matches_qualified_name
        ):
            return True
        stack.extend(node.children)
    return False


def branch_reachability(
    expression: cst.BaseExpression,
    active: LexicalReachability,
    matches_qualified_name: QualifiedNameMatcher,
) -> BranchReachability:
    """Split one active lexical state using conservative guard semantics."""
    polarity = type_checking_polarity(expression, matches_qualified_name)
    mixed_type_checking = polarity is None and _contains_type_checking(
        expression, matches_qualified_name
    )
    true_versions: set[PythonMinor] = set()
    false_versions: set[PythonMinor] = set()
    unsupported_patch = False
    for target in active.versions:
        evaluation = evaluate_guard(expression, target, matches_qualified_name)
        unsupported_patch = unsupported_patch or evaluation.unsupported_patch
        truth = TruthValue.UNKNOWN if mixed_type_checking else evaluation.truth
        if truth is not TruthValue.FALSE:
            true_versions.add(target)
        if truth is not TruthValue.TRUE:
            false_versions.add(target)

    if polarity is None:
        true_contexts = false_contexts = active.usage_contexts
    else:
        true_kind = UsageContext.TYPING if polarity else UsageContext.RUNTIME
        false_kind = UsageContext.RUNTIME if polarity else UsageContext.TYPING
        true_contexts = active.usage_contexts.intersection({true_kind})
        false_contexts = active.usage_contexts.intersection({false_kind})

    return BranchReachability(
        if_true=LexicalReachability(
            versions=frozenset(true_versions),
            usage_contexts=frozenset(true_contexts),
        ),
        if_false=LexicalReachability(
            versions=frozenset(false_versions),
            usage_contexts=frozenset(false_contexts),
        ),
        unsupported_patch=unsupported_patch,
    )
