"""Predicates for qualified calls and literal dynamic imports."""

from dataclasses import dataclass

import libcst as cst

from pyahead.model import CallShapeMatcher, LiteralValue

IMPORT_MODULE_FUNCTION = "importlib.import_module"
BUILTIN_IMPORT_FUNCTION = "builtins.__import__"


@dataclass(frozen=True)
class CallArguments:
    """Statically visible call arguments and expansion uncertainty."""

    positional: tuple[cst.BaseExpression, ...]
    keywords: dict[str, cst.BaseExpression]
    has_starred_positional: bool
    has_starred_keywords: bool
    duplicate_keyword: bool


def call_arguments(call: cst.Call) -> CallArguments:
    """Separate ordinary arguments without attempting general value inference."""
    positional: list[cst.BaseExpression] = []
    keywords: dict[str, cst.BaseExpression] = {}
    has_starred_positional = False
    has_starred_keywords = False
    duplicate_keyword = False
    for argument in call.args:
        if argument.star == "*":
            has_starred_positional = True
        elif argument.star == "**":
            has_starred_keywords = True
        elif argument.keyword is None:
            positional.append(argument.value)
        else:
            keyword = argument.keyword.value
            if keyword in keywords:
                duplicate_keyword = True
            keywords[keyword] = argument.value
    return CallArguments(
        positional=tuple(positional),
        keywords=keywords,
        has_starred_positional=has_starred_positional,
        has_starred_keywords=has_starred_keywords,
        duplicate_keyword=duplicate_keyword,
    )


def literal_value(expression: cst.BaseExpression) -> tuple[bool, LiteralValue]:
    """Evaluate only scalar source literals, never arbitrary expressions."""
    resolved = False
    value: LiteralValue = None
    if isinstance(expression, (cst.SimpleString, cst.ConcatenatedString)):
        evaluated_string = expression.evaluated_value
        if isinstance(evaluated_string, str):
            resolved = True
            value = evaluated_string
    elif isinstance(expression, (cst.Float, cst.Integer)):
        resolved = True
        value = expression.evaluated_value
    elif isinstance(expression, cst.Name):
        names: dict[str, LiteralValue] = {
            "False": False,
            "None": None,
            "True": True,
        }
        if expression.value in names:
            resolved = True
            value = names[expression.value]
    elif isinstance(expression, cst.UnaryOperation) and isinstance(
        expression.operator, (cst.Minus, cst.Plus)
    ):
        nested_resolved, nested_value = literal_value(expression.expression)
        if (
            nested_resolved
            and isinstance(nested_value, (float, int))
            and not isinstance(nested_value, bool)
        ):
            resolved = True
            value = (
                -nested_value
                if isinstance(expression.operator, cst.Minus)
                else nested_value
            )
    return resolved, value


def _literal_equals(expression: cst.BaseExpression, expected: LiteralValue) -> bool:
    resolved, actual = literal_value(expression)
    return resolved and type(actual) is type(expected) and actual == expected


def _positional_shape_matches(
    arguments: CallArguments,
    matcher: CallShapeMatcher,
) -> bool:
    expansion_makes_shape_unknown = matcher.max_positional_args is not None or any(
        item.position is not None for item in matcher.literal_arguments
    )
    if arguments.has_starred_positional and expansion_makes_shape_unknown:
        return False
    count = len(arguments.positional)
    return not (
        (
            matcher.min_positional_args is not None
            and count < matcher.min_positional_args
        )
        or (
            matcher.max_positional_args is not None
            and count > matcher.max_positional_args
        )
    )


def _keyword_shape_matches(
    arguments: CallArguments,
    matcher: CallShapeMatcher,
) -> bool:
    keyword_names = set(arguments.keywords)
    return (
        not (
            matcher.min_keyword_args is not None
            and len(keyword_names) < matcher.min_keyword_args
        )
        and not (
            matcher.max_keyword_args is not None
            and len(keyword_names) > matcher.max_keyword_args
        )
        and not (
            arguments.has_starred_keywords and matcher.max_keyword_args is not None
        )
        and set(matcher.required_keywords).issubset(keyword_names)
        and not set(matcher.forbidden_keywords).intersection(keyword_names)
        and not (arguments.has_starred_keywords and matcher.forbidden_keywords)
    )


def _literal_shape_matches(
    arguments: CallArguments,
    matcher: CallShapeMatcher,
) -> bool:
    count = len(arguments.positional)
    for predicate in matcher.literal_arguments:
        if predicate.position is not None:
            if predicate.position >= count or not _literal_equals(
                arguments.positional[predicate.position], predicate.equals
            ):
                return False
        elif predicate.keyword is not None:
            expression = arguments.keywords.get(predicate.keyword)
            if expression is None or not _literal_equals(expression, predicate.equals):
                return False
    return True


def call_shape_matches(call: cst.Call, matcher: CallShapeMatcher) -> bool:
    """Return whether a call proves every authored shape predicate."""
    arguments = call_arguments(call)
    return (
        not arguments.duplicate_keyword
        and _positional_shape_matches(arguments, matcher)
        and _keyword_shape_matches(arguments, matcher)
        and _literal_shape_matches(arguments, matcher)
    )


def _literal_dynamic_name(arguments: CallArguments) -> str | None:
    """Read one absolute literal module name from visible arguments."""
    expression = arguments.keywords.get("name")
    if expression is not None and arguments.positional:
        return None
    if expression is None and arguments.positional:
        expression = arguments.positional[0]
    if expression is None:
        return None
    resolved, value = literal_value(expression)
    if not resolved or not isinstance(value, str) or value.startswith("."):
        return None
    return value


def _has_duplicate_bound_argument(
    arguments: CallArguments,
    parameter_positions: dict[str, int],
) -> bool:
    """Return whether a keyword repeats an already-bound positional parameter."""
    return any(
        parameter_positions[keyword] < len(arguments.positional)
        for keyword in arguments.keywords
    )


def _literal_import_module(arguments: CallArguments) -> str | None:
    """Validate the signature facts relevant to ``import_module``."""
    parameter_positions = {"name": 0, "package": 1}
    if (
        len(arguments.positional) > len(parameter_positions)
        or not set(arguments.keywords).issubset(parameter_positions)
        or _has_duplicate_bound_argument(arguments, parameter_positions)
    ):
        return None
    return _literal_dynamic_name(arguments)


def _literal_builtin_import(arguments: CallArguments) -> str | None:
    """Require ``__import__`` to prove an absolute level-zero request."""
    parameter_positions = {
        "name": 0,
        "globals": 1,
        "locals": 2,
        "fromlist": 3,
        "level": 4,
    }
    if (
        len(arguments.positional) > len(parameter_positions)
        or not set(arguments.keywords).issubset(parameter_positions)
        or _has_duplicate_bound_argument(arguments, parameter_positions)
    ):
        return None
    level = (
        arguments.positional[parameter_positions["level"]]
        if len(arguments.positional) > parameter_positions["level"]
        else arguments.keywords.get("level")
    )
    if level is not None:
        resolved, value = literal_value(level)
        if not resolved or type(value) is not int or value != 0:
            return None
    return _literal_dynamic_name(arguments)


def literal_dynamic_module(call: cst.Call, dynamic_function: str) -> str | None:
    """Validate one whitelisted function call and return its absolute module."""
    arguments = call_arguments(call)
    if (
        arguments.duplicate_keyword
        or arguments.has_starred_positional
        or arguments.has_starred_keywords
    ):
        return None
    if dynamic_function == IMPORT_MODULE_FUNCTION:
        return _literal_import_module(arguments)
    if dynamic_function == BUILTIN_IMPORT_FUNCTION:
        return _literal_builtin_import(arguments)
    return None
