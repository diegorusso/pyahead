"""Whitelisted syntax-pattern dispatch for shapes unsafe to describe as code."""

from collections.abc import Callable, Mapping
from types import MappingProxyType

import libcst as cst

from pyahead.model import BuiltinPattern

BuiltinMatcher = Callable[[cst.CSTNode], bool]


def _bool_bitwise_inversion(node: cst.CSTNode) -> bool:
    return (
        isinstance(node, cst.UnaryOperation)
        and isinstance(node.operator, cst.BitInvert)
        and isinstance(node.expression, cst.Name)
        and node.expression.value in {"False", "True"}
    )


BUILTIN_PATTERN_DISPATCH: Mapping[BuiltinPattern, BuiltinMatcher] = MappingProxyType(
    {BuiltinPattern.BOOL_BITWISE_INVERSION: _bool_bitwise_inversion}
)


def matches_builtin_pattern(pattern: BuiltinPattern, node: cst.CSTNode) -> bool:
    """Dispatch only through the fixed in-process matcher whitelist."""
    return BUILTIN_PATTERN_DISPATCH[pattern](node)
