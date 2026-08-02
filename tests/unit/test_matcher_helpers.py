"""Boundary tests for conservative matcher helper predicates."""

from dataclasses import replace
from typing import cast

import libcst as cst
import pytest
from libcst.metadata import QualifiedName, QualifiedNameSource

from pyahead.analysis.matchers.calls import (
    BUILTIN_IMPORT_FUNCTION,
    IMPORT_MODULE_FUNCTION,
    call_arguments,
    call_shape_matches,
    literal_dynamic_module,
    literal_value,
)
from pyahead.analysis.matchers.imports import imported_modules, module_matches
from pyahead.analysis.matchers.qualified import (
    resolve_qualified_name,
    resolve_qualified_name_sources,
    terminal_name,
)
from pyahead.model import (
    CallShapeMatcher,
    LiteralArgumentPredicate,
    MatchConfidence,
    MatcherKind,
)


def _call(source: str) -> cst.Call:
    expression = cst.parse_expression(source)
    assert isinstance(expression, cst.Call)
    return expression


def _shape() -> CallShapeMatcher:
    return CallShapeMatcher(
        kind=MatcherKind.CALL_SHAPE,
        qualified_name="targetpkg.call",
        min_positional_args=1,
        max_positional_args=1,
        min_keyword_args=1,
        max_keyword_args=1,
        required_keywords=("mode",),
        forbidden_keywords=("legacy",),
        literal_arguments=(
            LiteralArgumentPredicate(position=0, keyword=None, equals=1),
            LiteralArgumentPredicate(position=None, keyword="mode", equals="text"),
        ),
    )


def test_call_arguments_records_expansions_and_duplicate_keywords() -> None:
    """Argument collection retains uncertainty instead of expanding values."""
    expanded = call_arguments(_call('fn(1, *items, mode="text", **options)'))
    duplicate = call_arguments(_call("fn(mode=1, mode=2)"))

    assert len(expanded.positional) == 1
    assert set(expanded.keywords) == {"mode"}
    assert expanded.has_starred_positional is True
    assert expanded.has_starred_keywords is True
    assert duplicate.duplicate_keyword is True


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('"text"', (True, "text")),
        ('"con" "catenated"', (True, "concatenated")),
        ("12", (True, 12)),
        ("1.5", (True, 1.5)),
        ("True", (True, True)),
        ("False", (True, False)),
        ("None", (True, None)),
        ("-2", (True, -2)),
        ("+3.5", (True, 3.5)),
        ("name", (False, None)),
        ('-"text"', (False, None)),
        ('b"bytes"', (False, None)),
    ],
)
def test_literal_value_accepts_only_scalar_source_literals(
    source: str,
    expected: tuple[bool, object],
) -> None:
    """Literal evaluation is bounded and never evaluates calls or names."""
    assert literal_value(cst.parse_expression(source)) == expected


@pytest.mark.parametrize(
    "source",
    [
        'fn(*items, mode="text")',
        'fn(1, mode="text", mode="text")',
        'fn(mode="text")',
        'fn(1, 2, mode="text")',
        "fn(1)",
        'fn(1, mode="text", legacy=True)',
        'fn(1, mode="text", extra=True)',
        'fn(1, mode="text", **options)',
        'fn(2, mode="text")',
        'fn(1, mode="binary")',
    ],
)
def test_call_shape_rejects_unknown_or_mismatched_arguments(source: str) -> None:
    """Every shape predicate must be statically proven."""
    assert call_shape_matches(_call(source), _shape()) is False


def test_call_shape_accepts_an_exact_shape() -> None:
    """Ordinary arguments satisfying all predicates match."""
    assert call_shape_matches(_call('fn(1, mode="text")'), _shape()) is True


def test_minimum_keyword_count_accepts_proven_visible_keywords() -> None:
    """Unknown **kwargs cannot reduce an already-proven visible minimum."""
    matcher = replace(
        _shape(),
        min_positional_args=None,
        max_positional_args=None,
        min_keyword_args=1,
        max_keyword_args=None,
        required_keywords=(),
        forbidden_keywords=(),
        literal_arguments=(),
    )

    assert call_shape_matches(_call("fn(option=True)"), matcher) is True
    assert call_shape_matches(_call("fn(option=True, **options)"), matcher) is True
    assert call_shape_matches(_call("fn()"), matcher) is False
    assert call_shape_matches(_call("fn(**options)"), matcher) is False


def test_minimum_positional_count_accepts_proven_visible_arguments() -> None:
    """Unknown *args cannot reduce an already-proven visible minimum."""
    matcher = replace(
        _shape(),
        min_positional_args=1,
        max_positional_args=None,
        min_keyword_args=None,
        max_keyword_args=None,
        required_keywords=(),
        forbidden_keywords=(),
        literal_arguments=(),
    )

    assert call_shape_matches(_call("fn(1, *())"), matcher) is True
    assert call_shape_matches(_call("fn(1, *items)"), matcher) is True
    assert call_shape_matches(_call("fn(*items)"), matcher) is False


@pytest.mark.parametrize(
    ("dynamic_function", "source", "expected"),
    [
        (IMPORT_MODULE_FUNCTION, 'load("targetpkg")', "targetpkg"),
        (IMPORT_MODULE_FUNCTION, 'load(name="targetpkg")', "targetpkg"),
        (
            IMPORT_MODULE_FUNCTION,
            'load("targetpkg", package="parent")',
            "targetpkg",
        ),
        (IMPORT_MODULE_FUNCTION, 'load("targetpkg", name="targetpkg")', None),
        (IMPORT_MODULE_FUNCTION, "load(name)", None),
        (IMPORT_MODULE_FUNCTION, "load()", None),
        (IMPORT_MODULE_FUNCTION, 'load(*["targetpkg"])', None),
        (IMPORT_MODULE_FUNCTION, 'load("targetpkg", **options)', None),
        (IMPORT_MODULE_FUNCTION, 'load(name="targetpkg", name="other")', None),
        (IMPORT_MODULE_FUNCTION, 'load(".targetpkg", package="parent")', None),
        (BUILTIN_IMPORT_FUNCTION, '__import__("targetpkg")', "targetpkg"),
        (
            BUILTIN_IMPORT_FUNCTION,
            '__import__("targetpkg", level=0)',
            "targetpkg",
        ),
        (
            BUILTIN_IMPORT_FUNCTION,
            '__import__("targetpkg", None, None, (), 0)',
            "targetpkg",
        ),
        (BUILTIN_IMPORT_FUNCTION, '__import__("targetpkg", level=1)', None),
        (
            BUILTIN_IMPORT_FUNCTION,
            '__import__("targetpkg", None, None, (), 1)',
            None,
        ),
        (BUILTIN_IMPORT_FUNCTION, '__import__("targetpkg", level=level)', None),
        (BUILTIN_IMPORT_FUNCTION, '__import__("targetpkg", **options)', None),
        ("other.importer", 'load("targetpkg")', None),
    ],
)
def test_literal_dynamic_module_requires_an_absolute_function_safe_call(
    dynamic_function: str,
    source: str,
    expected: str | None,
) -> None:
    """Dynamic imports stay literal, absolute, and signature-specific."""
    assert literal_dynamic_module(_call(source), dynamic_function) == expected


def test_import_helpers_cover_alias_star_relative_and_submodule_syntax() -> None:
    """Import extraction stays exact across supported statement forms."""
    direct_module = cst.parse_module("import targetpkg.sub as alias, targetpkg.sub\n")
    direct = cast("cst.SimpleStatementLine", direct_module.body[0]).body[0]
    assert isinstance(direct, cst.Import)
    from_module = cst.parse_module("from targetpkg import *\n")
    from_import = cast("cst.SimpleStatementLine", from_module.body[0]).body[0]
    assert isinstance(from_import, cst.ImportFrom)
    relative_module = cst.parse_module("from .targetpkg import value\n")
    relative = cast("cst.SimpleStatementLine", relative_module.body[0]).body[0]
    assert isinstance(relative, cst.ImportFrom)

    assert imported_modules(direct)[0].bound_names == ("alias", "targetpkg")
    assert imported_modules(from_import)[0].bound_names == ("*",)
    assert imported_modules(relative) == ()
    assert module_matches("targetpkg", "targetpkg.sub") is True
    assert module_matches("targetpkg", "targetpkg_extra") is False


def test_qualified_resolution_distinguishes_exact_ambiguous_and_shadowed() -> None:
    """Only multiple imports reduce confidence; local bindings suppress it."""
    target = QualifiedName("targetpkg.old", QualifiedNameSource.IMPORT)
    other = QualifiedName("replacement.old", QualifiedNameSource.IMPORT)
    local = QualifiedName("old", QualifiedNameSource.LOCAL)
    builtin = QualifiedName("builtins.__import__", QualifiedNameSource.BUILTIN)

    exact = resolve_qualified_name({target}, "targetpkg.old")
    ambiguous = resolve_qualified_name({target, other}, "targetpkg.old")
    shadowed = resolve_qualified_name({target, local}, "targetpkg.old")
    unresolved = resolve_qualified_name({other}, "targetpkg.old")
    exact_builtin = resolve_qualified_name(
        {builtin},
        "builtins.__import__",
        source=QualifiedNameSource.BUILTIN,
    )

    assert exact.confidence is MatchConfidence.HIGH
    assert ambiguous.confidence is MatchConfidence.MEDIUM
    assert shadowed.resolution == "lexically-shadowed"
    assert unresolved.resolution == "unresolved"
    assert exact_builtin.resolution == "exact-builtin"
    assert terminal_name(cst.parse_expression("factory()")) is None


def test_builtin_resolution_accepts_exact_import_aliases_but_not_competitors() -> None:
    """Built-in and imported forms share one conservative qualified-name boundary."""
    imported = QualifiedName("builtins.__import__", QualifiedNameSource.IMPORT)
    builtin = QualifiedName("builtins.__import__", QualifiedNameSource.BUILTIN)
    replacement = QualifiedName("replacement.load", QualifiedNameSource.IMPORT)
    local = QualifiedName("load", QualifiedNameSource.LOCAL)
    sources = frozenset({QualifiedNameSource.BUILTIN, QualifiedNameSource.IMPORT})

    exact_import = resolve_qualified_name_sources(
        {imported}, "builtins.__import__", sources
    )
    exact_builtin = resolve_qualified_name_sources(
        {builtin}, "builtins.__import__", sources
    )
    ambiguous = resolve_qualified_name_sources(
        {imported, replacement}, "builtins.__import__", sources
    )
    shadowed = resolve_qualified_name_sources(
        {imported, local}, "builtins.__import__", sources
    )

    assert exact_import.resolution == "exact-import"
    assert exact_builtin.resolution == "exact-builtin"
    assert ambiguous.confidence is MatchConfidence.MEDIUM
    assert shadowed.resolution == "lexically-shadowed"
