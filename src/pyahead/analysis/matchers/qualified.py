"""Exact qualified-name resolution and reference-context classification."""

from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import PurePosixPath

import libcst as cst
from libcst.metadata import QualifiedName, QualifiedNameSource

from pyahead.model import MatchConfidence, ReferenceContext


@dataclass(frozen=True)
class QualifiedResolution:
    """A conservative interpretation of LibCST qualified-name metadata."""

    confidence: MatchConfidence | None
    qualified_names: tuple[str, ...]
    resolution: str


def terminal_name(node: cst.BaseExpression) -> str | None:
    """Return the lookup terminal for a simple name or attribute chain."""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return node.attr.value
    return None


def resolve_qualified_name(
    names: Collection[QualifiedName],
    expected: str,
    *,
    source: QualifiedNameSource = QualifiedNameSource.IMPORT,
) -> QualifiedResolution:
    """Resolve one expected name without treating lexical shadowing as ambiguity."""
    return resolve_qualified_name_sources(names, expected, frozenset({source}))


def resolve_qualified_name_sources(
    names: Collection[QualifiedName],
    expected: str,
    sources: frozenset[QualifiedNameSource],
) -> QualifiedResolution:
    """Resolve an expected name admitted from one or more exact origins."""
    ordered_names = tuple(sorted({name.name for name in names}))
    expected_names = {name.name for name in names if name.source in sources}
    if expected not in expected_names:
        return QualifiedResolution(None, ordered_names, "unresolved")
    if any(name.source not in sources for name in names):
        return QualifiedResolution(None, ordered_names, "lexically-shadowed")
    if expected_names == {expected}:
        matching_sources = {
            name.source
            for name in names
            if name.name == expected and name.source in sources
        }
        if matching_sources == {QualifiedNameSource.BUILTIN}:
            resolution = "exact-builtin"
        elif matching_sources == {QualifiedNameSource.IMPORT}:
            resolution = "exact-import"
        else:
            resolution = "exact-import-or-builtin"
        return QualifiedResolution(
            MatchConfidence.HIGH,
            ordered_names,
            resolution,
        )
    return QualifiedResolution(
        MatchConfidence.MEDIUM,
        ordered_names,
        "ambiguous-import",
    )


def qualified_project_candidates(
    qualified_name: str,
    project_modules: dict[str, tuple[PurePosixPath, ...]],
) -> tuple[PurePosixPath, ...]:
    """Return project paths that can shadow a qualified name's leading import."""
    top_level = qualified_name.partition(".")[0]
    candidates = {
        *project_modules.get("*", ()),
        *project_modules.get(top_level, ()),
    }
    return tuple(sorted(candidates, key=PurePosixPath.as_posix))


def classify_reference_context(
    node: cst.BaseExpression,
    parent_for: Callable[[cst.CSTNode], cst.CSTNode | None],
) -> ReferenceContext:
    """Classify the supported syntactic context surrounding a reference."""
    current: cst.CSTNode = node
    while (parent := parent_for(current)) is not None:
        if isinstance(parent, cst.Annotation):
            return ReferenceContext.ANNOTATION
        if isinstance(parent, cst.Decorator):
            return ReferenceContext.DECORATOR
        if isinstance(parent, cst.Arg):
            grandparent = parent_for(parent)
            if isinstance(grandparent, cst.ClassDef) and any(
                base is parent for base in grandparent.bases
            ):
                return ReferenceContext.BASE_CLASS
        if isinstance(parent, cst.BaseStatement):
            break
        current = parent
    return ReferenceContext.READ
