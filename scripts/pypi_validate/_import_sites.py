"""What a module-import finding's statement actually binds, read from source.

A finding's static evidence records only the names a `from A import ...`
binds, which is not enough to probe it soundly:

- `from A import B as C` records `C`; the attribute to compare against is
  `A.B`, and `A.C` may well exist and be something else (`crypt` imports its
  C helper as `crypt._crypt`).
- `from A import B, C` followed by `def B(): ...` leaves `B` bound to the
  local function; `C` still shows whether the import ran.
- An import under `if os.name == "nt":` does not run on the probe's Linux
  host, so a mismatch there says nothing about Windows, where it does.
- An import inside `try: ... except ImportError:` does run where its module
  is gone, fails as the finding predicts, and leaves the fallback's value
  bound; that is the finding coming true, not a version-gated branch that
  never ran.

The harness has the installed source, so it reads the statement at the
finding's location and records the first binding the module does not
rebind, and whether a platform condition encloses it.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

_PLATFORM_TEST = re.compile(
    r"\b(?:os\.name|sys\.platform|platform\.system\(\)|platform\.platform\(\))"
)
_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_IMPORT_FAILURES = frozenset(
    {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
)


def _catches_import_failure(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    names = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(
        isinstance(name, ast.Name) and name.id in _IMPORT_FAILURES for name in names
    )


@dataclass(frozen=True)
class ImportSite:
    """The binding to probe for one `from A import ...` finding."""

    attribute: str
    bound_name: str
    platform_conditional: bool
    import_error_fallback: bool = False


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    return {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _import_at(tree: ast.AST, line: int, column: int) -> ast.ImportFrom | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.lineno == line
            and node.col_offset == column
        ):
            return node
    return None


def _target_names(target: ast.AST) -> Iterator[str]:
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            yield node.id


def _own_statements(scope: ast.AST) -> Iterator[ast.AST]:
    """Every node in ``scope`` that is not inside a nested function or class."""
    pending: list[ast.AST] = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, _SCOPES):
            pending.extend(ast.iter_child_nodes(node))


def _names_bound_elsewhere(scope: ast.AST, statement: ast.ImportFrom) -> set[str]:
    bound: set[str] = set()
    for node in _own_statements(scope):
        if node is statement:
            continue
        if isinstance(node, _SCOPES[1:]):
            bound.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update(
                (alias.asname or alias.name).split(".")[0] for alias in node.names
            )
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets: Iterable[ast.AST] = (
                node.targets if isinstance(node, ast.Assign) else (node.target,)
            )
            for target in targets:
                bound.update(_target_names(target))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)):
            items = (
                [node.target]
                if isinstance(node, (ast.For, ast.AsyncFor))
                else [item.optional_vars for item in node.items if item.optional_vars]
            )
            for target in items:
                bound.update(_target_names(target))
    return bound


def import_site(source: str, line: int, column: int) -> ImportSite | None:
    """Read the `from A import ...` statement at ``line``/``column`` (1-based)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    statement = _import_at(tree, line, column - 1)
    if statement is None:
        return None
    pairs = [
        (alias.name, alias.asname or alias.name)
        for alias in statement.names
        if alias.name != "*"
    ]
    if not pairs:
        return None
    parents = _parents(tree)
    scope: ast.AST = statement
    child: ast.AST = statement
    platform_conditional = False
    import_error_fallback = False
    while not isinstance(scope, _SCOPES):
        child, scope = scope, parents[id(scope)]
        if isinstance(scope, ast.If) and _PLATFORM_TEST.search(ast.unparse(scope.test)):
            platform_conditional = True
        if (
            isinstance(scope, ast.Try)
            and child in scope.body
            and any(_catches_import_failure(handler) for handler in scope.handlers)
        ):
            import_error_fallback = True
    rebound = _names_bound_elsewhere(scope, statement)
    attribute, bound_name = next(
        (pair for pair in pairs if pair[1] not in rebound), pairs[0]
    )
    return ImportSite(
        attribute,
        bound_name,
        platform_conditional=platform_conditional,
        import_error_fallback=import_error_fallback,
    )


def import_sites(findings: list[dict[str, Any]], root: Path) -> dict[str, ImportSite]:
    """Map each from-import finding's fingerprint to the binding to probe."""
    sources: dict[str, str | None] = {}
    sites: dict[str, ImportSite] = {}
    for finding in findings:
        match = finding.get("match")
        evidence = match.get("evidence") if isinstance(match, dict) else None
        location = finding.get("location")
        if (
            not isinstance(match, dict)
            or match.get("kind") != "module-import"
            or not isinstance(evidence, dict)
            or evidence.get("syntax") != "from-import"
            or not isinstance(location, dict)
        ):
            continue
        path = location.get("path")
        start = location.get("region", {}).get("start", {})
        if not isinstance(path, str) or not isinstance(start, dict):
            continue
        if path not in sources:
            try:
                sources[path] = (root / path).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                sources[path] = None
        source = sources[path]
        line, column = start.get("line"), start.get("column")
        if source is None or not isinstance(line, int) or not isinstance(column, int):
            continue
        site = import_site(source, line, column)
        if site is not None:
            sites[finding["fingerprint"]] = site
    return sites
