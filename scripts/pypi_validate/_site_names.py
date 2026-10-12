"""How a finding's site spells its name, and the import that binds it, from source.

The probe looks a finding's name up at runtime, in the module's globals or
the enclosing callable's, and cannot see three kinds of binding:

- an alias: after `import typing as t` the site says `t.AnyStr`, and the
  module has no global `typing` to start the canonical name from;
- a function-local import: `import asyncio` inside a function binds a local
  the probe cannot read without calling the function;
- an import that never runs: `from typing import Text` under
  `if TYPE_CHECKING:` binds nothing at runtime, though every annotation that
  says `Text` means `typing.Text`.

The harness has the installed source. For a reference it reads the site's
own spelling; for a name that a scope binds exactly once, by an import, it
records that import so the probe can run it and walk the same attributes.
A name bound more than once, by anything else, or by a relative or star
import gets no source binding and stays as visible as it was.

A module-import finding inside a function is its own binding. Its source
binding is recorded only where nothing in the source decides whether it
runs on a given Python: no enclosing or preceding test that mentions a
version, `TYPE_CHECKING` or a constant, and no earlier statement in an
enclosing `try` body that might fail first (the `unicode = unicode` shape).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from scripts.pypi_validate._import_sites import ImportSite

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, ast.Module)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_DECIDING_TEST = re.compile(
    r"version|py_?\d|TYPE_CHECKING|^(?:False|0|None)$", re.IGNORECASE
)
_QUALIFIED_KINDS = frozenset({"qualified-reference", "call-shape"})


@dataclass(frozen=True)
class SourceBinding:
    """The one import statement that binds a name: run it to get the object.

    `import a.b` imports `a.b` and binds `a`; `import a.b as h` binds `a.b`;
    `from a.b import c` binds attribute `c` of `a.b`.
    """

    imports: str
    binds: str
    attribute: str | None

    def as_probe(self) -> dict[str, Any]:
        """Return the probe payload's `source_binding` field."""
        return {
            "imports": self.imports,
            "binds": self.binds,
            "attribute": self.attribute,
        }


@dataclass(frozen=True)
class SiteName:
    """The site's own spelling of a reference, and how its head is bound."""

    head: str
    attribute_path: tuple[str, ...]
    source_binding: SourceBinding | None


def _parents(tree: ast.AST) -> dict[int, ast.AST]:
    return {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _dotted(node: ast.AST) -> tuple[str, ...] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return (node.id, *reversed(parts))


def _site_node(
    tree: ast.AST, line: int, column: int, last: str
) -> tuple[ast.AST, tuple[str, ...]] | None:
    """Find the longest `name.attr...` at the location that ends in `last`."""
    best: tuple[ast.AST, tuple[str, ...]] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        if node.lineno != line or node.col_offset != column:
            continue
        spelling = _dotted(node)
        if spelling is None or spelling[-1] != last:
            continue
        if best is None or len(spelling) > len(best[1]):
            best = (node, spelling)
    return best


def _scope_of(node: ast.AST, parents: dict[int, ast.AST]) -> ast.AST:
    """Return the scope a name at `node` is looked up in first.

    Decorators, defaults, annotations and base classes are evaluated in the
    scope around the `def` or `class`, not inside it.
    """
    child, current = node, parents[id(node)]
    while True:
        if isinstance(current, ast.Module):
            return current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if child in current.body:
                return current
        elif isinstance(current, ast.Lambda):
            if child is current.body:
                return current
        elif isinstance(current, _COMPREHENSIONS):
            return current
        child, current = current, parents[id(current)]


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Every node evaluated in `scope` itself, not in a nested scope."""
    if isinstance(scope, _FUNCTIONS):
        pending: list[ast.AST] = (
            [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
        )
    elif isinstance(scope, (ast.ClassDef, ast.Module)):
        pending = list(scope.body)
    else:
        pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Its name binds here; its decorators, defaults, annotations and
            # bases are evaluated here; its body is its own scope.
            pending.extend(node.decorator_list)
            if isinstance(node, ast.ClassDef):
                pending.extend(node.bases)
                pending.extend(keyword.value for keyword in node.keywords)
            else:
                pending.extend(_argument_expressions(node.args))
                if node.returns is not None:
                    pending.append(node.returns)
        elif isinstance(node, ast.Lambda):
            pending.extend(_argument_expressions(node.args))
        elif not isinstance(node, _COMPREHENSIONS):
            pending.extend(ast.iter_child_nodes(node))


def _argument_expressions(arguments: ast.arguments) -> Iterator[ast.AST]:
    yield from arguments.defaults
    yield from (default for default in arguments.kw_defaults if default is not None)
    for argument in _arguments(arguments):
        if argument.annotation is not None:
            yield argument.annotation


def _arguments(arguments: ast.arguments) -> Iterator[ast.arg]:
    yield from arguments.posonlyargs
    yield from arguments.args
    if arguments.vararg is not None:
        yield arguments.vararg
    yield from arguments.kwonlyargs
    if arguments.kwarg is not None:
        yield arguments.kwarg


@dataclass(frozen=True)
class _Bindings:
    nodes: tuple[ast.AST, ...]
    declared_global: bool
    declared_nonlocal: bool
    star_import: bool


def _bound_names(node: ast.AST) -> Iterator[str]:
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        for alias in node.names:
            if alias.name != "*":
                yield (alias.asname or alias.name).split(".")[0]
        return
    name: str | None = None
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        name = node.name
    elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        name = node.id
    elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
        name = node.name
    elif isinstance(node, ast.MatchMapping):
        name = node.rest
    if name is not None:
        yield name


def _bindings(scope: ast.AST, name: str) -> _Bindings:
    nodes: list[ast.AST] = []
    declared_global = declared_nonlocal = star_import = False
    if isinstance(scope, _FUNCTIONS):
        nodes.extend(arg for arg in _arguments(scope.args) if arg.arg == name)
    for node in _own_nodes(scope):
        if isinstance(node, ast.Global) and name in node.names:
            declared_global = True
        elif isinstance(node, ast.Nonlocal) and name in node.names:
            declared_nonlocal = True
        elif isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            star_import = True
        if name in _bound_names(node):
            nodes.append(node)
    return _Bindings(tuple(nodes), declared_global, declared_nonlocal, star_import)


def _import_binding(node: ast.AST, name: str) -> SourceBinding | None:
    if isinstance(node, ast.Import):
        alias = next(
            a for a in node.names if (a.asname or a.name).split(".")[0] == name
        )
        binds = alias.name if alias.asname else alias.name.split(".")[0]
        return SourceBinding(alias.name, binds, None)
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        alias = next(a for a in node.names if (a.asname or a.name) == name)
        return SourceBinding(node.module, node.module, alias.name)
    return None


def _source_binding(
    node: ast.AST, name: str, parents: dict[int, ast.AST], module: ast.Module
) -> SourceBinding | None:
    """Return the import binding `name` where `node` reads it, if it is the only one.

    Follows Python's lookup: the node's own scope, then enclosing function
    scopes (class bodies are skipped), then the module, honouring `global`
    and `nonlocal`.
    """
    scope = _scope_of(node, parents)
    innermost = True
    while True:
        if not innermost and isinstance(scope, ast.ClassDef):
            scope = _scope_of(scope, parents)
            continue
        bindings = _bindings(scope, name)
        if bindings.declared_global:
            bindings, scope = _bindings(module, name), module
        if bindings.nodes and not bindings.declared_nonlocal:
            if len(bindings.nodes) != 1 or bindings.star_import:
                return None
            return _import_binding(bindings.nodes[0], name)
        if isinstance(scope, ast.Module):
            return None
        scope = _scope_of(scope, parents)
        innermost = False


def site_name(
    source: str, line: int, column: int, qualified_name: str
) -> SiteName | None:
    """Read the reference to `qualified_name` at `line`/`column` (1-based)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    assert isinstance(tree, ast.Module)  # noqa: S101 - ast.parse's default mode.
    found = _site_node(
        tree, line, column - 1, qualified_name.rsplit(".", maxsplit=1)[-1]
    )
    if found is None:
        return None
    node, spelling = found
    parents = _parents(tree)
    head = node
    while isinstance(head, ast.Attribute):
        head = head.value
    return SiteName(
        spelling[0], spelling[1:], _source_binding(head, spelling[0], parents, tree)
    )


def _position(siblings: object, node: ast.AST) -> int | None:
    if not isinstance(siblings, list):
        return None
    return next((i for i, sibling in enumerate(siblings) if sibling is node), None)


def _deciding(test: ast.expr) -> bool:
    return _DECIDING_TEST.search(ast.unparse(test)) is not None


def _exits_early(statement: ast.If) -> bool:
    """Whether a deciding `if` can leave the block before what follows it."""
    pending: list[ast.AST] = [*statement.body, *statement.orelse]
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if not isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))
    return False


def _decided_by_source(statement: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Whether the source decides if `statement` runs on a given Python.

    True inside a test that mentions a version, `TYPE_CHECKING` or a
    constant; after such a test in the same block that can leave it (an
    early `return`);
    in an `except` or `try`-`else` block, which run only after the `try`
    body failed or succeeded; and after any earlier statement of a `try`
    body, which might fail first.
    """
    child: ast.AST = statement
    while True:
        current = parents[id(child)]
        if isinstance(current, ast.If) and _deciding(current.test):
            return True
        if isinstance(current, ast.ExceptHandler):
            return True
        if isinstance(current, (ast.Try, ast.TryStar)) and (
            _position(current.orelse, child) is not None
            or (_position(current.body, child) or 0) > 0
        ):
            return True
        for field in ("body", "orelse", "finalbody"):
            siblings = getattr(current, field, None)
            index = _position(siblings, child)
            if index is not None and any(
                isinstance(earlier, ast.If)
                and _deciding(earlier.test)
                and _exits_early(earlier)
                for earlier in getattr(current, field)[:index]
            ):
                return True
        if isinstance(current, ast.Module):
            return False
        child = current


def statement_binding(
    source: str, line: int, column: int, bound_name: str
) -> SourceBinding | None:
    """Return the source binding of a function-local import at `line`/`column`."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return None
    assert isinstance(tree, ast.Module)  # noqa: S101 - ast.parse's default mode.
    statement = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            and node.lineno == line
            and node.col_offset == column - 1
            and bound_name in _bound_names(node)
        ),
        None,
    )
    if statement is None:
        return None
    parents = _parents(tree)
    scope = _scope_of(statement, parents)
    if isinstance(scope, ast.Module) or _decided_by_source(statement, parents):
        return None
    bindings = _bindings(scope, bound_name)
    if bindings.nodes != (statement,) or bindings.declared_global:
        return None
    return _import_binding(statement, bound_name)


def _location(finding: dict[str, Any]) -> tuple[str, int, int] | None:
    location = finding.get("location")
    if not isinstance(location, dict):
        return None
    path = location.get("path")
    region = location.get("region")
    start = region.get("start") if isinstance(region, dict) else None
    if not isinstance(path, str) or not isinstance(start, dict):
        return None
    line, column = start.get("line"), start.get("column")
    if not isinstance(line, int) or not isinstance(column, int):
        return None
    return path, line, column


def _probed_name(evidence: dict[str, Any], site: ImportSite | None) -> str | None:
    if site is not None:
        return site.bound_name
    bound_names = evidence.get("bound_names")
    if (
        isinstance(bound_names, list)
        and bound_names
        and isinstance(bound_names[0], str)
    ):
        return bound_names[0]
    return None


def site_names(
    findings: list[dict[str, Any]], root: Path, import_sites: dict[str, ImportSite]
) -> tuple[dict[str, SiteName], dict[str, SourceBinding]]:
    """Read every reference's spelling and every local import's binding.

    A module-import finding's binding probe uses the name `import_sites`
    chose for it, else the first name it binds. Returns the references'
    site names and the module-import findings' source bindings, both by
    fingerprint.
    """
    sources: dict[str, str | None] = {}
    names: dict[str, SiteName] = {}
    statements: dict[str, SourceBinding] = {}
    for finding in findings:
        match = finding.get("match")
        evidence = match.get("evidence") if isinstance(match, dict) else None
        place = _location(finding)
        if not isinstance(match, dict) or not isinstance(evidence, dict) or not place:
            continue
        path, line, column = place
        if path not in sources:
            try:
                sources[path] = (root / path).read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                sources[path] = None
        source = sources[path]
        if source is None:
            continue
        fingerprint = finding["fingerprint"]
        qualified_names = evidence.get("qualified_names")
        if (
            match.get("kind") in _QUALIFIED_KINDS
            and isinstance(qualified_names, list)
            and qualified_names
            and isinstance(qualified_names[0], str)
        ):
            name = site_name(source, line, column, qualified_names[0])
            if name is not None:
                names[fingerprint] = name
        elif match.get("kind") == "module-import":
            bound_name = _probed_name(evidence, import_sites.get(fingerprint))
            binding = (
                statement_binding(source, line, column, bound_name)
                if bound_name is not None
                else None
            )
            if binding is not None:
                statements[fingerprint] = binding
    return names, statements
