"""Import-syntax helpers for module matcher dispatch."""

from dataclasses import dataclass
from pathlib import PurePosixPath

import libcst as cst
from libcst.helpers import get_full_name_for_node


@dataclass(frozen=True)
class ImportedModule:
    """One imported module and every name bound by its statement."""

    module: str
    syntax: str
    bound_names: tuple[str, ...]


def module_matches(configured_module: str, imported_module: str) -> bool:
    """Return whether an import names a module or one of its submodules."""
    return imported_module == configured_module or imported_module.startswith(
        f"{configured_module}."
    )


def imported_modules(node: cst.Import | cst.ImportFrom) -> tuple[ImportedModule, ...]:
    """Extract deterministic module bindings from one absolute import statement."""
    bindings: dict[str, list[str]] = {}
    syntax: str
    if isinstance(node, cst.Import):
        syntax = "import"
        for alias in node.names:
            module = get_full_name_for_node(alias.name)
            if module is None:
                continue
            bound_name = (
                get_full_name_for_node(alias.asname.name)
                if alias.asname is not None
                else module.partition(".")[0]
            )
            module_bindings = bindings.setdefault(module, [])
            resolved_binding = bound_name or module
            if resolved_binding not in module_bindings:
                module_bindings.append(resolved_binding)
    else:
        if node.relative:
            return ()
        syntax = "from-import"
        module = get_full_name_for_node(node.module) if node.module else None
        if module is None:
            return ()
        if isinstance(node.names, cst.ImportStar):
            bindings[module] = ["*"]
        else:
            bindings[module] = [
                name
                for alias in node.names
                if (
                    name := get_full_name_for_node(
                        alias.asname.name if alias.asname is not None else alias.name
                    )
                )
                is not None
            ]
    return tuple(
        ImportedModule(
            module=module,
            syntax=syntax,
            bound_names=tuple(module_bindings),
        )
        for module, module_bindings in bindings.items()
    )


def competing_project_paths(
    imported_module: str,
    project_modules: dict[str, tuple[PurePosixPath, ...]],
) -> tuple[PurePosixPath, ...]:
    """Return conventional project modules that may win absolute resolution."""
    top_level = imported_module.partition(".")[0]
    candidates: set[PurePosixPath] = set(project_modules.get("*", ()))
    candidates.update(project_modules.get(top_level, ()))
    candidates.update(project_modules.get(imported_module, ()))
    return tuple(sorted(candidates, key=PurePosixPath.as_posix))
