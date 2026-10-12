"""The dependency package's private names, for tests that pin its internals.

pyahead.dependencies is split across private submodules that import names
from one another, so a name can be bound in several of them. ``internals``
reads any of those names, and ``patch_dependency`` replaces one everywhere
it is bound, which is what patching the single module did before the split.
"""

import importlib
import pkgutil
from types import ModuleType

import pytest

import pyahead.dependencies as _package

MODULES: tuple[ModuleType, ...] = tuple(
    importlib.import_module(f"{_package.__name__}.{info.name}")
    for info in pkgutil.iter_modules(_package.__path__)
)


class _Internals:
    """Attribute access to the current value of a name in any submodule."""

    def __getattr__(self, name: str) -> object:
        for module in MODULES:
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(name)


internals = _Internals()


def patch_dependency(
    patch: pytest.MonkeyPatch,
    name: str,
    value: object,
) -> None:
    """Replace ``name`` in every dependency submodule that binds it."""
    holders = [module for module in MODULES if name in vars(module)]
    if not holders:
        raise AttributeError(name)
    for module in holders:
        patch.setattr(module, name, value)
