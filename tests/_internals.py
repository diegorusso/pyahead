"""A split package's private names, for tests that pin its internals.

A package split into private submodules binds a name wherever it is used,
so a test that reads or replaces one needs to see all of those modules.
``PackageInternals`` reads a name from whichever submodule binds it
(the package itself first), and ``patch`` replaces it everywhere it is
bound, which is what patching the single module did before the split.
"""

import importlib
import pkgutil
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


class PackageInternals:
    """Attribute access to the current value of a name in a package."""

    def __init__(self, package: str) -> None:
        """Import ``package`` and every submodule it contains."""
        root = importlib.import_module(package)
        self._modules: tuple[ModuleType, ...] = (
            root,
            *(
                importlib.import_module(f"{package}.{info.name}")
                for info in pkgutil.iter_modules(root.__path__)
                if info.name != "__main__"
            ),
        )

    def __getattr__(self, name: str) -> object:
        for module in self._modules:
            if name in vars(module):
                return vars(module)[name]
        raise AttributeError(name)

    def patch(self, monkeypatch: pytest.MonkeyPatch, name: str, value: object) -> None:
        """Replace ``name`` in every module of the package that binds it."""
        holders = [module for module in self._modules if name in vars(module)]
        if not holders:
            raise AttributeError(name)
        for module in holders:
            monkeypatch.setattr(module, name, value)
