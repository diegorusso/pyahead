"""The dependency package's private names, for tests that pin its internals."""

import pytest

from tests._internals import PackageInternals

internals = PackageInternals("pyahead.dependencies")


def patch_dependency(
    patch: pytest.MonkeyPatch,
    name: str,
    value: object,
) -> None:
    """Replace ``name`` in every dependency submodule that binds it."""
    internals.patch(patch, name, value)
