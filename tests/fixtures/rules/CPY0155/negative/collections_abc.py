import collections.abc
from collections.abc import Set  # noqa: PYI025


class Thing(Set):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Set) -> collections.abc.Set:
    """Annotate with the collections.abc name."""
    return value
