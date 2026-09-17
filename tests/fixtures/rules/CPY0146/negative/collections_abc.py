import collections.abc
from collections.abc import Hashable


class Thing(Hashable):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Hashable) -> collections.abc.Hashable:
    """Annotate with the collections.abc name."""
    return value
