import collections.abc
from collections.abc import Iterable


class Thing(Iterable):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Iterable) -> collections.abc.Iterable:
    """Annotate with the collections.abc name."""
    return value
