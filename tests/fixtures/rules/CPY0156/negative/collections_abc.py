import collections.abc
from collections.abc import MutableSet


class Thing(MutableSet):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.MutableSet) -> collections.abc.MutableSet:
    """Annotate with the collections.abc name."""
    return value
