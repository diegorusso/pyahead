import collections.abc
from collections.abc import MutableSequence


class Thing(MutableSequence):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.MutableSequence) -> collections.abc.MutableSequence:
    """Annotate with the collections.abc name."""
    return value
