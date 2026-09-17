import collections.abc
from collections.abc import Sequence


class Thing(Sequence):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Sequence) -> collections.abc.Sequence:
    """Annotate with the collections.abc name."""
    return value
