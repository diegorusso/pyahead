import collections.abc
from collections.abc import Sized


class Thing(Sized):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Sized) -> collections.abc.Sized:
    """Annotate with the collections.abc name."""
    return value
