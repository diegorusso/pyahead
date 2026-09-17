import collections.abc
from collections.abc import Coroutine


class Thing(Coroutine):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Coroutine) -> collections.abc.Coroutine:
    """Annotate with the collections.abc name."""
    return value
