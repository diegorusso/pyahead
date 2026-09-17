import collections.abc
from collections.abc import Awaitable


class Thing(Awaitable):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Awaitable) -> collections.abc.Awaitable:
    """Annotate with the collections.abc name."""
    return value
