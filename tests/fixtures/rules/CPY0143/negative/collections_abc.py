import collections.abc
from collections.abc import AsyncIterable


class Thing(AsyncIterable):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.AsyncIterable) -> collections.abc.AsyncIterable:
    """Annotate with the collections.abc name."""
    return value
