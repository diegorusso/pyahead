import collections.abc
from collections.abc import AsyncIterator


class Thing(AsyncIterator):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.AsyncIterator) -> collections.abc.AsyncIterator:
    """Annotate with the collections.abc name."""
    return value
