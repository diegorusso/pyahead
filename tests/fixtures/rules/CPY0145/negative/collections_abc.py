import collections.abc
from collections.abc import AsyncGenerator


class Thing(AsyncGenerator):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.AsyncGenerator) -> collections.abc.AsyncGenerator:
    """Annotate with the collections.abc name."""
    return value
