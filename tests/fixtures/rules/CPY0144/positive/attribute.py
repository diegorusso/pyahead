import collections


class Thing(collections.AsyncIterator):
    """Subclass the alias."""


def accept(value: collections.AsyncIterator) -> collections.AsyncIterator:
    """Annotate with the alias."""
    return value
