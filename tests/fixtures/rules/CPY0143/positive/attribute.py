import collections


class Thing(collections.AsyncIterable):
    """Subclass the alias."""


def accept(value: collections.AsyncIterable) -> collections.AsyncIterable:
    """Annotate with the alias."""
    return value
