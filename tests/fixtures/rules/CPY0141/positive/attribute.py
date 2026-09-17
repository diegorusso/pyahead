import collections


class Thing(collections.Awaitable):
    """Subclass the alias."""


def accept(value: collections.Awaitable) -> collections.Awaitable:
    """Annotate with the alias."""
    return value
