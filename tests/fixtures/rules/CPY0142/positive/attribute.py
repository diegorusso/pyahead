import collections


class Thing(collections.Coroutine):
    """Subclass the alias."""


def accept(value: collections.Coroutine) -> collections.Coroutine:
    """Annotate with the alias."""
    return value
