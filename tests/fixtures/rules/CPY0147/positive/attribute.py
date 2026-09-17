import collections


class Thing(collections.Iterable):
    """Subclass the alias."""


def accept(value: collections.Iterable) -> collections.Iterable:
    """Annotate with the alias."""
    return value
