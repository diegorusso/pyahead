import collections


class Thing(collections.Hashable):
    """Subclass the alias."""


def accept(value: collections.Hashable) -> collections.Hashable:
    """Annotate with the alias."""
    return value
