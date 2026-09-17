import collections


class Thing(collections.MutableSet):
    """Subclass the alias."""


def accept(value: collections.MutableSet) -> collections.MutableSet:
    """Annotate with the alias."""
    return value
