import collections


class Thing(collections.Iterator):
    """Subclass the alias."""


def accept(value: collections.Iterator) -> collections.Iterator:
    """Annotate with the alias."""
    return value
