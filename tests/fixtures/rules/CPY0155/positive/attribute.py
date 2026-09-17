import collections


class Thing(collections.Set):
    """Subclass the alias."""


def accept(value: collections.Set) -> collections.Set:
    """Annotate with the alias."""
    return value
