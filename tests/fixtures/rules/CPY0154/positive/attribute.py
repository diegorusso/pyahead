import collections


class Thing(collections.Collection):
    """Subclass the alias."""


def accept(value: collections.Collection) -> collections.Collection:
    """Annotate with the alias."""
    return value
