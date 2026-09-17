import collections


class Thing(collections.MutableSequence):
    """Subclass the alias."""


def accept(value: collections.MutableSequence) -> collections.MutableSequence:
    """Annotate with the alias."""
    return value
