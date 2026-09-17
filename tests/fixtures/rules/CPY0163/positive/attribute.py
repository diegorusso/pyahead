import collections


class Thing(collections.Sequence):
    """Subclass the alias."""


def accept(value: collections.Sequence) -> collections.Sequence:
    """Annotate with the alias."""
    return value
