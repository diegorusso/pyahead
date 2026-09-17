import collections


class Thing(collections.Reversible):
    """Subclass the alias."""


def accept(value: collections.Reversible) -> collections.Reversible:
    """Annotate with the alias."""
    return value
