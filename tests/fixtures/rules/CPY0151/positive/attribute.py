import collections


class Thing(collections.Sized):
    """Subclass the alias."""


def accept(value: collections.Sized) -> collections.Sized:
    """Annotate with the alias."""
    return value
