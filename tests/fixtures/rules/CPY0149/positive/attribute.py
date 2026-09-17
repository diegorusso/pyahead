import collections


class Thing(collections.Generator):
    """Subclass the alias."""


def accept(value: collections.Generator) -> collections.Generator:
    """Annotate with the alias."""
    return value
