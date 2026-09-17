import collections


class Thing(collections.Mapping):
    """Subclass the alias."""


def accept(value: collections.Mapping) -> collections.Mapping:
    """Annotate with the alias."""
    return value
