import collections


class Thing(collections.MutableMapping):
    """Subclass the alias."""


def accept(value: collections.MutableMapping) -> collections.MutableMapping:
    """Annotate with the alias."""
    return value
