import collections.abc
from collections.abc import Collection


class Thing(Collection):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Collection) -> collections.abc.Collection:
    """Annotate with the collections.abc name."""
    return value
