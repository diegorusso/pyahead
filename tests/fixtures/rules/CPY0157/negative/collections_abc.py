import collections.abc
from collections.abc import Mapping


class Thing(Mapping):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Mapping) -> collections.abc.Mapping:
    """Annotate with the collections.abc name."""
    return value
