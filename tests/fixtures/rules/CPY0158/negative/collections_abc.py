import collections.abc
from collections.abc import MutableMapping


class Thing(MutableMapping):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.MutableMapping) -> collections.abc.MutableMapping:
    """Annotate with the collections.abc name."""
    return value
