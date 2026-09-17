import collections.abc
from collections.abc import Iterator


class Thing(Iterator):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Iterator) -> collections.abc.Iterator:
    """Annotate with the collections.abc name."""
    return value
