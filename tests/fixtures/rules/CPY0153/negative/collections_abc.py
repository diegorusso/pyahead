import collections.abc
from collections.abc import Callable


class Thing(Callable):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Callable) -> collections.abc.Callable:
    """Annotate with the collections.abc name."""
    return value
