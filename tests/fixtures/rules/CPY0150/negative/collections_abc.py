import collections.abc
from collections.abc import Reversible


class Thing(Reversible):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Reversible) -> collections.abc.Reversible:
    """Annotate with the collections.abc name."""
    return value
