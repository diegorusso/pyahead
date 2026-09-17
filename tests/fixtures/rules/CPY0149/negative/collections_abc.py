import collections.abc
from collections.abc import Generator


class Thing(Generator):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Generator) -> collections.abc.Generator:
    """Annotate with the collections.abc name."""
    return value
