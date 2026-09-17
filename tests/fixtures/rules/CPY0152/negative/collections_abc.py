import collections.abc
from collections.abc import Container


class Thing(Container):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.Container) -> collections.abc.Container:
    """Annotate with the collections.abc name."""
    return value
