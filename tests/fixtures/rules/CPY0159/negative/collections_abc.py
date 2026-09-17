import collections.abc
from collections.abc import MappingView


class Thing(MappingView):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.MappingView) -> collections.abc.MappingView:
    """Annotate with the collections.abc name."""
    return value
