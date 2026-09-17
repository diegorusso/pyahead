import collections.abc
from collections.abc import ValuesView


class Thing(ValuesView):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.ValuesView) -> collections.abc.ValuesView:
    """Annotate with the collections.abc name."""
    return value
