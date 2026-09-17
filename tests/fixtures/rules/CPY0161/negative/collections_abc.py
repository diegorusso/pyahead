import collections.abc
from collections.abc import ItemsView


class Thing(ItemsView):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.ItemsView) -> collections.abc.ItemsView:
    """Annotate with the collections.abc name."""
    return value
