import collections


class Thing(collections.ItemsView):
    """Subclass the alias."""


def accept(value: collections.ItemsView) -> collections.ItemsView:
    """Annotate with the alias."""
    return value
