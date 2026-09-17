import collections


class Thing(collections.KeysView):
    """Subclass the alias."""


def accept(value: collections.KeysView) -> collections.KeysView:
    """Annotate with the alias."""
    return value
