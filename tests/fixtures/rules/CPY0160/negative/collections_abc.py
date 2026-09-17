import collections.abc
from collections.abc import KeysView


class Thing(KeysView):
    """Subclass the collections.abc name, which is the replacement."""


def accept(value: collections.abc.KeysView) -> collections.abc.KeysView:
    """Annotate with the collections.abc name."""
    return value
