import collections


class Thing(collections.ValuesView):
    """Subclass the alias."""


def accept(value: collections.ValuesView) -> collections.ValuesView:
    """Annotate with the alias."""
    return value
