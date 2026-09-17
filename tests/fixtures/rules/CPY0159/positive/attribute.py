import collections


class Thing(collections.MappingView):
    """Subclass the alias."""


def accept(value: collections.MappingView) -> collections.MappingView:
    """Annotate with the alias."""
    return value
