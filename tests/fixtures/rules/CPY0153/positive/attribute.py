import collections


class Thing(collections.Callable):
    """Subclass the alias."""


def accept(value: collections.Callable) -> collections.Callable:
    """Annotate with the alias."""
    return value
