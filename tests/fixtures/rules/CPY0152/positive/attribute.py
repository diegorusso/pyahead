import collections


class Thing(collections.Container):
    """Subclass the alias."""


def accept(value: collections.Container) -> collections.Container:
    """Annotate with the alias."""
    return value
