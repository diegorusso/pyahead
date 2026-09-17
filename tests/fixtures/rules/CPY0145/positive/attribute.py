import collections


class Thing(collections.AsyncGenerator):
    """Subclass the alias."""


def accept(value: collections.AsyncGenerator) -> collections.AsyncGenerator:
    """Annotate with the alias."""
    return value
