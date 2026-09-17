import collections


class Thing(collections.ByteString):
    """Subclass the alias."""


def accept(value: collections.ByteString) -> collections.ByteString:
    """Annotate with the alias."""
    return value
