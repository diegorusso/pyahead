"""A project module that shadows the standard-library name."""


def get_ident() -> int:
    """Return a fixed identifier."""
    return 0


class Lock:
    """A lock that does nothing."""
