class TruthLike:
    """A local object with inversion behavior."""

    def __invert__(self) -> bool:
        """Return a local inversion result."""
        return True


value = ~TruthLike()
