import random


def reorder(values: list[int], extra: tuple[object, ...]) -> None:
    """Shuffle with arguments the analyser cannot see through."""
    random.shuffle(values, *extra)
