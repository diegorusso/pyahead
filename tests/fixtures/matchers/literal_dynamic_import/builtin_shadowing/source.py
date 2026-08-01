from builtins import __import__ as load_module
from collections.abc import Callable


def wrapper(load_module: Callable[..., object]) -> None:  # noqa: F811
    load_module("targetpkg", level=0)
