from asyncio import coroutine
from collections.abc import Generator


@coroutine
def legacy() -> Generator[None, None, None]:
    """Yield once, as a generator-based coroutine did."""
    yield
