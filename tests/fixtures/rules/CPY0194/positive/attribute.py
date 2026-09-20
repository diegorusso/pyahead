import asyncio
from collections.abc import Generator


@asyncio.coroutine
def legacy() -> Generator[None, None, None]:
    """Yield once, as a generator-based coroutine did."""
    yield
