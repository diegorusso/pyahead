import asyncio
from collections.abc import Coroutine


def main(
    loop: asyncio.AbstractEventLoop, coro: Coroutine
) -> tuple[asyncio.Future, asyncio.Task]:
    return asyncio.Future(loop=loop), asyncio.Task(coro, loop=loop)
