import asyncio


async def modern() -> None:
    """Await once, as a native coroutine."""
    await asyncio.sleep(0)
