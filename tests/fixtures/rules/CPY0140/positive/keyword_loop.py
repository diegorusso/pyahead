import asyncio


async def main(loop: asyncio.AbstractEventLoop) -> asyncio.Queue:
    await asyncio.sleep(1, loop=loop)
    return asyncio.Queue(loop=loop)
