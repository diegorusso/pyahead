import asyncio


async def main() -> asyncio.Queue:
    await asyncio.sleep(1)
    return asyncio.Queue(maxsize=10)
