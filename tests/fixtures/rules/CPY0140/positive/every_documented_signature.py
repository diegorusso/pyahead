import asyncio


async def main(loop: asyncio.AbstractEventLoop) -> list[object]:
    return [
        asyncio.BoundedSemaphore(loop=loop),
        asyncio.Condition(loop=loop),
        asyncio.Event(loop=loop),
        asyncio.Lock(loop=loop),
        asyncio.Queue(loop=loop),
        asyncio.Semaphore(loop=loop),
        asyncio.as_completed(loop=loop),
        asyncio.create_subprocess_exec(loop=loop),
        asyncio.create_subprocess_shell(loop=loop),
        asyncio.gather(loop=loop),
        asyncio.open_connection(loop=loop),
        asyncio.open_unix_connection(loop=loop),
        asyncio.shield(loop=loop),
        asyncio.sleep(loop=loop),
        asyncio.start_server(loop=loop),
        asyncio.start_unix_server(loop=loop),
        asyncio.wait(loop=loop),
        asyncio.wait_for(loop=loop),
    ]
