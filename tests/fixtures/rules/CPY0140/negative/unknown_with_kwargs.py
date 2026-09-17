import asyncio


async def main(options: dict[str, object]) -> None:
    await asyncio.sleep(1, **options)
