from sqlite3 import Connection


def callback() -> int:
    return 0


def configure(connection: Connection) -> None:
    Connection.set_progress_handler(
        connection,
        progress_handler=callback,
        n=100,
    )
    Connection(":memory:").set_progress_handler(
        progress_handler=callback,
        n=100,
    )
