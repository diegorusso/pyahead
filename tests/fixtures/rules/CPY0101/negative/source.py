from sqlite3 import Connection, connect


def callback() -> int:
    return 0


def configure(connection: Connection) -> None:
    connect("app.db", timeout=5.0)
    Connection.set_progress_handler(connection, callback, n=100)
    Connection(":memory:").set_progress_handler(callback, n=100)
