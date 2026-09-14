"""Example source for the worked scan."""

import ssl
from typing import ByteString


def secure(sock, hostname: str):
    # Removed in 3.12.
    return ssl.wrap_socket(sock, server_hostname=hostname)


def framed(payload: ByteString) -> int:
    # typing.ByteString is deprecated.
    return len(payload)
