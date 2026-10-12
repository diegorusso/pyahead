"""Helpers shared by the repository's validation and release scripts."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import TextIO

# A spreadsheet evaluates a cell that starts with one of these as a formula.
SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def positive_integer(value: str) -> int:
    """Parse a command-line integer greater than zero."""
    try:
        parsed = int(value)
    except ValueError as error:
        message = "value must be an integer"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "value must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def positive_float(value: str) -> float:
    """Parse a command-line number greater than zero."""
    try:
        parsed = float(value)
    except ValueError as error:
        message = "value must be a number"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "value must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def normalized_name(name: str) -> str:
    """Normalize a distribution name as PEP 503 does."""
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_path(path: Path) -> str:
    """Hash a file in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def spreadsheet_safe(value: str) -> str:
    """Neutralize a value a spreadsheet would otherwise evaluate as a formula.

    Scanned-project text reaches the review worksheets: a file may legally be
    named `=cmd|...` and a project `-x`. The worksheet is opened in a
    spreadsheet, so such a value is quoted with a leading apostrophe rather
    than left to execute.
    """
    if value.startswith(SPREADSHEET_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def write_atomic_bytes(path: Path, content: bytes) -> None:
    """Replace ``path`` with ``content`` through a synced temporary file."""
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def write_atomic(path: Path, content: str) -> None:
    """Replace ``path`` with UTF-8 ``content``, newlines written as given."""
    write_atomic_bytes(path, content.encode("utf-8"))


def scan_environment() -> dict[str, str]:
    """Return the environment a PyAhead scan subprocess runs with.

    The interpreter's own path configuration is dropped so the scan imports
    the PyAhead installed alongside it, and no bytecode is written into the
    scanned tree.
    """
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH"):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def read_limited(stream: TextIO, limit: int, too_large: Exception) -> str:
    """Return what was written to ``stream``, raising ``too_large`` past ``limit``."""
    stream.flush()
    if stream.tell() > limit:
        raise too_large
    stream.seek(0)
    return stream.read()
