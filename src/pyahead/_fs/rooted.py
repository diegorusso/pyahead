"""Private root-anchored, bounded repository file input."""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import NoReturn

from pyahead._fs.chain import ChainFailure, DirectoryChain, open_directory_chain
from pyahead._fs.errors import (
    EntryChangedError,
    NotAFilePathError,
    NotRealDirectoryError,
    NotRegularFileError,
)
from pyahead._fs.windows import read_windows_rooted_file

_READ_CHUNK_BYTES = 64 * 1024


class RootedReadTooLargeError(OSError):
    """Raised after a rooted input exceeds its configured byte limit."""


def repository_relative_path(root: Path, path: Path) -> Path:
    """Return a lexical repository-relative path without following input links."""
    absolute_root = Path(os.path.abspath(root))  # noqa: PTH100
    selected = path if path.is_absolute() else absolute_root / path
    absolute_selected = Path(os.path.abspath(selected))  # noqa: PTH100
    try:
        relative = absolute_selected.relative_to(absolute_root)
    except ValueError as error:
        message = "input must remain beneath the trusted root"
        raise ValueError(message) from error
    if relative == Path() or not relative.name or ".." in relative.parts:
        message = "input must name a file beneath the trusted root"
        raise NotAFilePathError(message)
    return relative


def supports_rooted_descriptor_reads() -> bool:
    """Return whether POSIX directory-relative, no-follow input is available."""
    return bool(
        os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _file_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare identity and mutation-sensitive regular-file attributes."""
    return os.path.samestat(left, right) and all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


_OPEN_FAILURES: dict[ChainFailure, tuple[type[OSError], str]] = {
    "root-changed": (EntryChangedError, "input root changed while being opened"),
    "parent-not-directory": (
        NotRealDirectoryError,
        "input parents must be real directories",
    ),
    "parent-changed": (EntryChangedError, "input parent changed while being opened"),
}


def _fail_open(reason: ChainFailure) -> NoReturn:
    error, message = _OPEN_FAILURES[reason]
    raise error(message)


def _validate_read(
    chain: DirectoryChain,
    leaf_name: str,
    leaf_status: os.stat_result,
    leaf_descriptor: int,
) -> None:
    """Reject path bindings or file content changed during the read."""
    changed = chain.changed_binding()
    if changed == 0:
        message = "input root changed while being read"
        raise EntryChangedError(message)
    if changed is not None:
        message = "input parent changed while being read"
        raise EntryChangedError(message)
    current_leaf = os.stat(
        leaf_name,
        dir_fd=chain.parent_descriptor,
        follow_symlinks=False,
    )
    opened_leaf = os.fstat(leaf_descriptor)
    if not stat.S_ISREG(current_leaf.st_mode) or not (
        _same_stable_file(current_leaf, leaf_status)
        and _same_stable_file(opened_leaf, leaf_status)
    ):
        message = "input file changed while being read"
        raise EntryChangedError(message)


def _read_validated_leaf(
    chain: DirectoryChain,
    leaf_name: str,
    leaf_status: os.stat_result,
    descriptor: int,
    limit: int,
) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(
            descriptor,
            min(_READ_CHUNK_BYTES, limit + 1 - len(data)),
        )
        if not chunk:
            break
        data.extend(chunk)
    oversized = len(data) > limit
    try:
        _validate_read(chain, leaf_name, leaf_status, descriptor)
    except OSError:
        if not oversized:
            raise
    if oversized:
        message = f"input exceeds the {limit}-byte limit"
        raise RootedReadTooLargeError(message)
    return bytes(data)


def _read_posix_rooted_file(root: Path, relative: Path, limit: int) -> bytes:
    if not supports_rooted_descriptor_reads():
        message = "secure root-bounded input APIs are unavailable"
        raise OSError(message)
    chain = open_directory_chain(root, relative.parent.parts, _fail_open)
    with ExitStack() as cleanup:
        cleanup.callback(chain.close)
        expected_leaf = os.stat(
            relative.name,
            dir_fd=chain.parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(expected_leaf.st_mode):
            message = "input must be a real regular file"
            raise NotRegularFileError(message)
        descriptor = os.open(
            relative.name,
            _file_flags(),
            dir_fd=chain.parent_descriptor,
        )
        cleanup.callback(os.close, descriptor)
        opened_leaf = os.fstat(descriptor)
        if not stat.S_ISREG(opened_leaf.st_mode) or not os.path.samestat(
            expected_leaf, opened_leaf
        ):
            message = "input file changed while being opened"
            raise EntryChangedError(message)
        return _read_validated_leaf(
            chain, relative.name, opened_leaf, descriptor, limit
        )


def read_rooted_bytes(root: Path, path: Path, limit: int) -> bytes:
    """Read an unchanged regular repository file, returning at most ``limit`` bytes."""
    if type(limit) is not int or limit < 0:
        message = "input byte limit must be a non-negative integer"
        raise ValueError(message)
    absolute_root = Path(os.path.abspath(root))  # noqa: PTH100
    relative = repository_relative_path(absolute_root, path)
    if os.name == "nt" and any(":" in part for part in relative.parts):
        message = "Windows input paths cannot name alternate data streams"
        raise OSError(message)
    if supports_rooted_descriptor_reads():
        return _read_posix_rooted_file(absolute_root, relative, limit)
    if os.name == "nt":
        raw = read_windows_rooted_file(absolute_root, relative, limit)
        if len(raw) > limit:
            message = f"input exceeds the {limit}-byte limit"
            raise RootedReadTooLargeError(message)
        return raw
    message = "secure root-bounded input APIs are unavailable"
    raise OSError(message)


__all__ = [
    "RootedReadTooLargeError",
    "read_rooted_bytes",
    "repository_relative_path",
    "supports_rooted_descriptor_reads",
]
