"""Private root-anchored, bounded repository file input."""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from pyahead._windows_output import read_windows_rooted_file

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
        raise ValueError(message)
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


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right)


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare identity and mutation-sensitive regular-file attributes."""
    return _same_file(left, right) and all(
        getattr(left, field) == getattr(right, field)
        for field in ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


@dataclass(frozen=True)
class _RootedReadChain:
    root: Path
    descriptors: tuple[int, ...]
    statuses: tuple[os.stat_result, ...]
    names: tuple[str, ...]

    def validate(
        self,
        leaf_name: str,
        leaf_status: os.stat_result,
        leaf_descriptor: int,
    ) -> None:
        """Reject path bindings or file content changed during the read."""
        current_root = self.root.lstat()
        opened_root = os.fstat(self.descriptors[0])
        if not stat.S_ISDIR(current_root.st_mode) or not (
            _same_file(current_root, self.statuses[0])
            and _same_file(opened_root, self.statuses[0])
        ):
            message = "input root changed while being read"
            raise OSError(message)
        for index, name in enumerate(self.names, start=1):
            current = os.stat(
                name,
                dir_fd=self.descriptors[index - 1],
                follow_symlinks=False,
            )
            opened = os.fstat(self.descriptors[index])
            if not stat.S_ISDIR(current.st_mode) or not (
                _same_file(current, self.statuses[index])
                and _same_file(opened, self.statuses[index])
            ):
                message = "input parent changed while being read"
                raise OSError(message)
        current_leaf = os.stat(
            leaf_name,
            dir_fd=self.descriptors[-1],
            follow_symlinks=False,
        )
        opened_leaf = os.fstat(leaf_descriptor)
        if not stat.S_ISREG(current_leaf.st_mode) or not (
            _same_stable_file(current_leaf, leaf_status)
            and _same_stable_file(opened_leaf, leaf_status)
        ):
            message = "input file changed while being read"
            raise OSError(message)


def _open_relative_directory(
    name: str,
    parent_descriptor: int,
) -> tuple[int, os.stat_result]:
    expected = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISDIR(expected.st_mode):
        message = "input parents must be real directories"
        raise OSError(message)
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        opened = os.fstat(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    if not stat.S_ISDIR(opened.st_mode) or not _same_file(expected, opened):
        os.close(descriptor)
        message = "input parent changed while being opened"
        raise OSError(message)
    return descriptor, opened


def _read_validated_leaf(
    chain: _RootedReadChain,
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
        chain.validate(leaf_name, leaf_status, descriptor)
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
    with ExitStack() as cleanup:
        descriptors: list[int] = []
        statuses: list[os.stat_result] = []
        names: list[str] = []
        expected_root = root.lstat()
        root_descriptor = os.open(root, _directory_flags())
        cleanup.callback(os.close, root_descriptor)
        descriptors.append(root_descriptor)
        opened_root = os.fstat(root_descriptor)
        if not stat.S_ISDIR(opened_root.st_mode) or not _same_file(
            expected_root, opened_root
        ):
            message = "input root changed while being opened"
            raise OSError(message)
        statuses.append(opened_root)
        for name in relative.parent.parts:
            descriptor, opened = _open_relative_directory(name, descriptors[-1])
            cleanup.callback(os.close, descriptor)
            descriptors.append(descriptor)
            statuses.append(opened)
            names.append(name)

        expected_leaf = os.stat(
            relative.name,
            dir_fd=descriptors[-1],
            follow_symlinks=False,
        )
        if not stat.S_ISREG(expected_leaf.st_mode):
            message = "input must be a real regular file"
            raise OSError(message)
        descriptor = os.open(
            relative.name,
            _file_flags(),
            dir_fd=descriptors[-1],
        )
        cleanup.callback(os.close, descriptor)
        opened_leaf = os.fstat(descriptor)
        if not stat.S_ISREG(opened_leaf.st_mode) or not _same_file(
            expected_leaf, opened_leaf
        ):
            message = "input file changed while being opened"
            raise OSError(message)

        return _read_validated_leaf(
            _RootedReadChain(
                root=root,
                descriptors=tuple(descriptors),
                statuses=tuple(statuses),
                names=tuple(names),
            ),
            relative.name,
            opened_leaf,
            descriptor,
            limit,
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
