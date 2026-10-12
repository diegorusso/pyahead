"""A chain of directories opened from a trusted root without following links.

Readers and writers both reach their file through descriptors pinned one
directory at a time, so a link or a replaced directory anywhere on the path
cannot redirect them, and both re-check every binding before trusting what
they did. Callers phrase failures themselves: ``fail`` receives one of the
reasons below and must raise.
"""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, NoReturn

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

ChainFailure = Literal["root-changed", "parent-not-directory", "parent-changed"]


def directory_flags() -> int:
    """Open a directory read-only, without following a final link."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


@dataclass(frozen=True)
class DirectoryChain:
    """Open directory descriptors and the names used to reach each one."""

    root: Path
    descriptors: tuple[int, ...]
    statuses: tuple[os.stat_result, ...]
    names: tuple[str, ...]

    @property
    def parent_descriptor(self) -> int:
        """The innermost directory, which holds the file."""
        return self.descriptors[-1]

    def changed_binding(self) -> int | None:
        """Return the first position whose path or descriptor moved, if any.

        Position 0 is the root; position ``n`` is the ``n``-th name.
        """
        current_root = self.root.lstat()
        opened_root = os.fstat(self.descriptors[0])
        if not stat.S_ISDIR(current_root.st_mode) or not (
            os.path.samestat(current_root, self.statuses[0])
            and os.path.samestat(opened_root, self.statuses[0])
        ):
            return 0
        for index, name in enumerate(self.names, start=1):
            current = os.stat(
                name,
                dir_fd=self.descriptors[index - 1],
                follow_symlinks=False,
            )
            opened = os.fstat(self.descriptors[index])
            if not stat.S_ISDIR(current.st_mode) or not (
                os.path.samestat(current, self.statuses[index])
                and os.path.samestat(opened, self.statuses[index])
            ):
                return index
        return None

    def close(self) -> None:
        """Close every descriptor, innermost first."""
        for descriptor in reversed(self.descriptors):
            with suppress(OSError):
                os.close(descriptor)


def open_directory_chain(
    root: Path,
    names: tuple[str, ...],
    fail: Callable[[ChainFailure], NoReturn],
) -> DirectoryChain:
    """Open ``root`` and then each of ``names`` beneath it, pinning each one."""
    with ExitStack() as cleanup:
        descriptors: list[int] = []
        statuses: list[os.stat_result] = []
        expected_root = root.lstat()
        root_descriptor = os.open(root, directory_flags())
        cleanup.callback(os.close, root_descriptor)
        descriptors.append(root_descriptor)
        opened_root = os.fstat(root_descriptor)
        if not stat.S_ISDIR(opened_root.st_mode) or not os.path.samestat(
            expected_root, opened_root
        ):
            fail("root-changed")
        statuses.append(opened_root)
        for name in names:
            expected = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            if not stat.S_ISDIR(expected.st_mode):
                fail("parent-not-directory")
            descriptor = os.open(name, directory_flags(), dir_fd=descriptors[-1])
            cleanup.callback(os.close, descriptor)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or not os.path.samestat(
                expected, opened
            ):
                fail("parent-changed")
            statuses.append(opened)
        cleanup.pop_all()
        return DirectoryChain(
            root=root,
            descriptors=tuple(descriptors),
            statuses=tuple(statuses),
            names=names,
        )
