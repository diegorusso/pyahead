"""Atomic UTF-8 output-file replacement within an optional trusted root."""

import os
import secrets
import stat
import tempfile
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from pathlib import Path


class OutputError(OSError):
    """Raised when a requested output destination cannot be replaced."""


_TEMPORARY_ATTEMPTS = 128


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return os.path.samestat(left, right)


def _directory_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, name, 0)
    return flags


def _temporary_flags() -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for name in ("O_CLOEXEC", "O_NOFOLLOW"):
        flags |= getattr(os, name, 0)
    return flags


def _supports_pinned_directories() -> bool:
    required = (os.open, os.rename, os.stat, os.unlink)
    return (
        all(function in os.supports_dir_fd for function in required)
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _supports_guarded_paths() -> bool:
    return os.name == "nt"


def _require_pinned_directories() -> None:
    if not _supports_pinned_directories():
        message = "secure root-bounded output is unavailable on this platform"
        raise OutputError(message)


@dataclass(frozen=True)
class _PinnedDirectoryChain:
    """Open directory descriptors and the bindings used to reach each one."""

    root: Path
    descriptors: tuple[int, ...]
    statuses: tuple[os.stat_result, ...]
    names: tuple[str, ...]

    @property
    def parent_descriptor(self) -> int:
        return self.descriptors[-1]

    def validate(self) -> None:
        """Require every path binding to still reference its pinned directory."""
        root_status = self.root.lstat()
        if not stat.S_ISDIR(root_status.st_mode) or not _same_entry(
            root_status,
            self.statuses[0],
        ):
            message = "output directory changed while it was being used"
            raise OutputError(message)
        for index, name in enumerate(self.names, start=1):
            current = os.stat(
                name,
                dir_fd=self.descriptors[index - 1],
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(current.st_mode) or not _same_entry(
                current,
                self.statuses[index],
            ):
                message = "output directory changed while it was being used"
                raise OutputError(message)

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _is_real_directory(status: os.stat_result) -> bool:
    attributes = getattr(status, "st_file_attributes", 0)
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return (
        stat.S_ISDIR(status.st_mode)
        and not stat.S_ISLNK(status.st_mode)
        and not attributes & reparse_point
    )


@dataclass(frozen=True)
class _PathDirectoryChain:
    """Path-based directory bindings for platforms without directory FDs."""

    paths: tuple[Path, ...]
    statuses: tuple[os.stat_result, ...]

    def validate(self) -> None:
        """Require each parent to remain the same real directory."""
        for path, expected in zip(self.paths, self.statuses, strict=True):
            current = path.lstat()
            if not _is_real_directory(current) or not _same_entry(current, expected):
                message = "output directory changed while it was being used"
                raise OutputError(message)


def _open_guarded_directories(
    root: Path,
    relative_parent: Path,
) -> _PathDirectoryChain:
    paths = [root]
    for name in relative_parent.parts:
        paths.append(paths[-1] / name)
    statuses = tuple(path.lstat() for path in paths)
    if not all(_is_real_directory(status) for status in statuses):
        message = "secure root-bounded output is unavailable for reparse-point parents"
        raise OutputError(message)
    return _PathDirectoryChain(paths=tuple(paths), statuses=statuses)


def _open_pinned_directories(
    root: Path,
    relative_parent: Path,
) -> _PinnedDirectoryChain:
    with ExitStack() as cleanup:
        descriptors: list[int] = []
        statuses: list[os.stat_result] = []
        names: list[str] = []
        expected_root = root.lstat()
        root_descriptor = os.open(root, _directory_flags())
        cleanup.callback(os.close, root_descriptor)
        descriptors.append(root_descriptor)
        opened_root = os.fstat(root_descriptor)
        if not stat.S_ISDIR(opened_root.st_mode) or not _same_entry(
            expected_root,
            opened_root,
        ):
            message = "output root changed while it was being opened"
            raise OutputError(message)
        statuses.append(opened_root)

        for name in relative_parent.parts:
            descriptor = os.open(
                name,
                _directory_flags(),
                dir_fd=descriptors[-1],
            )
            cleanup.callback(os.close, descriptor)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode):
                message = "output parents must be real directories"
                raise OutputError(message)
            statuses.append(opened)
            names.append(name)
        chain = _PinnedDirectoryChain(
            root=root,
            descriptors=tuple(descriptors),
            statuses=tuple(statuses),
            names=tuple(names),
        )
        chain.validate()
        cleanup.pop_all()
        return chain


def _temporary_name(destination_name: str) -> str:
    return f".{destination_name}.{secrets.token_hex(8)}.tmp"


def _create_temporary_at(
    parent_descriptor: int,
    destination_name: str,
) -> tuple[int, str, os.stat_result]:
    for _ in range(_TEMPORARY_ATTEMPTS):
        name = _temporary_name(destination_name)
        try:
            descriptor = os.open(
                name,
                _temporary_flags(),
                0o600,
                dir_fd=parent_descriptor,
            )
        except FileExistsError:
            continue
        return descriptor, name, os.fstat(descriptor)
    message = "unable to allocate a unique output temporary file"
    raise OutputError(message)


def _write_descriptor(descriptor: int, content: str) -> None:
    """Write and synchronize content, taking ownership of the descriptor."""
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
    except Exception:
        os.close(descriptor)
        raise
    with stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _validate_temporary_at(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> None:
    current = os.stat(
        name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    if not stat.S_ISREG(current.st_mode) or not _same_entry(current, expected):
        message = "output temporary file changed before replacement"
        raise OutputError(message)


def _unlink_temporary_at(
    parent_descriptor: int,
    name: str,
    expected: os.stat_result,
) -> None:
    with suppress(OSError):
        current = os.stat(
            name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _same_entry(current, expected):
            os.unlink(name, dir_fd=parent_descriptor)


def _write_pinned_atomic(
    root: Path,
    relative_path: Path,
    content: str,
) -> None:
    chain = _open_pinned_directories(root, relative_path.parent)
    temporary_name: str | None = None
    temporary_status: os.stat_result | None = None
    try:
        chain.validate()
        descriptor, temporary_name, temporary_status = _create_temporary_at(
            chain.parent_descriptor,
            relative_path.name,
        )
        _write_descriptor(descriptor, content)
        chain.validate()
        _validate_temporary_at(
            chain.parent_descriptor,
            temporary_name,
            temporary_status,
        )
        os.replace(
            temporary_name,
            relative_path.name,
            src_dir_fd=chain.parent_descriptor,
            dst_dir_fd=chain.parent_descriptor,
        )
        temporary_name = None
        chain.validate()
    finally:
        if temporary_name is not None and temporary_status is not None:
            _unlink_temporary_at(
                chain.parent_descriptor,
                temporary_name,
                temporary_status,
            )
        chain.close()


def _matching_path_entry(path: Path, expected: os.stat_result) -> bool:
    try:
        current = path.lstat()
    except OSError:
        return False
    return _same_entry(current, expected)


def _write_path_atomic(
    path: Path,
    content: str,
    *,
    chain: _PathDirectoryChain | None = None,
) -> None:
    parent = path.parent
    temporary_path: Path | None = None
    temporary_status: os.stat_result | None = None
    try:
        if chain is not None:
            chain.validate()
        descriptor, temporary_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        temporary_status = os.fstat(descriptor)
        _write_descriptor(descriptor, content)
        if not _matching_path_entry(temporary_path, temporary_status):
            message = "output temporary file changed before replacement"
            raise OutputError(message)
        if chain is not None:
            chain.validate()
        temporary_path.replace(path)
        temporary_path = None
        if chain is not None:
            chain.validate()
    finally:
        if (
            temporary_path is not None
            and temporary_status is not None
            and _matching_path_entry(temporary_path, temporary_status)
        ):
            with suppress(OSError):
                temporary_path.unlink()


def _bounded_destination(path: Path, root: Path) -> tuple[Path, Path]:
    try:
        resolved_root = root.resolve(strict=True)
        logical_path = Path(os.path.abspath(path))  # noqa: PTH100
        relative_path = logical_path.relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as error:
        message = "output file must remain beneath its trusted root"
        raise OutputError(message) from error
    if relative_path == Path() or not relative_path.name:
        message = "output destination must name a file beneath its trusted root"
        raise OutputError(message)
    return resolved_root, relative_path


def write_text_atomic(path: Path, content: str, *, root: Path | None = None) -> None:
    """Atomically replace a file, optionally pinning its repository ancestry."""
    try:
        if root is None:
            _write_path_atomic(path, content)
            return
        resolved_root, relative_path = _bounded_destination(path, root)
        if _supports_pinned_directories():
            _write_pinned_atomic(resolved_root, relative_path, content)
        elif _supports_guarded_paths():
            chain = _open_guarded_directories(resolved_root, relative_path.parent)
            _write_path_atomic(resolved_root / relative_path, content, chain=chain)
        else:
            _require_pinned_directories()
    except OutputError:
        raise
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as error:
        message = "unable to write output file atomically"
        raise OutputError(message) from error


__all__ = ["OutputError", "write_text_atomic"]
