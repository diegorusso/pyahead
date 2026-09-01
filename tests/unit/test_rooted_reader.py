"""Tests for the shared private repository-input reader."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import pyahead._rooted_reader as rooted_reader_module
import pyahead._windows_output as windows_output_module
from pyahead._rooted_reader import RootedReadTooLargeError, read_rooted_bytes

_MULTI_CHUNK_BYTES = 70_000


def _requires_posix_rooted_reads() -> None:
    if os.name == "nt" or not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("requires POSIX directory-relative descriptor reads")


def test_exact_byte_limit_succeeds_and_limit_plus_one_fails(tmp_path: Path) -> None:
    """The reader accepts exactly the cap and retains only one sentinel byte."""
    selected = tmp_path / "input"
    selected.write_bytes(b"abc")

    assert read_rooted_bytes(tmp_path, Path("input"), 3) == b"abc"
    with pytest.raises(RootedReadTooLargeError, match="2-byte limit"):
        read_rooted_bytes(tmp_path, Path("input"), 2)


def test_lexical_escape_empty_name_and_non_regular_leaf_fail_closed(
    tmp_path: Path,
) -> None:
    """Lexical escapes, root-only names, and directories are invalid inputs."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.write_bytes(b"outside")
    directory = tmp_path / "directory"
    directory.mkdir()

    with pytest.raises(ValueError, match="trusted root"):
        read_rooted_bytes(tmp_path, outside, 64)
    with pytest.raises(ValueError, match="name a file"):
        read_rooted_bytes(tmp_path, tmp_path, 64)
    with pytest.raises(OSError, match="regular file"):
        read_rooted_bytes(tmp_path, directory, 64)


def test_stable_leaf_and_ancestor_symlinks_are_never_read(tmp_path: Path) -> None:
    """Even stable aliases inside the root remain opaque."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "input").write_bytes(b"secret")
    leaf = tmp_path / "leaf"
    ancestor = tmp_path / "ancestor"
    try:
        leaf.symlink_to(target / "input")
        ancestor.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(OSError, match="regular file"):
        read_rooted_bytes(tmp_path, leaf, 64)
    with pytest.raises(OSError, match="real directories"):
        read_rooted_bytes(tmp_path, ancestor / "input", 64)


def test_fifo_leaf_is_rejected_without_blocking(tmp_path: Path) -> None:
    """A nonblocking open policy never turns a FIFO into repository input."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    fifo = tmp_path / "input"
    os.mkfifo(fifo)

    with pytest.raises(OSError, match="regular file"):
        read_rooted_bytes(tmp_path, fifo, 64)


def test_leaf_replacement_before_open_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-open identity must equal the descriptor identity."""
    _requires_posix_rooted_reads()
    selected = tmp_path / "input"
    replacement = tmp_path / "replacement"
    selected.write_bytes(b"before")
    replacement.write_bytes(b"outside")
    original_open = rooted_reader_module.os.open
    replaced = False

    def replace_before_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if os.fspath(path) == "input" and dir_fd is not None and not replaced:
            replacement.replace(selected)
            replaced = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", replace_before_open)
    monkeypatch.setattr(
        rooted_reader_module,
        "supports_rooted_descriptor_reads",
        lambda: True,
    )

    with pytest.raises(OSError, match="changed while being opened"):
        read_rooted_bytes(tmp_path, selected, 64)
    assert replaced is True


@pytest.mark.parametrize("mutation", ["replace", "rewrite"])
def test_leaf_mutation_during_read_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Replacement and same-size rewrite are both detected after reading."""
    _requires_posix_rooted_reads()
    selected = tmp_path / "input"
    replacement = tmp_path / "replacement"
    selected.write_bytes(b"a" * _MULTI_CHUNK_BYTES)
    replacement.write_bytes(b"b" * _MULTI_CHUNK_BYTES)
    original_read = rooted_reader_module.os.read
    mutated = False

    def mutate_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if chunk and not mutated:
            if mutation == "replace":
                replacement.replace(selected)
            else:
                selected.write_bytes(b"b" * _MULTI_CHUNK_BYTES)
            mutated = True
        return chunk

    monkeypatch.setattr(rooted_reader_module.os, "read", mutate_after_first_chunk)

    with pytest.raises(OSError, match="changed while being read"):
        read_rooted_bytes(tmp_path, selected, _MULTI_CHUNK_BYTES)
    assert mutated is True


def test_ancestor_swap_after_pinning_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned descriptors do not make a swapped logical parent look stable."""
    _requires_posix_rooted_reads()
    parent = tmp_path / "parent"
    archived = tmp_path / "parent-before-swap"
    outside = tmp_path / "outside"
    parent.mkdir()
    outside.mkdir()
    (parent / "input").write_bytes(b"a" * _MULTI_CHUNK_BYTES)
    (outside / "input").write_bytes(b"secret")
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    probe.unlink()
    original_read = rooted_reader_module.os.read
    swapped = False

    def swap_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, size)
        if chunk and not swapped:
            parent.rename(archived)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return chunk

    monkeypatch.setattr(rooted_reader_module.os, "read", swap_after_first_chunk)

    with pytest.raises(OSError, match="parent changed while being read"):
        read_rooted_bytes(tmp_path, Path("parent/input"), _MULTI_CHUNK_BYTES)
    assert swapped is True


def test_root_replacement_during_open_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trusted-root identity is checked across its initial open."""
    _requires_posix_rooted_reads()
    root = tmp_path / "root"
    archived = tmp_path / "root-before-swap"
    root.mkdir()
    (root / "input").write_bytes(b"before")
    original_open = rooted_reader_module.os.open
    swapped = False

    def swap_root_before_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if Path(os.fspath(path)) == root and dir_fd is None and not swapped:
            root.rename(archived)
            root.mkdir()
            (root / "input").write_bytes(b"after")
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", swap_root_before_open)
    monkeypatch.setattr(
        rooted_reader_module,
        "supports_rooted_descriptor_reads",
        lambda: True,
    )

    with pytest.raises(OSError, match="root changed while being opened"):
        read_rooted_bytes(root, Path("input"), 64)
    assert swapped is True


def test_missing_secure_platform_api_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Platforms without a secure backend never fall back to path opens."""
    if os.name == "nt":
        pytest.skip("POSIX fallback behavior")
    selected = tmp_path / "input"
    selected.write_bytes(b"payload")
    monkeypatch.setattr(
        rooted_reader_module,
        "supports_rooted_descriptor_reads",
        lambda: False,
    )

    with pytest.raises(OSError, match="unavailable"):
        read_rooted_bytes(tmp_path, selected, 64)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_leaf_reparse_swap_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A native Windows leaf swap cannot expose a reparse target."""
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    selected = root / "input"
    archived = root / "input-before-swap"
    selected.write_bytes(b"inside")
    (outside / "input").write_bytes(b"outside-secret")
    probe = root / "probe"
    try:
        probe.symlink_to(outside / "input")
    except OSError:
        pytest.skip("the Windows runner cannot create file symlinks")
    probe.unlink()
    original_open_leaf = windows_output_module._nt_create_relative  # noqa: SLF001
    swapped = False

    def swap_leaf_before_open(
        api: windows_output_module._WindowsAPI,
        parent_handle: int,
        name: str,
        creation: windows_output_module._NtCreateOptions,
    ) -> int:
        nonlocal swapped
        if name == "input" and not swapped:
            selected.rename(archived)
            selected.symlink_to(outside / "input")
            swapped = True
        return original_open_leaf(api, parent_handle, name, creation)

    monkeypatch.setattr(
        windows_output_module,
        "_nt_create_relative",
        swap_leaf_before_open,
    )

    with pytest.raises(OSError, match="regular file"):
        read_rooted_bytes(root, Path("input"), 64)
    assert swapped is True


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_missing_leaf_raises_file_not_found(tmp_path: Path) -> None:
    """A native Windows read of an absent leaf raises FileNotFoundError."""
    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(FileNotFoundError):
        read_rooted_bytes(root, Path("missing.toml"), 64)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_missing_intermediate_directory_raises_file_not_found(
    tmp_path: Path,
) -> None:
    """An absent native Windows ancestor directory also raises FileNotFoundError."""
    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(FileNotFoundError):
        read_rooted_bytes(root, Path("missing-parent/input.toml"), 64)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_directory_leaf_does_not_surface_bare_ntstatus(tmp_path: Path) -> None:
    """A directory given as the leaf fails closed without a raw NTSTATUS message."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "leaf").mkdir()

    with pytest.raises(OSError, match="real regular file") as captured:
        read_rooted_bytes(root, Path("leaf"), 64)
    assert "NTSTATUS" not in str(captured.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows alternate data streams")
@pytest.mark.parametrize("path", [Path("input:stream"), Path("parent:stream/input")])
def test_windows_alternate_data_streams_are_rejected_in_every_component(
    tmp_path: Path,
    path: Path,
) -> None:
    """Neither the leaf nor an ancestor can select an alternate data stream."""
    with pytest.raises(OSError, match="alternate data streams"):
        read_rooted_bytes(tmp_path, path, 64)
