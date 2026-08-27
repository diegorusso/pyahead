"""Consumer-level mutation tests for shared repository input."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

import pyahead._rooted_reader as rooted_reader_module
from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import (
    DiscoveryIncompleteError,
    discover_python_files,
)
from pyahead.baseline import load_baseline
from pyahead.config import load_project_configuration
from pyahead.evidence import merge_evidence
from pyahead.model import ConfigurationError, ExitCode

if TYPE_CHECKING:
    from collections.abc import Callable


def _require_posix_reader() -> None:
    if os.name == "nt" or not rooted_reader_module.supports_rooted_descriptor_reads():
        pytest.skip("requires POSIX directory-relative descriptor reads")


def _swap_ancestor_on_open(
    monkeypatch: pytest.MonkeyPatch,
    parent: Path,
    outside: Path,
) -> Callable[[], bool]:
    archived = parent.with_name(f"{parent.name}-before-swap")
    original_open = rooted_reader_module.os.open
    swapped = False

    def swap_before_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if os.fspath(path) == parent.name and dir_fd is not None and not swapped:
            parent.rename(archived)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", swap_before_open)
    monkeypatch.setattr(
        rooted_reader_module,
        "supports_rooted_descriptor_reads",
        lambda: True,
    )
    return lambda: swapped


def _prepare_swappable_parent(root: Path, name: str) -> tuple[Path, Path]:
    parent = root / "nested"
    outside = root.parent / f"{root.name}-outside"
    parent.mkdir()
    outside.mkdir()
    (parent / name).write_text("inside", encoding="utf-8")
    (outside / name).write_text("outside-secret", encoding="utf-8")
    probe = root / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    probe.unlink()
    return parent, outside


def test_source_consumer_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Source analysis cannot follow a repository-parent replacement."""
    _require_posix_reader()
    parent, outside = _prepare_swappable_parent(tmp_path, "legacy.py")
    (parent / "legacy.py").write_text("import pathlib\n", encoding="utf-8")
    (outside / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    swapped = _swap_ancestor_on_open(monkeypatch, parent, outside)

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )

    assert swapped()
    assert report.findings == ()
    assert report.counts.files_analyzed == 0
    assert report.exit_code is ExitCode.INCOMPLETE


def test_gitignore_consumer_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ignore policy cannot be redirected through a replaced ancestor."""
    _require_posix_reader()
    parent, outside = _prepare_swappable_parent(tmp_path, ".gitignore")
    (parent / ".gitignore").write_text("*.py\n", encoding="utf-8")
    (outside / ".gitignore").write_text("\n", encoding="utf-8")
    (parent / "keep.py").write_text("", encoding="utf-8")
    (outside / "keep.py").write_text("", encoding="utf-8")
    swapped = _swap_ancestor_on_open(monkeypatch, parent, outside)

    with pytest.raises(DiscoveryIncompleteError, match=r"\.gitignore"):
        discover_python_files(tmp_path, ())
    assert swapped()


def test_explicit_configuration_consumer_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit configuration stays bound to its original parent."""
    _require_posix_reader()
    parent, outside = _prepare_swappable_parent(tmp_path, "config.toml")
    (parent / "config.toml").write_text(
        '[tool.pyahead]\nbaseline-python = "3.11"\n',
        encoding="utf-8",
    )
    (outside / "config.toml").write_text(
        '[tool.pyahead]\nbaseline-python = "3.13"\n',
        encoding="utf-8",
    )
    swapped = _swap_ancestor_on_open(monkeypatch, parent, outside)

    with pytest.raises(ConfigurationError, match="unable to read configuration"):
        load_project_configuration(tmp_path, Path("nested/config.toml"))
    assert swapped()


def test_default_configuration_consumer_rejects_root_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default configuration cannot be redirected by replacing its root."""
    _require_posix_reader()
    root = tmp_path / "root"
    archived = tmp_path / "root-before-swap"
    replacement = tmp_path / "replacement"
    root.mkdir()
    replacement.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )
    (replacement / "pyproject.toml").write_text(
        '[project]\nrequires-python = ">=3.13"\n',
        encoding="utf-8",
    )
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
            replacement.rename(root)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(rooted_reader_module.os, "open", swap_root_before_open)
    monkeypatch.setattr(
        rooted_reader_module,
        "supports_rooted_descriptor_reads",
        lambda: True,
    )

    with pytest.raises(ConfigurationError, match="unable to read configuration"):
        load_project_configuration(root, None)
    assert swapped


def test_baseline_consumer_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline loading cannot traverse a replaced repository parent."""
    _require_posix_reader()
    parent, outside = _prepare_swappable_parent(tmp_path, "baseline.json")
    swapped = _swap_ancestor_on_open(monkeypatch, parent, outside)

    with pytest.raises(ConfigurationError, match="unable to read baseline"):
        load_baseline(Path("nested/baseline.json"), tmp_path)
    assert swapped()


def test_evidence_consumer_rejects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Evidence ingestion cannot traverse a replaced repository parent."""
    _require_posix_reader()
    (tmp_path / "clean.py").write_text("import pathlib\n", encoding="utf-8")
    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )
    parent, outside = _prepare_swappable_parent(tmp_path, "warnings.json")
    swapped = _swap_ancestor_on_open(monkeypatch, parent, outside)

    with pytest.raises(ConfigurationError, match="unable to read evidence"):
        merge_evidence(
            report,
            (Path("nested/warnings.json"),),
            root=tmp_path,
            source_commit="a" * 40,
        )
    assert swapped()
