"""Tests for deterministic and bounded source discovery."""

from pathlib import Path, PurePosixPath

import pytest

from pyahead.analysis.discovery import (
    DiscoveryError,
    discover_python_files,
    project_module_names,
)


def test_discovery_is_sorted_deduplicated_and_excludes_build_data(
    tmp_path: Path,
) -> None:
    """Only eligible source files are returned in stable relative order."""
    (tmp_path / "b.py").write_text("", encoding="utf-8")
    (tmp_path / "a.pyi").write_text("", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/hidden.py").write_text("", encoding="utf-8")

    files = discover_python_files(tmp_path, (Path(), Path("b.py")))

    assert [file.relative_path.as_posix() for file in files] == ["a.pyi", "b.py"]


def test_discovery_rejects_unsafe_or_invalid_explicit_paths(
    tmp_path: Path,
) -> None:
    """Explicit files cannot escape the root or use unrelated suffixes."""
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")
    outside = tmp_path.parent / "outside.py"
    outside.write_text("", encoding="utf-8")

    with pytest.raises(DiscoveryError):
        discover_python_files(tmp_path, (Path("notes.txt"),))
    with pytest.raises(DiscoveryError):
        discover_python_files(tmp_path, (outside,))
    with pytest.raises(DiscoveryError):
        discover_python_files(tmp_path, (Path("missing.py"),))


def test_discovery_rejects_missing_or_non_directory_root(tmp_path: Path) -> None:
    """The scan root is an existing directory, never an implicit fallback."""
    source = tmp_path / "source.py"
    source.write_text("", encoding="utf-8")

    with pytest.raises(DiscoveryError):
        discover_python_files(tmp_path / "missing", ())
    with pytest.raises(DiscoveryError):
        discover_python_files(source, ())


def test_project_module_names_support_root_src_and_packages(tmp_path: Path) -> None:
    """Conventional import names are inferred without importing project code."""
    paths = [
        tmp_path / "cgi.py",
        tmp_path / "src/widget/__init__.py",
        tmp_path / "src/widget/api.py",
        tmp_path / "bad-name.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    files = discover_python_files(tmp_path, ())

    assert project_module_names(files) == frozenset({"cgi", "widget", "widget.api"})
    assert PurePosixPath("cgi.py") in {item.relative_path for item in files}


def test_discovery_does_not_follow_file_symlinks_outside_root(
    tmp_path: Path,
) -> None:
    """A directory scan silently excludes an explicitly unsafe file symlink."""
    outside = tmp_path.parent / "outside-target.py"
    outside.write_text("import cgi\n", encoding="utf-8")
    (tmp_path / "linked.py").symlink_to(outside)

    assert discover_python_files(tmp_path, ()) == ()
