"""Tests for deterministic and bounded source discovery."""

import os
from pathlib import Path, PurePosixPath

import pytest

from pyahead.analysis.discovery import (
    MAX_SOURCE_BYTES,
    DiscoveryError,
    discover_python_files,
    project_module_names,
    project_module_paths,
)

_TWO_FILES = 2


def test_discovery_is_sorted_deduplicated_and_excludes_build_data(
    tmp_path: Path,
) -> None:
    """Only eligible source files are returned in stable relative order."""
    (tmp_path / "b.py").write_text("", encoding="utf-8")
    (tmp_path / "a.pyi").write_text("", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/hidden.py").write_text("", encoding="utf-8")

    result = discover_python_files(tmp_path, (Path(), Path("b.py")))

    assert [file.relative_path.as_posix() for file in result.files] == [
        "a.pyi",
        "b.py",
    ]
    assert result.issues == ()


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
        tmp_path / "src/cgi.pyi",
        tmp_path / "bad-name.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    result = discover_python_files(tmp_path, ())

    assert project_module_names(result.files) == frozenset(
        {"cgi", "widget", "widget.api"}
    )
    assert PurePosixPath("cgi.py") in {item.relative_path for item in result.files}


def test_project_module_paths_include_implicit_namespace_package_parents(
    tmp_path: Path,
) -> None:
    """Descendant modules make namespace parents possible local import origins."""
    paths = [
        tmp_path / "rootpkg/old.py",
        tmp_path / "src/targetpkg/nested/old.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    result = discover_python_files(tmp_path, ())
    modules = project_module_paths(result.files, result.issues)

    assert modules["rootpkg"] == (PurePosixPath("rootpkg/old.py"),)
    assert modules["rootpkg.old"] == (PurePosixPath("rootpkg/old.py"),)
    assert modules["targetpkg"] == (PurePosixPath("src/targetpkg/nested/old.py"),)
    assert modules["targetpkg.nested"] == (
        PurePosixPath("src/targetpkg/nested/old.py"),
    )
    assert modules["targetpkg.nested.old"] == (
        PurePosixPath("src/targetpkg/nested/old.py"),
    )


def test_discovery_does_not_follow_file_symlinks_outside_root(
    tmp_path: Path,
) -> None:
    """An unsafe file alias remains incomplete project-module evidence."""
    outside = tmp_path.parent / "outside-target.py"
    outside.write_text("import cgi\n", encoding="utf-8")
    (tmp_path / "linked.py").symlink_to(outside)

    result = discover_python_files(tmp_path, ())

    assert result.files == ()
    issue_summary = [
        (issue.relative_path.as_posix(), issue.code) for issue in result.issues
    ]
    assert issue_summary == [("linked.py", "PYA1004")]
    assert project_module_paths(result.files, result.issues) == {
        "linked": (PurePosixPath("linked.py"),)
    }


@pytest.mark.parametrize("target_location", ["internal", "outside"])
def test_directory_symlink_is_not_traversed_but_remains_a_module_candidate(
    tmp_path: Path,
    target_location: str,
) -> None:
    """Internal and escaping directory aliases both prevent false certainty."""
    project = tmp_path / "project"
    project.mkdir()
    target = (
        tmp_path / "outside-package"
        if target_location == "outside"
        else project / "internal-package"
    )
    target.mkdir()
    (target / "implementation.py").write_text("VALUE = 1\n", encoding="utf-8")
    alias = project / "targetpkg"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(project, ())
    discovered_paths = {item.relative_path.as_posix() for item in result.files}

    assert not any(path.startswith("targetpkg/") for path in discovered_paths)
    assert [issue.relative_path.as_posix() for issue in result.issues] == ["targetpkg"]
    assert project_module_paths(result.files, result.issues)["targetpkg"] == (
        PurePosixPath("targetpkg"),
    )
    if target_location == "internal":
        selected = discover_python_files(project, (Path("targetpkg"),))
        assert selected.files == ()
        assert [issue.relative_path.as_posix() for issue in selected.issues] == [
            "targetpkg"
        ]
    else:
        with pytest.raises(DiscoveryError):
            discover_python_files(project, (Path("targetpkg"),))


def test_symlinked_src_root_conservatively_competes_with_every_module(
    tmp_path: Path,
) -> None:
    """Opaque contents under a conventional source root cannot produce certainty."""
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside-src"
    outside.mkdir()
    (outside / "targetpkg.py").write_text("VALUE = 1\n", encoding="utf-8")
    try:
        (project / "src").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(project, ())

    assert project_module_paths(result.files, result.issues)["*"] == (
        PurePosixPath("src"),
    )


def test_internal_file_symlink_preserves_logical_repository_path(
    tmp_path: Path,
) -> None:
    """An internal file alias keeps its importable name while reads stay resolved."""
    target = tmp_path / "internal/implementation.py"
    target.parent.mkdir()
    target.write_text("VALUE = 'local'\n", encoding="utf-8")
    alias = tmp_path / "cgi.py"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("the platform does not permit file symlinks")

    result = discover_python_files(tmp_path, ())
    files = {item.relative_path.as_posix(): item for item in result.files}

    assert set(files) == {"cgi.py", "internal/implementation.py"}
    assert files["cgi.py"].absolute_path == target.resolve()
    assert project_module_paths(result.files, result.issues)["cgi"] == (
        PurePosixPath("cgi.py"),
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_discovery_skips_oversized_and_non_regular_sources(tmp_path: Path) -> None:
    """Unsafe source entries are finite incomplete results, never open streams."""
    (tmp_path / "large.py").write_bytes(b"#" * (MAX_SOURCE_BYTES + 1))
    fifo = tmp_path / "pipe.py"
    os.mkfifo(fifo)

    result = discover_python_files(tmp_path, ())

    assert result.files == ()
    assert result.files_discovered == _TWO_FILES
    assert [
        (issue.relative_path.as_posix(), issue.code) for issue in result.issues
    ] == [("large.py", "PYA1005"), ("pipe.py", "PYA1004")]


def test_unsafe_runtime_module_candidate_still_prevents_false_certainty(
    tmp_path: Path,
) -> None:
    """An unanalysable .py candidate remains relevant to import resolution."""
    (tmp_path / "cgi.py").write_bytes(b"#" * (MAX_SOURCE_BYTES + 1))

    result = discover_python_files(tmp_path, ())

    assert project_module_paths(result.files, result.issues) == {
        "cgi": (PurePosixPath("cgi.py"),)
    }
