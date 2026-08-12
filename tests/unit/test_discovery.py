"""Tests for deterministic and bounded source discovery."""

import os
from pathlib import Path, PurePosixPath

import pytest

import pyahead.analysis.discovery as discovery_module
from pyahead.analysis.discovery import (
    MAX_SOURCE_BYTES,
    DiscoveryEntryKind,
    DiscoveryError,
    DiscoveryIncompleteError,
    DiscoveryOptions,
    discover_python_files,
    project_module_names,
    project_module_paths,
)

_TWO_FILES = 2
_THREE_FILES = 3


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


def test_unresolvable_file_symlink_is_a_stable_incomplete_issue(
    tmp_path: Path,
) -> None:
    """Broken and looping aliases cannot turn discovery into an internal error."""
    link = tmp_path / "loop.py"
    try:
        link.symlink_to(link.name)
    except OSError:
        pytest.skip("the platform does not permit file symlinks")

    result = discover_python_files(tmp_path, ())

    assert result.files == ()
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("loop.py", "PYA1004")
    ]


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


@pytest.mark.parametrize("source_root", ["vendor.lib", "vendor.lib/src"])
def test_dotted_opaque_authoritative_root_maps_to_wildcard(
    tmp_path: Path,
    source_root: str,
) -> None:
    """Directory identity, not a path suffix, controls opaque-root mapping."""
    project = tmp_path / "project"
    target = project / "internal-vendor"
    (target / "src").mkdir(parents=True)
    try:
        (project / "vendor.lib").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(
        project,
        (Path(source_root),),
        DiscoveryOptions(
            respect_gitignore=False,
            allow_explicit_built_in_roots=True,
        ),
    )

    assert result.files == ()
    assert [
        (issue.relative_path.as_posix(), issue.code, issue.entry_kind)
        for issue in result.issues
    ] == [("vendor.lib", "PYA1004", DiscoveryEntryKind.DIRECTORY)]
    assert project_module_paths(
        result.files,
        result.issues,
        (source_root,),
    ) == {"*": (PurePosixPath("vendor.lib"),)}


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


def test_discovery_stops_deterministically_at_source_entry_limit(
    tmp_path: Path,
) -> None:
    """The bounded prefix and first omitted entry are stable and incomplete."""
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_text("", encoding="utf-8")

    result = discover_python_files(
        tmp_path,
        (),
        DiscoveryOptions(max_source_entries=2),
    )

    assert [item.relative_path.as_posix() for item in result.files] == ["a.py", "b.py"]
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("c.py", "PYA1006")
    ]
    assert result.files_discovered == _THREE_FILES


def test_overlapping_requested_paths_share_one_source_entry_budget(
    tmp_path: Path,
) -> None:
    """Repeated discovery roots do not manufacture a limit diagnostic."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("", encoding="utf-8")
    (source / "b.py").write_text("", encoding="utf-8")

    result = discover_python_files(
        tmp_path,
        (Path(), Path("src")),
        DiscoveryOptions(max_source_entries=2),
    )

    assert [item.relative_path.as_posix() for item in result.files] == [
        "src/a.py",
        "src/b.py",
    ]
    assert result.issues == ()


def test_unsafe_runtime_module_candidate_still_prevents_false_certainty(
    tmp_path: Path,
) -> None:
    """An unanalysable .py candidate remains relevant to import resolution."""
    (tmp_path / "cgi.py").write_bytes(b"#" * (MAX_SOURCE_BYTES + 1))

    result = discover_python_files(tmp_path, ())

    assert project_module_paths(result.files, result.issues) == {
        "cgi": (PurePosixPath("cgi.py"),)
    }


def test_configured_include_exclude_and_gitignore_have_stable_order(
    tmp_path: Path,
) -> None:
    """Built-ins/gitignore filter first, includes select, and excludes win."""
    paths = [
        tmp_path / "src/keep.py",
        tmp_path / "src/ignored.py",
        tmp_path / "src/generated/drop.py",
        tmp_path / "tests/outside.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("src/ignored.py\n", encoding="utf-8")

    result = discover_python_files(
        tmp_path,
        (),
        DiscoveryOptions(
            include=("src/**/*.py",),
            exclude=("src/generated/**",),
        ),
    )

    assert [item.relative_path.as_posix() for item in result.files] == ["src/keep.py"]


def test_gitignore_negation_and_explicit_disable_are_deterministic(
    tmp_path: Path,
) -> None:
    """Git-compatible last-match negation works and can be explicitly disabled."""
    (tmp_path / "drop.py").write_text("", encoding="utf-8")
    (tmp_path / "keep.py").write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.py\n!keep.py\n", encoding="utf-8")

    respected = discover_python_files(tmp_path, ())
    disabled = discover_python_files(
        tmp_path,
        (),
        DiscoveryOptions(respect_gitignore=False),
    )

    assert [item.relative_path.as_posix() for item in respected.files] == ["keep.py"]
    assert [item.relative_path.as_posix() for item in disabled.files] == [
        "drop.py",
        "keep.py",
    ]


def test_nested_gitignore_patterns_are_relative_to_their_directory(
    tmp_path: Path,
) -> None:
    """Each nested ignore file applies only beneath its own directory."""
    package = tmp_path / "pkg"
    sibling = tmp_path / "sibling"
    package.mkdir()
    sibling.mkdir()
    for path in (
        package / "legacy.py",
        package / "keep.py",
        sibling / "legacy.py",
    ):
        path.write_text("", encoding="utf-8")
    (package / ".gitignore").write_text("/legacy.py\n", encoding="utf-8")

    result = discover_python_files(tmp_path, ())

    assert [item.relative_path.as_posix() for item in result.files] == [
        "pkg/keep.py",
        "sibling/legacy.py",
    ]


def test_nested_gitignore_negations_override_ancestors_in_order(
    tmp_path: Path,
) -> None:
    """Deeper negations re-include files while ignored parents stay closed."""
    nested = tmp_path / "pkg/nested"
    blocked = tmp_path / "blocked"
    nested.mkdir(parents=True)
    blocked.mkdir()
    for path in (
        tmp_path / "drop.py",
        tmp_path / "pkg/keep.py",
        nested / "drop.py",
        nested / "keep.py",
        blocked / "keep.py",
    ):
        path.write_text("", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("*.py\nblocked/\n", encoding="utf-8")
    (tmp_path / "pkg/.gitignore").write_text(
        "!keep.py\nnested/*.py\n",
        encoding="utf-8",
    )
    (nested / ".gitignore").write_text("!keep.py\n", encoding="utf-8")
    (blocked / ".gitignore").write_text("!keep.py\n", encoding="utf-8")

    result = discover_python_files(tmp_path, ())

    assert [item.relative_path.as_posix() for item in result.files] == [
        "pkg/keep.py",
        "pkg/nested/keep.py",
    ]


@pytest.mark.parametrize("target_kind", ["internal", "external", "dangling"])
def test_gitignore_symlink_is_never_followed(
    tmp_path: Path,
    target_kind: str,
) -> None:
    """Working-tree ignore symlinks cannot hide eligible Python files."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "keep.py").write_text("", encoding="utf-8")
    if target_kind == "internal":
        target = project / "ignore-rules.txt"
        target.write_text("*.py\n", encoding="utf-8")
    elif target_kind == "external":
        target = tmp_path / "outside-ignore-rules.txt"
        target.write_text("*.py\n", encoding="utf-8")
    else:
        target = project / "missing-ignore-rules.txt"
    try:
        (project / ".gitignore").symlink_to(target)
    except OSError:
        pytest.skip("the platform does not permit file symlinks")

    result = discover_python_files(project, ())

    assert [item.relative_path.as_posix() for item in result.files] == ["keep.py"]


@pytest.mark.parametrize("replacement_kind", ["fifo", "symlink", "regular"])
def test_gitignore_entry_replacement_fails_closed_without_blocking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    """The opened ignore entry must be the bounded regular file first inspected."""
    if replacement_kind == "fifo" and (
        not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK")
    ):
        pytest.skip("nonblocking FIFO creation is unavailable")
    ignore = tmp_path / ".gitignore"
    ignore.write_text("*.py\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("", encoding="utf-8")
    replacement = tmp_path / "replacement-ignore"
    replacement.write_text("keep.py\n", encoding="utf-8")
    original_open = os.open
    replaced = False
    observed_flags = 0

    def replace_before_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal observed_flags, replaced
        rendered = os.fspath(path)
        if not replaced and isinstance(rendered, str) and Path(rendered) == ignore:
            observed_flags = flags
            if replacement_kind == "regular":
                replacement.replace(ignore)
            else:
                ignore.unlink()
                if replacement_kind == "fifo":
                    os.mkfifo(ignore)
                else:
                    ignore.symlink_to(replacement)
            replaced = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_before_open)

    with pytest.raises(DiscoveryIncompleteError, match=r"\.gitignore"):
        discover_python_files(tmp_path, ())

    assert replaced is True
    if replacement_kind == "fifo":
        assert observed_flags & os.O_NONBLOCK


def test_oversized_gitignore_is_a_bounded_incomplete_read(tmp_path: Path) -> None:
    """Ignore policy cannot consume an unbounded regular file."""
    limit = discovery_module._MAX_GITIGNORE_BYTES  # noqa: SLF001
    (tmp_path / ".gitignore").write_bytes(b"#" * (limit + 1))
    (tmp_path / "keep.py").write_text("", encoding="utf-8")

    with pytest.raises(DiscoveryIncompleteError, match="ignore-file limit"):
        discover_python_files(tmp_path, ())


def test_growing_gitignore_is_bounded_after_descriptor_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Growth after fstat is caught by the descriptor read limit."""
    limit = discovery_module._MAX_GITIGNORE_BYTES  # noqa: SLF001
    ignore = tmp_path / ".gitignore"
    ignore.write_bytes(b"#" * limit)
    (tmp_path / "keep.py").write_text("", encoding="utf-8")
    expected = ignore.stat()
    original_fstat = os.fstat
    grown = False

    def grow_after_status(descriptor: int) -> os.stat_result:
        nonlocal grown
        opened = original_fstat(descriptor)
        if not grown and os.path.samestat(opened, expected):
            with ignore.open("ab") as stream:
                stream.write(b"x")
            grown = True
        return opened

    monkeypatch.setattr(os, "fstat", grow_after_status)

    with pytest.raises(DiscoveryIncompleteError, match="ignore-file limit"):
        discover_python_files(tmp_path, ())

    assert grown is True


def test_directory_only_gitignore_pattern_does_not_hide_directory_symlink(
    tmp_path: Path,
) -> None:
    """A trailing-slash rule matches directories, not symlink entries."""
    project = tmp_path / "project"
    target = tmp_path / "target"
    project.mkdir()
    target.mkdir()
    (target / "hidden.py").write_text("", encoding="utf-8")
    (project / ".gitignore").write_text("linked/\n", encoding="utf-8")
    try:
        (project / "linked").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(project, ())

    assert result.files == ()
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("linked", "PYA1004")
    ]


def test_directory_only_gitignore_does_not_hide_requested_directory_symlink(
    tmp_path: Path,
) -> None:
    """Explicit aliases use symlink, not target-directory, ignore semantics."""
    project = tmp_path / "project"
    target = project / "target"
    target.mkdir(parents=True)
    (target / "hidden.py").write_text("", encoding="utf-8")
    (project / ".gitignore").write_text("linked/\n", encoding="utf-8")
    try:
        (project / "linked").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(project, (Path("linked"),))

    assert result.files == ()
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("linked", "PYA1004")
    ]


def test_requested_symlink_descendant_does_not_load_target_gitignore(
    tmp_path: Path,
) -> None:
    """Explicit descendants stop at their alias before target-side policy is read."""
    project = tmp_path / "project"
    target = project / "target"
    target.mkdir(parents=True)
    (target / "child.py").write_text("", encoding="utf-8")
    (target / ".gitignore").write_bytes(b"\xff")
    (project / ".gitignore").write_text("linked/\n", encoding="utf-8")
    try:
        (project / "linked").symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    result = discover_python_files(project, (Path("linked/child.py"),))

    assert result.files == ()
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("linked", "PYA1004")
    ]


def test_configured_size_limit_and_explicit_built_in_exclusion(
    tmp_path: Path,
) -> None:
    """The configured byte bound applies while built-ins remain unconditionally out."""
    (tmp_path / "large.py").write_bytes(b"1234")
    build = tmp_path / "build"
    build.mkdir()
    (build / "generated.py").write_text("", encoding="utf-8")

    result = discover_python_files(
        tmp_path,
        (Path("large.py"), Path("build")),
        DiscoveryOptions(max_file_size_bytes=3),
    )

    assert result.files == ()
    assert [(item.relative_path.as_posix(), item.code) for item in result.issues] == [
        ("large.py", "PYA1005")
    ]


def test_authoritative_source_roots_change_module_identity(tmp_path: Path) -> None:
    """Configured roots replace conventional root/src import inference."""
    paths = [
        tmp_path / "lib/widget.py",
        tmp_path / "src/legacy.py",
        tmp_path / "root_module.py",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    result = discover_python_files(tmp_path, ())
    configured = project_module_paths(
        result.files,
        result.issues,
        source_roots=("lib",),
    )
    explicitly_empty = project_module_paths(
        result.files,
        result.issues,
        source_roots=(),
    )

    assert configured == {"widget": (PurePosixPath("lib/widget.py"),)}
    assert explicitly_empty == {}


def test_invalid_gitignore_encoding_is_a_configuration_error(
    tmp_path: Path,
) -> None:
    """Ignore policy is never silently skipped after a decoding failure."""
    (tmp_path / ".gitignore").write_bytes(b"\xff")

    with pytest.raises(DiscoveryError, match="UTF-8"):
        discover_python_files(tmp_path, ())
