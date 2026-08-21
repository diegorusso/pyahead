"""Tests for atomic output-file replacement."""

import os
from pathlib import Path
from typing import cast

import pytest

import pyahead._windows_output as windows_output_module
import pyahead.output as output_module
from pyahead.output import OutputError, write_text_atomic


def test_atomic_output_replaces_only_after_complete_write(tmp_path: Path) -> None:
    """A successful write leaves complete content and no sibling temporary."""
    destination = tmp_path / "report.json"
    destination.write_text("old", encoding="utf-8")

    write_text_atomic(destination, "new\n")

    assert destination.read_text(encoding="utf-8") == "new\n"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_atomic_output_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-replace failure cannot truncate the existing destination."""
    destination = tmp_path / "report.json"
    destination.write_text("old", encoding="utf-8")

    def fail_fsync(_descriptor: int) -> None:
        message = "simulated fsync failure"
        raise OSError(message)

    monkeypatch.setattr(os, "fsync", fail_fsync)

    with pytest.raises(OutputError):
        write_text_atomic(destination, "new\n")

    assert destination.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_atomic_output_requires_an_existing_parent(tmp_path: Path) -> None:
    """Destination setup failures use the stable output exception."""
    with pytest.raises(OutputError):
        write_text_atomic(tmp_path / "missing/report.json", "{}\n")


def test_root_bounded_output_replaces_within_pinned_parent(tmp_path: Path) -> None:
    """The root-aware path retains ordinary atomic replacement semantics."""
    if not output_module._supports_pinned_directories():  # noqa: SLF001
        pytest.skip("secure directory-relative replacement is unavailable")
    reports = tmp_path / "reports"
    reports.mkdir()
    destination = reports / "report.json"
    destination.write_text("old\n", encoding="utf-8")

    write_text_atomic(destination, "new\n", root=tmp_path)

    assert destination.read_text(encoding="utf-8") == "new\n"
    assert list(reports.glob(".report.json.*.tmp")) == []


def test_root_bounded_output_dispatches_to_windows_handle_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The non-dir-fd Windows branch never falls back to path replacement."""
    reports = tmp_path / "reports"
    reports.mkdir()
    destination = reports / "report.json"
    destination.write_text("old\n", encoding="utf-8")
    observed: list[tuple[Path, Path, str]] = []

    def fake_windows_write(root: Path, relative: Path, content: str) -> None:
        observed.append((root, relative, content))

    monkeypatch.setattr(output_module, "_supports_pinned_directories", lambda: False)
    monkeypatch.setattr(output_module, "_supports_windows_handles", lambda: True)
    monkeypatch.setattr(output_module, "write_windows_atomic", fake_windows_write)

    write_text_atomic(destination, "new\n", root=tmp_path)

    assert observed == [(tmp_path.resolve(), Path("reports/report.json"), "new\n")]
    assert destination.read_text(encoding="utf-8") == "old\n"


def test_root_bounded_windows_output_fails_closed_without_handle_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing Windows APIs cannot reactivate path-based replacement."""
    destination = tmp_path / "report.json"
    destination.write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(output_module, "_supports_pinned_directories", lambda: False)
    monkeypatch.setattr(output_module, "_supports_windows_handles", lambda: True)
    monkeypatch.setattr(
        windows_output_module.ctypes,
        "WinDLL",
        None,
        raising=False,
    )

    with pytest.raises(OutputError):
        write_text_atomic(destination, "new\n", root=tmp_path)

    assert destination.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".report.json.*.tmp")) == []


def test_windows_rename_buffer_includes_complete_structure() -> None:
    """The variable rename buffer satisfies the documented Windows ABI size."""
    calls: list[tuple[object, ...]] = []

    def record_call(*arguments: object) -> object:
        calls.append(arguments)
        return 1

    function = cast("windows_output_module._CFunction", record_call)  # noqa: SLF001
    api = windows_output_module._WindowsAPI(  # noqa: SLF001
        create_file=function,
        close_handle=function,
        flush_file_buffers=function,
        get_file_information=function,
        set_file_information=function,
        write_file=function,
        nt_create_file=function,
        nt_set_information=function,
    )
    destination_name = "report.json"

    windows_output_module._replace_windows_handle(  # noqa: SLF001
        api,
        temporary_handle=1,
        parent_handle=2,
        destination_name=destination_name,
    )

    assert len(calls) == 1
    buffer_size = cast("int", calls[0][3])
    assert buffer_size == max(
        windows_output_module.ctypes.sizeof(
            windows_output_module._FileRenameInformation,  # noqa: SLF001
        ),
        windows_output_module._FileRenameInformation.file_name.offset  # noqa: SLF001
        + len(destination_name.encode("utf-16-le")),
    )


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_root_bounded_output_replaces_with_handle_anchoring(
    tmp_path: Path,
) -> None:
    """Windows creates and replaces an output relative to pinned parents."""
    reports = tmp_path / "reports"
    reports.mkdir()
    destination = reports / "report.json"
    destination.write_text("old\n", encoding="utf-8")

    write_text_atomic(destination, "new\n", root=tmp_path)

    assert destination.read_text(encoding="utf-8") == "new\n"
    assert list(reports.glob(".report.json.*.tmp")) == []


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory handles")
def test_windows_parent_swap_at_final_replace_cannot_redirect_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned Windows parents block a reparse swap at the replace boundary."""
    project = tmp_path / "project"
    reports = project / "reports"
    archived = project / "reports-before-swap"
    outside = tmp_path / "outside"
    reports.mkdir(parents=True)
    outside.mkdir()
    outside_destination = outside / "report.json"
    outside_destination.write_text("outside sentinel\n", encoding="utf-8")

    original_replace = windows_output_module._replace_windows_handle  # noqa: SLF001
    swap_errors: list[OSError] = []

    def attempt_swap_then_replace(
        api: windows_output_module._WindowsAPI,
        temporary_handle: int,
        parent_handle: int,
        destination_name: str,
    ) -> None:
        try:
            reports.rename(archived)
            reports.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            swap_errors.append(error)
        original_replace(api, temporary_handle, parent_handle, destination_name)

    monkeypatch.setattr(
        windows_output_module,
        "_replace_windows_handle",
        attempt_swap_then_replace,
    )

    write_text_atomic(reports / "report.json", "new\n", root=project)

    assert swap_errors
    assert reports.is_dir()
    assert not reports.is_symlink()
    assert (reports / "report.json").read_text(encoding="utf-8") == "new\n"
    assert outside_destination.read_text(encoding="utf-8") == "outside sentinel\n"
    assert not archived.exists()


def test_root_bounded_output_rejects_parent_swap_before_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A validated parent cannot be replaced by an external symlink mid-write."""
    if not output_module._supports_pinned_directories():  # noqa: SLF001
        pytest.skip("secure directory-relative replacement is unavailable")
    project = tmp_path / "project"
    reports = project / "reports"
    archived = project / "reports-before-swap"
    outside = tmp_path / "outside"
    reports.mkdir(parents=True)
    outside.mkdir()
    outside_destination = outside / "report.json"
    outside_destination.write_text("outside sentinel\n", encoding="utf-8")
    probe = project / "symlink-probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")
    probe.unlink()

    original_write = output_module._write_descriptor  # noqa: SLF001
    swapped = False

    def write_then_swap(descriptor: int, content: str) -> None:
        nonlocal swapped
        original_write(descriptor, content)
        reports.rename(archived)
        reports.symlink_to(outside, target_is_directory=True)
        swapped = True

    monkeypatch.setattr(output_module, "_write_descriptor", write_then_swap)

    with pytest.raises(OutputError, match="directory changed"):
        write_text_atomic(reports / "report.json", "new\n", root=project)

    assert swapped is True
    assert outside_destination.read_text(encoding="utf-8") == "outside sentinel\n"
    assert list(outside.glob(".report.json.*.tmp")) == []
    assert not (archived / "report.json").exists()
    assert list(archived.glob(".report.json.*.tmp")) == []


def test_root_bounded_output_fails_closed_without_pinned_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsupported platform cannot redirect a root-bounded temporary outside."""
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    outside_destination = outside / "report.json"
    outside_destination.write_text("outside sentinel\n", encoding="utf-8")
    try:
        (project / "reports").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit directory symlinks")

    temporary_created = False

    def reject_temporary(*_args: object, **_kwargs: object) -> tuple[int, str]:
        nonlocal temporary_created
        temporary_created = True
        message = "temporary creation must not be reached"
        raise AssertionError(message)

    monkeypatch.setattr(output_module, "_supports_pinned_directories", lambda: False)
    monkeypatch.setattr(output_module, "_supports_windows_handles", lambda: False)
    monkeypatch.setattr(output_module.tempfile, "mkstemp", reject_temporary)

    with pytest.raises(OutputError, match="secure root-bounded output is unavailable"):
        write_text_atomic(
            project / "reports/report.json",
            "new\n",
            root=project,
        )

    assert temporary_created is False
    assert outside_destination.read_text(encoding="utf-8") == "outside sentinel\n"
    assert list(outside.glob(".report.json.*.tmp")) == []
