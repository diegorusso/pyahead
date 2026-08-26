"""Tests for atomic output-file replacement."""

import ctypes
import os
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import pyahead._windows_output as windows_output_module
import pyahead.output as output_module
from pyahead.output import OutputError, write_text_atomic


def _fake_windows_api(
    **overrides: windows_output_module._CFunction,
) -> windows_output_module._WindowsAPI:
    def succeed(*_arguments: object) -> object:
        return 1

    default = cast("windows_output_module._CFunction", succeed)  # noqa: SLF001
    return windows_output_module._WindowsAPI(  # noqa: SLF001
        create_file=overrides.get("create_file", default),
        close_handle=overrides.get("close_handle", default),
        flush_file_buffers=overrides.get("flush_file_buffers", default),
        get_file_information=overrides.get("get_file_information", default),
        read_file=overrides.get("read_file", default),
        set_file_information=overrides.get("set_file_information", default),
        write_file=overrides.get("write_file", default),
        nt_create_file=overrides.get("nt_create_file", default),
        nt_set_information=overrides.get("nt_set_information", default),
    )


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
        read_file=function,
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


def test_windows_read_directory_chain_does_not_request_write_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read-only dependency inspection never asks to add files to directories."""
    root_access: list[int] = []
    expected_handle = 10

    def create_file(*arguments: object) -> object:
        root_access.append(cast("int", arguments[1]))
        return expected_handle

    def succeed(*_arguments: object) -> object:
        return 1

    create_function = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        create_file,
    )
    function = cast("windows_output_module._CFunction", succeed)  # noqa: SLF001
    api = windows_output_module._WindowsAPI(  # noqa: SLF001
        create_file=create_function,
        close_handle=function,
        flush_file_buffers=function,
        get_file_information=function,
        read_file=function,
        set_file_information=function,
        write_file=function,
        nt_create_file=function,
        nt_set_information=function,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_is_real_directory",
        lambda *_arguments: True,
    )

    handle = windows_output_module._open_root(  # noqa: SLF001
        api, tmp_path, for_write=False
    )
    write_handle = windows_output_module._open_root(  # noqa: SLF001
        api, tmp_path, for_write=True
    )

    assert handle == expected_handle
    assert write_handle == expected_handle
    assert root_access[0] & windows_output_module._FILE_ADD_FILE == 0  # noqa: SLF001
    assert root_access[1] & windows_output_module._FILE_ADD_FILE  # noqa: SLF001

    failed_root_closes: list[int] = []

    def fail_root_validation(*_arguments: object) -> bool:
        message = "simulated GetFileInformationByHandleEx failure"
        raise OSError(message)

    monkeypatch.setattr(
        windows_output_module, "_is_real_directory", fail_root_validation
    )
    monkeypatch.setattr(
        windows_output_module,
        "_close_handle",
        lambda _api, raw_handle: failed_root_closes.append(raw_handle),
    )

    with pytest.raises(OSError, match="GetFileInformation"):
        windows_output_module._open_root(  # noqa: SLF001
            api, tmp_path, for_write=False
        )

    assert failed_root_closes == [expected_handle]

    parent_access: list[int] = []

    def open_relative(
        _api: windows_output_module._WindowsAPI,
        _parent: int,
        _name: str,
        creation: windows_output_module._NtCreateOptions,
    ) -> int:
        parent_access.append(creation.desired_access)
        return 20 + len(parent_access)

    monkeypatch.setattr(
        windows_output_module,
        "_open_root",
        lambda *_arguments, **_kwargs: 20,
    )
    monkeypatch.setattr(windows_output_module, "_nt_create_relative", open_relative)
    monkeypatch.setattr(
        windows_output_module,
        "_require_real_directory",
        lambda *_arguments: None,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_close_handle",
        lambda _api, _handle: None,
    )

    chain = windows_output_module._open_directory_chain(  # noqa: SLF001
        api,
        tmp_path,
        Path("one/two"),
        for_write=False,
    )
    chain.close(api)

    assert parent_access
    assert all(
        access & windows_output_module._FILE_ADD_FILE == 0  # noqa: SLF001
        for access in parent_access
    )

    interrupted_handles: list[int] = []
    opened_parents = 0

    def interrupt_second_parent(
        _api: windows_output_module._WindowsAPI,
        _parent: int,
        _name: str,
        _creation: windows_output_module._NtCreateOptions,
    ) -> int:
        nonlocal opened_parents
        opened_parents += 1
        if opened_parents > 1:
            raise KeyboardInterrupt
        return 21

    monkeypatch.setattr(
        windows_output_module, "_nt_create_relative", interrupt_second_parent
    )
    monkeypatch.setattr(
        windows_output_module,
        "_close_handle",
        lambda _api, handle: interrupted_handles.append(handle),
    )

    with pytest.raises(KeyboardInterrupt):
        windows_output_module._open_directory_chain(  # noqa: SLF001
            api,
            tmp_path,
            Path("one/two"),
            for_write=False,
        )

    assert interrupted_handles == [21, 20]


def test_windows_handle_reader_retains_only_limit_plus_one_bytes() -> None:
    """The Windows ReadFile loop cannot retain an unbounded input payload."""
    payload = b"abcdef"
    requests: list[int] = []

    def read_file(
        _handle: object,
        buffer: object,
        requested: object,
        read_pointer: object,
        _overlapped: object,
    ) -> object:
        size = cast("int", requested)
        requests.append(size)
        chunk = payload[:size]
        windows_output_module.ctypes.memmove(buffer, chunk, len(chunk))
        read_value = windows_output_module.ctypes.cast(
            read_pointer,
            windows_output_module.ctypes.POINTER(windows_output_module._DWORD),  # noqa: SLF001
        )
        read_value.contents.value = len(chunk)
        return 1

    def succeed(*_arguments: object) -> object:
        return 1

    function = cast("windows_output_module._CFunction", succeed)  # noqa: SLF001
    reader = cast("windows_output_module._CFunction", read_file)  # noqa: SLF001
    api = windows_output_module._WindowsAPI(  # noqa: SLF001
        create_file=function,
        close_handle=function,
        flush_file_buffers=function,
        get_file_information=function,
        read_file=reader,
        set_file_information=function,
        write_file=function,
        nt_create_file=function,
        nt_set_information=function,
    )

    result = windows_output_module._read_windows_handle(  # noqa: SLF001
        api, handle=1, limit=2
    )

    assert result == b"abc"
    assert requests == [3]


def test_windows_rooted_reader_uses_relative_handle_and_closes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public Windows reader owns both its leaf and directory handles."""
    closed: list[object] = []
    observed_write_modes: list[bool] = []
    observed_creation: list[windows_output_module._NtCreateOptions] = []
    expected_closed_handles = 2

    def close_handle(handle: object) -> object:
        closed.append(handle)
        return 1

    def succeed(*_arguments: object) -> object:
        return 1

    function = cast("windows_output_module._CFunction", succeed)  # noqa: SLF001
    closer = cast("windows_output_module._CFunction", close_handle)  # noqa: SLF001
    api = windows_output_module._WindowsAPI(  # noqa: SLF001
        create_file=function,
        close_handle=closer,
        flush_file_buffers=function,
        get_file_information=function,
        read_file=function,
        set_file_information=function,
        write_file=function,
        nt_create_file=function,
        nt_set_information=function,
    )
    chain = windows_output_module._WindowsDirectoryChain(handles=(11,))  # noqa: SLF001

    def open_chain(
        _api: windows_output_module._WindowsAPI,
        _root: Path,
        _parent: Path,
        *,
        for_write: bool,
    ) -> windows_output_module._WindowsDirectoryChain:
        observed_write_modes.append(for_write)
        return chain

    def open_leaf(
        _api: windows_output_module._WindowsAPI,
        _parent: int,
        _name: str,
        creation: windows_output_module._NtCreateOptions,
    ) -> int:
        observed_creation.append(creation)
        return 12

    monkeypatch.setattr(windows_output_module, "_windows_api", lambda: api)
    monkeypatch.setattr(windows_output_module, "_open_directory_chain", open_chain)
    monkeypatch.setattr(windows_output_module, "_nt_create_relative", open_leaf)
    monkeypatch.setattr(
        windows_output_module, "_is_real_file", lambda *_arguments: True
    )
    monkeypatch.setattr(
        windows_output_module,
        "_read_windows_handle",
        lambda *_arguments: b"payload",
    )

    result = windows_output_module.read_windows_rooted_file(
        tmp_path,
        Path("nested/input.metadata"),
        limit=64,
    )

    assert result == b"payload"
    assert observed_write_modes == [False]
    assert observed_creation[0].desired_access & windows_output_module._FILE_READ_DATA  # noqa: SLF001
    assert observed_creation[0].share_access == windows_output_module._FILE_SHARE_READ  # noqa: SLF001
    assert not (
        observed_creation[0].share_access & windows_output_module._FILE_SHARE_WRITE  # noqa: SLF001
    )
    assert not (
        observed_creation[0].options & windows_output_module._FILE_NON_DIRECTORY_FILE  # noqa: SLF001
    )
    assert len(closed) == expected_closed_handles

    with pytest.raises(OSError, match="alternate data streams"):
        windows_output_module.read_windows_rooted_file(
            tmp_path,
            Path("input:stream"),
            limit=64,
        )


def test_windows_api_configuration_binds_all_required_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The loader configures each required kernel and NT entry point."""
    loaded: list[tuple[str, bool]] = []

    def new_function() -> windows_output_module._CFunction:
        def function(*_arguments: object) -> object:
            return 1

        return cast("windows_output_module._CFunction", function)  # noqa: SLF001

    kernel32 = SimpleNamespace(
        CreateFileW=new_function(),
        CloseHandle=new_function(),
        FlushFileBuffers=new_function(),
        GetFileInformationByHandleEx=new_function(),
        ReadFile=new_function(),
        SetFileInformationByHandle=new_function(),
        WriteFile=new_function(),
    )
    ntdll = SimpleNamespace(
        NtCreateFile=new_function(),
        NtSetInformationFile=new_function(),
    )

    def factory(name: str, *, use_last_error: bool) -> object:
        loaded.append((name, use_last_error))
        return kernel32 if name == "kernel32" else ntdll

    monkeypatch.setattr(windows_output_module.ctypes, "WinDLL", factory, raising=False)

    api = windows_output_module._windows_api()  # noqa: SLF001

    assert loaded == [("kernel32", True), ("ntdll", True)]
    bindings = (
        (api.create_file, kernel32.CreateFileW, 7, windows_output_module._HANDLE),  # noqa: SLF001
        (api.close_handle, kernel32.CloseHandle, 1, ctypes.c_int),
        (api.flush_file_buffers, kernel32.FlushFileBuffers, 1, ctypes.c_int),
        (
            api.get_file_information,
            kernel32.GetFileInformationByHandleEx,
            4,
            ctypes.c_int,
        ),
        (api.read_file, kernel32.ReadFile, 5, ctypes.c_int),
        (
            api.set_file_information,
            kernel32.SetFileInformationByHandle,
            4,
            ctypes.c_int,
        ),
        (api.write_file, kernel32.WriteFile, 5, ctypes.c_int),
        (
            api.nt_create_file,
            ntdll.NtCreateFile,
            11,
            windows_output_module._NTSTATUS,  # noqa: SLF001
        ),
        (
            api.nt_set_information,
            ntdll.NtSetInformationFile,
            5,
            windows_output_module._NTSTATUS,  # noqa: SLF001
        ),
    )
    for configured, native, argument_count, result_type in bindings:
        assert configured is native
        assert len(configured.argtypes) == argument_count
        assert configured.restype is result_type

    def unavailable(_factory: object) -> windows_output_module._WindowsAPI:
        message = "missing entry point"
        raise AttributeError(message)

    monkeypatch.setattr(windows_output_module, "_configured_windows_api", unavailable)
    with pytest.raises(OSError, match="APIs are unavailable") as captured:
        windows_output_module._windows_api()  # noqa: SLF001
    assert isinstance(captured.value.__cause__, AttributeError)


def test_windows_path_and_attribute_helpers_cover_reparse_failures(
    tmp_path: Path,
) -> None:
    """Path rendering and attribute checks distinguish real files from reparses."""
    assert (
        windows_output_module._extended_path(  # noqa: SLF001
            Path(r"\\?\C:\project")
        )
        == r"\\?\C:\project"
    )
    assert (
        windows_output_module._extended_path(  # noqa: SLF001
            Path(r"\\server\share\folder")
        )
        == r"\\?\UNC\server\share\folder"
    )
    assert windows_output_module._extended_path(tmp_path).startswith("\\\\?\\")  # noqa: SLF001

    attributes = windows_output_module._FILE_ATTRIBUTE_DIRECTORY  # noqa: SLF001

    def get_information(
        _handle: object,
        _information_class: object,
        information_pointer: object,
        _size: object,
    ) -> object:
        information = windows_output_module.ctypes.cast(
            information_pointer,
            windows_output_module.ctypes.POINTER(
                windows_output_module._FileAttributeTagInfo  # noqa: SLF001
            ),
        )
        information.contents.file_attributes = attributes
        return 1

    getter = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        get_information,
    )
    api = _fake_windows_api(get_file_information=getter)

    assert windows_output_module._is_real_directory(api, 3)  # noqa: SLF001
    assert not windows_output_module._is_real_file(api, 3)  # noqa: SLF001

    attributes = 0
    assert windows_output_module._is_real_file(api, 3)  # noqa: SLF001
    assert not windows_output_module._is_real_directory(api, 3)  # noqa: SLF001

    attributes = windows_output_module._FILE_ATTRIBUTE_DIRECTORY  # noqa: SLF001
    attributes |= windows_output_module._FILE_ATTRIBUTE_REPARSE_POINT  # noqa: SLF001
    assert not windows_output_module._is_real_directory(api, 3)  # noqa: SLF001
    assert not windows_output_module._is_real_file(api, 3)  # noqa: SLF001
    with pytest.raises(OSError, match="trusted root"):
        windows_output_module._require_real_root(api, 3)  # noqa: SLF001
    with pytest.raises(OSError, match="path parents"):
        windows_output_module._require_real_directory(api, 3)  # noqa: SLF001

    failing = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        lambda *_arguments: 0,
    )
    with pytest.raises(OSError, match="GetFileInformationByHandleEx failed"):
        windows_output_module._is_real_file(  # noqa: SLF001
            _fake_windows_api(get_file_information=failing),
            3,
        )


def test_windows_nt_relative_open_success_and_failures() -> None:
    """NT relative opens reject both failed statuses and absent handles."""
    creation = windows_output_module._NtCreateOptions(  # noqa: SLF001
        desired_access=1,
        share_access=2,
        disposition=3,
        attributes=4,
        options=5,
    )

    expected_handle = 42

    def open_handle(handle_pointer: object, *_arguments: object) -> object:
        handle = windows_output_module.ctypes.cast(
            handle_pointer,
            windows_output_module.ctypes.POINTER(windows_output_module._HANDLE),  # noqa: SLF001
        )
        handle.contents.value = expected_handle
        return 0

    opener = cast("windows_output_module._CFunction", open_handle)  # noqa: SLF001
    assert (
        windows_output_module._nt_create_relative(  # noqa: SLF001
            _fake_windows_api(nt_create_file=opener),
            7,
            "artifact.whl",
            creation,
        )
        == expected_handle
    )

    failed = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        lambda *_arguments: -1,
    )
    with pytest.raises(OSError, match=r"NTSTATUS 0xffffffff"):
        windows_output_module._nt_create_relative(  # noqa: SLF001
            _fake_windows_api(nt_create_file=failed),
            7,
            "artifact.whl",
            creation,
        )

    invalid = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        lambda *_arguments: 0,
    )
    with pytest.raises(OSError, match="invalid handle"):
        windows_output_module._nt_create_relative(  # noqa: SLF001
            _fake_windows_api(nt_create_file=invalid),
            7,
            "artifact.whl",
            creation,
        )

    oversized = "x" * (windows_output_module._MAX_UNICODE_STRING_BYTES // 2 + 1)  # noqa: SLF001
    with pytest.raises(OSError, match="component is too long"):
        windows_output_module._unicode_string(oversized)  # noqa: SLF001


def test_windows_temporary_open_retries_only_name_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Temporary allocation retries collisions but propagates other failures."""
    attempts = 0
    expected_attempts = 2
    expected_handle = 44
    operation = "NtCreateFile"

    def collide_once(*_arguments: object) -> int:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise windows_output_module._NtStatusError(  # noqa: SLF001
                operation,
                windows_output_module._STATUS_OBJECT_NAME_COLLISION,  # noqa: SLF001
            )
        return expected_handle

    monkeypatch.setattr(windows_output_module, "_nt_create_relative", collide_once)
    assert (
        windows_output_module._create_temporary_handle(  # noqa: SLF001
            _fake_windows_api(),
            3,
            "report.json",
        )
        == expected_handle
    )
    assert attempts == expected_attempts

    def deny(*_arguments: object) -> int:
        raise windows_output_module._NtStatusError(operation, -2)  # noqa: SLF001

    monkeypatch.setattr(windows_output_module, "_nt_create_relative", deny)
    with pytest.raises(OSError, match=r"NTSTATUS 0xfffffffe"):
        windows_output_module._create_temporary_handle(  # noqa: SLF001
            _fake_windows_api(),
            3,
            "report.json",
        )

    monkeypatch.setattr(windows_output_module, "_TEMPORARY_ATTEMPTS", 2)

    def collide(*_arguments: object) -> int:
        raise windows_output_module._NtStatusError(  # noqa: SLF001
            operation,
            windows_output_module._STATUS_OBJECT_NAME_COLLISION,  # noqa: SLF001
        )

    monkeypatch.setattr(windows_output_module, "_nt_create_relative", collide)
    with pytest.raises(OSError, match="allocate a unique"):
        windows_output_module._create_temporary_handle(  # noqa: SLF001
            _fake_windows_api(),
            3,
            "report.json",
        )


def test_windows_handle_io_reports_partial_and_failed_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle I/O is chunked and fails closed on partial or failed API calls."""
    writes: list[bytes] = []

    def write_file(
        _handle: object,
        buffer: object,
        requested: object,
        written_pointer: object,
        _overlapped: object,
    ) -> object:
        size = cast("int", requested)
        writes.append(windows_output_module.ctypes.string_at(buffer, size))
        written = windows_output_module.ctypes.cast(
            written_pointer,
            windows_output_module.ctypes.POINTER(windows_output_module._DWORD),  # noqa: SLF001
        )
        written.contents.value = size
        return 1

    writer = cast("windows_output_module._CFunction", write_file)  # noqa: SLF001
    monkeypatch.setattr(windows_output_module, "_WRITE_CHUNK_BYTES", 2)
    windows_output_module._write_windows_handle(  # noqa: SLF001
        _fake_windows_api(write_file=writer),
        5,
        "abc",
    )
    assert writes == [b"ab", b"c"]

    def partial_write(
        _handle: object,
        _buffer: object,
        _requested: object,
        written_pointer: object,
        _overlapped: object,
    ) -> object:
        written = windows_output_module.ctypes.cast(
            written_pointer,
            windows_output_module.ctypes.POINTER(windows_output_module._DWORD),  # noqa: SLF001
        )
        written.contents.value = 0
        return 1

    partial = cast("windows_output_module._CFunction", partial_write)  # noqa: SLF001
    with pytest.raises(OSError, match="partial output write"):
        windows_output_module._write_windows_handle(  # noqa: SLF001
            _fake_windows_api(write_file=partial),
            5,
            "x",
        )

    failed = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        lambda *_arguments: 0,
    )
    with pytest.raises(OSError, match="ReadFile failed"):
        windows_output_module._read_windows_handle(  # noqa: SLF001
            _fake_windows_api(read_file=failed),
            5,
            3,
        )

    def end_of_file(
        _handle: object,
        _buffer: object,
        _requested: object,
        read_pointer: object,
        _overlapped: object,
    ) -> object:
        read = windows_output_module.ctypes.cast(
            read_pointer,
            windows_output_module.ctypes.POINTER(windows_output_module._DWORD),  # noqa: SLF001
        )
        read.contents.value = 0
        return 1

    reader = cast("windows_output_module._CFunction", end_of_file)  # noqa: SLF001
    assert (
        windows_output_module._read_windows_handle(  # noqa: SLF001
            _fake_windows_api(read_file=reader),
            5,
            3,
        )
        == b""
    )


def test_windows_atomic_writer_cleans_handles_on_success_and_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic replacement deletes only failed temporaries and closes all handles."""
    closed: list[int] = []
    deleted: list[int] = []

    def close_handle(handle: object) -> object:
        closed.append(cast("windows_output_module._HANDLE", handle).value or 0)  # noqa: SLF001
        return 1

    closer = cast("windows_output_module._CFunction", close_handle)  # noqa: SLF001
    api = _fake_windows_api(close_handle=closer)
    chain = windows_output_module._WindowsDirectoryChain(handles=(8, 9))  # noqa: SLF001
    monkeypatch.setattr(windows_output_module, "_windows_api", lambda: api)
    monkeypatch.setattr(
        windows_output_module,
        "_open_directory_chain",
        lambda *_arguments, **_keywords: chain,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_create_temporary_handle",
        lambda *_arguments: 10,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_write_windows_handle",
        lambda *_arguments: None,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_replace_windows_handle",
        lambda *_arguments: None,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_delete_windows_handle",
        lambda _api, handle: deleted.append(handle),
    )

    windows_output_module.write_windows_atomic(
        tmp_path,
        Path("reports/report.json"),
        "payload",
    )
    assert deleted == []
    assert closed == [10, 9, 8]

    closed.clear()

    def fail_write(*_arguments: object) -> None:
        message = "simulated write failure"
        raise OSError(message)

    monkeypatch.setattr(windows_output_module, "_write_windows_handle", fail_write)
    with pytest.raises(OSError, match="simulated write failure"):
        windows_output_module.write_windows_atomic(
            tmp_path,
            Path("reports/report.json"),
            "payload",
        )
    assert deleted == [10]
    assert closed == [10, 9, 8]

    closed.clear()

    def interrupt_delete(_api: object, _handle: int) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(
        windows_output_module,
        "_delete_windows_handle",
        interrupt_delete,
    )
    with pytest.raises(KeyboardInterrupt):
        windows_output_module.write_windows_atomic(
            tmp_path,
            Path("reports/report.json"),
            "payload",
        )
    assert closed == [10, 9, 8]

    with pytest.raises(OSError, match="alternate data streams"):
        windows_output_module.write_windows_atomic(
            tmp_path,
            Path("report:stream"),
            "payload",
        )


def test_windows_temporary_deletion_checks_native_result() -> None:
    """Temporary cleanup distinguishes a confirmed delete from native failure."""
    calls: list[int] = []

    def delete(
        handle: object,
        _information_class: object,
        _information: object,
        _size: object,
    ) -> object:
        calls.append(cast("windows_output_module._HANDLE", handle).value or 0)  # noqa: SLF001
        return 1

    deletion = cast("windows_output_module._CFunction", delete)  # noqa: SLF001
    windows_output_module._delete_windows_handle(  # noqa: SLF001
        _fake_windows_api(set_file_information=deletion),
        17,
    )
    assert calls == [17]

    failed = cast(
        "windows_output_module._CFunction",  # noqa: SLF001
        lambda *_arguments: 0,
    )
    with pytest.raises(OSError, match="FileDispositionInfo"):
        windows_output_module._delete_windows_handle(  # noqa: SLF001
            _fake_windows_api(set_file_information=failed),
            17,
        )


def test_windows_rooted_reader_rejects_non_regular_leaf_and_closes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reparse or directory leaf is rejected while every handle is retained."""
    closed: list[int] = []

    def close_handle(handle: object) -> object:
        closed.append(cast("windows_output_module._HANDLE", handle).value or 0)  # noqa: SLF001
        return 1

    closer = cast("windows_output_module._CFunction", close_handle)  # noqa: SLF001
    api = _fake_windows_api(close_handle=closer)
    chain = windows_output_module._WindowsDirectoryChain(handles=(12,))  # noqa: SLF001
    monkeypatch.setattr(windows_output_module, "_windows_api", lambda: api)
    monkeypatch.setattr(
        windows_output_module,
        "_open_directory_chain",
        lambda *_arguments, **_keywords: chain,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_nt_create_relative",
        lambda *_arguments: 13,
    )
    monkeypatch.setattr(
        windows_output_module,
        "_is_real_file",
        lambda *_arguments: False,
    )

    with pytest.raises(OSError, match="real regular file"):
        windows_output_module.read_windows_rooted_file(
            tmp_path,
            Path("nested/artifact.whl"),
            64,
        )
    assert closed == [13, 12]


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
