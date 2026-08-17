"""Handle-anchored, reparse-safe output replacement for Windows."""

from __future__ import annotations

import ctypes
import secrets
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from pathlib import Path

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_ULONG = ctypes.c_uint32
_USHORT = ctypes.c_uint16
_NTSTATUS = ctypes.c_int32

_DELETE = 0x00010000
_FILE_LIST_DIRECTORY = 0x00000001
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_TRAVERSE = 0x00000020
_FILE_WRITE_DATA = 0x00000002
_SYNCHRONIZE = 0x00100000

_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002

_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ATTRIBUTE_TEMPORARY = 0x00000100
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

_OPEN_EXISTING = 3
_FILE_OPEN = 1
_FILE_CREATE = 2
_FILE_DIRECTORY_FILE = 0x00000001
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_FILE_NON_DIRECTORY_FILE = 0x00000040
_FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000
_FILE_OPEN_REPARSE_POINT = 0x00200000

_OBJ_CASE_INSENSITIVE = 0x00000040
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_RENAME_INFO_CLASS = 3
_FILE_DISPOSITION_INFO_CLASS = 4
_FILE_RENAME_REPLACE_IF_EXISTS = 0x00000001
_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
_TEMPORARY_ATTEMPTS = 128
_WRITE_CHUNK_BYTES = 1024 * 1024
_MAX_UNICODE_STRING_BYTES = 0xFFFC


class _CFunction(Protocol):
    argtypes: list[object]
    restype: object

    def __call__(self, *arguments: object) -> object: ...


class _WinDLLFactory(Protocol):
    def __call__(self, name: str, *, use_last_error: bool) -> object: ...


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", _USHORT),
        ("maximum_length", _USHORT),
        ("buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", _ULONG),
        ("root_directory", _HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", _ULONG),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("status_or_pointer", ctypes.c_void_p),
        ("information", ctypes.c_size_t),
    ]


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("file_attributes", _DWORD), ("reparse_tag", _DWORD)]


class _FileRenameInfo(ctypes.Structure):
    _fields_ = [
        ("flags", _DWORD),
        ("root_directory", _HANDLE),
        ("file_name_length", _DWORD),
        ("file_name", ctypes.c_wchar * 1),
    ]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


@dataclass(frozen=True)
class _WindowsAPI:
    create_file: _CFunction
    close_handle: _CFunction
    flush_file_buffers: _CFunction
    get_file_information: _CFunction
    set_file_information: _CFunction
    write_file: _CFunction
    nt_create_file: _CFunction


@dataclass(frozen=True)
class _NtCreateOptions:
    desired_access: int
    share_access: int
    disposition: int
    attributes: int
    options: int


@dataclass(frozen=True)
class _WindowsDirectoryChain:
    handles: tuple[int, ...]

    @property
    def parent_handle(self) -> int:
        return self.handles[-1]

    def close(self, api: _WindowsAPI) -> None:
        for handle in reversed(self.handles):
            _close_handle(api, handle)


class _NtStatusError(OSError):
    def __init__(self, operation: str, status: int) -> None:
        self.status = status & 0xFFFFFFFF
        super().__init__(f"{operation} failed with NTSTATUS 0x{self.status:08x}")


def _function(
    library: object,
    name: str,
    argument_types: list[object],
    result_type: object,
) -> _CFunction:
    function = cast("_CFunction", getattr(library, name))
    function.argtypes = argument_types
    function.restype = result_type
    return function


def _windows_api() -> _WindowsAPI:
    factory_value = getattr(ctypes, "WinDLL", None)
    if factory_value is None:
        message = "secure root-bounded output is unavailable on this platform"
        raise OSError(message)
    factory = cast("_WinDLLFactory", factory_value)
    try:
        return _configured_windows_api(factory)
    except (AttributeError, OSError) as error:
        message = "secure root-bounded output APIs are unavailable on Windows"
        raise OSError(message) from error


def _configured_windows_api(factory: _WinDLLFactory) -> _WindowsAPI:
    kernel32 = factory("kernel32", use_last_error=True)
    ntdll = factory("ntdll", use_last_error=True)
    return _WindowsAPI(
        create_file=_function(
            kernel32,
            "CreateFileW",
            [
                ctypes.c_wchar_p,
                _DWORD,
                _DWORD,
                ctypes.c_void_p,
                _DWORD,
                _DWORD,
                _HANDLE,
            ],
            _HANDLE,
        ),
        close_handle=_function(kernel32, "CloseHandle", [_HANDLE], ctypes.c_int),
        flush_file_buffers=_function(
            kernel32,
            "FlushFileBuffers",
            [_HANDLE],
            ctypes.c_int,
        ),
        get_file_information=_function(
            kernel32,
            "GetFileInformationByHandleEx",
            [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD],
            ctypes.c_int,
        ),
        set_file_information=_function(
            kernel32,
            "SetFileInformationByHandle",
            [_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD],
            ctypes.c_int,
        ),
        write_file=_function(
            kernel32,
            "WriteFile",
            [_HANDLE, ctypes.c_void_p, _DWORD, ctypes.POINTER(_DWORD), ctypes.c_void_p],
            ctypes.c_int,
        ),
        nt_create_file=_function(
            ntdll,
            "NtCreateFile",
            [
                ctypes.POINTER(_HANDLE),
                _DWORD,
                ctypes.POINTER(_ObjectAttributes),
                ctypes.POINTER(_IoStatusBlock),
                ctypes.c_void_p,
                _DWORD,
                _DWORD,
                _DWORD,
                _DWORD,
                ctypes.c_void_p,
                _DWORD,
            ],
            _NTSTATUS,
        ),
    )


def _close_handle(api: _WindowsAPI, handle: int) -> None:
    with suppress(Exception):
        api.close_handle(_HANDLE(handle))


def _extended_path(path: Path) -> str:
    rendered = str(path)
    if rendered.startswith("\\\\?\\"):
        return rendered
    if rendered.startswith("\\\\"):
        return f"\\\\?\\UNC\\{rendered[2:]}"
    return f"\\\\?\\{rendered}"


def _require_success(result: object, operation: str) -> None:
    if not bool(result):
        message = f"{operation} failed"
        raise OSError(message)


def _is_real_directory(api: _WindowsAPI, handle: int) -> bool:
    information = _FileAttributeTagInfo()
    _require_success(
        api.get_file_information(
            _HANDLE(handle),
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ),
        "GetFileInformationByHandleEx",
    )
    return bool(
        information.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
        and not information.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _open_root(api: _WindowsAPI, root: Path) -> int:
    raw_handle = api.create_file(
        _extended_path(root),
        _FILE_LIST_DIRECTORY | _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    handle = cast("int | None", raw_handle)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid_handle:
        message = "unable to open the trusted output root without reparses"
        raise OSError(message)
    if not _is_real_directory(api, handle):
        _close_handle(api, handle)
        message = "trusted output root must be a real directory"
        raise OSError(message)
    return handle


def _unicode_string(name: str) -> tuple[_UnicodeString, ctypes.Array[ctypes.c_wchar]]:
    encoded_length = len(name.encode("utf-16-le"))
    if encoded_length > _MAX_UNICODE_STRING_BYTES:
        message = "Windows output path component is too long"
        raise OSError(message)
    buffer = ctypes.create_unicode_buffer(name)
    value = _UnicodeString(
        length=encoded_length,
        maximum_length=encoded_length + 2,
        buffer=ctypes.cast(buffer, ctypes.c_wchar_p),
    )
    return value, buffer


def _nt_create_relative(
    api: _WindowsAPI,
    parent_handle: int,
    name: str,
    creation: _NtCreateOptions,
) -> int:
    object_name, name_buffer = _unicode_string(name)
    object_attributes = _ObjectAttributes(
        length=ctypes.sizeof(_ObjectAttributes),
        root_directory=_HANDLE(parent_handle),
        object_name=ctypes.pointer(object_name),
        attributes=_OBJ_CASE_INSENSITIVE,
        security_descriptor=None,
        security_quality_of_service=None,
    )
    status_block = _IoStatusBlock()
    handle = _HANDLE()
    status = cast(
        "int",
        api.nt_create_file(
            ctypes.byref(handle),
            creation.desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(status_block),
            None,
            creation.attributes,
            creation.share_access,
            creation.disposition,
            creation.options,
            None,
            0,
        ),
    )
    del name_buffer
    if status < 0:
        operation = "NtCreateFile"
        raise _NtStatusError(operation, status)
    if handle.value is None:
        message = "NtCreateFile returned an invalid handle"
        raise OSError(message)
    return handle.value


def _open_directory_chain(
    api: _WindowsAPI,
    root: Path,
    relative_parent: Path,
) -> _WindowsDirectoryChain:
    handles = [_open_root(api, root)]
    try:
        for name in relative_parent.parts:
            handle = _nt_create_relative(
                api,
                handles[-1],
                name,
                _NtCreateOptions(
                    desired_access=(
                        _FILE_LIST_DIRECTORY
                        | _FILE_TRAVERSE
                        | _FILE_READ_ATTRIBUTES
                        | _SYNCHRONIZE
                    ),
                    share_access=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
                    disposition=_FILE_OPEN,
                    attributes=0,
                    options=(
                        _FILE_DIRECTORY_FILE
                        | _FILE_SYNCHRONOUS_IO_NONALERT
                        | _FILE_OPEN_FOR_BACKUP_INTENT
                        | _FILE_OPEN_REPARSE_POINT
                    ),
                ),
            )
            handles.append(handle)
            _require_real_directory(api, handle)
    except Exception:
        for handle in reversed(handles):
            _close_handle(api, handle)
        raise
    return _WindowsDirectoryChain(handles=tuple(handles))


def _require_real_directory(api: _WindowsAPI, handle: int) -> None:
    if not _is_real_directory(api, handle):
        message = "output parents must be real directories"
        raise OSError(message)


def _create_temporary_handle(
    api: _WindowsAPI,
    parent_handle: int,
    destination_name: str,
) -> int:
    for _ in range(_TEMPORARY_ATTEMPTS):
        name = f".{destination_name}.{secrets.token_hex(8)}.tmp"
        try:
            return _nt_create_relative(
                api,
                parent_handle,
                name,
                _NtCreateOptions(
                    desired_access=_FILE_WRITE_DATA | _DELETE | _SYNCHRONIZE,
                    share_access=0,
                    disposition=_FILE_CREATE,
                    attributes=_FILE_ATTRIBUTE_TEMPORARY,
                    options=(
                        _FILE_NON_DIRECTORY_FILE
                        | _FILE_SYNCHRONOUS_IO_NONALERT
                        | _FILE_OPEN_REPARSE_POINT
                    ),
                ),
            )
        except _NtStatusError as error:
            if error.status != _STATUS_OBJECT_NAME_COLLISION:
                raise
    message = "unable to allocate a unique output temporary file"
    raise OSError(message)


def _write_windows_handle(api: _WindowsAPI, handle: int, content: str) -> None:
    data = content.encode("utf-8")
    for start in range(0, len(data), _WRITE_CHUNK_BYTES):
        chunk = data[start : start + _WRITE_CHUNK_BYTES]
        buffer = ctypes.create_string_buffer(chunk, len(chunk))
        written = _DWORD()
        _require_success(
            api.write_file(
                _HANDLE(handle),
                ctypes.byref(buffer),
                len(chunk),
                ctypes.byref(written),
                None,
            ),
            "WriteFile",
        )
        if written.value != len(chunk):
            message = "WriteFile performed a partial output write"
            raise OSError(message)
    _require_success(
        api.flush_file_buffers(_HANDLE(handle)),
        "FlushFileBuffers",
    )


def _replace_windows_handle(
    api: _WindowsAPI,
    temporary_handle: int,
    parent_handle: int,
    destination_name: str,
) -> None:
    encoded_name = destination_name.encode("utf-16-le")
    name_offset = _FileRenameInfo.file_name.offset
    buffer = ctypes.create_string_buffer(
        ctypes.sizeof(_FileRenameInfo) + len(encoded_name)
    )
    information = _FileRenameInfo.from_buffer(buffer)
    information.flags = _FILE_RENAME_REPLACE_IF_EXISTS
    information.root_directory = _HANDLE(parent_handle)
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + name_offset,
        encoded_name,
        len(encoded_name),
    )
    _require_success(
        api.set_file_information(
            _HANDLE(temporary_handle),
            _FILE_RENAME_INFO_CLASS,
            ctypes.byref(buffer),
            len(buffer),
        ),
        "SetFileInformationByHandle(FileRenameInfo)",
    )


def _delete_windows_handle(api: _WindowsAPI, handle: int) -> None:
    information = _FileDispositionInfo(delete_file=1)
    with suppress(Exception):
        api.set_file_information(
            _HANDLE(handle),
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )


def write_windows_atomic(root: Path, relative_path: Path, content: str) -> None:
    """Replace one file through parent handles that cannot traverse reparses."""
    if ":" in relative_path.name:
        message = "Windows output destinations cannot name alternate data streams"
        raise OSError(message)
    api = _windows_api()
    chain = _open_directory_chain(api, root, relative_path.parent)
    temporary_handle: int | None = None
    replaced = False
    try:
        temporary_handle = _create_temporary_handle(
            api,
            chain.parent_handle,
            relative_path.name,
        )
        _write_windows_handle(api, temporary_handle, content)
        _replace_windows_handle(
            api,
            temporary_handle,
            chain.parent_handle,
            relative_path.name,
        )
        replaced = True
    finally:
        if temporary_handle is not None:
            if not replaced:
                _delete_windows_handle(api, temporary_handle)
            _close_handle(api, temporary_handle)
        chain.close(api)


__all__ = ["write_windows_atomic"]
