"""Bounded reading of wheel and sdist archives."""

from __future__ import annotations

import gzip
import struct
import tarfile
import zipfile
import zlib
from io import BytesIO, RawIOBase
from pathlib import Path, PurePosixPath

from packaging.utils import (
    InvalidSdistFilename,
    parse_sdist_filename,
)

from pyahead._fs.errors import EntryChangedError, NotAFilePathError
from pyahead._fs.rooted import (
    RootedReadTooLargeError,
    read_rooted_bytes,
    repository_relative_path,
)
from pyahead.dependencies._model import (
    _ACTIVE_ARCHIVE_BUDGET,
    _MAX_ARCHIVE_EXPANDED_BYTES,
    _MAX_ARCHIVE_MEMBERS,
    _MAX_ARTIFACT_BYTES,
    _MAX_METADATA_BYTES,
    _MAX_TAR_CONTROL_BYTES,
    _MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
    _SUPPORTED_ZIP_COMPRESSION,
    _TAR_BLOCK_SIZE,
    _TAR_CONTROL_TYPES,
    _TAR_READ_CHUNK_BYTES,
    _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE,
    _ZIP_CENTRAL_DIRECTORY_SIGNATURE,
    _ZIP_EOCD,
    _ZIP_EOCD_SIGNATURE,
    _ZIP_EOCD_SIZE,
    _ZIP_MAX_COMMENT_BYTES,
    _ZIP_UINT16_SENTINEL,
    _ZIP_UINT32_SENTINEL,
    MetadataKind,
    _configuration_error,
    _consume_archive_expansion,
    _error,
    _fail_metadata,
    _MetadataError,
    _string,
)
from pyahead.model import ConfigurationError


def _read_artifact(path: Path, root: Path) -> tuple[PurePosixPath, bytes]:
    label = "metadata input"
    selected = path if path.is_absolute() else root / path
    try:
        rooted_relative = repository_relative_path(root, selected)
        relative_text = rooted_relative.as_posix()
        _string(relative_text, label)
        relative = PurePosixPath(relative_text)
        if rooted_relative == Path() or not rooted_relative.name:
            _error(label, "is not a regular file")
        raw = read_rooted_bytes(root, rooted_relative, _MAX_ARTIFACT_BYTES)
    except FileNotFoundError as error:
        raise _configuration_error(label, "does not exist") from error
    except RootedReadTooLargeError as error:
        raise _configuration_error(
            label,
            f"exceeds {_MAX_ARTIFACT_BYTES} bytes",
        ) from error
    except NotAFilePathError as error:
        raise _configuration_error(label, "is not a regular file") from error
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        raise _configuration_error(
            label, "must remain beneath the project root"
        ) from error
    except EntryChangedError as error:
        raise _configuration_error(
            label, "metadata input changed while being read"
        ) from error
    except (OSError, RuntimeError) as error:
        raise _configuration_error(label, "unable to read metadata input") from error
    if len(raw) > _MAX_ARTIFACT_BYTES:
        raise _configuration_error(
            label,
            f"exceeds {_MAX_ARTIFACT_BYTES} bytes",
        )
    return relative, raw


class _ExpandedArchiveReader(RawIOBase):
    """Cap bytes returned from an incrementally decompressed archive stream."""

    def __init__(self, stream: gzip.GzipFile) -> None:
        self._stream = stream
        self._read = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        remaining_with_sentinel = _MAX_ARCHIVE_EXPANDED_BYTES - self._read + 1
        bounded_size = (
            remaining_with_sentinel
            if size < 0 or size > remaining_with_sentinel
            else size
        )
        if (budget := _ACTIVE_ARCHIVE_BUDGET.get()) is not None:
            bounded_size = min(bounded_size, budget.remaining + 1)
        payload = self._stream.read(bounded_size)
        self._read += len(payload)
        _consume_archive_expansion(len(payload))
        if self._read > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        return payload


def _read_exact_archive_bytes(stream: _ExpandedArchiveReader, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        payload = stream.read(min(remaining, _TAR_READ_CHUNK_BYTES))
        if not payload:
            _fail_metadata("invalid tar archive")
        chunks.append(payload)
        remaining -= len(payload)
    return b"".join(chunks)


def _discard_archive_bytes(stream: _ExpandedArchiveReader, size: int) -> None:
    remaining = size
    while remaining:
        payload = stream.read(min(remaining, _TAR_READ_CHUNK_BYTES))
        if not payload:
            _fail_metadata("invalid tar archive")
        remaining -= len(payload)


def _pax_uses_gnu_sparse(payload: bytes) -> bool:
    cursor = 0
    while cursor < len(payload):
        separator = payload.find(b" ", cursor)
        if separator <= cursor or not payload[cursor:separator].isdigit():
            _fail_metadata("invalid tar control metadata")
        record_size = int(payload[cursor:separator])
        record_end = cursor + record_size
        if (
            record_end <= separator + 1
            or record_end > len(payload)
            or payload[record_end - 1 : record_end] != b"\n"
        ):
            _fail_metadata("invalid tar control metadata")
        key, delimiter, _value = payload[separator + 1 : record_end - 1].partition(b"=")
        if not delimiter:
            _fail_metadata("invalid tar control metadata")
        if key.startswith(b"GNU.sparse."):
            return True
        cursor = record_end
    return False


def _tar_member_padded_size(member: tarfile.TarInfo) -> int:
    if member.type == tarfile.GNUTYPE_SPARSE:
        _fail_metadata("sparse tar members are unsupported")
    if member.size < 0:
        _fail_metadata("tar member has a negative size")
    if member.type in _TAR_CONTROL_TYPES and member.size > _MAX_TAR_CONTROL_BYTES:
        _fail_metadata("tar control metadata exceeds the size limit")
    return ((member.size + _TAR_BLOCK_SIZE - 1) // _TAR_BLOCK_SIZE) * _TAR_BLOCK_SIZE


def _discard_tar_member_payload(
    stream: _ExpandedArchiveReader,
    member: tarfile.TarInfo,
    padded_size: int,
) -> None:
    if member.type in {
        tarfile.SOLARIS_XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.XHDTYPE,
    }:
        control = _read_exact_archive_bytes(stream, member.size)
        if _pax_uses_gnu_sparse(control):
            _fail_metadata("GNU sparse tar metadata is unsupported")
        _discard_archive_bytes(stream, padded_size - member.size)
        return
    _discard_archive_bytes(stream, padded_size)


def _check_tar_archive_limits(raw: bytes) -> None:
    """Preflight physical tar headers before tarfile processes control records."""
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as decompressed:
            bounded = _ExpandedArchiveReader(decompressed)
            member_count = 0
            declared_bytes = 0
            while True:
                header = _read_exact_archive_bytes(bounded, _TAR_BLOCK_SIZE)
                if header == b"\0" * _TAR_BLOCK_SIZE:
                    return
                member = tarfile.TarInfo.frombuf(
                    header,
                    encoding="utf-8",
                    errors="surrogateescape",
                )
                member_count += 1
                if member_count > _MAX_ARCHIVE_MEMBERS:
                    _fail_metadata("archive contains too many members")
                padded_size = _tar_member_padded_size(member)
                declared_bytes += _TAR_BLOCK_SIZE + padded_size
                if declared_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
                    _fail_metadata("archive expanded data exceeds the size limit")
                _discard_tar_member_payload(bounded, member, padded_size)
    except _MetadataError:
        raise
    except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError, zlib.error):
        _fail_metadata("invalid tar archive")


def _zip_eocd(raw: bytes) -> tuple[int, tuple[int, ...]]:
    search_start = max(
        0,
        len(raw) - _ZIP_EOCD_SIZE - _ZIP_MAX_COMMENT_BYTES,
    )
    cursor = len(raw)
    while True:
        offset = raw.rfind(_ZIP_EOCD_SIGNATURE, search_start, cursor)
        if offset < 0:
            _fail_metadata("invalid ZIP archive")
        if offset + _ZIP_EOCD_SIZE <= len(raw):
            record = _ZIP_EOCD.unpack_from(raw, offset)
            comment_size = record[-1]
            if offset + _ZIP_EOCD_SIZE + comment_size == len(raw):
                return offset, tuple(record[1:])
        cursor = offset


def _check_zip_directory_budgets(total_entries: int, directory_size: int) -> None:
    if total_entries > _MAX_ARCHIVE_MEMBERS:
        _fail_metadata("archive contains too many members")
    if directory_size > _MAX_ZIP_CENTRAL_DIRECTORY_BYTES:
        _fail_metadata("ZIP central directory exceeds the size limit")


def _check_zip_archive_limits(raw: bytes) -> None:
    """Validate a bounded non-ZIP64 directory before ZipFile allocates entries."""
    eocd_offset, record = _zip_eocd(raw)
    (
        disk_number,
        directory_disk,
        disk_entries,
        total_entries,
        directory_size,
        directory_offset,
        _comment_size,
    ) = record
    if (
        disk_number != 0
        or directory_disk != 0
        or disk_entries != total_entries
        or total_entries == _ZIP_UINT16_SENTINEL
        or _ZIP_UINT32_SENTINEL in {directory_size, directory_offset}
    ):
        _fail_metadata("unsupported multi-disk or ZIP64 archive")
    _check_zip_directory_budgets(total_entries, directory_size)
    directory_end = directory_offset + directory_size
    if directory_end != eocd_offset:
        _fail_metadata("invalid ZIP archive")

    cursor = directory_offset
    counted_entries = 0
    expanded_bytes = 0
    while cursor < directory_end:
        if (
            cursor + _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE > directory_end
            or raw[cursor : cursor + 4] != _ZIP_CENTRAL_DIRECTORY_SIGNATURE
        ):
            _fail_metadata("invalid ZIP archive")
        compressed_size = struct.unpack_from("<L", raw, cursor + 20)[0]
        compression = struct.unpack_from("<H", raw, cursor + 10)[0]
        uncompressed_size, name_size, extra_size, comment_size = struct.unpack_from(
            "<L3H", raw, cursor + 24
        )
        disk_start = struct.unpack_from("<H", raw, cursor + 34)[0]
        local_header_offset = struct.unpack_from("<L", raw, cursor + 42)[0]
        if (
            _ZIP_UINT32_SENTINEL
            in {
                compressed_size,
                uncompressed_size,
                local_header_offset,
            }
            or disk_start != 0
        ):
            _fail_metadata("unsupported multi-disk or ZIP64 archive member")
        if compression not in _SUPPORTED_ZIP_COMPRESSION:
            _fail_metadata("unsupported ZIP compression method")
        counted_entries += 1
        if counted_entries > _MAX_ARCHIVE_MEMBERS:
            _fail_metadata("archive contains too many members")
        expanded_bytes += uncompressed_size
        if expanded_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        cursor += (
            _ZIP_CENTRAL_DIRECTORY_HEADER_SIZE + name_size + extra_size + comment_size
        )
    if cursor != directory_end or counted_entries != total_entries:
        _fail_metadata("invalid ZIP archive")


def _zip_metadata(raw: bytes, suffix: str) -> tuple[str, bytes]:
    _check_zip_archive_limits(raw)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            if len(members) > _MAX_ARCHIVE_MEMBERS:
                _fail_metadata("archive contains too many members")
            candidates = sorted(
                (
                    item
                    for item in members
                    if not item.is_dir() and item.filename.endswith(suffix)
                ),
                key=lambda item: item.filename,
            )
            if len(candidates) != 1:
                message = f"archive must contain exactly one {suffix}"
                _fail_metadata(message)
            selected = candidates[0]
            if selected.file_size > _MAX_METADATA_BYTES:
                _fail_metadata("core metadata exceeds the size limit")
            with archive.open(selected) as stream:
                payload = stream.read(_MAX_METADATA_BYTES + 1)
            _consume_archive_expansion(len(payload))
            if len(payload) > _MAX_METADATA_BYTES:
                _fail_metadata("core metadata exceeds the size limit")
            return selected.filename, payload
    except _MetadataError:
        raise
    except (
        EOFError,
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        _fail_metadata("invalid ZIP archive")


def _read_tar_metadata_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo
) -> bytes:
    if member.size > _MAX_METADATA_BYTES:
        _fail_metadata("core metadata exceeds the size limit")
    stream = archive.extractfile(member)
    if stream is None:
        _fail_metadata("unable to read PKG-INFO")
    payload = stream.read(_MAX_METADATA_BYTES + 1)
    if len(payload) > _MAX_METADATA_BYTES:
        _fail_metadata("core metadata exceeds the size limit")
    return payload


def _read_tar_metadata(archive: tarfile.TarFile) -> tuple[str, bytes]:
    selected_name: str | None = None
    selected_payload: bytes | None = None
    member_count = 0
    declared_bytes = 0
    while (member := archive.next()) is not None:
        archive.members.clear()  # type: ignore[attr-defined]
        member_count += 1
        if member_count > _MAX_ARCHIVE_MEMBERS:
            _fail_metadata("archive contains too many members")
        if member.size < 0:
            _fail_metadata("tar member has a negative size")
        declared_bytes += member.size
        if declared_bytes > _MAX_ARCHIVE_EXPANDED_BYTES:
            _fail_metadata("archive expanded data exceeds the size limit")
        if not member.isfile() or not member.name.endswith("/PKG-INFO"):
            continue
        if selected_name is not None:
            _fail_metadata("archive must contain exactly one PKG-INFO")
        selected_name = member.name
        selected_payload = _read_tar_metadata_member(archive, member)
    if selected_name is None or selected_payload is None:
        _fail_metadata("archive must contain exactly one PKG-INFO")
    return selected_name, selected_payload


def _tar_metadata(raw: bytes) -> tuple[str, bytes]:
    _check_tar_archive_limits(raw)
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw), mode="rb") as decompressed:
            bounded = _ExpandedArchiveReader(decompressed)
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                return _read_tar_metadata(archive)
    except _MetadataError:
        raise
    except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError, zlib.error):
        _fail_metadata("invalid tar archive")


def _metadata_payload(
    path: PurePosixPath, raw: bytes
) -> tuple[MetadataKind, str, bytes]:
    name = path.name
    if name.endswith(".whl"):
        metadata_path, payload = _zip_metadata(raw, ".dist-info/METADATA")
        return MetadataKind.WHEEL, metadata_path, payload
    try:
        parse_sdist_filename(name)
    except InvalidSdistFilename:
        if len(raw) > _MAX_METADATA_BYTES:
            _fail_metadata("core metadata exceeds the size limit")
        return MetadataKind.CORE_METADATA, name, raw
    if name.endswith(".zip"):
        metadata_path, payload = _zip_metadata(raw, "/PKG-INFO")
    else:
        metadata_path, payload = _tar_metadata(raw)
    return MetadataKind.SDIST, metadata_path, payload
