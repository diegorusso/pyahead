"""A bounded, contained subprocess runner for the resolver."""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import threading
from contextlib import suppress
from ctypes import wintypes
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    Protocol,
    cast,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from types import FrameType
from pyahead.dependencies._model import (
    _CREATE_SUSPENDED,
    _INVALID_DWORD,
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
    _JOB_OBJECT_LIMIT_KILL_ON_CLOSE,
    _MAX_RESOLVER_STREAM_BYTES,
    _POSIX_FORCE_KILL_SIGNAL,
    _PROCESS_CLEANUP_SECONDS,
    _TAR_READ_CHUNK_BYTES,
    _TH32CS_SNAPTHREAD,
    _THREAD_SUSPEND_RESUME,
    _fail_metadata,
    _ResolverOutputLimitError,
)


class _ResolverPipeError(OSError):
    """Raised when inherited resolver output pipes remain open after exit."""


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _IoCounters(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    )


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _ThreadEntry32(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    )


class _CtypesFunction(Protocol):
    argtypes: object
    restype: object

    def __call__(self, *args: object) -> object: ...


def _windows_kernel32() -> object:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError
    return loader("kernel32", use_last_error=True)


def _windows_function(library: object, name: str) -> _CtypesFunction:
    return cast("_CtypesFunction", getattr(library, name))


def _create_windows_kill_job(process: subprocess.Popen[bytes]) -> int | None:
    if os.name != "nt":
        return None
    kernel32 = _windows_kernel32()
    create_job = _windows_function(kernel32, "CreateJobObjectW")
    set_information = _windows_function(kernel32, "SetInformationJobObject")
    assign_process = _windows_function(kernel32, "AssignProcessToJobObject")
    close_handle = _windows_function(kernel32, "CloseHandle")
    create_job.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    create_job.restype = wintypes.HANDLE
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    assign_process.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    assign_process.restype = wintypes.BOOL
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_job = create_job(None, None)
    if not isinstance(raw_job, int) or not raw_job:
        return None
    job = raw_job
    information = _JobObjectExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_CLOSE
    configured = set_information(
        job,
        _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(information),
        ctypes.sizeof(information),
    )
    process_handle = getattr(process, "_handle", None)
    assigned = bool(
        configured
        and isinstance(process_handle, int)
        and assign_process(job, wintypes.HANDLE(process_handle))
    )
    if not assigned:
        close_handle(job)
        return None
    return int(job)


def _close_windows_job(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close_handle = _windows_function(kernel32, "CloseHandle")
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        message = "CloseHandle failed for resolver Job Object"
        raise OSError(message)


def _terminate_windows_job(handle: int) -> None:
    """Terminate every process assigned to one resolver Job Object."""
    kernel32 = _windows_kernel32()
    terminate_job = _windows_function(kernel32, "TerminateJobObject")
    terminate_job.argtypes = (wintypes.HANDLE, wintypes.UINT)
    terminate_job.restype = wintypes.BOOL
    if not terminate_job(wintypes.HANDLE(handle), wintypes.UINT(1)):
        message = "TerminateJobObject failed for resolver Job Object"
        raise OSError(message)


def _dispose_windows_job(handle: int) -> bool:
    """Close a Job, explicitly terminating its tree if close is not confirmed."""
    try:
        _close_windows_job(handle)
    except OSError:
        try:
            _terminate_windows_job(handle)
        except OSError:
            return False
        with suppress(OSError):
            _close_windows_job(handle)
    return True


def _windows_process_thread_ids(process_id: int) -> tuple[int, ...]:
    kernel32 = _windows_kernel32()
    create_snapshot = _windows_function(kernel32, "CreateToolhelp32Snapshot")
    thread_first = _windows_function(kernel32, "Thread32First")
    thread_next = _windows_function(kernel32, "Thread32Next")
    close_handle = _windows_function(kernel32, "CloseHandle")
    create_snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create_snapshot.restype = wintypes.HANDLE
    thread_first.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32))
    thread_first.restype = wintypes.BOOL
    thread_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32))
    thread_next.restype = wintypes.BOOL
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_snapshot = create_snapshot(_TH32CS_SNAPTHREAD, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if (
        not isinstance(raw_snapshot, int)
        or not raw_snapshot
        or raw_snapshot == invalid_handle
    ):
        return ()
    snapshot = raw_snapshot
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(_ThreadEntry32)
        identifiers: list[int] = []
        present = bool(thread_first(snapshot, ctypes.byref(entry)))
        while present:
            if int(entry.th32OwnerProcessID) == process_id:
                identifiers.append(int(entry.th32ThreadID))
            present = bool(thread_next(snapshot, ctypes.byref(entry)))
        return tuple(identifiers)
    finally:
        close_handle(wintypes.HANDLE(snapshot))


def _resume_windows_primary_thread(process_id: int) -> bool:
    identifiers = _windows_process_thread_ids(process_id)
    if len(identifiers) != 1:
        return False
    kernel32 = _windows_kernel32()
    open_thread = _windows_function(kernel32, "OpenThread")
    resume_thread = _windows_function(kernel32, "ResumeThread")
    close_handle = _windows_function(kernel32, "CloseHandle")
    open_thread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_thread.restype = wintypes.HANDLE
    resume_thread.argtypes = (wintypes.HANDLE,)
    resume_thread.restype = wintypes.DWORD
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    raw_thread = open_thread(_THREAD_SUSPEND_RESUME, wintypes.BOOL(), identifiers[0])
    if not isinstance(raw_thread, int) or not raw_thread:
        return False
    thread = raw_thread
    try:
        previous_count = resume_thread(wintypes.HANDLE(thread))
        return (
            isinstance(previous_count, int)
            and previous_count > 0
            and previous_count != _INVALID_DWORD
        )
    finally:
        close_handle(wintypes.HANDLE(thread))


class _ProcessContainment:
    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.windows_job: int | None = None
        self.lock = threading.Lock()
        self.terminated = False

    def attach_process(self, process: subprocess.Popen[bytes]) -> None:
        """Record process ownership before any later setup can be interrupted."""
        self.process = process

    def attach_windows_job(self, windows_job: int) -> None:
        """Record Job ownership before the suspended process is resumed."""
        self.windows_job = windows_job

    def terminate(self) -> None:
        """Kill the isolated process tree, retaining state for interrupted retries."""
        with self.lock:
            if self.terminated:
                return
            if self.windows_job is not None:
                job_terminated = _dispose_windows_job(self.windows_job)
                if job_terminated:
                    self.windows_job = None
                    self.terminated = True
                    return
            if self.process is None:
                self.terminated = self.windows_job is None
                return
            if os.name != "nt":
                try:
                    os.killpg(self.process.pid, _POSIX_FORCE_KILL_SIGNAL)
                except OSError:
                    pass
                else:
                    self.terminated = self.windows_job is None
                    return
            try:
                self.process.kill()
            except OSError:
                pass
            else:
                self.terminated = self.windows_job is None


def _retry_windows_job_disposal(
    windows_job: int,
) -> tuple[bool, BaseException | None]:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            terminated = _dispose_windows_job(windows_job)
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        if terminated:
            return True, interruption
    return False, interruption


def _terminate_uncontained_root(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            process.kill()
        except OSError:
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _retry_process_group_termination(
    process: subprocess.Popen[bytes],
) -> tuple[bool, BaseException | None]:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            os.killpg(process.pid, _POSIX_FORCE_KILL_SIGNAL)
        except OSError:
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        return True, interruption
    return False, interruption


def _finish_uncontained_cleanup(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption = _wait_for_process_cleanup(process)
    return _preserve_first_cleanup_error(
        interruption,
        _close_process_streams(process),
    )


def _cleanup_uncontained_process(
    process: subprocess.Popen[bytes], windows_job: int | None
) -> None:
    """Bound cleanup before ownership passes to ``_ProcessContainment``."""
    terminated = False
    interruption: BaseException | None = None
    if windows_job is not None:
        terminated, interruption = _retry_windows_job_disposal(windows_job)
    elif os.name != "nt":
        terminated, interruption = _retry_process_group_termination(process)
    if not terminated:
        root_interruption = _terminate_uncontained_root(process)
        if interruption is None:
            interruption = root_interruption
    finish_interruption = _finish_uncontained_cleanup(process)
    if interruption is None:
        interruption = finish_interruption
    if interruption is not None:
        raise interruption


def _replay_deferred_sigint(
    handler: object,
    signum: int,
    frame: FrameType | None,
) -> None:
    """Run the prior SIGINT disposition after process ownership is recorded."""
    if handler is signal.SIG_IGN:
        return
    if handler is signal.SIG_DFL or not callable(handler):
        signal.default_int_handler(signum, frame)
    else:
        handler(signum, frame)


def _popen_attached_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    creationflags: int,
    containment: _ProcessContainment,
) -> subprocess.Popen[bytes]:
    """Spawn and record ownership before replaying a main-thread SIGINT."""

    def spawn() -> subprocess.Popen[bytes]:
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        containment.attach_process(process)
        return process

    if threading.current_thread() is not threading.main_thread():
        return spawn()

    deferred_sigint: list[tuple[int, FrameType | None]] = []

    def record_sigint(signum: int, frame: FrameType | None) -> None:
        if not deferred_sigint:
            deferred_sigint.append((signum, frame))

    prior_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, record_sigint)
    try:
        process = spawn()
    finally:
        signal.signal(signal.SIGINT, prior_handler)
        if deferred_sigint:
            _replay_deferred_sigint(prior_handler, *deferred_sigint[0])
    return process


def _cleanup_failed_process_start(
    process: subprocess.Popen[bytes],
    windows_job: int | None,
    containment: _ProcessContainment,
) -> None:
    """Clean a failed start whether or not ownership was already recorded."""
    if containment.process is not process:
        _cleanup_uncontained_process(process, windows_job)
        return
    if windows_job is not None and containment.windows_job is None:
        containment.attach_windows_job(windows_job)
    interruption = _retry_containment_termination(containment)
    finish_interruption = _finish_uncontained_cleanup(process)
    if interruption is not None:
        raise interruption
    if finish_interruption is not None:
        raise finish_interruption


def _start_contained_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    containment: _ProcessContainment,
) -> subprocess.Popen[bytes]:
    creationflags = (
        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) | _CREATE_SUSPENDED
        if os.name == "nt"
        else 0
    )
    process: subprocess.Popen[bytes] | None = None
    windows_job: int | None = None
    try:
        process = _popen_attached_process(
            command,
            cwd=cwd,
            env=env,
            creationflags=creationflags,
            containment=containment,
        )
        windows_ready = os.name != "nt"
        if os.name == "nt":
            try:
                windows_job = _create_windows_kill_job(process)
                if windows_job is not None:
                    containment.attach_windows_job(windows_job)
                windows_ready = (
                    windows_job is not None
                    and _resume_windows_primary_thread(process.pid)
                )
            except OSError:
                windows_ready = False
        if not windows_ready:
            _fail_metadata("unable to contain isolated resolver process")
    except BaseException:
        owned_process = containment.process
        if owned_process is not None:
            _cleanup_failed_process_start(
                owned_process,
                windows_job,
                containment,
            )
        raise
    else:
        return process


def _read_process_pipe(
    stream: BinaryIO,
    retained: bytearray,
    overflow: threading.Event,
    containment: _ProcessContainment,
    errors: list[OSError],
) -> None:
    """Retain bounded bytes from one pipe and stop a flooding child."""
    try:
        while payload := stream.read(_TAR_READ_CHUNK_BYTES):
            remaining = _MAX_RESOLVER_STREAM_BYTES - len(retained)
            retained.extend(payload[:remaining])
            if len(payload) > remaining:
                overflow.set()
                containment.terminate()
                return
    except OSError as error:
        errors.append(error)


def _retry_containment_termination(
    containment: _ProcessContainment,
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            containment.terminate()
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        if containment.terminated:
            break
    return interruption


def _wait_for_process_cleanup(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            break
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _join_process_reader(reader: threading.Thread) -> BaseException | None:
    interruption: BaseException | None = None
    for _attempt in range(2):
        try:
            reader.join(timeout=_PROCESS_CLEANUP_SECONDS)
        except BaseException as error:  # noqa: BLE001
            if interruption is None:
                interruption = error
            continue
        break
    return interruption


def _close_process_streams(
    process: subprocess.Popen[bytes],
) -> BaseException | None:
    interruption: BaseException | None = None
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            for _attempt in range(2):
                try:
                    stream.close()
                except (OSError, ValueError):
                    break
                except BaseException as error:  # noqa: BLE001
                    if interruption is None:
                        interruption = error
                    continue
                break
    return interruption


def _preserve_first_cleanup_error(
    current: BaseException | None,
    candidate: BaseException | None,
) -> BaseException | None:
    return current if current is not None else candidate


def _finish_process_readers(
    process: subprocess.Popen[bytes],
    containment: _ProcessContainment,
    readers: Sequence[threading.Thread],
) -> bool:
    """Terminate the process tree and report whether a pipe reader survived."""
    interruption = _retry_containment_termination(containment)
    interruption = _preserve_first_cleanup_error(
        interruption,
        _wait_for_process_cleanup(process),
    )
    started = tuple(reader for reader in readers if reader.ident is not None)
    for reader in started:
        interruption = _preserve_first_cleanup_error(
            interruption,
            _join_process_reader(reader),
        )
    if any(reader.is_alive() for reader in started):
        interruption = _preserve_first_cleanup_error(
            interruption,
            _close_process_streams(process),
        )
        for reader in started:
            interruption = _preserve_first_cleanup_error(
                interruption,
                _join_process_reader(reader),
            )
    interruption = _preserve_first_cleanup_error(
        interruption,
        _close_process_streams(process),
    )
    reader_survived = any(reader.is_alive() for reader in started)
    if interruption is not None:
        raise interruption
    return reader_survived


class ProcessRunner(Protocol):
    """Run one resolver command and return its completed, decoded process."""

    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``command`` within ``timeout`` seconds."""


def _run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run one resolver command with bounded, separate UTF-8 output streams."""
    process: subprocess.Popen[bytes] | None = None
    containment = _ProcessContainment()
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    stdout_errors: list[OSError] = []
    stderr_errors: list[OSError] = []
    readers: tuple[threading.Thread, ...] = ()
    timed_out: subprocess.TimeoutExpired | None = None
    returncode = -1
    reader_survived = False
    try:
        process = _start_contained_process(
            command,
            cwd=cwd,
            env=env,
            containment=containment,
        )
        if process.stdout is None or process.stderr is None:
            _fail_metadata("unable to capture isolated resolver output")
        readers = (
            threading.Thread(
                target=_read_process_pipe,
                args=(
                    process.stdout,
                    stdout,
                    overflow,
                    containment,
                    stdout_errors,
                ),
                daemon=True,
            ),
            threading.Thread(
                target=_read_process_pipe,
                args=(
                    process.stderr,
                    stderr,
                    overflow,
                    containment,
                    stderr_errors,
                ),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            timed_out = error
            containment.terminate()
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=_PROCESS_CLEANUP_SECONDS)
            returncode = process.returncode if process.returncode is not None else -1
    finally:
        owned_process = containment.process
        if owned_process is not None:
            reader_survived = _finish_process_readers(
                owned_process,
                containment,
                readers,
            )
    if timed_out is not None:
        raise timed_out
    if reader_survived:
        raise _ResolverPipeError
    if stdout_errors or stderr_errors:
        raise (stdout_errors or stderr_errors)[0]
    if overflow.is_set():
        raise _ResolverOutputLimitError
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=returncode,
        stdout=bytes(stdout).decode("utf-8", errors="strict"),
        stderr=bytes(stderr).decode("utf-8", errors="strict"),
    )
