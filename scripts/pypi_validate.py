"""Offline environment provisioning and static scan for the PyPI validation harness.

This runner installs and imports arbitrary third-party code from the pinned
wheelhouse built by `pypi_corpus.py`, which crosses PyAhead's own "never
execute target code" boundary. It never touches the network: interpreters and
packages must already be installed locally, and installation always uses
`--no-index --find-links` against the verified wheelhouse.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from functools import cache
from importlib.metadata import PathDistribution
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, TypeAlias

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from pyahead._human_text import SafeArgumentParser, escape_terminal_text
from pyahead.versions import InvalidPythonMinorError, PythonMinor
from scripts import pypi_corpus

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from scripts.pypi_corpus import PackageEntry

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PROBE_SCRIPT = _REPO_ROOT / "scripts" / "pypi_probe.py"
_BASELINE_MINOR = 11
_SUPPORTED_MAJOR = 3
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_STDERR_TAIL_BYTES = 4000
_VENV_TIMEOUT_SECONDS = 60.0
_ACCEPTED_SCAN_EXITS = frozenset({0, 3})
_QUALIFIED_MATCH_KINDS = frozenset(
    {"call-shape", "qualified-reference", "qualified-call"}
)
# "import-timeout" is not produced by pypi_probe.py itself (its own
# per-probe budget failure is "probe-timeout"): it is synthesized here when
# the *whole batch subprocess* - one `pypi-probe` invocation covering many
# probes - exceeds its own wall-clock timeout before any individual probe
# gets a chance to report anything, so it is deliberately absent from
# pypi_probe.py's mirrored `_RESULT_STATUSES_BY_KIND`.
_KNOWN_PROBE_FAILURE_STATUSES = frozenset(
    {"probe-timeout", "probe-crashed", "import-timeout"}
)
_PROBE_RESULT_STATUSES_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset({"present", "absent", "import-error"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "binding": frozenset({"resolved", "import-error", "binding-not-visible"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "call-shape": frozenset(
        {"accepted", "rejected", "absent", "no-signature", "import-error"}
    )
    | _KNOWN_PROBE_FAILURE_STATUSES,
}
# The exact key set a real (non-failure-status) result of this kind carries;
# mirrors pypi_probe.py's own `_RESULT_FIELDS_BY_KIND`. A failure-status
# result instead always has exactly `{id, kind, status, error}`. Matching the
# key set exactly - not just accepting a closed `status` vocabulary - is what
# makes this a closed schema: a batch process writing a truncated or
# padded-with-extra-keys record is rejected outright.
_PROBE_RESULT_FIELDS_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset(
        {"id", "kind", "status", "deprecation_warning", "signature", "error"}
    ),
    "binding": frozenset(
        {"id", "kind", "status", "identity_match", "subject_status", "error"}
    ),
    "call-shape": frozenset({"id", "kind", "status", "error"}),
}
_FAILURE_RESULT_FIELDS = frozenset({"id", "kind", "status", "error"})
# A batch of probes for one interpreter minor, run and reported back by id.
_ProbeRunner: TypeAlias = (
    "Callable[[int, list[dict[str, Any]]], dict[str, dict[str, Any]]]"
)
CLOSED_VERDICTS = frozenset(
    {"confirmed", "refuted-binding", "refuted-timeline", "not-adjudicable"}
)


class PypiValidateError(RuntimeError):
    """Raised when a PyPI validation run would be incomplete or untrustworthy."""


@dataclass(frozen=True)
class InstalledInterpreter:
    """One locally installed CPython interpreter available to `uv`."""

    minor: int
    version: str
    path: Path


@dataclass(frozen=True)
class ResourceLimits:
    """Wall-clock-adjacent OS resource ceilings applied to installer children."""

    cpu_seconds: int
    address_space_bytes: int
    max_processes: int
    max_file_size_bytes: int


_INSTALL_LIMITS = ResourceLimits(
    cpu_seconds=180,
    address_space_bytes=3 * 1024 * 1024 * 1024,
    # RLIMIT_NPROC counts every thread already running under the real UID
    # system-wide, not just this subtree, so it needs generous headroom for
    # whatever else shares the host rather than a tight per-package budget.
    max_processes=2048,
    max_file_size_bytes=512 * 1024 * 1024,
)


@dataclass(frozen=True)
class Isolation:
    """A command rewritten to run under sandboxing, and which mode was used."""

    mode: str
    command: list[str]


@dataclass(frozen=True)
class ScanOutcome:
    """The result of one `pyahead check` invocation against an installed package."""

    exit_code: int | None
    duration_seconds: float
    findings: tuple[dict[str, Any], ...]
    error: str | None


@dataclass(frozen=True)
class RunOptions:
    """Immutable configuration threaded through one `run` invocation."""

    wheelhouse: Path
    work_dir: Path
    timeout: float
    horizon_minor: int
    baseline_minor: int
    bwrap: str | None
    uv: str
    manifest_sha256: str
    python_install_dir: Path | None


def _tail(text: str) -> str:
    return text[-_STDERR_TAIL_BYTES:]


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        message = "value must be a number"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "value must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        message = "value must be an integer"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "value must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def _shard_spec(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([0-9]+)/([0-9]+)", value)
    if match is None:
        message = "--shard must look like INDEX/COUNT"
        raise argparse.ArgumentTypeError(message)
    index, count = int(match.group(1)), int(match.group(2))
    if count < 1 or not (0 <= index < count):
        message = "--shard index must satisfy 0 <= INDEX < COUNT"
        raise argparse.ArgumentTypeError(message)
    return index, count


def _shard_selected(rank: int, shard_index: int, shard_count: int) -> bool:
    return (rank - 1) % shard_count == shard_index


# --- interpreter resolution -------------------------------------------------


def _installed_interpreters(
    uv: str, *, timeout: float
) -> dict[int, InstalledInterpreter]:
    result = subprocess.run(  # noqa: S603 - fixed argv, resolved uv executable.
        [
            uv,
            "python",
            "list",
            "--only-installed",
            "--output-format",
            "json",
            "--offline",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=_install_environment(),
    )
    if result.returncode != 0:
        message = f"unable to list installed interpreters: {_tail(result.stderr)}"
        raise PypiValidateError(message)
    try:
        entries: Any = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        message = "uv python list produced invalid JSON"
        raise PypiValidateError(message) from error
    if not isinstance(entries, list):
        message = "uv python list produced an unexpected shape"
        raise PypiValidateError(message)

    installed: dict[int, InstalledInterpreter] = {}
    for item in entries:
        if not isinstance(item, dict) or item.get("implementation") != "cpython":
            continue
        if item.get("variant") not in (None, "default"):
            continue
        version_parts = item.get("version_parts")
        path = item.get("path")
        version = item.get("version")
        if (
            not isinstance(version_parts, dict)
            or not isinstance(path, str)
            or not isinstance(version, str)
            or version_parts.get("major") != _SUPPORTED_MAJOR
        ):
            continue
        minor = version_parts.get("minor")
        if not isinstance(minor, int) or minor in installed:
            continue
        # Resolved to the real interpreter file: `uv python install` also
        # links each interpreter into `~/.local/bin`, and `uv python list`
        # reports that launcher link. The sandbox binds uv's managed install
        # root, not `~/.local/bin`, so a bare-interpreter probe started
        # through the link would fail at exec inside `bwrap` and every C2
        # probe would surface as `probe-crashed`.
        installed[minor] = InstalledInterpreter(
            minor=minor, version=version, path=Path(path).resolve()
        )
    return installed


def _reference_interpreter(  # noqa: PLR0913 - mirrors the manifest entry's own fields.
    requires_python: str | None,
    installed: Mapping[int, InstalledInterpreter],
    *,
    baseline_minor: int,
    horizon_minor: int,
    filename: str,
    is_wheel: bool,
) -> InstalledInterpreter | None:
    """Pick the lowest available minor satisfying `requires_python`, clamped up.

    For a wheel artifact, a candidate minor must also be able to install
    the pinned wheel itself: `requires_python` alone cannot predict a wheel
    built only for a narrower range of interpreters than the distribution
    claims to support, and installing under a tag-incompatible venv would
    fail for a reason unrelated to anything this harness is measuring.
    """
    specifier: SpecifierSet | None = None
    if requires_python:
        try:
            specifier = SpecifierSet(requires_python)
        except InvalidSpecifier:
            specifier = None
    for minor in range(baseline_minor, horizon_minor + 1):
        candidate = installed.get(minor)
        if candidate is None:
            continue
        version = Version(candidate.version)
        if specifier is not None and not specifier.contains(version, prereleases=True):
            continue
        if is_wheel and not pypi_corpus.wheel_supports_minor(filename, minor):
            continue
        return candidate
    return None


def _action_version_minor(value: object) -> int:
    if not isinstance(value, str):
        message = f"finding action_version must be a string, got {value!r}"
        raise PypiValidateError(message)
    try:
        return PythonMinor.parse(value).minor
    except InvalidPythonMinorError as error:
        message = f"finding action_version has an unexpected shape: {value!r}"
        raise PypiValidateError(message) from error


def _finding_interpreters_needed(
    action_minor: int, *, baseline_minor: int, horizon_minor: int
) -> tuple[int, ...]:
    """Return the `(action_version - 1, action_version)` pair, clamped to horizon."""
    candidates = {action_minor - 1, action_minor}
    return tuple(sorted(m for m in candidates if baseline_minor <= m <= horizon_minor))


# --- RECORD-derived path selection and module mapping -----------------------


def _owned_python_files(dist_info: Path) -> tuple[PurePosixPath, ...]:
    """Return the distribution's own `.py` files, excluding installer metadata."""
    distribution = PathDistribution(dist_info)
    files = distribution.files or ()
    owned: set[PurePosixPath] = set()
    for file in files:
        path = PurePosixPath(str(file))
        if path.suffix != ".py" or path.is_absolute() or ".." in path.parts:
            continue
        if any(part.endswith((".dist-info", ".data")) for part in path.parts[:-1]):
            continue
        owned.add(path)
    return tuple(sorted(owned))


def _include_patterns(paths: tuple[PurePosixPath, ...]) -> tuple[str, ...]:
    """Return one root-anchored gitignore pattern per owned file.

    A top-level-directory pattern (e.g. `google/`) would also sweep in
    unrelated distributions that share the same namespace-package prefix
    (`google-cloud-*`, `azure-*`, `zope.*`, ...) when they are also
    installed in the venv as dependencies, corrupting this package's
    finding counts. An exact `/`-anchored path per owned file scans only
    the files this distribution's RECORD actually claims.
    """
    return tuple(sorted({f"/{path.as_posix()}" for path in paths}))


def _module_name(path: PurePosixPath) -> str:
    parts = list(path.parts)
    if not parts:
        message = "cannot derive a module name from an empty path"
        raise PypiValidateError(message)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = path.stem
    if not parts:
        message = f"cannot derive a module name for {path.as_posix()!r}"
        raise PypiValidateError(message)
    return ".".join(parts)


def _distribution_info_dir(site_packages: Path, *, normalized_name: str) -> Path:
    for candidate in sorted(site_packages.glob("*.dist-info")):
        metadata_path = candidate / "METADATA"
        try:
            metadata_text = metadata_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in metadata_text.splitlines():
            if not line.startswith("Name:"):
                continue
            if _normalized_name(line.removeprefix("Name:").strip()) == normalized_name:
                return candidate
            break
    message = f"installed distribution metadata not found for {normalized_name}"
    raise PypiValidateError(message)


# --- isolation ---------------------------------------------------------------


def _apply_resource_limits(limits: ResourceLimits) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    resource.setrlimit(
        resource.RLIMIT_AS, (limits.address_space_bytes, limits.address_space_bytes)
    )
    resource.setrlimit(
        resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes)
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE, (limits.max_file_size_bytes, limits.max_file_size_bytes)
    )


# The base system directories a dynamically linked CPython interpreter and
# `uv` need to run at all. Deliberately excludes the operator's home
# directory (and everything else under "/"): target code executes inside
# this sandbox, and a blanket `--ro-bind / /` would let it read credentials
# and other secrets by absolute path. Anything else a specific command needs
# (the wheelhouse, a uv-managed interpreter's own install root, the `uv`
# binary itself when it lives outside these directories) is added by the
# caller via `read_only_binds`.
_BASE_READ_ONLY_ROOTS = (
    Path("/usr"),
    Path("/bin"),
    Path("/sbin"),
    Path("/lib"),
    Path("/lib64"),
)


def _isolate_command(  # noqa: PLR0913 - one flag per independent isolation choice.
    command: list[str],
    *,
    bwrap: str | None,
    venv_dir: Path | None,
    scratch_home: Path,
    venv_writable: bool,
    read_only_binds: tuple[Path, ...] = (),
) -> Isolation:
    """Wrap a third-party-code-executing command in `bwrap`, when available.

    `venv_dir` is `None` for a bare-interpreter probe (C2): there is no
    installed-distribution venv to bind, only the scratch home and whatever
    the interpreter itself needs, already covered by the base read-only
    roots or `read_only_binds`.
    """
    if bwrap is None:
        return Isolation(mode="rlimit-only", command=command)
    wrapped = [
        bwrap,
        "--die-with-parent",
        "--unshare-net",
        "--unshare-pid",
        "--dev",
        "/dev",
        # A sandbox-scoped /proc: without this, target code could enumerate
        # and inspect every process on the host (cmdlines included) despite
        # --unshare-pid.
        "--proc",
        "/proc",
        # These must come before any bind below: the wheelhouse, work
        # directory, venv, and scratch home all commonly live under /tmp,
        # and a --tmpfs mounted after a nested bind would erase it instead
        # of just clearing everything else under /tmp.
        "--tmpfs",
        "/tmp",  # noqa: S108 - a private sandbox tmpfs mount point, not a host path.
        # --unshare-net only isolates the network namespace, not pathname
        # Unix-domain sockets: without this, target code could still reach
        # host sockets under /run (an agent, a bus, a container daemon).
        "--tmpfs",
        "/run",
    ]
    for read_only in (*_BASE_READ_ONLY_ROOTS, *read_only_binds):
        if read_only.exists():
            wrapped.extend(["--ro-bind", str(read_only), str(read_only)])
    if venv_dir is not None:
        wrapped.extend(
            ["--bind" if venv_writable else "--ro-bind", str(venv_dir), str(venv_dir)]
        )
    wrapped.extend(
        [
            "--bind",
            str(scratch_home),
            str(scratch_home),
            "--setenv",
            "HOME",
            str(scratch_home),
            "--chdir",
            str(scratch_home),
            "--",
            *command,
        ]
    )
    return Isolation(mode="bwrap", command=wrapped)


_INSTALL_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR")


def _install_environment(*, home: Path | None = None) -> dict[str, str]:
    """Build the child environment from an explicit allowlist, not the parent's.

    The parent process's environment can carry ambient secrets (cloud
    credentials, CI tokens) that have nothing to do with provisioning or
    installing a package; copying it wholesale into a process that may end
    up executing arbitrary third-party code hands that code the same
    secrets. `home`, when given, overrides `HOME` with a scratch, per-package
    directory instead of the operator's real one - required in the
    `bwrap`-unavailable fallback, where there is no `--setenv HOME` to do it
    instead.
    """
    environment = {
        name: os.environ[name] for name in _INSTALL_ENV_ALLOWLIST if name in os.environ
    }
    environment["HOME"] = str(home) if home is not None else os.environ.get("HOME", "")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["UV_NO_PROGRESS"] = "1"
    environment["UV_OFFLINE"] = "1"
    environment["UV_PYTHON_DOWNLOADS"] = "never"
    return environment


# --- provisioning --------------------------------------------------------


def _uv_executable() -> str:
    uv = shutil.which("uv")
    if uv is None:
        message = "uv is required to provision interpreters and packages"
        raise PypiValidateError(message)
    return uv


def _uv_python_install_dir(uv: str, *, timeout: float) -> Path | None:
    """Return uv's managed-interpreter root, so probes can see it read-only.

    A uv-managed CPython build (needed for 3.15, which no system package
    provides) lives outside every base system directory, often under the
    operator's own home directory - it must be bound explicitly rather than
    swept in by a blanket root bind.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, resolved uv executable.
        [uv, "python", "dir"],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=_install_environment(),
    )
    if result.returncode != 0:
        return None
    directory = Path(result.stdout.strip())
    if not directory.is_dir():
        return None
    # Resolved for the same reason `_installed_interpreters` resolves each
    # interpreter path: the sandbox binds this root and the probes exec the
    # resolved interpreter file beneath it, so a symlink anywhere in the
    # root's own path (a relocated `~/.local/share`, or
    # `UV_PYTHON_INSTALL_DIR` pointing through a link) would otherwise leave
    # that file outside every bound tree and fail every bare-interpreter
    # probe at exec inside `bwrap`.
    return directory.resolve()


def _create_venv(uv: str, python_path: Path, venv_dir: Path, *, timeout: float) -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv, resolved uv executable.
        [
            uv,
            "venv",
            "--python",
            str(python_path),
            "--no-project",
            "--clear",
            str(venv_dir),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=_install_environment(),
    )
    if result.returncode != 0:
        message = f"unable to create a virtual environment: {_tail(result.stderr)}"
        raise PypiValidateError(message)


def _install_distribution(
    entry: PackageEntry,
    *,
    venv_dir: Path,
    scratch_home: Path,
    options: RunOptions,
) -> tuple[str, str | None]:
    """Install one pinned artifact offline; return (isolation_mode, error)."""
    venv_python = venv_dir / "bin" / "python"
    # The exact pinned artifact path, not `name==version`: a `verify`-only
    # match on name/version would let `uv` pick any wheelhouse file that
    # satisfies it (e.g. a stale re-download left over from a prior run),
    # installing bytes `_verify` never re-hashed while the shard still
    # records the manifest's filename and digest as if they were what ran.
    artifact_path = options.wheelhouse / entry.filename
    command = [
        options.uv,
        "pip",
        "install",
        "--python",
        str(venv_python),
        "--no-index",
        "--find-links",
        str(options.wheelhouse),
        "--no-cache",
        str(artifact_path),
    ]
    extra_read_only = [options.wheelhouse, Path(options.uv).resolve()]
    if options.python_install_dir is not None:
        extra_read_only.append(options.python_install_dir)
    isolation = _isolate_command(
        command,
        bwrap=options.bwrap,
        venv_dir=venv_dir,
        scratch_home=scratch_home,
        venv_writable=True,
        read_only_binds=tuple(extra_read_only),
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, sandboxed target code.
            isolation.command,
            cwd=scratch_home,
            env=_install_environment(home=scratch_home),
            capture_output=True,
            text=True,
            timeout=options.timeout,
            check=False,
            preexec_fn=lambda: _apply_resource_limits(_INSTALL_LIMITS),
        )
    except subprocess.TimeoutExpired:
        return isolation.mode, "install exceeded its timeout"
    if completed.returncode != 0:
        return isolation.mode, _tail(completed.stderr)
    return isolation.mode, None


@dataclass(frozen=True)
class BindingVenv:
    """One interpreter's own installed-package venv, ready for C1 probes."""

    venv_dir: Path
    scratch_home: Path


def _provision_binding_venv(
    entry: PackageEntry,
    *,
    python_path: Path,
    package_dir: Path,
    label: str,
    options: RunOptions,
) -> BindingVenv | None:
    """Provision and install into one extra, interpreter-specific venv for C1.

    A version-gated fallback binds a different object at different
    interpreters, so C1 must be checked under every interpreter a finding
    actually needs, each with the distribution genuinely installed - not
    only under whichever interpreter happened to scan the package. Returns
    `None` on any failure; the caller treats that minor as
    `not-adjudicable:install-failed` for the findings that needed it,
    rather than aborting the whole package.
    """
    venv_dir = package_dir / f"venv-{label}"
    scratch_home = package_dir / f"home-{label}"
    try:
        scratch_home.mkdir(parents=True, exist_ok=True)
        _create_venv(options.uv, python_path, venv_dir, timeout=_VENV_TIMEOUT_SECONDS)
    except (PypiValidateError, subprocess.TimeoutExpired):
        return None
    _, install_error = _install_distribution(
        entry, venv_dir=venv_dir, scratch_home=scratch_home, options=options
    )
    if install_error is not None:
        return None
    return BindingVenv(venv_dir=venv_dir, scratch_home=scratch_home)


def _site_packages_dir(python_executable: Path, *, timeout: float) -> Path:
    result = subprocess.run(  # noqa: S603 - fixed argv, trusted interpreter query.
        [
            str(python_executable),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        message = f"unable to resolve site-packages: {_tail(result.stderr)}"
        raise PypiValidateError(message)
    site_packages = Path(result.stdout.strip())
    if not site_packages.is_dir():
        message = "resolved site-packages directory does not exist"
        raise PypiValidateError(message)
    return site_packages


# --- static scan --------------------------------------------------------


def _scan_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH"):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _read_limited(stream: Any) -> str:  # noqa: ANN401 - a writable text file object.
    stream.flush()
    size = stream.tell()
    if size > _MAX_REPORT_BYTES:
        message = "scan report exceeded the 64 MiB review limit"
        raise PypiValidateError(message)
    stream.seek(0)
    return stream.read()  # type: ignore[no-any-return]


def _run_scan(
    site_packages: Path,
    *,
    include_patterns: tuple[str, ...],
    baseline_minor: int,
    horizon_minor: int,
    timeout: float,
) -> ScanOutcome:
    command = [
        sys.executable,
        "-I",
        "-m",
        "pyahead",
        "check",
        "--root",
        str(site_packages),
        "--source-root",
        ".",
        *[
            argument
            for pattern in include_patterns
            for argument in ("--include", pattern)
        ],
        "--baseline-python",
        f"3.{baseline_minor}",
        "--horizon-python",
        f"3.{horizon_minor}",
        "--minimum-confidence",
        "high",
        "--fail-on",
        "never",
        "--format",
        "json",
        "--output",
        "-",
    ]
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        started = time.perf_counter()
        try:
            result = subprocess.run(  # noqa: S603 - fixed isolated Python argv.
                command,
                cwd=_REPO_ROOT,
                env=_scan_environment(),
                check=False,
                stdout=output,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ScanOutcome(
                None, time.perf_counter() - started, (), "scan exceeded its timeout"
            )
        duration = time.perf_counter() - started
        rendered = _read_limited(output)
    if result.returncode not in _ACCEPTED_SCAN_EXITS:
        error = f"scan exited with code {result.returncode}"
        return ScanOutcome(result.returncode, duration, (), error)
    try:
        report: Any = json.loads(rendered)
    except json.JSONDecodeError:
        error = "scan produced invalid JSON"
        return ScanOutcome(result.returncode, duration, (), error)
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, list):
        return ScanOutcome(
            result.returncode, duration, (), "scan report is missing a findings array"
        )
    high_confidence = tuple(
        finding
        for finding in findings
        if isinstance(finding, dict)
        and isinstance(finding.get("match"), dict)
        and finding["match"].get("confidence") == "high"
    )
    return ScanOutcome(result.returncode, duration, high_confidence, None)


def _mapped_finding(
    finding: dict[str, Any], *, baseline_minor: int, horizon_minor: int
) -> dict[str, Any]:
    location = finding.get("location")
    if not isinstance(location, dict) or not isinstance(location.get("path"), str):
        message = "scan finding has an unexpected location shape"
        raise PypiValidateError(message)
    path = PurePosixPath(location["path"])
    if path.is_absolute() or ".." in path.parts:
        message = "scan finding path escapes the scan root"
        raise PypiValidateError(message)
    action_minor = _action_version_minor(finding.get("action_version"))
    interpreters_needed = _finding_interpreters_needed(
        action_minor, baseline_minor=baseline_minor, horizon_minor=horizon_minor
    )
    adjudication_status = (
        "not-adjudicable:no-interpreter" if action_minor > horizon_minor else "pending"
    )
    return {
        **finding,
        "module": _module_name(path),
        "interpreters_needed": list(interpreters_needed),
        "adjudication_status": adjudication_status,
    }


# --- adjudication ----------------------------------------------------------


@dataclass(frozen=True)
class SubjectDescriptor:
    """A resolved `{owner_module, attribute_path}` pair identifying `S`."""

    owner_module: str
    attribute_path: tuple[str, ...]

    def as_probe(self) -> dict[str, Any]:
        """Render as the `{owner_module, attribute_path}` probe descriptor shape."""
        return {
            "owner_module": self.owner_module,
            "attribute_path": list(self.attribute_path),
        }


@dataclass(frozen=True)
class BindingTarget:
    """Where to look up the finding's recorded binding inside module `M`."""

    module: str
    enclosing_scope: tuple[str, ...] | None
    head: str
    attribute_path: tuple[str, ...]
    subject: SubjectDescriptor


@cache
def _stdlib_owner_module(qualified_name: str) -> SubjectDescriptor:
    """Find the longest importable module prefix of a dotted stdlib name.

    A call-shape or qualified-reference subject may name a class attribute or
    method (e.g. `smtplib.SMTP.starttls`), so the module/attribute boundary
    cannot be assumed from dot position. Every candidate here is a CPython
    stdlib dotted name drawn from the registry's own scope, so importing
    prefixes with the tool's own interpreter is safe (never third-party code).
    """
    parts = qualified_name.split(".")
    for split_at in range(len(parts), 0, -1):
        candidate = ".".join(parts[:split_at])
        try:
            importlib.import_module(candidate)
        except Exception:  # noqa: BLE001, S112 - failure means "try a shorter prefix".
            continue
        return SubjectDescriptor(candidate, tuple(parts[split_at:]))
    return SubjectDescriptor(parts[0], tuple(parts[1:]))


def _finding_evidence(finding: dict[str, Any]) -> dict[str, Any]:
    match = finding.get("match")
    evidence = match.get("evidence") if isinstance(match, dict) else None
    return evidence if isinstance(evidence, dict) else {}


def _module_import_subject(
    imported_module: str, evidence: dict[str, Any]
) -> SubjectDescriptor | None:
    """Name S per import syntax: `from A import B` is `A.B`; `import A` is `A`.

    Mirrors `_binding_target`'s from-import branch: `from A import B` binds
    `B` to the attribute itself, so `S` is `A.B`, not `A`. Evidence only
    records the *bound* name, which for `from A import B as C` is `C`, not
    `B` - there is no way to recover the pre-alias attribute from static
    evidence alone. An aliased from-import therefore names a nonexistent
    attribute on `A` here, which correctly resolves to "absent" (not a false
    identity match) and yields `not-adjudicable:module-not-importable`
    rather than a wrong verdict - see the "aliased from-import" limitation
    in docs/pypi-validation.md.
    """
    if evidence.get("syntax") != "from-import":
        return SubjectDescriptor(imported_module, ())
    bound_names = evidence.get("bound_names")
    if (
        not isinstance(bound_names, list)
        or not bound_names
        or not isinstance(bound_names[0], str)
    ):
        return None
    return SubjectDescriptor(imported_module, (bound_names[0],))


def _subject_descriptor(finding: dict[str, Any]) -> SubjectDescriptor | None:
    """Derive `S`'s import path from the finding's own match evidence.

    The registry's authored `subject` name is not used: a single rule can
    cover several sibling modules (e.g. `sre_compile`/`sre_parse`), so only
    the evidence actually recorded at this finding's site identifies `S`.
    """
    match = finding.get("match")
    if not isinstance(match, dict):
        return None
    evidence = _finding_evidence(finding)
    if match.get("kind") == "module-import":
        imported_module = evidence.get("imported_module")
        if not isinstance(imported_module, str) or not imported_module:
            return None
        return _module_import_subject(imported_module, evidence)
    if match.get("kind") in _QUALIFIED_MATCH_KINDS:
        qualified_names = evidence.get("qualified_names")
        if (
            not isinstance(qualified_names, list)
            or not qualified_names
            or not isinstance(qualified_names[0], str)
        ):
            return None
        return _stdlib_owner_module(qualified_names[0])
    return None


def _enclosing_scope_path(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, str) or value == "<module>":
        return None
    return tuple(value.split("."))


def _binding_target(
    finding: dict[str, Any], subject: SubjectDescriptor
) -> BindingTarget | None:
    """Where the finding's recorded name should be visible inside module `M`."""
    match = finding["match"]
    evidence = _finding_evidence(finding)
    enclosing_scope = _enclosing_scope_path(finding.get("enclosing_scope"))
    module = finding["module"]
    if match["kind"] == "module-import":
        bound_names = evidence.get("bound_names")
        syntax = evidence.get("syntax")
        imported_module = evidence.get("imported_module")
        if (
            not isinstance(bound_names, list)
            or not bound_names
            or not isinstance(bound_names[0], str)
            or not isinstance(syntax, str)
            or not isinstance(imported_module, str)
        ):
            return None
        head = bound_names[0]
        if syntax == "from-import":
            # `from A import B` binds B directly to the attribute itself.
            attribute_path: tuple[str, ...] = ()
        else:
            # Plain `import a.b.c` binds only "a"; an alias binds the target
            # directly, with no further attributes to walk.
            top_level = imported_module.split(".")[0]
            attribute_path = (
                tuple(imported_module.split(".")[1:]) if head == top_level else ()
            )
        return BindingTarget(module, enclosing_scope, head, attribute_path, subject)
    if match["kind"] in _QUALIFIED_MATCH_KINDS:
        qualified_names = evidence.get("qualified_names")
        if (
            not isinstance(qualified_names, list)
            or not qualified_names
            or not isinstance(qualified_names[0], str)
        ):
            return None
        parts = qualified_names[0].split(".")
        return BindingTarget(
            module, enclosing_scope, parts[0], tuple(parts[1:]), subject
        )
    return None


def _binding_probe_payload(fingerprint: str, target: BindingTarget) -> dict[str, Any]:
    return {
        "id": fingerprint,
        "kind": "binding",
        "module": target.module,
        "enclosing_scope": (
            list(target.enclosing_scope) if target.enclosing_scope is not None else None
        ),
        "head": target.head,
        "attribute_path": list(target.attribute_path),
        "subject": target.subject.as_probe(),
    }


def _call_shape_probe_payload(
    finding: dict[str, Any], subject: SubjectDescriptor
) -> dict[str, Any] | None:
    evidence = _finding_evidence(finding)
    positional_count = evidence.get("positional_count")
    keyword_names = evidence.get("keyword_names")
    if not isinstance(positional_count, str) or not positional_count.isdigit():
        return None
    if not isinstance(keyword_names, list) or not all(
        isinstance(name, str) for name in keyword_names
    ):
        return None
    return {
        "kind": "call-shape",
        "subject": subject.as_probe(),
        "positional_count": int(positional_count),
        "keyword_names": list(keyword_names),
    }


_BINDING_FAILURE_REASONS = frozenset({"import-error", "binding-not-visible"})
_MODULE_NOT_FOUND_PATTERN = re.compile(
    r"^ModuleNotFoundError: No module named '([^']*)'$"
)


def _module_not_found_name(error_text: object) -> str | None:
    """Return the missing module named by a probe's `ModuleNotFoundError` text."""
    if not isinstance(error_text, str):
        return None
    match = _MODULE_NOT_FOUND_PATTERN.match(error_text)
    return match.group(1) if match else None


def _binding_verdict(  # noqa: PLR0911, PLR0913 - one branch/input per C1 concern.
    result: dict[str, Any],
    *,
    subject: SubjectDescriptor,
    action_minor: int,
    impact: str,
    reference_minor: int,
    expected_presence: str,
) -> tuple[str | None, dict[str, Any]]:
    """Return one of (verdict, evidence) or (None, evidence) when C1 holds.

    An import failure is usually inconclusive, but when it is a
    `ModuleNotFoundError` naming exactly `S`'s owner module, and the registry
    already expects `S` to be gone by the reference interpreter, that failure
    *is* the finding: the code as written cannot even be imported because `S`
    was removed. This is the strongest available confirmation - a
    `module-import-end-to-end` verdict - so it short-circuits C2 rather than
    falling through to a generic `not-adjudicable:import-error`.

    Symmetrically, an identity mismatch derived only from `S` being *absent*
    (the probe found a live binding but nothing to compare it against) is a
    refutation only where the registry itself expects `S` to be gone by
    `reference_minor` (`expected_presence == "absent"`): that is the
    version-gated-fallback shape the cross-check exists to catch. Where the
    registry still expects `S` to be present, its absence means `S` was not
    observable at all - an aliased `from A import B as C` names the
    nonexistent `A.C`, a platform-only attribute is missing on this host, a
    runtime-set attribute like `sys.last_type` is unset in a fresh
    interpreter - and C1 has nothing to compare, so the finding is
    `not-adjudicable:module-not-importable` rather than wrongly refuted.
    """
    status = result.get("status")
    evidence = {
        "status": status,
        "identity_match": result.get("identity_match"),
        "subject_status": result.get("subject_status"),
    }
    if status == "import-error":
        missing = _module_not_found_name(result.get("error"))
        # `missing` may name `S`'s owner module exactly, or one of its
        # dotted-path parents: importing `pkg.sub.mod` first imports `pkg`,
        # then `pkg.sub`, so a missing parent surfaces as `error.name ==
        # "pkg"` even though the whole `pkg.sub.mod` chain - including the
        # owner module itself - is equally gone. See `_resolve_subject` in
        # `pypi_probe.py` for the identical reasoning on the C2 side.
        owner_missing = missing is not None and (
            missing == subject.owner_module
            or subject.owner_module.startswith(f"{missing}.")
        )
        if owner_missing and impact == "breaking" and action_minor <= reference_minor:
            return "confirmed", {**evidence, "confirmation": "module-import-end-to-end"}
    if status in _KNOWN_PROBE_FAILURE_STATUSES or status in _BINDING_FAILURE_REASONS:
        return f"not-adjudicable:{status}", evidence
    if status != "resolved":
        return "not-adjudicable:probe-crashed", evidence
    identity_match = result.get("identity_match")
    if identity_match is False:
        if result.get("subject_status") == "absent" and expected_presence == "present":
            return "not-adjudicable:module-not-importable", evidence
        return "refuted-binding", evidence
    if identity_match is True:
        return None, evidence
    # The subject itself was not present/resolvable at the reference interpreter.
    return "not-adjudicable:module-not-importable", evidence


def _timeline_event_minor(event: object) -> int | None:
    if not isinstance(event, dict):
        return None
    python = event.get("python")
    if not isinstance(python, str):
        return None
    try:
        return PythonMinor.parse(python).minor
    except InvalidPythonMinorError:
        return None


def _timeline_event_has_taken_effect(
    finding: dict[str, Any], *, event_type: str, minor: int
) -> bool:
    """Whether one of the finding's own `timeline` events has fired by `minor`."""
    timeline = finding.get("timeline")
    if not isinstance(timeline, list):
        return False
    for event in timeline:
        if not isinstance(event, dict) or event.get("event") != event_type:
            continue
        event_minor = _timeline_event_minor(event)
        if event_minor is not None and event_minor <= minor:
            return True
    return False


def _expected_presence(finding: dict[str, Any], minor: int) -> str:
    """Return the registry's claimed presence of `S` at one interpreter.

    Keyed on the finding's own `removed` timeline event, not on `impact`
    alone: a rule is "breaking" both when `S` is actually removed (S
    genuinely disappears) and when its behavior or call shape changes while
    `S` itself stays put (`ssl.SSLSession` after its behavior change, for
    instance). Only the former ever makes "absent" the registry's claim -
    conflating the two turns a subject that never left into a false
    `refuted-timeline`.
    """
    if _timeline_event_has_taken_effect(finding, event_type="removed", minor=minor):
        return "absent"
    return "present"


def _expected_call_shape(finding: dict[str, Any], minor: int) -> str:
    """Return the registry's claimed call-shape acceptance at one interpreter.

    "Rejected" is the registry's claim only when `S` itself is gone
    (`_expected_presence`) or its own `signature_changed` event has fired -
    the one timeline event that actually changes what
    `inspect.signature(...).bind_partial` accepts. A `behavior_changed` or
    `support_dropped` rule that flags one specific literal argument value
    (`shlex.split(None)`, `webbrowser.get("grail")`) still binds at the
    signature level even once it starts raising at runtime, so it must not
    be asserted as "rejected" merely because the rule is breaking.
    """
    if _expected_presence(finding, minor) == "absent":
        return "rejected"
    if _timeline_event_has_taken_effect(
        finding, event_type="signature_changed", minor=minor
    ):
        return "rejected"
    return "accepted"


def _observed_presence(result: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return `(observed-state, not-adjudicable-reason)` for a subject probe."""
    status = result.get("status")
    if status == "present":
        return "present", None
    if status == "absent":
        return "absent", None
    if status == "import-error":
        return None, "import-error"
    if status in _KNOWN_PROBE_FAILURE_STATUSES:
        return None, status
    return None, "probe-crashed"


def _observed_call_shape(result: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return `(observed-state, not-adjudicable-reason)` for a call-shape probe."""
    status = result.get("status")
    if status == "accepted":
        return "accepted", None
    if status in ("rejected", "absent"):
        return "rejected", None
    if status == "no-signature":
        return None, "no-signature"
    if status == "import-error":
        return None, "import-error"
    if status in _KNOWN_PROBE_FAILURE_STATUSES:
        return None, status
    return None, "probe-crashed"


def _extra_binding_refutation(
    finding: dict[str, Any],
    *,
    subject: SubjectDescriptor,
    reference_minor: int,
    available_minors: frozenset[int],
    results_by_minor: dict[int, dict[str, dict[str, Any]]],
) -> dict[str, Any] | None:
    """Cross-check C1 at any other needed minor whose own venv is available.

    A version-gated fallback (`if sys.version_info >= (3, 12): ... else:
    ...`) binds a different object at different interpreters, so a hold at
    the reference interpreter alone cannot rule it out. Only a clean
    refutation (identity genuinely does not match) overrides the reference
    verdict; an inconsistent probe at one extra minor (crashed, subject not
    importable there, ...) is not treated as a reason to make an otherwise
    confirmable finding not-adjudicable.
    """
    fingerprint = finding["fingerprint"]
    action_minor = _action_version_minor(finding["action_version"])
    impact = finding["impact"]
    for minor in finding["interpreters_needed"]:
        if minor == reference_minor or minor not in available_minors:
            continue
        result = results_by_minor.get(minor, {}).get(fingerprint)
        if result is None:
            continue
        verdict, evidence = _binding_verdict(
            result,
            subject=subject,
            action_minor=action_minor,
            impact=impact,
            reference_minor=minor,
            expected_presence=_expected_presence(finding, minor),
        )
        if verdict == "refuted-binding":
            return evidence
    return None


def _run_binding_phase(
    pending: list[dict[str, Any]],
    *,
    run_binding_probes: _ProbeRunner,
    reference_minor: int,
    available_minors: frozenset[int],
) -> tuple[list[dict[str, Any]], dict[str, SubjectDescriptor]]:
    """Run C1 binding probes; assign a verdict in place for every non-holding one.

    C1 is always checked at the reference interpreter - already sufficient
    to confirm or refute many findings (module-import-end-to-end, or a
    straightforward identity mismatch), which a host with only one
    interpreter installed must still be able to reach. When a finding's own
    `interpreters_needed` includes another minor whose own installed-package
    venv is also available, that minor is cross-checked too, additionally
    catching a version-gated fallback that binds a different object away
    from the reference (see `_extra_binding_refutation`).
    """
    subject_by_fingerprint: dict[str, SubjectDescriptor] = {}
    probes_by_minor: dict[int, list[dict[str, Any]]] = {}
    for finding in pending:
        subject = _subject_descriptor(finding)
        target = _binding_target(finding, subject) if subject is not None else None
        if subject is None or target is None:
            finding["adjudication_status"] = "not-adjudicable:module-not-importable"
            continue
        fingerprint = finding["fingerprint"]
        subject_by_fingerprint[fingerprint] = subject
        minors = {reference_minor} | (
            set(finding["interpreters_needed"]) & available_minors
        )
        for minor in minors:
            probes_by_minor.setdefault(minor, []).append(
                _binding_probe_payload(fingerprint, target)
            )

    results_by_minor = {
        minor: run_binding_probes(minor, probes)
        for minor, probes in probes_by_minor.items()
    }

    c1_confirmed: list[dict[str, Any]] = []
    for finding in pending:
        fingerprint = finding["fingerprint"]
        if fingerprint not in subject_by_fingerprint:
            continue
        subject = subject_by_fingerprint[fingerprint]
        reference_result = results_by_minor.get(reference_minor, {}).get(fingerprint)
        if reference_result is None:
            finding["adjudication_status"] = "not-adjudicable:probe-crashed"
            finding["adjudication_evidence"] = {"binding": {}}
            continue
        verdict, evidence = _binding_verdict(
            reference_result,
            subject=subject,
            action_minor=_action_version_minor(finding["action_version"]),
            impact=finding["impact"],
            reference_minor=reference_minor,
            expected_presence=_expected_presence(finding, reference_minor),
        )
        if verdict is None:
            extra_evidence = _extra_binding_refutation(
                finding,
                subject=subject,
                reference_minor=reference_minor,
                available_minors=available_minors,
                results_by_minor=results_by_minor,
            )
            if extra_evidence is not None:
                verdict, evidence = "refuted-binding", extra_evidence
        finding["adjudication_evidence"] = {"binding": evidence}
        if verdict is not None:
            finding["adjudication_status"] = verdict
            continue
        c1_confirmed.append(finding)
    return c1_confirmed, subject_by_fingerprint


@dataclass(frozen=True)
class TimelinePlan:
    """Deduplicated C2 probes to run, and which probe id answers which finding."""

    probes_by_interpreter: dict[int, list[dict[str, Any]]]
    subject_probe_id: dict[str, dict[int, str]]
    call_shape_probe_id: dict[str, dict[int, str]]


def _build_timeline_plan(
    findings: list[dict[str, Any]],
    subject_by_fingerprint: dict[str, SubjectDescriptor],
) -> TimelinePlan:
    """Cross-check C2 once per (subject, interpreter), shared across findings."""
    probes_by_interpreter: dict[int, list[dict[str, Any]]] = {}
    subject_cache: dict[tuple[str, tuple[str, ...], int], str] = {}
    call_shape_cache: dict[
        tuple[str, tuple[str, ...], int, int, tuple[str, ...]], str
    ] = {}
    subject_probe_id: dict[str, dict[int, str]] = {}
    call_shape_probe_id: dict[str, dict[int, str]] = {}

    for finding in findings:
        fingerprint = finding["fingerprint"]
        subject = subject_by_fingerprint[fingerprint]
        is_call_shape = finding["match"]["kind"] == "call-shape"
        for minor in finding["interpreters_needed"]:
            key = (subject.owner_module, subject.attribute_path, minor)
            probe_id = subject_cache.get(key)
            if probe_id is None:
                probe_id = f"subject-{len(subject_cache)}"
                subject_cache[key] = probe_id
                probes_by_interpreter.setdefault(minor, []).append(
                    {"id": probe_id, "kind": "subject", **subject.as_probe()}
                )
            subject_probe_id.setdefault(fingerprint, {})[minor] = probe_id

            if not is_call_shape:
                continue
            shape = _call_shape_probe_payload(finding, subject)
            if shape is None:
                continue
            shape_key = (
                subject.owner_module,
                subject.attribute_path,
                minor,
                shape["positional_count"],
                tuple(shape["keyword_names"]),
            )
            shape_id = call_shape_cache.get(shape_key)
            if shape_id is None:
                shape_id = f"callshape-{len(call_shape_cache)}"
                call_shape_cache[shape_key] = shape_id
                probes_by_interpreter.setdefault(minor, []).append(
                    {**shape, "id": shape_id}
                )
            call_shape_probe_id.setdefault(fingerprint, {})[minor] = shape_id

    return TimelinePlan(probes_by_interpreter, subject_probe_id, call_shape_probe_id)


def _evaluate_timeline(
    finding: dict[str, Any],
    *,
    plan: TimelinePlan,
    interpreter_results: dict[int, dict[str, dict[str, Any]]],
) -> None:
    """Assign `confirmed`/`refuted-timeline`/`not-adjudicable:<reason>` in place."""
    fingerprint = finding["fingerprint"]
    is_call_shape = finding["match"]["kind"] == "call-shape"
    observed_by_minor: dict[int, str | None] = {}
    # Not scored (see docs/pypi-validation.md's "Deprecation onset" limitation),
    # but retained on every verdict so triage can see whether Python's own
    # DeprecationWarning actually fired at the interpreters probed.
    deprecation_warnings_by_minor: dict[int, str] = {}

    for minor in sorted(finding["interpreters_needed"]):
        if is_call_shape:
            probe_id = plan.call_shape_probe_id.get(fingerprint, {}).get(minor)
            if probe_id is None:
                finding["adjudication_status"] = "not-adjudicable:no-signature"
                return
            result = interpreter_results.get(minor, {}).get(probe_id)
            observed, reason = (
                (None, "probe-crashed")
                if result is None
                else _observed_call_shape(result)
            )
            expected = _expected_call_shape(finding, minor)
        else:
            probe_id = plan.subject_probe_id[fingerprint][minor]
            result = interpreter_results.get(minor, {}).get(probe_id)
            observed, reason = (
                (None, "probe-crashed")
                if result is None
                else _observed_presence(result)
            )
            expected = _expected_presence(finding, minor)
            deprecation_warning = (
                None if result is None else result.get("deprecation_warning")
            )
            if isinstance(deprecation_warning, str):
                deprecation_warnings_by_minor[minor] = deprecation_warning

        if reason is not None:
            finding["adjudication_status"] = f"not-adjudicable:{reason}"
            return
        observed_by_minor[minor] = observed
        if observed != expected:
            finding["adjudication_status"] = "refuted-timeline"
            finding["adjudication_evidence"] = {
                **finding.get("adjudication_evidence", {}),
                "timeline": {
                    "rule_id": finding["rule_id"],
                    "interpreter": minor,
                    "observed": observed,
                    "deprecation_warnings": deprecation_warnings_by_minor,
                },
            }
            return

    finding["adjudication_status"] = "confirmed"
    finding["adjudication_evidence"] = {
        **finding.get("adjudication_evidence", {}),
        "timeline": {
            "observed": observed_by_minor,
            "deprecation_warnings": deprecation_warnings_by_minor,
        },
    }


def _adjudicate(  # noqa: PLR0913 - one input per independent adjudication concern.
    findings: list[dict[str, Any]],
    *,
    installed: Mapping[int, InstalledInterpreter],
    reference_minor: int,
    available_binding_minors: frozenset[int],
    run_binding_probes: _ProbeRunner,
    run_subject_probes: _ProbeRunner,
) -> tuple[list[dict[str, Any]], frozenset[int]]:
    """Adjudicate every `pending` finding against a real CPython interpreter.

    `run_binding_probes(minor, ...)` targets that minor's own installed-package
    venv (binding probes, C1, always checked at `reference_minor` and
    additionally cross-checked at any other minor the finding needs whose
    own venv is available - see `_run_binding_phase`). `run_subject_probes(minor,
    ...)` targets the bare interpreter for that minor (subject/call-shape
    probes, C2).
    """
    updated = [dict(finding) for finding in findings]
    pending = [
        finding for finding in updated if finding["adjudication_status"] == "pending"
    ]

    c1_confirmed, subject_by_fingerprint = _run_binding_phase(
        pending,
        run_binding_probes=run_binding_probes,
        reference_minor=reference_minor,
        available_minors=available_binding_minors,
    )

    timeline_pending: list[dict[str, Any]] = []
    for finding in c1_confirmed:
        missing = [
            minor for minor in finding["interpreters_needed"] if minor not in installed
        ]
        if missing:
            finding["adjudication_status"] = "not-adjudicable:no-interpreter"
            continue
        timeline_pending.append(finding)

    plan = _build_timeline_plan(timeline_pending, subject_by_fingerprint)
    interpreter_results = {
        minor: run_subject_probes(minor, probes)
        for minor, probes in plan.probes_by_interpreter.items()
    }
    for finding in timeline_pending:
        _evaluate_timeline(finding, plan=plan, interpreter_results=interpreter_results)

    return updated, frozenset(plan.probes_by_interpreter)


def _adjudication_summary(
    findings: list[dict[str, Any]], *, interpreters_used: frozenset[int]
) -> dict[str, Any]:
    verdicts: dict[str, int] = {}
    not_adjudicable_reasons: dict[str, int] = {}
    for finding in findings:
        status = finding["adjudication_status"]
        if status.startswith("not-adjudicable:"):
            reason = status.removeprefix("not-adjudicable:")
            not_adjudicable_reasons[reason] = not_adjudicable_reasons.get(reason, 0) + 1
            verdicts["not-adjudicable"] = verdicts.get("not-adjudicable", 0) + 1
        else:
            verdicts[status] = verdicts.get(status, 0) + 1
    return {
        "verdicts": verdicts,
        "not_adjudicable_reasons": not_adjudicable_reasons,
        "interpreters_used": sorted(interpreters_used),
    }


def _probe_batch_payload(probes: list[dict[str, Any]]) -> bytes:
    return json.dumps({"schema_version": 1, "probes": probes}).encode()


def _probe_result_subject_fields_well_typed(item: dict[str, Any]) -> bool:
    return isinstance(item["deprecation_warning"], (str, type(None))) and isinstance(
        item["signature"], (str, type(None))
    )


_SUBJECT_STATUS_VALUES = frozenset({"present", "absent", "import-error"})
_RESOLVED_IDENTITY_MATCH_BY_SUBJECT_STATUS: dict[str, tuple[bool | None, ...]] = {
    "present": (True, False),
    "absent": (False,),
    "import-error": (None,),
}


def _probe_result_binding_fields_well_typed(item: dict[str, Any]) -> bool:
    """Enforce the exact `(subject_status, error, identity_match)` triples possible.

    Mirrors `_binding_fields_well_typed` in `pypi_probe.py`: checking each
    field's own type in isolation would still accept an impossible
    combination (e.g. a non-null `error` paired with `identity_match=True`)
    from a forged or corrupted record.
    """
    identity_match = item["identity_match"]
    subject_status = item["subject_status"]
    if not isinstance(identity_match, (bool, type(None))) or not isinstance(
        subject_status, (str, type(None))
    ):
        return False
    if item["status"] != "resolved":
        return True
    if subject_status not in _SUBJECT_STATUS_VALUES:
        return False
    expected: tuple[bool | None, ...]
    if item["error"] is not None:
        # Mirrors `pypi_probe.py`: a failed walk refutes, except when it
        # stopped at `S`'s own slot while `S` is absent, which is inconclusive.
        expected = (False, None) if subject_status == "absent" else (False,)
    else:
        expected = _RESOLVED_IDENTITY_MATCH_BY_SUBJECT_STATUS[subject_status]
    return identity_match in expected


_PROBE_RESULT_EXTRA_FIELD_CHECKS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "subject": _probe_result_subject_fields_well_typed,
    "binding": _probe_result_binding_fields_well_typed,
    "call-shape": lambda _item: True,
}


def _is_well_formed_probe_result(item: dict[str, Any], *, kind: str) -> bool:
    """Enforce the exact closed schema for one kind, not just its status vocabulary."""
    status = item.get("status")
    if status not in _PROBE_RESULT_STATUSES_BY_KIND[kind]:
        return False
    if status in _KNOWN_PROBE_FAILURE_STATUSES:
        return set(item) == _FAILURE_RESULT_FIELDS and isinstance(item["error"], str)
    if set(item) != _PROBE_RESULT_FIELDS_BY_KIND[kind]:
        return False
    if not isinstance(item["error"], (str, type(None))):
        return False
    return _PROBE_RESULT_EXTRA_FIELD_CHECKS[kind](item)


def _parse_probe_batch_output(stdout: bytes) -> dict[str, dict[str, Any]]:
    """Parse a probe batch result, trusting nothing the target process wrote.

    Target code executes inside the process that produces this output, so a
    forged or malformed record must never reach adjudication: any schema
    violation - wrong `schema_version`, a non-closed `kind`, a `status` not
    in that kind's own closed vocabulary, a field missing or of the wrong
    type, or a duplicate `id` - discards the whole batch rather than the one
    offending record.
    """
    try:
        document: Any = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return {}
    items = document.get("results")
    if not isinstance(items, list):
        return {}
    results: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            return {}
        kind = item.get("kind")
        if (
            item["id"] in results
            or not isinstance(kind, str)
            or kind not in _PROBE_RESULT_STATUSES_BY_KIND
            or not _is_well_formed_probe_result(item, kind=kind)
        ):
            return {}
        results[item["id"]] = item
    return results


def _import_timeout_results(probes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Every probe in a batch whose own subprocess never got to answer.

    Distinct from `probe-timeout`, which pypi_probe.py reports for one
    probe whose individual wall-clock budget ran out: this is the harness's
    own `subprocess.run` timeout on the *whole* batch process, so no
    individual probe ever ran at all. Returning `{}` here would discard
    that distinction - every one of these probes would surface downstream
    as the unrelated `not-adjudicable:probe-crashed`, losing the deciding
    evidence that it was a timeout.
    """
    return {
        probe["id"]: {
            "id": probe["id"],
            "kind": probe["kind"],
            "status": "import-timeout",
            "error": "probe batch subprocess exceeded its timeout",
        }
        for probe in probes
    }


def _run_bare_probe_batch(
    python_path: Path,
    probes: list[dict[str, Any]],
    *,
    timeout: float,
    scratch_home: Path,
    options: RunOptions,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Run stdlib-only subject/call-shape probes under a bare interpreter.

    Stdlib-only does not mean risk-free: an interpreter invoked without
    `-I` still loads user-site and `sitecustomize`/`usercustomize` code at
    startup, from whatever `HOME` and site directories it sees. This gets
    the same sandboxing (isolation mode, scratch home, resource limits) as
    the C1 binding probes, not a lighter-weight path, and returns which
    mode actually ran so the shard cannot report a stronger isolation mode
    than what C2 used.
    """
    if not probes:
        return {}, "rlimit-only"
    extra_read_only = [_PROBE_SCRIPT]
    if options.python_install_dir is not None:
        extra_read_only.append(options.python_install_dir)
    isolation = _isolate_command(
        [str(python_path), str(_PROBE_SCRIPT)],
        bwrap=options.bwrap,
        venv_dir=None,
        scratch_home=scratch_home,
        venv_writable=False,
        read_only_binds=tuple(extra_read_only),
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, sandboxed interpreter.
            isolation.command,
            input=_probe_batch_payload(probes),
            cwd=scratch_home,
            env=_install_environment(home=scratch_home),
            capture_output=True,
            timeout=timeout,
            check=False,
            preexec_fn=lambda: _apply_resource_limits(_INSTALL_LIMITS),
        )
    except subprocess.TimeoutExpired:
        return _import_timeout_results(probes), isolation.mode
    if completed.returncode != 0:
        return {}, isolation.mode
    return _parse_probe_batch_output(completed.stdout), isolation.mode


def _run_binding_probe_batch(
    probes: list[dict[str, Any]],
    *,
    venv_dir: Path,
    scratch_home: Path,
    options: RunOptions,
) -> tuple[dict[str, dict[str, Any]], str]:
    """Run binding probes (C1) against the installed package under one venv.

    `venv_dir` may be the reference venv or any other minor's own
    installed-package venv - see `_run_binding_phase`.
    """
    if not probes:
        return {}, "rlimit-only"
    venv_python = venv_dir / "bin" / "python"
    extra_read_only = [_PROBE_SCRIPT]
    if options.python_install_dir is not None:
        extra_read_only.append(options.python_install_dir)
    isolation = _isolate_command(
        [str(venv_python), str(_PROBE_SCRIPT)],
        bwrap=options.bwrap,
        venv_dir=venv_dir,
        scratch_home=scratch_home,
        venv_writable=False,
        read_only_binds=tuple(extra_read_only),
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, sandboxed target code.
            isolation.command,
            input=_probe_batch_payload(probes),
            cwd=scratch_home,
            env=_install_environment(home=scratch_home),
            capture_output=True,
            timeout=options.timeout,
            check=False,
            preexec_fn=lambda: _apply_resource_limits(_INSTALL_LIMITS),
        )
    except subprocess.TimeoutExpired:
        return _import_timeout_results(probes), isolation.mode
    if completed.returncode != 0:
        return {}, isolation.mode
    return _parse_probe_batch_output(completed.stdout), isolation.mode


# --- per-package orchestration -------------------------------------------


def _write_atomic(path: Path, content: str) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _package_base(entry: PackageEntry, *, manifest_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "manifest_sha256": manifest_sha256,
        "package": {
            "rank": entry.rank,
            "name": entry.name,
            "version": entry.version,
            "filename": entry.filename,
            "sha256": entry.sha256,
            "requires_python": entry.requires_python,
            "is_wheel": entry.is_wheel,
        },
    }


def _provision_binding_venvs(  # noqa: PLR0913 - one venv input per provisioning input.
    entry: PackageEntry,
    *,
    findings: list[dict[str, Any]],
    reference_minor: int,
    reference_venv: BindingVenv,
    installed: Mapping[int, InstalledInterpreter],
    package_dir: Path,
    options: RunOptions,
) -> dict[int, BindingVenv]:
    """Provision one C1 venv per interpreter minor any finding actually needs.

    A version-gated fallback binds a different object at different
    interpreters, so C1 must be checked under every interpreter a finding
    needs, each with the distribution genuinely installed - not only under
    whichever interpreter happened to scan the package. The reference venv
    is reused for its own minor rather than installed twice.
    """
    binding_venvs: dict[int, BindingVenv] = {reference_minor: reference_venv}
    extra_minors = sorted(
        {minor for finding in findings for minor in finding["interpreters_needed"]}
        - {reference_minor}
    )
    for minor in extra_minors:
        candidate = installed.get(minor)
        if candidate is None:
            continue
        provisioned = _provision_binding_venv(
            entry,
            python_path=candidate.path,
            package_dir=package_dir,
            label=str(minor),
            options=options,
        )
        if provisioned is not None:
            binding_venvs[minor] = provisioned
    return binding_venvs


def _process_package(  # noqa: C901, PLR0911 - one early return per closed shard status.
    entry: PackageEntry,
    *,
    installed: Mapping[int, InstalledInterpreter],
    options: RunOptions,
) -> dict[str, Any]:
    base = _package_base(entry, manifest_sha256=options.manifest_sha256)
    reference = _reference_interpreter(
        entry.requires_python,
        installed,
        baseline_minor=options.baseline_minor,
        horizon_minor=options.horizon_minor,
        filename=entry.filename,
        is_wheel=entry.is_wheel,
    )
    if reference is None:
        return {
            **base,
            "status": "skipped",
            "reason": "no-compatible-interpreter",
            "isolation_mode": None,
            "interpreter": None,
        }

    interpreter_info = {
        "reference_minor": reference.minor,
        "reference_version": reference.version,
    }
    package_dir = options.work_dir / "tmp" / f"{entry.rank:04d}"
    venv_dir = package_dir / "venv"
    scratch_home = package_dir / "home"
    isolation_mode: str | None = None
    try:
        package_dir.mkdir(parents=True, exist_ok=True)
        scratch_home.mkdir(parents=True, exist_ok=True)

        try:
            _create_venv(
                options.uv, reference.path, venv_dir, timeout=_VENV_TIMEOUT_SECONDS
            )
        except (PypiValidateError, subprocess.TimeoutExpired) as error:
            return {
                **base,
                "status": "install-failed",
                "reason": str(error),
                "isolation_mode": None,
                "interpreter": interpreter_info,
            }

        # Resolved from the bare venv, before any third-party code is
        # installed into it: querying it after install would run the just
        # installed distribution's `.pth`/`sitecustomize.py` startup code
        # outside the bwrap/rlimit isolation that `_install_distribution`
        # and the probes use.
        site_packages = _site_packages_dir(
            venv_dir / "bin" / "python", timeout=options.timeout
        )

        isolation_mode, install_error = _install_distribution(
            entry, venv_dir=venv_dir, scratch_home=scratch_home, options=options
        )
        if install_error is not None:
            return {
                **base,
                "status": "install-failed",
                "reason": install_error,
                "isolation_mode": isolation_mode,
                "interpreter": interpreter_info,
            }

        dist_info = _distribution_info_dir(
            site_packages, normalized_name=_normalized_name(entry.name)
        )
        owned = _owned_python_files(dist_info)
        if not owned:
            return {
                **base,
                "status": "skipped",
                "reason": "no-python-files",
                "isolation_mode": isolation_mode,
                "interpreter": interpreter_info,
            }

        scan = _run_scan(
            site_packages,
            include_patterns=_include_patterns(owned),
            baseline_minor=reference.minor,
            horizon_minor=options.horizon_minor,
            timeout=options.timeout,
        )
        if scan.error is not None:
            return {
                **base,
                "status": "scan-failed",
                "reason": scan.error,
                "isolation_mode": isolation_mode,
                "interpreter": interpreter_info,
            }

        findings = [
            _mapped_finding(
                finding,
                baseline_minor=options.baseline_minor,
                horizon_minor=options.horizon_minor,
            )
            for finding in scan.findings
        ]

        binding_venvs = _provision_binding_venvs(
            entry,
            findings=findings,
            reference_minor=reference.minor,
            reference_venv=BindingVenv(venv_dir=venv_dir, scratch_home=scratch_home),
            installed=installed,
            package_dir=package_dir,
            options=options,
        )

        # `None` until a probe batch actually runs: a package with nothing to
        # probe must not claim the unsandboxed `rlimit-only` fallback ran.
        probe_isolation_mode: str | None = None

        def _run_binding_probes(
            minor: int, probes: list[dict[str, Any]]
        ) -> dict[str, dict[str, Any]]:
            nonlocal probe_isolation_mode
            binding_venv = binding_venvs.get(minor)
            if binding_venv is None:
                return {}
            results, mode = _run_binding_probe_batch(
                probes,
                venv_dir=binding_venv.venv_dir,
                scratch_home=binding_venv.scratch_home,
                options=options,
            )
            probe_isolation_mode = mode
            return results

        def _run_subject_probes(
            minor: int, probes: list[dict[str, Any]]
        ) -> dict[str, dict[str, Any]]:
            nonlocal probe_isolation_mode
            candidate = installed.get(minor)
            if candidate is None:
                return {}
            results, mode = _run_bare_probe_batch(
                candidate.path,
                probes,
                timeout=options.timeout,
                scratch_home=scratch_home,
                options=options,
            )
            probe_isolation_mode = mode
            return results

        findings, interpreters_used = _adjudicate(
            findings,
            installed=installed,
            reference_minor=reference.minor,
            available_binding_minors=frozenset(binding_venvs),
            run_binding_probes=_run_binding_probes,
            run_subject_probes=_run_subject_probes,
        )
        adjudication = _adjudication_summary(
            findings, interpreters_used=interpreters_used
        )
        adjudication["isolation_mode"] = probe_isolation_mode

        return {
            **base,
            "status": "scanned",
            "reason": None,
            "isolation_mode": isolation_mode,
            "interpreter": interpreter_info,
            "scan": {
                "exit_code": scan.exit_code,
                "duration_seconds": round(scan.duration_seconds, 6),
                "high_confidence_findings": len(findings),
            },
            "findings": findings,
            "adjudication": adjudication,
        }
    except (PypiValidateError, subprocess.TimeoutExpired) as error:
        # An unexpected failure anywhere past venv creation (a malformed scan
        # report, a hung site-packages query, ...) must not abort the whole
        # sharded sweep: record it against this one package and move on.
        return {
            **base,
            "status": "scan-failed",
            "reason": str(error),
            "isolation_mode": isolation_mode,
            "interpreter": interpreter_info,
        }
    finally:
        shutil.rmtree(package_dir, ignore_errors=True)


# --- CLI -------------------------------------------------------------------


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="pyahead-pypi-validate",
        description="provision, scan, and shard the pinned PyPI top-1000 corpus",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="provision interpreters and packages, scan, and write per-package shards",
    )
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--wheelhouse", type=Path, required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    run.add_argument(
        "--execute-third-party-code",
        action="store_true",
        help="required acknowledgement: this installs and imports arbitrary code",
    )
    run.add_argument("--shard", type=_shard_spec, default=(0, 1), metavar="INDEX/COUNT")
    run.add_argument("--refresh", action="store_true", help="reprocess existing shards")
    run.add_argument("--limit", type=_positive_integer, default=None)
    run.add_argument(
        "--timeout",
        type=_positive_float,
        default=300.0,
        help="maximum seconds for each install or scan subprocess (default: 300)",
    )
    run.add_argument("--horizon-python", default="3.15", metavar="VERSION")

    return parser


def _run(arguments: argparse.Namespace) -> None:
    if not arguments.execute_third_party_code:
        message = (
            "refusing to install and import third-party code without "
            "--execute-third-party-code"
        )
        raise PypiValidateError(message)

    try:
        horizon = PythonMinor.parse(arguments.horizon_python)
    except InvalidPythonMinorError as error:
        message = f"invalid --horizon-python: {error}"
        raise PypiValidateError(message) from error

    manifest_path = arguments.manifest.resolve(strict=True)
    _, entries = pypi_corpus.load_manifest(manifest_path)
    manifest_sha256 = _sha256_path(manifest_path)
    wheelhouse = arguments.wheelhouse.resolve(strict=True)

    # Resolved like the manifest and wheelhouse above: the per-package venv
    # and scratch home derive from this path and are handed to `bwrap` as
    # bind sources, which bubblewrap looks up against the sandbox's old root
    # rather than the caller's working directory, so a relative work
    # directory (as the documented invocation uses) fails every install
    # with "Can't find source path".
    work_dir = arguments.work_dir.resolve()
    shard_dir = work_dir / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)

    uv = _uv_executable()
    bwrap = shutil.which("bwrap")
    installed = _installed_interpreters(uv, timeout=arguments.timeout)
    python_install_dir = _uv_python_install_dir(uv, timeout=arguments.timeout)

    shard_index, shard_count = arguments.shard
    selected = [
        entry
        for entry in entries
        if _shard_selected(entry.rank, shard_index, shard_count)
    ]
    if arguments.limit is not None:
        selected = selected[: arguments.limit]

    options = RunOptions(
        wheelhouse=wheelhouse,
        work_dir=work_dir,
        timeout=arguments.timeout,
        horizon_minor=horizon.minor,
        baseline_minor=_BASELINE_MINOR,
        bwrap=bwrap,
        uv=uv,
        manifest_sha256=manifest_sha256,
        python_install_dir=python_install_dir,
    )

    for entry in selected:
        shard_path = shard_dir / f"{entry.rank:04d}-{_normalized_name(entry.name)}.json"
        if shard_path.exists() and not arguments.refresh:
            continue
        sys.stderr.write(f"[{entry.rank}] {escape_terminal_text(entry.name)}\n")
        result = _process_package(entry, installed=installed, options=options)
        _write_atomic(shard_path, json.dumps(result, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Provision, scan, and shard the pinned PyPI corpus offline."""
    arguments = _parser().parse_args(argv)
    try:
        _run(arguments)
    except (
        PypiValidateError,
        pypi_corpus.PypiCorpusError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        rendered = escape_terminal_text(str(error))
        sys.stderr.write(f"pypi validate run failed: {rendered}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
