"""Creating the virtual environment and installing one package."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.pypi_corpus import PackageEntry

from scripts.pypi_validate._isolation import (
    _apply_resource_limits,
    _install_environment,
    _isolate_command,
)
from scripts.pypi_validate._model import (
    _INSTALL_LIMITS,
    _VENV_TIMEOUT_SECONDS,
    PypiValidateError,
    _tail,
)

if TYPE_CHECKING:
    from scripts.pypi_validate._model import RunOptions


def _uv_executable() -> str:
    uv = shutil.which("uv")
    if uv is None:
        message = "uv is required to provision interpreters and packages"
        raise PypiValidateError(message)
    # Resolved: the sandbox binds the resolved file, so a PATH entry that is a
    # symlink (Homebrew's bin/uv -> ../Cellar/uv/<version>/bin/uv) would be
    # exec'd at a path the sandbox does not contain.
    return str(Path(uv).resolve())


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
