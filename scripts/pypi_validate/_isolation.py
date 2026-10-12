"""Running untrusted installs and probes inside a sandbox."""

from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.pypi_validate._model import ResourceLimits


@dataclass(frozen=True)
class Isolation:
    """A command rewritten to run under sandboxing, and which mode was used."""

    mode: str
    command: list[str]


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
