"""Finding the managed interpreters a package can be scanned under."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from pyahead.registry import load_registry
from pyahead.versions import InvalidPythonMinorError, PythonMinor
from scripts import pypi_corpus

if TYPE_CHECKING:
    from collections.abc import Mapping


from scripts.pypi_validate._isolation import _install_environment
from scripts.pypi_validate._model import (
    _SUPPORTED_MAJOR,
    InstalledInterpreter,
    PypiValidateError,
    _tail,
)


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


def _reference_candidates(  # noqa: PLR0913 - mirrors the manifest entry's own fields.
    requires_python: str | None,
    installed: Mapping[int, InstalledInterpreter],
    *,
    baseline_minor: int,
    horizon_minor: int,
    filename: str,
    is_wheel: bool,
) -> tuple[InstalledInterpreter, ...]:
    """Every installed minor the entry could be scanned under, lowest first.

    The first is the reference the package claims to support. Its dependency
    tree may not install there from a one-artifact-per-package wheelhouse:
    the current release of a dependency can require a newer Python than the
    package still declares, or ship only a wheel tagged for the interpreter
    the corpus was acquired with. The runner then moves to the next candidate
    and records why, so the scan happens at the lowest floor the package
    actually installs at rather than being skipped.
    """
    specifier: SpecifierSet | None = None
    if requires_python:
        try:
            specifier = SpecifierSet(requires_python)
        except InvalidSpecifier:
            specifier = None
    candidates: list[InstalledInterpreter] = []
    for minor in range(baseline_minor, horizon_minor + 1):
        candidate = installed.get(minor)
        if candidate is None:
            continue
        version = Version(candidate.version)
        if specifier is not None and not specifier.contains(version, prereleases=True):
            continue
        if is_wheel and not pypi_corpus.wheel_supports_minor(filename, minor):
            continue
        candidates.append(candidate)
    return tuple(candidates)


def _registry_window_floor() -> int:
    """Return the oldest minor the bundled registry admits as a baseline.

    The sweep scans each package at its own floor, and that floor cannot be
    lower than the registry window. It used to be the constant 11; when the
    window opened at 3.8 that constant silently scanned every package at 3.11
    and never exercised a rule whose event fell before it. Reading the window
    from the registry means the sweep measures what the registry claims.
    """
    return min(release.python.minor for release in load_registry().releases)


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
