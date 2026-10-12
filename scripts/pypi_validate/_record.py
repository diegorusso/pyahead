"""Selecting scannable paths and module names from a wheel's RECORD."""

from __future__ import annotations

from importlib.metadata import PathDistribution
from pathlib import Path, PurePosixPath

from scripts._common import normalized_name as _normalized_name
from scripts.pypi_validate._model import PypiValidateError


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
