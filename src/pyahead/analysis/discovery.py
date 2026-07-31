"""Bounded deterministic Python-file discovery for the M1 slice."""

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "venv",
    }
)
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})


class DiscoveryError(ValueError):
    """Raised when an explicit scan path is invalid or unsafe."""


class DiscoveryIncompleteError(OSError):
    """Raised when repository source discovery cannot complete."""


@dataclass(frozen=True, order=True)
class DiscoveredFile:
    """An absolute read path paired with a repository-relative output path."""

    relative_path: PurePosixPath
    absolute_path: Path


def _beneath_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _relative_file(path: Path, root: Path) -> DiscoveredFile:
    resolved = path.resolve(strict=True)
    if not _beneath_root(resolved, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    if resolved.suffix not in _PYTHON_SUFFIXES:
        message = "explicit scan files must end in .py or .pyi"
        raise DiscoveryError(message)
    return DiscoveredFile(
        relative_path=PurePosixPath(resolved.relative_to(root).as_posix()),
        absolute_path=resolved,
    )


def _directory_files(directory: Path, root: Path) -> list[DiscoveredFile]:
    discovered: list[DiscoveredFile] = []

    def raise_walk_error(error: OSError) -> None:
        message = "unable to enumerate a source directory"
        raise DiscoveryIncompleteError(message) from error

    for current, directory_names, file_names in os.walk(
        directory,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current_path = Path(current)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRECTORIES
            and not current_path.joinpath(name).is_symlink()
        )
        for file_name in sorted(file_names):
            path = current_path / file_name
            if path.suffix not in _PYTHON_SUFFIXES:
                continue
            try:
                discovered.append(_relative_file(path, root))
            except DiscoveryError:
                continue
            except OSError as error:
                message = "unable to resolve a discovered source file"
                raise DiscoveryIncompleteError(message) from error
    return discovered


def _resolve_root(root: Path) -> Path:
    try:
        return root.resolve(strict=True)
    except FileNotFoundError as error:
        message = "scan root does not exist"
        raise DiscoveryError(message) from error
    except OSError as error:
        message = "unable to resolve the scan root"
        raise DiscoveryIncompleteError(message) from error


def _resolve_requested_path(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except FileNotFoundError as error:
        message = "a requested scan path does not exist"
        raise DiscoveryError(message) from error
    except OSError as error:
        message = "unable to resolve a requested scan path"
        raise DiscoveryIncompleteError(message) from error


def _requested_file(path: Path, root: Path) -> DiscoveredFile:
    try:
        return _relative_file(path, root)
    except OSError as error:
        message = "unable to resolve a requested source file"
        raise DiscoveryIncompleteError(message) from error


def discover_python_files(
    root: Path, requested_paths: tuple[Path, ...]
) -> tuple[DiscoveredFile, ...]:
    """Discover eligible files beneath an explicit root without following dirs."""
    resolved_root = _resolve_root(root)
    if not resolved_root.is_dir():
        message = "scan root must be a directory"
        raise DiscoveryError(message)

    unique: dict[PurePosixPath, DiscoveredFile] = {}
    paths = requested_paths or (Path(),)
    for requested_path in paths:
        candidate = (
            requested_path
            if requested_path.is_absolute()
            else resolved_root / requested_path
        )
        resolved = _resolve_requested_path(candidate)
        if not _beneath_root(resolved, resolved_root):
            message = "scan paths must remain beneath the scan root"
            raise DiscoveryError(message)
        if resolved.is_file():
            item = _requested_file(resolved, resolved_root)
            unique[item.relative_path] = item
        elif resolved.is_dir():
            for item in _directory_files(resolved, resolved_root):
                unique[item.relative_path] = item
        else:
            message = "requested scan paths must be files or directories"
            raise DiscoveryError(message)

    return tuple(unique[path] for path in sorted(unique))


def project_module_names(files: tuple[DiscoveredFile, ...]) -> frozenset[str]:
    """Infer only conventional repository-root and ``src`` module names."""
    modules: set[str] = set()
    for item in files:
        parts = list(item.relative_path.parts)
        if parts and parts[0] == "src":
            parts = parts[1:]
        if not parts:
            continue
        last = PurePosixPath(parts[-1])
        if last.suffix not in _PYTHON_SUFFIXES:
            continue
        parts[-1] = last.stem
        if parts[-1] == "__init__":
            parts.pop()
        if parts and all(part.isidentifier() for part in parts):
            modules.add(".".join(parts))
    return frozenset(modules)
