"""Bounded deterministic Python-file discovery for the M1 slice."""

import os
import stat
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 2 * 1024 * 1024

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


@dataclass(frozen=True, order=True)
class DiscoveryIssue:
    """A repository entry that was discovered but cannot be analysed safely."""

    relative_path: PurePosixPath
    code: str
    message: str
    module_name: str | None = field(default=None, compare=False)


@dataclass(frozen=True)
class DiscoveryResult:
    """Eligible source files and deterministic per-entry incomplete results."""

    files: tuple[DiscoveredFile, ...]
    issues: tuple[DiscoveryIssue, ...]

    @property
    def files_discovered(self) -> int:
        """Count both analysable files and skipped source entries."""
        return len(self.files) + len(self.issues)


def _beneath_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _relative_source(
    path: Path,
    root: Path,
) -> DiscoveredFile | DiscoveryIssue:
    # Collapse ``..`` without resolving the final symlink and losing its alias.
    logical_path = Path(os.path.abspath(path))  # noqa: PTH100
    if not _beneath_root(logical_path, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    if logical_path.suffix not in _PYTHON_SUFFIXES:
        message = "explicit scan files must end in .py or .pyi"
        raise DiscoveryError(message)

    relative_path = PurePosixPath(logical_path.relative_to(root).as_posix())
    resolved = path.resolve(strict=True)
    if not _beneath_root(resolved, root):
        return DiscoveryIssue(
            relative_path=relative_path,
            code="PYA1004",
            message="source file symlink resolves outside the scan root",
        )
    file_status = resolved.stat()
    if not stat.S_ISREG(file_status.st_mode):
        return DiscoveryIssue(
            relative_path=relative_path,
            code="PYA1004",
            message="source entry is not a regular file",
        )
    if file_status.st_size > MAX_SOURCE_BYTES:
        return DiscoveryIssue(
            relative_path=relative_path,
            code="PYA1005",
            message=(f"source file exceeds the {MAX_SOURCE_BYTES}-byte analysis limit"),
        )
    return DiscoveredFile(relative_path=relative_path, absolute_path=resolved)


def _directory_symlink_issue(path: Path, root: Path) -> DiscoveryIssue:
    """Represent an untraversed directory alias as incomplete module evidence."""
    logical_path = Path(os.path.abspath(path))  # noqa: PTH100
    if not _beneath_root(logical_path, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    relative_path = PurePosixPath(logical_path.relative_to(root).as_posix())
    return DiscoveryIssue(
        relative_path=relative_path,
        code="PYA1004",
        message="source directory symlink is not traversed",
        module_name=_project_directory_module_name(relative_path),
    )


def _directory_entries(
    directory: Path,
    root: Path,
) -> list[DiscoveredFile | DiscoveryIssue]:
    discovered: list[DiscoveredFile | DiscoveryIssue] = []

    def raise_walk_error(error: OSError) -> None:
        message = "unable to enumerate a source directory"
        raise DiscoveryIncompleteError(message) from error

    for current, directory_names, file_names in os.walk(
        directory,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current_path = Path(current)
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            if name in _EXCLUDED_DIRECTORIES:
                continue
            child = current_path / name
            if child.is_symlink():
                discovered.append(_directory_symlink_issue(child, root))
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories
        for file_name in sorted(file_names):
            path = current_path / file_name
            if path.suffix not in _PYTHON_SUFFIXES:
                continue
            try:
                discovered.append(_relative_source(path, root))
            except DiscoveryError:
                continue
            except OSError as error:
                message = "unable to inspect a discovered source file"
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


def _requested_entry(
    path: Path,
    root: Path,
) -> DiscoveredFile | DiscoveryIssue:
    try:
        return _relative_source(path, root)
    except OSError as error:
        message = "unable to inspect a requested source file"
        raise DiscoveryIncompleteError(message) from error


def _requested_directory_symlink(
    candidate: Path,
    root: Path,
    resolved: Path,
) -> DiscoveryIssue | None:
    """Find a directory symlink in an explicit path without traversing it."""
    logical_path = Path(os.path.abspath(candidate))  # noqa: PTH100
    if not _beneath_root(logical_path, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    relative_parts = logical_path.relative_to(root).parts
    directory_parts = relative_parts if resolved.is_dir() else relative_parts[:-1]
    current = root
    for part in directory_parts:
        current = current / part
        if current.is_symlink():
            return _directory_symlink_issue(current, root)
    return None


def discover_python_files(
    root: Path,
    requested_paths: tuple[Path, ...],
) -> DiscoveryResult:
    """Discover bounded source entries beneath an explicit repository root."""
    resolved_root = _resolve_root(root)
    if not resolved_root.is_dir():
        message = "scan root must be a directory"
        raise DiscoveryError(message)

    unique: dict[PurePosixPath, DiscoveredFile | DiscoveryIssue] = {}
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
        directory_symlink = _requested_directory_symlink(
            candidate,
            resolved_root,
            resolved,
        )
        entries: list[DiscoveredFile | DiscoveryIssue]
        if directory_symlink is not None:
            entries = [directory_symlink]
        elif resolved.is_dir():
            entries = _directory_entries(resolved, resolved_root)
        else:
            entries = [_requested_entry(candidate, resolved_root)]
        for entry in entries:
            unique[entry.relative_path] = entry

    ordered = tuple(unique[path] for path in sorted(unique))
    return DiscoveryResult(
        files=tuple(item for item in ordered if isinstance(item, DiscoveredFile)),
        issues=tuple(item for item in ordered if isinstance(item, DiscoveryIssue)),
    )


def _project_module_name(path: PurePosixPath) -> str | None:
    """Infer a runtime module name from conventional root or ``src`` layout."""
    if path.suffix != ".py":
        return None
    parts = list(path.parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    parts[-1] = PurePosixPath(parts[-1]).stem
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _project_directory_module_name(path: PurePosixPath) -> str | None:
    """Infer the module prefix represented by an untraversed directory alias."""
    parts = list(path.parts)
    if parts == ["src"]:
        # An opaque conventional source root may contain any top-level module.
        return "*"
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _project_module_prefixes(module: str) -> tuple[str, ...]:
    """Return a module and every implicit namespace-package parent."""
    parts = module.split(".")
    return tuple(".".join(parts[:length]) for length in range(1, len(parts) + 1))


def project_module_paths(
    files: tuple[DiscoveredFile, ...],
    issues: tuple[DiscoveryIssue, ...] = (),
) -> dict[str, tuple[PurePosixPath, ...]]:
    """Map possible runtime project modules to deterministic candidate paths."""
    candidates: defaultdict[str, set[PurePosixPath]] = defaultdict(set)
    items: tuple[DiscoveredFile | DiscoveryIssue, ...] = (*files, *issues)
    for item in items:
        relative_path = item.relative_path
        module = (
            item.module_name
            if isinstance(item, DiscoveryIssue) and item.module_name is not None
            else _project_module_name(relative_path)
        )
        if module is not None:
            for prefix in _project_module_prefixes(module):
                candidates[prefix].add(relative_path)
    return {
        module: tuple(sorted(paths, key=PurePosixPath.as_posix))
        for module, paths in sorted(candidates.items())
    }


def project_module_names(files: tuple[DiscoveredFile, ...]) -> frozenset[str]:
    """Return conventional runtime module names for direct discovery callers."""
    return frozenset(project_module_paths(files))
