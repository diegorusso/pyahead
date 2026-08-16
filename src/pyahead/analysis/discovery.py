"""Bounded deterministic Python-file discovery and project path policy."""

import os
import stat
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pathspec import GitIgnoreSpec, PathSpec
from pathspec.pattern import Pattern

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_ENTRIES = 100_000

_MAX_GITIGNORE_BYTES = MAX_SOURCE_BYTES
_READ_CHUNK_BYTES = 64 * 1024

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pypackages__",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "node_modules",
        "site-packages",
        "venv",
    }
)
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})


class DiscoveryError(ValueError):
    """Raised when an explicit scan path is invalid or unsafe."""


class DiscoveryIncompleteError(OSError):
    """Raised when repository source discovery cannot complete."""


class DiscoveryEntryKind(StrEnum):
    """Filesystem entry kind represented by an incomplete discovery issue."""

    FILE = "file"
    DIRECTORY = "directory"


@dataclass(frozen=True)
class DiscoveryOptions:
    """Deterministic configured discovery policy."""

    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    respect_gitignore: bool = True
    max_file_size_bytes: int = MAX_SOURCE_BYTES
    max_source_entries: int = MAX_SOURCE_ENTRIES
    allow_explicit_built_in_roots: bool = False


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
    entry_kind: DiscoveryEntryKind = field(
        default=DiscoveryEntryKind.FILE,
        compare=False,
    )


@dataclass(frozen=True)
class DiscoveryResult:
    """Eligible source files and deterministic per-entry incomplete results."""

    files: tuple[DiscoveredFile, ...]
    issues: tuple[DiscoveryIssue, ...]

    @property
    def files_discovered(self) -> int:
        """Count both analysable files and skipped source entries."""
        return len(self.files) + len(self.issues)


_GitIgnoreRules = tuple[tuple[PurePosixPath, GitIgnoreSpec], ...]


class _GitIgnoreHierarchy:
    """Ancestor-ordered, directory-relative ``.gitignore`` evaluation."""

    def __init__(self, root: Path, *, enabled: bool) -> None:
        self._root = root
        self._enabled = enabled
        self._specs: dict[PurePosixPath, GitIgnoreSpec | None] = {}
        # ``None`` is a blocked directory whose parent was ignored.
        self._contexts: dict[PurePosixPath, _GitIgnoreRules | None] = {}

    def ignored(self, path: PurePosixPath, *, directory: bool) -> bool:
        """Return the last matching ancestor decision for one logical path."""
        if not self._enabled or path == PurePosixPath("."):
            return False
        context = self._context(path.parent)
        return context is None or self._matches(
            path, directory=directory, rules=context
        )

    def prepare_directory(self, path: PurePosixPath) -> None:
        """Load the ignore file for one directory reached by the walker."""
        if self._enabled:
            self._context(path)

    def _context(self, directory: PurePosixPath) -> _GitIgnoreRules | None:
        missing: list[PurePosixPath] = []
        current = directory
        while current not in self._contexts:
            missing.append(current)
            if current == PurePosixPath("."):
                break
            current = current.parent

        for candidate in reversed(missing):
            if candidate == PurePosixPath("."):
                spec = self._load_spec(candidate)
                self._contexts[candidate] = (
                    ((candidate, spec),) if spec is not None else ()
                )
                continue
            parent_context = self._contexts[candidate.parent]
            if parent_context is None or self._matches(
                candidate,
                directory=True,
                rules=parent_context,
            ):
                self._contexts[candidate] = None
                continue
            spec = self._load_spec(candidate)
            self._contexts[candidate] = (
                (*parent_context, (candidate, spec))
                if spec is not None
                else parent_context
            )
        return self._contexts[directory]

    def _load_spec(self, directory: PurePosixPath) -> GitIgnoreSpec | None:
        if directory not in self._specs:
            self._specs[directory] = _read_gitignore(self._root, directory)
        return self._specs[directory]

    @staticmethod
    def _matches(
        path: PurePosixPath,
        *,
        directory: bool,
        rules: _GitIgnoreRules,
    ) -> bool:
        ignored = False
        for base, spec in rules:
            relative = path.relative_to(base)
            rendered = relative.as_posix()
            if directory:
                rendered = f"{rendered.rstrip('/')}/"
            result = spec.check_file(rendered)
            if result.include is not None:
                ignored = result.include
        return ignored


@dataclass(frozen=True)
class _DiscoveryFilter:
    include: PathSpec[Pattern] | None
    exclude: PathSpec[Pattern] | None
    gitignore: _GitIgnoreHierarchy

    def prepare_directory(self, path: PurePosixPath) -> None:
        self.gitignore.prepare_directory(path)

    def file_selected(self, path: PurePosixPath) -> bool:
        rendered = path.as_posix()
        if self.gitignore.ignored(path, directory=False):
            return False
        if self.include is not None and not self.include.match_file(rendered):
            return False
        return self.exclude is None or not self.exclude.match_file(rendered)

    def directory_excluded(self, path: PurePosixPath) -> bool:
        rendered = f"{path.as_posix().rstrip('/')}/"
        if self.gitignore.ignored(path, directory=True):
            return True
        return self.exclude is not None and self.exclude.match_file(rendered)

    def symlink_excluded(self, path: PurePosixPath) -> bool:
        """Evaluate a directory symlink as the non-directory entry Git sees."""
        rendered = path.as_posix()
        if self.gitignore.ignored(path, directory=False):
            return True
        return self.exclude is not None and self.exclude.match_file(rendered)


def _beneath_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _compile_path_spec(
    patterns: tuple[str, ...], kind: str
) -> PathSpec[Pattern] | None:
    if not patterns:
        return None
    try:
        return PathSpec.from_lines("gitignore", patterns)
    except (TypeError, ValueError) as error:
        message = f"invalid {kind} path pattern"
        raise DiscoveryError(message) from error


def _gitignore_limit_error(relative_path: str) -> DiscoveryIncompleteError:
    message = (
        f"{relative_path} exceeds the {_MAX_GITIGNORE_BYTES}-byte ignore-file limit"
    )
    return DiscoveryIncompleteError(message)


def _read_validated_gitignore_bytes(
    descriptor: int,
    entry_status: os.stat_result,
    relative_path: str,
) -> bytes:
    opened_status = os.fstat(descriptor)
    if not stat.S_ISREG(opened_status.st_mode) or not os.path.samestat(
        opened_status,
        entry_status,
    ):
        message = f"{relative_path} changed while it was being read"
        raise DiscoveryIncompleteError(message)
    if opened_status.st_size > _MAX_GITIGNORE_BYTES:
        raise _gitignore_limit_error(relative_path)
    data = bytearray()
    while len(data) <= _MAX_GITIGNORE_BYTES:
        chunk = os.read(
            descriptor,
            min(_READ_CHUNK_BYTES, _MAX_GITIGNORE_BYTES + 1 - len(data)),
        )
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > _MAX_GITIGNORE_BYTES:
        raise _gitignore_limit_error(relative_path)
    return bytes(data)


def _read_gitignore_lines(
    path: Path,
    entry_status: os.stat_result,
    relative_path: str,
) -> list[str]:
    """Read one bounded, unchanged regular ignore entry without following it."""
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        for name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
            flags |= getattr(os, name, 0)
        descriptor = os.open(path, flags)
        data = _read_validated_gitignore_bytes(
            descriptor,
            entry_status,
            relative_path,
        )
    except DiscoveryIncompleteError:
        raise
    except (OSError, RuntimeError) as error:
        message = f"unable to read {relative_path}"
        raise DiscoveryIncompleteError(message) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeError as error:
        message = f"{relative_path} must be valid UTF-8"
        raise DiscoveryError(message) from error


def _read_gitignore(
    root: Path,
    directory: PurePosixPath,
) -> GitIgnoreSpec | None:
    base = root.joinpath(*directory.parts)
    path = base / ".gitignore"
    relative_path = path.relative_to(root).as_posix()
    try:
        entry_status = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        message = f"unable to inspect {relative_path}"
        raise DiscoveryIncompleteError(message) from error
    # Git does not follow a working-tree .gitignore symbolic link. This also
    # handles dangling links without consulting their targets.
    if stat.S_ISLNK(entry_status.st_mode):
        return None
    if not stat.S_ISREG(entry_status.st_mode):
        message = f"{relative_path} must be a regular file"
        raise DiscoveryError(message)
    if entry_status.st_size > _MAX_GITIGNORE_BYTES:
        raise _gitignore_limit_error(relative_path)
    lines = _read_gitignore_lines(path, entry_status, relative_path)
    try:
        return GitIgnoreSpec.from_lines(lines)
    except (TypeError, ValueError) as error:
        message = f"{relative_path} contains an invalid pattern"
        raise DiscoveryError(message) from error


def _discovery_filter(root: Path, options: DiscoveryOptions) -> _DiscoveryFilter:
    if options.max_file_size_bytes <= 0:
        message = "maximum source file size must be positive"
        raise DiscoveryError(message)
    if options.max_source_entries <= 0:
        message = "maximum source entry count must be positive"
        raise DiscoveryError(message)
    return _DiscoveryFilter(
        include=_compile_path_spec(options.include, "include"),
        exclude=_compile_path_spec(options.exclude, "exclude"),
        gitignore=_GitIgnoreHierarchy(root, enabled=options.respect_gitignore),
    )


def _relative_logical_path(path: Path, root: Path) -> PurePosixPath:
    logical_path = Path(os.path.abspath(path))  # noqa: PTH100
    if not _beneath_root(logical_path, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    return PurePosixPath(logical_path.relative_to(root).as_posix())


def _built_in_excluded(path: PurePosixPath, *, directory: bool = False) -> bool:
    parts = path.parts if directory else path.parts[:-1]
    return any(part in _EXCLUDED_DIRECTORIES for part in parts)


def _relative_source(
    path: Path,
    root: Path,
    max_file_size_bytes: int,
) -> DiscoveredFile | DiscoveryIssue:
    # Collapse ``..`` without resolving the final symlink and losing its alias.
    logical_path = Path(os.path.abspath(path))  # noqa: PTH100
    relative_path = _relative_logical_path(path, root)
    if logical_path.suffix not in _PYTHON_SUFFIXES:
        message = "explicit scan files must end in .py or .pyi"
        raise DiscoveryError(message)

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        if logical_path.is_symlink():
            return DiscoveryIssue(
                relative_path=relative_path,
                code="PYA1004",
                message="source file symlink cannot be resolved safely",
            )
        raise
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
    if file_status.st_size > max_file_size_bytes:
        return DiscoveryIssue(
            relative_path=relative_path,
            code="PYA1005",
            message=(
                f"source file exceeds the {max_file_size_bytes}-byte analysis limit"
            ),
        )
    return DiscoveredFile(relative_path=relative_path, absolute_path=resolved)


def _directory_symlink_issue(path: Path, root: Path) -> DiscoveryIssue:
    """Represent an untraversed directory alias as incomplete module evidence."""
    relative_path = _relative_logical_path(path, root)
    return DiscoveryIssue(
        relative_path=relative_path,
        code="PYA1004",
        message="source directory symlink is not traversed",
        module_name=_project_directory_module_name(relative_path),
        entry_kind=DiscoveryEntryKind.DIRECTORY,
    )


def _source_entry_limit_issue(
    relative_path: PurePosixPath,
    max_source_entries: int,
) -> DiscoveryIssue:
    """Represent deterministic early termination at the source-entry bound."""
    return DiscoveryIssue(
        relative_path=relative_path,
        code="PYA1006",
        message=(
            f"source entry count exceeds the {max_source_entries}-entry analysis limit"
        ),
    )


@dataclass
class _SourceEntryBudget:
    """Share one deduplicated source-entry bound across requested paths."""

    limit: int
    seen_paths: set[PurePosixPath] = field(default_factory=set)
    overflowed: bool = False

    def select(
        self,
        entry: DiscoveredFile | DiscoveryIssue,
    ) -> DiscoveredFile | DiscoveryIssue | None:
        """Return a new entry, a limit issue, or nothing for a duplicate."""
        if entry.relative_path in self.seen_paths:
            return None
        if len(self.seen_paths) >= self.limit:
            self.overflowed = True
            return _source_entry_limit_issue(entry.relative_path, self.limit)
        self.seen_paths.add(entry.relative_path)
        return entry


def _directory_entries(  # noqa: C901, PLR0912 - bounded walk policy coordinator.
    directory: Path,
    root: Path,
    options: DiscoveryOptions,
    discovery_filter: _DiscoveryFilter,
    budget: _SourceEntryBudget,
) -> list[DiscoveredFile | DiscoveryIssue]:
    discovered: list[DiscoveredFile | DiscoveryIssue] = []
    built_in_boundary = (
        _relative_logical_path(directory, root)
        if options.allow_explicit_built_in_roots
        else PurePosixPath(".")
    )

    def raise_walk_error(error: OSError) -> None:
        message = "unable to enumerate a source directory"
        raise DiscoveryIncompleteError(message) from error

    def append_entry(entry: DiscoveredFile | DiscoveryIssue) -> bool:
        selected = budget.select(entry)
        if selected is None:
            return True
        discovered.append(selected)
        return not budget.overflowed

    for current, directory_names, file_names in os.walk(
        directory,
        followlinks=False,
        onerror=raise_walk_error,
    ):
        current_path = Path(current)
        discovery_filter.prepare_directory(_relative_logical_path(current_path, root))
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            if name in _EXCLUDED_DIRECTORIES:
                continue
            child = current_path / name
            relative_child = _relative_logical_path(child, root)
            if child.is_symlink():
                if not discovery_filter.symlink_excluded(
                    relative_child
                ) and not append_entry(_directory_symlink_issue(child, root)):
                    return discovered
                continue
            if discovery_filter.directory_excluded(relative_child):
                continue
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for file_name in sorted(file_names):
            path = current_path / file_name
            if path.suffix not in _PYTHON_SUFFIXES:
                continue
            relative_path = _relative_logical_path(path, root)
            built_in_path = (
                relative_path.relative_to(built_in_boundary)
                if options.allow_explicit_built_in_roots
                else relative_path
            )
            if _built_in_excluded(built_in_path):
                continue
            if not discovery_filter.file_selected(relative_path):
                continue
            try:
                entry = _relative_source(path, root, options.max_file_size_bytes)
                if not append_entry(entry):
                    return discovered
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
    except (OSError, RuntimeError) as error:
        message = "unable to resolve the scan root"
        raise DiscoveryIncompleteError(message) from error


def _resolve_requested_path(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except FileNotFoundError as error:
        message = "a requested scan path does not exist"
        raise DiscoveryError(message) from error
    except (OSError, RuntimeError) as error:
        message = "unable to resolve a requested scan path"
        raise DiscoveryIncompleteError(message) from error


def _requested_entry(
    path: Path,
    root: Path,
    options: DiscoveryOptions,
) -> DiscoveredFile | DiscoveryIssue:
    try:
        return _relative_source(path, root, options.max_file_size_bytes)
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


def _requested_symlink_excluded(
    issue: DiscoveryIssue,
    options: DiscoveryOptions,
    discovery_filter: _DiscoveryFilter,
) -> bool:
    """Apply fixed-name and path policy to an explicit directory alias."""
    alias_path = issue.relative_path
    built_in_excluded = _built_in_excluded(alias_path, directory=True)
    return (
        built_in_excluded and not options.allow_explicit_built_in_roots
    ) or discovery_filter.symlink_excluded(alias_path)


def _selected_requested_entries(
    candidate: Path,
    root: Path,
    options: DiscoveryOptions,
    discovery_filter: _DiscoveryFilter,
    budget: _SourceEntryBudget,
) -> list[DiscoveredFile | DiscoveryIssue]:
    """Classify an explicit path safely before applying selection policy."""
    resolved = _resolve_requested_path(candidate)
    if not _beneath_root(resolved, root):
        message = "scan paths must remain beneath the scan root"
        raise DiscoveryError(message)
    directory_symlink = _requested_directory_symlink(candidate, root, resolved)
    if directory_symlink is not None:
        if _requested_symlink_excluded(
            directory_symlink,
            options,
            discovery_filter,
        ):
            return []
        selected = budget.select(directory_symlink)
        return [] if selected is None else [selected]

    relative_candidate = _relative_logical_path(candidate, root)
    if _built_in_excluded(
        relative_candidate,
        directory=resolved.is_dir(),
    ) and not (options.allow_explicit_built_in_roots and resolved.is_dir()):
        return []
    if resolved.is_dir():
        if discovery_filter.directory_excluded(relative_candidate):
            entries: list[DiscoveredFile | DiscoveryIssue] = []
        else:
            entries = _directory_entries(
                resolved,
                root,
                options,
                discovery_filter,
                budget,
            )
    elif discovery_filter.file_selected(relative_candidate):
        entry = _requested_entry(candidate, root, options)
        selected = budget.select(entry)
        entries = [] if selected is None else [selected]
    else:
        entries = []
    return entries


def discover_python_files(
    root: Path,
    requested_paths: tuple[Path, ...],
    options: DiscoveryOptions | None = None,
) -> DiscoveryResult:
    """Discover bounded source entries beneath an explicit repository root."""
    resolved_root = _resolve_root(root)
    if not resolved_root.is_dir():
        message = "scan root must be a directory"
        raise DiscoveryError(message)
    effective_options = options or DiscoveryOptions()
    discovery_filter = _discovery_filter(resolved_root, effective_options)

    unique: dict[PurePosixPath, DiscoveredFile | DiscoveryIssue] = {}
    budget = _SourceEntryBudget(effective_options.max_source_entries)
    paths = requested_paths or (Path(),)
    for requested_path in paths:
        candidate = (
            requested_path
            if requested_path.is_absolute()
            else resolved_root / requested_path
        )
        entries = _selected_requested_entries(
            candidate,
            resolved_root,
            effective_options,
            discovery_filter,
            budget,
        )
        for entry in entries:
            unique[entry.relative_path] = entry
        if budget.overflowed:
            break

    ordered = tuple(unique[path] for path in sorted(unique))
    return DiscoveryResult(
        files=tuple(item for item in ordered if isinstance(item, DiscoveredFile)),
        issues=tuple(item for item in ordered if isinstance(item, DiscoveryIssue)),
    )


def _module_name_beneath(
    path: PurePosixPath,
    source_root: PurePosixPath,
) -> str | None:
    try:
        relative = path.relative_to(source_root)
    except ValueError:
        return None
    parts = list(relative.parts)
    if not parts:
        return None
    parts[-1] = PurePosixPath(parts[-1]).stem
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _project_module_names_for_path(
    path: PurePosixPath,
    source_roots: tuple[str, ...] | None,
) -> tuple[str, ...]:
    """Infer runtime module names from authoritative or conventional roots."""
    if path.suffix != ".py":
        return ()
    roots = (
        tuple(PurePosixPath(root) for root in source_roots)
        if source_roots is not None
        else (PurePosixPath("."), PurePosixPath("src"))
    )
    names = {
        name for root in roots if (name := _module_name_beneath(path, root)) is not None
    }
    if source_roots is not None:
        return tuple(sorted(names))
    # Conventional ``src`` wins over the repository root for descendants.
    src_name = _module_name_beneath(path, PurePosixPath("src"))
    if src_name is not None:
        return (src_name,)
    root_name = _module_name_beneath(path, PurePosixPath("."))
    return (root_name,) if root_name is not None else ()


def _project_directory_module_names_for_path(
    path: PurePosixPath,
    source_roots: tuple[str, ...],
) -> tuple[str, ...]:
    """Map an opaque directory to conservative authoritative-root candidates."""
    names: set[str] = set()
    for raw_root in source_roots:
        root = PurePosixPath(raw_root)
        try:
            relative = path.relative_to(root)
        except ValueError:
            try:
                root.relative_to(path)
            except ValueError:
                continue
            # The opaque directory blocks access to the configured source root,
            # whose unknown contents may provide any top-level module.
            names.add("*")
            continue
        if not relative.parts:
            names.add("*")
        elif all(part.isidentifier() for part in relative.parts):
            names.add(".".join(relative.parts))
    return tuple(sorted(names))


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
    source_roots: tuple[str, ...] | None = None,
) -> dict[str, tuple[PurePosixPath, ...]]:
    """Map possible runtime project modules to deterministic candidate paths."""
    candidates: defaultdict[str, set[PurePosixPath]] = defaultdict(set)
    items: tuple[DiscoveredFile | DiscoveryIssue, ...] = (*files, *issues)
    for item in items:
        relative_path = item.relative_path
        modules = (
            (item.module_name,)
            if (
                source_roots is None
                and isinstance(item, DiscoveryIssue)
                and item.module_name is not None
            )
            else (
                _project_directory_module_names_for_path(relative_path, source_roots)
                if source_roots is not None
                and isinstance(item, DiscoveryIssue)
                and item.entry_kind is DiscoveryEntryKind.DIRECTORY
                else _project_module_names_for_path(relative_path, source_roots)
            )
        )
        for module in modules:
            for prefix in _project_module_prefixes(module):
                candidates[prefix].add(relative_path)
    return {
        module: tuple(sorted(paths, key=PurePosixPath.as_posix))
        for module, paths in sorted(candidates.items())
    }


def project_module_names(files: tuple[DiscoveredFile, ...]) -> frozenset[str]:
    """Return conventional runtime module names for direct discovery callers."""
    return frozenset(project_module_paths(files))
