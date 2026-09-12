"""Acquire and verify a pinned local wheelhouse of the PyPI top-1000 packages.

This is the only network step in the PyPI validation harness. Every other
script (`pypi_probe.py`, `pypi_validate.py`, `pypi_report.py`) operates
offline against the manifest and wheelhouse this module produces.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from packaging.tags import compatible_tags, cpython_tags, sys_tags
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

from pyahead._human_text import SafeArgumentParser, escape_terminal_text

_CORPUS_SIZE = 1000
_SHA256_HEX_LENGTH = 64
# The validation harness only ever provisions CPython 3.11-3.15 (see
# docs/pypi-validation.md); a wheel built for any other interpreter or
# platform can never be installed by `pypi_validate.py run`.
_MIN_SUPPORTED_MINOR = 11
_MAX_SUPPORTED_MINOR = 15
_DEFAULT_SOURCE_URL = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json"
)
_MANIFEST_FIELDS = (
    "filename",
    "is_wheel",
    "name",
    "rank",
    "requires_python",
    "sha256",
    "version",
)
# A ranked project whose current release has neither an sdist nor a wheel any
# supported interpreter on this host can install (a Windows-only extension,
# say) cannot be part of a Linux sweep at all. Acquisition records it under
# the manifest's `unresolved` list with one of these closed reasons instead
# of aborting the whole corpus, so `packages` plus `unresolved` always
# account for every one of the 1000 ranks; downstream tooling operates on
# `packages` only and the evidence record must name every unresolved entry.
_UNRESOLVED_FIELDS = ("name", "rank", "reason", "version")
_NO_INSTALLABLE_ARTIFACT = "no-installable-artifact"
_UNRESOLVED_REASONS = frozenset({_NO_INSTALLABLE_ARTIFACT})

HttpGet = Callable[[str, float], bytes]
Clock = Callable[[], datetime]


class PypiCorpusError(RuntimeError):
    """Raised when the PyPI corpus manifest or wheelhouse would be untrustworthy."""


class NoInstallableArtifactError(PypiCorpusError):
    """Raised when a release has no sdist and no wheel this host could install.

    This is the one acquisition failure that is a property of the package on
    this platform rather than of the network or the metadata, so `_acquire`
    records it as an `unresolved` manifest entry and carries on; every other
    `PypiCorpusError` still aborts the acquisition.
    """

    def __init__(self, *, name: str, version: str) -> None:
        """Name the release so the manifest can record what was left out and why."""
        super().__init__(f"PyPI metadata for {name} {version} has no wheel or sdist")
        self.name = name
        self.version = version


@dataclass(frozen=True)
class AcquireHooks:
    """Injectable network, clock, and progress hooks for `_acquire`."""

    http_get: HttpGet
    clock: Clock
    progress: Callable[[str], None]


@dataclass(frozen=True)
class PackageEntry:
    """One pinned, locally verified PyPI package artifact."""

    rank: int
    name: str
    version: str
    filename: str
    sha256: str
    requires_python: str | None
    is_wheel: bool


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


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _https_url(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        message = f"{field} must be a non-empty string"
        raise PypiCorpusError(message)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
    ):
        message = f"{field} must be a credential-free HTTPS URL"
        raise PypiCorpusError(message)
    return value


def _safe_filename(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "/" in value
        or "\\" in value
        or value in (".", "..")
    ):
        message = f"{field} must be a plain filename"
        raise PypiCorpusError(message)
    return value


def _http_get(url: str, timeout: float) -> bytes:
    request = Request(  # noqa: S310 - scheme is validated https before every call.
        url,
        headers={"User-Agent": "pyahead-pypi-corpus-validation/1"},
    )
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - see above.
        return response.read()  # type: ignore[no-any-return]


def _parse_ranking(payload: bytes) -> list[tuple[int, str]]:
    try:
        document: Any = json.loads(payload)
    except json.JSONDecodeError as error:
        message = "ranking snapshot is not valid JSON"
        raise PypiCorpusError(message) from error
    if not isinstance(document, dict):
        message = "ranking snapshot must be a JSON object"
        raise PypiCorpusError(message)
    rows = document.get("rows")
    if not isinstance(rows, list):
        message = "ranking snapshot is missing a rows array"
        raise PypiCorpusError(message)

    ranked: list[tuple[int, str]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("project"), str):
            message = "ranking snapshot row has an unexpected shape"
            raise PypiCorpusError(message)
        name = row["project"]
        if not name:
            message = "ranking snapshot row has an empty project name"
            raise PypiCorpusError(message)
        normalized = _normalized_name(name)
        if normalized in seen:
            message = f"ranking snapshot lists duplicate project {name!r}"
            raise PypiCorpusError(message)
        seen.add(normalized)
        ranked.append((len(ranked) + 1, name))
        if len(ranked) == _CORPUS_SIZE:
            break
    if len(ranked) < _CORPUS_SIZE:
        message = f"ranking snapshot must list at least {_CORPUS_SIZE} unique projects"
        raise PypiCorpusError(message)
    return ranked


def _project_metadata_url(name: str) -> str:
    return f"https://pypi.org/pypi/{quote(name, safe='')}/json"


@cache
def _supported_wheel_tags_for_minor(minor: int) -> frozenset[tuple[str, str, str]]:
    """Wheel `(interpreter, abi, platform)` tags installable by CPython 3.<minor>."""
    platforms = frozenset(tag.platform for tag in sys_tags())
    # "any" is `sys_tags()`'s own platform value for the generic
    # `pyN-none-any` compatibility tags `compatible_tags()` below is meant to
    # produce - `cpython_tags()` has no such generic case and would otherwise
    # fabricate a CPython-ABI-specific tag no real wheel ever uses (e.g.
    # `cp313-cp313-any`), silently widening what counts as "installable".
    concrete_platforms = platforms - {"any"}
    interpreter = f"cp3{minor}"
    supported: set[tuple[str, str, str]] = set()
    for tag in cpython_tags(python_version=(3, minor), platforms=concrete_platforms):
        supported.add((tag.interpreter, tag.abi, tag.platform))
    for tag in compatible_tags(
        python_version=(3, minor), interpreter=interpreter, platforms=platforms
    ):
        supported.add((tag.interpreter, tag.abi, tag.platform))
    return frozenset(supported)


def _supported_wheel_tags() -> frozenset[tuple[str, str, str]]:
    """Wheel `(interpreter, abi, platform)` tags installable on this host.

    Only C1's binding probe needs the distribution installed, and it always
    runs under a single reference-interpreter venv, so a wheel need only be
    installable by *some* interpreter in the harness's supported 3.11-3.15
    range (`docs/pypi-validation.md`) on this host's platform - not
    necessarily by the interpreter running this acquisition step.
    """
    supported: set[tuple[str, str, str]] = set()
    for minor in range(_MIN_SUPPORTED_MINOR, _MAX_SUPPORTED_MINOR + 1):
        supported.update(_supported_wheel_tags_for_minor(minor))
    return frozenset(supported)


def wheel_supports_minor(filename: str, minor: int) -> bool:
    """Return whether CPython 3.<minor> on this host can install this wheel.

    Used by `pypi_validate.py` to pick a reference interpreter that can
    actually install the pinned artifact, not just one that satisfies
    `requires_python` - a wheel narrower than its own `requires_python`
    range (for example, built only for the newest supported interpreter)
    would otherwise be handed to an older, tag-incompatible venv and fail
    to install for a reason `requires_python` alone could not predict.
    """
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return True
    supported = _supported_wheel_tags_for_minor(minor)
    return any((tag.interpreter, tag.abi, tag.platform) in supported for tag in tags)


def _wheel_is_installable(filename: str) -> bool:
    """Return whether some supported interpreter on this host can install it.

    A filename that does not even parse as a wheel is not excluded here:
    that is `_safe_filename`'s dedicated validation to raise on (a plain,
    non-path filename), not something this tag check should silently
    swallow into a generic "no wheel or sdist" error.
    """
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return True
    supported = _supported_wheel_tags()
    return any((tag.interpreter, tag.abi, tag.platform) in supported for tag in tags)


def _select_release_file(document: object, *, name: str) -> dict[str, Any]:
    if not isinstance(document, dict):
        message = f"PyPI metadata for {name} is not a JSON object"
        raise PypiCorpusError(message)
    info = document.get("info")
    if not isinstance(info, dict):
        message = f"PyPI metadata for {name} is missing project info"
        raise PypiCorpusError(message)
    version = info.get("version")
    if not isinstance(version, str) or not version:
        message = f"PyPI metadata for {name} has no current version"
        raise PypiCorpusError(message)
    files = document.get("urls")
    if not isinstance(files, list):
        message = f"PyPI metadata for {name} {version} is missing release files"
        raise PypiCorpusError(message)
    candidates = sorted(
        (
            file
            for file in files
            if isinstance(file, dict)
            and not file.get("yanked", False)
            and (
                file.get("packagetype") == "sdist"
                or (
                    file.get("packagetype") == "bdist_wheel"
                    and _wheel_is_installable(str(file.get("filename", "")))
                )
            )
        ),
        key=lambda file: (
            0 if file.get("packagetype") == "bdist_wheel" else 1,
            str(file.get("filename", "")),
        ),
    )
    if not candidates:
        raise NoInstallableArtifactError(name=name, version=version)
    chosen = candidates[0]
    filename = _safe_filename(chosen.get("filename"), field=f"{name} filename")
    url = _https_url(chosen.get("url"), field=f"{name} file url")
    requires_python = chosen.get("requires_python")
    if not isinstance(requires_python, str):
        requires_python = info.get("requires_python")
        if not isinstance(requires_python, str):
            requires_python = None
    return {
        "version": version,
        "filename": filename,
        "url": url,
        "is_wheel": chosen.get("packagetype") == "bdist_wheel",
        "requires_python": requires_python,
    }


def _write_atomic_text(path: Path, content: str) -> None:
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


def _write_atomic_bytes(path: Path, content: bytes) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _acquire_package(
    rank: int,
    name: str,
    *,
    timeout: float,
    hooks: AcquireHooks,
    seen_filenames: set[str],
) -> tuple[dict[str, Any], bytes]:
    hooks.progress(f"[{rank}/{_CORPUS_SIZE}] resolving {name}")
    metadata_payload = hooks.http_get(_project_metadata_url(name), timeout)
    try:
        metadata: Any = json.loads(metadata_payload)
    except json.JSONDecodeError as error:
        message = f"PyPI metadata for {name} is not valid JSON"
        raise PypiCorpusError(message) from error
    selected = _select_release_file(metadata, name=name)

    filename = str(selected["filename"])
    if filename in seen_filenames:
        message = f"duplicate wheelhouse filename {filename!r}"
        raise PypiCorpusError(message)
    seen_filenames.add(filename)

    artifact = hooks.http_get(str(selected["url"]), timeout)
    entry = {
        "filename": filename,
        "is_wheel": bool(selected["is_wheel"]),
        "name": name,
        "rank": rank,
        "requires_python": selected["requires_python"],
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "version": selected["version"],
    }
    return entry, artifact


def _acquire(
    *,
    source_url: str,
    manifest_path: Path,
    wheelhouse: Path,
    timeout: float,
    hooks: AcquireHooks,
) -> None:
    _https_url(source_url, field="source_url")
    ranking_payload = hooks.http_get(source_url, timeout)
    upstream_sha256 = hashlib.sha256(ranking_payload).hexdigest()
    ranked_names = _parse_ranking(ranking_payload)

    wheelhouse.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    seen_filenames: set[str] = set()
    for rank, name in ranked_names:
        try:
            entry, artifact = _acquire_package(
                rank,
                name,
                timeout=timeout,
                hooks=hooks,
                seen_filenames=seen_filenames,
            )
        except NoInstallableArtifactError as error:
            hooks.progress(
                f"[{rank}/{_CORPUS_SIZE}] unresolved {error.name} {error.version}: "
                f"{_NO_INSTALLABLE_ARTIFACT}"
            )
            unresolved.append(
                {
                    "name": error.name,
                    "rank": rank,
                    "reason": _NO_INSTALLABLE_ARTIFACT,
                    "version": error.version,
                }
            )
            continue
        _write_atomic_bytes(wheelhouse / str(entry["filename"]), artifact)
        entries.append(entry)

    if len(entries) + len(unresolved) != _CORPUS_SIZE:
        message = (
            f"acquired {len(entries)} packages and recorded {len(unresolved)} "
            f"unresolved, expected exactly {_CORPUS_SIZE} in total"
        )
        raise PypiCorpusError(message)

    document = {
        "packages": entries,
        "retrieved_on": hooks.clock().astimezone(UTC).isoformat(),
        "schema_version": 1,
        "source_url": source_url,
        "unresolved": unresolved,
        "upstream_payload_sha256": upstream_sha256,
    }
    manifest_text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    _write_atomic_text(manifest_path, manifest_text)


@dataclass
class _SeenIdentities:
    ranks: set[int]
    names: set[str]
    filenames: set[str]


def _valid_rank(value: object) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not (1 <= value <= _CORPUS_SIZE)
    ):
        message = "PyPI corpus entry rank is invalid"
        raise PypiCorpusError(message)
    return value


def _valid_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        message = "PyPI corpus entry name must be a non-empty string"
        raise PypiCorpusError(message)
    return value


def _valid_version(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value:
        message = f"PyPI corpus entry for {name} has an invalid version"
        raise PypiCorpusError(message)
    return value


def _valid_sha256(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        message = f"PyPI corpus entry for {name} has an invalid sha256"
        raise PypiCorpusError(message)
    return value


def _valid_requires_python(value: object, *, name: str) -> str | None:
    if value is not None and not isinstance(value, str):
        message = f"PyPI corpus entry for {name} has an invalid requires_python"
        raise PypiCorpusError(message)
    return value


def _valid_is_wheel(value: object, *, name: str) -> bool:
    if not isinstance(value, bool):
        message = f"PyPI corpus entry for {name} has an invalid is_wheel"
        raise PypiCorpusError(message)
    return value


def _claim_rank(value: object, *, seen: _SeenIdentities) -> int:
    rank = _valid_rank(value)
    if rank in seen.ranks:
        message = f"PyPI corpus manifest has duplicate rank {rank}"
        raise PypiCorpusError(message)
    seen.ranks.add(rank)
    return rank


def _claim_name(value: object, *, seen: _SeenIdentities) -> str:
    name = _valid_name(value)
    normalized = _normalized_name(name)
    if normalized in seen.names:
        message = f"PyPI corpus manifest has duplicate normalized name {name!r}"
        raise PypiCorpusError(message)
    seen.names.add(normalized)
    return name


def _load_manifest_entry(item: object, *, seen: _SeenIdentities) -> PackageEntry:
    if not isinstance(item, dict) or set(item) != set(_MANIFEST_FIELDS):
        message = "every PyPI corpus entry must contain only the documented fields"
        raise PypiCorpusError(message)

    rank = _claim_rank(item["rank"], seen=seen)
    name = _claim_name(item["name"], seen=seen)
    filename = _safe_filename(item["filename"], field=f"{name} filename")
    if filename in seen.filenames:
        message = f"PyPI corpus manifest has duplicate filename {filename!r}"
        raise PypiCorpusError(message)
    seen.filenames.add(filename)

    return PackageEntry(
        rank=rank,
        name=name,
        version=_valid_version(item["version"], name=name),
        filename=filename,
        sha256=_valid_sha256(item["sha256"], name=name),
        requires_python=_valid_requires_python(item["requires_python"], name=name),
        is_wheel=_valid_is_wheel(item["is_wheel"], name=name),
    )


def _check_unresolved_entry(item: object, *, seen: _SeenIdentities) -> None:
    """Validate one `unresolved` entry; ranks and names stay unique corpus-wide."""
    if not isinstance(item, dict) or set(item) != set(_UNRESOLVED_FIELDS):
        message = (
            "every unresolved PyPI corpus entry must contain only its documented fields"
        )
        raise PypiCorpusError(message)
    _claim_rank(item["rank"], seen=seen)
    name = _claim_name(item["name"], seen=seen)
    _valid_version(item["version"], name=name)
    reason = item["reason"]
    if not isinstance(reason, str) or reason not in _UNRESOLVED_REASONS:
        message = f"unresolved PyPI corpus entry for {name} has an unknown reason"
        raise PypiCorpusError(message)


def _load_manifest(path: Path) -> tuple[dict[str, Any], tuple[PackageEntry, ...]]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        message = "unable to load PyPI corpus manifest"
        raise PypiCorpusError(message) from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        message = "PyPI corpus manifest must use schema version 1"
        raise PypiCorpusError(message)
    for field in ("source_url", "retrieved_on", "upstream_payload_sha256"):
        if not isinstance(document.get(field), str) or not document[field]:
            message = f"PyPI corpus manifest is missing {field}"
            raise PypiCorpusError(message)
    _https_url(document["source_url"], field="source_url")

    packages = document.get("packages")
    unresolved = document.get("unresolved", [])
    if (
        not isinstance(packages, list)
        or not isinstance(unresolved, list)
        or len(packages) + len(unresolved) != _CORPUS_SIZE
    ):
        message = (
            f"PyPI corpus manifest must account for exactly {_CORPUS_SIZE} packages "
            "across its packages and unresolved lists"
        )
        raise PypiCorpusError(message)

    seen = _SeenIdentities(ranks=set(), names=set(), filenames=set())
    entries = [_load_manifest_entry(item, seen=seen) for item in packages]
    for item in unresolved:
        _check_unresolved_entry(item, seen=seen)
    entries.sort(key=lambda entry: entry.rank)
    return document, tuple(entries)


def load_manifest(path: Path) -> tuple[dict[str, Any], tuple[PackageEntry, ...]]:
    """Load and validate a pinned PyPI corpus manifest for downstream tooling."""
    return _load_manifest(path)


def _verify(*, manifest_path: Path, wheelhouse: Path) -> list[str]:
    _, entries = _load_manifest(manifest_path)
    resolved_wheelhouse = wheelhouse.resolve()
    problems: list[str] = []
    manifest_filenames = {entry.filename for entry in entries}
    for entry in entries:
        artifact_path = (wheelhouse / entry.filename).resolve()
        if (
            not artifact_path.is_relative_to(resolved_wheelhouse)
            or not artifact_path.is_file()
        ):
            problems.append(
                f"rank {entry.rank} ({entry.name}): missing artifact {entry.filename}"
            )
            continue
        digest = _sha256_path(artifact_path)
        if digest != entry.sha256:
            problems.append(
                f"rank {entry.rank} ({entry.name}): "
                f"sha256 mismatch for {entry.filename}"
            )
    # The runner installs with `--find-links` against the whole wheelhouse
    # directory, so it can resolve a package's own dependency on another
    # corpus member without a second download - but that only stays safe
    # if the directory contains *only* hash-verified manifest entries. An
    # unmanifested file sitting alongside them (a stale artifact from a
    # prior acquire, or one dropped in some other way) would never be
    # re-hashed here yet could still be selected as a dependency and
    # executed during install, so it must fail verification rather than
    # pass silently.
    if resolved_wheelhouse.is_dir():
        for candidate in resolved_wheelhouse.iterdir():
            if not candidate.is_file() or candidate.name.startswith("."):
                continue
            if candidate.name not in manifest_filenames:
                problems.append(f"unmanifested wheelhouse file: {candidate.name}")
    return problems


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="pyahead-pypi-corpus",
        description="acquire and verify a pinned local PyPI top-1000 wheelhouse",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    acquire = subparsers.add_parser(
        "acquire",
        help="download the pinned top-1000 manifest and wheelhouse (network)",
    )
    acquire.add_argument("--manifest", type=Path, required=True)
    acquire.add_argument("--wheelhouse", type=Path, required=True)
    acquire.add_argument(
        "--source-url",
        default=_DEFAULT_SOURCE_URL,
        help="HTTPS URL of the top-1000 download ranking snapshot",
    )
    acquire.add_argument(
        "--timeout",
        type=_positive_float,
        default=30.0,
        help="maximum seconds for each HTTP request (default: 30)",
    )

    verify = subparsers.add_parser(
        "verify",
        help="offline re-hash of an acquired wheelhouse against its manifest",
    )
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--wheelhouse", type=Path, required=True)

    return parser


def _report_progress(message: str) -> None:
    sys.stderr.write(escape_terminal_text(message) + "\n")


def _run_verify(*, manifest_path: Path, wheelhouse: Path) -> None:
    problems = _verify(manifest_path=manifest_path, wheelhouse=wheelhouse)
    for problem in problems:
        sys.stderr.write(escape_terminal_text(problem) + "\n")
    if problems:
        message = f"{len(problems)} wheelhouse artifact(s) failed verification"
        raise PypiCorpusError(message)


def main(argv: list[str] | None = None) -> int:
    """Acquire a pinned PyPI top-1000 wheelhouse or verify one offline."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "acquire":
            hooks = AcquireHooks(
                http_get=_http_get,
                clock=lambda: datetime.now(UTC),
                progress=_report_progress,
            )
            _acquire(
                source_url=arguments.source_url,
                manifest_path=arguments.manifest,
                wheelhouse=arguments.wheelhouse,
                timeout=arguments.timeout,
                hooks=hooks,
            )
        else:
            _run_verify(
                manifest_path=arguments.manifest,
                wheelhouse=arguments.wheelhouse,
            )
    except (PypiCorpusError, OSError, URLError) as error:
        sys.stderr.write(
            f"pypi corpus run failed: {escape_terminal_text(str(error))}\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
