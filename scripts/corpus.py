"""Scan an exact 100-repository local corpus and prepare precision review."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TextIO
from urllib.parse import urlsplit

_CORPUS_SIZE = 100
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_ACCEPTED_SCAN_EXITS = frozenset({0, 3})
_WORKSHEET_FIELDS = (
    "sample_rank",
    "repository_url",
    "commit",
    "rule_id",
    "fingerprint",
    "path",
    "start_line",
    "subject",
    "match_kind",
    "classification",
    "reviewer",
    "notes",
    "regression_fixture",
)


class CorpusError(RuntimeError):
    """Raised when corpus evidence would be incomplete or untrustworthy."""


@dataclass(frozen=True)
class RepositorySpec:
    """A locally acquired public repository pinned to one exact commit."""

    repository_url: str
    commit: str
    checkout: Path
    baseline_python: str
    horizon_python: str


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


def _repository_url(value: object) -> str:
    if not isinstance(value, str):
        message = "repository_url must be a string"
        raise CorpusError(message)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.path.strip("/")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        message = "repository_url must be a credential-free HTTPS URL"
        raise CorpusError(message)
    normalized = value.rstrip("/")
    return normalized.removesuffix(".git")


def _commit(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdefABCDEF" for character in value)
    ):
        message = "commit must be a full 40- or 64-character hexadecimal object ID"
        raise CorpusError(message)
    return value.lower()


def _minor(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        message = f"{field} must be a Python minor string"
        raise CorpusError(message)
    major, separator, minor = value.partition(".")
    if separator != "." or major != "3" or not minor.isdecimal():
        message = f"{field} must use MAJOR.MINOR form"
        raise CorpusError(message)
    return value


def _checkout(value: object, *, manifest_parent: Path) -> Path:
    if not isinstance(value, str) or not value:
        message = "checkout must be a non-empty local path"
        raise CorpusError(message)
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = manifest_parent / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        message = "checkout does not resolve to a local directory"
        raise CorpusError(message) from error
    if not resolved.is_dir():
        message = "checkout must resolve to a local directory"
        raise CorpusError(message)
    return resolved


def _load_manifest(path: Path) -> tuple[RepositorySpec, ...]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        message = "unable to load corpus manifest"
        raise CorpusError(message) from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        message = "corpus manifest must use schema version 1"
        raise CorpusError(message)
    repositories = document.get("repositories")
    if not isinstance(repositories, list) or len(repositories) != _CORPUS_SIZE:
        message = f"corpus manifest must contain exactly {_CORPUS_SIZE} repositories"
        raise CorpusError(message)

    specs: list[RepositorySpec] = []
    urls: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict) or set(item) != {
            "baseline_python",
            "checkout",
            "commit",
            "horizon_python",
            "repository_url",
        }:
            message = "every corpus entry must contain only the documented fields"
            raise CorpusError(message)
        url = _repository_url(item["repository_url"])
        if url in urls:
            message = "corpus repository URLs must be unique"
            raise CorpusError(message)
        urls.add(url)
        specs.append(
            RepositorySpec(
                repository_url=url,
                commit=_commit(item["commit"]),
                checkout=_checkout(item["checkout"], manifest_parent=path.parent),
                baseline_python=_minor(
                    item["baseline_python"],
                    field="baseline_python",
                ),
                horizon_python=_minor(
                    item["horizon_python"],
                    field="horizon_python",
                ),
            )
        )
    return tuple(sorted(specs, key=lambda spec: spec.repository_url))


def _git_output(git: str, checkout: Path, arguments: list[str]) -> str:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_") or name in {
            "SSH_ASKPASS",
            "SSH_ASKPASS_REQUIRE",
        }:
            environment.pop(name)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    result = subprocess.run(  # noqa: S603 - resolved Git executable, no shell.
        [
            git,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "credential.interactive=false",
            "-C",
            str(checkout),
            *arguments,
        ],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        message = "unable to verify a corpus checkout with Git"
        raise CorpusError(message)
    return result.stdout.strip()


def _verify_checkout(spec: RepositorySpec, *, git: str) -> None:
    origin = _git_output(
        git,
        spec.checkout,
        ["config", "--get", "remote.origin.url"],
    )
    if _repository_url(origin) != spec.repository_url:
        message = f"checkout origin does not match manifest for {spec.repository_url}"
        raise CorpusError(message)
    head = _git_output(git, spec.checkout, ["rev-parse", "--verify", "HEAD"])
    if head.lower() != spec.commit:
        message = f"checkout commit does not match manifest for {spec.repository_url}"
        raise CorpusError(message)
    status = _git_output(
        git,
        spec.checkout,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )
    if status:
        message = f"checkout is not clean for {spec.repository_url}"
        raise CorpusError(message)


def _scan_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH"):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _read_limited(stream: TextIO) -> str:
    stream.flush()
    size = stream.tell()
    if size > _MAX_REPORT_BYTES:
        message = "corpus scan report exceeded the 64 MiB review limit"
        raise CorpusError(message)
    stream.seek(0)
    return stream.read()


def _run_scan(spec: RepositorySpec, *, timeout: float) -> tuple[int, float, Any]:
    command = [
        sys.executable,
        "-I",
        "-m",
        "pyahead",
        "check",
        "--root",
        str(spec.checkout),
        "--baseline-python",
        spec.baseline_python,
        "--horizon-python",
        spec.horizon_python,
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
        result = subprocess.run(  # noqa: S603 - fixed isolated Python argv.
            command,
            cwd=Path(__file__).resolve().parents[1],
            env=_scan_environment(),
            check=False,
            stdout=output,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
        duration = time.perf_counter() - started
        rendered = _read_limited(output)
    if result.returncode not in _ACCEPTED_SCAN_EXITS:
        message = (
            f"scan failed with exit code {result.returncode} for {spec.repository_url}"
        )
        raise CorpusError(message)
    try:
        report: Any = json.loads(rendered)
    except json.JSONDecodeError as error:
        message = f"scan returned invalid JSON for {spec.repository_url}"
        raise CorpusError(message) from error
    return result.returncode, duration, report


def _relative_location(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "region"}:
        message = "finding location has an unexpected shape"
        raise CorpusError(message)
    path = value.get("path")
    if not isinstance(path, str):
        message = "finding path must be a string"
        raise CorpusError(message)
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        message = "finding path must remain repository relative"
        raise CorpusError(message)
    return {"path": path, "region": value["region"]}


def _review_finding(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        message = "scan finding must be an object"
        raise CorpusError(message)
    match = value.get("match")
    if not isinstance(match, dict):
        message = "scan finding match must be an object"
        raise CorpusError(message)
    if match.get("confidence") != "high":
        return None
    keys = (
        "action_version",
        "fingerprint",
        "impact",
        "reachable_versions",
        "rule_id",
        "sources",
        "states",
        "subject",
        "timeline",
        "title",
        "usage_contexts",
    )
    missing = [key for key in keys if key not in value]
    if missing:
        message = f"scan finding is missing review fields: {', '.join(missing)}"
        raise CorpusError(message)
    return {
        **{key: value[key] for key in keys},
        "location": _relative_location(value.get("location")),
        "match": {
            "confidence": "high",
            "evidence": match.get("evidence", {}),
            "kind": match.get("kind"),
        },
    }


def _metrics(
    report: object,
    *,
    duration: float,
    exit_code: int,
    finding_count: int,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        message = "scan report must be an object"
        raise CorpusError(message)
    required = ("diagnostics", "policy", "registry", "scan", "summary")
    if any(key not in report for key in required):
        message = "scan report is missing corpus metrics"
        raise CorpusError(message)
    diagnostics = report["diagnostics"]
    if not isinstance(diagnostics, list):
        message = "scan diagnostics must be a list"
        raise CorpusError(message)
    diagnostic_counts: dict[str, int] = {}
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict) or not isinstance(
            diagnostic.get("code"), str
        ):
            message = "scan diagnostic has an unexpected shape"
            raise CorpusError(message)
        code = diagnostic["code"]
        diagnostic_counts[code] = diagnostic_counts.get(code, 0) + 1
    return {
        "diagnostic_counts": dict(sorted(diagnostic_counts.items())),
        "duration_seconds": round(duration, 6),
        "exit_code": exit_code,
        "high_confidence_findings": finding_count,
        "policy": report["policy"],
        "registry": report["registry"],
        "scan": report["scan"],
        "summary": report["summary"],
    }


def _repository_result(
    spec: RepositorySpec,
    *,
    timeout: float,
) -> dict[str, Any]:
    exit_code, duration, report = _run_scan(spec, timeout=timeout)
    raw_findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(raw_findings, list):
        message = f"scan returned invalid findings for {spec.repository_url}"
        raise CorpusError(message)
    findings = [
        selected
        for finding in raw_findings
        if (selected := _review_finding(finding)) is not None
    ]
    findings.sort(
        key=lambda finding: (
            str(finding["rule_id"]),
            str(finding["location"]["path"]),
            str(finding["fingerprint"]),
        )
    )
    return {
        "commit": spec.commit,
        "findings": findings,
        "metrics": _metrics(
            report,
            duration=duration,
            exit_code=exit_code,
            finding_count=len(findings),
        ),
        "repository_url": spec.repository_url,
    }


def _sample_rank(repository: dict[str, Any], finding: dict[str, Any]) -> str:
    identity = "\0".join(
        (
            str(repository["repository_url"]),
            str(repository["commit"]),
            str(finding["fingerprint"]),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def _worksheet_rows(
    repositories: list[dict[str, Any]],
    *,
    sample_size: int,
) -> list[dict[str, Any]]:
    candidates = [
        (_sample_rank(repository, finding), repository, finding)
        for repository in repositories
        for finding in repository["findings"]
    ]
    candidates.sort(key=lambda item: item[0])
    rows: list[dict[str, Any]] = []
    for sample_rank, repository, finding in candidates[:sample_size]:
        location = finding["location"]
        region = location["region"]
        start = region["start"]
        rows.append(
            {
                "classification": "",
                "commit": repository["commit"],
                "fingerprint": finding["fingerprint"],
                "match_kind": finding["match"]["kind"],
                "notes": "",
                "path": location["path"],
                "regression_fixture": "",
                "repository_url": repository["repository_url"],
                "reviewer": "",
                "rule_id": finding["rule_id"],
                "sample_rank": sample_rank,
                "start_line": start["line"],
                "subject": finding["subject"],
            }
        )
    return rows


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


def _render_worksheet(rows: list[dict[str, Any]]) -> str:
    with tempfile.SpooledTemporaryFile(
        mode="w+", encoding="utf-8", newline="", max_size=1_048_576
    ) as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=_WORKSHEET_FIELDS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
        stream.seek(0)
        return stream.read()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="scan exactly 100 clean pinned public repository checkouts"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worksheet", type=Path, required=True)
    parser.add_argument("--sample-size", type=_positive_integer, default=200)
    parser.add_argument("--timeout", type=_positive_float, default=300.0)
    return parser


def _validate_destinations(
    manifest: Path,
    specs: tuple[RepositorySpec, ...],
    destinations: tuple[Path, Path],
) -> None:
    resolved = tuple(path.resolve() for path in destinations)
    if len(set(resolved)) != len(resolved) or manifest in resolved:
        message = "corpus output, worksheet, and manifest must be distinct paths"
        raise CorpusError(message)
    for destination in resolved:
        if any(destination.is_relative_to(spec.checkout) for spec in specs):
            message = "corpus outputs must remain outside every scanned checkout"
            raise CorpusError(message)


def _git_executable() -> str:
    git = shutil.which("git")
    if git is None:
        message = "Git is required to verify corpus commits"
        raise CorpusError(message)
    return git


def main(argv: list[str] | None = None) -> int:
    """Scan a corpus and atomically write minimal evidence plus a worksheet."""
    arguments = _parser().parse_args(argv)
    try:
        manifest = arguments.manifest.resolve(strict=True)
        specs = _load_manifest(manifest)
        _validate_destinations(
            manifest,
            specs,
            (arguments.output, arguments.worksheet),
        )
        git = _git_executable()
        repositories: list[dict[str, Any]] = []
        for index, spec in enumerate(specs, start=1):
            sys.stderr.write(f"[{index}/{len(specs)}] scanning {spec.repository_url}\n")
            _verify_checkout(spec, git=git)
            repositories.append(_repository_result(spec, timeout=arguments.timeout))
        document = {
            "repositories": repositories,
            "schema_version": 1,
        }
        worksheet = _render_worksheet(
            _worksheet_rows(repositories, sample_size=arguments.sample_size)
        )
        _write_atomic(
            arguments.output,
            json.dumps(document, indent=2, sort_keys=True) + "\n",
        )
        _write_atomic(arguments.worksheet, worksheet)
    except (CorpusError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(f"corpus run failed: {error}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
