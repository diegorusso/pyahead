"""Scanning an installed package with PyAhead."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, TextIO

from scripts import _common
from scripts.pypi_validate._interpreters import (
    _action_version_minor,
    _finding_interpreters_needed,
)
from scripts.pypi_validate._model import (
    _ACCEPTED_SCAN_EXITS,
    _MAX_REPORT_BYTES,
    _REPO_ROOT,
    PypiValidateError,
)
from scripts.pypi_validate._record import _module_name


@dataclass(frozen=True)
class ScanOutcome:
    """The result of one `pyahead check` invocation against an installed package."""

    exit_code: int | None
    duration_seconds: float
    findings: tuple[dict[str, Any], ...]
    error: str | None


_scan_environment = _common.scan_environment


def _read_limited(stream: TextIO) -> str:
    message = "scan report exceeded the 64 MiB review limit"
    return _common.read_limited(stream, _MAX_REPORT_BYTES, PypiValidateError(message))


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
