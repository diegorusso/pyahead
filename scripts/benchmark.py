"""Measure synthetic scan budgets and fail on a checked-in regression."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BenchmarkError(RuntimeError):
    """Raised when a benchmark cannot produce trustworthy measurements."""


@dataclass(frozen=True)
class Budget:
    """One checked-in synthetic scan budget."""

    name: str
    files: int
    max_seconds: float
    max_regression_seconds: float
    max_peak_rss_bytes: int | None = None


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


def _strict_number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        message = f"{label} must be a number"
        raise BenchmarkError(message)
    parsed = float(value)
    if parsed <= 0:
        message = f"{label} must be greater than zero"
        raise BenchmarkError(message)
    return parsed


def _strict_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        message = f"{label} must be a positive integer"
        raise BenchmarkError(message)
    return value


def _load_budgets(path: Path) -> tuple[Budget, ...]:
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        message = "unable to load performance budgets"
        raise BenchmarkError(message) from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        message = "performance budgets must use schema version 1"
        raise BenchmarkError(message)
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        message = "performance budgets must declare at least one case"
        raise BenchmarkError(message)

    budgets: list[Budget] = []
    names: set[str] = set()
    for item in cases:
        if not isinstance(item, dict):
            message = "every performance budget must be an object"
            raise BenchmarkError(message)
        name = item.get("name")
        if not isinstance(name, str) or not name or name in names:
            message = "performance budget names must be unique non-empty strings"
            raise BenchmarkError(message)
        names.add(name)
        memory_value = item.get("max_peak_rss_bytes")
        memory = (
            None
            if memory_value is None
            else _strict_integer(memory_value, label=f"{name}.max_peak_rss_bytes")
        )
        budgets.append(
            Budget(
                name=name,
                files=_strict_integer(item.get("files"), label=f"{name}.files"),
                max_seconds=_strict_number(
                    item.get("max_seconds"),
                    label=f"{name}.max_seconds",
                ),
                max_regression_seconds=_strict_number(
                    item.get("max_regression_seconds"),
                    label=f"{name}.max_regression_seconds",
                ),
                max_peak_rss_bytes=memory,
            )
        )
    return tuple(budgets)


def _peak_rss_bytes() -> int | None:
    try:
        import resource  # noqa: PLC0415 - unavailable on Windows.
    except ImportError:
        return None
    maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return maximum if sys.platform == "darwin" else maximum * 1024


def _worker(root: Path, report_path: Path) -> int:
    from pyahead.cli import main as pyahead_main  # noqa: PLC0415

    result = pyahead_main(
        [
            "check",
            "--root",
            str(root),
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.14",
            "--include",
            "src/**/*.py",
            "--source-root",
            "src",
            "--fail-on",
            "never",
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
    )
    sys.stdout.write(json.dumps({"peak_rss_bytes": _peak_rss_bytes()}))
    return result


def _write_synthetic_project(root: Path, files: int) -> None:
    source = root / "src"
    source.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "pyahead-benchmark"\n'
            'version = "0"\n'
            'requires-python = ">=3.11"\n'
        ),
        encoding="utf-8",
    )
    content = '"""Synthetic benchmark module."""\n\nVALUE = 1\n'
    for index in range(files):
        (source / f"module_{index:05d}.py").write_text(content, encoding="utf-8")


def _run_once(
    root: Path,
    *,
    timeout: float,
    expected_files: int,
) -> tuple[float, int | None, str]:
    report_path = root / "benchmark-report.json"
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--_worker-root",
        str(root),
        "--_worker-report",
        str(report_path),
    ]
    started = time.perf_counter()
    result = subprocess.run(  # noqa: S603 - fixed interpreter and script argv.
        command,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    duration = time.perf_counter() - started
    if result.returncode != 0:
        message = f"benchmark worker failed with exit code {result.returncode}"
        raise BenchmarkError(message)
    try:
        measurement: Any = json.loads(result.stdout)
        report: Any = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        message = "benchmark worker returned invalid JSON"
        raise BenchmarkError(message) from error
    if not isinstance(measurement, dict):
        message = "benchmark worker measurement is not an object"
        raise BenchmarkError(message)
    scan = report.get("scan") if isinstance(report, dict) else None
    if (
        not isinstance(scan, dict)
        or scan.get("files_discovered") != expected_files
        or scan.get("files_analyzed") != expected_files
        or scan.get("files_incomplete") != 0
    ):
        message = "benchmark scan did not completely analyze the synthetic corpus"
        raise BenchmarkError(message)
    memory = measurement.get("peak_rss_bytes")
    if memory is not None and (isinstance(memory, bool) or not isinstance(memory, int)):
        message = "benchmark worker returned invalid memory data"
        raise BenchmarkError(message)
    digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    return duration, memory, digest


def _measure(budget: Budget, *, repeat: int) -> dict[str, Any]:
    durations: list[float] = []
    memories: list[int] = []
    report_digests: list[str] = []
    determinism_runs = max(2, repeat)
    with tempfile.TemporaryDirectory(prefix=f"pyahead-benchmark-{budget.name}-") as tmp:
        root = Path(tmp)
        _write_synthetic_project(root, budget.files)
        for run_index in range(determinism_runs):
            duration, memory, report_digest = _run_once(
                root,
                timeout=max(60.0, budget.max_regression_seconds * 1.25),
                expected_files=budget.files,
            )
            report_digests.append(report_digest)
            if run_index < repeat:
                durations.append(duration)
                if memory is not None:
                    memories.append(memory)

    median_seconds = statistics.median(durations)
    peak_memory = max(memories) if memories else None
    target_duration_passed = median_seconds <= budget.max_seconds
    regression_duration_passed = median_seconds <= budget.max_regression_seconds
    memory_passed = (
        True
        if budget.max_peak_rss_bytes is None or peak_memory is None
        else peak_memory <= budget.max_peak_rss_bytes
    )
    deterministic = len(set(report_digests)) == 1
    return {
        "budget": {
            "max_peak_rss_bytes": budget.max_peak_rss_bytes,
            "max_regression_seconds": budget.max_regression_seconds,
            "max_seconds": budget.max_seconds,
        },
        "files": budget.files,
        "measurements": {
            "duration_seconds": [round(value, 6) for value in durations],
            "median_seconds": round(median_seconds, 6),
            "peak_rss_bytes": peak_memory,
            "report_sha256": sorted(set(report_digests)),
        },
        "deterministic": deterministic,
        "determinism_runs": determinism_runs,
        "memory_measured": peak_memory is not None,
        "name": budget.name,
        "passed": regression_duration_passed and memory_passed and deterministic,
        "target_passed": target_duration_passed and memory_passed and deterministic,
    }


def _render_document(results: list[dict[str, Any]], *, repeat: int) -> str:
    document = {
        "cases": results,
        "passed": all(bool(result["passed"]) for result in results),
        "performance_targets_met": all(
            bool(result["target_passed"]) for result in results
        ),
        "platform": {
            "implementation": platform.python_implementation(),
            "python": platform.python_version(),
            "system": platform.system(),
        },
        "repeat": repeat,
        "schema_version": 1,
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _select_budgets(
    budgets: tuple[Budget, ...],
    selected_cases: list[str],
) -> tuple[Budget, ...]:
    known = {budget.name for budget in budgets}
    unknown = sorted(set(selected_cases) - known)
    if unknown:
        message = f"unknown benchmark case: {', '.join(unknown)}"
        raise BenchmarkError(message)
    if not selected_cases:
        return budgets
    selected_names = set(selected_cases)
    return tuple(budget for budget in budgets if budget.name in selected_names)


def _write_output(destination: Path, content: str) -> None:
    if destination == Path("-"):
        sys.stdout.write(content)
        return
    destination = destination.resolve()
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="measure checked-in PyAhead scan performance budgets"
    )
    parser.add_argument("--repeat", type=_positive_integer, default=3)
    parser.add_argument("--output", type=Path, default=Path("-"))
    parser.add_argument(
        "--budgets",
        type=Path,
        default=Path(__file__).with_name("performance-budgets.json"),
    )
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        dest="selected_cases",
        help="measure only a named case (repeatable; intended for diagnosis)",
    )
    parser.add_argument(
        "--_worker-root",
        type=Path,
        dest="worker_root",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--_worker-report",
        type=Path,
        dest="worker_report",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark suite or one internal measurement worker."""
    arguments = _parser().parse_args(argv)
    if arguments.worker_root is not None:
        if arguments.worker_report is None:
            sys.stderr.write("benchmark worker requires a report path\n")
            return 2
        return _worker(arguments.worker_root, arguments.worker_report)

    try:
        budgets = _load_budgets(arguments.budgets)
        selected = _select_budgets(budgets, arguments.selected_cases)
        results = [_measure(budget, repeat=arguments.repeat) for budget in selected]
        rendered = _render_document(results, repeat=arguments.repeat)
        _write_output(arguments.output, rendered)
    except (BenchmarkError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(f"benchmark failed: {error}\n")
        return 2
    return 0 if all(bool(result["passed"]) for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
