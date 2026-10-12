"""The harness's command line."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from pyahead._human_text import SafeArgumentParser, escape_terminal_text
from pyahead.versions import InvalidPythonMinorError, PythonMinor
from scripts import pypi_corpus
from scripts._common import normalized_name as _normalized_name
from scripts._common import positive_float as _positive_float
from scripts._common import positive_integer as _positive_integer
from scripts._common import sha256_path as _sha256_path
from scripts._common import write_atomic as _write_atomic
from scripts.pypi_validate._interpreters import (
    _installed_interpreters,
    _registry_window_floor,
)
from scripts.pypi_validate._model import PypiValidateError, RunOptions
from scripts.pypi_validate._orchestration import _process_package
from scripts.pypi_validate._provision import _uv_executable, _uv_python_install_dir


def _shard_spec(value: str) -> tuple[int, int]:
    match = re.fullmatch(r"([0-9]+)/([0-9]+)", value)
    if match is None:
        message = "--shard must look like INDEX/COUNT"
        raise argparse.ArgumentTypeError(message)
    index, count = int(match.group(1)), int(match.group(2))
    if count < 1 or not (0 <= index < count):
        message = "--shard index must satisfy 0 <= INDEX < COUNT"
        raise argparse.ArgumentTypeError(message)
    return index, count


def _shard_selected(rank: int, shard_index: int, shard_count: int) -> bool:
    return (rank - 1) % shard_count == shard_index


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="pyahead-pypi-validate",
        description="provision, scan, and shard the pinned PyPI top-1000 corpus",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="provision interpreters and packages, scan, and write per-package shards",
    )
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--wheelhouse", type=Path, required=True)
    run.add_argument("--work-dir", type=Path, required=True)
    run.add_argument(
        "--execute-third-party-code",
        action="store_true",
        help="required acknowledgement: this installs and imports arbitrary code",
    )
    run.add_argument("--shard", type=_shard_spec, default=(0, 1), metavar="INDEX/COUNT")
    run.add_argument("--refresh", action="store_true", help="reprocess existing shards")
    run.add_argument("--limit", type=_positive_integer, default=None)
    run.add_argument(
        "--timeout",
        type=_positive_float,
        default=300.0,
        help="maximum seconds for each install or scan subprocess (default: 300)",
    )
    run.add_argument("--horizon-python", default="3.15", metavar="VERSION")

    return parser


def _run(arguments: argparse.Namespace) -> None:
    if not arguments.execute_third_party_code:
        message = (
            "refusing to install and import third-party code without "
            "--execute-third-party-code"
        )
        raise PypiValidateError(message)

    try:
        horizon = PythonMinor.parse(arguments.horizon_python)
    except InvalidPythonMinorError as error:
        message = f"invalid --horizon-python: {error}"
        raise PypiValidateError(message) from error

    manifest_path = arguments.manifest.resolve(strict=True)
    _, entries = pypi_corpus.load_manifest(manifest_path)
    manifest_sha256 = _sha256_path(manifest_path)
    wheelhouse = arguments.wheelhouse.resolve(strict=True)

    # Resolved like the manifest and wheelhouse above: the per-package venv
    # and scratch home derive from this path and are handed to `bwrap` as
    # bind sources, which bubblewrap looks up against the sandbox's old root
    # rather than the caller's working directory, so a relative work
    # directory (as the documented invocation uses) fails every install
    # with "Can't find source path".
    work_dir = arguments.work_dir.resolve()
    shard_dir = work_dir / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)

    uv = _uv_executable()
    bwrap = shutil.which("bwrap")
    installed = _installed_interpreters(uv, timeout=arguments.timeout)
    python_install_dir = _uv_python_install_dir(uv, timeout=arguments.timeout)

    shard_index, shard_count = arguments.shard
    selected = [
        entry
        for entry in entries
        if _shard_selected(entry.rank, shard_index, shard_count)
    ]
    if arguments.limit is not None:
        selected = selected[: arguments.limit]

    options = RunOptions(
        wheelhouse=wheelhouse,
        work_dir=work_dir,
        timeout=arguments.timeout,
        horizon_minor=horizon.minor,
        baseline_minor=_registry_window_floor(),
        bwrap=bwrap,
        uv=uv,
        manifest_sha256=manifest_sha256,
        python_install_dir=python_install_dir,
    )

    for entry in selected:
        shard_path = shard_dir / f"{entry.rank:04d}-{_normalized_name(entry.name)}.json"
        if shard_path.exists() and not arguments.refresh:
            continue
        sys.stderr.write(f"[{entry.rank}] {escape_terminal_text(entry.name)}\n")
        result = _process_package(entry, installed=installed, options=options)
        _write_atomic(shard_path, json.dumps(result, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Provision, scan, and shard the pinned PyPI corpus offline."""
    arguments = _parser().parse_args(argv)
    try:
        _run(arguments)
    except (
        PypiValidateError,
        pypi_corpus.PypiCorpusError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        rendered = escape_terminal_text(str(error))
        sys.stderr.write(f"pypi validate run failed: {rendered}\n")
        return 1
    return 0
