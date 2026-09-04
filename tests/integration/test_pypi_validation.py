"""Hermetic end-to-end test for the PyPI validation harness pipeline.

Drives `pypi_corpus.py verify`, `pypi_validate.py run`, and `pypi_report.py`
as real subprocesses of `sys.executable` against a synthetic two-distribution
wheelhouse: no network, no `uv python install`, no mocking of any harness
internals. One package genuinely imports a stdlib module that is already
removed at the reference interpreter (the strongest available confirmation);
the other vendors a same-named shadow that only manifests at runtime, a
guaranteed false positive for PyAhead's static resolver.
"""

# ruff: noqa: SLF001

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scripts import pypi_validate

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_SIZE = 1000
_SUBPROCESS_TIMEOUT_SECONDS = 300.0


# --- fixtures: synthetic wheels and manifest (mirrors test_pypi_validate.py) -


def _record_line(path: str, data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return f"{path},sha256={encoded},{len(data)}"


def _build_wheel(
    wheelhouse: Path, name: str, version: str, files: dict[str, bytes]
) -> tuple[str, str]:
    """Hand-build a minimal, valid wheel and return (filename, sha256)."""
    dist_info = f"{name}-{version}.dist-info"
    all_files = dict(files)
    all_files[f"{dist_info}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    ).encode()
    all_files[f"{dist_info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: test\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n"
    )
    lines = [_record_line(path, data) for path, data in all_files.items()]
    lines.append(f"{dist_info}/RECORD,,")

    filename = f"{name}-{version}-py3-none-any.whl"
    wheel_path = wheelhouse / filename
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for path, data in all_files.items():
            archive.writestr(path, data)
        archive.writestr(f"{dist_info}/RECORD", "\n".join(lines) + "\n")
    return filename, hashlib.sha256(wheel_path.read_bytes()).hexdigest()


def _package_entry(
    *, rank: int, name: str, filename: str, sha256: str
) -> dict[str, Any]:
    return {
        "rank": rank,
        "name": name,
        "version": "1.0.0",
        "filename": filename,
        "sha256": sha256,
        "requires_python": None,
        "is_wheel": True,
    }


def _padding_entries(wheelhouse: Path, *, ranks: range) -> list[dict[str, Any]]:
    # `pypi_corpus.py verify` re-hashes every manifest entry's artifact, so
    # padding needs a real (tiny) wheel on disk; an impossible requires_python
    # then keeps `pypi_validate.py run` on the fast no-compatible-interpreter
    # path, never actually installing it.
    entries = []
    for rank in ranks:
        name = f"pad{rank}"
        filename, sha256 = _build_wheel(wheelhouse, name, "1.0.0", {f"{name}.py": b""})
        entries.append(
            {
                "rank": rank,
                "name": name,
                "version": "1.0.0",
                "filename": filename,
                "sha256": sha256,
                "requires_python": ">=3.999",
                "is_wheel": True,
            }
        )
    return entries


def _write_manifest(
    path: Path, wheelhouse: Path, entries: list[dict[str, Any]]
) -> None:
    padding = _padding_entries(
        wheelhouse, ranks=range(len(entries) + 1, _CORPUS_SIZE + 1)
    )
    padded = [*entries, *padding]
    assert len(padded) == _CORPUS_SIZE
    document = {
        "schema_version": 1,
        "source_url": "https://example.test/top-pypi-packages.json",
        "retrieved_on": "2026-09-03T12:00:00+00:00",
        "upstream_payload_sha256": "a" * 64,
        "packages": padded,
    }
    path.write_text(json.dumps(document), encoding="utf-8")


# --- reference-interpreter discovery -----------------------------------------


def _reference_minor() -> int | None:
    """Return the minor `pypi_validate.py run` picks for an unconstrained package.

    A finding can only be confirmed via a genuine removed-module import when
    the reference interpreter is already past that removal; on this host's
    lone interpreter, that requires knowing which minor it actually is before
    building the fixtures below.
    """
    uv = shutil.which("uv")
    if uv is None:
        return None
    installed = pypi_validate._installed_interpreters(
        uv, timeout=_SUBPROCESS_TIMEOUT_SECONDS
    )
    reference = pypi_validate._reference_interpreter(
        None,
        installed,
        baseline_minor=11,
        horizon_minor=15,
        filename="",
        is_wheel=False,
    )
    return reference.minor if reference is not None else None


# --- driving the three scripts as real subprocesses --------------------------


def _run_module(module: str, argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, test-controlled input.
        [sys.executable, "-m", module, *argv],
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        cwd=_REPO_ROOT,
        check=False,
    )


def test_end_to_end_pipeline_confirms_and_refutes(tmp_path: Path) -> None:
    """The real corpus/validate/report pipeline reaches both terminal verdicts."""
    reference_minor = _reference_minor()
    # `imp` was removed in 3.12; below that, no interpreter on this host has
    # yet passed any real registry removal, so no finding can be confirmed
    # via the module-import end-to-end path, and a second, older interpreter
    # to cross-check the timeline is never available in this hermetic setup.
    if reference_minor is None or reference_minor < 12:  # noqa: PLR2004
        pytest.skip(
            "no installed interpreter has passed a real stdlib removal; "
            "confirmation is unreachable with only one interpreter"
        )

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()

    # Package 1: a genuine `import imp` — removed in 3.12, so this raises
    # ModuleNotFoundError naming `imp` under any reference interpreter this
    # host could have, the strongest available confirmation.
    confirmed_filename, confirmed_sha256 = _build_wheel(
        wheelhouse, "impuser", "1.0.0", {"impuser/__init__.py": b"import imp\n"}
    )

    # Package 2: `a.py` genuinely imports `collections.abc` and reads
    # `collections.abc.ByteString` (real, high-confidence, still present in
    # every supported interpreter). `b.py` — imported after `a` — vendors a
    # same-named shadow and overwrites `a`'s own `collections` global at
    # import time. PyAhead's static resolver never sees this cross-file
    # mutation, so it stays high confidence; at runtime the bound name no
    # longer identifies the real subject.
    refuted_filename, refuted_sha256 = _build_wheel(
        wheelhouse,
        "bsvendor",
        "1.0.0",
        {
            "bsvendor/__init__.py": b"from . import a\nfrom . import b\n\na.use()\n",
            "bsvendor/a.py": (
                b"import collections.abc\n\n\n"
                b"def use():\n"
                b"    return collections.abc.ByteString\n"
            ),
            "bsvendor/b.py": (
                b"from . import a\n\n\n"
                b"class _FakeAbc:\n"
                b"    ByteString = object()\n\n\n"
                b"class _FakeCollections:\n"
                b"    abc = _FakeAbc()\n\n\n"
                b"a.collections = _FakeCollections()\n"
            ),
        },
    )

    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        wheelhouse,
        [
            _package_entry(
                rank=1,
                name="impuser",
                filename=confirmed_filename,
                sha256=confirmed_sha256,
            ),
            _package_entry(
                rank=2,
                name="bsvendor",
                filename=refuted_filename,
                sha256=refuted_sha256,
            ),
        ],
    )

    verify = _run_module(
        "scripts.pypi_corpus",
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
        ],
    )
    assert verify.returncode == 0, verify.stderr

    work_dir = tmp_path / "work"
    run = _run_module(
        "scripts.pypi_validate",
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--timeout",
            "60",
        ],
    )
    assert run.returncode == 0, run.stderr

    output_path = tmp_path / "report.json"
    worksheet_path = tmp_path / "worksheet.csv"
    report = _run_module(
        "scripts.pypi_report",
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(work_dir / "shards"),
            "--output",
            str(output_path),
            "--worksheet",
            str(worksheet_path),
        ],
    )
    assert report.returncode == 0, report.stderr

    record = json.loads(output_path.read_text(encoding="utf-8"))
    assert record["packages_scanned"] == 2  # noqa: PLR2004
    assert record["findings_total"] == 2  # noqa: PLR2004
    assert record["verdicts"]["confirmed"] == 1
    assert record["verdicts"]["refuted-binding"] == 1
    assert record["verdicts"]["refuted-timeline"] == 0
    assert record["verdicts"]["not-adjudicable"] == 0
    assert record["agreement_rate"] == pytest.approx(0.5)
    assert record["adjudication_coverage"] == pytest.approx(1.0)

    verify_identity = _run_module(
        "scripts.pypi_report",
        [
            "--output",
            str(output_path),
            "--worksheet",
            str(worksheet_path),
            "--verify-identity",
        ],
    )
    assert verify_identity.returncode == 0, verify_identity.stderr
