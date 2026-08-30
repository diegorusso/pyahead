"""M8.5f packaging and public typing contract tests.

The wheel and sdist are built through the locked Hatchling API rather than a
`uv build` subprocess so the check stays offline and host-independent.
"""

import os
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder

from pyahead.analysis.discovery import project_module_names
from pyahead.evidence import render_evidence_schema

ROOT = Path(__file__).parents[2]
CONSUMER = """\
from pathlib import Path

from pyahead.analysis import ScanRequest, scan
from pyahead.registry import RegistryError, load_registry

report = scan(ScanRequest(root=Path(".")))
registry = load_registry()
error: type[RegistryError] = RegistryError
reveal_type(report)
reveal_type(registry)
reveal_type(report.findings)
reveal_type(report.schema_version)
"""
EXPECTED_REVEALED = (
    'Revealed type is "pyahead.model.ScanReport"',
    'Revealed type is "pyahead.model.Registry"',
    'Revealed type is "tuple[pyahead.model.Finding, ...]"',
    'Revealed type is "int"',
)


@dataclass(frozen=True)
class _Distributions:
    """One built wheel and sdist plus the extracted wheel tree."""

    wheel_names: tuple[str, ...]
    sdist_names: tuple[str, ...]
    extracted: Path


@pytest.fixture(scope="module")
def distributions(tmp_path_factory: pytest.TempPathFactory) -> _Distributions:
    """Build both distributions once for this module."""
    output = tmp_path_factory.mktemp("dist")
    wheel = next(
        iter(
            WheelBuilder(str(ROOT)).build(directory=str(output), versions=["standard"])
        )
    )
    sdist = next(
        iter(
            SdistBuilder(str(ROOT)).build(directory=str(output), versions=["standard"])
        )
    )
    extracted = output / "site"
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = tuple(archive.namelist())
        archive.extractall(extracted)  # noqa: S202 - our own freshly built wheel.
    with tarfile.open(sdist) as archive:
        sdist_names = tuple(archive.getnames())
    return _Distributions(
        wheel_names=wheel_names,
        sdist_names=sdist_names,
        extracted=extracted,
    )


def test_wheel_ships_the_typing_marker_and_packaged_data(
    distributions: _Distributions,
) -> None:
    """Installed consumers get the typing marker, registry data, and schema."""
    names = distributions.wheel_names

    assert "pyahead/py.typed" in names
    assert "pyahead/reporting/schema.py" in names
    assert "pyahead/data/schema/report-v1.json" in names
    assert any(name.startswith("pyahead/data/registry/") for name in names)


def test_sdist_ships_every_published_schema(distributions: _Distributions) -> None:
    """The source distribution carries the checked-in machine contracts."""
    schemas = {
        name.split("docs/schema/", 1)[1]
        for name in distributions.sdist_names
        if "docs/schema/" in name
    }

    assert {
        "dependency-report-v1.json",
        "evidence-v1.json",
        "registry-coverage-v1.json",
        "registry-index-v1.json",
        "registry-rule-v1.json",
        "report-v1.json",
    } <= schemas


def test_installed_wheel_consumer_passes_strict_mypy(
    distributions: _Distributions,
    tmp_path: Path,
) -> None:
    """A clean consumer of the built wheel type-checks with concrete types.

    Wheel-tree resolution alone does not require `py.typed`; the marker's
    presence is asserted separately by the packaging test above. The subprocess
    inherits the ambient environment, so colour output is disabled explicitly:
    `FORCE_COLOR` otherwise makes mypy interleave ANSI escapes with the revealed
    types and the substring assertions below stop matching.
    """
    consumer = tmp_path / "use_pyahead.py"
    consumer.write_text(CONSUMER, encoding="utf-8")
    environment = dict(os.environ, MYPYPATH=str(distributions.extracted))

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell.
        [
            sys.executable,
            "-m",
            "mypy",
            "--strict",
            "--no-color-output",
            "--no-incremental",
            "--cache-dir",
            str(tmp_path / "cache"),
            str(consumer),
        ],
        capture_output=True,
        text=True,
        env=environment,
        cwd=tmp_path,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    for revealed in EXPECTED_REVEALED:
        assert revealed in completed.stdout, completed.stdout
    assert "Any" not in completed.stdout


def test_documented_compatibility_exports_remain_importable() -> None:
    """M8.5f keeps the named compatibility accessors until a separate decision."""
    assert callable(project_module_names)
    assert render_evidence_schema().endswith("\n")
