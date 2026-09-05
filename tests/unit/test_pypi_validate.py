"""Hermetic unit tests for PyPI environment provisioning and static scanning."""

# ruff: noqa: SLF001

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest
from packaging.tags import cpython_tags

if sys.platform != "linux":  # pragma: no cover - CI platform guard
    pytest.skip(
        "the PyPI validation harness targets Linux: its isolation depends on "
        "bwrap, and RLIMIT_AS is not dependably enforceable elsewhere",
        allow_module_level=True,
    )

from scripts import pypi_validate

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from scripts.pypi_corpus import PackageEntry

_CORPUS_SIZE = 1000


# --- fixtures: synthetic wheels and manifests -------------------------------


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


def _package_entry(  # noqa: PLR0913 - mirrors the manifest schema's own fields.
    *,
    rank: int,
    name: str,
    version: str = "1.0.0",
    filename: str,
    sha256: str,
    requires_python: str | None = None,
) -> dict[str, Any]:
    return {
        "rank": rank,
        "name": name,
        "version": version,
        "filename": filename,
        "sha256": sha256,
        "requires_python": requires_python,
        "is_wheel": True,
    }


def _padding_entries(*, ranks: range) -> list[dict[str, Any]]:
    # An impossible requires_python keeps every padding entry on the fast
    # no-compatible-interpreter path, never attempting a real install of an
    # artifact that was never written to the test wheelhouse.
    return [
        _package_entry(
            rank=rank,
            name=f"pad{rank}",
            filename=f"pad{rank}-1.0.0-py3-none-any.whl",
            sha256=hashlib.sha256(f"pad{rank}".encode()).hexdigest(),
            requires_python=">=3.999",
        )
        for rank in ranks
    ]


def _write_manifest(path: Path, entries: list[dict[str, Any]]) -> None:
    padding = _padding_entries(ranks=range(len(entries) + 1, _CORPUS_SIZE + 1))
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


# --- interpreter resolution --------------------------------------------


def _installed(*minors: int) -> dict[int, pypi_validate.InstalledInterpreter]:
    return {
        minor: pypi_validate.InstalledInterpreter(
            minor=minor, version=f"3.{minor}.0", path=Path(f"/usr/bin/python3.{minor}")
        )
        for minor in minors
    }


def _reference_interpreter(  # noqa: PLR0913 - mirrors the manifest entry's own fields.
    requires_python: str | None,
    installed: Mapping[int, pypi_validate.InstalledInterpreter],
    *,
    baseline_minor: int,
    horizon_minor: int,
    filename: str = "pkg-1.0.0-py3-none-any.whl",
    is_wheel: bool = False,
) -> pypi_validate.InstalledInterpreter | None:
    """`_reference_interpreter` with a not-a-wheel default.

    Keeps plain `requires_python` resolution tests from tripping the
    wheel-tag check.
    """
    return pypi_validate._reference_interpreter(
        requires_python,
        installed,
        baseline_minor=baseline_minor,
        horizon_minor=horizon_minor,
        filename=filename,
        is_wheel=is_wheel,
    )


def test_reference_interpreter_picks_the_lowest_satisfying_minor() -> None:
    """A `>=3.12` constraint skips an installed 3.11 in favor of 3.12."""
    installed = _installed(11, 12, 13)
    reference = _reference_interpreter(
        ">=3.12", installed, baseline_minor=11, horizon_minor=15
    )
    assert reference == installed[12]


def test_reference_interpreter_clamps_unconstrained_packages_to_baseline() -> None:
    """A package with no `requires_python` still starts at the baseline minor."""
    installed = _installed(11, 13)
    reference = _reference_interpreter(
        None, installed, baseline_minor=11, horizon_minor=15
    )
    assert reference == installed[11]


def test_reference_interpreter_ignores_an_unparseable_specifier() -> None:
    """A malformed `requires_python` is treated as unconstrained, not fatal."""
    installed = _installed(11)
    reference = _reference_interpreter(
        "not-a-specifier", installed, baseline_minor=11, horizon_minor=15
    )
    assert reference == installed[11]


def test_reference_interpreter_returns_none_when_nothing_satisfies() -> None:
    """A `>=3.99` constraint that no installed interpreter can satisfy yields None."""
    reference = _reference_interpreter(
        ">=3.99", _installed(11, 12, 13), baseline_minor=11, horizon_minor=15
    )
    assert reference is None


def test_reference_interpreter_returns_none_when_minor_is_not_installed() -> None:
    """A satisfiable constraint with no matching installed minor yields None."""
    reference = _reference_interpreter(
        ">=3.14", _installed(11, 12, 13), baseline_minor=11, horizon_minor=15
    )
    assert reference is None


def test_reference_interpreter_skips_a_minor_the_wheel_cannot_install() -> None:
    """A `cp313`-only wheel is skipped for an older minor even a `requires_python` fit.

    `requires_python` is a distribution-wide claim; the specific wheel
    artifact pinned in the manifest can be narrower than that claim. Picking
    a reference interpreter that satisfies `requires_python` but not the
    wheel's own tags would hand `uv pip install` an artifact it can never
    install under that venv, for a reason unrelated to anything this harness
    measures.
    """
    platform = next(iter(cpython_tags(python_version=(3, 13)))).platform
    reference = _reference_interpreter(
        ">=3.11",
        _installed(11, 12, 13),
        baseline_minor=11,
        horizon_minor=15,
        filename=f"pkg-1.0.0-cp313-cp313-{platform}.whl",
        is_wheel=True,
    )
    assert reference == _installed(11, 12, 13)[13]


def test_reference_interpreter_returns_none_when_no_wheel_tag_matches() -> None:
    """A wheel tagged for an interpreter outside the installed set yields None."""
    reference = _reference_interpreter(
        ">=3.11",
        _installed(11, 12),
        baseline_minor=11,
        horizon_minor=15,
        filename="pkg-1.0.0-cp313-cp313-any.whl",
        is_wheel=True,
    )
    assert reference is None


def test_reference_interpreter_ignores_wheel_tags_for_an_sdist() -> None:
    """`is_wheel=False` never consults the (sdist) filename's tags at all."""
    reference = _reference_interpreter(
        ">=3.11",
        _installed(11, 12, 13),
        baseline_minor=11,
        horizon_minor=15,
        filename="pkg-1.0.0.tar.gz",
        is_wheel=False,
    )
    assert reference == _installed(11, 12, 13)[11]


# --- interpreter-set derivation ------------------------------------------


@pytest.mark.parametrize(
    ("action_minor", "expected"),
    [
        (14, (13, 14)),
        (11, (11,)),  # action_version - 1 falls below the baseline and is dropped.
        (16, (15,)),  # action_version itself exceeds the horizon and is dropped.
        (17, ()),  # both sides of the pair fall outside the horizon.
    ],
)
def test_finding_interpreters_needed_pairs_and_clamps(
    action_minor: int, expected: tuple[int, ...]
) -> None:
    """The `(action_version - 1, action_version)` pair is clamped to 3.11-3.15."""
    assert (
        pypi_validate._finding_interpreters_needed(
            action_minor, baseline_minor=11, horizon_minor=15
        )
        == expected
    )


def test_action_version_minor_parses_a_valid_minor() -> None:
    """A well-formed `MAJOR.MINOR` action_version parses to its minor int."""
    expected_minor = 14
    assert pypi_validate._action_version_minor("3.14") == expected_minor


def test_action_version_minor_rejects_a_non_string() -> None:
    """A non-string action_version fails closed instead of coercing."""
    with pytest.raises(pypi_validate.PypiValidateError, match="must be a string"):
        pypi_validate._action_version_minor(314)


def test_action_version_minor_rejects_a_malformed_value() -> None:
    """A malformed action_version string fails closed."""
    with pytest.raises(pypi_validate.PypiValidateError, match="unexpected shape"):
        pypi_validate._action_version_minor("not-a-version")


# --- RECORD-derived path selection and module mapping --------------------


def _write_installed_distribution(
    site_packages: Path, *, name: str, version: str, files: dict[str, bytes]
) -> Path:
    """Create a real on-disk distribution: importlib.metadata skips missing files."""
    dist_info = site_packages / f"{name}-{version}.dist-info"
    dist_info.mkdir(parents=True)
    all_files = dict(files)
    all_files[f"{dist_info.name}/METADATA"] = (
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    ).encode()
    for relative, data in all_files.items():
        destination = site_packages / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    lines = [_record_line(path, data) for path, data in all_files.items()]
    lines.append(f"{dist_info.name}/RECORD,,")
    (dist_info / "RECORD").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dist_info


def test_owned_python_files_keeps_only_the_distributions_own_py_files(
    tmp_path: Path,
) -> None:
    """Installer metadata, data-directory scripts, and non-.py files are excluded."""
    dist_info = _write_installed_distribution(
        tmp_path,
        name="demo",
        version="1.0.0",
        files={
            "demo/__init__.py": b"",
            "demo/sub/mod.py": b"",
            "demo/data.txt": b"",
            "demo-1.0.0.data/scripts/demoscript": b"",
        },
    )
    owned = pypi_validate._owned_python_files(dist_info)
    assert owned == (
        PurePosixPath("demo/__init__.py"),
        PurePosixPath("demo/sub/mod.py"),
    )


def test_include_patterns_lists_each_owned_file_exactly() -> None:
    """Patterns are root-anchored per file, not widened to a shared top-level dir.

    A directory-level pattern would also match unrelated distributions
    installed under the same namespace-package prefix (e.g. `google/`),
    corrupting this package's finding counts.
    """
    paths = (
        PurePosixPath("pkg/__init__.py"),
        PurePosixPath("pkg/sub/mod.py"),
        PurePosixPath("single_module.py"),
    )
    assert pypi_validate._include_patterns(paths) == (
        "/pkg/__init__.py",
        "/pkg/sub/mod.py",
        "/single_module.py",
    )


def test_module_name_strips_init_for_packages() -> None:
    """A package's `__init__.py` maps to the package's own dotted name."""
    assert pypi_validate._module_name(PurePosixPath("pkg/__init__.py")) == "pkg"


def test_module_name_handles_a_nested_submodule() -> None:
    """A nested submodule file maps to its full dotted path."""
    assert pypi_validate._module_name(PurePosixPath("pkg/sub/mod.py")) == "pkg.sub.mod"


def test_module_name_handles_a_namespace_packages_init(tmp_path: Path) -> None:
    """Mapping does not require `__init__.py` to exist on disk (namespace packages)."""
    assert pypi_validate._module_name(PurePosixPath("pkg/sub/__init__.py")) == "pkg.sub"
    assert not (tmp_path / "pkg" / "sub" / "__init__.py").exists()


def test_module_name_handles_a_lone_top_level_module() -> None:
    """A single top-level module file maps to its own bare name."""
    assert pypi_validate._module_name(PurePosixPath("mod.py")) == "mod"


def test_distribution_info_dir_matches_by_normalized_name(tmp_path: Path) -> None:
    """A dist-info directory is located by its declared, normalized project name."""
    _write_installed_distribution(
        tmp_path,
        name="Other-Pkg",
        version="2.0.0",
        files={"other_pkg/__init__.py": b""},
    )
    dist_info = _write_installed_distribution(
        tmp_path, name="Demo_Pkg", version="1.0.0", files={"demo_pkg/__init__.py": b""}
    )
    found = pypi_validate._distribution_info_dir(tmp_path, normalized_name="demo-pkg")
    assert found == dist_info


def test_distribution_info_dir_raises_when_no_distribution_matches(
    tmp_path: Path,
) -> None:
    """A normalized name with no matching installed distribution fails closed."""
    with pytest.raises(pypi_validate.PypiValidateError, match="not found"):
        pypi_validate._distribution_info_dir(tmp_path, normalized_name="missing")


# --- finding mapping -----------------------------------------------------


def _finding(
    *, path: str = "pkg/mod.py", action_version: str = "3.14"
) -> dict[str, Any]:
    return {
        "rule_id": "CPY9999",
        "fingerprint": "deadbeef",
        "action_version": action_version,
        "location": {"path": path, "region": {}},
    }


def test_mapped_finding_adds_module_and_interpreter_fields() -> None:
    """A mapped finding gains its module name and needed-interpreter set."""
    mapped = pypi_validate._mapped_finding(
        _finding(path="pkg/mod.py", action_version="3.14"),
        baseline_minor=11,
        horizon_minor=15,
    )
    assert mapped["module"] == "pkg.mod"
    assert mapped["interpreters_needed"] == [13, 14]
    assert mapped["adjudication_status"] == "pending"
    assert mapped["rule_id"] == "CPY9999"


def test_mapped_finding_marks_out_of_horizon_action_versions_not_adjudicable() -> None:
    """A finding whose action_version exceeds the interpreter horizon is flagged."""
    mapped = pypi_validate._mapped_finding(
        _finding(action_version="3.16"), baseline_minor=11, horizon_minor=15
    )
    assert mapped["adjudication_status"] == "not-adjudicable:no-interpreter"


def test_mapped_finding_rejects_an_absolute_location_path() -> None:
    """A finding location outside the scan root is never trusted."""
    with pytest.raises(pypi_validate.PypiValidateError, match="escapes"):
        pypi_validate._mapped_finding(
            _finding(path="/etc/passwd"), baseline_minor=11, horizon_minor=15
        )


def test_mapped_finding_rejects_a_path_traversal() -> None:
    """A finding location containing `..` is never trusted."""
    with pytest.raises(pypi_validate.PypiValidateError, match="escapes"):
        pypi_validate._mapped_finding(
            _finding(path="../outside.py"), baseline_minor=11, horizon_minor=15
        )


# --- CLI argument parsing -------------------------------------------------


def test_shard_spec_parses_a_valid_index_and_count() -> None:
    """A well-formed `INDEX/COUNT` shard spec parses to a tuple of ints."""
    assert pypi_validate._shard_spec("1/4") == (1, 4)


def test_shard_spec_rejects_an_out_of_range_index() -> None:
    """A shard index that is not below its count is refused."""
    with pytest.raises(argparse.ArgumentTypeError, match="0 <= INDEX < COUNT"):
        pypi_validate._shard_spec("4/4")


def test_shard_spec_rejects_a_malformed_value() -> None:
    """A shard spec that is not `INDEX/COUNT` is refused."""
    with pytest.raises(argparse.ArgumentTypeError, match="INDEX/COUNT"):
        pypi_validate._shard_spec("nonsense")


def test_shard_selected_partitions_ranks_by_index() -> None:
    """Every rank is claimed by exactly one shard index for a given count."""
    selected_by_shard = [
        [rank for rank in range(1, 7) if pypi_validate._shard_selected(rank, index, 3)]
        for index in range(3)
    ]
    assert selected_by_shard == [[1, 4], [2, 5], [3, 6]]


# --- isolation -------------------------------------------------------------


def test_isolate_command_never_binds_the_host_root(tmp_path: Path) -> None:
    """The sandbox must never expose the whole host filesystem read-only.

    A blanket `--ro-bind / /` would let target code read credentials and
    other secrets anywhere on the host by absolute path; only specific,
    narrow directories are ever bound.
    """
    isolation = pypi_validate._isolate_command(
        ["python3"],
        bwrap="/usr/bin/bwrap",
        venv_dir=tmp_path / "venv",
        scratch_home=tmp_path / "home",
        venv_writable=False,
    )
    assert isolation.mode == "bwrap"
    assert "/" not in isolation.command
    proc_index = isolation.command.index("--proc")
    assert isolation.command[proc_index + 1] == "/proc"


def test_isolate_command_binds_the_venv_read_only_for_probes(tmp_path: Path) -> None:
    """Probes must not be able to write into the shared venv between runs."""
    venv_dir = tmp_path / "venv"
    isolation = pypi_validate._isolate_command(
        ["python3"],
        bwrap="/usr/bin/bwrap",
        venv_dir=venv_dir,
        scratch_home=tmp_path / "home",
        venv_writable=False,
    )
    venv_index = isolation.command.index(str(venv_dir))
    assert isolation.command[venv_index - 1] == "--ro-bind"


def test_isolate_command_binds_the_venv_read_write_for_install(tmp_path: Path) -> None:
    """Installing a distribution must still be able to write into the venv."""
    venv_dir = tmp_path / "venv"
    isolation = pypi_validate._isolate_command(
        ["python3"],
        bwrap="/usr/bin/bwrap",
        venv_dir=venv_dir,
        scratch_home=tmp_path / "home",
        venv_writable=True,
    )
    venv_index = isolation.command.index(str(venv_dir))
    assert isolation.command[venv_index - 1] == "--bind"


def test_isolate_command_binds_no_venv_for_a_bare_interpreter_probe(
    tmp_path: Path,
) -> None:
    """A C2 bare-interpreter probe has no installed-distribution venv to bind.

    `venv_dir=None` must still produce a sandboxed command - scratch home
    bound and `HOME` pointed at it - just without the venv-specific bind
    that only C1 probes need.
    """
    scratch_home = tmp_path / "home"
    isolation = pypi_validate._isolate_command(
        ["python3"],
        bwrap="/usr/bin/bwrap",
        venv_dir=None,
        scratch_home=scratch_home,
        venv_writable=False,
    )
    assert isolation.mode == "bwrap"
    home_index = isolation.command.index(str(scratch_home))
    assert isolation.command[home_index - 1] == "--bind"
    setenv_index = isolation.command.index("--setenv")
    assert isolation.command[setenv_index + 1 : setenv_index + 3] == [
        "HOME",
        str(scratch_home),
    ]


def test_isolate_command_falls_back_to_rlimit_only_without_bwrap(
    tmp_path: Path,
) -> None:
    """No `bwrap` executable means the command runs unwrapped, rlimit-only."""
    isolation = pypi_validate._isolate_command(
        ["python3"],
        bwrap=None,
        venv_dir=tmp_path / "venv",
        scratch_home=tmp_path / "home",
        venv_writable=False,
    )
    assert isolation == pypi_validate.Isolation(mode="rlimit-only", command=["python3"])


# --- full pipeline: real uv venv/install/scan subprocesses ---------------


def _run_main(argv: list[str]) -> int:
    return pypi_validate.main(argv)


def test_main_requires_execute_third_party_code(tmp_path: Path) -> None:
    """The CLI refuses to run at all without the explicit safety acknowledgement."""
    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(tmp_path / "missing-manifest.json"),
            "--wheelhouse",
            str(tmp_path / "missing-wheelhouse"),
            "--work-dir",
            str(work_dir),
        ]
    )
    assert result == 1
    assert not work_dir.exists()


def test_run_skips_a_package_with_no_compatible_interpreter(tmp_path: Path) -> None:
    """A package with no satisfying installed interpreter is skipped."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [
            _package_entry(
                rank=1,
                name="nopeforever",
                filename="nopeforever-1.0.0-py3-none-any.whl",
                sha256="c" * 64,
                requires_python=">=3.99",
            )
        ],
    )
    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--limit",
            "1",
        ]
    )
    assert result == 0
    shards = list((work_dir / "shards").glob("*.json"))
    assert len(shards) == 1
    document = json.loads(shards[0].read_text(encoding="utf-8"))
    assert document["status"] == "skipped"
    assert document["reason"] == "no-compatible-interpreter"


def test_run_shards_select_disjoint_packages(tmp_path: Path) -> None:
    """`--shard INDEX/COUNT` partitions packages without any real provisioning."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [
            _package_entry(
                rank=1,
                name="never1",
                filename="never1-1.0.0-py3-none-any.whl",
                sha256="c" * 64,
                requires_python=">=3.99",
            ),
            _package_entry(
                rank=2,
                name="never2",
                filename="never2-1.0.0-py3-none-any.whl",
                sha256="d" * 64,
                requires_python=">=3.99",
            ),
        ],
    )
    work_dir = tmp_path / "work"
    for index in (0, 1):
        result = _run_main(
            [
                "run",
                "--manifest",
                str(manifest_path),
                "--wheelhouse",
                str(wheelhouse),
                "--work-dir",
                str(work_dir),
                "--execute-third-party-code",
                "--limit",
                "1",
                "--shard",
                f"{index}/2",
            ]
        )
        assert result == 0
    shards = sorted((work_dir / "shards").glob("*.json"))
    assert [shard.name for shard in shards] == [
        "0001-never1.json",
        "0002-never2.json",
    ]


def _real_pipeline_manifest(tmp_path: Path, entry: dict[str, Any]) -> tuple[Path, Path]:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, [entry])
    return manifest_path, wheelhouse


def test_run_writes_a_scanned_shard_with_a_mapped_finding(tmp_path: Path) -> None:
    """A package that imports a removed stdlib module scans to one mapped finding."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    filename, sha256 = _build_wheel(
        wheelhouse, "cgiuser", "1.0.0", {"cgiuser/__init__.py": b"import cgi\n"}
    )
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [_package_entry(rank=1, name="cgiuser", filename=filename, sha256=sha256)],
    )
    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--limit",
            "1",
            "--timeout",
            "60",
        ]
    )
    assert result == 0
    shard_path = work_dir / "shards" / "0001-cgiuser.json"
    document = json.loads(shard_path.read_text(encoding="utf-8"))
    assert document["status"] == "scanned"
    assert document["isolation_mode"] in ("bwrap", "rlimit-only")
    assert document["scan"]["exit_code"] == 0
    assert document["scan"]["high_confidence_findings"] == 1
    (finding,) = document["findings"]
    assert finding["rule_id"] == "CPY0001"
    assert finding["module"] == "cgiuser"
    assert finding["interpreters_needed"]
    # Adjudication always reaches a terminal verdict; the exact one depends on
    # which interpreters happen to be installed on the host running the test.
    assert finding["adjudication_status"] != "pending"
    assert finding["adjudication_status"].split(":")[0] in pypi_validate.CLOSED_VERDICTS
    assert document["adjudication"].keys() == {
        "verdicts",
        "not_adjudicable_reasons",
        "interpreters_used",
        "isolation_mode",
    }
    # The provisioning venv is torn down after each package.
    assert not (work_dir / "tmp").exists() or not list((work_dir / "tmp").iterdir())


def test_run_survives_an_unexpected_failure_past_venv_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed scan report is recorded per-package, not a fatal crash.

    Only `_create_venv` failures were guarded; any later step raising
    `PypiValidateError` (e.g. an unparseable scan report) used to propagate
    out of the per-package loop and abort the rest of the sharded sweep.
    """
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    filename, sha256 = _build_wheel(
        wheelhouse, "cgiuser", "1.0.0", {"cgiuser/__init__.py": b"import cgi\n"}
    )
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [_package_entry(rank=1, name="cgiuser", filename=filename, sha256=sha256)],
    )

    def _broken_scan(*_args: object, **_kwargs: object) -> None:
        message = "scan report exceeded the 64 MiB review limit"
        raise pypi_validate.PypiValidateError(message)

    monkeypatch.setattr(pypi_validate, "_run_scan", _broken_scan)

    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--limit",
            "1",
            "--timeout",
            "60",
        ]
    )
    assert result == 0
    document = json.loads((work_dir / "shards" / "0001-cgiuser.json").read_text())
    assert document["status"] == "scan-failed"
    assert "64 MiB" in document["reason"]


def test_run_skips_a_package_with_no_python_files(tmp_path: Path) -> None:
    """A distribution with only non-.py files never reaches the scanner."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    filename, sha256 = _build_wheel(
        wheelhouse, "dataonly", "1.0.0", {"dataonly/resource.txt": b"data\n"}
    )
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [_package_entry(rank=1, name="dataonly", filename=filename, sha256=sha256)],
    )
    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--limit",
            "1",
            "--timeout",
            "60",
        ]
    )
    assert result == 0
    document = json.loads((work_dir / "shards" / "0001-dataonly.json").read_text())
    assert document["status"] == "skipped"
    assert document["reason"] == "no-python-files"


def test_run_captures_an_install_failure(tmp_path: Path) -> None:
    """A pinned version missing from the offline wheelhouse is `install-failed`."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _build_wheel(wheelhouse, "onlyone", "1.0.0", {"onlyone/__init__.py": b""})
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(
        manifest_path,
        [
            _package_entry(
                rank=1,
                name="onlyone",
                version="9.9.9",
                filename="onlyone-9.9.9-py3-none-any.whl",
                sha256="e" * 64,
            )
        ],
    )
    work_dir = tmp_path / "work"
    result = _run_main(
        [
            "run",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--work-dir",
            str(work_dir),
            "--execute-third-party-code",
            "--limit",
            "1",
            "--timeout",
            "60",
        ]
    )
    assert result == 0
    document = json.loads((work_dir / "shards" / "0001-onlyone.json").read_text())
    assert document["status"] == "install-failed"
    assert document["reason"]
    assert not (work_dir / "tmp").exists() or not list((work_dir / "tmp").iterdir())


def test_run_resumes_by_default_and_reprocesses_with_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing shard is untouched by default, rewritten only with `--refresh`."""
    manifest_path, wheelhouse = _real_pipeline_manifest(
        tmp_path,
        _package_entry(
            rank=1,
            name="tracked",
            filename="tracked-1.0.0-py3-none-any.whl",
            sha256="f" * 64,
        ),
    )
    calls = 0

    def _fake_process_package(
        entry: PackageEntry,
        *,
        installed: Mapping[int, pypi_validate.InstalledInterpreter],  # noqa: ARG001
        options: pypi_validate.RunOptions,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        base = pypi_validate._package_base(
            entry, manifest_sha256=options.manifest_sha256
        )
        return {**base, "status": "skipped", "reason": "test-stub"}

    monkeypatch.setattr(pypi_validate, "_process_package", _fake_process_package)
    work_dir = tmp_path / "work"
    base_argv = [
        "run",
        "--manifest",
        str(manifest_path),
        "--wheelhouse",
        str(wheelhouse),
        "--work-dir",
        str(work_dir),
        "--execute-third-party-code",
        "--limit",
        "1",
    ]

    assert _run_main(base_argv) == 0
    assert calls == 1

    assert _run_main(base_argv) == 0
    assert calls == 1, "an existing shard must not be reprocessed by default"

    assert _run_main([*base_argv, "--refresh"]) == 0
    expected_calls_after_refresh = 2
    assert calls == expected_calls_after_refresh


# --- adjudication: subject/binding descriptor derivation ------------------


def test_stdlib_owner_module_splits_a_plain_function() -> None:
    """A two-level dotted name splits at the (importable) module boundary."""
    assert pypi_validate._stdlib_owner_module("shutil.rmtree") == (
        pypi_validate.SubjectDescriptor("shutil", ("rmtree",))
    )


def test_stdlib_owner_module_splits_a_method_on_a_class() -> None:
    """A class method is not itself importable; the module prefix is shorter."""
    assert pypi_validate._stdlib_owner_module("smtplib.SMTP.starttls") == (
        pypi_validate.SubjectDescriptor("smtplib", ("SMTP", "starttls"))
    )


def _match_evidence(kind: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "confidence": "high", "evidence": evidence}


def test_subject_descriptor_for_module_import_uses_the_imported_module() -> None:
    """The subject is drawn from the finding's own evidence, not the registry."""
    finding = {"match": _match_evidence("module-import", {"imported_module": "cgi"})}
    assert pypi_validate._subject_descriptor(finding) == (
        pypi_validate.SubjectDescriptor("cgi", ())
    )


def test_subject_descriptor_for_a_from_import_includes_the_bound_attribute() -> None:
    """`from A import B` names S as `A.B`, matching the binding probe."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"imported_module": "os", "bound_names": ["path"], "syntax": "from-import"},
        )
    }
    assert pypi_validate._subject_descriptor(finding) == (
        pypi_validate.SubjectDescriptor("os", ("path",))
    )


def test_subject_descriptor_for_call_shape_splits_the_qualified_name() -> None:
    """A call-shape subject resolves through the stdlib module boundary search."""
    finding = {
        "match": _match_evidence("call-shape", {"qualified_names": ["shutil.rmtree"]})
    }
    assert pypi_validate._subject_descriptor(finding) == (
        pypi_validate.SubjectDescriptor("shutil", ("rmtree",))
    )


def test_subject_descriptor_returns_none_for_malformed_evidence() -> None:
    """Missing or malformed evidence fails closed instead of guessing."""
    finding = {"match": _match_evidence("module-import", {})}
    assert pypi_validate._subject_descriptor(finding) is None


def test_subject_descriptor_returns_none_for_an_unsupported_match_kind() -> None:
    """A matcher kind outside the harness's scope is never adjudicated blindly."""
    finding = {"match": _match_evidence("builtin-pattern", {})}
    assert pypi_validate._subject_descriptor(finding) is None


_SUBJECT = pypi_validate.SubjectDescriptor("cgi", ())


def test_binding_target_for_a_plain_import_walks_the_remaining_dots() -> None:
    """`import a.b` binds only "a"; the rest of the dotted path is walked."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["os"], "syntax": "import", "imported_module": "os.path"},
        ),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate.SubjectDescriptor("os.path", ())
    target = pypi_validate._binding_target(finding, subject)
    assert target == pypi_validate.BindingTarget(
        "pkg.mod", None, "os", ("path",), subject
    )


def test_binding_target_for_an_aliased_import_has_no_remaining_attributes() -> None:
    """An alias binds the full target directly; nothing further to walk."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["p"], "syntax": "import", "imported_module": "os.path"},
        ),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate.SubjectDescriptor("os.path", ())
    target = pypi_validate._binding_target(finding, subject)
    assert target is not None
    assert target.head == "p"
    assert target.attribute_path == ()


def test_binding_target_for_a_from_import_binds_the_attribute_directly() -> None:
    """`from A import B` binds B to the attribute value itself, no further walk."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["path"], "syntax": "from-import", "imported_module": "os"},
        ),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate.SubjectDescriptor("os", ("path",))
    target = pypi_validate._binding_target(finding, subject)
    assert target is not None
    assert target.head == "path"
    assert target.attribute_path == ()


def test_subject_descriptor_and_binding_target_agree_for_a_from_import() -> None:
    """The real wiring must not refute a genuine, unshadowed from-import."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["path"], "syntax": "from-import", "imported_module": "os"},
        ),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate._subject_descriptor(finding)
    assert subject == pypi_validate.SubjectDescriptor("os", ("path",))
    target = pypi_validate._binding_target(finding, subject)
    assert target is not None
    assert target.head == "path"
    assert target.attribute_path == ()
    assert target.subject == subject


def test_subject_descriptor_for_an_aliased_from_import_fails_safe() -> None:
    """An aliased from-import must not silently mis-identify S.

    `from cgi import escape as esc` records only the bound name `esc` in
    evidence, never the real attribute `escape`, so `S` here names a
    nonexistent `cgi.esc` attribute. This must resolve to "absent" (and
    thus `not-adjudicable:module-not-importable` downstream), never a false
    identity match against some unrelated object also named `esc`.
    """
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["esc"], "syntax": "from-import", "imported_module": "cgi"},
        ),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate._subject_descriptor(finding)
    assert subject == pypi_validate.SubjectDescriptor("cgi", ("esc",))
    target = pypi_validate._binding_target(finding, subject)
    assert target is not None
    assert target.head == "esc"
    assert target.attribute_path == ()


def test_binding_target_for_call_shape_splits_off_the_head_name() -> None:
    """A call-shape target's head is the qualified name's first dotted component."""
    finding = {
        "match": _match_evidence("call-shape", {"qualified_names": ["shutil.rmtree"]}),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    subject = pypi_validate.SubjectDescriptor("shutil", ("rmtree",))
    target = pypi_validate._binding_target(finding, subject)
    assert target is not None
    assert target.head == "shutil"
    assert target.attribute_path == ("rmtree",)


def test_binding_target_converts_a_nested_enclosing_scope() -> None:
    """A non-module enclosing scope becomes a dotted attribute path."""
    finding = {
        "match": _match_evidence(
            "module-import",
            {"bound_names": ["cgi"], "syntax": "import", "imported_module": "cgi"},
        ),
        "enclosing_scope": "Outer.method",
        "module": "pkg.mod",
    }
    target = pypi_validate._binding_target(finding, _SUBJECT)
    assert target is not None
    assert target.enclosing_scope == ("Outer", "method")


def test_binding_target_returns_none_for_malformed_evidence() -> None:
    """A finding missing the fields its own match kind requires fails closed."""
    finding = {
        "match": _match_evidence("module-import", {"imported_module": "cgi"}),
        "enclosing_scope": "<module>",
        "module": "pkg.mod",
    }
    assert pypi_validate._binding_target(finding, _SUBJECT) is None


# --- adjudication: expected/observed state mapping ------------------------


def _timeline_finding(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {"timeline": events}


_REMOVED_AT_13 = {"event": "removed", "python": "3.13"}
_SIGNATURE_CHANGED_AT_13 = {"event": "signature_changed", "python": "3.13"}
_BEHAVIOR_CHANGED_AT_13 = {"event": "behavior_changed", "python": "3.13"}
_DEPRECATED_AT_12 = {"event": "deprecated", "python": "3.12"}


@pytest.mark.parametrize(
    ("events", "minor", "expected"),
    [
        ([_DEPRECATED_AT_12, _REMOVED_AT_13], 12, "present"),
        ([_DEPRECATED_AT_12, _REMOVED_AT_13], 13, "absent"),
        ([_DEPRECATED_AT_12], 13, "present"),
        # A behavior change never removes S itself - ssl.SSLSession stays a
        # live class after Python starts rejecting its direct construction.
        ([_BEHAVIOR_CHANGED_AT_13], 13, "present"),
        ([_SIGNATURE_CHANGED_AT_13], 13, "present"),
    ],
)
def test_expected_presence_follows_the_removed_event(
    events: list[dict[str, Any]], minor: int, expected: str
) -> None:
    """Presence is expected to flip to absent only for an actual removal."""
    assert (
        pypi_validate._expected_presence(_timeline_finding(events), minor) == expected
    )


@pytest.mark.parametrize(
    ("events", "minor", "expected"),
    [
        ([_SIGNATURE_CHANGED_AT_13], 12, "accepted"),
        ([_SIGNATURE_CHANGED_AT_13], 13, "rejected"),
        ([_REMOVED_AT_13], 13, "rejected"),
        # A behavior change flagged on a specific literal argument
        # (shlex.split(None), webbrowser.get("grail")) still binds at the
        # signature level even once it raises at runtime.
        ([_BEHAVIOR_CHANGED_AT_13], 13, "accepted"),
        ([_DEPRECATED_AT_12], 13, "accepted"),
    ],
)
def test_expected_call_shape_follows_the_signature_changed_event(
    events: list[dict[str, Any]], minor: int, expected: str
) -> None:
    """A call shape is expected to be rejected only for an actual signature change."""
    assert (
        pypi_validate._expected_call_shape(_timeline_finding(events), minor) == expected
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("present", ("present", None)),
        ("absent", ("absent", None)),
        ("import-error", (None, "import-error")),
        ("probe-timeout", (None, "probe-timeout")),
        ("probe-crashed", (None, "probe-crashed")),
        ("something-else", (None, "probe-crashed")),
    ],
)
def test_observed_presence_maps_subject_probe_statuses(
    status: str, expected: tuple[str | None, str | None]
) -> None:
    """Every subject-probe status maps to a closed (observed, reason) pair."""
    assert pypi_validate._observed_presence({"status": status}) == expected


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("accepted", ("accepted", None)),
        ("rejected", ("rejected", None)),
        ("absent", ("rejected", None)),
        ("no-signature", (None, "no-signature")),
        ("import-error", (None, "import-error")),
        ("probe-timeout", (None, "probe-timeout")),
    ],
)
def test_observed_call_shape_maps_call_shape_probe_statuses(
    status: str, expected: tuple[str | None, str | None]
) -> None:
    """A missing subject is treated the same as a rejected call shape."""
    assert pypi_validate._observed_call_shape({"status": status}) == expected


@pytest.mark.parametrize(
    ("result", "expected_verdict"),
    [
        ({"status": "resolved", "identity_match": True}, None),
        ({"status": "resolved", "identity_match": False}, "refuted-binding"),
        (
            {"status": "resolved", "identity_match": None},
            "not-adjudicable:module-not-importable",
        ),
        ({"status": "import-error"}, "not-adjudicable:import-error"),
        ({"status": "binding-not-visible"}, "not-adjudicable:binding-not-visible"),
        ({"status": "probe-timeout"}, "not-adjudicable:probe-timeout"),
        ({"status": "probe-crashed"}, "not-adjudicable:probe-crashed"),
    ],
)
def test_binding_verdict_covers_every_status(
    result: dict[str, Any], expected_verdict: str | None
) -> None:
    """Every binding-probe status maps to exactly one closed-set outcome."""
    verdict, evidence = pypi_validate._binding_verdict(
        result,
        subject=pypi_validate.SubjectDescriptor("cgi", ()),
        action_minor=13,
        impact="breaking",
        reference_minor=13,
    )
    assert verdict == expected_verdict
    assert evidence["status"] == result["status"]


_CGI_NOT_FOUND_ERROR = "ModuleNotFoundError: No module named 'cgi'"


def test_binding_verdict_confirms_a_module_not_found_error_naming_the_subject() -> None:
    """A `ModuleNotFoundError` naming `S` itself is the strongest confirmation."""
    verdict, evidence = pypi_validate._binding_verdict(
        {"status": "import-error", "error": _CGI_NOT_FOUND_ERROR},
        subject=pypi_validate.SubjectDescriptor("cgi", ()),
        action_minor=13,
        impact="breaking",
        reference_minor=13,
    )
    assert verdict == "confirmed"
    assert evidence["confirmation"] == "module-import-end-to-end"


def test_binding_verdict_does_not_confirm_an_unrelated_import_error() -> None:
    """An import failure naming a different module stays a generic import-error."""
    verdict, _ = pypi_validate._binding_verdict(
        {
            "status": "import-error",
            "error": "ModuleNotFoundError: No module named 'some_dependency'",
        },
        subject=pypi_validate.SubjectDescriptor("cgi", ()),
        action_minor=13,
        impact="breaking",
        reference_minor=13,
    )
    assert verdict == "not-adjudicable:import-error"


def test_binding_verdict_does_not_confirm_a_removal_before_its_own_action_version() -> (
    None
):
    """A module missing ahead of its registry-scheduled removal isn't confirmed."""
    verdict, _ = pypi_validate._binding_verdict(
        {"status": "import-error", "error": _CGI_NOT_FOUND_ERROR},
        subject=pypi_validate.SubjectDescriptor("cgi", ()),
        action_minor=14,
        impact="breaking",
        reference_minor=13,
    )
    assert verdict == "not-adjudicable:import-error"


def test_binding_verdict_does_not_confirm_a_deprecation_only_import_error() -> None:
    """A deprecated-not-removed rule never expects `S` to vanish outright."""
    verdict, _ = pypi_validate._binding_verdict(
        {"status": "import-error", "error": _CGI_NOT_FOUND_ERROR},
        subject=pypi_validate.SubjectDescriptor("cgi", ()),
        action_minor=13,
        impact="deprecated",
        reference_minor=13,
    )
    assert verdict == "not-adjudicable:import-error"


# --- probe batch output: closed-schema parsing -----------------------------


def test_parse_probe_batch_output_accepts_a_well_formed_batch() -> None:
    """A closed, well-formed batch parses into one result per probe id."""
    payload = json.dumps(
        {
            "schema_version": 1,
            "results": [
                {
                    "id": "a",
                    "kind": "binding",
                    "status": "resolved",
                    "identity_match": True,
                    "subject_status": "present",
                    "error": None,
                },
                {
                    "id": "b",
                    "kind": "subject",
                    "status": "present",
                    "deprecation_warning": None,
                    "signature": "()",
                    "error": None,
                },
                {"id": "c", "kind": "call-shape", "status": "accepted", "error": None},
            ],
        }
    ).encode()
    results = pypi_validate._parse_probe_batch_output(payload)
    assert set(results) == {"a", "b", "c"}


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 2, "results": []},
        {"results": [{"id": "a", "kind": "binding", "status": "resolved"}]},
        {"schema_version": 1, "results": "not-a-list"},
        {
            "schema_version": 1,
            "results": [{"id": "a", "kind": "not-a-real-kind", "status": "resolved"}],
        },
        {
            "schema_version": 1,
            "results": [{"id": "a", "kind": "binding", "status": None}],
        },
        {
            "schema_version": 1,
            "results": [{"kind": "binding", "status": "resolved"}],
        },
        {
            "schema_version": 1,
            "results": [
                {"id": "a", "kind": "binding", "status": "resolved"},
                {"id": "a", "kind": "binding", "status": "resolved"},
            ],
        },
        # `resolved` is a binding-only status: a subject result claiming it
        # is an impossible kind/status combination, not a well-formed record.
        {
            "schema_version": 1,
            "results": [{"id": "a", "kind": "subject", "status": "resolved"}],
        },
        # `present` is a subject-only status: nonsensical for a call-shape
        # result even though it is a real status string somewhere else.
        {
            "schema_version": 1,
            "results": [{"id": "a", "kind": "call-shape", "status": "present"}],
        },
        # `_run_binding_probe` never pairs a non-null `error` with
        # `identity_match=True` - that combination can only come from a
        # forged or corrupted record, not a well-typed field in isolation.
        {
            "schema_version": 1,
            "results": [
                {
                    "id": "a",
                    "kind": "binding",
                    "status": "resolved",
                    "identity_match": True,
                    "subject_status": "forged",
                    "error": "AttributeError: nope",
                }
            ],
        },
        # `subject_status` is not a free-form string: only the three values
        # `_resolve_subject` can actually return are well-formed here.
        {
            "schema_version": 1,
            "results": [
                {
                    "id": "a",
                    "kind": "binding",
                    "status": "resolved",
                    "identity_match": True,
                    "subject_status": "forged",
                    "error": None,
                }
            ],
        },
        # `subject_status="import-error"` only ever pairs with
        # `identity_match=None` - the subject itself could not be resolved.
        {
            "schema_version": 1,
            "results": [
                {
                    "id": "a",
                    "kind": "binding",
                    "status": "resolved",
                    "identity_match": True,
                    "subject_status": "import-error",
                    "error": None,
                }
            ],
        },
    ],
)
def test_parse_probe_batch_output_fails_closed_on_schema_violations(
    document: dict[str, Any],
) -> None:
    """Target code produces this output, so any schema violation is discarded whole.

    A forged or malformed record must never silently sway adjudication - not
    even the one offending record while trusting its siblings.
    """
    payload = json.dumps(document).encode()
    assert pypi_validate._parse_probe_batch_output(payload) == {}


def test_parse_probe_batch_output_rejects_invalid_json() -> None:
    """Undecodable bytes are the same closed failure as any other malformed batch."""
    assert pypi_validate._parse_probe_batch_output(b"not json") == {}


# --- adjudication: end-to-end verdict assignment over fixture probes ------


def _mapped_finding_fixture(  # noqa: PLR0913 - mirrors the mapped-finding shape under test.
    *,
    fingerprint: str,
    rule_id: str = "CPY0001",
    match_kind: str = "module-import",
    evidence: dict[str, Any],
    module: str = "pkg.mod",
    impact: str = "breaking",
    action_version: str = "3.13",
    timeline: list[dict[str, Any]] | None = None,
    interpreters_needed: list[int],
) -> dict[str, Any]:
    if timeline is None:
        timeline = [
            {
                "event": "removed",
                "python": action_version,
                "certainty": "released",
                "source": "test",
            }
        ]
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "match": _match_evidence(match_kind, evidence),
        "enclosing_scope": "<module>",
        "module": module,
        "impact": impact,
        "action_version": action_version,
        "timeline": timeline,
        "interpreters_needed": interpreters_needed,
        "adjudication_status": "pending",
    }


def _cgi_finding(
    fingerprint: str = "f1",
    **overrides: Any,  # noqa: ANN401 - forwarded kwargs.
) -> dict[str, Any]:
    overrides.setdefault("interpreters_needed", [12, 13])
    return _mapped_finding_fixture(
        fingerprint=fingerprint,
        evidence={
            "bound_names": ["cgi"],
            "syntax": "import",
            "imported_module": "cgi",
        },
        **overrides,
    )


def _binding_result(
    *, identity_match: bool | None, status: str = "resolved"
) -> dict[str, Any]:
    return {
        "status": status,
        "identity_match": identity_match,
        "subject_status": "present" if identity_match is not None else "absent",
    }


class _ProbeRunners(NamedTuple):
    """The two independent probe callbacks one `_adjudicate` call needs."""

    run_binding_probes: Callable[[int, list[dict[str, Any]]], dict[str, dict[str, Any]]]
    run_subject_probes: Callable[[int, list[dict[str, Any]]], dict[str, dict[str, Any]]]


def _make_run_probes(
    *,
    binding_results: dict[str, dict[str, Any]],
    subject_status_by_minor: dict[int, str] | None = None,
    call_shape_status_by_minor: dict[int, str] | None = None,
    probe_counts: dict[int, int] | None = None,
) -> _ProbeRunners:
    """Build stand-in C1/C2 probe callbacks; C1 returns the same result at any minor."""
    subject_status_by_minor = subject_status_by_minor or {}
    call_shape_status_by_minor = call_shape_status_by_minor or {}

    def run_binding_probes(
        _minor: int, probes: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        return {
            probe["id"]: binding_results[probe["id"]]
            for probe in probes
            if probe["id"] in binding_results
        }

    def run_subject_probes(
        minor: int, probes: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        if probe_counts is not None:
            probe_counts[minor] = probe_counts.get(minor, 0) + len(probes)
        results: dict[str, dict[str, Any]] = {}
        for probe in probes:
            if probe["kind"] == "subject":
                status = subject_status_by_minor.get(minor, "present")
                results[probe["id"]] = {
                    "status": status,
                    "deprecation_warning": None,
                    "signature": None,
                    "error": None,
                }
            elif probe["kind"] == "call-shape":
                status = call_shape_status_by_minor.get(minor, "accepted")
                results[probe["id"]] = {"status": status, "error": None}
        return results

    return _ProbeRunners(run_binding_probes, run_subject_probes)


def test_adjudicate_confirms_a_finding_whose_timeline_matches_reality() -> None:
    """C1 holds and every needed interpreter matches the registry's timeline."""
    finding = _cgi_finding()
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
        subject_status_by_minor={12: "present", 13: "absent"},
    )
    findings, interpreters_used = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "confirmed"
    assert result["adjudication_evidence"]["timeline"]["observed"] == {
        12: "present",
        13: "absent",
    }
    assert interpreters_used == frozenset({12, 13})


def test_adjudicate_refutes_binding_when_identity_does_not_match() -> None:
    """A vendored/shadowed name never reaches C2 at all."""
    finding = _cgi_finding()
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=False)},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "refuted-binding"


def test_adjudicate_catches_a_version_gated_fallback_at_a_non_reference_minor() -> None:
    """A finding that binds correctly at the reference but not at another needed minor.

    `if sys.version_info >= (3, 12): NEW() else: OLD()` binds `S` at the
    reference interpreter (3.11, say) but binds something else entirely
    once actually run under 3.12 - the exact interpreter the finding's own
    timeline claims the code breaks at. A reference-only C1 check can never
    see this: it must also cross-check the finding's own
    `interpreters_needed` pair, when that minor's own venv is available.
    """
    reference_minor = 13
    finding = _cgi_finding(interpreters_needed=[12, reference_minor])

    def run_binding_probes(
        minor: int, _probes: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        # Holds at the reference; a different object is bound at 12, the
        # other interpreter this finding needs.
        return {"f1": _binding_result(identity_match=(minor == reference_minor))}

    runners = _make_run_probes(binding_results={})
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "refuted-binding"


def test_adjudicate_ignores_an_inconclusive_extra_binding_check() -> None:
    """An unavailable extra-minor probe never blocks an otherwise-confirmed C1.

    The reference check is already sufficient on its own; the cross-check
    at other needed minors is a bonus catch, not a new requirement - a host
    where the extra minor's venv never installed must still be able to
    confirm findings via the reference alone.
    """
    finding = _cgi_finding(interpreters_needed=[12, 13])
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
        subject_status_by_minor={12: "present", 13: "absent"},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        # The extra minor (12) has no available binding venv at all.
        available_binding_minors=frozenset({13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "confirmed"


def test_adjudicate_refutes_timeline_when_the_registry_disagrees() -> None:
    """A subject the registry claims is removed, but is actually still present."""
    finding = _cgi_finding()
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
        subject_status_by_minor={12: "present", 13: "present"},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "refuted-timeline"
    assert result["adjudication_evidence"]["timeline"] == {
        "rule_id": "CPY0001",
        "interpreter": 13,
        "observed": "present",
        "deprecation_warnings": {},
    }


def test_adjudicate_confirms_a_behavior_change_that_never_removes_the_subject() -> None:
    """A `behavior_changed` rule (ssl.SSLSession-style) never expects S to vanish.

    CPY0076 flags direct `ssl.SSLSession()` construction, which starts
    raising in 3.12 - but the class itself stays a live attribute of `ssl`
    forever. Expecting "absent" from `impact == "breaking"` alone would
    misread that live class as a registry defect.
    """
    finding = _mapped_finding_fixture(
        fingerprint="f1",
        match_kind="qualified-call",
        evidence={"qualified_names": ["ssl.SSLSession"]},
        action_version="3.12",
        timeline=[
            {
                "event": "behavior_changed",
                "python": "3.12",
                "certainty": "released",
                "source": "test",
            }
        ],
        interpreters_needed=[11, 12],
    )
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
        subject_status_by_minor={11: "present", 12: "present"},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(11, 12),
        reference_minor=12,
        available_binding_minors=frozenset({11, 12}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "confirmed"


def test_adjudicate_confirms_a_behavior_change_call_shape_that_still_binds() -> None:
    """A `behavior_changed` call-shape rule (shlex.split(None)-style) still binds.

    CPY0075 flags `shlex.split(None)`, which starts raising *inside* the
    function body in 3.12 - the call still binds fine at the
    `inspect.signature(...).bind_partial` level, since `split`'s formal
    parameters never change. Expecting "rejected" from `impact ==
    "breaking"` alone would misread that as a registry defect.
    """
    finding = _mapped_finding_fixture(
        fingerprint="f1",
        match_kind="call-shape",
        evidence={
            "qualified_names": ["shlex.split"],
            "positional_count": "1",
            "keyword_names": [],
        },
        action_version="3.12",
        timeline=[
            {
                "event": "behavior_changed",
                "python": "3.12",
                "certainty": "released",
                "source": "test",
            }
        ],
        interpreters_needed=[11, 12],
    )
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
        call_shape_status_by_minor={11: "accepted", 12: "accepted"},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(11, 12),
        reference_minor=12,
        available_binding_minors=frozenset({11, 12}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "confirmed"


def test_adjudicate_retains_deprecation_warnings_for_manual_triage() -> None:
    """A captured `DeprecationWarning` survives into the timeline evidence.

    C2 does not gate on it (see docs/pypi-validation.md's "Deprecation
    onset" limitation), but it must still reach the shard for triage.
    """
    finding = _cgi_finding(
        impact="deprecated",
        timeline=[
            {
                "event": "deprecated",
                "python": "3.13",
                "certainty": "released",
                "source": "test",
            }
        ],
    )
    warns_at_minor = pypi_validate._action_version_minor(finding["action_version"])

    def run_binding_probes(
        _minor: int, _probes: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        return {"f1": _binding_result(identity_match=True)}

    def run_subject_probes(
        minor: int, probes: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        return {
            probe["id"]: {
                "status": "present",
                "deprecation_warning": (
                    f"deprecated as of 3.{minor}" if minor == warns_at_minor else None
                ),
                "signature": None,
                "error": None,
            }
            for probe in probes
        }

    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=run_binding_probes,
        run_subject_probes=run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "confirmed"
    assert result["adjudication_evidence"]["timeline"]["deprecation_warnings"] == {
        13: "deprecated as of 3.13",
    }


def test_adjudicate_marks_an_unsupported_match_kind_module_not_importable() -> None:
    """A finding this harness cannot build a probe for still gets a terminal verdict."""
    finding = _mapped_finding_fixture(
        fingerprint="f1",
        match_kind="builtin-pattern",
        evidence={},
        interpreters_needed=[13],
    )
    runners = _make_run_probes(binding_results={})
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(13),
        reference_minor=13,
        available_binding_minors=frozenset({13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "not-adjudicable:module-not-importable"


def test_adjudicate_marks_a_missing_binding_result_probe_crashed() -> None:
    """A binding batch that never answers a probe id fails closed, not silently."""
    finding = _cgi_finding()
    runners = _make_run_probes(binding_results={})
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "not-adjudicable:probe-crashed"


def test_adjudicate_marks_a_needed_interpreter_that_is_not_installed() -> None:
    """A finding needing an interpreter the host never installed cannot reach C2."""
    finding = _cgi_finding(interpreters_needed=[12, 14])
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(12, 13),
        reference_minor=13,
        available_binding_minors=frozenset({12, 13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "not-adjudicable:no-interpreter"


def test_adjudicate_marks_a_call_shape_finding_missing_shape_no_signature() -> None:
    """A call-shape finding without positional_count/keyword_names can't be probed."""
    finding = _mapped_finding_fixture(
        fingerprint="f1",
        match_kind="call-shape",
        evidence={"qualified_names": ["shutil.rmtree"]},
        interpreters_needed=[13],
    )
    runners = _make_run_probes(
        binding_results={"f1": _binding_result(identity_match=True)},
    )
    findings, _ = pypi_validate._adjudicate(
        [finding],
        installed=_installed(13),
        reference_minor=13,
        available_binding_minors=frozenset({13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    (result,) = findings
    assert result["adjudication_status"] == "not-adjudicable:no-signature"


def test_adjudicate_caches_c2_subject_probes_per_rule_and_interpreter() -> None:
    """Two findings sharing a rule and interpreter cross-check C2 only once."""
    first = _cgi_finding(fingerprint="f1", interpreters_needed=[13])
    second = _cgi_finding(fingerprint="f2", interpreters_needed=[13])
    probe_counts: dict[int, int] = {}
    runners = _make_run_probes(
        binding_results={
            "f1": _binding_result(identity_match=True),
            "f2": _binding_result(identity_match=True),
        },
        subject_status_by_minor={13: "absent"},
        probe_counts=probe_counts,
    )
    findings, _ = pypi_validate._adjudicate(
        [first, second],
        installed=_installed(13),
        reference_minor=13,
        available_binding_minors=frozenset({13}),
        run_binding_probes=runners.run_binding_probes,
        run_subject_probes=runners.run_subject_probes,
    )
    assert [finding["adjudication_status"] for finding in findings] == [
        "confirmed",
        "confirmed",
    ]
    assert probe_counts == {13: 1}
