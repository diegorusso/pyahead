"""Processing one package end to end and writing its shard."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scripts._common import normalized_name as _normalized_name

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from scripts.pypi_corpus import PackageEntry

from scripts.pypi_validate._adjudication import (
    _adjudicate,
    _adjudication_summary,
    _run_bare_probe_batch,
    _run_binding_probe_batch,
)
from scripts.pypi_validate._import_sites import import_sites
from scripts.pypi_validate._interpreters import _reference_candidates
from scripts.pypi_validate._model import _VENV_TIMEOUT_SECONDS, PypiValidateError
from scripts.pypi_validate._provision import (
    BindingVenv,
    _create_venv,
    _install_distribution,
    _provision_binding_venv,
    _site_packages_dir,
)
from scripts.pypi_validate._record import (
    _distribution_info_dir,
    _include_patterns,
    _owned_python_files,
)
from scripts.pypi_validate._scan import _mapped_finding, _run_scan

if TYPE_CHECKING:
    from scripts.pypi_validate._model import InstalledInterpreter, RunOptions


def _package_base(entry: PackageEntry, *, manifest_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "manifest_sha256": manifest_sha256,
        "package": {
            "rank": entry.rank,
            "name": entry.name,
            "version": entry.version,
            "filename": entry.filename,
            "sha256": entry.sha256,
            "requires_python": entry.requires_python,
            "is_wheel": entry.is_wheel,
        },
    }


def _provision_binding_venvs(  # noqa: PLR0913 - one venv input per provisioning input.
    entry: PackageEntry,
    *,
    findings: list[dict[str, Any]],
    reference_minor: int,
    reference_venv: BindingVenv,
    installed: Mapping[int, InstalledInterpreter],
    package_dir: Path,
    options: RunOptions,
) -> dict[int, BindingVenv]:
    """Provision one C1 venv per interpreter minor any finding actually needs.

    A version-gated fallback binds a different object at different
    interpreters, so C1 must be checked under every interpreter a finding
    needs, each with the distribution genuinely installed - not only under
    whichever interpreter happened to scan the package. The reference venv
    is reused for its own minor rather than installed twice.
    """
    binding_venvs: dict[int, BindingVenv] = {reference_minor: reference_venv}
    extra_minors = sorted(
        {minor for finding in findings for minor in finding["interpreters_needed"]}
        - {reference_minor}
    )
    for minor in extra_minors:
        candidate = installed.get(minor)
        if candidate is None:
            continue
        provisioned = _provision_binding_venv(
            entry,
            python_path=candidate.path,
            package_dir=package_dir,
            label=str(minor),
            options=options,
        )
        if provisioned is not None:
            binding_venvs[minor] = provisioned
    return binding_venvs


@dataclass(frozen=True)
class _InstalledUnder:
    """Where a package finally installed, and every candidate it did not."""

    reference: InstalledInterpreter | None
    site_packages: Path | None
    isolation_mode: str | None
    error: str | None
    fallback: list[dict[str, str | int]]


def _install_under_first_candidate(
    entry: PackageEntry,
    candidates: tuple[InstalledInterpreter, ...],
    *,
    package_dir: Path,
    options: RunOptions,
) -> _InstalledUnder:
    """Try each candidate reference, lowest first, until the package installs.

    Each candidate the package would not install under is recorded with its
    reason, so a reference above the declared floor is explained in the shard
    rather than silent.
    """
    venv_dir = package_dir / "venv"
    scratch_home = package_dir / "home"
    fallback: list[dict[str, str | int]] = []
    isolation_mode: str | None = None
    install_error: str | None = None
    for candidate in candidates:
        if package_dir.exists():
            shutil.rmtree(package_dir)
        package_dir.mkdir(parents=True, exist_ok=True)
        scratch_home.mkdir(parents=True, exist_ok=True)
        try:
            _create_venv(
                options.uv, candidate.path, venv_dir, timeout=_VENV_TIMEOUT_SECONDS
            )
        except (PypiValidateError, subprocess.TimeoutExpired) as error:
            install_error = str(error)
            isolation_mode = None
        else:
            # Resolved from the bare venv, before any third-party code is
            # installed into it: querying it after install would run the just
            # installed distribution's `.pth`/`sitecustomize.py` startup code
            # outside the bwrap/rlimit isolation that `_install_distribution`
            # and the probes use.
            site_packages = _site_packages_dir(
                venv_dir / "bin" / "python", timeout=options.timeout
            )
            isolation_mode, install_error = _install_distribution(
                entry, venv_dir=venv_dir, scratch_home=scratch_home, options=options
            )
            if install_error is None:
                return _InstalledUnder(
                    candidate, site_packages, isolation_mode, None, fallback
                )
        fallback.append(
            {
                "minor": candidate.minor,
                "version": candidate.version,
                "reason": install_error,
            }
        )
    return _InstalledUnder(None, None, isolation_mode, install_error, fallback)


def _process_package(  # noqa: C901 - one early return per closed shard status.
    entry: PackageEntry,
    *,
    installed: Mapping[int, InstalledInterpreter],
    options: RunOptions,
) -> dict[str, Any]:
    base = _package_base(entry, manifest_sha256=options.manifest_sha256)
    candidates = _reference_candidates(
        entry.requires_python,
        installed,
        baseline_minor=options.baseline_minor,
        horizon_minor=options.horizon_minor,
        filename=entry.filename,
        is_wheel=entry.is_wheel,
    )
    if not candidates:
        return {
            **base,
            "status": "skipped",
            "reason": "no-compatible-interpreter",
            "isolation_mode": None,
            "interpreter": None,
        }

    package_dir = options.work_dir / "tmp" / f"{entry.rank:04d}"
    venv_dir = package_dir / "venv"
    scratch_home = package_dir / "home"
    try:
        installed_under = _install_under_first_candidate(
            entry, candidates, package_dir=package_dir, options=options
        )
        reference = installed_under.reference
        site_packages = installed_under.site_packages
        isolation_mode = installed_under.isolation_mode
        install_error = installed_under.error
        fallback = installed_under.fallback

        if reference is None or site_packages is None:
            last = candidates[-1]
            return {
                **base,
                "status": "install-failed",
                "reason": install_error or "install failed under every candidate",
                "isolation_mode": isolation_mode,
                "interpreter": {
                    "reference_minor": last.minor,
                    "reference_version": last.version,
                    "reference_fallback": fallback,
                },
            }

        interpreter_info: dict[str, Any] = {
            "reference_minor": reference.minor,
            "reference_version": reference.version,
        }
        if fallback:
            interpreter_info["reference_fallback"] = fallback

        dist_info = _distribution_info_dir(
            site_packages, normalized_name=_normalized_name(entry.name)
        )
        owned = _owned_python_files(dist_info)
        if not owned:
            return {
                **base,
                "status": "skipped",
                "reason": "no-python-files",
                "isolation_mode": isolation_mode,
                "interpreter": interpreter_info,
            }

        scan = _run_scan(
            site_packages,
            include_patterns=_include_patterns(owned),
            baseline_minor=reference.minor,
            horizon_minor=options.horizon_minor,
            timeout=options.timeout,
        )
        if scan.error is not None:
            return {
                **base,
                "status": "scan-failed",
                "reason": scan.error,
                "isolation_mode": isolation_mode,
                "interpreter": interpreter_info,
            }

        findings = [
            _mapped_finding(
                finding,
                baseline_minor=options.baseline_minor,
                horizon_minor=options.horizon_minor,
            )
            for finding in scan.findings
        ]

        binding_venvs = _provision_binding_venvs(
            entry,
            findings=findings,
            reference_minor=reference.minor,
            reference_venv=BindingVenv(venv_dir=venv_dir, scratch_home=scratch_home),
            installed=installed,
            package_dir=package_dir,
            options=options,
        )

        # `None` until a probe batch actually runs: a package with nothing to
        # probe must not claim the unsandboxed `rlimit-only` fallback ran.
        probe_isolation_mode: str | None = None

        def _run_binding_probes(
            minor: int, probes: list[dict[str, Any]]
        ) -> dict[str, dict[str, Any]]:
            nonlocal probe_isolation_mode
            binding_venv = binding_venvs.get(minor)
            if binding_venv is None:
                return {}
            results, mode = _run_binding_probe_batch(
                probes,
                venv_dir=binding_venv.venv_dir,
                scratch_home=binding_venv.scratch_home,
                options=options,
            )
            probe_isolation_mode = mode
            return results

        def _run_subject_probes(
            minor: int, probes: list[dict[str, Any]]
        ) -> dict[str, dict[str, Any]]:
            nonlocal probe_isolation_mode
            candidate = installed.get(minor)
            if candidate is None:
                return {}
            results, mode = _run_bare_probe_batch(
                candidate.path,
                probes,
                timeout=options.timeout,
                scratch_home=scratch_home,
                options=options,
            )
            probe_isolation_mode = mode
            return results

        findings, interpreters_used = _adjudicate(
            findings,
            installed=installed,
            reference_minor=reference.minor,
            available_binding_minors=frozenset(binding_venvs),
            run_binding_probes=_run_binding_probes,
            run_subject_probes=_run_subject_probes,
            import_sites=import_sites(findings, site_packages),
        )
        adjudication = _adjudication_summary(
            findings, interpreters_used=interpreters_used
        )
        adjudication["isolation_mode"] = probe_isolation_mode

        return {
            **base,
            "status": "scanned",
            "reason": None,
            "isolation_mode": isolation_mode,
            "interpreter": interpreter_info,
            "scan": {
                "exit_code": scan.exit_code,
                "duration_seconds": round(scan.duration_seconds, 6),
                "high_confidence_findings": len(findings),
            },
            "findings": findings,
            "adjudication": adjudication,
        }
    except (PypiValidateError, subprocess.TimeoutExpired) as error:
        # An unexpected failure anywhere past venv creation (a malformed scan
        # report, a hung site-packages query, ...) must not abort the whole
        # sharded sweep: record it against this one package and move on.
        return {
            **base,
            "status": "scan-failed",
            "reason": str(error),
            "isolation_mode": isolation_mode,
            "interpreter": interpreter_info,
        }
    finally:
        shutil.rmtree(package_dir, ignore_errors=True)
