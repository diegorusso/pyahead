"""Golden dependency-status contract independent of resolver diagnostic text."""

import json
from pathlib import Path, PurePosixPath
from typing import cast

from jsonschema import Draft202012Validator
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

import pyahead.dependencies as dependency_module
from pyahead.dependencies import (
    ArtifactAvailability,
    DependencyAssessment,
    DependencyCompatibilityStatus,
    DependencyProjectKind,
    DependencyReport,
    EnvironmentTarget,
    EvaluatedRequirement,
    MetadataArtifact,
    MetadataKind,
    RequiresPythonStatus,
    ResolutionStatus,
    ResolvedPackage,
    ResolverResult,
    TargetDependencyResult,
    dependency_report_document,
)

ROOT = Path(__file__).parents[2]
MATRIX_PATH = Path(__file__).with_name("dependency-status-matrix.json")
SCHEMA_PATH = ROOT / "docs/schema/dependency-report-v1.json"
ARTIFACT_ID = "a" * 64
ALTERNATIVE_ARTIFACT_ID = "b" * 64
REVIEWED_UV_VERSION = "0.11.21"
EXPECTED_SCENARIOS = (
    "closed-exact-pin-inventory",
    "closed-missing-package",
    "closed-missing-version",
    "closed-wrong-target-wheel",
    "direct-application-matching-wheel",
    "direct-application-sdist-only",
    "direct-application-wrong-target-wheel",
    "direct-final-requires-python-exclusion",
    "genuine-constraint-contradiction",
    "library-sample",
    "online-index-failure",
    "resolver-timeout",
    "successful-alternative-selection",
    "unknown-uv-diagnostic-grammar",
)


def _target() -> EnvironmentTarget:
    return EnvironmentTarget(
        name="cp312-linux",
        python_full_version="3.12.4",
        implementation_name="cpython",
        implementation_version="3.12.4",
        os_name="posix",
        sys_platform="linux",
        platform_machine="x86_64",
        platform_python_implementation="CPython",
        platform_system="Linux",
        platform_release="",
        platform_version="",
        compatible_tags=("py3-none-any",),
        resolver_platform="x86_64-manylinux_2_17",
    )


def _metadata(
    availability: str | None,
    *,
    version: str = "1.0",
    artifact_id: str = ARTIFACT_ID,
) -> MetadataArtifact:
    is_sdist = availability == ArtifactAvailability.SOURCE_BUILD_POSSIBLE.value
    is_wrong_target = availability == ArtifactAvailability.UNAVAILABLE.value
    wheel_name = (
        f"demo-{version}-cp311-cp311-win_amd64.whl"
        if is_wrong_target
        else f"demo-{version}-py3-none-any.whl"
    )
    return MetadataArtifact(
        artifact_id=artifact_id,
        path=PurePosixPath(f"demo-{version}.tar.gz" if is_sdist else wheel_name),
        kind=MetadataKind.SDIST if is_sdist else MetadataKind.WHEEL,
        name="demo",
        canonical_name="demo",
        version=version,
        metadata_version="2.4",
        requires_python=">=3.12",
        requires_dist=(),
        provides_extra=(),
        dynamic=(),
        wheel_tags=(
            ()
            if is_sdist
            else ("cp311-cp311-win_amd64",)
            if is_wrong_target
            else ("py3-none-any",)
        ),
        metadata_path=(
            f"demo-{version}/PKG-INFO"
            if is_sdist
            else f"demo-{version}.dist-info/METADATA"
        ),
        sha256=artifact_id,
    )


def _assessment(
    row: dict[str, object],
    *,
    version: str = "1.0",
    artifact_id: str = ARTIFACT_ID,
) -> tuple[DependencyAssessment, ...]:
    raw_status = row["assessment_status"]
    if raw_status is None:
        return ()
    availability = ArtifactAvailability(cast("str", row["artifact_availability"]))
    return (
        DependencyAssessment(
            package="demo",
            version=version,
            status=DependencyCompatibilityStatus(cast("str", raw_status)),
            requires_python_status=RequiresPythonStatus(
                cast("str", row["requires_python_status"])
            ),
            artifact_availability=availability,
            source_build_possible=(
                availability is ArtifactAvailability.SOURCE_BUILD_POSSIBLE
            ),
            metadata_used=(artifact_id,),
            applicable_requirements=(),
            reason="golden dependency-status scenario",
        ),
    )


def _report(row: dict[str, object]) -> DependencyReport:
    resolution_status = ResolutionStatus(cast("str", row["resolution_status"]))
    complete = cast("bool", row["resolution_complete"])
    network = cast("bool", row["network"])
    requirement = cast("str", row["requirement"])
    succeeded = resolution_status is ResolutionStatus.SUCCEEDED
    alternative_selection = row["name"] == "successful-alternative-selection"
    selected_artifact_id = (
        ALTERNATIVE_ARTIFACT_ID if alternative_selection else ARTIFACT_ID
    )
    selected_version = "2.0" if alternative_selection else "1.0"
    assessments = _assessment(
        row,
        version=selected_version,
        artifact_id=selected_artifact_id,
    )
    metadata = (
        _metadata(cast("str | None", row["artifact_availability"])),
        *(
            (
                _metadata(
                    ArtifactAvailability.AVAILABLE.value,
                    version=selected_version,
                    artifact_id=selected_artifact_id,
                ),
            )
            if alternative_selection
            else ()
        ),
    )
    matching_metadata = (selected_artifact_id,) if assessments else ()
    resolution_arguments = {
        "status": resolution_status,
        "complete": complete,
        "resolver": "uv",
        "resolver_version": (
            None
            if resolution_status is ResolutionStatus.NOT_REQUESTED
            else REVIEWED_UV_VERSION
        ),
        "packages": (
            (
                ResolvedPackage(
                    name="demo",
                    version=selected_version,
                    metadata_used=(selected_artifact_id,),
                ),
            )
            if succeeded
            else ()
        ),
        "reason": "golden dependency-status scenario",
    }
    if resolution_status in {
        ResolutionStatus.ARTIFACT_UNAVAILABLE,
        ResolutionStatus.RESOLUTION_FAILED,
    }:
        resolution = dependency_module._UvResolverResult(  # noqa: SLF001
            **resolution_arguments,
            verified_failure_names=(canonicalize_name(Requirement(requirement).name),),
            verified_failure_requirements=(str(Requirement(requirement)),),
            verified_artifact_snapshots=(
                dependency_module._metadata_artifact_snapshots(metadata)  # noqa: SLF001
            ),
            verified_target_snapshot=dependency_module._target_snapshot(  # noqa: SLF001
                _target()
            ),
        )
    else:
        resolution = ResolverResult(**resolution_arguments)
    declared = EvaluatedRequirement(
        requirement=requirement,
        applies=True,
        matching_extras=("base",),
        matching_metadata=matching_metadata,
        resolved_versions=((f"demo=={selected_version}",) if succeeded else ()),
        verified=True,
        reason="golden dependency-status scenario",
    )
    return DependencyReport(
        schema_version=1,
        project_kind=DependencyProjectKind(cast("str", row["project_kind"])),
        resolve=resolution_status is not ResolutionStatus.NOT_REQUESTED,
        network=network,
        timeout_seconds=30.0,
        resolver="uv",
        index_url="https://packages.example/simple" if network else None,
        requirements=(requirement,),
        extras=(),
        metadata=metadata,
        metadata_issues=(),
        targets=(
            TargetDependencyResult(
                target=_target(),
                declared_requirements=(declared,),
                transitive_requirements=(),
                assessments=assessments,
                resolution=resolution,
            ),
        ),
    )


def _projection(row: dict[str, object], report: DependencyReport) -> dict[str, object]:
    assessment = report.targets[0].assessments
    return {
        "artifact_availability": (
            assessment[0].artifact_availability.value if assessment else None
        ),
        "assessment_status": assessment[0].status.value if assessment else None,
        "exit_code": int(report.exit_code),
        "name": row["name"],
        "network": report.network,
        "project_kind": report.project_kind.value,
        "requirement": report.requirements[0],
        "requires_python_status": (
            assessment[0].requires_python_status.value if assessment else None
        ),
        "resolution_complete": report.targets[0].resolution.complete,
        "resolution_status": report.targets[0].resolution.status.value,
    }


def test_dependency_status_matrix_is_canonical_and_schema_valid() -> None:
    """Every semantic scenario has stable status, completeness, and exit evidence."""
    matrix_text = MATRIX_PATH.read_text(encoding="utf-8")
    matrix = cast("dict[str, object]", json.loads(matrix_text))
    assert matrix_text == json.dumps(matrix, indent=2, sort_keys=True) + "\n"
    assert matrix["schema_version"] == 1
    scenarios = cast("list[dict[str, object]]", matrix["scenarios"])
    names = [cast("str", row["name"]) for row in scenarios]
    assert names == list(EXPECTED_SCENARIOS)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for row in scenarios:
        report = _report(row)
        validator.validate(dependency_report_document(report))
        assert _projection(row, report) == row
