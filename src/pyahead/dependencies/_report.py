"""Collecting, validating and rendering dependency reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Protocol,
)

from packaging.requirements import Requirement
from packaging.utils import (
    canonicalize_name,
)
from packaging.version import InvalidVersion, Version

from pyahead._human_text import escape_terminal_text
from pyahead.model import ExitCode

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
from pyahead.dependencies._artifacts import _validate_metadata_artifacts
from pyahead.dependencies._assessment import (
    _assess_declared_dependency_metadata,
    _assessment_with_closure,
    _evaluate_requirement,
    _requirement_accepts_version,
    _resolution_evidence_artifacts,
    _target_semantic_artifacts,
    assess_dependency_metadata,
)
from pyahead.dependencies._config import (
    _ensure_marker_evaluation_budget,
    _ensure_target_coherence,
    _parse_requirements,
    _resolved_dependency_root,
    _validate_dependency_configuration,
)
from pyahead.dependencies._metadata import inspect_dependency_metadata
from pyahead.dependencies._model import (
    DependencyCompatibilityStatus,
    DependencyConfiguration,
    DependencyProjectKind,
    ResolutionStatus,
    ResolverResult,
    _error,
    _failure_requirement_identities,
    _metadata_artifact_document,
    _metadata_artifact_snapshots,
    _verified_failure_artifact_snapshots,
    _verified_failure_names,
    _verified_failure_requirements,
    _verified_failure_target_snapshot,
    _with_marker_evaluation_budget,
)
from pyahead.dependencies._resolution import (
    _conflicting_requirement_names,
    _correlate_declared_requirements,
    _offline_artifact_unavailability,
    _resolver_unverified,
    _ResolverValidationContext,
    _target_document,
    _target_snapshot,
    _transitive_requirement_evidence,
    _validated_resolver_closure,
    _validated_resolver_result,
)
from pyahead.dependencies._uv import UvResolverAdapter

if TYPE_CHECKING:
    from pyahead.dependencies._model import (
        DependencyAssessment,
        EnvironmentTarget,
        EvaluatedRequirement,
        JsonValue,
        MetadataArtifact,
        MetadataIssue,
        TransitiveRequirementEvidence,
        _ClosedArtifactUnavailability,
    )


class ResolverAdapter(Protocol):
    """Replaceable dependency resolver boundary."""

    name: str

    def resolve(
        self,
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        """Resolve one explicitly declared environment target."""
        ...


@dataclass(frozen=True)
class TargetDependencyResult:
    """Metadata and resolver evidence for one environment target."""

    target: EnvironmentTarget
    declared_requirements: tuple[EvaluatedRequirement, ...]
    transitive_requirements: tuple[TransitiveRequirementEvidence, ...]
    assessments: tuple[DependencyAssessment, ...]
    resolution: ResolverResult


@dataclass(frozen=True)
class DependencyReport:
    """Deterministic dependency report independent from the static finding gate."""

    schema_version: int
    project_kind: DependencyProjectKind
    resolve: bool
    network: bool
    timeout_seconds: float
    resolver: str
    index_url: str | None
    requirements: tuple[str, ...]
    extras: tuple[str, ...]
    metadata: tuple[MetadataArtifact, ...]
    metadata_issues: tuple[MetadataIssue, ...]
    targets: tuple[TargetDependencyResult, ...]

    @property
    def exit_code(self) -> ExitCode:
        """Map compatibility and incomplete evidence to stable CLI outcomes."""
        incomplete = bool(self.metadata_issues)
        incompatible = False
        for result in self.targets:
            incomplete = incomplete or not result.resolution.complete
            incomplete = incomplete or any(
                item.applies and not item.verified
                for item in result.declared_requirements
            )
            incomplete = incomplete or any(
                not item.verified for item in result.transitive_requirements
            )
            incomplete = incomplete or result.resolution.status in {
                ResolutionStatus.TIMED_OUT,
                ResolutionStatus.UNVERIFIED,
            }
            incompatible = incompatible or result.resolution.status in {
                ResolutionStatus.ARTIFACT_UNAVAILABLE,
                ResolutionStatus.RESOLUTION_FAILED,
            }
            for assessment in result.assessments:
                incomplete = incomplete or assessment.status is (
                    DependencyCompatibilityStatus.UNVERIFIED
                )
                incompatible = incompatible or assessment.status in {
                    DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE,
                    DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE,
                }
        if incomplete:
            return ExitCode.INCOMPLETE
        if incompatible:
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS


@_with_marker_evaluation_budget
def collect_dependency_report(
    configuration: DependencyConfiguration,
    *,
    root: Path,
    resolver: ResolverAdapter | None = None,
) -> DependencyReport:
    """Collect deterministic direct metadata and optional resolver evidence."""
    configuration = _validate_dependency_configuration(configuration)
    resolved_root = _resolved_dependency_root(root)
    artifacts, issues = inspect_dependency_metadata(
        configuration.metadata_paths, root=resolved_root
    )
    _ensure_marker_evaluation_budget(
        (
            (configuration.requirements, 2 if configuration.resolve else 1),
            (
                tuple(
                    requirement
                    for artifact in artifacts
                    for requirement in artifact.requires_dist
                ),
                1,
            ),
        ),
        extras=configuration.extras,
        target_count=len(configuration.targets),
        label="dependency collection",
    )
    if resolver is None:
        adapter: ResolverAdapter = UvResolverAdapter()
        built_in_uv_evidence = True
    else:
        adapter = resolver
        built_in_uv_evidence = False
    targets: list[TargetDependencyResult] = []
    for target in configuration.targets:
        _ensure_target_coherence(target, label="dependency target")
        declared = tuple(
            _evaluate_requirement(value, target, configuration.extras)
            for value in configuration.requirements
        )
        if not configuration.resolve:
            expected_resolver = configuration.resolver
            resolution = ResolverResult(
                status=ResolutionStatus.NOT_REQUESTED,
                complete=True,
                resolver="uv",
                resolver_version=None,
                packages=(),
                reason="resolver was not requested",
            )
        elif issues:
            expected_resolver = configuration.resolver
            resolution = _resolver_unverified(
                "resolver was not executed because configured metadata evidence "
                "is incomplete"
            )
        else:
            expected_resolver = adapter.name
            resolution = adapter.resolve(
                configuration,
                target,
                artifacts,
                root=resolved_root,
            )
        resolution = _validated_resolver_result(
            resolution,
            _ResolverValidationContext(
                artifacts=artifacts,
                declared=declared,
                configuration=configuration,
                target=target,
                expected_resolver=expected_resolver,
                built_in_uv_evidence=built_in_uv_evidence,
            ),
        )
        evidence_resolution = resolution
        if declared:
            assessments = _assess_declared_dependency_metadata(
                artifacts,
                target=target,
                configuration=configuration,
                declared=declared,
                resolution=resolution,
            )
        else:
            assessments = assess_dependency_metadata(
                artifacts,
                target=target,
                extras=configuration.extras,
            )
        resolution = _validated_resolver_closure(
            resolution,
            assessments,
            artifacts,
        )
        if resolution is not evidence_resolution:
            assessments = tuple(
                _assessment_with_closure(assessment, closure_proven=False)
                for assessment in assessments
            )
        selected_evidence = _target_semantic_artifacts(
            _resolution_evidence_artifacts(
                artifacts,
                evidence_resolution,
            ),
            target,
        )
        correlated_declared = _correlate_declared_requirements(
            declared,
            selected_evidence,
            resolution,
            configuration.project_kind,
        )
        targets.append(
            TargetDependencyResult(
                target=target,
                declared_requirements=correlated_declared,
                transitive_requirements=_transitive_requirement_evidence(
                    configuration.project_kind,
                    assessments,
                    correlated_declared,
                    selected_evidence,
                    resolution,
                ),
                assessments=assessments,
                resolution=resolution,
            )
        )
    return DependencyReport(
        schema_version=1,
        project_kind=configuration.project_kind,
        resolve=configuration.resolve,
        network=configuration.network,
        timeout_seconds=configuration.timeout_seconds,
        resolver=configuration.resolver,
        index_url=configuration.index_url,
        requirements=configuration.requirements,
        extras=configuration.extras,
        metadata=artifacts,
        metadata_issues=issues,
        targets=tuple(targets),
    )


@dataclass(frozen=True)
class _NegativeReportContext:
    active_requirements: tuple[str, ...]
    verified_names: frozenset[str]
    carried_names: frozenset[str]


def _declared_evidence_projection(
    rows: Sequence[EvaluatedRequirement],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            item.requirement,
            item.applies,
            item.matching_extras,
            item.matching_metadata,
            item.resolved_versions,
            item.verified,
        )
        for item in rows
    )


def _transitive_evidence_projection(
    rows: Sequence[TransitiveRequirementEvidence],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            item.requirement,
            item.required_by,
            item.locked_versions,
            item.matching_metadata,
            item.resolved_versions,
            item.verified,
        )
        for item in rows
    )


def _assessment_evidence_projection(
    rows: Sequence[DependencyAssessment],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            item.package,
            item.version,
            item.status,
            item.requires_python_status,
            item.artifact_availability,
            item.source_build_possible,
            item.metadata_used,
            item.applicable_requirements,
        )
        for item in rows
    )


def _validated_negative_provenance(
    report: DependencyReport,
    result: TargetDependencyResult,
    active_requirements: Sequence[str],
) -> frozenset[str]:
    """Validate private uv inputs before recomputing a complete negative."""
    carried_names = _verified_failure_names(result.resolution)
    carried_requirements = _verified_failure_requirements(result.resolution)
    carried_artifact_snapshots = _verified_failure_artifact_snapshots(result.resolution)
    carried_target_snapshot = _verified_failure_target_snapshot(result.resolution)
    if (
        not carried_names
        or not carried_requirements
        or carried_artifact_snapshots is None
        or carried_target_snapshot is None
    ):
        _error(
            "dependency report",
            "complete negative lacks internal reviewed uv evidence",
        )
    if carried_target_snapshot != _target_snapshot(result.target):
        _error(
            "dependency report",
            "complete negative target changed after uv review",
        )
    if carried_requirements != frozenset(
        _failure_requirement_identities(active_requirements, carried_names)
    ):
        _error(
            "dependency report",
            "complete negative requirement identity changed after uv review",
        )
    carried_artifact_ids = tuple(item[0] for item in carried_artifact_snapshots)
    report_artifact_ids = tuple(sorted(item.artifact_id for item in report.metadata))
    if carried_artifact_ids != report_artifact_ids:
        _error(
            "dependency report",
            "complete negative artifact inventory changed after uv review",
        )
    if carried_artifact_snapshots != _metadata_artifact_snapshots(report.metadata):
        _error(
            "dependency report",
            "complete negative artifact snapshot changed after uv review",
        )
    return carried_names


def _negative_report_context(
    report: DependencyReport,
    result: TargetDependencyResult,
) -> _NegativeReportContext:
    if tuple(item.requirement for item in result.declared_requirements) != (
        report.requirements
    ):
        _error(
            "dependency report",
            "declared requirement rows do not match the configured roots",
        )
    evaluated = tuple(
        _evaluate_requirement(value, result.target, report.extras)
        for value in report.requirements
    )
    active_requirements = tuple(item.requirement for item in evaluated if item.applies)
    carried_names = _validated_negative_provenance(
        report,
        result,
        active_requirements,
    )
    configuration = DependencyConfiguration(
        project_kind=report.project_kind,
        requirements=report.requirements,
        extras=report.extras,
        metadata_paths=tuple(Path(item.path) for item in report.metadata),
        targets=(result.target,),
        resolve=report.resolve,
        network=report.network,
        timeout_seconds=report.timeout_seconds,
        resolver=report.resolver,
        index_url=report.index_url,
    )
    recomputed_assessments = _assess_declared_dependency_metadata(
        report.metadata,
        target=result.target,
        configuration=configuration,
        declared=evaluated,
        resolution=result.resolution,
    )
    if _assessment_evidence_projection(
        result.assessments
    ) != _assessment_evidence_projection(recomputed_assessments):
        _error(
            "dependency report",
            "complete negative contains contradictory assessment evidence",
        )
    closed_resolution = _validated_resolver_closure(
        result.resolution,
        recomputed_assessments,
        report.metadata,
    )
    if (
        closed_resolution.status is not result.resolution.status
        or closed_resolution.complete is not result.resolution.complete
    ):
        _error(
            "dependency report",
            "complete negative contradicts the recomputed artifact closure",
        )
    selected_evidence = _target_semantic_artifacts(
        _resolution_evidence_artifacts(report.metadata, result.resolution),
        result.target,
    )
    recomputed = _correlate_declared_requirements(
        evaluated,
        selected_evidence,
        result.resolution,
        report.project_kind,
    )
    if _declared_evidence_projection(
        result.declared_requirements
    ) != _declared_evidence_projection(recomputed):
        _error(
            "dependency report",
            "complete negative contains contradictory declared evidence",
        )
    recomputed_transitive = _transitive_requirement_evidence(
        report.project_kind,
        recomputed_assessments,
        recomputed,
        selected_evidence,
        result.resolution,
    )
    if _transitive_evidence_projection(
        result.transitive_requirements
    ) != _transitive_evidence_projection(recomputed_transitive):
        _error(
            "dependency report",
            "complete negative contains contradictory transitive evidence",
        )
    active_rows = tuple(item for item in recomputed if item.applies)
    return _NegativeReportContext(
        active_requirements=tuple(item.requirement for item in active_rows),
        verified_names=frozenset(
            canonicalize_name(Requirement(item.requirement).name)
            for item in active_rows
            if item.verified
        ),
        carried_names=carried_names,
    )


def _validate_resolution_failed_report(
    report: DependencyReport,
    context: _NegativeReportContext,
) -> None:
    conflicting_names = frozenset(
        _conflicting_requirement_names(context.active_requirements)
    )
    if (
        not report.resolve
        or not context.carried_names.issubset(conflicting_names)
        or not context.carried_names.issubset(context.verified_names)
    ):
        _error(
            "dependency report",
            "resolution-failed lacks a verified contradictory root",
        )


def _artifact_assessment_is_bound(
    assessment: DependencyAssessment,
    *,
    closures: Mapping[str, _ClosedArtifactUnavailability],
    artifacts: Mapping[str, MetadataArtifact],
) -> bool:
    closure = closures.get(canonicalize_name(assessment.package))
    try:
        return bool(
            closure is not None
            and all(
                _requirement_accepts_version(
                    Requirement(requirement), assessment.version
                )
                for requirement in closure.requirements
            )
            and assessment.metadata_used
            and all(
                (artifact := artifacts.get(artifact_id)) is not None
                and artifact.canonical_name == canonicalize_name(assessment.package)
                and Version(artifact.version) == Version(assessment.version)
                for artifact_id in assessment.metadata_used
            )
        )
    except InvalidVersion:
        return False


def _validate_artifact_unavailable_report(
    report: DependencyReport,
    result: TargetDependencyResult,
    context: _NegativeReportContext,
) -> None:
    closures = {
        item.canonical_name: item
        for item in _offline_artifact_unavailability(
            context.active_requirements,
            report.metadata,
            result.target,
            report.project_kind,
        )
    }
    negative_assessments = tuple(
        item
        for item in result.assessments
        if item.status is DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE
    )
    artifacts_by_id = {item.artifact_id: item for item in report.metadata}
    if (
        not report.resolve
        or report.network
        or report.project_kind is not DependencyProjectKind.APPLICATION
        or not context.carried_names.issubset(closures)
        or not context.carried_names.issubset(context.verified_names)
        or not {
            canonicalize_name(item.package) for item in negative_assessments
        }.issubset(context.carried_names)
        or not all(
            _artifact_assessment_is_bound(
                item,
                closures=closures,
                artifacts=artifacts_by_id,
            )
            for item in negative_assessments
        )
        or any(
            item.status is DependencyCompatibilityStatus.COMPATIBLE
            for item in result.assessments
        )
    ):
        _error(
            "dependency report",
            "artifact-unavailable lacks one bound closed-inventory root",
        )


def _validate_dependency_report_semantics(report: DependencyReport) -> None:
    """Reject forged complete-negative models before machine serialization.

    JSON Schema closes the document shape, but it cannot compare package names
    across arrays or evaluate PEP 440 constraint intersections.  Keep those
    semantic checks at the trusted model-to-document boundary.
    """
    _validate_metadata_artifacts(report.metadata)
    _parse_requirements(report.requirements, report.project_kind)
    for result in report.targets:
        status = result.resolution.status
        if status not in {
            ResolutionStatus.ARTIFACT_UNAVAILABLE,
            ResolutionStatus.RESOLUTION_FAILED,
        }:
            continue
        context = _negative_report_context(report, result)
        if status is ResolutionStatus.RESOLUTION_FAILED:
            _validate_resolution_failed_report(report, context)
        else:
            _validate_artifact_unavailable_report(report, result, context)


def dependency_report_document(report: DependencyReport) -> dict[str, JsonValue]:
    """Return the closed deterministic JSON representation of a dependency report."""
    _validate_dependency_report_semantics(report)
    return {
        "controls": {
            "index_url": report.index_url,
            "network": report.network,
            "resolve": report.resolve,
            "resolver": report.resolver,
            "timeout_seconds": report.timeout_seconds,
        },
        "extras": list(report.extras),
        "metadata": [_metadata_artifact_document(item) for item in report.metadata],
        "metadata_issues": [
            {"incomplete": True, "message": item.message, "path": item.path.as_posix()}
            for item in report.metadata_issues
        ],
        "project_kind": report.project_kind.value,
        "requirements": list(report.requirements),
        "schema_version": report.schema_version,
        "targets": [
            {
                "assessments": [
                    {
                        "applicable_requirements": list(item.applicable_requirements),
                        "artifact_availability": item.artifact_availability.value,
                        "metadata_used": list(item.metadata_used),
                        "package": item.package,
                        "reason": item.reason,
                        "requires_python_status": item.requires_python_status.value,
                        "source_build_possible": item.source_build_possible,
                        "status": item.status.value,
                        "version": item.version,
                    }
                    for item in result.assessments
                ],
                "declared_requirements": [
                    {
                        "applies": item.applies,
                        "matching_metadata": list(item.matching_metadata),
                        "matching_extras": list(item.matching_extras),
                        "reason": item.reason,
                        "requirement": item.requirement,
                        "resolved_versions": list(item.resolved_versions),
                        "verified": item.verified,
                    }
                    for item in result.declared_requirements
                ],
                "transitive_requirements": [
                    {
                        "locked_versions": list(item.locked_versions),
                        "matching_metadata": list(item.matching_metadata),
                        "reason": item.reason,
                        "requirement": item.requirement,
                        "required_by": list(item.required_by),
                        "resolved_versions": list(item.resolved_versions),
                        "verified": item.verified,
                    }
                    for item in result.transitive_requirements
                ],
                "resolution": {
                    "complete": result.resolution.complete,
                    "packages": [
                        {
                            "metadata_used": list(item.metadata_used),
                            "name": item.name,
                            "version": item.version,
                        }
                        for item in result.resolution.packages
                    ],
                    "reason": result.resolution.reason,
                    "resolver": result.resolution.resolver,
                    "resolver_version": result.resolution.resolver_version,
                    "status": result.resolution.status.value,
                },
                "target": _target_document(result.target),
            }
            for result in report.targets
        ],
    }


def render_dependency_json(report: DependencyReport) -> str:
    """Render byte-stable machine output."""
    return (
        json.dumps(dependency_report_document(report), indent=2, sort_keys=True) + "\n"
    )


def render_dependency_text(report: DependencyReport) -> str:
    """Render a concise compatibility distinction for each target."""
    mode = "online" if report.network else "offline"
    lines = [
        (
            f"Dependency compatibility ({report.project_kind.value}; {mode}; "
            f"timeout {report.timeout_seconds:g}s)"
        )
    ]
    for item in report.metadata:
        dynamic = ",".join(escape_terminal_text(value) for value in item.dynamic)
        lines.append(
            f"Metadata {escape_terminal_text(item.artifact_id)}: "
            f"{escape_terminal_text(item.name)}=="
            f"{escape_terminal_text(item.version)}; "
            f"Core Metadata {escape_terminal_text(item.metadata_version)}; "
            "Requires-Python "
            f"{escape_terminal_text(item.requires_python or 'unspecified')}; "
            f"{escape_terminal_text(item.path.as_posix())}!"
            f"{escape_terminal_text(item.metadata_path)}; "
            f"sha256={escape_terminal_text(item.sha256)}; "
            "dynamic="
            f"{dynamic or 'none'}"
        )
    lines.append(
        f"Resolver control: requested={str(report.resolve).lower()}; "
        f"adapter={escape_terminal_text(report.resolver)}; "
        f"index={escape_terminal_text(report.index_url or 'disabled')}"
    )
    for result in report.targets:
        lines.append(
            f"Target {escape_terminal_text(result.target.name)}: "
            f"Python {escape_terminal_text(result.target.python_full_version)}; "
            f"{escape_terminal_text(result.target.sys_platform)}/"
            f"{escape_terminal_text(result.target.platform_machine)}"
        )
        for requirement in result.declared_requirements:
            state = "verified" if requirement.verified else "unverified"
            lines.append(
                f"  Declared {escape_terminal_text(requirement.requirement)}: "
                f"{'active' if requirement.applies else 'inactive'}; {state}"
            )
            lines.append(f"    {escape_terminal_text(requirement.reason)}")
        for transitive in result.transitive_requirements:
            state = "verified" if transitive.verified else "unverified"
            required_by = ", ".join(
                escape_terminal_text(item) for item in transitive.required_by
            )
            lines.append(
                f"  Transitive {escape_terminal_text(transitive.requirement)}: "
                f"{state}; required by {required_by}"
            )
            lines.append(f"    {escape_terminal_text(transitive.reason)}")
        for assessment in result.assessments:
            lines.append(
                f"  {escape_terminal_text(assessment.package)}=="
                f"{escape_terminal_text(assessment.version)}: "
                f"{assessment.status.value}; Requires-Python "
                f"{assessment.requires_python_status.value}; artifact "
                f"{assessment.artifact_availability.value}"
            )
            lines.append(f"    {escape_terminal_text(assessment.reason)}")
            lines.append(
                "    Metadata: "
                + ", ".join(
                    escape_terminal_text(item) for item in assessment.metadata_used
                )
            )
            lines.append(
                "    Applicable requirements: "
                + (
                    ", ".join(
                        escape_terminal_text(item)
                        for item in assessment.applicable_requirements
                    )
                    or "none"
                )
            )
        resolution = result.resolution
        lines.append(
            f"  Resolver: {resolution.status.value}; "
            f"complete={str(resolution.complete).lower()}; "
            "version="
            f"{escape_terminal_text(resolution.resolver_version or 'unavailable')}"
        )
        lines.append(f"    {escape_terminal_text(resolution.reason)}")
        lines.extend(
            f"    {escape_terminal_text(package.name)}=="
            f"{escape_terminal_text(package.version)}"
            for package in resolution.packages
        )
    lines.extend(
        f"Incomplete metadata {escape_terminal_text(issue.path.as_posix())}: "
        f"{escape_terminal_text(issue.message)}"
        for issue in report.metadata_issues
    )
    return "\n".join(lines) + "\n"
