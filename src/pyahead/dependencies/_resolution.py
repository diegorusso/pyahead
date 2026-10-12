"""Validation and correlation of resolver results."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    TYPE_CHECKING,
)
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from packaging.requirements import Requirement
from packaging.utils import (
    canonicalize_name,
)
from packaging.version import InvalidVersion, Version

from pyahead.model import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Sequence
from pyahead.dependencies._assessment import (
    _active_requirement_groups,
    _artifact_satisfies_version_constraints,
    _assessment,
    _evaluate_requirement,
    _matching_metadata_artifact_ids,
    _requirement_is_singleton_pin,
    _resolution_evidence_artifacts,
    _resolved_artifact_group,
    _resolved_package_satisfies_requirements,
    _resolved_package_satisfies_version_constraints,
    assess_dependency_metadata,
)
from pyahead.dependencies._model import (
    _MAX_METADATA_INPUTS,
    _MAX_RESOLVER_PACKAGES,
    _MAX_TEXT_LENGTH,
    _RESOLVER_VERSION,
    _SHA256,
    ArtifactAvailability,
    DependencyCompatibilityStatus,
    DependencyProjectKind,
    EvaluatedRequirement,
    MetadataKind,
    ResolutionStatus,
    ResolvedPackage,
    ResolverResult,
    TransitiveRequirementEvidence,
    _canonical_requested_extras,
    _ClosedArtifactUnavailability,
    _consume_dependency_work,
    _fail_metadata,
    _failure_requirement_identities,
    _metadata_artifact_snapshots,
    _string,
    _verified_failure_artifact_snapshots,
    _verified_failure_names,
    _verified_failure_requirements,
    _verified_failure_target_snapshot,
)

if TYPE_CHECKING:
    from pyahead.dependencies._model import (
        DependencyAssessment,
        DependencyConfiguration,
        EnvironmentTarget,
        JsonValue,
        MetadataArtifact,
    )


@dataclass(frozen=True)
class _TransitiveCoverage:
    project_kind: DependencyProjectKind
    resolution: ResolverResult
    resolved_versions: tuple[str, ...]
    lock_requirements: tuple[Requirement, ...]
    common_lock_versions: frozenset[Version]
    matching_metadata: tuple[str, ...]


@dataclass(frozen=True)
class _ResolverValidationContext:
    artifacts: Sequence[MetadataArtifact]
    declared: Sequence[EvaluatedRequirement]
    configuration: DependencyConfiguration
    target: EnvironmentTarget
    expected_resolver: str
    built_in_uv_evidence: bool


def _resolver_result_header_is_valid(
    resolution: ResolverResult,
    expected_resolver: str,
) -> bool:
    try:
        _string(expected_resolver, "expected resolver adapter")
        _string(resolution.resolver, "resolver result adapter")
        _string(resolution.reason, "resolver result reason")
        if resolution.resolver_version is not None:
            version = _string(resolution.resolver_version, "resolver result version")
            if not _resolver_version_is_valid(version):
                return False
    except ConfigurationError:
        return False
    return (
        isinstance(resolution.status, ResolutionStatus)
        and type(resolution.complete) is bool
        and resolution.resolver == expected_resolver
    )


def _normalized_resolved_packages(
    packages: object,
) -> tuple[ResolvedPackage, ...] | None:
    if not isinstance(packages, tuple) or len(packages) > _MAX_RESOLVER_PACKAGES:
        return None
    normalized: list[ResolvedPackage] = []
    for package in packages:
        try:
            if not isinstance(package, ResolvedPackage):
                return None
            name = canonicalize_name(
                _string(package.name, "resolved package name"),
                validate=True,
            )
            version = _string(package.version, "resolved package version")
            canonical_version = str(Version(version))
            if (
                not isinstance(package.metadata_used, tuple)
                or len(package.metadata_used) > _MAX_METADATA_INPUTS
            ):
                return None
            metadata_used = tuple(
                _string(value, "resolved package metadata identity")
                for value in package.metadata_used
            )
            if len(metadata_used) != len(set(metadata_used)) or any(
                _SHA256.fullmatch(value) is None for value in metadata_used
            ):
                return None
        except (ConfigurationError, ValueError):
            return None
        normalized.append(
            replace(
                package,
                name=name,
                version=canonical_version,
                metadata_used=tuple(sorted(metadata_used)),
            )
        )
    ordered = tuple(
        sorted(
            normalized,
            key=lambda item: (
                item.name,
                Version(item.version),
            ),
        )
    )
    names = tuple(item.name for item in ordered)
    return ordered if len(names) == len(set(names)) else None


def _resolver_status_shape_is_valid(
    resolution: ResolverResult,
    *,
    requested: bool,
) -> bool:
    if not requested:
        return (
            resolution.status is ResolutionStatus.NOT_REQUESTED
            and resolution.complete
            and resolution.resolver_version is None
            and not resolution.packages
        )
    if resolution.status is ResolutionStatus.SUCCEEDED:
        return resolution.complete and resolution.resolver_version is not None
    if resolution.status in {
        ResolutionStatus.ARTIFACT_UNAVAILABLE,
        ResolutionStatus.RESOLUTION_FAILED,
    }:
        return (
            resolution.complete
            and resolution.resolver_version is not None
            and not resolution.packages
        )
    if resolution.status is ResolutionStatus.TIMED_OUT:
        return not resolution.complete and not resolution.packages
    return (
        resolution.status is ResolutionStatus.UNVERIFIED
        and not resolution.complete
        and (not resolution.packages or resolution.resolver_version is not None)
    )


def _partial_resolver_provenance_is_valid(
    resolution: ResolverResult,
    artifacts: Sequence[MetadataArtifact],
) -> bool:
    """Validate every artifact identity a partial resolver result chooses to cite."""
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    return all(
        not package.metadata_used
        or _resolved_artifact_group(package, artifacts_by_id) is not None
        for package in resolution.packages
    )


def _resolver_failure_is_corroborated(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> bool:
    if resolution.status not in {
        ResolutionStatus.ARTIFACT_UNAVAILABLE,
        ResolutionStatus.RESOLUTION_FAILED,
    }:
        return True
    active_requirements = tuple(
        item.requirement for item in context.declared if item.applies
    )
    verified_names = _verified_failure_names(resolution)
    verified_requirements = _verified_failure_requirements(resolution)
    verified_artifact_snapshots = _verified_failure_artifact_snapshots(resolution)
    verified_target_snapshot = _verified_failure_target_snapshot(resolution)
    if (
        not context.built_in_uv_evidence
        or not verified_names
        or not verified_requirements
        or verified_requirements
        != frozenset(
            _failure_requirement_identities(active_requirements, verified_names)
        )
        or verified_artifact_snapshots is None
        or verified_artifact_snapshots
        != _metadata_artifact_snapshots(context.artifacts)
        or verified_target_snapshot != _target_snapshot(context.target)
    ):
        return False
    if resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE:
        independently_unavailable = {
            item.canonical_name
            for item in _offline_artifact_unavailability(
                active_requirements,
                context.artifacts,
                context.target,
                context.configuration.project_kind,
            )
        }
        return bool(
            not context.configuration.network
            and verified_names.issubset(independently_unavailable)
        )
    if resolution.status is ResolutionStatus.RESOLUTION_FAILED:
        return verified_names.issubset(
            _conflicting_requirement_names(active_requirements)
        )
    return True


def _resolver_success_is_provenance_bound(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> bool:
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in context.artifacts}
    canonical_names = tuple(
        canonicalize_name(package.name) for package in resolution.packages
    )
    structurally_valid = len(canonical_names) == len(set(canonical_names)) and all(
        _resolved_artifact_group(package, artifacts_by_id) is not None
        for package in resolution.packages
    )
    active_groups = _active_requirement_groups(context.declared)
    _consume_dependency_work(len(active_groups) * len(resolution.packages))
    target_bound = structurally_valid and all(
        len(package.metadata_used) == 1
        and (selected := _resolved_artifact_group(package, artifacts_by_id)) is not None
        and (
            assessment := _assessment(
                selected,
                context.target,
                tuple(
                    sorted(
                        _canonical_requested_extras(
                            active_groups.get(canonicalize_name(package.name), ())
                        )
                    )
                ),
            )
        ).status
        is DependencyCompatibilityStatus.COMPATIBLE
        and frozenset(assessment.metadata_used) == frozenset(package.metadata_used)
        for package in resolution.packages
    )
    roots_covered = structurally_valid and all(
        sum(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == name
        )
        == 1
        for name, requirements in active_groups.items()
    )
    return structurally_valid and target_bound and roots_covered


def _validated_resolver_result(
    resolution: ResolverResult,
    context: _ResolverValidationContext,
) -> ResolverResult:
    """Fail closed when a replaceable resolver contradicts exact provenance."""
    if not isinstance(resolution, ResolverResult) or not (
        _resolver_result_header_is_valid(resolution, context.expected_resolver)
    ):
        return _resolver_unverified("resolver returned invalid structured evidence")
    packages = _normalized_resolved_packages(resolution.packages)
    if packages is None:
        return _resolver_unverified("resolver returned invalid structured evidence")
    resolution = replace(resolution, packages=packages)
    if (
        not _resolver_status_shape_is_valid(
            resolution,
            requested=context.configuration.resolve,
        )
        or not _resolver_failure_is_corroborated(resolution, context)
        or not _partial_resolver_provenance_is_valid(
            resolution,
            context.artifacts,
        )
    ):
        return _resolver_unverified(
            "resolver returned contradictory structured evidence"
        )
    if resolution.status is not ResolutionStatus.SUCCEEDED:
        return resolution
    if _resolver_success_is_provenance_bound(
        resolution,
        context,
    ):
        return resolution
    return replace(
        resolution,
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        reason=(
            "resolver success did not provide one exact, provenance-bound selection "
            "for every active requirement"
        ),
    )


def _correlate_declared_requirements(
    declared: Sequence[EvaluatedRequirement],
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
    project_kind: DependencyProjectKind,
) -> tuple[EvaluatedRequirement, ...]:
    active_groups = _active_requirement_groups(declared)
    conflicting_names = frozenset(
        _conflicting_requirement_names(
            tuple(item.requirement for item in declared if item.applies)
        )
    )
    verified_failure_names = _verified_failure_names(resolution)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_artifacts = _resolution_evidence_artifacts(artifacts, resolution)
    correlations: dict[
        str,
        tuple[tuple[str, ...], tuple[str, ...], bool, str],
    ] = {}
    for name, active_group in active_groups.items():
        group = tuple(active_group)
        _consume_dependency_work(
            len(evidence_artifacts) + len(resolution.packages) + len(artifacts)
        )
        matching_metadata = _matching_metadata_artifact_ids(
            evidence_artifacts,
            group,
        )
        matching_versions = {
            Version(artifact.version)
            for artifact in evidence_artifacts
            if _artifact_satisfies_version_constraints(artifact, group)
        }
        resolved_versions = tuple(
            sorted(
                f"{canonicalize_name(package.name)}=={package.version}"
                for package in resolution.packages
                if _resolved_package_satisfies_requirements(
                    package,
                    group,
                    artifacts_by_id,
                )
            )
        )
        complete_selection = (
            resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete
        )
        if (
            project_kind is DependencyProjectKind.APPLICATION
            and not complete_selection
            and len(matching_versions) > 1
        ):
            verified = False
            reason = (
                "active application pin matches multiple supplied package versions; "
                "exact resolver provenance is required"
            )
        elif (
            resolution.status is ResolutionStatus.RESOLUTION_FAILED
            and resolution.complete
            and name in conflicting_names
            and name in verified_failure_names
        ):
            verified = True
            reason = "complete resolver evidence proves the declared set unsatisfiable"
        elif (
            project_kind is DependencyProjectKind.LIBRARY
            and not complete_selection
            and not any(_requirement_is_singleton_pin(item) for item in group)
        ):
            verified = False
            reason = (
                "a finite library artifact sample does not prove the complete "
                "declared version set"
            )
        elif matching_metadata:
            verified = True
            reason = "active requirement matches directly inspected metadata"
        elif (
            resolution.status is ResolutionStatus.SUCCEEDED
            and resolution.complete
            and resolved_versions
        ):
            verified = True
            reason = "active requirement matches complete resolver evidence"
        elif (
            resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
            and resolution.complete
            and name in verified_failure_names
            and not any(
                _artifact_satisfies_version_constraints(artifact, group)
                for artifact in artifacts
            )
        ):
            verified = True
            reason = (
                "the complete offline artifact set contains no distribution "
                "satisfying the active requirement"
            )
        else:
            verified = False
            reason = (
                "simultaneously active constraints have no common exact metadata "
                "or complete resolver selection"
                if len(group) > 1
                else "active requirement has no matching exact metadata or complete "
                "resolver evidence"
            )
        correlations[name] = (
            matching_metadata,
            resolved_versions,
            verified,
            reason,
        )
    correlated: list[EvaluatedRequirement] = []
    for item in declared:
        if not item.applies:
            correlated.append(item)
            continue
        requirement = Requirement(item.requirement)
        matching_metadata, resolved_versions, verified, reason = correlations[
            canonicalize_name(requirement.name)
        ]
        correlated.append(
            EvaluatedRequirement(
                requirement=item.requirement,
                applies=True,
                matching_extras=item.matching_extras,
                matching_metadata=matching_metadata,
                resolved_versions=resolved_versions,
                verified=verified,
                reason=reason,
            )
        )
    return tuple(correlated)


def _exact_requirement_version(requirement: Requirement) -> str | None:
    specifiers = tuple(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator not in {"==", "==="}
        or specifiers[0].version.endswith(".*")
    ):
        return None
    try:
        return str(Version(specifiers[0].version))
    except InvalidVersion:
        return None


def _raw_exact_requirement_version(requirement: Requirement) -> str | None:
    """Retain spelling for arbitrary-equality witness checks."""
    specifiers = tuple(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator not in {"==", "==="}
        or specifiers[0].version.endswith(".*")
    ):
        return None
    try:
        Version(specifiers[0].version)
    except InvalidVersion:
        return None
    return specifiers[0].version


def _transitive_occurrences(
    assessments: Sequence[DependencyAssessment],
) -> dict[str, dict[str, set[str]]]:
    occurrences: dict[str, dict[str, set[str]]] = {}
    for assessment in assessments:
        parent = f"{canonicalize_name(assessment.package)}=={assessment.version}"
        for value in assessment.applicable_requirements:
            requirement = Requirement(value)
            name = canonicalize_name(requirement.name)
            occurrences.setdefault(name, {}).setdefault(value, set()).add(parent)
    return occurrences


def _validated_resolver_closure(
    resolution: ResolverResult,
    assessments: Sequence[DependencyAssessment],
    artifacts: Sequence[MetadataArtifact],
) -> ResolverResult:
    """Reject successful selections that omit an active dependency package."""
    if not (resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete):
        return resolution
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    resolved_keys = {
        (canonicalize_name(package.name), Version(package.version))
        for package in resolution.packages
    }
    reachable_keys = {
        (canonicalize_name(assessment.package), Version(assessment.version))
        for assessment in assessments
    }
    if reachable_keys != resolved_keys:
        return replace(
            resolution,
            status=ResolutionStatus.UNVERIFIED,
            complete=False,
            reason=(
                "resolver success included a package outside the exact active "
                "dependency closure"
            ),
        )
    occurrences = _transitive_occurrences(assessments)
    _consume_dependency_work(len(occurrences) * len(resolution.packages))
    closure_complete = all(
        sum(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == name
        )
        == 1
        for name, values in occurrences.items()
        for requirements in (tuple(Requirement(value) for value in values),)
    )
    if closure_complete:
        return resolution
    return replace(
        resolution,
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        reason=(
            "resolver success omitted an exact provenance-bound package from the "
            "active selected dependency closure"
        ),
    )


def _transitive_coverage_verdict(
    coverage: _TransitiveCoverage,
) -> tuple[bool, str]:
    if coverage.project_kind is DependencyProjectKind.LIBRARY:
        verified = bool(
            coverage.resolution.status is ResolutionStatus.SUCCEEDED
            and coverage.resolution.complete
            and coverage.resolved_versions
        )
        reason = (
            "active library requirement matches complete resolver evidence"
            if verified
            else "active library transitive requirement requires complete resolver "
            "evidence"
        )
        verdict = verified, reason
    elif (
        coverage.resolution.status is ResolutionStatus.SUCCEEDED
        and coverage.resolution.complete
        and coverage.resolved_versions
    ):
        verdict = (
            True,
            "active transitive requirement matches complete resolver evidence",
        )
    elif not coverage.lock_requirements:
        verdict = (
            False,
            "active transitive requirement is missing from the application lock",
        )
    elif len(coverage.common_lock_versions) != 1:
        verdict = (
            False,
            (
                "simultaneously active Requires-Dist entries and application pins "
                "have no common exact version"
            ),
        )
    elif coverage.matching_metadata:
        verdict = (
            True,
            (
                "active transitive requirement matches the exact application lock "
                "and directly inspected metadata"
            ),
        )
    else:
        verdict = (
            False,
            (
                "active transitive requirement has an application pin but no "
                "matching exact metadata or complete resolver evidence"
            ),
        )
    return verdict


def _transitive_requirement_evidence(
    project_kind: DependencyProjectKind,
    assessments: Sequence[DependencyAssessment],
    declared: Sequence[EvaluatedRequirement],
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
) -> tuple[TransitiveRequirementEvidence, ...]:
    occurrences = _transitive_occurrences(assessments)
    active_lock = _active_requirement_groups(declared)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    evidence_artifacts = _resolution_evidence_artifacts(artifacts, resolution)
    _consume_dependency_work(
        len(occurrences) * (len(evidence_artifacts) + len(resolution.packages))
    )
    evidence: list[TransitiveRequirementEvidence] = []
    for name in sorted(occurrences):
        requirement_values = tuple(sorted(occurrences[name]))
        requirements = tuple(Requirement(value) for value in requirement_values)
        lock_requirements = tuple(active_lock.get(name, ()))
        raw_lock_versions = tuple(
            version
            for requirement in lock_requirements
            if (version := _exact_requirement_version(requirement)) is not None
        )
        lock_versions = tuple(
            sorted({f"{name}=={version}" for version in raw_lock_versions})
        )
        evidence_requirements = (
            requirements
            if project_kind is DependencyProjectKind.LIBRARY
            else (*lock_requirements, *requirements)
        )
        matching_metadata = _matching_metadata_artifact_ids(
            evidence_artifacts,
            evidence_requirements,
        )
        matching_ids = frozenset(matching_metadata)
        common_lock_versions = frozenset(
            Version(artifact.version)
            for artifact in evidence_artifacts
            if artifact.artifact_id in matching_ids
        )
        resolved_versions = tuple(
            sorted(
                f"{name}=={package.version}"
                for package in resolution.packages
                if _resolved_package_satisfies_requirements(
                    package, requirements, artifacts_by_id
                )
                and (
                    project_kind is DependencyProjectKind.LIBRARY
                    or not lock_requirements
                    or Version(package.version) in common_lock_versions
                )
            )
        )

        verified, reason = _transitive_coverage_verdict(
            _TransitiveCoverage(
                project_kind=project_kind,
                resolution=resolution,
                resolved_versions=resolved_versions,
                lock_requirements=lock_requirements,
                common_lock_versions=common_lock_versions,
                matching_metadata=matching_metadata,
            )
        )
        evidence.extend(
            TransitiveRequirementEvidence(
                requirement=value,
                required_by=tuple(sorted(occurrences[name][value])),
                locked_versions=lock_versions,
                matching_metadata=matching_metadata,
                resolved_versions=resolved_versions,
                verified=verified,
                reason=reason,
            )
            for value in requirement_values
        )
    return tuple(evidence)


def _active_resolver_requirements(
    requirements: Sequence[str], target: EnvironmentTarget, extras: tuple[str, ...]
) -> tuple[str, ...]:
    active: list[str] = []
    for value in requirements:
        evaluated = _evaluate_requirement(value, target, extras)
        if evaluated.applies:
            active.append(value.partition(";")[0].rstrip())
    return tuple(active)


def _resolver_requirement_groups(
    requirements: Sequence[str],
) -> dict[str, tuple[Requirement, ...]]:
    groups: dict[str, list[Requirement]] = {}
    for value in requirements:
        requirement = Requirement(value)
        groups.setdefault(canonicalize_name(requirement.name), []).append(requirement)
    return {
        name: tuple(sorted(group, key=str)) for name, group in sorted(groups.items())
    }


def _conflicting_requirement_names(requirements: Sequence[str]) -> tuple[str, ...]:
    """Name groups whose active constraints prove a direct contradiction."""
    conflicts: list[str] = []
    for name, group in _resolver_requirement_groups(requirements).items():
        exact_versions = tuple(
            sorted(
                {
                    version
                    for requirement in group
                    if (version := _raw_exact_requirement_version(requirement))
                    is not None
                }
            )
        )
        _consume_dependency_work(len(exact_versions) * len(group))
        exact_conflict = bool(exact_versions) and not any(
            all(
                requirement.specifier.contains(candidate, prereleases=True)
                for requirement in group
            )
            for candidate in exact_versions
        )
        lower: tuple[Version, bool] | None = None
        upper: tuple[Version, bool] | None = None
        for requirement in group:
            for specifier in requirement.specifier:
                if specifier.operator not in {">", ">=", "<", "<="}:
                    continue
                try:
                    boundary = Version(specifier.version)
                except InvalidVersion:
                    continue
                inclusive = specifier.operator in {">=", "<="}
                if specifier.operator in {">", ">="} and (
                    lower is None
                    or boundary > lower[0]
                    or (boundary == lower[0] and not inclusive and lower[1])
                ):
                    lower = boundary, inclusive
                if specifier.operator in {"<", "<="} and (
                    upper is None
                    or boundary < upper[0]
                    or (boundary == upper[0] and not inclusive and upper[1])
                ):
                    upper = boundary, inclusive
        bounded_conflict = bool(
            lower is not None
            and upper is not None
            and (
                lower[0] > upper[0]
                or (lower[0] == upper[0] and not (lower[1] and upper[1]))
            )
        )
        if exact_conflict or bounded_conflict:
            conflicts.append(name)
    return tuple(conflicts)


def _offline_artifact_unavailability(
    requirements: Sequence[str],
    artifacts: Sequence[MetadataArtifact],
    target: EnvironmentTarget,
    project_kind: DependencyProjectKind,
) -> tuple[_ClosedArtifactUnavailability, ...]:
    """Identify requirements the closed, revalidated wheelhouse cannot satisfy."""
    if project_kind is not DependencyProjectKind.APPLICATION:
        return ()
    groups = _resolver_requirement_groups(requirements)
    if any(
        any(_exact_requirement_version(requirement) is None for requirement in group)
        for group in groups.values()
    ):
        return ()
    conflicts = frozenset(_conflicting_requirement_names(requirements))
    unavailable: list[_ClosedArtifactUnavailability] = []
    for name, group in groups.items():
        if name in conflicts:
            continue
        exact_versions = {
            version
            for requirement in group
            if (version := _exact_requirement_version(requirement)) is not None
        }
        if len(exact_versions) != 1:
            continue
        closure = _ClosedArtifactUnavailability(
            canonical_name=name,
            version=exact_versions.pop(),
            requirements=tuple(str(requirement) for requirement in group),
            description=" & ".join(str(requirement) for requirement in group),
        )
        _consume_dependency_work(len(artifacts))
        candidates = tuple(
            artifact
            for artifact in artifacts
            if _artifact_satisfies_version_constraints(artifact, group)
        )
        if not candidates:
            unavailable.append(closure)
            continue
        selected_extras = tuple(sorted(_canonical_requested_extras(group)))
        assessments = assess_dependency_metadata(
            candidates,
            target=target,
            extras=selected_extras,
        )
        if assessments and all(
            assessment.artifact_availability
            in {
                ArtifactAvailability.SOURCE_BUILD_POSSIBLE,
                ArtifactAvailability.UNAVAILABLE,
            }
            for assessment in assessments
        ):
            unavailable.append(closure)
    return tuple(unavailable)


def _resolver_version_is_valid(value: str) -> bool:
    match = _RESOLVER_VERSION.fullmatch(value)
    if match is None:
        return False
    try:
        Version(match.group("release"))
    except InvalidVersion:
        return False
    return True


def _resolver_version(output: str, resolver: str) -> str | None:
    line = output.removesuffix("\n")
    if "\n" in line or not line.startswith(f"{resolver} "):
        return None
    version = line[len(resolver) + 1 :]
    if (
        not version
        or len(version) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in version)
        or not _resolver_version_is_valid(version)
    ):
        return None
    return version


def _safe_process_text(value: str, workspace: Path) -> str:
    variants = {str(workspace), workspace.as_posix()}
    try:
        uri = workspace.resolve().as_uri()
    except (OSError, RuntimeError, ValueError):
        uri = ""
    if uri:
        variants.add(uri)
        variants.add(urlsplit(uri).path)
    normalized = value
    for variant in sorted((item for item in variants if item), key=len, reverse=True):
        normalized = normalized.replace(variant, "<workspace>")
    lines = []
    for raw_line in normalized.splitlines():
        safe_line = "".join(
            character if character.isprintable() else " " for character in raw_line
        ).strip()
        if safe_line:
            lines.append(safe_line)
    return " ".join(lines)[:_MAX_TEXT_LENGTH]


def _selected_metadata(
    raw_wheels: object,
    *,
    package_name: str,
    package_version: str,
    artifacts_by_filename: dict[str, MetadataArtifact],
    wheelhouse: Path,
) -> tuple[str, ...]:
    if not isinstance(raw_wheels, list) or len(raw_wheels) != 1:
        return ()
    wheel = raw_wheels[0]
    url = wheel.get("url") if isinstance(wheel, dict) else None
    if (
        not isinstance(url, str)
        or len(url) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in url)
    ):
        return ()
    parsed = urlsplit(url)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        return ()
    try:
        selected = Path(url2pathname(unquote(parsed.path))).resolve()
    except (OSError, RuntimeError, ValueError):
        return ()
    artifact = artifacts_by_filename.get(selected.name)
    if (
        artifact is None
        or selected.parent != wheelhouse
        or artifact.canonical_name != package_name
        or Version(artifact.version) != Version(package_version)
        or artifact.kind is not MetadataKind.WHEEL
    ):
        return ()
    return (artifact.artifact_id,)


def _pylock_package(
    raw_package: object,
    *,
    artifacts_by_filename: dict[str, MetadataArtifact],
    wheelhouse: Path,
) -> ResolvedPackage:
    if not isinstance(raw_package, dict):
        _fail_metadata("resolver pylock.toml has an invalid package record")
    name = raw_package.get("name")
    raw_version = raw_package.get("version")
    if (
        not isinstance(name, str)
        or not isinstance(raw_version, str)
        or not name
        or len(name) > _MAX_TEXT_LENGTH
        or len(raw_version) > _MAX_TEXT_LENGTH
        or any(not character.isprintable() for character in name + raw_version)
    ):
        _fail_metadata("resolver pylock.toml omits an exact package identity")
    try:
        version = str(Version(raw_version))
    except InvalidVersion:
        _fail_metadata("resolver pylock.toml has an invalid package version")
    canonical_name = canonicalize_name(name)
    return ResolvedPackage(
        name=name,
        version=version,
        metadata_used=_selected_metadata(
            raw_package.get("wheels"),
            package_name=canonical_name,
            package_version=version,
            artifacts_by_filename=artifacts_by_filename,
            wheelhouse=wheelhouse,
        ),
    )


def _resolved_packages(
    output: str,
    artifacts: Sequence[MetadataArtifact],
    *,
    wheelhouse: Path,
) -> tuple[tuple[ResolvedPackage, ...], bool]:
    try:
        document = tomllib.loads(output)
    except tomllib.TOMLDecodeError:
        _fail_metadata("resolver produced invalid pylock.toml output")
    if document.get("lock-version") != "1.0" or document.get("created-by") != "uv":
        _fail_metadata("resolver produced an unsupported pylock.toml document")
    raw_packages = document.get("packages", [])
    if not isinstance(raw_packages, list):
        _fail_metadata("resolver pylock.toml omits its package list")
    if len(raw_packages) > _MAX_RESOLVER_PACKAGES:
        _fail_metadata("resolver pylock.toml contains too many packages")
    artifacts_by_filename = {artifact.path.name: artifact for artifact in artifacts}
    packages = tuple(
        _pylock_package(
            item,
            artifacts_by_filename=artifacts_by_filename,
            wheelhouse=wheelhouse.resolve(),
        )
        for item in raw_packages
    )
    canonical_names = tuple(canonicalize_name(item.name) for item in packages)
    if len(canonical_names) != len(set(canonical_names)):
        _fail_metadata("resolver pylock.toml repeats a package identity")
    return (
        tuple(
            sorted(
                packages,
                key=lambda item: (canonicalize_name(item.name), Version(item.version)),
            )
        ),
        all(item.metadata_used for item in packages),
    )


def _resolver_unverified(
    reason: str,
    version: str | None = None,
    packages: tuple[ResolvedPackage, ...] = (),
) -> ResolverResult:
    return ResolverResult(
        status=ResolutionStatus.UNVERIFIED,
        complete=False,
        resolver="uv",
        resolver_version=version,
        packages=packages,
        reason=reason,
    )


def _target_document(target: EnvironmentTarget) -> dict[str, JsonValue]:
    return {
        "compatible_tags": list(target.compatible_tags),
        "implementation_name": target.implementation_name,
        "implementation_version": target.implementation_version,
        "name": target.name,
        "os_name": target.os_name,
        "platform_machine": target.platform_machine,
        "platform_python_implementation": target.platform_python_implementation,
        "platform_release": target.platform_release,
        "platform_system": target.platform_system,
        "platform_version": target.platform_version,
        "python_full_version": target.python_full_version,
        "python_version": target.python_version,
        "resolver_platform": target.resolver_platform,
        "sys_platform": target.sys_platform,
    }


def _target_snapshot(target: EnvironmentTarget) -> str:
    """Bind uv evidence to every target field emitted in machine reports."""
    encoded = json.dumps(
        _target_document(target),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
