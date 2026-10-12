"""Assessing inspected metadata against declared targets."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import (
    TYPE_CHECKING,
)

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import (
    canonicalize_name,
)
from packaging.version import InvalidVersion, Version

from pyahead.model import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
from pyahead.dependencies._artifacts import _validate_metadata_artifacts
from pyahead.dependencies._config import (
    _ensure_marker_evaluation_budget,
    _ensure_target_coherence,
    _validate_effective_extras,
)
from pyahead.dependencies._model import (
    _ACTIVE_MARKER_BUDGET,
    ArtifactAvailability,
    DependencyAssessment,
    DependencyCompatibilityStatus,
    DependencyProjectKind,
    EvaluatedRequirement,
    MetadataKind,
    RequiresPythonStatus,
    ResolutionStatus,
    _canonical_requested_extras,
    _consume_dependency_work,
    _MarkerEvaluationLimitError,
    _verified_failure_names,
    _with_marker_evaluation_budget,
)

if TYPE_CHECKING:
    from pyahead.dependencies._model import (
        DependencyConfiguration,
        EnvironmentTarget,
        MetadataArtifact,
        ResolvedPackage,
        ResolverResult,
    )


@dataclass(frozen=True)
class _ArtifactSelection:
    matching_wheels: tuple[MetadataArtifact, ...]
    wheels: tuple[MetadataArtifact, ...]
    sdists: tuple[MetadataArtifact, ...]
    raw_metadata: tuple[MetadataArtifact, ...]
    semantic_metadata: tuple[MetadataArtifact, ...]


def _evaluate_requirement(
    value: str, target: EnvironmentTarget, extras: tuple[str, ...]
) -> EvaluatedRequirement:
    _consume_dependency_work(1)
    budget = _ACTIVE_MARKER_BUDGET.get()
    requirement = Requirement(value)
    if requirement.marker is None:
        return EvaluatedRequirement(
            requirement=value,
            applies=True,
            matching_extras=("base",),
            matching_metadata=(),
            resolved_versions=(),
            verified=False,
            reason="active requirement has not been correlated with evidence",
        )
    contexts = extras or ("",)
    if budget is not None and len(contexts) > 1:
        budget.consume(len(contexts) - 1)
    try:
        matching = [
            extra or "base"
            for extra in contexts
            if requirement.marker.evaluate(
                environment=target.marker_environment(extra=extra),
                context="metadata",
            )
        ]
    except (UndefinedComparison, UndefinedEnvironmentName) as error:
        message = f"environment marker cannot be evaluated for target {target.name!r}"
        raise ConfigurationError(message) from error
    return EvaluatedRequirement(
        requirement=value,
        applies=bool(matching),
        matching_extras=tuple(matching),
        matching_metadata=(),
        resolved_versions=(),
        verified=not matching,
        reason=(
            "active requirement has not been correlated with evidence"
            if matching
            else "requirement marker does not apply to the declared target"
        ),
    )


def _select_artifacts(
    group: tuple[MetadataArtifact, ...], target: EnvironmentTarget
) -> _ArtifactSelection:
    wheels = tuple(item for item in group if item.kind is MetadataKind.WHEEL)
    _consume_dependency_work(
        len(target.tags) + sum(len(item.wheel_tags) for item in wheels)
    )
    target_tags = frozenset(map(str, target.tags))
    matching_wheels = tuple(
        item for item in wheels if any(tag in target_tags for tag in item.wheel_tags)
    )
    sdists = tuple(item for item in group if item.kind is MetadataKind.SDIST)
    raw_metadata = tuple(
        item for item in group if item.kind is MetadataKind.CORE_METADATA
    )
    semantic_metadata = matching_wheels or sdists or raw_metadata or wheels
    return _ArtifactSelection(
        matching_wheels=matching_wheels,
        wheels=wheels,
        sdists=sdists,
        raw_metadata=raw_metadata,
        semantic_metadata=semantic_metadata,
    )


def _requires_python_status(
    artifacts: Sequence[MetadataArtifact], target: EnvironmentTarget
) -> tuple[RequiresPythonStatus, bool]:
    declarations = {
        item.requires_python
        for item in artifacts
        if "requires-python" not in item.dynamic
    }
    dynamic = any("requires-python" in item.dynamic for item in artifacts)
    if dynamic:
        return RequiresPythonStatus.UNVERIFIED, True
    if not declarations:
        return RequiresPythonStatus.UNSPECIFIED, False
    if len(declarations) != 1:
        return RequiresPythonStatus.UNVERIFIED, dynamic
    declaration = next(iter(declarations))
    if declaration is None:
        return RequiresPythonStatus.UNSPECIFIED, dynamic
    compatible = SpecifierSet(declaration).contains(
        Version(target.python_full_version), prereleases=True
    )
    status = (
        RequiresPythonStatus.COMPATIBLE
        if compatible
        else RequiresPythonStatus.INCOMPATIBLE
    )
    return status, dynamic


def _artifact_availability(selection: _ArtifactSelection) -> ArtifactAvailability:
    if selection.matching_wheels:
        return ArtifactAvailability.AVAILABLE
    if selection.sdists:
        return ArtifactAvailability.SOURCE_BUILD_POSSIBLE
    if selection.wheels:
        return ArtifactAvailability.UNAVAILABLE
    return ArtifactAvailability.UNVERIFIED


def _assessment_outcome(
    requires_status: RequiresPythonStatus,
    availability: ArtifactAvailability,
    *,
    dynamic_requires_python: bool,
    source_build_possible: bool,
) -> tuple[DependencyCompatibilityStatus, str]:
    if requires_status is RequiresPythonStatus.INCOMPATIBLE:
        return (
            DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE,
            "Requires-Python excludes the declared target",
        )
    if requires_status is RequiresPythonStatus.UNVERIFIED:
        reason = (
            "candidate metadata marks Requires-Python as dynamic"
            if dynamic_requires_python
            else "candidate artifacts disagree on Requires-Python"
        )
        return DependencyCompatibilityStatus.UNVERIFIED, reason
    if availability is ArtifactAvailability.AVAILABLE:
        return (
            DependencyCompatibilityStatus.COMPATIBLE,
            (
                "Requires-Python does not exclude the target and a matching wheel "
                "is supplied"
            ),
        )
    if availability in {
        ArtifactAvailability.SOURCE_BUILD_POSSIBLE,
        ArtifactAvailability.UNAVAILABLE,
    }:
        reason = (
            "no matching wheel is supplied; a source build may remain possible"
            if source_build_possible
            else "no matching wheel or source distribution is supplied"
        )
        return DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE, reason
    return (
        DependencyCompatibilityStatus.UNVERIFIED,
        "core metadata alone does not establish artifact availability",
    )


def _artifact_applicable_requirements(
    artifact: MetadataArtifact,
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> tuple[str, ...]:
    """Evaluate one candidate's dependency edges without blending candidates."""
    return tuple(
        sorted(
            {
                item.requirement
                for value in artifact.requires_dist
                if (item := _evaluate_requirement(value, target, extras)).applies
            }
        )
    )


def _assessment(
    group: tuple[MetadataArtifact, ...],
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> DependencyAssessment:
    first = group[0]
    selection = _select_artifacts(group, target)
    semantic_metadata = selection.semantic_metadata
    requires_status, dynamic_requires_python = _requires_python_status(
        semantic_metadata, target
    )
    fallback_metadata = (
        (*selection.sdists, *selection.raw_metadata)
        if selection.matching_wheels
        else selection.raw_metadata
        if selection.sdists
        else ()
    )
    if requires_status is RequiresPythonStatus.INCOMPATIBLE and fallback_metadata:
        combined_metadata = (*semantic_metadata, *fallback_metadata)
        combined_status, combined_dynamic = _requires_python_status(
            combined_metadata, target
        )
        semantic_metadata = combined_metadata
        requires_status = combined_status
        dynamic_requires_python = combined_dynamic
    metadata_used = tuple(sorted({item.artifact_id for item in semantic_metadata}))
    marker_issue: str | None = None
    dynamic_requires_dist = any(
        "requires-dist" in artifact.dynamic for artifact in semantic_metadata
    )
    requires_dist_disagreement = False
    try:
        candidate_requirements = tuple(
            _artifact_applicable_requirements(artifact, target, extras)
            for artifact in semantic_metadata
            if "requires-dist" not in artifact.dynamic
        )
        requires_dist_disagreement = len(set(candidate_requirements)) > 1
        requirements = (
            () if requires_dist_disagreement else next(iter(candidate_requirements), ())
        )
    except _MarkerEvaluationLimitError:
        raise
    except ConfigurationError:
        requirements = ()
        marker_issue = (
            "candidate Requires-Dist marker cannot be evaluated for the declared target"
        )
    availability = _artifact_availability(selection)
    status, reason = _assessment_outcome(
        requires_status,
        availability,
        dynamic_requires_python=dynamic_requires_python,
        source_build_possible=bool(selection.sdists),
    )
    if marker_issue is not None:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = marker_issue
    elif dynamic_requires_dist:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = (
            "candidate metadata declares Requires-Dist dynamic; dependency "
            "compatibility remains unverified"
        )
    elif requires_dist_disagreement:
        status = DependencyCompatibilityStatus.UNVERIFIED
        reason = "candidate artifacts disagree on applicable Requires-Dist"
    return DependencyAssessment(
        package=first.name,
        version=first.version,
        status=status,
        requires_python_status=requires_status,
        artifact_availability=availability,
        source_build_possible=bool(selection.sdists),
        metadata_used=metadata_used,
        applicable_requirements=requirements,
        reason=reason,
    )


@_with_marker_evaluation_budget
def assess_dependency_metadata(
    artifacts: Sequence[MetadataArtifact],
    *,
    target: EnvironmentTarget,
    extras: tuple[str, ...],
) -> tuple[DependencyAssessment, ...]:
    """Assess exact supplied versions for one fully declared target."""
    _validate_metadata_artifacts(artifacts)
    _ensure_target_coherence(target, label="dependency target")
    validated_extras = _validate_effective_extras(
        extras,
        label="dependency assessment extras",
    )
    _ensure_marker_evaluation_budget(
        (
            (
                tuple(
                    requirement
                    for artifact in artifacts
                    for requirement in artifact.requires_dist
                ),
                1,
            ),
        ),
        extras=validated_extras,
        target_count=1,
        label="dependency assessment",
    )
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        key = (artifact.canonical_name, Version(artifact.version))
        grouped.setdefault(key, []).append(artifact)
    return tuple(
        _assessment_with_closure(
            _assessment(
                tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
                target,
                validated_extras,
            ),
            closure_proven=False,
        )
        for key in sorted(grouped, key=lambda item: (item[0], item[1]))
    )


def _assessment_with_closure(
    assessment: DependencyAssessment,
    *,
    closure_proven: bool,
) -> DependencyAssessment:
    """Separate sample observations from conclusions requiring resolver closure."""
    if closure_proven or assessment.status not in {
        DependencyCompatibilityStatus.COMPATIBLE,
        DependencyCompatibilityStatus.ARTIFACT_UNAVAILABLE,
    }:
        return assessment
    return replace(
        assessment,
        status=DependencyCompatibilityStatus.UNVERIFIED,
        reason=(
            "the supplied artifact sample does not establish complete target "
            "compatibility; complete resolver evidence is required"
        ),
    )


def _requirement_accepts_version(requirement: Requirement, version: str) -> bool:
    _consume_dependency_work(1)
    return requirement.specifier.contains(Version(version), prereleases=True)


def _resolved_artifact_group(
    package: ResolvedPackage,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> tuple[MetadataArtifact, ...] | None:
    """Return only exact artifacts explicitly attributed to one resolver package."""
    if not package.metadata_used or len(package.metadata_used) != len(
        set(package.metadata_used)
    ):
        return None
    selected: list[MetadataArtifact] = []
    for artifact_id in package.metadata_used:
        artifact = artifacts_by_id.get(artifact_id)
        if (
            artifact is None
            or artifact.canonical_name != canonicalize_name(package.name)
            or Version(artifact.version) != Version(package.version)
        ):
            return None
        selected.append(artifact)
    return tuple(selected)


def _resolution_evidence_artifacts(
    artifacts: Sequence[MetadataArtifact],
    resolution: ResolverResult,
) -> tuple[MetadataArtifact, ...]:
    if not (resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete):
        return tuple(artifacts)
    selected_ids = {
        artifact_id
        for package in resolution.packages
        for artifact_id in package.metadata_used
    }
    return tuple(
        artifact for artifact in artifacts if artifact.artifact_id in selected_ids
    )


def _target_semantic_artifacts(
    artifacts: Sequence[MetadataArtifact], target: EnvironmentTarget
) -> tuple[MetadataArtifact, ...]:
    """Keep only artifacts whose metadata is selected for the declared target."""
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        key = (artifact.canonical_name, Version(artifact.version))
        grouped.setdefault(key, []).append(artifact)
    selected: list[MetadataArtifact] = []
    for key in sorted(grouped, key=lambda item: (item[0], item[1])):
        group = tuple(sorted(grouped[key], key=lambda item: item.path.as_posix()))
        selected.extend(_select_artifacts(group, target).semantic_metadata)
    return tuple(selected)


def _propagated_dependency_assessments(
    grouped: Mapping[tuple[str, Version], Sequence[MetadataArtifact]],
    ordered_keys: Sequence[tuple[str, Version]],
    *,
    target: EnvironmentTarget,
    initial_extras: Mapping[tuple[str, Version], set[str]],
    seed_keys: Sequence[tuple[str, Version]],
) -> dict[tuple[str, Version], DependencyAssessment]:
    """Assess reachable dependencies and requested extras to a fixed point."""
    extras_by_key = {key: set(initial_extras[key]) for key in ordered_keys}
    keys_by_name: dict[str, list[tuple[str, Version]]] = {}
    for key in ordered_keys:
        keys_by_name.setdefault(key[0], []).append(key)

    assessments: dict[tuple[str, Version], DependencyAssessment] = {}
    pending = list(seed_keys)
    queued = set(seed_keys)
    cursor = 0
    while cursor < len(pending):
        key = pending[cursor]
        cursor += 1
        queued.discard(key)
        assessment = _assessment(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
            tuple(sorted(extras_by_key[key])),
        )
        assessments[key] = assessment
        for value in assessment.applicable_requirements:
            requirement = Requirement(value)
            requested = _canonical_requested_extras((requirement,))
            name = canonicalize_name(requirement.name)
            candidate_keys = keys_by_name.get(name, [])
            _consume_dependency_work(len(candidate_keys))
            for candidate_key in candidate_keys:
                if not _requirement_accepts_version(requirement, str(candidate_key[1])):
                    continue
                candidate_group = _select_artifacts(
                    tuple(
                        sorted(
                            grouped[candidate_key],
                            key=lambda item: item.path.as_posix(),
                        )
                    ),
                    target,
                ).semantic_metadata
                _consume_dependency_work(len(candidate_group))
                eligible = bool(candidate_group) and all(
                    _artifact_satisfies_requirements(artifact, (requirement,))
                    if requested
                    else _artifact_satisfies_version_constraints(
                        artifact, (requirement,)
                    )
                    for artifact in candidate_group
                )
                if not eligible:
                    continue
                previous_size = len(extras_by_key[candidate_key])
                extras_by_key[candidate_key].update(requested)
                if (
                    candidate_key not in assessments
                    or len(extras_by_key[candidate_key]) != previous_size
                ) and candidate_key not in queued:
                    pending.append(candidate_key)
                    queued.add(candidate_key)
    return assessments


def _direct_dependency_groups(
    artifacts: Sequence[MetadataArtifact],
    active: Sequence[Requirement],
) -> dict[tuple[str, Version], list[MetadataArtifact]]:
    requirements_by_name: dict[str, list[Requirement]] = {}
    for requirement in active:
        requirements_by_name.setdefault(
            canonicalize_name(requirement.name),
            [],
        ).append(requirement)
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        candidates = requirements_by_name.get(artifact.canonical_name, [])
        _consume_dependency_work(len(candidates))
        if candidates and all(
            _requirement_accepts_version(requirement, artifact.version)
            for requirement in candidates
        ):
            key = (artifact.canonical_name, Version(artifact.version))
            grouped.setdefault(key, []).append(artifact)
    return grouped


def _resolver_dependency_groups(
    resolution: ResolverResult,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> dict[tuple[str, Version], list[MetadataArtifact]]:
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for package in resolution.packages:
        selected = _resolved_artifact_group(package, artifacts_by_id)
        if selected is not None:
            key = (canonicalize_name(package.name), Version(package.version))
            grouped[key] = list(selected)
    return grouped


def _resolver_root_keys(
    ordered_keys: Sequence[tuple[str, Version]],
    active_groups: Mapping[str, Sequence[Requirement]],
    resolution: ResolverResult,
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> tuple[tuple[str, Version], ...]:
    _consume_dependency_work(len(ordered_keys) * len(resolution.packages))
    return tuple(
        key
        for key in ordered_keys
        if (requirements := active_groups.get(key[0])) is not None
        and any(
            _resolved_package_satisfies_version_constraints(
                package,
                requirements,
                artifacts_by_id,
            )
            for package in resolution.packages
            if canonicalize_name(package.name) == key[0]
            and Version(package.version) == key[1]
        )
    )


def _initial_dependency_extras(
    ordered_keys: Sequence[tuple[str, Version]],
    active: Sequence[Requirement],
    grouped: Mapping[tuple[str, Version], Sequence[MetadataArtifact]],
    target: EnvironmentTarget,
) -> dict[tuple[str, Version], set[str]]:
    _consume_dependency_work(len(ordered_keys) * len(active))
    initial: dict[tuple[str, Version], set[str]] = {}
    for key in ordered_keys:
        matching = tuple(
            requirement
            for requirement in active
            if canonicalize_name(requirement.name) == key[0]
            and _requirement_accepts_version(requirement, str(key[1]))
        )
        requested = _canonical_requested_extras(matching)
        selected = _select_artifacts(
            tuple(sorted(grouped[key], key=lambda item: item.path.as_posix())),
            target,
        ).semantic_metadata
        initial[key] = {
            extra
            for extra in requested
            if all(
                "provides-extra" not in artifact.dynamic
                and extra in artifact.provides_extra
                for artifact in selected
            )
        }
    return initial


def _assess_declared_dependency_metadata(
    artifacts: Sequence[MetadataArtifact],
    *,
    target: EnvironmentTarget,
    configuration: DependencyConfiguration,
    declared: Sequence[EvaluatedRequirement],
    resolution: ResolverResult,
) -> tuple[DependencyAssessment, ...]:
    active = tuple(Requirement(item.requirement) for item in declared if item.applies)
    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    active_groups: dict[str, list[Requirement]] = {}
    for requirement in active:
        name = canonicalize_name(requirement.name)
        active_groups.setdefault(name, []).append(requirement)
    use_resolver_selection = (
        resolution.status is ResolutionStatus.SUCCEEDED and resolution.complete
    )
    verified_failure_names = _verified_failure_names(resolution)
    grouped = (
        _resolver_dependency_groups(resolution, artifacts_by_id)
        if use_resolver_selection
        else _direct_dependency_groups(artifacts, active)
    )
    ordered_keys = tuple(sorted(grouped, key=lambda item: (item[0], item[1])))
    ambiguous_names = {
        name
        for name in {key[0] for key in ordered_keys}
        if sum(key[0] == name for key in ordered_keys) > 1
    }
    seed_keys = (
        _resolver_root_keys(
            ordered_keys,
            active_groups,
            resolution,
            artifacts_by_id,
        )
        if use_resolver_selection
        else ordered_keys
    )
    initial_extras = _initial_dependency_extras(ordered_keys, active, grouped, target)
    raw_assessments = _propagated_dependency_assessments(
        grouped,
        ordered_keys,
        target=target,
        initial_extras=initial_extras,
        seed_keys=seed_keys,
    )
    assessments: list[DependencyAssessment] = []
    for key in ordered_keys:
        if key not in raw_assessments:
            continue
        matching_requirements = tuple(
            requirement
            for requirement in active_groups.get(key[0], ())
            if _requirement_accepts_version(requirement, str(key[1]))
        )
        assessment = raw_assessments[key]
        if not use_resolver_selection and key[0] in ambiguous_names:
            assessment = replace(
                assessment,
                status=DependencyCompatibilityStatus.UNVERIFIED,
                reason=(
                    "active constraints match multiple supplied package versions; "
                    "exact resolver provenance is required"
                ),
            )
        if (
            configuration.project_kind is DependencyProjectKind.LIBRARY
            and assessment.status is DependencyCompatibilityStatus.DECLARED_INCOMPATIBLE
            and matching_requirements
            and not any(
                _requirement_is_singleton_pin(requirement)
                for requirement in matching_requirements
            )
        ):
            assessment = replace(
                assessment,
                status=DependencyCompatibilityStatus.UNVERIFIED,
                reason=(
                    "one sampled library version does not establish compatibility "
                    "for the declared range; complete resolver evidence is required"
                ),
            )
        assessment = _assessment_with_closure(
            assessment,
            closure_proven=bool(
                resolution.complete
                and (
                    resolution.status is ResolutionStatus.SUCCEEDED
                    or (
                        resolution.status is ResolutionStatus.ARTIFACT_UNAVAILABLE
                        and key[0] in verified_failure_names
                    )
                )
            ),
        )
        assessments.append(assessment)
    return tuple(assessments)


def _artifact_satisfies_requirements(
    artifact: MetadataArtifact, requirements: Sequence[Requirement]
) -> bool:
    if not requirements:
        return False
    canonical_name = canonicalize_name(requirements[0].name)
    required_extras = _canonical_requested_extras(requirements)
    return (
        artifact.canonical_name == canonical_name
        and all(
            _requirement_accepts_version(requirement, artifact.version)
            for requirement in requirements
        )
        and "provides-extra" not in artifact.dynamic
        and required_extras.issubset(artifact.provides_extra)
    )


def _matching_metadata_artifact_ids(
    artifacts: Sequence[MetadataArtifact], requirements: Sequence[Requirement]
) -> tuple[str, ...]:
    """Return candidate groups whose every viable artifact proves the extras."""
    if not requirements:
        return ()
    grouped: dict[tuple[str, Version], list[MetadataArtifact]] = {}
    for artifact in artifacts:
        if _artifact_satisfies_version_constraints(artifact, requirements):
            key = artifact.canonical_name, Version(artifact.version)
            grouped.setdefault(key, []).append(artifact)
    matching = {
        artifact.artifact_id
        for group in grouped.values()
        if all(
            _artifact_satisfies_requirements(artifact, requirements)
            for artifact in group
        )
        for artifact in group
    }
    return tuple(sorted(matching))


def _artifact_satisfies_version_constraints(
    artifact: MetadataArtifact, requirements: Sequence[Requirement]
) -> bool:
    """Return whether one artifact matches only the named version constraints."""
    if not requirements:
        return False
    canonical_name = canonicalize_name(requirements[0].name)
    return artifact.canonical_name == canonical_name and all(
        _requirement_accepts_version(requirement, artifact.version)
        for requirement in requirements
    )


def _resolved_package_satisfies_requirements(
    package: ResolvedPackage,
    requirements: Sequence[Requirement],
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> bool:
    if (
        not package.metadata_used
        or len(package.metadata_used) != len(set(package.metadata_used))
        or not requirements
    ):
        return False
    selected = tuple(
        artifacts_by_id.get(artifact_id) for artifact_id in package.metadata_used
    )
    return (
        all(artifact is not None for artifact in selected)
        and all(
            canonicalize_name(package.name) == canonicalize_name(requirement.name)
            and _requirement_accepts_version(requirement, package.version)
            for requirement in requirements
        )
        and all(
            artifact is not None
            and artifact.canonical_name == canonicalize_name(package.name)
            and Version(artifact.version) == Version(package.version)
            and _artifact_satisfies_requirements(artifact, requirements)
            for artifact in selected
        )
    )


def _resolved_package_satisfies_version_constraints(
    package: ResolvedPackage,
    requirements: Sequence[Requirement],
    artifacts_by_id: Mapping[str, MetadataArtifact],
) -> bool:
    selected = _resolved_artifact_group(package, artifacts_by_id)
    return selected is not None and all(
        _artifact_satisfies_version_constraints(artifact, requirements)
        for artifact in selected
    )


def _active_requirement_groups(
    declared: Sequence[EvaluatedRequirement],
) -> dict[str, list[Requirement]]:
    groups: dict[str, list[Requirement]] = {}
    for item in declared:
        if item.applies:
            requirement = Requirement(item.requirement)
            groups.setdefault(canonicalize_name(requirement.name), []).append(
                requirement
            )
    return groups


def _requirement_is_singleton_pin(requirement: Requirement) -> bool:
    """Return whether one specifier names a single distribution version."""
    specifiers = tuple(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].version.endswith(".*"):
        return False
    if specifiers[0].operator == "===":
        return True
    if specifiers[0].operator != "==":
        return False
    try:
        return Version(specifiers[0].version).local is not None
    except InvalidVersion:
        return False
