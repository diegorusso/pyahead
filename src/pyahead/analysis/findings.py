"""Turning per-file matches into deduplicated, policy-filtered findings."""

import hashlib
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from pyahead.analysis.suppressions import (
    InlineSuppressionIndex,
    PerFileSuppressionIndex,
    suppression_for_finding,
)
from pyahead.model import (
    AnalysisInference,
    BaselineStatus,
    ChangeEventKind,
    Finding,
    Impact,
    MatchConfidence,
    Policy,
    Registry,
    SourceLocation,
    StaticMatch,
    SubjectKind,
)
from pyahead.timeline import derive_state_ranges


@dataclass(frozen=True)
class FindingContext:
    """Everything that decides which matches become which findings."""

    registry: Registry
    policy: Policy
    minimum_confidence: MatchConfidence
    show_unscheduled: bool
    inline_suppressions: dict[PurePosixPath, InlineSuppressionIndex]
    per_file_ignores: PerFileSuppressionIndex
    baseline_fingerprints: frozenset[str]


@dataclass(frozen=True)
class ImportPathMutation:
    """An exact import-derived mutation of Python's module search path."""

    operation: str
    location: SourceLocation


def _fingerprint(match: StaticMatch, occurrence_ordinal: int) -> str:
    material = "\0".join(
        (
            "pyahead-fingerprint-v1",
            match.rule_id,
            match.location.path.as_posix(),
            match.enclosing_scope,
            match.subject,
            str(occurrence_ordinal),
        )
    )
    return hashlib.sha256(material.encode()).hexdigest()


_MATCH_KIND_PRIORITY = {
    "module-import": 0,
    "qualified-reference": 1,
    "qualified-call": 2,
    "literal-dynamic-import": 2,
    "builtin-pattern": 2,
    "call-shape": 3,
}
_CONFIDENCE_PRIORITY = {
    MatchConfidence.LOW: 0,
    MatchConfidence.MEDIUM: 1,
    MatchConfidence.HIGH: 2,
}


def deduplicate_matches(matches: list[StaticMatch]) -> tuple[StaticMatch, ...]:
    """Merge matchers that identify the same rule, region, and subject."""
    deduplicated: dict[tuple[str, SourceLocation, str], StaticMatch] = {}
    for match in sorted(
        matches,
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.region.start,
            item.rule_id,
            item.matcher_kind,
        ),
    ):
        key = (match.rule_id, match.location, match.subject)
        existing = deduplicated.get(key)
        if existing is None:
            deduplicated[key] = match
            continue
        existing_strength = (
            _CONFIDENCE_PRIORITY[existing.confidence],
            _MATCH_KIND_PRIORITY[existing.matcher_kind],
        )
        incoming_strength = (
            _CONFIDENCE_PRIORITY[match.confidence],
            _MATCH_KIND_PRIORITY[match.matcher_kind],
        )
        primary, secondary = (
            (match, existing)
            if incoming_strength > existing_strength
            else (existing, match)
        )
        evidence = list(primary.evidence)
        evidence_keys = {name for name, _value in evidence}
        evidence.extend(
            (name, value)
            for name, value in secondary.evidence
            if name not in evidence_keys
        )
        deduplicated[key] = StaticMatch(
            rule_id=primary.rule_id,
            matcher_kind=primary.matcher_kind,
            location=primary.location,
            enclosing_scope=primary.enclosing_scope,
            subject=primary.subject,
            confidence=primary.confidence,
            reachable_versions=(
                primary.reachable_versions | secondary.reachable_versions
            ),
            usage_contexts=primary.usage_contexts | secondary.usage_contexts,
            evidence=tuple(evidence),
        )
    return tuple(deduplicated.values())


def _replace_evidence(
    evidence: tuple[tuple[str, str | tuple[str, ...]], ...],
    **updates: str | tuple[str, ...],
) -> tuple[tuple[str, str | tuple[str, ...]], ...]:
    """Replace named evidence while retaining deterministic key order."""
    values = dict(evidence)
    values.update(updates)
    return tuple(sorted(values.items()))


def dynamic_path_adjustments(
    matches: list[StaticMatch],
    registry: Registry,
    dynamic_modules: dict[str, tuple[PurePosixPath, ...]],
    mutations: list[ImportPathMutation],
) -> tuple[list[StaticMatch], tuple[AnalysisInference, ...]]:
    """Prevent dynamic repository paths from fabricating an exact origin."""
    if not mutations:
        return matches, ()
    rules = {rule.id: rule for rule in registry.rules}
    operations = tuple(sorted({mutation.operation for mutation in mutations}))
    mutation_locations = tuple(
        sorted(
            {
                (
                    f"{mutation.location.path.as_posix()}:"
                    f"{mutation.location.region.start.line}:"
                    f"{mutation.location.region.start.column}"
                )
                for mutation in mutations
            }
        )
    )
    adjusted: list[StaticMatch] = []
    inferences: dict[tuple[SourceLocation, str], AnalysisInference] = {}
    for match in matches:
        match_evidence = dict(match.evidence)
        if not ({"imported_module", "qualified_names"} & match_evidence.keys()):
            adjusted.append(match)
            continue
        module = match.subject.partition(".")[0]
        candidates = dynamic_modules.get(module, ())
        rule = rules[match.rule_id]
        has_insert = "insert" in operations
        removals = tuple(
            event.python
            for event in rule.events
            if event.kind is ChangeEventKind.REMOVED
        )
        append_after_removal = (
            "append" in operations
            and rule.subject_kind is SubjectKind.MODULE
            and bool(removals)
        )
        if not candidates or not (has_insert or append_after_removal):
            adjusted.append(match)
            continue

        candidate_paths = tuple(path.as_posix() for path in candidates)
        resolution = (
            "dynamic-sys-path-ambiguity"
            if has_insert
            else "stdlib-before-appended-project-module"
        )
        reachable_versions = match.reachable_versions
        confidence = match.confidence
        if has_insert:
            confidence = MatchConfidence.MEDIUM
        else:
            removal = min(removals)
            reachable_versions = frozenset(
                version for version in reachable_versions if version < removal
            )
        adjusted.append(
            replace(
                match,
                confidence=confidence,
                reachable_versions=reachable_versions,
                evidence=_replace_evidence(
                    match.evidence,
                    candidate_paths=candidate_paths,
                    resolution=resolution,
                    sys_path_mutations=mutation_locations,
                    sys_path_operations=operations,
                ),
            )
        )
        key = (match.location, module)
        inferences[key] = AnalysisInference(
            code="PYA2001",
            kind="module-resolution",
            message=(
                f"treated import origin for {module!r} as uncertain because "
                "the repository mutates sys.path and contains a matching "
                "nested module"
            ),
            location=match.location,
            evidence=(
                ("candidate_paths", candidate_paths),
                ("imported_module", module),
                ("resolution", resolution),
                ("sys_path_mutations", mutation_locations),
                ("sys_path_operations", operations),
            ),
        )
    return adjusted, tuple(inferences[key] for key in sorted(inferences))


def build_findings(
    matches: list[StaticMatch],
    context: FindingContext,
) -> tuple[Finding, ...]:
    """Turn deduplicated matches into ordered, suppressed, baselined findings."""
    registry = context.registry
    policy = context.policy
    rules = {rule.id: rule for rule in registry.rules}
    ordinals: defaultdict[tuple[str, str, str, str], int] = defaultdict(int)
    findings: list[Finding] = []
    for match in sorted(
        deduplicate_matches(matches),
        key=lambda item: (
            item.location.path.as_posix(),
            item.location.region.start,
            item.rule_id,
        ),
    ):
        ordinal_key = (
            match.location.path.as_posix(),
            match.rule_id,
            match.enclosing_scope,
            match.subject,
        )
        occurrence_ordinal = ordinals[ordinal_key]
        ordinals[ordinal_key] += 1
        # Fingerprint identity is established before finding-emission filters.
        fingerprint = _fingerprint(match, occurrence_ordinal)
        if (
            _CONFIDENCE_PRIORITY[match.confidence]
            < _CONFIDENCE_PRIORITY[context.minimum_confidence]
        ):
            continue
        rule = rules[match.rule_id]
        usage_contexts = frozenset(rule.contexts).intersection(match.usage_contexts)
        if not usage_contexts:
            continue
        states = derive_state_ranges(rule, match.reachable_versions)
        if not states:
            continue
        removal_unscheduled = rule.removal_unscheduled
        deprecation_only = all(
            event.kind is ChangeEventKind.DEPRECATED for event in rule.events
        )
        if removal_unscheduled and deprecation_only and not context.show_unscheduled:
            continue
        impact = max(
            (Impact(state.state.value) for state in states),
            key=lambda value: {
                Impact.INFORMATIONAL: 0,
                Impact.DEPRECATED: 1,
                Impact.RISK: 2,
                Impact.BREAKING: 3,
            }[value],
        )
        action_version = min(
            state.from_python for state in states if state.state.value == impact.value
        )
        finding = Finding(
            fingerprint=fingerprint,
            rule_id=rule.id,
            title=rule.title,
            location=match.location,
            enclosing_scope=match.enclosing_scope,
            subject=match.subject,
            match_kind=match.matcher_kind,
            match_confidence=match.confidence,
            match_evidence=match.evidence,
            usage_contexts=tuple(
                sorted(usage_contexts, key=lambda context: context.value)
            ),
            reachable_versions=tuple(sorted(match.reachable_versions)),
            states=states,
            impact=impact,
            action_version=action_version,
            events=tuple(
                event for event in rule.events if event.python <= policy.horizon_python
            ),
            remediation=rule.remediation,
            sources=rule.sources,
            registry_revision=registry.revision,
            removal_unscheduled=removal_unscheduled,
        )
        findings.append(
            replace(
                finding,
                suppression=suppression_for_finding(
                    finding,
                    context.inline_suppressions.get(finding.location.path),
                    context.per_file_ignores,
                ),
                baseline_status=(
                    BaselineStatus.EXISTING
                    if finding.fingerprint in context.baseline_fingerprints
                    else BaselineStatus.NEW
                ),
            )
        )
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.action_version,
                finding.impact,
                finding.rule_id,
                finding.location,
            ),
        )
    )
