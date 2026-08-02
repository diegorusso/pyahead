"""Derive finding states from sourced registry events."""

from dataclasses import replace

from pyahead.model import FindingState, FindingStateRange, Rule
from pyahead.versions import PythonMinor


def state_for_version(rule: Rule, version: PythonMinor) -> FindingState | None:
    """Return the state established by the latest event at one target."""
    applicable = tuple(event for event in rule.events if event.python <= version)
    if not applicable:
        return None
    latest = applicable[-1]
    return FindingState(rule.impact_for(latest.kind).value)


def derive_state_ranges(
    rule: Rule,
    reachable_versions: frozenset[PythonMinor],
) -> tuple[FindingStateRange, ...]:
    """Summarize affected reachable targets as contiguous state ranges."""
    ranges: list[FindingStateRange] = []
    for version in sorted(reachable_versions):
        state = state_for_version(rule, version)
        if state is None:
            continue
        if (
            ranges
            and ranges[-1].state is state
            and ranges[-1].through_python.major == version.major
            and ranges[-1].through_python.minor + 1 == version.minor
        ):
            ranges[-1] = replace(ranges[-1], through_python=version)
            continue
        ranges.append(
            FindingStateRange(
                from_python=version,
                through_python=version,
                state=state,
            )
        )
    return tuple(ranges)
