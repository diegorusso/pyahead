"""Tests for event-to-state timeline derivation."""

from dataclasses import replace

import pytest

from pyahead.model import ChangeEventKind, FindingState, Impact, RuleEvent
from pyahead.registry import load_registry
from pyahead.timeline import derive_state_ranges, state_for_version
from pyahead.versions import PythonMinor, target_set


def test_pep_594_events_form_contiguous_deprecated_and_breaking_ranges() -> None:
    """One rule becomes one complete state timeline over reachable targets."""
    rule = load_registry().rules[0]

    states = derive_state_ranges(
        rule,
        target_set(PythonMinor.parse("3.11"), PythonMinor.parse("3.16")),
    )

    assert [
        (str(state.from_python), str(state.through_python), state.state)
        for state in states
    ] == [
        ("3.11", "3.12", FindingState.DEPRECATED),
        ("3.13", "3.16", FindingState.BREAKING),
    ]


def test_unreachable_gaps_are_never_hidden_inside_state_ranges() -> None:
    """Equal states remain separate when an intervening target is unreachable."""
    rule = load_registry().rules[0]
    reachable = frozenset(
        {
            PythonMinor.parse("3.11"),
            PythonMinor.parse("3.13"),
            PythonMinor.parse("3.15"),
        }
    )

    states = derive_state_ranges(rule, reachable)

    observed = [(str(state.from_python), str(state.through_python)) for state in states]
    assert observed == [
        ("3.11", "3.11"),
        ("3.13", "3.13"),
        ("3.15", "3.15"),
    ]


@pytest.mark.parametrize(
    ("kind", "impact"),
    [
        (ChangeEventKind.DEPRECATED, Impact.DEPRECATED),
        (ChangeEventKind.REMOVED, Impact.BREAKING),
        (ChangeEventKind.SIGNATURE_CHANGED, Impact.BREAKING),
        (ChangeEventKind.BEHAVIOR_CHANGED, Impact.RISK),
        (ChangeEventKind.SYNTAX_CHANGED, Impact.RISK),
        (ChangeEventKind.SUPPORT_DROPPED, Impact.INFORMATIONAL),
    ],
)
def test_each_event_uses_its_authored_impact(
    kind: ChangeEventKind,
    impact: Impact,
) -> None:
    """Event kinds do not collapse authored impact into an implicit severity."""
    rule = load_registry().rules[0]
    event = RuleEvent(
        kind=kind,
        python=PythonMinor.parse("3.12"),
        certainty=rule.events[0].certainty,
        source_id=rule.events[0].source_id,
    )
    rule = replace(rule, events=(event,), event_impacts=((kind, impact),))

    assert state_for_version(rule, PythonMinor.parse("3.11")) is None
    assert state_for_version(rule, PythonMinor.parse("3.12")) is FindingState(
        impact.value
    )
