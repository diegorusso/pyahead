"""Compilation of registry matchers into deterministic lookup indexes."""

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypeVar

from pyahead.model import (
    BuiltinPattern,
    BuiltinPatternMatcher,
    CallShapeMatcher,
    LiteralDynamicImportMatcher,
    ModuleImportMatcher,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    Registry,
    Rule,
    RuleMatcher,
)

_IndexKey = TypeVar("_IndexKey", str, BuiltinPattern)


@dataclass(frozen=True)
class IndexedMatcher:
    """A declarative matcher paired with its owning rule."""

    rule: Rule
    matcher: RuleMatcher


@dataclass(frozen=True)
class MatcherIndex:
    """Small lookup tables that avoid testing every node against every rule."""

    module_imports: Mapping[str, tuple[IndexedMatcher, ...]]
    qualified_references: Mapping[str, tuple[IndexedMatcher, ...]]
    qualified_calls: Mapping[str, tuple[IndexedMatcher, ...]]
    call_shapes: Mapping[str, tuple[IndexedMatcher, ...]]
    literal_dynamic_imports: Mapping[str, tuple[IndexedMatcher, ...]]
    builtin_patterns: Mapping[BuiltinPattern, tuple[IndexedMatcher, ...]]


def _freeze(
    index: dict[_IndexKey, list[IndexedMatcher]],
) -> dict[_IndexKey, tuple[IndexedMatcher, ...]]:
    return {
        key: tuple(
            sorted(
                bindings,
                key=lambda binding: (binding.rule.id, repr(binding.matcher)),
            )
        )
        for key, bindings in index.items()
    }


def build_matcher_index(registry: Registry) -> MatcherIndex:
    """Compile one immutable registry into node-oriented matcher indexes."""
    module_imports: defaultdict[str, list[IndexedMatcher]] = defaultdict(list)
    qualified_references: defaultdict[str, list[IndexedMatcher]] = defaultdict(list)
    qualified_calls: defaultdict[str, list[IndexedMatcher]] = defaultdict(list)
    call_shapes: defaultdict[str, list[IndexedMatcher]] = defaultdict(list)
    dynamic_imports: defaultdict[str, list[IndexedMatcher]] = defaultdict(list)
    builtin_patterns: defaultdict[BuiltinPattern, list[IndexedMatcher]] = defaultdict(
        list
    )

    for rule in registry.rules:
        for matcher in rule.matchers:
            binding = IndexedMatcher(rule=rule, matcher=matcher)
            if isinstance(matcher, ModuleImportMatcher):
                module_imports[matcher.module.partition(".")[0]].append(binding)
            elif isinstance(matcher, QualifiedReferenceMatcher):
                qualified_references[matcher.qualified_name.rpartition(".")[2]].append(
                    binding
                )
            elif isinstance(matcher, QualifiedCallMatcher):
                qualified_calls[matcher.qualified_name.rpartition(".")[2]].append(
                    binding
                )
            elif isinstance(matcher, CallShapeMatcher):
                call_shapes[matcher.qualified_name.rpartition(".")[2]].append(binding)
            elif isinstance(matcher, LiteralDynamicImportMatcher):
                dynamic_imports[matcher.module.partition(".")[0]].append(binding)
            elif isinstance(matcher, BuiltinPatternMatcher):
                builtin_patterns[matcher.pattern].append(binding)

    return MatcherIndex(
        module_imports=_freeze(module_imports),
        qualified_references=_freeze(qualified_references),
        qualified_calls=_freeze(qualified_calls),
        call_shapes=_freeze(call_shapes),
        literal_dynamic_imports=_freeze(dynamic_imports),
        builtin_patterns=_freeze(builtin_patterns),
    )
