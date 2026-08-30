"""Deterministic human-readable registry and rule presentation."""

from collections import Counter

from pyahead._human_text import escape_terminal_text
from pyahead.model import (
    CallShapeMatcher,
    CoverageDisposition,
    LiteralDynamicImportMatcher,
    ModuleImportMatcher,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    Registry,
    Rule,
    RuleMatcher,
)


def render_registry_coverage(registry: Registry) -> str:
    """Summarize complete authoritative-source classifications."""
    entries = tuple(
        entry for manifest in registry.coverage for entry in manifest.entries
    )
    source_keys = tuple(
        source_key
        for manifest in registry.coverage
        for source_key in manifest.source_keys
    )
    classified_source_keys = {
        (manifest.source.id, entry.source_key)
        for manifest in registry.coverage
        for entry in manifest.entries
    }
    audited_source_keys = {
        (manifest.source.id, source_key)
        for manifest in registry.coverage
        for source_key in manifest.source_keys
    }
    unclassified_count = len(audited_source_keys - classified_source_keys)
    counts = Counter(entry.disposition for entry in entries)
    covered_rules = {
        rule_id
        for entry in entries
        if entry.disposition
        in {CoverageDisposition.IMPLEMENTED, CoverageDisposition.PARTIAL}
        for rule_id in entry.rules
    }
    lines = [
        (
            f"Registry {escape_terminal_text(registry.release)} "
            f"({escape_terminal_text(registry.revision[:12])}) coverage"
        ),
        f"Sources: {len(registry.coverage)}",
        f"Source entries: {len(source_keys)}",
        "",
    ]
    for manifest in registry.coverage:
        lines.append(
            f"{escape_terminal_text(manifest.source.id)}  {len(manifest.entries)}/"
            f"{len(manifest.source_keys)} entries  "
            f"checked {escape_terminal_text(manifest.source.checked_on)}"
        )
        lines.append(f"  {escape_terminal_text(manifest.source.url)}")
    lines.extend(["", "Dispositions:"])
    lines.extend(
        f"  {disposition.value}: {counts[disposition]}"
        for disposition in CoverageDisposition
    )
    lines.extend(
        [
            "",
            f"Rules covered: {len(covered_rules)}/{len(registry.rules)}",
            f"Unclassified source entries: {unclassified_count}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_registry_list(registry: Registry) -> str:
    """List canonical rules without loading or scanning a project."""
    lines = [
        (
            f"Registry {escape_terminal_text(registry.release)} "
            f"({escape_terminal_text(registry.revision[:12])})"
        ),
        f"Rules: {len(registry.rules)}",
        "",
    ]
    for rule in sorted(registry.rules, key=lambda item: item.id):
        matcher_kinds = ", ".join(
            sorted({matcher.kind.value for matcher in rule.matchers})
        )
        lines.append(
            f"{escape_terminal_text(rule.id)}  {escape_terminal_text(rule.title)}"
        )
        lines.append(
            f"  Subject: {rule.subject_kind.value} {escape_terminal_text(rule.subject)}"
        )
        lines.append(f"  Matchers: {matcher_kinds}")
    return "\n".join(lines) + "\n"


def _literal_text(value: object) -> str:
    """Render one closed scalar with canonical terminal-safe string controls."""
    if not isinstance(value, str):
        return repr(value)
    rendered = ["'"]
    for character in value:
        escaped = escape_terminal_text(character)
        if escaped != character:
            rendered.append(escaped)
        elif character in {"'", "\\"}:
            rendered.append(f"\\{character}")
        else:
            rendered.append(character)
    rendered.append("'")
    return "".join(rendered)


def _call_shape_details(matcher: CallShapeMatcher) -> str:
    predicates: list[str] = []
    if matcher.min_positional_args is not None:
        predicates.append(f"min_positional_args={matcher.min_positional_args}")
    if matcher.max_positional_args is not None:
        predicates.append(f"max_positional_args={matcher.max_positional_args}")
    if matcher.min_keyword_args is not None:
        predicates.append(f"min_keyword_args={matcher.min_keyword_args}")
    if matcher.max_keyword_args is not None:
        predicates.append(f"max_keyword_args={matcher.max_keyword_args}")
    if matcher.required_keywords:
        predicates.append(
            "required_keywords="
            + ",".join(escape_terminal_text(item) for item in matcher.required_keywords)
        )
    if matcher.forbidden_keywords:
        predicates.append(
            "forbidden_keywords="
            + ",".join(
                escape_terminal_text(item) for item in matcher.forbidden_keywords
            )
        )
    predicates.extend(
        (
            f"position[{predicate.position}]={_literal_text(predicate.equals)}"
            if predicate.position is not None
            else f"keyword[{escape_terminal_text(predicate.keyword or '')}]="
            f"{_literal_text(predicate.equals)}"
        )
        for predicate in matcher.literal_arguments
    )
    return (
        f"qualified_name={escape_terminal_text(matcher.qualified_name)}; "
        f"{'; '.join(predicates)}"
    )


def _matcher_details(matcher: RuleMatcher) -> str:
    if isinstance(matcher, ModuleImportMatcher):
        return f"module={escape_terminal_text(matcher.module)}"
    if isinstance(matcher, QualifiedReferenceMatcher):
        contexts = (
            ",".join(context.value for context in matcher.contexts)
            if matcher.contexts
            else "any-read"
        )
        return (
            f"qualified_name={escape_terminal_text(matcher.qualified_name)}; "
            f"contexts={contexts}"
        )
    if isinstance(matcher, QualifiedCallMatcher):
        return f"qualified_name={escape_terminal_text(matcher.qualified_name)}"
    if isinstance(matcher, CallShapeMatcher):
        return _call_shape_details(matcher)
    if isinstance(matcher, LiteralDynamicImportMatcher):
        return (
            f"module={escape_terminal_text(matcher.module)}; "
            f"confidence={matcher.confidence.value}"
        )
    return f"pattern={escape_terminal_text(matcher.pattern.value)}"


def _matcher_example(matcher: RuleMatcher) -> str:
    if isinstance(matcher, ModuleImportMatcher):
        return f"import {escape_terminal_text(matcher.module)}"
    if isinstance(matcher, QualifiedReferenceMatcher):
        return escape_terminal_text(matcher.qualified_name)
    if isinstance(matcher, (QualifiedCallMatcher, CallShapeMatcher)):
        return f"{escape_terminal_text(matcher.qualified_name)}(...)"
    if isinstance(matcher, LiteralDynamicImportMatcher):
        return f'importlib.import_module("{escape_terminal_text(matcher.module)}")'
    return "~True"


def render_rule_explanation(registry: Registry, rule: Rule) -> str:
    """Explain a rule entirely from registry data."""
    lines = [
        f"{escape_terminal_text(rule.id)} — {escape_terminal_text(rule.title)}",
        (
            f"Registry: {escape_terminal_text(registry.release)} "
            f"({escape_terminal_text(registry.revision[:12])})"
        ),
        f"Subject: {rule.subject_kind.value} {escape_terminal_text(rule.subject)}",
        (
            f"Scope: {escape_terminal_text(rule.ecosystem)}/"
            f"{escape_terminal_text(rule.runtime)}; contexts: "
            f"{', '.join(context.value for context in rule.contexts)}"
        ),
        "",
        escape_terminal_text(rule.summary),
        "",
        "Timeline:",
    ]
    source_by_id = {source.id: source for source in rule.sources}
    for event in rule.events:
        impact = rule.impact_for(event.kind)
        source = source_by_id[event.source_id]
        lines.append(
            f"  Python {event.python}: {event.kind.value}; impact={impact.value}; "
            f"certainty={event.certainty.value}; "
            f"source={escape_terminal_text(source.id)}"
        )
    if rule.removal_unscheduled:
        lines.append("  Removal schedule: unscheduled (no authoritative removal event)")
    lines.extend(["", "Matchers:"])
    for matcher in rule.matchers:
        lines.append(f"  {matcher.kind.value}: {_matcher_details(matcher)}")
        lines.append(f"    Example: {_matcher_example(matcher)}")
    lines.extend(
        ["", "Remediation:", f"  {escape_terminal_text(rule.remediation.summary)}"]
    )
    if rule.remediation.documentation_url is not None:
        lines.append(
            "  Documentation: "
            f"{escape_terminal_text(rule.remediation.documentation_url)}"
        )
    if rule.remediation.automation is not None:
        automation = rule.remediation.automation
        lines.append(
            f"  Automation metadata: {automation.tool.value} "
            f"{escape_terminal_text(automation.rule)} "
            "(not invoked)"
        )
    lines.extend(["", "Sources:"])
    lines.extend(
        f"  {escape_terminal_text(source.id)}: "
        f"{escape_terminal_text(source.title)} — {escape_terminal_text(source.url)}"
        for source in rule.sources
    )
    if rule.aliases:
        lines.extend(
            [
                "",
                "Aliases: "
                + ", ".join(escape_terminal_text(item) for item in rule.aliases),
            ]
        )
    if rule.tags:
        lines.extend(
            [
                "",
                "Tags: " + ", ".join(escape_terminal_text(item) for item in rule.tags),
            ]
        )
    return "\n".join(lines) + "\n"
