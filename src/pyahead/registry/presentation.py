"""Deterministic human-readable registry and rule presentation."""

from pyahead.model import (
    CallShapeMatcher,
    LiteralDynamicImportMatcher,
    ModuleImportMatcher,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    Registry,
    Rule,
    RuleMatcher,
)


def render_registry_list(registry: Registry) -> str:
    """List canonical rules without loading or scanning a project."""
    lines = [
        f"Registry {registry.release} ({registry.revision[:12]})",
        f"Rules: {len(registry.rules)}",
        "",
    ]
    for rule in sorted(registry.rules, key=lambda item: item.id):
        matcher_kinds = ", ".join(
            sorted({matcher.kind.value for matcher in rule.matchers})
        )
        lines.append(f"{rule.id}  {rule.title}")
        lines.append(f"  Subject: {rule.subject_kind.value} {rule.subject}")
        lines.append(f"  Matchers: {matcher_kinds}")
    return "\n".join(lines) + "\n"


def _matcher_details(matcher: RuleMatcher) -> str:
    if isinstance(matcher, ModuleImportMatcher):
        return f"module={matcher.module}"
    if isinstance(matcher, QualifiedReferenceMatcher):
        contexts = (
            ",".join(context.value for context in matcher.contexts)
            if matcher.contexts
            else "any-read"
        )
        return f"qualified_name={matcher.qualified_name}; contexts={contexts}"
    if isinstance(matcher, QualifiedCallMatcher):
        return f"qualified_name={matcher.qualified_name}"
    if isinstance(matcher, CallShapeMatcher):
        predicates: list[str] = []
        if matcher.min_positional_args is not None:
            predicates.append(f"min_positional_args={matcher.min_positional_args}")
        if matcher.max_positional_args is not None:
            predicates.append(f"max_positional_args={matcher.max_positional_args}")
        if matcher.required_keywords:
            predicates.append(
                f"required_keywords={','.join(matcher.required_keywords)}"
            )
        if matcher.forbidden_keywords:
            predicates.append(
                f"forbidden_keywords={','.join(matcher.forbidden_keywords)}"
            )
        predicates.extend(
            (
                f"position[{predicate.position}]={predicate.equals!r}"
                if predicate.position is not None
                else f"keyword[{predicate.keyword}]={predicate.equals!r}"
            )
            for predicate in matcher.literal_arguments
        )
        return f"qualified_name={matcher.qualified_name}; {'; '.join(predicates)}"
    if isinstance(matcher, LiteralDynamicImportMatcher):
        return f"module={matcher.module}; confidence={matcher.confidence.value}"
    return f"pattern={matcher.pattern.value}"


def _matcher_example(matcher: RuleMatcher) -> str:
    if isinstance(matcher, ModuleImportMatcher):
        return f"import {matcher.module}"
    if isinstance(matcher, QualifiedReferenceMatcher):
        return matcher.qualified_name
    if isinstance(matcher, (QualifiedCallMatcher, CallShapeMatcher)):
        return f"{matcher.qualified_name}(...)"
    if isinstance(matcher, LiteralDynamicImportMatcher):
        return f'importlib.import_module("{matcher.module}")'
    return "~True"


def render_rule_explanation(registry: Registry, rule: Rule) -> str:
    """Explain a rule entirely from registry data."""
    lines = [
        f"{rule.id} — {rule.title}",
        f"Registry: {registry.release} ({registry.revision[:12]})",
        f"Subject: {rule.subject_kind.value} {rule.subject}",
        (
            f"Scope: {rule.ecosystem}/{rule.runtime}; contexts: "
            f"{', '.join(context.value for context in rule.contexts)}"
        ),
        "",
        rule.summary,
        "",
        "Timeline:",
    ]
    source_by_id = {source.id: source for source in rule.sources}
    for event in rule.events:
        impact = rule.impact_for(event.kind)
        source = source_by_id[event.source_id]
        lines.append(
            f"  Python {event.python}: {event.kind.value}; impact={impact.value}; "
            f"certainty={event.certainty.value}; source={source.id}"
        )
    lines.extend(["", "Matchers:"])
    for matcher in rule.matchers:
        lines.append(f"  {matcher.kind.value}: {_matcher_details(matcher)}")
        lines.append(f"    Example: {_matcher_example(matcher)}")
    lines.extend(["", "Remediation:", f"  {rule.remediation.summary}"])
    if rule.remediation.documentation_url is not None:
        lines.append(f"  Documentation: {rule.remediation.documentation_url}")
    if rule.remediation.automation is not None:
        automation = rule.remediation.automation
        lines.append(
            f"  Automation metadata: {automation.tool.value} {automation.rule} "
            "(not invoked)"
        )
    lines.extend(["", "Sources:"])
    lines.extend(
        f"  {source.id}: {source.title} — {source.url}" for source in rule.sources
    )
    if rule.aliases:
        lines.extend(["", f"Aliases: {', '.join(rule.aliases)}"])
    if rule.tags:
        lines.extend(["", f"Tags: {', '.join(rule.tags)}"])
    return "\n".join(lines) + "\n"
