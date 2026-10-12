"""Strict schema parsing and JSON Schema generation for registry version 1."""

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn, TypeAlias, cast

from pyahead._human_text import SafeArgumentParser
from pyahead._schema_check import schema_problem
from pyahead.model import (
    AutomationReference,
    AutomationTool,
    BuiltinPattern,
    BuiltinPatternMatcher,
    CallShapeMatcher,
    ChangeEventKind,
    CoverageDisposition,
    CoverageEntry,
    CoverageManifest,
    CoverageSource,
    Impact,
    LiteralArgumentPredicate,
    LiteralDynamicImportMatcher,
    LiteralValue,
    MatchConfidence,
    MatcherKind,
    ModuleImportMatcher,
    PythonRelease,
    QualifiedCallMatcher,
    QualifiedReferenceMatcher,
    ReferenceContext,
    RegistryCertainty,
    ReleaseStatus,
    Remediation,
    Rule,
    RuleEvent,
    RuleMatcher,
    SourceReference,
    SubjectKind,
    UsageContext,
)
from pyahead.versions import (
    PYTHON_MINOR_PATTERN,
    PythonMinor,
)

RULE_ID_PATTERN = r"CPY[0-9]{4}"
_DOTTED_NAME_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_IDENTIFIER_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"
_DATE_PATTERN = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
_SOURCE_ID_PATTERN = r"[a-z0-9][a-z0-9.-]*"
_TAG_PATTERN = r"[a-z0-9][a-z0-9-]*"
# The union of Python ``str.isspace()`` and ECMAScript whitespace makes
# canonical registry boundaries independent of the regex engine used by a
# Draft 2020-12 JSON Schema consumer. Interior whitespace remains permitted.
_REGISTRY_WHITESPACE_CLASS = (
    r"\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680"
    r"\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_SURROGATE_CLASS = r"\ud800-\udfff"
_NON_REGISTRY_WHITESPACE = rf"[^{_REGISTRY_WHITESPACE_CLASS}]"
_UNICODE_STRING_PATTERN = rf"(?![\s\S]*[{_SURROGATE_CLASS}])[\s\S]*"
_TRIMMED_STRING_PATTERN = (
    rf"(?![\s\S]*[{_SURROGATE_CLASS}])"
    rf"{_NON_REGISTRY_WHITESPACE}"
    rf"(?:[\s\S]*{_NON_REGISTRY_WHITESPACE})?"
)
_RULE_PATH_SEGMENT_PATTERN = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?"
_RULE_PATH_PATTERN = (
    rf"(?:{_RULE_PATH_SEGMENT_PATTERN}/)*"
    rf"{_RULE_PATH_SEGMENT_PATTERN}\.ya?ml"
)
_HOST_LABEL_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOST_PATTERN = rf"{_HOST_LABEL_PATTERN}(?:\.{_HOST_LABEL_PATTERN})*"
_PORT_PATTERN = (
    r"(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|"
    r"65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
)
_HTTPS_URL_PATTERN = (
    rf"(?![\s\S]*[{_SURROGATE_CLASS}])"
    rf"https://(?![^/?#]*@){_HOST_PATTERN}(?::{_PORT_PATTERN})?"
    rf"(?:[/?#][^{_REGISTRY_WHITESPACE_CLASS}]*)?"
)

_EVENT_IMPACT_KEYS: dict[ChangeEventKind, str] = {
    ChangeEventKind.DEPRECATED: "on_deprecation",
    ChangeEventKind.REMOVED: "on_removal",
    ChangeEventKind.SIGNATURE_CHANGED: "on_signature_change",
    ChangeEventKind.BEHAVIOR_CHANGED: "on_behavior_change",
    ChangeEventKind.SYNTAX_CHANGED: "on_syntax_change",
    ChangeEventKind.SUPPORT_DROPPED: "on_support_drop",
}
_TERMINAL_EVENTS = frozenset({ChangeEventKind.REMOVED, ChangeEventKind.SUPPORT_DROPPED})

JsonSchema: TypeAlias = dict[str, object]


class RegistryError(ValueError):
    """Raised when registry data does not satisfy the closed schema."""


@dataclass(frozen=True)
class RegistryManifest:
    """Validated index data used by the registry loader."""

    release: str
    rule_paths: tuple[PurePosixPath, ...]
    coverage_paths: tuple[PurePosixPath, ...]
    retired_ids: tuple[str, ...]
    release_path: PurePosixPath | None


def _formats() -> dict[str, str]:
    """Return what each registry schema pattern stands for, for error messages."""
    return {
        _json_schema_exact_pattern(pattern): description
        for pattern, description in (
            (RULE_ID_PATTERN, "a rule ID in the CPY0000 format"),
            (_DOTTED_NAME_PATTERN, "a dotted Python name"),
            (_IDENTIFIER_PATTERN, "one Python identifier"),
            (_SOURCE_ID_PATTERN, "a lowercase source ID"),
            (_TAG_PATTERN, "a lowercase tag"),
            (_RULE_PATH_PATTERN, "a safe relative path to a registry file"),
            (_HTTPS_URL_PATTERN, "a direct HTTPS URL without credentials"),
            (_TRIMMED_STRING_PATTERN, "a non-empty, trimmed string"),
            (_UNICODE_STRING_PATTERN, "a string without lone surrogates"),
            (PYTHON_MINOR_PATTERN, "a Python minor such as '3.13'"),
            (_DATE_PATTERN, "a date in YYYY-MM-DD form"),
        )
    }


def _check(schema: JsonSchema, data: object, context: str) -> None:
    """Reject a document that breaks its published schema, naming the field."""
    problem = schema_problem(schema, data, context, formats=_formats())
    if problem is not None:
        location, message = problem
        message = f"{location} {message}"
        raise RegistryError(message)


def _fail(message: str) -> NoReturn:
    raise RegistryError(message)


def _date(text: str, context: str) -> str:
    """Reject a well-formed YYYY-MM-DD string that is not a calendar date."""
    try:
        date.fromisoformat(text)
    except ValueError as error:
        message = f"{context} must be an ISO 8601 calendar date"
        raise RegistryError(message) from error
    return text


def _unique(values: Sequence[object], context: str, what: str) -> None:
    if len(set(values)) != len(values):
        _fail(f"{context} must use unique {what}")


def parse_manifest(data: object, context: str = "index.yaml") -> RegistryManifest:
    """Validate one strict registry manifest mapping."""
    _check(registry_index_json_schema(), data, context)
    return _build_manifest(cast("dict[str, Any]", data), context)


def _build_manifest(manifest: dict[str, Any], context: str) -> RegistryManifest:
    paths = tuple(PurePosixPath(item) for item in manifest["rules"])
    coverage_paths = tuple(PurePosixPath(item) for item in manifest.get("coverage", []))
    release_path = (
        PurePosixPath(manifest["releases"]) if "releases" in manifest else None
    )
    all_paths = (*paths, *coverage_paths)
    if release_path is not None:
        all_paths = (*all_paths, release_path)
    if len(set(all_paths)) != len(all_paths):
        _fail(f"{context} registry file paths must be unique across sections")
    return RegistryManifest(
        release=manifest["release"],
        rule_paths=paths,
        coverage_paths=coverage_paths,
        retired_ids=tuple(manifest.get("retired_ids", [])),
        release_path=release_path,
    )


_RULE_BACKED_COVERAGE = frozenset(
    {
        CoverageDisposition.IMPLEMENTED,
        CoverageDisposition.PARTIAL,
        CoverageDisposition.DUPLICATE,
    }
)
_NOTE_REQUIRED_COVERAGE = frozenset(
    disposition
    for disposition in CoverageDisposition
    if disposition is not CoverageDisposition.IMPLEMENTED
)


def parse_coverage_manifest(
    data: object,
    context: str = "coverage.yaml",
) -> CoverageManifest:
    """Validate one closed authoritative-source coverage manifest."""
    _check(registry_coverage_json_schema(), data, context)
    return _build_coverage_manifest(cast("dict[str, Any]", data), context)


def _build_coverage_manifest(
    document: dict[str, Any], context: str
) -> CoverageManifest:
    source_data = document["source"]
    source = CoverageSource(
        id=source_data["id"],
        title=source_data["title"],
        url=source_data["url"],
        checked_on=_date(source_data["checked_on"], f"{context}.source.checked_on"),
    )
    entries = tuple(
        CoverageEntry(
            source_key=entry["source_key"],
            disposition=CoverageDisposition(entry["disposition"]),
            rules=tuple(entry.get("rules", [])),
            note=entry.get("note"),
        )
        for entry in document["entries"]
    )
    _unique(
        [entry.source_key for entry in entries],
        f"{context}.entries",
        "source_key values",
    )
    return CoverageManifest(
        source=source,
        source_keys=tuple(document["source_keys"]),
        entries=entries,
    )


def parse_release_metadata(
    data: object,
    context: str = "releases.yaml",
) -> tuple[PythonRelease, ...]:
    """Validate strict informative Python release metadata."""
    _check(registry_releases_json_schema(), data, context)
    return _build_release_metadata(cast("dict[str, Any]", data), context)


def _build_release_metadata(
    document: dict[str, Any], context: str
) -> tuple[PythonRelease, ...]:
    releases = tuple(
        PythonRelease(
            python=PythonMinor.parse(release["python"]),
            status=ReleaseStatus(release["status"]),
            released_on=(
                _date(
                    release["released_on"], f"{context}.releases[{index}].released_on"
                )
                if "released_on" in release
                else None
            ),
            expected_final_on=(
                _date(
                    release["expected_final_on"],
                    f"{context}.releases[{index}].expected_final_on",
                )
                if "expected_final_on" in release
                else None
            ),
            source=release.get("source"),
        )
        for index, release in enumerate(document["releases"])
    )
    if any(
        current.python >= following.python for current, following in pairwise(releases)
    ):
        _fail(f"{context}.releases must be strictly ordered by Python version")
    return releases


def _validate_timeline(events: tuple[RuleEvent, ...], context: str) -> None:
    if len({event.kind for event in events}) != len(events):
        _fail(f"{context} must not repeat an event kind")
    if any(
        current.python >= following.python for current, following in pairwise(events)
    ):
        _fail(f"{context} must be strictly ordered by increasing Python version")
    terminal_indexes = [
        index for index, event in enumerate(events) if event.kind in _TERMINAL_EVENTS
    ]
    if terminal_indexes and terminal_indexes != [len(events) - 1]:
        _fail(f"{context} may contain one terminal event, and it must be last")


def _parse_impact(
    impact: dict[str, Any],
    events: tuple[RuleEvent, ...],
    context: str,
) -> tuple[tuple[ChangeEventKind, Impact], ...]:
    """Pair impacts with events; the schema cannot see which events exist."""
    required = {_EVENT_IMPACT_KEYS[event.kind] for event in events}
    missing = sorted(required.difference(impact))
    if missing:
        _fail(f"{context} is missing required field(s): {', '.join(missing)}")
    return tuple(
        (kind, Impact(impact[key]))
        for kind, key in _EVENT_IMPACT_KEYS.items()
        if key in impact
    )


def _literal_argument(argument: dict[str, Any]) -> LiteralArgumentPredicate:
    return LiteralArgumentPredicate(
        position=argument.get("position"),
        keyword=argument.get("keyword"),
        equals=cast("LiteralValue", argument["equals"]),
    )


def _parse_call_shape(matcher: dict[str, Any], context: str) -> CallShapeMatcher:
    """Build a call shape and reject predicates that contradict each other."""
    minimum = matcher.get("min_positional_args")
    maximum = matcher.get("max_positional_args")
    min_keywords = matcher.get("min_keyword_args")
    max_keywords = matcher.get("max_keyword_args")
    required = tuple(matcher.get("required_keywords", []))
    forbidden = tuple(matcher.get("forbidden_keywords", []))
    literals = tuple(
        _literal_argument(item) for item in matcher.get("literal_arguments", [])
    )
    if minimum is not None and maximum is not None and minimum > maximum:
        _fail(f"{context} minimum positional count exceeds its maximum")
    if (
        min_keywords is not None
        and max_keywords is not None
        and (min_keywords > max_keywords)
    ):
        _fail(f"{context} minimum keyword count exceeds its maximum")
    if set(required).intersection(forbidden):
        _fail(f"{context} cannot both require and forbid a keyword")
    if max_keywords is not None and len(required) > max_keywords:
        _fail(f"{context} requires more keywords than its maximum allows")
    selectors = [
        ("position", item.position)
        if item.position is not None
        else ("keyword", item.keyword)
        for item in literals
    ]
    if len(set(selectors)) != len(selectors):
        _fail(f"{context}.literal_arguments must not repeat an argument")
    if any(item.keyword in forbidden for item in literals if item.keyword is not None):
        _fail(f"{context} cannot require a literal for a forbidden keyword")
    if maximum is not None and any(
        item.position is not None and item.position >= maximum for item in literals
    ):
        _fail(f"{context} positional literal is outside the maximum shape")
    return CallShapeMatcher(
        kind=MatcherKind.CALL_SHAPE,
        qualified_name=matcher["qualified_name"],
        min_positional_args=minimum,
        max_positional_args=maximum,
        min_keyword_args=min_keywords,
        max_keyword_args=max_keywords,
        required_keywords=required,
        forbidden_keywords=forbidden,
        literal_arguments=literals,
    )


def _parse_matcher(matcher: dict[str, Any], context: str) -> RuleMatcher:
    kind = MatcherKind(matcher["kind"])
    if kind is MatcherKind.MODULE_IMPORT:
        return ModuleImportMatcher(kind=kind, module=matcher["module"])
    if kind is MatcherKind.QUALIFIED_REFERENCE:
        return QualifiedReferenceMatcher(
            kind=kind,
            qualified_name=matcher["qualified_name"],
            contexts=tuple(
                ReferenceContext(item) for item in matcher.get("contexts", [])
            ),
        )
    if kind is MatcherKind.QUALIFIED_CALL:
        return QualifiedCallMatcher(kind=kind, qualified_name=matcher["qualified_name"])
    if kind is MatcherKind.CALL_SHAPE:
        return _parse_call_shape(matcher, context)
    if kind is MatcherKind.LITERAL_DYNAMIC_IMPORT:
        return LiteralDynamicImportMatcher(
            kind=kind,
            module=matcher["module"],
            confidence=MatchConfidence(
                matcher.get("confidence", MatchConfidence.MEDIUM.value)
            ),
        )
    return BuiltinPatternMatcher(kind=kind, pattern=BuiltinPattern(matcher["pattern"]))


def _literal_value(value: object, context: str) -> LiteralValue:
    """Reject the YAML-only scalars a JSON Schema cannot see: inf, nan."""
    if isinstance(value, float) and not math.isfinite(value):
        _fail(f"{context} must be a finite JSON scalar")
    return cast("LiteralValue", value)


def _remediation(remediation: dict[str, Any]) -> Remediation:
    automation = remediation.get("automation")
    return Remediation(
        summary=remediation["summary"],
        documentation_url=remediation.get("documentation_url"),
        automation=(
            AutomationReference(
                tool=AutomationTool(automation["tool"]), rule=automation["rule"]
            )
            if automation is not None
            else None
        ),
    )


def parse_rule(data: object, context: str) -> Rule:
    """Validate one rule mapping and convert it to the immutable domain model."""
    _check(registry_rule_json_schema(), data, context)
    return _build_rule(cast("dict[str, Any]", data), context)


def _build_rule(document: dict[str, Any], context: str) -> Rule:
    """Build a rule whose shape the schema has checked; check what it cannot."""
    identifier: str = document["id"]
    aliases = tuple(document.get("aliases", []))
    if identifier in aliases:
        _fail(f"{context}.aliases must be unique and differ from the canonical ID")
    events = tuple(
        RuleEvent(
            kind=ChangeEventKind(event["event"]),
            python=PythonMinor.parse(event["python"]),
            certainty=RegistryCertainty(event["certainty"]),
            source_id=event["source"],
        )
        for event in document["timeline"]
    )
    _validate_timeline(events, f"{context}.timeline")
    matchers = tuple(
        _parse_matcher(item, f"{context}.matchers[{index}]")
        for index, item in enumerate(document["matchers"])
    )
    for index, matcher in enumerate(matchers):
        if isinstance(matcher, CallShapeMatcher):
            for position, predicate in enumerate(matcher.literal_arguments):
                _literal_value(
                    predicate.equals,
                    f"{context}.matchers[{index}].literal_arguments[{position}].equals",
                )
    if len({_matcher_identity(matcher) for matcher in matchers}) != len(matchers):
        _fail(f"{context}.matchers must not contain duplicates")
    sources = tuple(
        SourceReference(id=source["id"], title=source["title"], url=source["url"])
        for source in document["sources"]
    )
    source_ids = [source.id for source in sources]
    _unique(source_ids, f"{context}.sources", "IDs")
    missing_sources = sorted(
        {event.source_id for event in events}.difference(source_ids)
    )
    if missing_sources:
        _fail(
            f"{context}.timeline references missing source(s): "
            f"{', '.join(missing_sources)}"
        )
    scope = document["scope"]
    subject = document["subject"]
    return Rule(
        id=identifier,
        aliases=aliases,
        title=document["title"],
        summary=document["summary"],
        ecosystem=scope["ecosystem"],
        runtime=scope["runtime"],
        subject_kind=SubjectKind(subject["kind"]),
        subject=subject["name"],
        contexts=tuple(UsageContext(item) for item in scope["contexts"]),
        events=events,
        event_impacts=_parse_impact(document["impact"], events, f"{context}.impact"),
        matchers=matchers,
        remediation=_remediation(document["remediation"]),
        sources=sources,
        tags=tuple(document["tags"]),
    )


def _literal_identity(value: LiteralValue) -> tuple[str, object]:
    """Preserve JSON scalar type identity where Python equality does not."""
    if value is None:
        return ("null", None)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int:
        return ("integer", value)
    if type(value) is float:
        return ("number", value)
    return ("string", value)


def _literal_argument_identity(
    predicate: LiteralArgumentPredicate,
) -> tuple[object, ...]:
    selector: tuple[str, object]
    if predicate.position is not None:
        selector = ("position", predicate.position)
    else:
        selector = ("keyword", predicate.keyword)
    return (*selector, *_literal_identity(predicate.equals))


def _matcher_identity(matcher: RuleMatcher) -> tuple[object, ...]:
    """Return a canonical, type-aware semantic identity for one matcher."""
    if isinstance(matcher, ModuleImportMatcher):
        return (matcher.kind.value, matcher.module)
    if isinstance(matcher, QualifiedReferenceMatcher):
        return (
            matcher.kind.value,
            matcher.qualified_name,
            tuple(sorted(context.value for context in matcher.contexts)),
        )
    if isinstance(matcher, QualifiedCallMatcher):
        return (matcher.kind.value, matcher.qualified_name)
    if isinstance(matcher, CallShapeMatcher):
        return (
            matcher.kind.value,
            matcher.qualified_name,
            matcher.min_positional_args,
            matcher.max_positional_args,
            matcher.min_keyword_args,
            matcher.max_keyword_args,
            tuple(sorted(matcher.required_keywords)),
            tuple(sorted(matcher.forbidden_keywords)),
            tuple(
                sorted(
                    _literal_argument_identity(predicate)
                    for predicate in matcher.literal_arguments
                )
            ),
        )
    if isinstance(matcher, LiteralDynamicImportMatcher):
        return (matcher.kind.value, matcher.module, matcher.confidence.value)
    return (matcher.kind.value, matcher.pattern.value)


def _object_schema(
    properties: JsonSchema,
    required: Sequence[str],
) -> JsonSchema:
    return {
        "additionalProperties": False,
        "properties": properties,
        "required": list(required),
        "type": "object",
    }


def _trimmed_string_schema() -> JsonSchema:
    return {
        "minLength": 1,
        "pattern": _json_schema_exact_pattern(_TRIMMED_STRING_PATTERN),
        "type": "string",
    }


def _json_schema_exact_pattern(pattern: str) -> str:
    """Anchor an ECMA-compatible pattern without ``$`` newline ambiguity."""
    return rf"^(?:{pattern})(?![\s\S])"


def _https_url_schema() -> JsonSchema:
    return {
        "format": "uri",
        "pattern": _json_schema_exact_pattern(_HTTPS_URL_PATTERN),
        "type": "string",
    }


def registry_index_json_schema() -> JsonSchema:
    """Generate the structural JSON Schema for ``index.yaml``."""
    return {
        "$id": "https://pyahead.dev/schema/registry-index-v1.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "coverage": {
                "default": [],
                "items": {
                    "pattern": _json_schema_exact_pattern(_RULE_PATH_PATTERN),
                    "type": "string",
                },
                "type": "array",
                "uniqueItems": True,
            },
            "release": _trimmed_string_schema(),
            "retired_ids": {
                "default": [],
                "items": {
                    "pattern": _json_schema_exact_pattern(RULE_ID_PATTERN),
                    "type": "string",
                },
                "type": "array",
                "uniqueItems": True,
            },
            "releases": {
                "pattern": _json_schema_exact_pattern(_RULE_PATH_PATTERN),
                "type": "string",
            },
            "rules": {
                "items": {
                    "pattern": _json_schema_exact_pattern(_RULE_PATH_PATTERN),
                    "type": "string",
                },
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "schema_version": {"const": 1, "type": "integer"},
        },
        "required": ["schema_version", "release", "rules"],
        "title": "PyAhead registry index schema version 1",
        "type": "object",
    }


def registry_coverage_json_schema() -> JsonSchema:
    """Generate the structural JSON Schema for coverage manifests."""
    rule_ids = {
        "items": {
            "pattern": _json_schema_exact_pattern(RULE_ID_PATTERN),
            "type": "string",
        },
        "type": "array",
        "uniqueItems": True,
    }
    rule_backed = [item.value for item in sorted(_RULE_BACKED_COVERAGE)]
    note_required = [item.value for item in sorted(_NOTE_REQUIRED_COVERAGE)]
    return {
        "$id": "https://pyahead.dev/schema/registry-coverage-v1.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "entry": {
                "additionalProperties": False,
                "allOf": [
                    {
                        "if": {
                            "properties": {
                                "disposition": {"enum": rule_backed},
                            },
                            "required": ["disposition"],
                        },
                        "then": {
                            "properties": {"rules": {**rule_ids, "minItems": 1}},
                            "required": ["rules"],
                        },
                        "else": {
                            "properties": {"rules": {**rule_ids, "maxItems": 0}},
                        },
                    },
                    {
                        "if": {
                            "properties": {
                                "disposition": {"enum": note_required},
                            },
                            "required": ["disposition"],
                        },
                        "then": {"required": ["note"]},
                    },
                ],
                "properties": {
                    "disposition": {
                        "enum": [item.value for item in CoverageDisposition],
                        "type": "string",
                    },
                    "note": _trimmed_string_schema(),
                    "rules": rule_ids,
                    "source_key": _trimmed_string_schema(),
                },
                "required": ["source_key", "disposition"],
                "type": "object",
            },
        },
        "additionalProperties": False,
        "properties": {
            "entries": {
                "items": {"$ref": "#/$defs/entry"},
                "minItems": 1,
                "type": "array",
            },
            "schema_version": {"const": 1, "type": "integer"},
            "source_keys": {
                "items": _trimmed_string_schema(),
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "source": _object_schema(
                {
                    "checked_on": {
                        "pattern": _json_schema_exact_pattern(_DATE_PATTERN),
                        "type": "string",
                    },
                    "id": {
                        "pattern": _json_schema_exact_pattern(_SOURCE_ID_PATTERN),
                        "type": "string",
                    },
                    "title": _trimmed_string_schema(),
                    "url": _https_url_schema(),
                },
                ["id", "title", "url", "checked_on"],
            ),
        },
        "required": ["schema_version", "source", "source_keys", "entries"],
        "title": "PyAhead registry coverage schema version 1",
        "type": "object",
        "x-pyahead-semantic-validation": [
            "source keys are unique within a manifest",
            "every audited source key has exactly one classification entry",
            "rule references resolve to canonical IDs",
            "every canonical rule is classified by at least one selected source",
        ],
    }


def registry_releases_json_schema() -> JsonSchema:
    """Generate the structural JSON Schema for ``releases.yaml``."""
    calendar_date = {
        "pattern": _json_schema_exact_pattern(_DATE_PATTERN),
        "type": "string",
    }
    return {
        "$id": "https://pyahead.dev/schema/registry-releases-v1.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "releases": {
                "items": _object_schema(
                    {
                        "expected_final_on": calendar_date,
                        "python": {
                            "pattern": _json_schema_exact_pattern(PYTHON_MINOR_PATTERN),
                            "type": "string",
                        },
                        "released_on": calendar_date,
                        "source": _https_url_schema(),
                        "status": {
                            "enum": [status.value for status in ReleaseStatus],
                            "type": "string",
                        },
                    },
                    ["python", "status"],
                ),
                "minItems": 1,
                "type": "array",
            },
            "schema_version": {"const": 1, "type": "integer"},
        },
        "required": ["schema_version", "releases"],
        "title": "PyAhead registry Python releases schema version 1",
        "type": "object",
        "x-pyahead-semantic-validation": [
            "dates are real calendar dates",
            "releases are strictly ordered by Python version",
        ],
    }


def _matcher_schemas() -> list[JsonSchema]:
    dotted_name = {
        "pattern": _json_schema_exact_pattern(_DOTTED_NAME_PATTERN),
        "type": "string",
    }
    reference_context = {
        "enum": [context.value for context in ReferenceContext],
        "type": "string",
    }
    literal = {
        "oneOf": [
            {"type": "boolean"},
            {"type": "number"},
            {
                "pattern": _json_schema_exact_pattern(_UNICODE_STRING_PATTERN),
                "type": "string",
            },
            {"type": "null"},
        ]
    }
    literal_argument_common: JsonSchema = {
        "equals": literal,
        "keyword": {
            "pattern": _json_schema_exact_pattern(_IDENTIFIER_PATTERN),
            "type": "string",
        },
        "position": {"minimum": 0, "type": "integer"},
    }
    keyword_array = {
        "items": {
            "pattern": _json_schema_exact_pattern(_IDENTIFIER_PATTERN),
            "type": "string",
        },
        "minItems": 1,
        "type": "array",
        "uniqueItems": True,
    }
    return [
        _object_schema(
            {
                "kind": {"const": MatcherKind.MODULE_IMPORT.value},
                "module": dotted_name,
            },
            ("kind", "module"),
        ),
        _object_schema(
            {
                "contexts": {
                    "items": reference_context,
                    "minItems": 1,
                    "type": "array",
                    "uniqueItems": True,
                },
                "kind": {"const": MatcherKind.QUALIFIED_REFERENCE.value},
                "qualified_name": dotted_name,
            },
            ("kind", "qualified_name"),
        ),
        _object_schema(
            {
                "kind": {"const": MatcherKind.QUALIFIED_CALL.value},
                "qualified_name": dotted_name,
            },
            ("kind", "qualified_name"),
        ),
        {
            **_object_schema(
                {
                    "forbidden_keywords": keyword_array,
                    "kind": {"const": MatcherKind.CALL_SHAPE.value},
                    "literal_arguments": {
                        "items": {
                            "oneOf": [
                                _object_schema(
                                    literal_argument_common,
                                    ("position", "equals"),
                                ),
                                _object_schema(
                                    literal_argument_common,
                                    ("keyword", "equals"),
                                ),
                            ]
                        },
                        "minItems": 1,
                        "type": "array",
                        "uniqueItems": True,
                    },
                    "max_keyword_args": {"minimum": 0, "type": "integer"},
                    "max_positional_args": {"minimum": 0, "type": "integer"},
                    "min_keyword_args": {"minimum": 1, "type": "integer"},
                    "min_positional_args": {"minimum": 0, "type": "integer"},
                    "qualified_name": dotted_name,
                    "required_keywords": keyword_array,
                },
                ("kind", "qualified_name"),
            ),
            "anyOf": [
                {"required": ["min_positional_args"]},
                {"required": ["max_positional_args"]},
                {"required": ["min_keyword_args"]},
                {"required": ["max_keyword_args"]},
                {"required": ["required_keywords"]},
                {"required": ["forbidden_keywords"]},
                {"required": ["literal_arguments"]},
            ],
        },
        _object_schema(
            {
                "confidence": {
                    "const": MatchConfidence.MEDIUM.value,
                    "default": MatchConfidence.MEDIUM.value,
                    "type": "string",
                },
                "kind": {"const": MatcherKind.LITERAL_DYNAMIC_IMPORT.value},
                "module": dotted_name,
            },
            ("kind", "module"),
        ),
        _object_schema(
            {
                "kind": {"const": MatcherKind.BUILTIN_PATTERN.value},
                "pattern": {
                    "enum": [pattern.value for pattern in BuiltinPattern],
                    "type": "string",
                },
            },
            ("kind", "pattern"),
        ),
    ]


def registry_rule_json_schema() -> JsonSchema:
    """Generate the structural JSON Schema for one registry rule."""
    event_kinds = [event.value for event in ChangeEventKind]
    impacts = [impact.value for impact in Impact]
    impact_properties = {
        key: {"enum": impacts, "type": "string"} for key in _EVENT_IMPACT_KEYS.values()
    }
    return {
        "$id": "https://pyahead.dev/schema/registry-rule-v1.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "automation": _object_schema(
                {
                    "rule": _trimmed_string_schema(),
                    "tool": {
                        "enum": [tool.value for tool in AutomationTool],
                        "type": "string",
                    },
                },
                ("tool", "rule"),
            ),
            "matcher": {"oneOf": _matcher_schemas()},
            "source": _object_schema(
                {
                    "id": {
                        "pattern": _json_schema_exact_pattern(_SOURCE_ID_PATTERN),
                        "type": "string",
                    },
                    "title": _trimmed_string_schema(),
                    "url": _https_url_schema(),
                },
                ("id", "title", "url"),
            ),
            "timeline_event": _object_schema(
                {
                    "certainty": {
                        "enum": [certainty.value for certainty in RegistryCertainty],
                        "type": "string",
                    },
                    "event": {"enum": event_kinds, "type": "string"},
                    "python": {
                        "pattern": _json_schema_exact_pattern(PYTHON_MINOR_PATTERN),
                        "type": "string",
                    },
                    "source": {
                        "pattern": _json_schema_exact_pattern(_SOURCE_ID_PATTERN),
                        "type": "string",
                    },
                },
                ("event", "python", "certainty", "source"),
            ),
        },
        "additionalProperties": False,
        "properties": {
            "aliases": {
                "items": {
                    "pattern": _json_schema_exact_pattern(RULE_ID_PATTERN),
                    "type": "string",
                },
                "type": "array",
                "uniqueItems": True,
            },
            "id": {
                "pattern": _json_schema_exact_pattern(RULE_ID_PATTERN),
                "type": "string",
            },
            "impact": {
                "additionalProperties": False,
                "minProperties": 1,
                "properties": impact_properties,
                "type": "object",
            },
            "matchers": {
                "items": {"$ref": "#/$defs/matcher"},
                "minItems": 1,
                "type": "array",
            },
            "remediation": _object_schema(
                {
                    "automation": {
                        "oneOf": [{"$ref": "#/$defs/automation"}, {"type": "null"}]
                    },
                    "documentation_url": _https_url_schema(),
                    "summary": _trimmed_string_schema(),
                },
                ("summary",),
            ),
            "schema_version": {"const": 1, "type": "integer"},
            "scope": _object_schema(
                {
                    "contexts": {
                        "items": {
                            "enum": [context.value for context in UsageContext],
                            "type": "string",
                        },
                        "minItems": 1,
                        "type": "array",
                        "uniqueItems": True,
                    },
                    "ecosystem": {"const": "python", "type": "string"},
                    "runtime": {"const": "cpython", "type": "string"},
                },
                ("ecosystem", "runtime", "contexts"),
            ),
            "sources": {
                "items": {"$ref": "#/$defs/source"},
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "subject": {
                **_object_schema(
                    {
                        "kind": {
                            "enum": [kind.value for kind in SubjectKind],
                            "type": "string",
                        },
                        "name": _trimmed_string_schema(),
                    },
                    ("kind", "name"),
                ),
                "allOf": [
                    {
                        "else": {
                            "properties": {
                                "name": {
                                    "pattern": _json_schema_exact_pattern(
                                        _DOTTED_NAME_PATTERN
                                    ),
                                    "type": "string",
                                }
                            }
                        },
                        "if": {
                            "properties": {"kind": {"const": SubjectKind.SYNTAX.value}},
                            "required": ["kind"],
                        },
                        "then": {"properties": {"name": _trimmed_string_schema()}},
                    }
                ],
            },
            "summary": _trimmed_string_schema(),
            "tags": {
                "items": {
                    "pattern": _json_schema_exact_pattern(_TAG_PATTERN),
                    "type": "string",
                },
                "type": "array",
                "uniqueItems": True,
            },
            "timeline": {
                "items": {"$ref": "#/$defs/timeline_event"},
                "minItems": 1,
                "type": "array",
                "uniqueItems": True,
            },
            "title": _trimmed_string_schema(),
        },
        "required": [
            "schema_version",
            "id",
            "title",
            "summary",
            "scope",
            "subject",
            "timeline",
            "impact",
            "matchers",
            "remediation",
            "sources",
            "tags",
        ],
        "title": "PyAhead registry rule schema version 1",
        "type": "object",
        "x-pyahead-semantic-validation": [
            "canonical IDs and aliases are unique across the registry",
            "the rule filename stem equals its canonical ID",
            "timeline events are unique, strictly ordered, and source-resolved",
            "call-shape predicates are internally consistent",
            (
                "matcher identities are type-exact and unique after normalizing "
                "set-like predicates"
            ),
        ],
    }


def render_json_schema(document: JsonSchema) -> str:
    """Render a generated schema deterministically."""
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_json_schemas(directory: Path) -> tuple[Path, Path]:
    """Write the generated registry schemas and return their paths."""
    directory.mkdir(parents=True, exist_ok=True)
    index_path = directory / "registry-index-v1.json"
    rule_path = directory / "registry-rule-v1.json"
    coverage_path = directory / "registry-coverage-v1.json"
    releases_path = directory / "registry-releases-v1.json"
    index_path.write_text(
        render_json_schema(registry_index_json_schema()), encoding="utf-8"
    )
    rule_path.write_text(
        render_json_schema(registry_rule_json_schema()), encoding="utf-8"
    )
    coverage_path.write_text(
        render_json_schema(registry_coverage_json_schema()), encoding="utf-8"
    )
    releases_path.write_text(
        render_json_schema(registry_releases_json_schema()), encoding="utf-8"
    )
    return index_path, rule_path


def _parser() -> SafeArgumentParser:
    """Build the terminal-safe registry-schema maintenance parser."""
    parser = SafeArgumentParser(prog="python -m pyahead.registry.schema")
    parser.add_argument("directory", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate the checked-in schemas for registry authors."""
    parser = _parser()
    arguments = parser.parse_args(argv)
    write_json_schemas(arguments.directory)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the function.
    raise SystemExit(main())
