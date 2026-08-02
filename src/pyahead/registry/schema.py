"""Strict schema parsing and JSON Schema generation for registry version 1."""

import argparse
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import TypeAlias, TypeVar, cast

from pyahead.model import (
    AutomationReference,
    AutomationTool,
    BuiltinPattern,
    BuiltinPatternMatcher,
    CallShapeMatcher,
    ChangeEventKind,
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
    InvalidPythonMinorError,
    PythonMinor,
)

RULE_ID_PATTERN = r"CPY[0-9]{4}"
_RULE_ID_RE = re.compile(f"{RULE_ID_PATTERN}\\Z")
_DOTTED_NAME_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
_DOTTED_NAME_RE = re.compile(f"{_DOTTED_NAME_PATTERN}\\Z")
_SOURCE_ID_PATTERN = r"[a-z0-9][a-z0-9.-]*"
_SOURCE_ID_RE = re.compile(f"{_SOURCE_ID_PATTERN}\\Z")
_TAG_PATTERN = r"[a-z0-9][a-z0-9-]*"
_TAG_RE = re.compile(f"{_TAG_PATTERN}\\Z")
# The union of Python ``str.isspace()`` and ECMAScript whitespace makes
# canonical registry boundaries independent of the regex engine used by a
# Draft 2020-12 JSON Schema consumer. Interior whitespace remains permitted.
_REGISTRY_WHITESPACE_CLASS = (
    r"\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680"
    r"\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_SURROGATE_CLASS = r"\ud800-\udfff"
_NON_REGISTRY_WHITESPACE = rf"[^{_REGISTRY_WHITESPACE_CLASS}]"
_TRIMMED_STRING_PATTERN = (
    rf"(?![\s\S]*[{_SURROGATE_CLASS}])"
    rf"{_NON_REGISTRY_WHITESPACE}"
    rf"(?:[\s\S]*{_NON_REGISTRY_WHITESPACE})?"
)
_TERMINAL_WHITESPACE_RE = re.compile(rf"[{_REGISTRY_WHITESPACE_CLASS}]\Z")
_SURROGATE_RE = re.compile(rf"[{_SURROGATE_CLASS}]")
_RULE_PATH_SEGMENT_PATTERN = r"[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_-])?"
_RULE_PATH_PATTERN = (
    rf"(?:{_RULE_PATH_SEGMENT_PATTERN}/)*"
    rf"{_RULE_PATH_SEGMENT_PATTERN}\.ya?ml"
)
_RULE_PATH_RE = re.compile(f"{_RULE_PATH_PATTERN}\\Z")
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
_HTTPS_URL_RE = re.compile(f"(?:{_HTTPS_URL_PATTERN})\\Z")

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
_StrEnumT = TypeVar("_StrEnumT", bound=StrEnum)


class RegistryError(ValueError):
    """Raised when registry data does not satisfy the closed schema."""


@dataclass(frozen=True)
class RegistryManifest:
    """Validated index data used by the registry loader."""

    release: str
    rule_paths: tuple[PurePosixPath, ...]
    retired_ids: tuple[str, ...]
    release_path: PurePosixPath | None


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        message = f"{context} must be a mapping with string keys"
        raise RegistryError(message)
    return cast("dict[str, object]", value)


def _sequence(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        message = f"{context} must be a list"
        raise RegistryError(message)
    return cast("list[object]", value)


def _fields(
    data: Mapping[str, object],
    context: str,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    missing = sorted(required.difference(data))
    if missing:
        message = f"{context} is missing required field(s): {', '.join(missing)}"
        raise RegistryError(message)
    unknown = sorted(set(data).difference(required | optional))
    if unknown:
        message = f"{context} contains unknown field(s): {', '.join(unknown)}"
        raise RegistryError(message)


def _string(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or _SURROGATE_RE.search(value) is not None
        or _TERMINAL_WHITESPACE_RE.fullmatch(value[0]) is not None
        or _TERMINAL_WHITESPACE_RE.fullmatch(value[-1]) is not None
    ):
        message = f"{context} must be a non-empty, trimmed string"
        raise RegistryError(message)
    return value


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        message = f"{context} must be an integer greater than or equal to {minimum}"
        raise RegistryError(message)
    return value


def _schema_version(value: object, context: str) -> None:
    if type(value) is not int or value != 1:
        message = f"{context}.schema_version must equal 1"
        raise RegistryError(message)


def _enum_value(
    value: object,
    enum_type: type[_StrEnumT],
    context: str,
) -> _StrEnumT:
    if not isinstance(value, str):
        message = f"{context} must be a string"
        raise RegistryError(message)
    try:
        return enum_type(value)
    except ValueError as error:
        message = f"{context} contains an unsupported value {value!r}"
        raise RegistryError(message) from error


def _unique_strings(
    value: object,
    context: str,
    *,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    items = _sequence(value, context)
    if not allow_empty and not items:
        message = f"{context} must not be empty"
        raise RegistryError(message)
    strings = tuple(
        _string(item, f"{context}[{index}]") for index, item in enumerate(items)
    )
    if pattern is not None and any(pattern.fullmatch(item) is None for item in strings):
        message = f"{context} contains an invalid value"
        raise RegistryError(message)
    if len(set(strings)) != len(strings):
        message = f"{context} must not contain duplicates"
        raise RegistryError(message)
    return strings


def _https_url(value: object, context: str) -> str:
    url = _string(value, context)
    message = f"{context} must be a direct HTTPS URL without credentials"
    if _HTTPS_URL_RE.fullmatch(url) is None:
        raise RegistryError(message)
    return url


def _dotted_name(value: object, context: str) -> str:
    name = _string(value, context)
    if _DOTTED_NAME_RE.fullmatch(name) is None:
        message = f"{context} must be a dotted Python name"
        raise RegistryError(message)
    return name


def _rule_id(value: object, context: str) -> str:
    identifier = _string(value, context)
    if _RULE_ID_RE.fullmatch(identifier) is None:
        message = f"{context} must use the CPY0000 format"
        raise RegistryError(message)
    return identifier


def _safe_rule_path(value: object, context: str) -> PurePosixPath:
    text = _string(value, context)
    if _RULE_PATH_RE.fullmatch(text) is None:
        message = f"{context} contains unsafe registry rule path {text!r}"
        raise RegistryError(message)
    return PurePosixPath(text)


def parse_manifest(data: object, context: str = "index.yaml") -> RegistryManifest:
    """Validate one strict registry manifest mapping."""
    manifest = _mapping(data, context)
    _fields(
        manifest,
        context,
        required=frozenset({"schema_version", "release", "rules"}),
        optional=frozenset({"releases", "retired_ids"}),
    )
    _schema_version(manifest["schema_version"], context)
    raw_paths = _sequence(manifest["rules"], f"{context}.rules")
    if not raw_paths:
        message = f"{context}.rules must not be empty"
        raise RegistryError(message)
    paths = tuple(
        _safe_rule_path(item, f"{context}.rules[{index}]")
        for index, item in enumerate(raw_paths)
    )
    if len(set(paths)) != len(paths):
        message = f"{context}.rules must not contain duplicates"
        raise RegistryError(message)
    retired_ids = tuple(
        _rule_id(item, f"{context}.retired_ids[{index}]")
        for index, item in enumerate(
            _sequence(manifest.get("retired_ids", []), f"{context}.retired_ids")
        )
    )
    if len(set(retired_ids)) != len(retired_ids):
        message = f"{context}.retired_ids must not contain duplicates"
        raise RegistryError(message)
    return RegistryManifest(
        release=_string(manifest["release"], f"{context}.release"),
        rule_paths=paths,
        retired_ids=retired_ids,
        release_path=(
            _safe_rule_path(manifest["releases"], f"{context}.releases")
            if "releases" in manifest
            else None
        ),
    )


def _date(value: object, context: str) -> str:
    text = _string(value, context)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as error:
        message = f"{context} must be an ISO 8601 calendar date"
        raise RegistryError(message) from error
    if parsed.isoformat() != text:
        message = f"{context} must use canonical YYYY-MM-DD form"
        raise RegistryError(message)
    return text


def parse_release_metadata(
    data: object,
    context: str = "releases.yaml",
) -> tuple[PythonRelease, ...]:
    """Validate strict informative Python release metadata."""
    document = _mapping(data, context)
    _fields(
        document,
        context,
        required=frozenset({"schema_version", "releases"}),
    )
    _schema_version(document["schema_version"], context)
    raw_releases = _sequence(document["releases"], f"{context}.releases")
    if not raw_releases:
        message = f"{context}.releases must not be empty"
        raise RegistryError(message)

    releases: list[PythonRelease] = []
    for index, value in enumerate(raw_releases):
        release_context = f"{context}.releases[{index}]"
        release = _mapping(value, release_context)
        _fields(
            release,
            release_context,
            required=frozenset({"python", "status"}),
            optional=frozenset({"expected_final_on", "released_on", "source"}),
        )
        try:
            python = PythonMinor.parse(
                _string(release["python"], f"{release_context}.python")
            )
        except InvalidPythonMinorError as error:
            message = f"{release_context}.python must be a Python minor such as '3.13'"
            raise RegistryError(message) from error
        releases.append(
            PythonRelease(
                python=python,
                status=_enum_value(
                    release["status"],
                    ReleaseStatus,
                    f"{release_context}.status",
                ),
                released_on=(
                    _date(release["released_on"], f"{release_context}.released_on")
                    if "released_on" in release
                    else None
                ),
                expected_final_on=(
                    _date(
                        release["expected_final_on"],
                        f"{release_context}.expected_final_on",
                    )
                    if "expected_final_on" in release
                    else None
                ),
                source=(
                    _https_url(release["source"], f"{release_context}.source")
                    if "source" in release
                    else None
                ),
            )
        )
    if any(
        current.python >= following.python for current, following in pairwise(releases)
    ):
        message = f"{context}.releases must be strictly ordered by Python version"
        raise RegistryError(message)
    return tuple(releases)


def _parse_scope(
    value: object, context: str
) -> tuple[str, str, tuple[UsageContext, ...]]:
    scope = _mapping(value, context)
    _fields(
        scope,
        context,
        required=frozenset({"ecosystem", "runtime", "contexts"}),
    )
    ecosystem = _string(scope["ecosystem"], f"{context}.ecosystem")
    runtime = _string(scope["runtime"], f"{context}.runtime")
    if ecosystem != "python" or runtime != "cpython":
        message = (
            f"{context} supports only the python/cpython scope in schema version 1"
        )
        raise RegistryError(message)
    raw_contexts = _sequence(scope["contexts"], f"{context}.contexts")
    if not raw_contexts:
        message = f"{context}.contexts must not be empty"
        raise RegistryError(message)
    contexts = tuple(
        _enum_value(item, UsageContext, f"{context}.contexts[{index}]")
        for index, item in enumerate(raw_contexts)
    )
    if len(set(contexts)) != len(contexts):
        message = f"{context}.contexts must not contain duplicates"
        raise RegistryError(message)
    return ecosystem, runtime, contexts


def _parse_subject(value: object, context: str) -> tuple[SubjectKind, str]:
    subject = _mapping(value, context)
    _fields(subject, context, required=frozenset({"kind", "name"}))
    kind = _enum_value(subject["kind"], SubjectKind, f"{context}.kind")
    name = _string(subject["name"], f"{context}.name")
    if kind is not SubjectKind.SYNTAX and _DOTTED_NAME_RE.fullmatch(name) is None:
        message = (
            f"{context}.name must be a dotted Python name for {kind.value} subjects"
        )
        raise RegistryError(message)
    return kind, name


def _parse_event(value: object, context: str) -> RuleEvent:
    event = _mapping(value, context)
    _fields(
        event,
        context,
        required=frozenset({"event", "python", "certainty", "source"}),
    )
    try:
        python = PythonMinor.parse(_string(event["python"], f"{context}.python"))
    except InvalidPythonMinorError as error:
        message = f"{context}.python must be a Python minor such as '3.13'"
        raise RegistryError(message) from error
    source_id = _string(event["source"], f"{context}.source")
    if _SOURCE_ID_RE.fullmatch(source_id) is None:
        message = f"{context}.source must be a lowercase source ID"
        raise RegistryError(message)
    return RuleEvent(
        kind=_enum_value(event["event"], ChangeEventKind, f"{context}.event"),
        python=python,
        certainty=_enum_value(
            event["certainty"], RegistryCertainty, f"{context}.certainty"
        ),
        source_id=source_id,
    )


def _validate_timeline(events: tuple[RuleEvent, ...], context: str) -> None:
    if not events:
        message = f"{context} must not be empty"
        raise RegistryError(message)
    if len({event.kind for event in events}) != len(events):
        message = f"{context} must not repeat an event kind"
        raise RegistryError(message)
    if any(
        current.python >= following.python for current, following in pairwise(events)
    ):
        message = f"{context} must be strictly ordered by increasing Python version"
        raise RegistryError(message)
    terminal_indexes = [
        index for index, event in enumerate(events) if event.kind in _TERMINAL_EVENTS
    ]
    if terminal_indexes and terminal_indexes != [len(events) - 1]:
        message = f"{context} may contain one terminal event, and it must be last"
        raise RegistryError(message)


def _parse_impact(
    value: object,
    events: tuple[RuleEvent, ...],
    context: str,
) -> tuple[tuple[ChangeEventKind, Impact], ...]:
    impact = _mapping(value, context)
    allowed = frozenset(_EVENT_IMPACT_KEYS.values())
    required = frozenset(_EVENT_IMPACT_KEYS[event.kind] for event in events)
    _fields(impact, context, required=required, optional=allowed - required)
    parsed: list[tuple[ChangeEventKind, Impact]] = []
    for kind, key in _EVENT_IMPACT_KEYS.items():
        if key in impact:
            parsed.append((kind, _enum_value(impact[key], Impact, f"{context}.{key}")))
    return tuple(parsed)


def _parse_reference_contexts(
    value: object, context: str
) -> tuple[ReferenceContext, ...]:
    raw_contexts = _sequence(value, context)
    if not raw_contexts:
        message = f"{context} must not be empty when provided"
        raise RegistryError(message)
    contexts = tuple(
        _enum_value(item, ReferenceContext, f"{context}[{index}]")
        for index, item in enumerate(raw_contexts)
    )
    if len(set(contexts)) != len(contexts):
        message = f"{context} must not contain duplicates"
        raise RegistryError(message)
    return contexts


def _parse_literal(value: object, context: str) -> LiteralValue:
    if value is None or type(value) in {bool, float, int, str}:
        if isinstance(value, float) and not math.isfinite(value):
            message = f"{context} must be a finite JSON scalar"
            raise RegistryError(message)
        if isinstance(value, str) and _SURROGATE_RE.search(value) is not None:
            message = f"{context} must not contain an invalid Unicode surrogate"
            raise RegistryError(message)
        return cast("LiteralValue", value)
    message = f"{context} must be a JSON scalar literal"
    raise RegistryError(message)


def _parse_literal_argument(value: object, context: str) -> LiteralArgumentPredicate:
    argument = _mapping(value, context)
    _fields(
        argument,
        context,
        required=frozenset({"equals"}),
        optional=frozenset({"position", "keyword"}),
    )
    has_position = "position" in argument
    has_keyword = "keyword" in argument
    if has_position == has_keyword:
        message = f"{context} must select exactly one of position or keyword"
        raise RegistryError(message)
    position = (
        _integer(argument["position"], f"{context}.position") if has_position else None
    )
    keyword = (
        _dotted_name(argument["keyword"], f"{context}.keyword") if has_keyword else None
    )
    if keyword is not None and "." in keyword:
        message = f"{context}.keyword must be one Python identifier"
        raise RegistryError(message)
    return LiteralArgumentPredicate(
        position=position,
        keyword=keyword,
        equals=_parse_literal(argument["equals"], f"{context}.equals"),
    )


_CALL_SHAPE_FIELDS = frozenset(
    {
        "min_positional_args",
        "max_positional_args",
        "required_keywords",
        "forbidden_keywords",
        "literal_arguments",
    }
)


def _call_shape_bounds(
    matcher: Mapping[str, object],
    context: str,
) -> tuple[int | None, int | None]:
    minimum = (
        _integer(
            matcher["min_positional_args"],
            f"{context}.min_positional_args",
        )
        if "min_positional_args" in matcher
        else None
    )
    maximum = (
        _integer(
            matcher["max_positional_args"],
            f"{context}.max_positional_args",
        )
        if "max_positional_args" in matcher
        else None
    )
    if minimum is not None and maximum is not None and minimum > maximum:
        message = f"{context} minimum positional count exceeds its maximum"
        raise RegistryError(message)
    return minimum, maximum


def _call_shape_keywords(
    matcher: Mapping[str, object],
    context: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    required = (
        _unique_strings(
            matcher["required_keywords"],
            f"{context}.required_keywords",
            pattern=_DOTTED_NAME_RE,
            allow_empty=False,
        )
        if "required_keywords" in matcher
        else ()
    )
    forbidden = (
        _unique_strings(
            matcher["forbidden_keywords"],
            f"{context}.forbidden_keywords",
            pattern=_DOTTED_NAME_RE,
            allow_empty=False,
        )
        if "forbidden_keywords" in matcher
        else ()
    )
    if any("." in keyword for keyword in required + forbidden):
        message = f"{context} keyword predicates must use single identifiers"
        raise RegistryError(message)
    if set(required).intersection(forbidden):
        message = f"{context} cannot both require and forbid a keyword"
        raise RegistryError(message)
    return required, forbidden


def _call_shape_literals(
    matcher: Mapping[str, object],
    context: str,
    forbidden_keywords: tuple[str, ...],
    maximum: int | None,
) -> tuple[LiteralArgumentPredicate, ...]:
    raw_literals = (
        _sequence(matcher["literal_arguments"], f"{context}.literal_arguments")
        if "literal_arguments" in matcher
        else ()
    )
    if "literal_arguments" in matcher and not raw_literals:
        message = f"{context}.literal_arguments must not be empty"
        raise RegistryError(message)
    literals = tuple(
        _parse_literal_argument(item, f"{context}.literal_arguments[{index}]")
        for index, item in enumerate(raw_literals)
    )
    literal_keys = tuple(
        ("position", item.position)
        if item.position is not None
        else ("keyword", item.keyword)
        for item in literals
    )
    if len(set(literal_keys)) != len(literal_keys):
        message = f"{context}.literal_arguments must not repeat an argument"
        raise RegistryError(message)
    if any(
        item.keyword in forbidden_keywords
        for item in literals
        if item.keyword is not None
    ):
        message = f"{context} cannot require a literal for a forbidden keyword"
        raise RegistryError(message)
    if maximum is not None and any(
        item.position is not None and item.position >= maximum for item in literals
    ):
        message = f"{context} positional literal is outside the maximum shape"
        raise RegistryError(message)
    return literals


def _parse_call_shape(
    matcher: Mapping[str, object],
    kind: MatcherKind,
    context: str,
) -> CallShapeMatcher:
    _fields(
        matcher,
        context,
        required=frozenset({"kind", "qualified_name"}),
        optional=_CALL_SHAPE_FIELDS,
    )
    if not set(matcher).intersection(_CALL_SHAPE_FIELDS):
        message = f"{context} must declare at least one call-shape predicate"
        raise RegistryError(message)
    minimum, maximum = _call_shape_bounds(matcher, context)
    required_keywords, forbidden_keywords = _call_shape_keywords(matcher, context)
    literal_arguments = _call_shape_literals(
        matcher, context, forbidden_keywords, maximum
    )
    if (
        minimum is None
        and maximum is None
        and not required_keywords
        and not forbidden_keywords
        and not literal_arguments
    ):
        message = f"{context} must declare at least one effective call-shape predicate"
        raise RegistryError(message)
    return CallShapeMatcher(
        kind=kind,
        qualified_name=_dotted_name(
            matcher["qualified_name"], f"{context}.qualified_name"
        ),
        min_positional_args=minimum,
        max_positional_args=maximum,
        required_keywords=required_keywords,
        forbidden_keywords=forbidden_keywords,
        literal_arguments=literal_arguments,
    )


def _parse_matcher(value: object, context: str) -> RuleMatcher:
    matcher = _mapping(value, context)
    if "kind" not in matcher:
        message = f"{context} is missing required field(s): kind"
        raise RegistryError(message)
    kind = _enum_value(matcher["kind"], MatcherKind, f"{context}.kind")
    if kind is MatcherKind.MODULE_IMPORT:
        _fields(matcher, context, required=frozenset({"kind", "module"}))
        return ModuleImportMatcher(
            kind=kind,
            module=_dotted_name(matcher["module"], f"{context}.module"),
        )
    if kind is MatcherKind.QUALIFIED_REFERENCE:
        _fields(
            matcher,
            context,
            required=frozenset({"kind", "qualified_name"}),
            optional=frozenset({"contexts"}),
        )
        contexts = (
            _parse_reference_contexts(matcher["contexts"], f"{context}.contexts")
            if "contexts" in matcher
            else ()
        )
        return QualifiedReferenceMatcher(
            kind=kind,
            qualified_name=_dotted_name(
                matcher["qualified_name"], f"{context}.qualified_name"
            ),
            contexts=contexts,
        )
    if kind is MatcherKind.QUALIFIED_CALL:
        _fields(
            matcher,
            context,
            required=frozenset({"kind", "qualified_name"}),
        )
        return QualifiedCallMatcher(
            kind=kind,
            qualified_name=_dotted_name(
                matcher["qualified_name"], f"{context}.qualified_name"
            ),
        )
    if kind is MatcherKind.CALL_SHAPE:
        return _parse_call_shape(matcher, kind, context)
    if kind is MatcherKind.LITERAL_DYNAMIC_IMPORT:
        _fields(
            matcher,
            context,
            required=frozenset({"kind", "module"}),
            optional=frozenset({"confidence"}),
        )
        confidence = _enum_value(
            matcher.get("confidence", MatchConfidence.MEDIUM.value),
            MatchConfidence,
            f"{context}.confidence",
        )
        if confidence is not MatchConfidence.MEDIUM:
            message = f"{context}.confidence must be medium for literal dynamic imports"
            raise RegistryError(message)
        return LiteralDynamicImportMatcher(
            kind=kind,
            module=_dotted_name(matcher["module"], f"{context}.module"),
            confidence=confidence,
        )
    _fields(matcher, context, required=frozenset({"kind", "pattern"}))
    return BuiltinPatternMatcher(
        kind=kind,
        pattern=_enum_value(matcher["pattern"], BuiltinPattern, f"{context}.pattern"),
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


def _parse_remediation(value: object, context: str) -> Remediation:
    remediation = _mapping(value, context)
    _fields(
        remediation,
        context,
        required=frozenset({"summary"}),
        optional=frozenset({"documentation_url", "automation"}),
    )
    documentation_url = (
        _https_url(remediation["documentation_url"], f"{context}.documentation_url")
        if "documentation_url" in remediation
        else None
    )
    raw_automation = remediation.get("automation")
    automation: AutomationReference | None = None
    if raw_automation is not None:
        automation_data = _mapping(raw_automation, f"{context}.automation")
        _fields(
            automation_data,
            f"{context}.automation",
            required=frozenset({"tool", "rule"}),
        )
        automation = AutomationReference(
            tool=_enum_value(
                automation_data["tool"],
                AutomationTool,
                f"{context}.automation.tool",
            ),
            rule=_string(automation_data["rule"], f"{context}.automation.rule"),
        )
    return Remediation(
        summary=_string(remediation["summary"], f"{context}.summary"),
        documentation_url=documentation_url,
        automation=automation,
    )


def _parse_source(value: object, context: str) -> SourceReference:
    source = _mapping(value, context)
    _fields(
        source,
        context,
        required=frozenset({"id", "title", "url"}),
    )
    source_id = _string(source["id"], f"{context}.id")
    if _SOURCE_ID_RE.fullmatch(source_id) is None:
        message = f"{context}.id must be a lowercase source ID"
        raise RegistryError(message)
    return SourceReference(
        id=source_id,
        title=_string(source["title"], f"{context}.title"),
        url=_https_url(source["url"], f"{context}.url"),
    )


def parse_rule(data: object, context: str) -> Rule:
    """Validate one rule mapping and convert it to the immutable domain model."""
    document = _mapping(data, context)
    _fields(
        document,
        context,
        required=frozenset(
            {
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
            }
        ),
        optional=frozenset({"aliases"}),
    )
    _schema_version(document["schema_version"], context)
    identifier = _rule_id(document["id"], f"{context}.id")
    aliases = tuple(
        _rule_id(item, f"{context}.aliases[{index}]")
        for index, item in enumerate(
            _sequence(document.get("aliases", []), f"{context}.aliases")
        )
    )
    if identifier in aliases or len(set(aliases)) != len(aliases):
        message = f"{context}.aliases must be unique and differ from the canonical ID"
        raise RegistryError(message)
    ecosystem, runtime, contexts = _parse_scope(document["scope"], f"{context}.scope")
    subject_kind, subject = _parse_subject(document["subject"], f"{context}.subject")
    events = tuple(
        _parse_event(item, f"{context}.timeline[{index}]")
        for index, item in enumerate(
            _sequence(document["timeline"], f"{context}.timeline")
        )
    )
    _validate_timeline(events, f"{context}.timeline")
    matchers = tuple(
        _parse_matcher(item, f"{context}.matchers[{index}]")
        for index, item in enumerate(
            _sequence(document["matchers"], f"{context}.matchers")
        )
    )
    if not matchers:
        message = f"{context}.matchers must not be empty"
        raise RegistryError(message)
    if len({_matcher_identity(matcher) for matcher in matchers}) != len(matchers):
        message = f"{context}.matchers must not contain duplicates"
        raise RegistryError(message)
    sources = tuple(
        _parse_source(item, f"{context}.sources[{index}]")
        for index, item in enumerate(
            _sequence(document["sources"], f"{context}.sources")
        )
    )
    if not sources:
        message = f"{context}.sources must not be empty"
        raise RegistryError(message)
    source_ids = tuple(source.id for source in sources)
    if len(set(source_ids)) != len(source_ids):
        message = f"{context}.sources must use unique IDs"
        raise RegistryError(message)
    missing_sources = sorted(
        {event.source_id for event in events}.difference(source_ids)
    )
    if missing_sources:
        message = (
            f"{context}.timeline references missing source(s): "
            f"{', '.join(missing_sources)}"
        )
        raise RegistryError(message)
    tags = _unique_strings(
        document["tags"],
        f"{context}.tags",
        pattern=_TAG_RE,
    )
    return Rule(
        id=identifier,
        aliases=aliases,
        title=_string(document["title"], f"{context}.title"),
        summary=_string(document["summary"], f"{context}.summary"),
        ecosystem=ecosystem,
        runtime=runtime,
        subject_kind=subject_kind,
        subject=subject,
        contexts=contexts,
        events=events,
        event_impacts=_parse_impact(document["impact"], events, f"{context}.impact"),
        matchers=matchers,
        remediation=_parse_remediation(
            document["remediation"], f"{context}.remediation"
        ),
        sources=sources,
        tags=tags,
    )


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
                "pattern": _json_schema_exact_pattern(
                    rf"(?![\s\S]*[{_SURROGATE_CLASS}])[\s\S]*"
                ),
                "type": "string",
            },
            {"type": "null"},
        ]
    }
    literal_argument_common: JsonSchema = {
        "equals": literal,
        "keyword": {
            "pattern": _json_schema_exact_pattern(r"[A-Za-z_][A-Za-z0-9_]*"),
            "type": "string",
        },
        "position": {"minimum": 0, "type": "integer"},
    }
    keyword_array = {
        "items": {
            "pattern": _json_schema_exact_pattern(r"[A-Za-z_][A-Za-z0-9_]*"),
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
                    "max_positional_args": {"minimum": 0, "type": "integer"},
                    "min_positional_args": {"minimum": 0, "type": "integer"},
                    "qualified_name": dotted_name,
                    "required_keywords": keyword_array,
                },
                ("kind", "qualified_name"),
            ),
            "anyOf": [
                {"required": ["min_positional_args"]},
                {"required": ["max_positional_args"]},
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
    """Write both generated registry schemas to an existing directory."""
    directory.mkdir(parents=True, exist_ok=True)
    index_path = directory / "registry-index-v1.json"
    rule_path = directory / "registry-rule-v1.json"
    index_path.write_text(
        render_json_schema(registry_index_json_schema()), encoding="utf-8"
    )
    rule_path.write_text(
        render_json_schema(registry_rule_json_schema()), encoding="utf-8"
    )
    return index_path, rule_path


def main(argv: list[str] | None = None) -> int:
    """Generate the checked-in schemas for registry authors."""
    parser = argparse.ArgumentParser(prog="python -m pyahead.registry.schema")
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args(argv)
    write_json_schemas(arguments.directory)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the function.
    raise SystemExit(main())
