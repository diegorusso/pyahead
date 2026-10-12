"""Check documents against PyAhead's published JSON Schemas.

Inputs PyAhead does not produce itself (author-supplied registries, pytest
warning evidence) are checked against the same schema that is published for
them, and the parsers then handle only what a schema cannot express. The
first problem is reported in PyAhead's own words, naming the field and never
echoing the offending value, which may be large or contain control text.
"""

from __future__ import annotations

import json
from functools import cache
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from jsonschema.exceptions import ValidationError

_TYPE_NAMES = {
    "array": "an array",
    "boolean": "a boolean",
    "integer": "an integer",
    "number": "a number",
    "object": "an object",
    "string": "a string",
}


@cache
def _validator(schema_json: str) -> Callable[[object], ValidationError | None]:
    # Imported on first use: most scans check no external document.
    from jsonschema import Draft202012Validator, validators  # noqa: PLC0415
    from jsonschema.exceptions import relevance  # noqa: PLC0415

    # JSON Schema counts 1.0 as an integer; PyAhead's documents never have.
    strict = validators.extend(  # type: ignore[no-untyped-call]
        Draft202012Validator,
        type_checker=Draft202012Validator.TYPE_CHECKER.redefine(
            "integer", lambda _checker, value: type(value) is int
        ),
    )
    validator = strict(json.loads(schema_json))

    def first_error(instance: object) -> ValidationError | None:
        error: ValidationError | None = max(
            validator.iter_errors(instance), key=relevance, default=None
        )
        # A oneOf/anyOf failure says only that no alternative fits; report
        # the closest alternative's own problem instead: the alternative
        # with the fewest problems, then the first listed.
        while error is not None and error.validator in {"oneOf", "anyOf"}:
            branches: dict[int, list[ValidationError]] = {}
            for problem in error.context or ():
                branch = cast("int", problem.relative_schema_path[0])
                branches.setdefault(branch, []).append(problem)
            if not branches:
                break
            closest = min(sorted(branches.items()), key=lambda item: len(item[1]))
            error = max(closest[1], key=relevance)
        return error

    return first_error


def _location(context: str, error: ValidationError) -> str:
    rendered = context
    for part in error.absolute_path:
        rendered += f"[{part}]" if isinstance(part, int) else f".{part}"
    return rendered


def _fields(names: Iterable[object]) -> str:
    return ", ".join(sorted(str(name) for name in names))


def _count(singular: str, plural: str) -> Callable[[object], str]:
    def render(expected: object) -> str:
        return singular if expected == 1 else plural.format(expected)

    return render


# How each keyword's expected value reads; the value itself is never shown.
_EXPECTATIONS: dict[str, Callable[[object], str]] = {
    "const": lambda expected: f"must equal {json.dumps(expected)}",
    "enum": lambda expected: (
        "must be one of: "
        + ", ".join(str(item) for item in cast("list[object]", expected))
    ),
    "minLength": _count("must not be empty", "needs at least {} characters"),
    "maxLength": lambda expected: f"must be at most {expected} characters",
    "pattern": lambda _expected: "has an invalid format",
    "minimum": lambda expected: f"must be at least {expected}",
    "maximum": lambda expected: f"must be at most {expected}",
    "minItems": _count("must not be empty", "needs at least {} items"),
    "maxItems": lambda expected: f"must contain at most {expected} items",
    "uniqueItems": lambda _expected: "must not contain duplicates",
}


def _message(error: ValidationError, formats: Mapping[str, str]) -> str:
    keyword = str(error.validator)
    expected: object = error.validator_value
    instance: object = error.instance
    if keyword == "pattern" and isinstance(expected, str) and expected in formats:
        return f"must be {formats[expected]}"
    if keyword == "type":
        names = [expected] if isinstance(expected, str) else cast("list[str]", expected)
        return "must be " + " or ".join(_TYPE_NAMES.get(n, n) for n in names)
    if keyword == "required" and isinstance(instance, dict):
        required = cast("list[str]", expected)
        missing = [name for name in required if name not in instance]
        return f"is missing required field(s): {_fields(missing)}"
    if keyword == "additionalProperties" and isinstance(instance, dict):
        schema = cast("dict[str, dict[str, object]]", error.schema)
        known = set(schema.get("properties", {}))
        return f"contains unknown field(s): {_fields(set(instance) - known)}"
    render = _EXPECTATIONS.get(keyword)
    return render(expected) if render is not None else "does not match the schema"


def schema_problem(
    schema: Mapping[str, object],
    instance: object,
    context: str,
    *,
    formats: Mapping[str, str] | None = None,
) -> tuple[str, str] | None:
    """Return where and how ``instance`` first breaks ``schema``, or ``None``.

    The location is ``context`` followed by the field path, as in
    ``rule x.timeline[0].python``; callers phrase the error their own way.
    ``formats`` names what a schema pattern stands for, so a mismatch reads
    "must be a dotted Python name" rather than "has an invalid format".
    """
    error = _validator(json.dumps(schema, sort_keys=True))(instance)
    if error is None:
        return None
    return _location(context, error), _message(error, formats or {})
