"""Schema problems read as PyAhead messages and never echo the value."""

import pytest

from pyahead._schema_check import schema_problem

_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": False,
    "properties": {
        "name": {
            "maxLength": 8,
            "minLength": 1,
            "pattern": "^[a-z]+$",
            "type": "string",
        },
        "kind": {"enum": ["alpha", "beta"], "type": "string"},
        "version": {"const": 1, "type": "integer"},
        "count": {"maximum": 9, "minimum": 1, "type": "integer"},
        "items": {
            "items": {"type": "string"},
            "maxItems": 2,
            "minItems": 1,
            "type": "array",
            "uniqueItems": True,
        },
    },
    "required": ["name", "version"],
    "type": "object",
}
_VALID = {"name": "ok", "version": 1}


@pytest.mark.parametrize(
    ("instance", "location", "message"),
    [
        ([], "doc", "must be an object"),
        ({}, "doc", "is missing required field(s): name, version"),
        ({**_VALID, "zz": 1, "aa": 2}, "doc", "contains unknown field(s): aa, zz"),
        ({**_VALID, "version": 2}, "doc.version", "must equal 1"),
        ({**_VALID, "kind": "gamma"}, "doc.kind", "must be one of: alpha, beta"),
        ({**_VALID, "name": ""}, "doc.name", "must not be empty"),
        ({**_VALID, "name": "abcdefghij"}, "doc.name", "must be at most 8 characters"),
        ({**_VALID, "name": "A\x1b[31m"}, "doc.name", "has an invalid format"),
        ({**_VALID, "count": 0}, "doc.count", "must be at least 1"),
        ({**_VALID, "count": 10}, "doc.count", "must be at most 9"),
        ({**_VALID, "count": 1.0}, "doc.count", "must be an integer"),
        ({**_VALID, "count": True}, "doc.count", "must be an integer"),
        ({**_VALID, "items": []}, "doc.items", "must not be empty"),
        (
            {**_VALID, "items": ["a", "b", "c"]},
            "doc.items",
            "must contain at most 2 items",
        ),
        ({**_VALID, "items": ["a", "a"]}, "doc.items", "must not contain duplicates"),
        ({**_VALID, "items": ["a", 3]}, "doc.items[1]", "must be a string"),
    ],
)
def test_each_keyword_has_a_plain_message(
    instance: object, location: str, message: str
) -> None:
    """The field path is spelled as PyAhead spells it elsewhere."""
    assert schema_problem(_SCHEMA, instance, "doc") == (location, message)


def test_a_valid_document_has_no_problem() -> None:
    """Nothing is reported for a conforming document."""
    assert schema_problem(_SCHEMA, {**_VALID, "items": ["a"]}, "doc") is None


def test_the_offending_value_is_never_echoed() -> None:
    """Attacker-chosen text stays out of the message."""
    hostile = "\x1b]8;;https://example.invalid\x07click\x1b]8;;\x07"
    problem = schema_problem(_SCHEMA, {**_VALID, "name": hostile}, "doc")
    assert problem is not None
    assert hostile not in "".join(problem)
    assert "\x1b" not in "".join(problem)


def test_a_named_pattern_reads_as_what_it_stands_for() -> None:
    """Callers can say what a pattern means instead of "invalid format"."""
    problem = schema_problem(
        _SCHEMA,
        {**_VALID, "name": "ABC"},
        "doc",
        formats={"^[a-z]+$": "a lowercase word"},
    )
    assert problem == ("doc.name", "must be a lowercase word")


def test_one_of_reports_the_closest_alternative() -> None:
    """A tagged union names the problem in the branch the document meant."""
    schema = {
        "oneOf": [
            {
                "additionalProperties": False,
                "properties": {"kind": {"const": "a"}, "x": {"type": "string"}},
                "required": ["kind", "x"],
                "type": "object",
            },
            {
                "additionalProperties": False,
                "properties": {"kind": {"const": "b"}, "y": {"type": "integer"}},
                "required": ["kind", "y"],
                "type": "object",
            },
        ]
    }
    problem = schema_problem(schema, {"kind": "b", "y": 1, "z": 2}, "doc")
    assert problem == ("doc", "contains unknown field(s): z")
    problem = schema_problem(schema, {"kind": "a", "x": 3}, "doc")
    assert problem == ("doc.x", "must be a string")
