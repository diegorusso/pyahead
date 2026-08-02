"""Focused structural and semantic tests for registry schema version 1."""

from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from pyahead.model import Registry
from pyahead.registry.presentation import (
    render_registry_list,
    render_rule_explanation,
)
from pyahead.registry.schema import (
    RegistryError,
    main,
    parse_manifest,
    parse_rule,
    registry_index_json_schema,
    registry_rule_json_schema,
)

_BUNDLED_RULE = (
    Path(__file__).parents[2] / "src/pyahead/data/registry/cpython/CPY0001.yaml"
)


def _rule_document() -> dict[str, object]:
    loaded = yaml.safe_load(_BUNDLED_RULE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast("dict[str, object]", loaded)


def _index_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "release": "test",
        "retired_ids": [],
        "rules": ["cpython/CPY0001.yaml"],
    }


def _call_shape_json_schema() -> dict[str, object]:
    document = registry_rule_json_schema()
    definitions = cast("dict[str, object]", document["$defs"])
    matcher = cast("dict[str, object]", definitions["matcher"])
    variants = cast("list[dict[str, object]]", matcher["oneOf"])
    for variant in variants:
        properties = cast("dict[str, object]", variant["properties"])
        kind = cast("dict[str, object]", properties["kind"])
        if kind.get("const") == "call-shape":
            return variant
    message = "generated matcher schema has no call-shape variant"
    raise AssertionError(message)


@pytest.mark.parametrize(
    "manifest",
    [
        [],
        {"schema_version": 1, "release": "test", "rules": ["a.yaml", "a.yaml"]},
        {
            "schema_version": 1,
            "release": "test",
            "retired_ids": ["CPY0001", "CPY0001"],
            "rules": ["a.yaml"],
        },
        {"schema_version": 1, "release": " test ", "rules": ["a.yaml"]},
        {"schema_version": 1, "release": "test", "rules": [1]},
    ],
)
def test_manifest_schema_rejects_noncanonical_values(manifest: object) -> None:
    """Manifest collections, paths, releases, and reservations are strict."""
    with pytest.raises(RegistryError):
        parse_manifest(manifest)


def test_generated_index_schema_matches_runtime_structural_constraints() -> None:
    """The authoring schema rejects the same representative index shapes."""
    validator = Draft202012Validator(registry_index_json_schema())
    valid_document = _index_document()

    validator.check_schema(validator.schema)
    validator.validate(valid_document)
    assert parse_manifest(valid_document).release == "test"

    padded_release = deepcopy(valid_document)
    padded_release["release"] = " test "
    newline_release = deepcopy(valid_document)
    newline_release["release"] = "test\n"
    duplicate_rules = deepcopy(valid_document)
    duplicate_rules["rules"] = [
        "cpython/CPY0001.yaml",
        "cpython/CPY0001.yaml",
    ]

    for invalid_document in (padded_release, newline_release, duplicate_rules):
        with pytest.raises(ValidationError):
            validator.validate(invalid_document)
        with pytest.raises(RegistryError):
            parse_manifest(invalid_document)


@pytest.mark.parametrize(
    "rule_path",
    [
        "/cpython/CPY0001.yaml",
        "./cpython/CPY0001.yaml",
        "cpython//CPY0001.yaml",
        "cpython/../CPY0001.yaml",
        "cpython\\CPY0001.yaml",
        "cpython/CPY0001.yaml\nignored",
        "cpython/CPY 0001.yaml",
        "cpython/CPY0001.yaml\x00",
    ],
)
def test_manifest_rule_paths_share_one_canonical_posix_grammar(
    rule_path: str,
) -> None:
    """Runtime and JSON Schema reject normalized aliases and unsafe characters."""
    document = _index_document()
    document["rules"] = [rule_path]

    with pytest.raises(ValidationError):
        Draft202012Validator(registry_index_json_schema()).validate(document)
    with pytest.raises(RegistryError, match="unsafe registry rule path"):
        parse_manifest(document)


@pytest.mark.parametrize("boundary", ["\u0085", "\u001c", "\ufeff"])
def test_registry_whitespace_policy_has_runtime_and_schema_parity(
    boundary: str,
) -> None:
    """Python-only and ECMAScript-only whitespace share one boundary policy."""
    index_validator = Draft202012Validator(registry_index_json_schema())
    rule_validator = Draft202012Validator(registry_rule_json_schema())

    for release in (f"{boundary}test", f"test{boundary}"):
        index_document = _index_document()
        index_document["release"] = release
        with pytest.raises(ValidationError):
            index_validator.validate(index_document)
        with pytest.raises(RegistryError):
            parse_manifest(index_document)

    rule_document = _rule_document()
    sources = cast("list[dict[str, object]]", rule_document["sources"])
    sources[0]["url"] = f"https://example.com/{boundary}"
    with pytest.raises(ValidationError):
        rule_validator.validate(rule_document)
    with pytest.raises(RegistryError):
        parse_rule(rule_document, "CPY0001.yaml")


def test_oversized_python_minor_fails_runtime_and_generated_schema() -> None:
    """Timeline version conversion stays bounded at both schema boundaries."""
    document = _rule_document()
    timeline = cast("list[dict[str, object]]", document["timeline"])
    timeline[0]["python"] = "3." + ("9" * 5_000)

    with pytest.raises(ValidationError):
        Draft202012Validator(registry_rule_json_schema()).validate(document)
    with pytest.raises(RegistryError, match="must be a Python minor"):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize("location", ["title", "literal"])
def test_lone_unicode_surrogates_fail_runtime_and_generated_schema(
    location: str,
) -> None:
    """Invalid Unicode never reaches canonical digest encoding."""
    document = _rule_document()
    surrogate = "\ud800"
    if location == "title":
        document["title"] = surrogate
    else:
        document["matchers"] = [
            {
                "kind": "call-shape",
                "qualified_name": "targetpkg.call",
                "literal_arguments": [{"position": 0, "equals": surrogate}],
            }
        ]

    with pytest.raises(ValidationError):
        Draft202012Validator(registry_rule_json_schema()).validate(document)
    with pytest.raises(RegistryError):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize(
    "matcher",
    [
        {},
        {"kind": 1, "module": "targetpkg"},
        {"kind": "module-import", "module": "bad-name"},
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old",
            "contexts": [],
        },
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old",
            "contexts": ["read", "read"],
        },
        {"kind": "call-shape", "qualified_name": "targetpkg.call"},
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "required_keywords": [],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "min_positional_args": True,
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "min_positional_args": 2,
            "max_positional_args": 1,
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "min_keyword_args": 2,
            "max_keyword_args": 1,
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "min_keyword_args": 0,
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "required_keywords": ["bad.name"],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "required_keywords": ["mode"],
            "forbidden_keywords": ["mode"],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"equals": "value"}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [
                {"position": 0, "keyword": "mode", "equals": "value"}
            ],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"keyword": "bad.name", "equals": "value"}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [
                {"position": 0, "equals": "one"},
                {"position": 0, "equals": "two"},
            ],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "forbidden_keywords": ["mode"],
            "literal_arguments": [{"keyword": "mode", "equals": "value"}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "max_positional_args": 1,
            "literal_arguments": [{"position": 1, "equals": "value"}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"position": 0, "equals": ["not", "scalar"]}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"position": 0, "equals": float("inf")}],
        },
        {"kind": "literal-dynamic-import", "module": "targetpkg", "confidence": "low"},
    ],
)
def test_matcher_schema_rejects_unsafe_or_inconsistent_shapes(
    matcher: dict[str, object],
) -> None:
    """Matcher predicates fail closed whenever exact evidence is impossible."""
    document = _rule_document()
    document["matchers"] = [matcher]

    with pytest.raises(RegistryError):
        parse_rule(document, "CPY0001.yaml")


def test_literal_dynamic_import_cannot_be_authored_as_high_confidence() -> None:
    """Registry data cannot promote literal evidence into the default gate."""
    document = _rule_document()
    document["matchers"] = [
        {
            "kind": "literal-dynamic-import",
            "module": "targetpkg",
            "confidence": "high",
        }
    ]
    validator = Draft202012Validator(registry_rule_json_schema())

    with pytest.raises(ValidationError):
        validator.validate(document)
    with pytest.raises(RegistryError, match="must be medium"):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize(
    ("container", "field", "value"),
    [
        ("scope", "runtime", "pypy"),
        ("scope", "contexts", []),
        ("scope", "contexts", ["runtime", "runtime"]),
        ("subject", "name", "bad-name"),
        ("timeline", "source", "Bad Source"),
        ("source", "id", "Bad Source"),
        ("document", "aliases", ["CPY0002", "CPY0002"]),
        ("document", "aliases", ["CPY0001"]),
        ("document", "tags", ["bad_tag"]),
        ("document", "tags", ["stdlib", "stdlib"]),
    ],
)
def test_rule_schema_rejects_invalid_nested_identity_values(
    container: str,
    field: str,
    value: object,
) -> None:
    """Nested identities and closed enumerations cannot drift silently."""
    document = deepcopy(_rule_document())
    if container == "document":
        target = document
    elif container == "timeline":
        target = cast("list[dict[str, object]]", document["timeline"])[0]
    elif container == "source":
        target = cast("list[dict[str, object]]", document["sources"])[0]
    else:
        target = cast("dict[str, object]", document[container])
    target[field] = value

    with pytest.raises(RegistryError):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize(
    "url",
    [
        "https://[invalid",
        "https://example.com:not-a-port/path",
        "https://:443/path",
    ],
)
def test_malformed_source_urls_are_registry_errors(url: str) -> None:
    """URL parsing and hostname or port access stay inside the input boundary."""
    document = _rule_document()
    sources = cast("list[dict[str, object]]", document["sources"])
    sources[0]["url"] = url
    validator = Draft202012Validator(registry_rule_json_schema())

    with pytest.raises(ValidationError):
        validator.validate(document)
    with pytest.raises(RegistryError, match="direct HTTPS URL"):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize(
    "case",
    [
        "rule-title",
        "source-title",
        "source-id",
        "source-url",
        "matcher-module",
        "timeline-python",
        "tag",
    ],
)
def test_terminal_newlines_fail_runtime_and_generated_rule_schema(case: str) -> None:
    """ECMA patterns reject newlines where runtime requires canonical text."""
    document = deepcopy(_rule_document())
    if case == "rule-title":
        document["title"] = f"{document['title']}\n"
    elif case == "source-title":
        source = cast("list[dict[str, object]]", document["sources"])[0]
        source["title"] = f"{source['title']}\n"
    elif case == "source-id":
        source = cast("list[dict[str, object]]", document["sources"])[0]
        source["id"] = f"{source['id']}\n"
    elif case == "source-url":
        source = cast("list[dict[str, object]]", document["sources"])[0]
        source["url"] = f"{source['url']}\n"
    elif case == "matcher-module":
        matcher = cast("list[dict[str, object]]", document["matchers"])[0]
        matcher["module"] = f"{matcher['module']}\n"
    elif case == "timeline-python":
        event = cast("list[dict[str, object]]", document["timeline"])[0]
        event["python"] = f"{event['python']}\n"
    else:
        tags = cast("list[str]", document["tags"])
        tags[0] = f"{tags[0]}\n"

    validator = Draft202012Validator(registry_rule_json_schema())
    with pytest.raises(ValidationError):
        validator.validate(document)
    with pytest.raises(RegistryError):
        parse_rule(document, "CPY0001.yaml")


def test_subject_name_constraints_match_generated_schema_and_runtime() -> None:
    """JSON Schema and runtime agree on dotted and free-form subject names."""
    validator = Draft202012Validator(registry_rule_json_schema())
    valid_document = _rule_document()

    validator.check_schema(validator.schema)
    validator.validate(valid_document)
    assert parse_rule(valid_document, "CPY0001.yaml").subject == "cgi"

    invalid_document = deepcopy(valid_document)
    invalid_document["subject"] = {"kind": "module", "name": "bad-name"}
    with pytest.raises(ValidationError):
        validator.validate(invalid_document)
    with pytest.raises(RegistryError, match="must be a dotted Python name"):
        parse_rule(invalid_document, "CPY0001.yaml")

    syntax_document = deepcopy(valid_document)
    syntax_document["subject"] = {
        "kind": "syntax",
        "name": "bool-bitwise-inversion",
    }
    validator.validate(syntax_document)
    assert (
        parse_rule(syntax_document, "CPY0001.yaml").subject == "bool-bitwise-inversion"
    )


def test_generated_rule_schema_matches_runtime_structural_constraints() -> None:
    """Representative canonical strings, URLs, and arrays have schema parity."""
    validator = Draft202012Validator(registry_rule_json_schema())
    valid_document = _rule_document()

    validator.check_schema(validator.schema)
    validator.validate(valid_document)
    assert parse_rule(valid_document, "CPY0001.yaml").id == "CPY0001"

    padded_title = deepcopy(valid_document)
    padded_title["title"] = " The cgi module is removed "

    credential_url = deepcopy(valid_document)
    credential_sources = cast("list[dict[str, object]]", credential_url["sources"])
    credential_sources[0]["url"] = "https://author:secret@example.com/source"

    duplicate_source = deepcopy(valid_document)
    source_records = cast("list[dict[str, object]]", duplicate_source["sources"])
    source_records.append(deepcopy(source_records[0]))

    duplicate_timeline = deepcopy(valid_document)
    timeline_records = cast("list[dict[str, object]]", duplicate_timeline["timeline"])
    timeline_records.append(deepcopy(timeline_records[0]))

    for invalid_document in (
        padded_title,
        credential_url,
        duplicate_source,
        duplicate_timeline,
    ):
        with pytest.raises(ValidationError):
            validator.validate(invalid_document)
        with pytest.raises(RegistryError):
            parse_rule(invalid_document, "CPY0001.yaml")


@pytest.mark.parametrize("field", ["matchers", "sources"])
def test_rule_schema_rejects_duplicate_complex_records(field: str) -> None:
    """Equivalent matcher or source records are never silently coalesced."""
    document = deepcopy(_rule_document())
    values = cast("list[dict[str, object]]", document[field])
    document[field] = [values[0], values[0]]

    with pytest.raises(RegistryError):
        parse_rule(document, "CPY0001.yaml")


@pytest.mark.parametrize(
    "field",
    ["required_keywords", "forbidden_keywords", "literal_arguments"],
)
def test_empty_call_shape_arrays_fail_runtime_and_generated_schema(
    field: str,
) -> None:
    """An explicitly empty predicate is invalid even beside another predicate."""
    document = deepcopy(_rule_document())
    document["matchers"] = [
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "min_positional_args": 0,
            field: [],
        }
    ]

    with pytest.raises(RegistryError, match="must not be empty"):
        parse_rule(document, "CPY0001.yaml")

    properties = cast("dict[str, object]", _call_shape_json_schema()["properties"])
    field_schema = cast("dict[str, object]", properties[field])
    assert field_schema["minItems"] == 1


def test_runtime_valid_call_shape_satisfies_generated_array_constraints() -> None:
    """Representative non-empty unique predicates are valid at both boundaries."""
    matcher: dict[str, object] = {
        "kind": "call-shape",
        "qualified_name": "targetpkg.call",
        "required_keywords": ["mode"],
        "forbidden_keywords": ["legacy"],
        "literal_arguments": [{"position": 0, "equals": "payload"}],
    }
    document = deepcopy(_rule_document())
    document["matchers"] = [matcher]

    assert parse_rule(document, "CPY0001.yaml").matchers

    properties = cast("dict[str, object]", _call_shape_json_schema()["properties"])
    for field in ("required_keywords", "forbidden_keywords", "literal_arguments"):
        values = cast("list[object]", matcher[field])
        field_schema = cast("dict[str, object]", properties[field])
        assert len(values) >= cast("int", field_schema["minItems"])
        if field_schema.get("uniqueItems") is True:
            assert all(values.count(value) == 1 for value in values)


def test_duplicate_matchers_are_a_documented_runtime_semantic() -> None:
    """JSON Schema stays truthful when semantic identity exceeds JSON equality."""
    document = deepcopy(_rule_document())
    matcher = cast("list[dict[str, object]]", document["matchers"])[0]
    document["matchers"] = [matcher, deepcopy(matcher)]

    with pytest.raises(RegistryError, match="must not contain duplicates"):
        parse_rule(document, "CPY0001.yaml")

    schema = registry_rule_json_schema()
    properties = cast("dict[str, object]", schema["properties"])
    matcher_array = cast("dict[str, object]", properties["matchers"])
    assert "uniqueItems" not in matcher_array
    Draft202012Validator(schema).validate(document)


@pytest.mark.parametrize(("first", "second"), [(True, 1), (1, 1.0)])
def test_matcher_identity_preserves_exact_literal_scalar_types(
    first: object,
    second: object,
) -> None:
    """Boolean, integer, and floating predicates remain distinct matchers."""
    document = deepcopy(_rule_document())
    document["matchers"] = [
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"position": 0, "equals": first}],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "literal_arguments": [{"position": 0, "equals": second}],
        },
    ]

    parsed = parse_rule(document, "CPY0001.yaml")
    authored = cast("list[dict[str, object]]", document["matchers"])
    assert len(parsed.matchers) == len(authored)
    Draft202012Validator(registry_rule_json_schema()).validate(document)


def test_matcher_identity_normalizes_set_like_keyword_predicates() -> None:
    """Reordering required keywords cannot disguise a semantic duplicate."""
    document = deepcopy(_rule_document())
    document["matchers"] = [
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "required_keywords": ["mode", "legacy"],
        },
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.call",
            "required_keywords": ["legacy", "mode"],
        },
    ]

    with pytest.raises(RegistryError, match="must not contain duplicates"):
        parse_rule(document, "CPY0001.yaml")


def test_schema_supports_all_event_and_matcher_metadata_for_explanation() -> None:
    """The strict model represents M2 data without executing later behavior."""
    document = _rule_document()
    document["id"] = "CPY9002"
    document["aliases"] = ["CPY9001"]
    document["subject"] = {"kind": "syntax", "name": "extended-schema-test"}
    document["scope"] = {
        "ecosystem": "python",
        "runtime": "cpython",
        "contexts": ["runtime", "typing"],
    }
    document["timeline"] = [
        {
            "event": "deprecated",
            "python": "3.10",
            "certainty": "released",
            "source": "pep-0594",
        },
        {
            "event": "signature_changed",
            "python": "3.11",
            "certainty": "released",
            "source": "pep-0594",
        },
        {
            "event": "behavior_changed",
            "python": "3.12",
            "certainty": "released",
            "source": "pep-0594",
        },
        {
            "event": "syntax_changed",
            "python": "3.13",
            "certainty": "scheduled",
            "source": "pep-0594",
        },
        {
            "event": "support_dropped",
            "python": "3.14",
            "certainty": "provisional",
            "source": "pep-0594",
        },
    ]
    document["impact"] = {
        "on_deprecation": "deprecated",
        "on_signature_change": "breaking",
        "on_behavior_change": "risk",
        "on_syntax_change": "breaking",
        "on_support_drop": "breaking",
    }
    document["matchers"] = [
        {"kind": "module-import", "module": "targetpkg"},
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old",
            "contexts": ["decorator", "annotation"],
        },
        {"kind": "qualified-call", "qualified_name": "targetpkg.old"},
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.old",
            "min_positional_args": 1,
            "max_positional_args": 2,
            "min_keyword_args": 1,
            "max_keyword_args": 1,
            "required_keywords": ["mode"],
            "forbidden_keywords": ["legacy"],
            "literal_arguments": [
                {"position": 0, "equals": -1},
                {"keyword": "mode", "equals": None},
            ],
        },
        {
            "kind": "literal-dynamic-import",
            "module": "targetpkg",
            "confidence": "medium",
        },
        {"kind": "builtin-pattern", "pattern": "bool-bitwise-inversion"},
    ]
    remediation = cast("dict[str, object]", document["remediation"])
    remediation["documentation_url"] = "https://example.com/remediation"
    remediation["automation"] = {"tool": "pyupgrade", "rule": "--py311-plus"}

    rule = parse_rule(document, "CPY9002.yaml")
    registry = Registry(
        release="test",
        revision="a" * 64,
        retired_ids=(),
        rules=(rule,),
    )
    explanation = render_rule_explanation(registry, rule)
    listing = render_registry_list(registry)

    assert "CPY9002  The cgi module is removed" in listing
    assert "aliases" not in listing.lower()
    assert "signature_changed; impact=breaking" in explanation
    assert "contexts=decorator,annotation" in explanation
    assert "min_positional_args=1" in explanation
    assert "min_keyword_args=1" in explanation
    assert "max_keyword_args=1" in explanation
    assert "required_keywords=mode" in explanation
    assert "position[0]=-1" in explanation
    assert "confidence=medium" in explanation
    assert "pattern=bool-bitwise-inversion" in explanation
    assert "Documentation: https://example.com/remediation" in explanation
    assert "Aliases: CPY9001" in explanation
    assert registry.find_rule("CPY9001") is rule
    assert registry.find_rule("CPY9999") is None


def test_schema_generator_main_writes_all_documents(tmp_path: Path) -> None:
    """The documented generator entry function succeeds deterministically."""
    assert main([str(tmp_path)]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "registry-coverage-v1.json",
        "registry-index-v1.json",
        "registry-rule-v1.json",
    ]
