"""Strict schema and cross-file validation for M5 coverage manifests."""

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

from pyahead.registry import RegistryError, load_registry
from pyahead.registry.schema import (
    parse_coverage_manifest,
    registry_coverage_json_schema,
    render_json_schema,
    write_json_schemas,
)

ROOT = Path(__file__).parents[2]
BUNDLED_RULE = ROOT / "src/pyahead/data/registry/cpython/CPY0001.yaml"


def _coverage_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "source": {
            "id": "source-page",
            "title": "Source page",
            "url": "https://docs.python.org/3/whatsnew/",
            "checked_on": "2026-07-31",
        },
        "source_keys": ["entry-one", "entry-two"],
        "entries": [
            {
                "source_key": "entry-one",
                "disposition": "implemented",
                "rules": ["CPY0001"],
            },
            {
                "source_key": "entry-two",
                "disposition": "c-api-roadmap",
                "note": "Python-source analysis does not inspect C symbols.",
            },
        ],
    }


def _write_registry(
    root: Path,
    coverage_documents: list[dict[str, object]],
) -> Path:
    registry = root / "registry"
    (registry / "cpython").mkdir(parents=True)
    (registry / "coverage").mkdir()
    coverage_paths = [
        f"coverage/source-{index}.yaml"
        for index in range(1, 1 + len(coverage_documents))
    ]
    (registry / "index.yaml").write_text(
        "schema_version: 1\n"
        "release: test\n"
        "rules: [cpython/CPY0001.yaml]\n"
        "coverage:\n" + "".join(f"  - {path}\n" for path in coverage_paths),
        encoding="utf-8",
    )
    (registry / "cpython/CPY0001.yaml").write_text(
        BUNDLED_RULE.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    for path, document in zip(coverage_paths, coverage_documents, strict=True):
        (registry / path).write_text(
            yaml.safe_dump(document, sort_keys=False),
            encoding="utf-8",
        )
    return registry


def test_coverage_schema_is_current_closed_and_runtime_compatible(
    tmp_path: Path,
) -> None:
    """The generated authoring schema and strict parser accept the same document."""
    document = _coverage_document()
    validator = Draft202012Validator(registry_coverage_json_schema())

    validator.check_schema(validator.schema)
    validator.validate(document)
    parsed = parse_coverage_manifest(document)

    assert parsed.source.id == "source-page"
    assert parsed.source_keys == ("entry-one", "entry-two")
    assert [entry.source_key for entry in parsed.entries] == [
        "entry-one",
        "entry-two",
    ]
    write_json_schemas(tmp_path)
    generated = tmp_path / "registry-coverage-v1.json"
    checked_in = ROOT / "docs/schema/registry-coverage-v1.json"
    assert generated.read_text(encoding="utf-8") == checked_in.read_text(
        encoding="utf-8"
    )
    assert (
        json.loads(render_json_schema(registry_coverage_json_schema()))[
            "additionalProperties"
        ]
        is False
    )
    closed_document = _coverage_document()
    closed_document["unknown"] = True
    with pytest.raises(ValidationError):
        validator.validate(closed_document)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda document: document.update({"entries": []}),
        lambda document: document.update({"source_keys": []}),
        lambda document: cast("list[dict[str, object]]", document["entries"])[0].pop(
            "rules"
        ),
        lambda document: cast("list[dict[str, object]]", document["entries"])[1].pop(
            "note"
        ),
        lambda document: cast("list[dict[str, object]]", document["entries"])[1].update(
            {"rules": ["CPY0001"]}
        ),
        lambda document: cast("list[dict[str, object]]", document["entries"])[0].update(
            {"rules": ["CPY0001", "CPY0001"]}
        ),
        lambda document: cast("list[dict[str, object]]", document["entries"])[1].update(
            {"source_key": "entry-one"}
        ),
        lambda document: cast("dict[str, object]", document["source"]).update(
            {"checked_on": "2026-7-31"}
        ),
        lambda document: document.update({"unknown": True}),
    ],
)
def test_invalid_coverage_documents_are_rejected(
    mutator: object,
) -> None:
    """Required ownership, notes, uniqueness, dates, and closed fields are strict."""
    document = deepcopy(_coverage_document())
    mutate = cast("object", mutator)
    assert callable(mutate)
    mutate(document)

    with pytest.raises(RegistryError):
        parse_coverage_manifest(document)


def test_loader_resolves_coverage_rules_and_hashes_manifests(tmp_path: Path) -> None:
    """Coverage is part of snapshot identity and resolves canonical IDs."""
    document = _coverage_document()
    registry_path = _write_registry(tmp_path, [document])

    before = load_registry(registry_path)
    coverage_path = registry_path / "coverage/source-1.yaml"
    changed = deepcopy(document)
    entries = cast("list[dict[str, object]]", changed["entries"])
    entries[1]["note"] = "A changed reviewed classification note."
    coverage_path.write_text(
        yaml.safe_dump(changed, sort_keys=False),
        encoding="utf-8",
    )
    after = load_registry(registry_path)

    assert before.coverage[0].entries[0].rules == ("CPY0001",)
    assert before.revision != after.revision


def test_loader_rejects_unknown_uncovered_and_duplicate_source_ownership(
    tmp_path: Path,
) -> None:
    """Cross-file coverage cannot refer to unknown rules or omit rule ownership."""
    unknown = _coverage_document()
    unknown_entries = cast("list[dict[str, object]]", unknown["entries"])
    unknown_entries[0]["rules"] = ["CPY9999"]
    with pytest.raises(RegistryError, match="unknown canonical rule"):
        load_registry(_write_registry(tmp_path / "unknown", [unknown]))

    uncovered = _coverage_document()
    uncovered_entries = cast("list[dict[str, object]]", uncovered["entries"])
    uncovered_entries.pop(0)
    cast("list[str]", uncovered["source_keys"]).remove("entry-one")
    with pytest.raises(RegistryError, match="lack implemented or partial"):
        load_registry(_write_registry(tmp_path / "uncovered", [uncovered]))

    first = _coverage_document()
    second = _coverage_document()
    with pytest.raises(RegistryError, match="unique source IDs"):
        load_registry(_write_registry(tmp_path / "duplicate", [first, second]))


def test_loader_rejects_source_census_drift(tmp_path: Path) -> None:
    """Every audited source key must have exactly one classification."""
    unclassified = _coverage_document()
    source_keys = cast("list[str]", unclassified["source_keys"])
    source_keys.append("entry-three")
    with pytest.raises(RegistryError, match="unclassified source entries"):
        load_registry(_write_registry(tmp_path / "unclassified", [unclassified]))

    unknown = _coverage_document()
    source_keys = cast("list[str]", unknown["source_keys"])
    source_keys.remove("entry-two")
    with pytest.raises(RegistryError, match="absent from its audited"):
        load_registry(_write_registry(tmp_path / "unknown-entry", [unknown]))
