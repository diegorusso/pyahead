"""Tests for safe bundled-registry loading."""

import json
import os
import subprocess
from pathlib import Path
from typing import NoReturn, cast

import pytest
import yaml

from pyahead.model import (
    AutomationTool,
    ChangeEventKind,
    Impact,
    MatcherKind,
    RegistryCertainty,
    ReleaseStatus,
)
from pyahead.registry import RegistryError, load_registry
from pyahead.registry.loader import MAX_REGISTRY_FILE_BYTES
from pyahead.registry.presentation import render_rule_explanation
from pyahead.registry.schema import (
    parse_release_metadata,
    registry_index_json_schema,
    registry_rule_json_schema,
    render_json_schema,
    write_json_schemas,
)

_SHA256_HEX_LENGTH = 64
_CURATED_RULE_COUNT = 133
_COVERAGE_SOURCE_COUNT = 13
_BUNDLED_REGISTRY = Path(__file__).parents[2] / "src/pyahead/data/registry"


def _write_registry(
    root: Path,
    rule_text: str,
    *,
    rule_entries: str = "  - cpython/CPY0001.yaml\n",
) -> Path:
    registry_dir = root / "registry"
    (registry_dir / "cpython").mkdir(parents=True)
    (registry_dir / "index.yaml").write_text(
        "schema_version: 1\nrelease: test\nrules:\n" + rule_entries,
        encoding="utf-8",
    )
    (registry_dir / "cpython/CPY0001.yaml").write_text(
        rule_text,
        encoding="utf-8",
    )
    return registry_dir


def test_bundled_registry_has_sourced_pep_594_rule() -> None:
    """The seed registry records released deprecation and removal facts."""
    registry = load_registry()

    assert registry.release == "2026.07.31"
    assert len(registry.revision) == _SHA256_HEX_LENGTH
    assert len(registry.rules) == _CURATED_RULE_COUNT
    assert [release.python.minor for release in registry.releases] == [
        11,
        12,
        13,
        14,
        15,
        16,
    ]
    assert [release.status for release in registry.releases] == [
        ReleaseStatus.SECURITY,
        ReleaseStatus.SECURITY,
        ReleaseStatus.STABLE,
        ReleaseStatus.STABLE,
        ReleaseStatus.PRERELEASE,
        ReleaseStatus.PLANNED,
    ]
    assert len(registry.coverage) == _COVERAGE_SOURCE_COUNT
    python_313 = registry.releases[2]
    assert python_313.source == "https://peps.python.org/pep-0719/"
    assert python_313.status is ReleaseStatus.STABLE
    rule = registry.rules[0]
    assert rule.id == "CPY0001"
    assert rule.subject == "cgi"
    assert rule.on_deprecation is Impact.DEPRECATED
    assert rule.on_removal is Impact.BREAKING
    assert [event.kind for event in rule.events] == [
        ChangeEventKind.DEPRECATED,
        ChangeEventKind.REMOVED,
    ]
    assert all(event.certainty is RegistryCertainty.RELEASED for event in rule.events)
    assert {source.id for source in rule.sources} == {
        "pep-0594",
        "python-3.13-cgi",
    }


def test_registry_revision_is_content_addressed(
    tmp_path: Path,
) -> None:
    """Changing registry content changes its stable revision digest."""
    registry_dir = tmp_path / "registry"
    (registry_dir / "cpython").mkdir(parents=True)
    rule = _BUNDLED_REGISTRY / "cpython/CPY0001.yaml"
    releases = _BUNDLED_REGISTRY / "releases.yaml"
    (registry_dir / "index.yaml").write_text(
        "schema_version: 1\n"
        "release: test\n"
        "releases: releases.yaml\n"
        "rules: [cpython/CPY0001.yaml]\n",
        encoding="utf-8",
    )
    (registry_dir / "releases.yaml").write_text(
        releases.read_text(encoding="utf-8"), encoding="utf-8"
    )
    copied_rule = registry_dir / "cpython/CPY0001.yaml"
    copied_rule.write_text(rule.read_text(encoding="utf-8"), encoding="utf-8")

    first = load_registry(registry_dir)
    copied_rule.write_text(
        copied_rule.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    second = load_registry(registry_dir / "index.yaml")
    copied_rule.write_text(
        copied_rule.read_text(encoding="utf-8").replace(
            "The cgi module is removed",
            "The cgi module is unavailable",
        ),
        encoding="utf-8",
    )
    third = load_registry(registry_dir)

    assert first.revision == second.revision
    assert second.revision != third.revision
    assert first.rules == second.rules


def test_release_metadata_changes_the_registry_revision(tmp_path: Path) -> None:
    """Release presentation facts participate in content identity."""
    registry_dir = tmp_path / "registry"
    (registry_dir / "cpython").mkdir(parents=True)
    (registry_dir / "index.yaml").write_text(
        "schema_version: 1\n"
        "release: test\n"
        "releases: releases.yaml\n"
        "rules: [cpython/CPY0001.yaml]\n",
        encoding="utf-8",
    )
    for relative_path in (Path("releases.yaml"), Path("cpython/CPY0001.yaml")):
        target = registry_dir / relative_path
        target.write_text(
            (_BUNDLED_REGISTRY / relative_path).read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    before = load_registry(registry_dir)
    release_path = registry_dir / "releases.yaml"
    release_path.write_text(
        release_path.read_text(encoding="utf-8").replace(
            "status: prerelease", "status: planned"
        ),
        encoding="utf-8",
    )
    after = load_registry(registry_dir)

    assert before.revision != after.revision
    assert after.releases[-1].status is ReleaseStatus.PLANNED


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 1, "releases": []},
        {
            "schema_version": 1,
            "releases": [{"python": "3.14.1", "status": "stable"}],
        },
        {
            "schema_version": 1,
            "releases": [{"python": "3.14", "status": "unknown"}],
        },
        {
            "schema_version": 1,
            "releases": [
                {
                    "python": "3.14",
                    "status": "stable",
                    "released_on": "2025-1-07",
                }
            ],
        },
        {
            "schema_version": 1,
            "releases": [
                {
                    "python": "3.14",
                    "status": "stable",
                    "source": "http://example.com/release",
                }
            ],
        },
        {
            "schema_version": 1,
            "releases": [
                {"python": "3.15", "status": "prerelease"},
                {"python": "3.14", "status": "stable"},
            ],
        },
        {
            "schema_version": 1,
            "releases": [{"python": "3.14", "status": "stable", "unexpected": True}],
        },
    ],
)
def test_release_metadata_is_strict(document: dict[str, object]) -> None:
    """Invalid, patch-level, unordered, or unknown release facts fail closed."""
    with pytest.raises(RegistryError):
        parse_release_metadata(document)


@pytest.mark.parametrize(
    "index_text",
    [
        "not: [valid",
        "schema_version: 2\nrelease: test\nrules: [rule.yaml]\n",
        "schema_version: 1\nrelease: test\nrules: []\n",
        "schema_version: 1\nrelease: test\nrules: [../rule.yaml]\n",
        "schema_version: 1\nrelease: test\nrules: [rule.txt]\n",
    ],
)
def test_registry_rejects_invalid_manifests(
    tmp_path: Path,
    index_text: str,
) -> None:
    """Malformed or unsafe manifests fail closed."""
    (tmp_path / "index.yaml").write_text(index_text, encoding="utf-8")
    with pytest.raises(RegistryError):
        load_registry(tmp_path)


def test_registry_rejects_duplicate_manifest_keys(tmp_path: Path) -> None:
    """Contradictory manifest fields cannot be overwritten during YAML loading."""
    (tmp_path / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: first\n"
            "release: second\n"
            "rules: [cpython/CPY0001.yaml]\n"
        ),
        encoding="utf-8",
    )

    with pytest.raises(RegistryError, match="not valid YAML"):
        load_registry(tmp_path)


@pytest.mark.parametrize(
    ("location", "original", "duplicate"),
    [
        (
            "rule",
            "id: CPY0001\n",
            "id: CPY0001\nid: CPY0002\n",
        ),
        (
            "timeline",
            '    python: "3.11"\n',
            '    python: "3.11"\n    python: "3.12"\n',
        ),
        (
            "matcher",
            "  - kind: module-import\n    module: cgi\n",
            "  - kind: module-import\n    module: cgi\n    module: email\n",
        ),
    ],
)
def test_registry_rejects_duplicate_rule_keys_recursively(
    tmp_path: Path,
    location: str,
    original: str,
    duplicate: str,
) -> None:
    """Rule, timeline, and matcher mappings all preserve strict key identity."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    assert original in rule_text, location
    registry = _write_registry(
        tmp_path,
        rule_text.replace(original, duplicate, 1),
    )

    with pytest.raises(RegistryError, match="not valid YAML"):
        load_registry(registry)


def test_registry_rejects_missing_path(tmp_path: Path) -> None:
    """An absent explicit registry is invalid input."""
    with pytest.raises(RegistryError):
        load_registry(tmp_path / "missing")


def test_registry_wraps_inaccessible_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filesystem access failures remain invalid registry input, not internals."""

    def deny_resolution(_path: Path, *, strict: bool = False) -> Path:
        del strict
        message = "access denied"
        raise PermissionError(message)

    monkeypatch.setattr(Path, "resolve", deny_resolution)

    with pytest.raises(RegistryError, match="unable to resolve registry path"):
        load_registry(tmp_path)


@pytest.mark.parametrize("oversized_entry", ["index", "rule"])
def test_registry_rejects_oversized_files_before_parsing(
    tmp_path: Path,
    oversized_entry: str,
) -> None:
    """Both manifest and rule reads have one explicit byte ceiling."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    registry = _write_registry(tmp_path, rule_text)
    target = (
        registry / "index.yaml"
        if oversized_entry == "index"
        else registry / "cpython/CPY0001.yaml"
    )
    target.write_bytes(b"#" * (MAX_REGISTRY_FILE_BYTES + 1))

    with pytest.raises(RegistryError, match=r"exceeds the .*byte limit"):
        load_registry(registry)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_registry_refuses_fifo_without_opening_or_blocking(tmp_path: Path) -> None:
    """A non-regular rule entry is rejected by metadata inspection alone."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    registry = _write_registry(tmp_path, rule_text)
    rule_path = registry / "cpython/CPY0001.yaml"
    rule_path.unlink()
    os.mkfifo(rule_path)

    with pytest.raises(RegistryError, match="regular files"):
        load_registry(registry)


def test_registry_refuses_rule_symlink_escape(tmp_path: Path) -> None:
    """Registry rule reads never follow even a valid external YAML target."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    registry = _write_registry(tmp_path / "root", rule_text)
    outside = tmp_path / "outside.yaml"
    outside.write_text(rule_text, encoding="utf-8")
    rule_path = registry / "cpython/CPY0001.yaml"
    rule_path.unlink()
    try:
        rule_path.symlink_to(outside)
    except OSError:
        pytest.skip("the platform does not permit file symlinks")

    with pytest.raises(RegistryError, match="must not traverse symlinks"):
        load_registry(registry)


@pytest.mark.parametrize("source_kind", ["file", "directory", "parent"])
def test_registry_refuses_explicit_source_symlinks(
    tmp_path: Path,
    source_kind: str,
) -> None:
    """The caller's file, directory, and parent aliases are never dereferenced."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    registry = _write_registry(tmp_path / "target", rule_text)
    alias = tmp_path / f"{source_kind}-link"
    if source_kind == "file":
        target = registry / "index.yaml"
        source = alias
        target_is_directory = False
    elif source_kind == "directory":
        target = registry
        source = alias
        target_is_directory = True
    else:
        target = registry.parent
        source = alias / registry.name / "index.yaml"
        target_is_directory = True
    try:
        alias.symlink_to(target, target_is_directory=target_is_directory)
    except OSError:
        pytest.skip("the platform does not permit symlinks")

    with pytest.raises(RegistryError, match="source path must not traverse symlinks"):
        load_registry(source)


def test_registry_detects_file_replacement_between_check_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opened descriptor must identify the same file that was validated."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    registry = _write_registry(tmp_path / "root", rule_text)
    rule_path = registry / "cpython/CPY0001.yaml"
    replacement = tmp_path / "replacement.yaml"
    replacement.write_text(rule_text, encoding="utf-8")
    original_open = os.open
    replaced = False

    def replace_before_open(path: Path, flags: int) -> int:
        nonlocal replaced
        if Path(path) == rule_path and not replaced:
            replaced = True
            rule_path.replace(tmp_path / "original.yaml")
            replacement.replace(rule_path)
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", replace_before_open)

    with pytest.raises(RegistryError, match="changed while it was being opened"):
        load_registry(registry)


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("id: CPY0001", "id: invalid"),
        ("kind: module\n  name: cgi", "kind: package\n  name: cgi"),
        ("event: deprecated", "event: renamed"),
        ('python: "3.11"', 'python: "3.11.1"'),
        ("certainty: released", "certainty: rumored"),
        ("kind: module-import", "kind: qualified-call"),
        ("https://peps.python.org", "http://peps.python.org"),
        ("on_removal: breaking", "on_removal: catastrophe"),
        ("source: pep-0594", "source: absent-source"),
        ("tags: [stdlib, module-removal, pep-594]", 'tags: [stdlib, ""]'),
        ("contexts: [runtime]", "contexts: runtime"),
    ],
)
def test_registry_rejects_invalid_rule_values(
    tmp_path: Path,
    original: str,
    replacement: str,
) -> None:
    """M1 validates every rule value it consumes before analysis."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    assert original in rule_text
    registry_dir = _write_registry(
        tmp_path,
        rule_text.replace(original, replacement, 1),
    )

    with pytest.raises(RegistryError):
        load_registry(registry_dir)


@pytest.mark.parametrize("key", ["timeline", "matchers"])
def test_registry_rejects_empty_required_rule_lists(
    tmp_path: Path,
    key: str,
) -> None:
    """Timeline and matcher lists cannot silently disappear."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    document = yaml.safe_load(rule_text)
    assert isinstance(document, dict)
    document[key] = []
    registry_dir = _write_registry(tmp_path, yaml.safe_dump(document))

    with pytest.raises(RegistryError):
        load_registry(registry_dir)


def test_registry_rejects_duplicate_ids_and_missing_files(tmp_path: Path) -> None:
    """Manifest entries resolve safely and rule IDs remain unique."""
    rule_text = (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    duplicate = _write_registry(
        tmp_path / "duplicate",
        rule_text,
        rule_entries=("  - cpython/CPY0001.yaml\n  - cpython/CPY0001.yaml\n"),
    )
    missing = _write_registry(tmp_path / "missing", rule_text)
    (missing / "index.yaml").write_text(
        "schema_version: 1\nrelease: test\nrules:\n  - absent.yaml\n",
        encoding="utf-8",
    )

    with pytest.raises(RegistryError):
        load_registry(duplicate)
    with pytest.raises(RegistryError):
        load_registry(missing)


def _bundled_rule_document() -> dict[str, object]:
    loaded = yaml.safe_load(
        (_BUNDLED_REGISTRY / "cpython/CPY0001.yaml").read_text(encoding="utf-8")
    )
    assert isinstance(loaded, dict)
    return cast("dict[str, object]", loaded)


def test_generated_json_schemas_are_current_and_closed(tmp_path: Path) -> None:
    """Checked-in schemas are deterministic products of the runtime schema."""
    schema_directory = Path(__file__).parents[2] / "docs/schema"

    generated = write_json_schemas(tmp_path)

    assert generated == (
        tmp_path / "registry-index-v1.json",
        tmp_path / "registry-rule-v1.json",
    )
    assert generated[0].read_text(encoding="utf-8") == (
        schema_directory / "registry-index-v1.json"
    ).read_text(encoding="utf-8")
    assert generated[1].read_text(encoding="utf-8") == (
        schema_directory / "registry-rule-v1.json"
    ).read_text(encoding="utf-8")
    rule_schema = registry_rule_json_schema()
    assert rule_schema["additionalProperties"] is False
    matcher_schema = cast(
        "dict[str, object]", cast("dict[str, object]", rule_schema["$defs"])["matcher"]
    )
    matcher_variants = cast("list[dict[str, object]]", matcher_schema["oneOf"])
    assert len(matcher_variants) == len(MatcherKind)
    assert (
        json.loads(render_json_schema(registry_index_json_schema()))[
            "additionalProperties"
        ]
        is False
    )


@pytest.mark.parametrize(
    ("location", "field", "value"),
    [
        ("rule", "unexpected", True),
        ("scope", "platform", "linux"),
        ("subject", "callable", "os.system"),
        ("timeline", "note", "ignored typo"),
        ("matcher", "callable", "os.system"),
        ("source", "kind", "web"),
        ("remediation", "command", "ruff --fix"),
    ],
)
def test_registry_schema_rejects_unknown_fields_at_every_level(
    tmp_path: Path,
    location: str,
    field: str,
    value: object,
) -> None:
    """Typos and executable-looking extensions fail closed."""
    document = _bundled_rule_document()
    if location == "rule":
        target = document
    elif location == "timeline":
        target = cast("list[dict[str, object]]", document["timeline"])[0]
    elif location == "matcher":
        target = cast("list[dict[str, object]]", document["matchers"])[0]
    elif location == "source":
        target = cast("list[dict[str, object]]", document["sources"])[0]
    else:
        target = cast("dict[str, object]", document[location])
    target[field] = value
    registry = _write_registry(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(RegistryError, match="unknown field"):
        load_registry(registry)


@pytest.mark.parametrize(
    "matcher",
    [
        {
            "kind": "builtin-pattern",
            "pattern": "pathlib.Path.unlink",
        },
        {
            "kind": "builtin-pattern",
            "pattern": "bool-bitwise-inversion",
            "callable": "subprocess.run",
        },
    ],
)
def test_builtin_pattern_rejects_arbitrary_callable_paths(
    tmp_path: Path,
    matcher: dict[str, object],
) -> None:
    """Registry YAML selects a fixed ID and cannot name executable code."""
    document = _bundled_rule_document()
    document["matchers"] = [matcher]
    registry = _write_registry(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(RegistryError):
        load_registry(registry)


@pytest.mark.parametrize(
    "mutate",
    [
        "missing-source",
        "empty-sources",
        "descending",
        "duplicate-event",
        "event-after-removal",
        "missing-impact",
    ],
)
def test_registry_rejects_missing_sources_and_invalid_timelines(
    tmp_path: Path,
    mutate: str,
) -> None:
    """Every event is ordered, uniquely typed, sourced, and impact-mapped."""
    document = _bundled_rule_document()
    timeline = cast("list[dict[str, object]]", document["timeline"])
    if mutate == "missing-source":
        timeline[0]["source"] = "absent-source"
    elif mutate == "empty-sources":
        document["sources"] = []
    elif mutate == "descending":
        timeline.reverse()
    elif mutate == "duplicate-event":
        timeline[1]["event"] = "deprecated"
    elif mutate == "event-after-removal":
        timeline.append(
            {
                "event": "behavior_changed",
                "python": "3.14",
                "certainty": "released",
                "source": "pep-0594",
            }
        )
        cast("dict[str, object]", document["impact"])["on_behavior_change"] = "risk"
    else:
        del cast("dict[str, object]", document["impact"])["on_removal"]
    registry = _write_registry(tmp_path, yaml.safe_dump(document, sort_keys=False))

    with pytest.raises(RegistryError):
        load_registry(registry)


def test_registry_ids_are_filename_stable_unique_and_never_reused(
    tmp_path: Path,
) -> None:
    """Canonical IDs, aliases, filenames, and retired reservations cannot collide."""
    document = _bundled_rule_document()
    document["aliases"] = ["CPY0099"]
    registry = _write_registry(tmp_path / "filename", yaml.safe_dump(document))
    rule_path = registry / "cpython/CPY0001.yaml"
    mismatched = cast("dict[str, object]", yaml.safe_load(rule_path.read_text()))
    mismatched["id"] = "CPY0002"
    rule_path.write_text(yaml.safe_dump(mismatched), encoding="utf-8")

    with pytest.raises(RegistryError, match="filename"):
        load_registry(registry)

    retired_registry = _write_registry(
        tmp_path / "retired", yaml.safe_dump(document, sort_keys=False)
    )
    (retired_registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "retired_ids: [CPY0099]\n"
            "rules: [cpython/CPY0001.yaml]\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(RegistryError, match="retired"):
        load_registry(retired_registry)

    collision_registry = _write_registry(
        tmp_path / "collision", yaml.safe_dump(document, sort_keys=False)
    )
    second = _bundled_rule_document()
    second["id"] = "CPY0002"
    second["aliases"] = ["CPY0099"]
    (collision_registry / "cpython/CPY0002.yaml").write_text(
        yaml.safe_dump(second, sort_keys=False),
        encoding="utf-8",
    )
    (collision_registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "rules: [cpython/CPY0001.yaml, cpython/CPY0002.yaml]\n"
        ),
        encoding="utf-8",
    )
    with pytest.raises(RegistryError, match="already owned"):
        load_registry(collision_registry)


@pytest.mark.parametrize("tool", ["ruff", "pyupgrade"])
def test_automation_metadata_is_exposed_without_invoking_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool: str,
) -> None:
    """Verified external transform metadata remains inert registry data."""

    def refuse_execution(*_args: object, **_kwargs: object) -> NoReturn:
        message = "external tools must not execute while loading or explaining"
        raise AssertionError(message)

    monkeypatch.setattr(subprocess, "run", refuse_execution)
    document = _bundled_rule_document()
    remediation = cast("dict[str, object]", document["remediation"])
    remediation["documentation_url"] = "https://example.com/remediation"
    remediation["automation"] = {"tool": tool, "rule": "UP999"}
    registry_path = _write_registry(tmp_path, yaml.safe_dump(document, sort_keys=False))

    registry = load_registry(registry_path)
    automation = registry.rules[0].remediation.automation
    explanation = render_rule_explanation(registry, registry.rules[0])

    assert automation is not None
    assert automation.tool is AutomationTool(tool)
    assert automation.rule == "UP999"
    assert f"Automation metadata: {tool} UP999 (not invoked)" in explanation
