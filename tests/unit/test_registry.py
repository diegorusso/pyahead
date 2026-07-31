"""Tests for safe bundled-registry loading."""

from pathlib import Path

import pytest
import yaml

from pyahead.model import ChangeEventKind, Impact, RegistryCertainty
from pyahead.registry import RegistryError, load_registry

_SHA256_HEX_LENGTH = 64
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
    assert len(registry.rules) == 1
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
    index = _BUNDLED_REGISTRY / "index.yaml"
    rule = _BUNDLED_REGISTRY / "cpython/CPY0001.yaml"
    (registry_dir / "index.yaml").write_text(index.read_text(encoding="utf-8"))
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


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("id: CPY0001", "id: invalid"),
        ("kind: module\n  name: cgi", "kind: function\n  name: cgi"),
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
