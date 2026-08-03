"""Tests for strict baseline creation and identity matching."""

import json
from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.baseline import (
    load_baseline,
    parse_baseline_document,
    render_baseline,
)
from pyahead.model import (
    BaselineStatus,
    ConfigurationError,
    MatchConfidence,
    ScanReport,
)


def _scan(
    root: Path,
    *,
    baseline_file: Path | None = None,
    minimum_confidence: MatchConfidence | None = None,
) -> ScanReport:
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.13",
            baseline_file=baseline_file,
            fail_new_only=baseline_file is not None,
            minimum_confidence=minimum_confidence,
        )
    )


def test_baseline_round_trip_and_line_shift_preserve_existing_status(
    tmp_path: Path,
) -> None:
    """Fingerprint identity is independent of physical line numbers."""
    source = tmp_path / "legacy.py"
    source.write_text("import cgi\n", encoding="utf-8")
    initial = _scan(tmp_path)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_baseline(initial), encoding="utf-8")

    parsed = load_baseline(baseline_path, tmp_path)
    source.write_text("\n\nimport cgi\n", encoding="utf-8")
    shifted = _scan(tmp_path, baseline_file=Path("baseline.json"))

    assert parsed.fingerprints == frozenset({initial.findings[0].fingerprint})
    assert shifted.findings[0].baseline_status is BaselineStatus.EXISTING
    assert shifted.gate_failed is False


def test_baseline_move_is_documented_as_a_new_fingerprint(
    tmp_path: Path,
) -> None:
    """Moving a finding changes its repository-relative identity."""
    source = tmp_path / "legacy.py"
    source.write_text("import cgi\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_baseline(_scan(tmp_path)), encoding="utf-8")
    source.rename(tmp_path / "moved.py")

    moved = _scan(tmp_path, baseline_file=Path("baseline.json"))

    assert moved.findings[0].baseline_status is BaselineStatus.NEW
    assert moved.gate_failed is True


def test_stricter_confidence_filter_preserves_baseline_identity(
    tmp_path: Path,
) -> None:
    """A filtered earlier match still contributes to later occurrence ordinals."""
    (tmp_path / "legacy.py").write_text(
        'import importlib\nimportlib.import_module("cgi")\nimport cgi\n',
        encoding="utf-8",
    )
    medium = _scan(tmp_path, minimum_confidence=MatchConfidence.MEDIUM)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(render_baseline(medium), encoding="utf-8")

    strict = _scan(
        tmp_path,
        baseline_file=Path("baseline.json"),
        minimum_confidence=MatchConfidence.HIGH,
    )

    assert [finding.match_confidence for finding in medium.findings] == [
        MatchConfidence.MEDIUM,
        MatchConfidence.HIGH,
    ]
    assert len(strict.findings) == 1
    assert strict.findings[0].fingerprint == medium.findings[1].fingerprint
    assert strict.findings[0].baseline_status is BaselineStatus.EXISTING
    assert strict.gate_failed is False


@pytest.mark.parametrize(
    "document",
    [
        {},
        {
            "schema_version": 2,
            "created_by": "pyahead",
            "registry_revision": "revision",
            "findings": [],
        },
        {
            "schema_version": 1,
            "created_by": "pyahead",
            "registry_revision": "revision",
            "findings": "invalid",
        },
        {
            "schema_version": 1,
            "created_by": "pyahead",
            "registry_revision": "revision",
            "findings": [
                {
                    "fingerprint": "not-a-digest",
                    "rule_id": "CPY0001",
                    "path": "legacy.py",
                    "subject": "cgi",
                }
            ],
        },
        {
            "schema_version": 1,
            "created_by": "pyahead",
            "registry_revision": "revision",
            "findings": [
                {
                    "fingerprint": "a" * 64,
                    "rule_id": "CPY0001",
                    "path": "../legacy.py",
                    "subject": "cgi",
                }
            ],
        },
        {
            "schema_version": 1,
            "created_by": "pyahead",
            "registry_revision": "revision",
            "findings": [
                {
                    "fingerprint": "a" * 64,
                    "rule_id": "CPY0001",
                    "path": "legacy.py",
                    "subject": "cgi",
                    "unknown": True,
                }
            ],
        },
    ],
)
def test_baseline_schema_is_closed_and_strict(document: object) -> None:
    """Malformed or schema-drifted baseline data is rejected."""
    with pytest.raises(ConfigurationError):
        parse_baseline_document(document)


def test_duplicate_fingerprints_are_rejected() -> None:
    """One identity cannot occur more than once in a baseline."""
    finding = {
        "fingerprint": "a" * 64,
        "rule_id": "CPY0001",
        "path": "legacy.py",
        "subject": "cgi",
    }
    document = {
        "schema_version": 1,
        "created_by": "pyahead",
        "registry_revision": "revision",
        "findings": [finding, dict(finding)],
    }

    with pytest.raises(ConfigurationError, match="unique"):
        parse_baseline_document(document)


def test_baseline_load_errors_are_concise_and_root_bounded(
    tmp_path: Path,
) -> None:
    """Missing, invalid, and escaping baseline paths fail as configuration."""
    outside = tmp_path.parent / "outside-baseline.json"
    outside.write_text("{}", encoding="utf-8")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="does not exist"):
        load_baseline(Path("missing.json"), tmp_path)
    with pytest.raises(ConfigurationError, match="valid JSON"):
        load_baseline(invalid, tmp_path)
    with pytest.raises(ConfigurationError, match="beneath"):
        load_baseline(outside, tmp_path)


@pytest.mark.parametrize(
    "document",
    [
        (
            '{"schema_version":2,"schema_version":1,"created_by":"pyahead",'
            '"registry_revision":"revision","findings":[]}'
        ),
        (
            '{"schema_version":1,"created_by":"pyahead",'
            '"registry_revision":"revision","findings":[{'
            f'"fingerprint":"{"a" * 64}","rule_id":"CPY0001",'
            '"path":"wrong.py","path":"legacy.py","subject":"cgi"}]}'
        ),
    ],
)
def test_baseline_load_rejects_duplicate_json_members(
    tmp_path: Path,
    document: str,
) -> None:
    """Raw duplicate keys cannot be collapsed before closed-world validation."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(document, encoding="utf-8")

    with pytest.raises(ConfigurationError, match="duplicate object member"):
        load_baseline(baseline, tmp_path)


def test_rendered_baseline_is_sorted_deterministic_json(tmp_path: Path) -> None:
    """Baseline creation emits stable metadata and source-order identities."""
    (tmp_path / "legacy.py").write_text(
        "import cgi\n\ndef use():\n    import cgi\n",
        encoding="utf-8",
    )

    first = render_baseline(_scan(tmp_path))
    second = render_baseline(_scan(tmp_path))
    document = json.loads(first)

    assert first == second
    assert document["schema_version"] == 1
    assert document["created_by"].startswith("pyahead ")
    assert [item["path"] for item in document["findings"]] == [
        "legacy.py",
        "legacy.py",
    ]
