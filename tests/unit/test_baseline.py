"""Tests for strict baseline creation and identity matching."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

import pyahead.baseline as baseline_module
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

_EXPECTED_BASELINE_FINDINGS = 100_000


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


def _baseline_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "created_by": "pyahead",
        "registry_revision": "revision",
        "findings": [
            {
                "fingerprint": "a" * 64,
                "rule_id": "CPY0001",
                "path": "legacy.py",
                "subject": "cgi",
            }
        ],
    }


def test_baseline_document_byte_limit_is_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rooted loader accepts exactly its cap and rejects one extra byte."""
    assert baseline_module.MAX_BASELINE_BYTES == 32 * 1024 * 1024
    raw = json.dumps(_baseline_value(), separators=(",", ":")).encode()
    monkeypatch.setattr(baseline_module, "MAX_BASELINE_BYTES", len(raw))
    baseline = tmp_path / "baseline.json"
    baseline.write_bytes(raw)

    assert load_baseline(baseline, tmp_path).fingerprints == frozenset({"a" * 64})

    baseline.write_bytes(raw + b" ")
    with pytest.raises(ConfigurationError, match="baseline exceeds"):
        load_baseline(baseline, tmp_path)


def test_baseline_finding_count_limit_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The finite finding bound accepts its cap and rejects cap plus one."""
    assert baseline_module.MAX_BASELINE_FINDINGS == _EXPECTED_BASELINE_FINDINGS
    document = _baseline_value()
    first = document["findings"]
    assert isinstance(first, list)
    second = dict(first[0])
    second["fingerprint"] = "b" * 64
    monkeypatch.setattr(baseline_module, "MAX_BASELINE_FINDINGS", 1)

    assert parse_baseline_document(document).fingerprints == frozenset({"a" * 64})
    first.append(second)
    with pytest.raises(ConfigurationError, match="1-finding limit"):
        parse_baseline_document(document)


@pytest.mark.parametrize(
    "field",
    ["created_by", "registry_revision", "rule_id", "path", "subject"],
)
def test_baseline_variable_text_limit_is_exact(field: str) -> None:
    """Every caller-controlled baseline string has the same finite character cap."""
    document = _baseline_value()
    findings = document["findings"]
    assert isinstance(findings, list)
    finding = findings[0]
    assert isinstance(finding, dict)
    target = document if field in {"created_by", "registry_revision"} else finding
    target[field] = "a" * baseline_module.MAX_BASELINE_TEXT_CHARACTERS

    parse_baseline_document(document)

    target[field] = "a" * (baseline_module.MAX_BASELINE_TEXT_CHARACTERS + 1)
    with pytest.raises(ConfigurationError, match="character limit"):
        parse_baseline_document(document)


def test_baseline_producer_obeys_loader_count_text_and_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline creation cannot emit a document that its own loader rejects."""
    (tmp_path / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    report = _scan(tmp_path)
    finding = report.findings[0]

    monkeypatch.setattr(baseline_module, "MAX_BASELINE_FINDINGS", 1)
    with pytest.raises(ConfigurationError, match="finding limit"):
        render_baseline(
            replace(
                report,
                findings=(
                    finding,
                    replace(finding, fingerprint="b" * 64),
                ),
            )
        )

    monkeypatch.setattr(baseline_module, "MAX_BASELINE_FINDINGS", 100_000)
    with pytest.raises(ConfigurationError, match="character limit"):
        render_baseline(
            replace(
                report,
                findings=(
                    replace(
                        finding,
                        subject=(
                            "x" * (baseline_module.MAX_BASELINE_TEXT_CHARACTERS + 1)
                        ),
                    ),
                ),
            )
        )

    rendered = render_baseline(report)
    monkeypatch.setattr(
        baseline_module,
        "MAX_BASELINE_BYTES",
        len(rendered.encode()) - 1,
    )
    with pytest.raises(ConfigurationError, match="baseline exceeds"):
        render_baseline(report)


def test_baseline_symlink_is_rejected(tmp_path: Path) -> None:
    """A stable in-root baseline alias is never followed."""
    target = tmp_path / "target.json"
    target.write_text(json.dumps(_baseline_value()), encoding="utf-8")
    selected = tmp_path / "baseline.json"
    try:
        selected.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ConfigurationError, match="not a regular file"):
        load_baseline(selected, tmp_path)


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
