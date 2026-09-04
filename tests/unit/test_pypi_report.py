"""Hermetic unit tests for aggregating PyPI validation shards into a report."""

# ruff: noqa: SLF001

from __future__ import annotations

import csv
import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest

from scripts import pypi_report
from scripts.pypi_corpus import PackageEntry

if TYPE_CHECKING:
    from pathlib import Path

_CORPUS_SIZE = 1000
_MANIFEST_SHA = "m" * 64


# --- fixtures ----------------------------------------------------------------


def _entry(
    *,
    rank: int,
    name: str,
    version: str = "1.0.0",
    requires_python: str | None = None,
) -> PackageEntry:
    return PackageEntry(
        rank=rank,
        name=name,
        version=version,
        filename=f"{name}-{version}-py3-none-any.whl",
        sha256=hashlib.sha256(name.encode()).hexdigest(),
        requires_python=requires_python,
        is_wheel=True,
    )


def _base_shard(  # noqa: PLR0913 - mirrors the shard schema's own fields.
    *,
    rank: int,
    name: str,
    version: str = "1.0.0",
    manifest_sha256: str = _MANIFEST_SHA,
    status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "manifest_sha256": manifest_sha256,
        "package": {
            "rank": rank,
            "name": name,
            "version": version,
            "filename": f"{name}-{version}-py3-none-any.whl",
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
            "requires_python": None,
            "is_wheel": True,
        },
        "status": status,
        "reason": reason,
        "isolation_mode": None,
        "interpreter": None,
    }


def _finding(  # noqa: PLR0913 - mirrors the mapped-finding schema's own fields.
    *,
    fingerprint: str,
    adjudication_status: str,
    rule_id: str = "CPY0001",
    match_kind: str = "module-import",
    module: str = "pkg.mod",
    path: str = "pkg/mod.py",
    start_line: int = 1,
    subject: str = "cgi",
) -> dict[str, Any]:
    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "module": module,
        "subject": subject,
        "match": {"kind": match_kind, "confidence": "high", "evidence": {}},
        "location": {"path": path, "region": {"start": {"line": start_line}}},
        "adjudication_status": adjudication_status,
    }


def _padding_manifest_entries(*, start: int, end: int) -> list[dict[str, Any]]:
    return [
        {
            "rank": rank,
            "name": f"pad{rank}",
            "version": "1.0.0",
            "filename": f"pad{rank}-1.0.0-py3-none-any.whl",
            "sha256": hashlib.sha256(f"pad{rank}".encode()).hexdigest(),
            "requires_python": None,
            "is_wheel": True,
        }
        for rank in range(start, end + 1)
    ]


def _write_full_manifest(path: Path, entries: list[dict[str, Any]]) -> None:
    padding = _padding_manifest_entries(start=len(entries) + 1, end=_CORPUS_SIZE)
    document = {
        "packages": [*entries, *padding],
        "retrieved_on": "2026-09-03T12:00:00+00:00",
        "schema_version": 1,
        "source_url": "https://example.test/top-pypi-packages.json",
        "upstream_payload_sha256": "a" * 64,
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def _write_shard(shards_dir: Path, shard: dict[str, Any]) -> None:
    package = shard["package"]
    name = pypi_report._normalized_name(package["name"])
    path = shards_dir / f"{package['rank']:04d}-{name}.json"
    path.write_text(json.dumps(shard), encoding="utf-8")


def _write_padding_shards(
    shards_dir: Path, *, manifest_sha256: str, start: int, end: int
) -> None:
    for rank in range(start, end + 1):
        _write_shard(
            shards_dir,
            _base_shard(
                rank=rank,
                name=f"pad{rank}",
                manifest_sha256=manifest_sha256,
                status="skipped",
                reason="no-compatible-interpreter",
            ),
        )


# --- aggregation arithmetic ---------------------------------------------------


def test_build_record_computes_agreement_rate_and_coverage() -> None:
    """Verdict, coverage, and breakdown arithmetic matches the metric formulas."""
    entries = (
        _entry(rank=1, name="pkg1"),
        _entry(rank=2, name="pkg2"),
        _entry(rank=3, name="pkg3"),
        _entry(rank=4, name="pkg4"),
    )
    shards = [
        {
            **_base_shard(rank=1, name="pkg1", status="scanned"),
            "findings": [
                _finding(fingerprint="f1", adjudication_status="confirmed"),
                _finding(fingerprint="f2", adjudication_status="refuted-binding"),
            ],
        },
        {
            **_base_shard(rank=2, name="pkg2", status="scanned"),
            "findings": [
                _finding(fingerprint="f3", adjudication_status="refuted-timeline"),
                _finding(
                    fingerprint="f4",
                    adjudication_status="not-adjudicable:no-interpreter",
                ),
            ],
        },
        _base_shard(rank=3, name="pkg3", status="install-failed", reason="boom"),
        _base_shard(rank=4, name="pkg4", status="skipped", reason="no-python-files"),
    ]
    record = pypi_report._build_record(entries, shards, manifest_sha256=_MANIFEST_SHA)

    expected_packages_total = 4
    expected_packages_scanned = 2
    expected_findings_total = 4
    assert record["packages_total"] == expected_packages_total
    assert record["packages_scanned"] == expected_packages_scanned
    assert record["findings_total"] == expected_findings_total
    assert record["verdicts"] == {
        "confirmed": 1,
        "refuted-binding": 1,
        "refuted-timeline": 1,
        "not-adjudicable": 1,
    }
    assert record["agreement_rate"] == pytest.approx(1 / 3)
    assert record["adjudication_coverage"] == pytest.approx(3 / 4)
    assert record["not_adjudicable_reasons"] == {"no-interpreter": 1}
    assert record["by_rule"] == {
        "CPY0001": {
            "confirmed": 1,
            "not-adjudicable": 1,
            "refuted-binding": 1,
            "refuted-timeline": 1,
        }
    }
    assert record["by_match_kind"] == {
        "module-import": {
            "confirmed": 1,
            "not-adjudicable": 1,
            "refuted-binding": 1,
            "refuted-timeline": 1,
        }
    }
    assert record["skipped_packages"] == [
        {"name": "pkg3", "rank": 3, "reason": "boom", "status": "install-failed"},
        {"name": "pkg4", "rank": 4, "reason": "no-python-files", "status": "skipped"},
    ]


def test_build_record_reports_none_rates_with_no_findings() -> None:
    """An empty denominator yields `None`, not a division error or a fake zero."""
    entries = (_entry(rank=1, name="pkg1"),)
    shards = [
        _base_shard(rank=1, name="pkg1", status="skipped", reason="no-python-files")
    ]
    record = pypi_report._build_record(entries, shards, manifest_sha256=_MANIFEST_SHA)
    assert record["agreement_rate"] is None
    assert record["adjudication_coverage"] is None
    assert record["findings_total"] == 0


# --- shard loading and completeness verification ------------------------------


def test_load_shards_rejects_a_missing_shard(tmp_path: Path) -> None:
    """A manifest entry with no corresponding shard file fails closed."""
    entries = (_entry(rank=1, name="pkg1"), _entry(rank=2, name="pkg2"))
    shards_dir = tmp_path / "shards"
    shards_dir.mkdir()
    _write_shard(
        shards_dir, _base_shard(rank=1, name="pkg1", status="skipped", reason="x")
    )
    with pytest.raises(pypi_report.PypiReportError, match="missing shard"):
        pypi_report._load_shards(
            entries, shards_dir=shards_dir, manifest_sha256=_MANIFEST_SHA
        )


def test_load_shard_rejects_invalid_json(tmp_path: Path) -> None:
    """A truncated or corrupted shard file fails closed instead of guessing."""
    entry = _entry(rank=1, name="pkg1")
    path = tmp_path / "shard.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="not valid JSON"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_missing_required_fields(tmp_path: Path) -> None:
    """A shard missing a documented top-level field fails closed."""
    entry = _entry(rank=1, name="pkg1")
    path = tmp_path / "shard.json"
    path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="missing required fields"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    """A shard from a future or unknown schema version fails closed."""
    entry = _entry(rank=1, name="pkg1")
    shard = _base_shard(rank=1, name="pkg1", status="skipped", reason="x")
    shard["schema_version"] = 2
    path = tmp_path / "shard.json"
    path.write_text(json.dumps(shard), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="unsupported schema version"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_a_mismatched_manifest_digest(tmp_path: Path) -> None:
    """A shard produced against a different manifest is a 'mixed digests' failure."""
    entry = _entry(rank=1, name="pkg1")
    shard = _base_shard(
        rank=1, name="pkg1", manifest_sha256="different", status="skipped", reason="x"
    )
    path = tmp_path / "shard.json"
    path.write_text(json.dumps(shard), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="different manifest"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_a_rank_mismatch(tmp_path: Path) -> None:
    """A shard whose embedded package rank disagrees with the manifest fails closed."""
    entry = _entry(rank=1, name="pkg1")
    shard = _base_shard(rank=2, name="pkg1", status="skipped", reason="x")
    path = tmp_path / "shard.json"
    path.write_text(json.dumps(shard), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="does not match"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_a_scanned_shard_without_findings(tmp_path: Path) -> None:
    """A `scanned` shard missing its findings array is truncated, not empty."""
    entry = _entry(rank=1, name="pkg1")
    shard = _base_shard(rank=1, name="pkg1", status="scanned")
    path = tmp_path / "shard.json"
    path.write_text(json.dumps(shard), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="missing its findings array"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_load_shard_rejects_an_unrecognized_status(tmp_path: Path) -> None:
    """An unknown package status fails closed instead of being silently skipped."""
    entry = _entry(rank=1, name="pkg1")
    shard = _base_shard(rank=1, name="pkg1", status="bogus-status", reason="x")
    path = tmp_path / "shard.json"
    path.write_text(json.dumps(shard), encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="unrecognized status"):
        pypi_report._load_shard(path, entry=entry, manifest_sha256=_MANIFEST_SHA)


def test_record_finding_rejects_a_non_terminal_status() -> None:
    """A finding stuck at `pending` must not be silently dropped from the totals."""
    finding = _finding(fingerprint="f1", adjudication_status="pending")
    with pytest.raises(pypi_report.PypiReportError, match="unrecognized status"):
        pypi_report._record_finding(
            finding,
            verdicts={},
            not_adjudicable_reasons={},
            by_rule={},
            by_match_kind={},
        )


def test_record_finding_rejects_an_unrecognized_not_adjudicable_reason() -> None:
    """A closed reason vocabulary rejects an unknown `not-adjudicable:<reason>`."""
    finding = _finding(
        fingerprint="f1", adjudication_status="not-adjudicable:made-up-reason"
    )
    with pytest.raises(pypi_report.PypiReportError, match="not-adjudicable reason"):
        pypi_report._record_finding(
            finding,
            verdicts={},
            not_adjudicable_reasons={},
            by_rule={},
            by_match_kind={},
        )


# --- worksheet rows ------------------------------------------------------------


def test_worksheet_rows_always_includes_every_refuted_finding() -> None:
    """`refuted-*` findings are never subject to sampling."""
    shard = {
        **_base_shard(rank=1, name="pkg1", status="scanned"),
        "findings": [
            _finding(fingerprint="f1", adjudication_status="refuted-binding"),
            _finding(fingerprint="f2", adjudication_status="refuted-timeline"),
        ],
    }
    rows = pypi_report._worksheet_rows([shard], sample_size=0)
    assert {row["fingerprint"] for row in rows} == {"f1", "f2"}


def test_worksheet_rows_samples_confirmed_findings_deterministically() -> None:
    """A `confirmed` sample is capped at `sample_size` and stable across runs."""
    shard = {
        **_base_shard(rank=1, name="pkg1", status="scanned"),
        "findings": [
            _finding(fingerprint=f"f{i}", adjudication_status="confirmed")
            for i in range(10)
        ],
    }
    first = pypi_report._worksheet_rows([shard], sample_size=3)
    second = pypi_report._worksheet_rows([shard], sample_size=3)
    expected_sample_size = 3
    assert len(first) == expected_sample_size
    first_fingerprints = [row["fingerprint"] for row in first]
    second_fingerprints = [row["fingerprint"] for row in second]
    assert first_fingerprints == second_fingerprints


def test_worksheet_rows_ignores_findings_from_unscanned_shards() -> None:
    """A `skipped`/`install-failed` shard contributes no worksheet rows."""
    shard = _base_shard(rank=1, name="pkg1", status="skipped", reason="no-python-files")
    assert pypi_report._worksheet_rows([shard], sample_size=200) == []


def test_worksheet_rows_excludes_not_adjudicable_findings() -> None:
    """A `not-adjudicable` finding is neither always-included nor sampled."""
    shard = {
        **_base_shard(rank=1, name="pkg1", status="scanned"),
        "findings": [
            _finding(
                fingerprint="f1", adjudication_status="not-adjudicable:install-failed"
            ),
        ],
    }
    assert pypi_report._worksheet_rows([shard], sample_size=200) == []


# --- spreadsheet formula neutralisation ---------------------------------------


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r", "\n"])
def test_finding_row_neutralises_every_package_derived_field(prefix: str) -> None:
    """A package-derived column beginning with a formula prefix gets quoted."""
    package = {"rank": 1, "name": f"{prefix}cmd", "version": f"{prefix}1.0.0"}
    finding = _finding(
        fingerprint="f1",
        adjudication_status="confirmed",
        match_kind=f"{prefix}kind",
        module=f"{prefix}mod",
        path=f"{prefix}path.py",
        subject=f"{prefix}subject",
    )
    row = pypi_report._finding_row(package, finding)
    for field in pypi_report._PACKAGE_DERIVED_FIELDS:
        assert row[field].startswith("'" + prefix), field


def test_finding_row_leaves_a_benign_value_untouched() -> None:
    """A value with no formula prefix is passed through unquoted."""
    package = {"rank": 1, "name": "safe-package", "version": "1.0.0"}
    finding = _finding(fingerprint="f1", adjudication_status="confirmed")
    row = pypi_report._finding_row(package, finding)
    assert row["package_name"] == "safe-package"
    assert row["path"] == "pkg/mod.py"


# --- identity-bound worksheet round trip --------------------------------------


def test_render_and_verify_worksheet_identity_round_trip(tmp_path: Path) -> None:
    """A freshly rendered worksheet verifies against its own result digest."""
    package = {"rank": 1, "name": "pkg1", "version": "1.0.0"}
    finding = _finding(fingerprint="f1", adjudication_status="refuted-binding")
    rows = [pypi_report._finding_row(package, finding)]
    result_text = json.dumps({"schema_version": 1}) + "\n"
    result_path = tmp_path / "report.json"
    result_path.write_text(result_text, encoding="utf-8")
    digest = hashlib.sha256(result_text.encode()).hexdigest()
    worksheet_path = tmp_path / "worksheet.csv"
    worksheet_path.write_text(
        pypi_report._render_worksheet(rows, result_digest=digest), encoding="utf-8"
    )
    pypi_report._verify_worksheet_identity(result_path, worksheet_path)


def test_verify_worksheet_identity_rejects_a_tampered_result(tmp_path: Path) -> None:
    """A result file edited after the worksheet was rendered fails verification."""
    result_path = tmp_path / "report.json"
    result_path.write_text(json.dumps({"schema_version": 1}) + "\n", encoding="utf-8")
    digest = pypi_report._sha256_path(result_path)
    worksheet_path = tmp_path / "worksheet.csv"
    worksheet_path.write_text(
        pypi_report._render_worksheet([], result_digest=digest), encoding="utf-8"
    )
    result_path.write_text(json.dumps({"schema_version": 2}) + "\n", encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="does not match"):
        pypi_report._verify_worksheet_identity(result_path, worksheet_path)


def test_verify_worksheet_identity_rejects_the_wrong_schema(tmp_path: Path) -> None:
    """A worksheet with different columns is never treated as this schema."""
    result_path = tmp_path / "report.json"
    result_path.write_text("{}", encoding="utf-8")
    worksheet_path = tmp_path / "worksheet.csv"
    worksheet_path.write_text("a,b,c\n1,2,3\n", encoding="utf-8")
    with pytest.raises(pypi_report.PypiReportError, match="documented identity-bound"):
        pypi_report._verify_worksheet_identity(result_path, worksheet_path)


def test_verify_worksheet_identity_rejects_a_finding_bound_to_another_result(
    tmp_path: Path,
) -> None:
    """A finding row stamped with a different digest than the identity row fails."""
    result_path = tmp_path / "report.json"
    result_path.write_text("{}", encoding="utf-8")
    digest = pypi_report._sha256_path(result_path)
    with (tmp_path / "worksheet.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=pypi_report._WORKSHEET_FIELDS, lineterminator="\n"
        )
        writer.writeheader()
        identity_row = dict.fromkeys(pypi_report._WORKSHEET_FIELDS, "")
        identity_row.update({"row_kind": "report-identity", "report_sha256": digest})
        writer.writerow(identity_row)
        finding_row = dict.fromkeys(pypi_report._WORKSHEET_FIELDS, "")
        finding_row.update({"row_kind": "finding", "report_sha256": "not-the-digest"})
        writer.writerow(finding_row)
    with pytest.raises(pypi_report.PypiReportError, match="not bound to the report"):
        pypi_report._verify_worksheet_identity(result_path, tmp_path / "worksheet.csv")


def test_verify_worksheet_identity_rejects_an_unescaped_formula(tmp_path: Path) -> None:
    """A package-derived cell that lost its neutralising apostrophe fails closed."""
    result_path = tmp_path / "report.json"
    result_path.write_text("{}", encoding="utf-8")
    digest = pypi_report._sha256_path(result_path)
    with (tmp_path / "worksheet.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=pypi_report._WORKSHEET_FIELDS, lineterminator="\n"
        )
        writer.writeheader()
        identity_row = dict.fromkeys(pypi_report._WORKSHEET_FIELDS, "")
        identity_row.update({"row_kind": "report-identity", "report_sha256": digest})
        writer.writerow(identity_row)
        finding_row = dict.fromkeys(pypi_report._WORKSHEET_FIELDS, "")
        finding_row.update(
            {"row_kind": "finding", "report_sha256": digest, "path": "=cmd|calc"}
        )
        writer.writerow(finding_row)
    with pytest.raises(pypi_report.PypiReportError, match="unescaped spreadsheet"):
        pypi_report._verify_worksheet_identity(result_path, tmp_path / "worksheet.csv")


# --- full CLI pipeline ---------------------------------------------------------


def _prepare_pipeline(tmp_path: Path) -> tuple[Path, Path, str]:
    manifest_path = tmp_path / "manifest.json"
    _write_full_manifest(
        manifest_path,
        [
            {
                "rank": 1,
                "name": "cgiuser",
                "version": "1.0.0",
                "filename": "cgiuser-1.0.0-py3-none-any.whl",
                "sha256": hashlib.sha256(b"cgiuser").hexdigest(),
                "requires_python": None,
                "is_wheel": True,
            },
            {
                "rank": 2,
                "name": "shadowpkg",
                "version": "1.0.0",
                "filename": "shadowpkg-1.0.0-py3-none-any.whl",
                "sha256": hashlib.sha256(b"shadowpkg").hexdigest(),
                "requires_python": None,
                "is_wheel": True,
            },
        ],
    )
    manifest_sha256 = pypi_report._sha256_path(manifest_path)
    shards_dir = tmp_path / "shards"
    shards_dir.mkdir()
    _write_shard(
        shards_dir,
        {
            **_base_shard(
                rank=1,
                name="cgiuser",
                manifest_sha256=manifest_sha256,
                status="scanned",
            ),
            "findings": [
                _finding(fingerprint="f1", adjudication_status="confirmed"),
            ],
        },
    )
    _write_shard(
        shards_dir,
        {
            **_base_shard(
                rank=2,
                name="shadowpkg",
                manifest_sha256=manifest_sha256,
                status="scanned",
            ),
            "findings": [
                _finding(fingerprint="f2", adjudication_status="refuted-binding"),
            ],
        },
    )
    _write_padding_shards(
        shards_dir, manifest_sha256=manifest_sha256, start=3, end=_CORPUS_SIZE
    )
    return manifest_path, shards_dir, manifest_sha256


def test_main_aggregates_a_complete_shard_set_and_verifies_identity(
    tmp_path: Path,
) -> None:
    """The full pipeline produces a matching accuracy record and worksheet."""
    manifest_path, shards_dir, _ = _prepare_pipeline(tmp_path)
    output_path = tmp_path / "report.json"
    worksheet_path = tmp_path / "worksheet.csv"
    result = pypi_report.main(
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(shards_dir),
            "--output",
            str(output_path),
            "--worksheet",
            str(worksheet_path),
        ]
    )
    assert result == 0
    record = json.loads(output_path.read_text(encoding="utf-8"))
    expected_packages_scanned = 2
    expected_agreement_rate = 0.5
    assert record["packages_total"] == _CORPUS_SIZE
    assert record["packages_scanned"] == expected_packages_scanned
    assert record["verdicts"]["confirmed"] == 1
    assert record["verdicts"]["refuted-binding"] == 1
    assert record["agreement_rate"] == expected_agreement_rate

    verify_result = pypi_report.main(
        [
            "--output",
            str(output_path),
            "--worksheet",
            str(worksheet_path),
            "--verify-identity",
        ]
    )
    assert verify_result == 0


def test_main_is_deterministic_across_runs(tmp_path: Path) -> None:
    """Re-running against the same shard set reproduces byte-identical output."""
    manifest_path, shards_dir, _ = _prepare_pipeline(tmp_path)
    first_output, first_worksheet = tmp_path / "a.json", tmp_path / "a.csv"
    second_output, second_worksheet = tmp_path / "b.json", tmp_path / "b.csv"
    for output_path, worksheet_path in (
        (first_output, first_worksheet),
        (second_output, second_worksheet),
    ):
        assert (
            pypi_report.main(
                [
                    "--manifest",
                    str(manifest_path),
                    "--shards",
                    str(shards_dir),
                    "--output",
                    str(output_path),
                    "--worksheet",
                    str(worksheet_path),
                ]
            )
            == 0
        )
    assert first_output.read_bytes() == second_output.read_bytes()
    assert first_worksheet.read_bytes() == second_worksheet.read_bytes()


def test_main_fails_closed_on_a_missing_shard(tmp_path: Path) -> None:
    """An incomplete shard set is rejected instead of a partial denominator."""
    manifest_path, shards_dir, _ = _prepare_pipeline(tmp_path)
    (shards_dir / "0001-cgiuser.json").unlink()
    result = pypi_report.main(
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(shards_dir),
            "--output",
            str(tmp_path / "report.json"),
            "--worksheet",
            str(tmp_path / "worksheet.csv"),
        ]
    )
    assert result == 1


def test_main_fails_closed_on_a_mixed_manifest_digest(tmp_path: Path) -> None:
    """A shard from a different manifest breaks the run instead of skewing it."""
    manifest_path, shards_dir, manifest_sha256 = _prepare_pipeline(tmp_path)
    shard_path = shards_dir / "0001-cgiuser.json"
    tampered = json.loads(shard_path.read_text())
    tampered["manifest_sha256"] = "0" * 64
    assert tampered["manifest_sha256"] != manifest_sha256
    shard_path.write_text(json.dumps(tampered), encoding="utf-8")
    result = pypi_report.main(
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(shards_dir),
            "--output",
            str(tmp_path / "report.json"),
            "--worksheet",
            str(tmp_path / "worksheet.csv"),
        ]
    )
    assert result == 1


def test_main_fails_closed_on_a_truncated_shard(tmp_path: Path) -> None:
    """Invalid JSON in a shard file is treated as truncation, not an empty result."""
    manifest_path, shards_dir, _ = _prepare_pipeline(tmp_path)
    (shards_dir / "0001-cgiuser.json").write_text("{not json", encoding="utf-8")
    result = pypi_report.main(
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(shards_dir),
            "--output",
            str(tmp_path / "report.json"),
            "--worksheet",
            str(tmp_path / "worksheet.csv"),
        ]
    )
    assert result == 1


def test_main_verify_identity_rejects_a_tampered_output(tmp_path: Path) -> None:
    """`--verify-identity` fails closed once the report file has been edited."""
    manifest_path, shards_dir, _ = _prepare_pipeline(tmp_path)
    output_path = tmp_path / "report.json"
    worksheet_path = tmp_path / "worksheet.csv"
    assert (
        pypi_report.main(
            [
                "--manifest",
                str(manifest_path),
                "--shards",
                str(shards_dir),
                "--output",
                str(output_path),
                "--worksheet",
                str(worksheet_path),
            ]
        )
        == 0
    )
    document = json.loads(output_path.read_text(encoding="utf-8"))
    document["packages_scanned"] = 999
    output_path.write_text(json.dumps(document), encoding="utf-8")
    result = pypi_report.main(
        [
            "--output",
            str(output_path),
            "--worksheet",
            str(worksheet_path),
            "--verify-identity",
        ]
    )
    assert result == 1


def test_main_requires_a_manifest_unless_verifying_identity(tmp_path: Path) -> None:
    """Running without `--manifest` (and without `--verify-identity`) fails closed."""
    result = pypi_report.main(
        [
            "--shards",
            str(tmp_path / "shards"),
            "--output",
            str(tmp_path / "report.json"),
            "--worksheet",
            str(tmp_path / "worksheet.csv"),
        ]
    )
    assert result == 1


def test_main_rejects_colliding_output_and_worksheet_paths(tmp_path: Path) -> None:
    """The output and worksheet destinations must never be the same file."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    shards_dir = tmp_path / "shards"
    shards_dir.mkdir()
    same_path = tmp_path / "same.json"
    result = pypi_report.main(
        [
            "--manifest",
            str(manifest_path),
            "--shards",
            str(shards_dir),
            "--output",
            str(same_path),
            "--worksheet",
            str(same_path),
        ]
    )
    assert result == 1
