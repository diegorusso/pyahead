"""Aggregate PyPI validation shards into an accuracy record and worksheet.

This is the final, offline stage of the PyPI validation harness. It reads the
per-package shards written by `pypi_validate.py run`, verifies the shard set
is complete and internally consistent, and emits a deterministic accuracy
record plus an identity-bound disagreement worksheet for triage.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pyahead._human_text import SafeArgumentParser, escape_terminal_text
from scripts import pypi_corpus

if TYPE_CHECKING:
    from scripts.pypi_corpus import PackageEntry

_SPREADSHEET_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")

_PACKAGE_DERIVED_FIELDS = (
    "package_name",
    "package_version",
    "module",
    "path",
    "subject",
    "match_kind",
)

_WORKSHEET_FIELDS = (
    "row_kind",
    "report_sha256",
    "sample_rank",
    "package_rank",
    "package_name",
    "package_version",
    "rule_id",
    "fingerprint",
    "module",
    "path",
    "start_line",
    "subject",
    "match_kind",
    "adjudication_status",
    "classification",
    "reviewer",
    "notes",
    "regression_fixture",
)

_TERMINAL_VERDICTS = (
    "confirmed",
    "refuted-binding",
    "refuted-timeline",
    "not-adjudicable",
)
_SAMPLED_VERDICT = "confirmed"
_ALWAYS_INCLUDED_VERDICTS = frozenset({"refuted-binding", "refuted-timeline"})
_REQUIRED_SHARD_FIELDS = frozenset(
    {"schema_version", "manifest_sha256", "package", "status"}
)
_SHARD_STATUSES = frozenset({"scanned", "skipped", "install-failed", "scan-failed"})
_NOT_ADJUDICABLE_REASONS = frozenset(
    {
        "install-failed",
        "module-not-importable",
        "import-error",
        "import-timeout",
        "binding-not-visible",
        "no-signature",
        "probe-timeout",
        "probe-crashed",
        "no-interpreter",
    }
)


class PypiReportError(RuntimeError):
    """Raised when a PyPI validation report would be incomplete or untrustworthy."""


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        message = "value must be an integer"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "value must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def _normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# --- shard loading and completeness verification ----------------------------


def _shard_path(shards_dir: Path, entry: PackageEntry) -> Path:
    return shards_dir / f"{entry.rank:04d}-{_normalized_name(entry.name)}.json"


def _load_shard(
    path: Path, *, entry: PackageEntry, manifest_sha256: str
) -> dict[str, Any]:
    label = f"rank {entry.rank} ({entry.name})"
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        message = f"shard for {label} is not valid JSON"
        raise PypiReportError(message) from error
    if not isinstance(document, dict) or not _REQUIRED_SHARD_FIELDS.issubset(document):
        message = f"shard for {label} is missing required fields"
        raise PypiReportError(message)
    if document["schema_version"] != 1:
        message = f"shard for {label} uses an unsupported schema version"
        raise PypiReportError(message)
    if document["status"] not in _SHARD_STATUSES:
        message = f"shard for {label} has an unrecognized status {document['status']!r}"
        raise PypiReportError(message)
    if document["manifest_sha256"] != manifest_sha256:
        message = f"shard for {label} was produced against a different manifest"
        raise PypiReportError(message)
    package = document["package"]
    if not isinstance(package, dict) or package.get("rank") != entry.rank:
        message = f"shard for {label} does not match its manifest entry"
        raise PypiReportError(message)
    findings_present = isinstance(document.get("findings"), list)
    if document["status"] == "scanned" and not findings_present:
        message = f"shard for {label} is missing its findings array"
        raise PypiReportError(message)
    return document


def _load_shards(
    entries: tuple[PackageEntry, ...], *, shards_dir: Path, manifest_sha256: str
) -> list[dict[str, Any]]:
    """Load every manifest entry's shard, failing closed on any that is absent."""
    missing: list[str] = []
    shards: list[dict[str, Any]] = []
    for entry in entries:
        path = _shard_path(shards_dir, entry)
        if not path.is_file():
            missing.append(f"rank {entry.rank} ({entry.name})")
            continue
        shards.append(_load_shard(path, entry=entry, manifest_sha256=manifest_sha256))
    if missing:
        shown = ", ".join(missing[:5])
        suffix = ", ..." if len(missing) > 5 else ""  # noqa: PLR2004 - a short preview length.
        message = f"missing shard(s) for {len(missing)} package(s): {shown}{suffix}"
        raise PypiReportError(message)
    return shards


# --- accuracy record ---------------------------------------------------------


def _verdict_key(adjudication_status: str) -> str:
    return (
        "not-adjudicable"
        if adjudication_status.startswith("not-adjudicable:")
        else adjudication_status
    )


def _record_finding(
    finding: dict[str, Any],
    *,
    verdicts: dict[str, int],
    not_adjudicable_reasons: dict[str, int],
    by_rule: dict[str, dict[str, int]],
    by_match_kind: dict[str, dict[str, int]],
) -> None:
    status = finding["adjudication_status"]
    key = _verdict_key(status)
    if key not in _TERMINAL_VERDICTS:
        message = (
            f"finding {finding.get('fingerprint')!r} has an unrecognized status "
            f"{status!r}"
        )
        raise PypiReportError(message)
    verdicts[key] = verdicts.get(key, 0) + 1
    if key == "not-adjudicable":
        reason = status.removeprefix("not-adjudicable:")
        if reason not in _NOT_ADJUDICABLE_REASONS:
            message = (
                f"finding {finding.get('fingerprint')!r} has an unrecognized "
                f"not-adjudicable reason {reason!r}"
            )
            raise PypiReportError(message)
        not_adjudicable_reasons[reason] = not_adjudicable_reasons.get(reason, 0) + 1
    rule_counts = by_rule.setdefault(finding["rule_id"], {})
    rule_counts[key] = rule_counts.get(key, 0) + 1
    kind_counts = by_match_kind.setdefault(finding["match"]["kind"], {})
    kind_counts[key] = kind_counts.get(key, 0) + 1


def _build_record(
    entries: tuple[PackageEntry, ...],
    shards: list[dict[str, Any]],
    *,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Aggregate loaded shards into one deterministic accuracy record."""
    skipped_packages: list[dict[str, Any]] = []
    verdicts: dict[str, int] = dict.fromkeys(_TERMINAL_VERDICTS, 0)
    not_adjudicable_reasons: dict[str, int] = {}
    by_rule: dict[str, dict[str, int]] = {}
    by_match_kind: dict[str, dict[str, int]] = {}
    packages_scanned = 0

    for shard in shards:
        package = shard["package"]
        if shard["status"] != "scanned":
            skipped_packages.append(
                {
                    "rank": package["rank"],
                    "name": package["name"],
                    "status": shard["status"],
                    "reason": shard.get("reason"),
                }
            )
            continue
        packages_scanned += 1
        for finding in shard["findings"]:
            _record_finding(
                finding,
                verdicts=verdicts,
                not_adjudicable_reasons=not_adjudicable_reasons,
                by_rule=by_rule,
                by_match_kind=by_match_kind,
            )

    skipped_packages.sort(key=lambda item: int(item["rank"]))
    confirmed = verdicts["confirmed"]
    refuted_binding = verdicts["refuted-binding"]
    refuted_timeline = verdicts["refuted-timeline"]
    adjudicated = confirmed + refuted_binding + refuted_timeline
    findings_total = adjudicated + verdicts["not-adjudicable"]

    return {
        "schema_version": 1,
        "manifest_sha256": manifest_sha256,
        "packages_total": len(entries),
        "packages_scanned": packages_scanned,
        "skipped_packages": skipped_packages,
        "findings_total": findings_total,
        "verdicts": verdicts,
        "not_adjudicable_reasons": dict(sorted(not_adjudicable_reasons.items())),
        "agreement_rate": (confirmed / adjudicated) if adjudicated else None,
        "adjudication_coverage": (
            (adjudicated / findings_total) if findings_total else None
        ),
        "by_rule": {
            rule_id: dict(sorted(counts.items()))
            for rule_id, counts in sorted(by_rule.items())
        },
        "by_match_kind": {
            kind: dict(sorted(counts.items()))
            for kind, counts in sorted(by_match_kind.items())
        },
    }


# --- disagreement worksheet ---------------------------------------------------


def _spreadsheet_safe(value: str) -> str:
    """Neutralize a value a spreadsheet would otherwise evaluate as a formula.

    Package-derived worksheet columns carry attacker-chosen text: a scanned
    file may legally be named `=cmd|...` or a PyPI project may be registered
    as `-x`. The review worksheet is opened in a spreadsheet, so such a value
    is quoted with a leading apostrophe rather than left to execute.
    """
    if value.startswith(_SPREADSHEET_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _sample_rank(package: dict[str, Any], finding: dict[str, Any]) -> str:
    identity = "\0".join(
        (
            str(package["rank"]),
            str(package["name"]),
            str(package["version"]),
            str(finding["fingerprint"]),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()


def _finding_row(package: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location")
    location = location if isinstance(location, dict) else {}
    region = location.get("region")
    region = region if isinstance(region, dict) else {}
    start = region.get("start")
    start = start if isinstance(start, dict) else {}
    row = {
        "row_kind": "finding",
        "sample_rank": _sample_rank(package, finding),
        "package_rank": package["rank"],
        "package_name": str(package["name"]),
        "package_version": str(package["version"]),
        "rule_id": finding["rule_id"],
        "fingerprint": finding["fingerprint"],
        "module": str(finding.get("module", "")),
        "path": str(location.get("path", "")),
        "start_line": start.get("line", ""),
        "subject": str(finding.get("subject", "")),
        "match_kind": str(finding["match"]["kind"]),
        "adjudication_status": finding["adjudication_status"],
        "classification": "",
        "reviewer": "",
        "notes": "",
        "regression_fixture": "",
    }
    for field in _PACKAGE_DERIVED_FIELDS:
        row[field] = _spreadsheet_safe(str(row[field]))
    return row


def _worksheet_rows(
    shards: list[dict[str, Any]], *, sample_size: int
) -> list[dict[str, Any]]:
    always_included: list[dict[str, Any]] = []
    sample_candidates: list[dict[str, Any]] = []
    for shard in shards:
        if shard["status"] != "scanned":
            continue
        package = shard["package"]
        for finding in shard["findings"]:
            key = _verdict_key(finding["adjudication_status"])
            if key in _ALWAYS_INCLUDED_VERDICTS:
                always_included.append(_finding_row(package, finding))
            elif key == _SAMPLED_VERDICT:
                sample_candidates.append(_finding_row(package, finding))

    sample_candidates.sort(key=lambda row: str(row["sample_rank"]))
    rows = [*always_included, *sample_candidates[:sample_size]]
    rows.sort(key=lambda row: str(row["sample_rank"]))
    return rows


def _write_atomic(path: Path, content: str) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_path.replace(destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _render_worksheet(rows: list[dict[str, Any]], *, result_digest: str) -> str:
    with tempfile.SpooledTemporaryFile(
        mode="w+", encoding="utf-8", newline="", max_size=1_048_576
    ) as stream:
        writer = csv.DictWriter(
            stream, fieldnames=_WORKSHEET_FIELDS, lineterminator="\n"
        )
        writer.writeheader()
        identity = dict.fromkeys(_WORKSHEET_FIELDS, "")
        identity.update({"report_sha256": result_digest, "row_kind": "report-identity"})
        writer.writerow(identity)
        for row in rows:
            writer.writerow({**row, "report_sha256": result_digest})
        stream.seek(0)
        return stream.read()


def _verify_worksheet_identity(result_path: Path, worksheet_path: Path) -> None:
    expected = _sha256_path(result_path)
    with worksheet_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != _WORKSHEET_FIELDS:
            message = "worksheet does not use the documented identity-bound schema"
            raise PypiReportError(message)
        rows = list(reader)
    if not rows or rows[0]["row_kind"] != "report-identity":
        message = "worksheet is missing its report identity row"
        raise PypiReportError(message)
    if rows[0]["report_sha256"] != expected:
        message = "worksheet report identity does not match the result"
        raise PypiReportError(message)
    for row in rows[1:]:
        if row["row_kind"] != "finding" or row["report_sha256"] != expected:
            message = "worksheet finding is not bound to the report result"
            raise PypiReportError(message)
    for line, row in enumerate(rows, start=2):
        for field in _PACKAGE_DERIVED_FIELDS:
            value = row.get(field)
            if isinstance(value, str) and value.startswith(
                _SPREADSHEET_FORMULA_PREFIXES
            ):
                message = (
                    f"worksheet line {line} has an unescaped spreadsheet formula "
                    f"in {field}; package-derived values keep their apostrophe"
                )
                raise PypiReportError(message)


# --- CLI ----------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="pyahead-pypi-report",
        description="aggregate PyPI validation shards into an accuracy record",
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--shards", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worksheet", type=Path, required=True)
    parser.add_argument(
        "--verify-identity",
        action="store_true",
        help="verify that an existing worksheet is bound to its report result",
    )
    parser.add_argument("--sample-size", type=_positive_integer, default=200)
    return parser


def _require_manifest(path: Path | None) -> Path:
    if path is None:
        message = "--manifest is required unless --verify-identity is used"
        raise PypiReportError(message)
    return path


def _require_shards(path: Path | None) -> Path:
    if path is None:
        message = "--shards is required unless --verify-identity is used"
        raise PypiReportError(message)
    return path


def _validate_destinations(manifest: Path, destinations: tuple[Path, Path]) -> None:
    resolved = tuple(path.resolve() for path in destinations)
    if len(set(resolved)) != len(resolved) or manifest.resolve() in resolved:
        message = "report output, worksheet, and manifest must be distinct paths"
        raise PypiReportError(message)


def main(argv: list[str] | None = None) -> int:
    """Aggregate PyPI validation shards or verify a worksheet's identity binding."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.verify_identity:
            _verify_worksheet_identity(arguments.output, arguments.worksheet)
            return 0

        manifest_path = _require_manifest(arguments.manifest).resolve(strict=True)
        shards_dir = _require_shards(arguments.shards).resolve(strict=True)
        _validate_destinations(manifest_path, (arguments.output, arguments.worksheet))

        _, entries = pypi_corpus.load_manifest(manifest_path)
        manifest_sha256 = _sha256_path(manifest_path)
        shards = _load_shards(
            entries, shards_dir=shards_dir, manifest_sha256=manifest_sha256
        )

        record = _build_record(entries, shards, manifest_sha256=manifest_sha256)
        result_text = json.dumps(record, indent=2, sort_keys=True) + "\n"
        result_digest = hashlib.sha256(result_text.encode()).hexdigest()

        rows = _worksheet_rows(shards, sample_size=arguments.sample_size)
        worksheet_text = _render_worksheet(rows, result_digest=result_digest)

        _write_atomic(arguments.output, result_text)
        _write_atomic(arguments.worksheet, worksheet_text)
    except (PypiReportError, pypi_corpus.PypiCorpusError, OSError) as error:
        rendered = escape_terminal_text(str(error))
        sys.stderr.write(f"pypi report run failed: {rendered}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
