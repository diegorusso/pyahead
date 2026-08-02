"""Strict deterministic M4 baseline files."""

import json
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pyahead import __version__
from pyahead.model import ConfigurationError, ScanReport

_TOP_LEVEL_KEYS = frozenset(
    {"created_by", "findings", "registry_revision", "schema_version"}
)
_FINDING_KEYS = frozenset({"fingerprint", "path", "rule_id", "subject"})
_HEX_DIGITS = frozenset("0123456789abcdef")
_SHA256_HEX_LENGTH = 64


@dataclass(frozen=True)
class Baseline:
    """Validated baseline identity data used by gate evaluation."""

    fingerprints: frozenset[str]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous duplicate JSON members before schema validation."""
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = f"baseline JSON contains duplicate object member {key!r}"
            raise ConfigurationError(message)
        value[key] = item
    return value


def _mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        message = f"baseline {where} must be an object"
        raise ConfigurationError(message)
    return value


def _string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        message = f"baseline {where} must be a non-empty string"
        raise ConfigurationError(message)
    return value


def _validate_relative_path(value: object, index: int) -> None:
    path_text = _string(value, f"finding {index} path")
    path = PurePosixPath(path_text)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != path_text
        or "\\" in path_text
    ):
        message = f"baseline finding {index} path must be repository-relative POSIX"
        raise ConfigurationError(message)


def parse_baseline_document(value: object) -> Baseline:
    """Validate a closed-world baseline document."""
    document = _mapping(value, "document")
    if set(document) != _TOP_LEVEL_KEYS:
        message = (
            "baseline document must contain exactly schema_version, created_by, "
            "registry_revision, and findings"
        )
        raise ConfigurationError(message)
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        message = "baseline schema_version must equal 1"
        raise ConfigurationError(message)
    _string(document["created_by"], "created_by")
    _string(document["registry_revision"], "registry_revision")
    raw_findings = document["findings"]
    if not isinstance(raw_findings, list):
        message = "baseline findings must be an array"
        raise ConfigurationError(message)

    fingerprints: set[str] = set()
    for index, raw_finding in enumerate(raw_findings):
        finding = _mapping(raw_finding, f"finding {index}")
        if set(finding) != _FINDING_KEYS:
            message = f"baseline finding {index} has unknown or missing keys"
            raise ConfigurationError(message)
        fingerprint = _string(finding["fingerprint"], f"finding {index} fingerprint")
        if len(fingerprint) != _SHA256_HEX_LENGTH or not set(fingerprint).issubset(
            _HEX_DIGITS
        ):
            message = f"baseline finding {index} fingerprint must be lowercase SHA-256"
            raise ConfigurationError(message)
        if fingerprint in fingerprints:
            message = "baseline fingerprints must be unique"
            raise ConfigurationError(message)
        fingerprints.add(fingerprint)
        _string(finding["rule_id"], f"finding {index} rule_id")
        _validate_relative_path(finding["path"], index)
        _string(finding["subject"], f"finding {index} subject")
    return Baseline(fingerprints=frozenset(fingerprints))


def load_baseline(path: Path, root: Path) -> Baseline:
    """Read a baseline without permitting paths outside the project root."""
    label = path.name
    selected = path if path.is_absolute() else root / path
    try:
        resolved = selected.resolve(strict=True)
        resolved.relative_to(root)
        if not stat.S_ISREG(resolved.stat().st_mode):
            message = f"{label}: baseline is not a regular file"
            raise ConfigurationError(message)
        with resolved.open(encoding="utf-8") as stream:
            value = json.load(stream, object_pairs_hook=_unique_object)
    except FileNotFoundError as error:
        message = f"{label}: baseline file does not exist"
        raise ConfigurationError(message) from error
    except json.JSONDecodeError as error:
        message = f"{label}: baseline is not valid JSON"
        raise ConfigurationError(message) from error
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        message = f"{label}: baseline must remain beneath the project root"
        raise ConfigurationError(message) from error
    except (OSError, RuntimeError, UnicodeError) as error:
        message = f"{label}: unable to read baseline"
        raise ConfigurationError(message) from error
    return parse_baseline_document(value)


def baseline_document(report: ScanReport) -> dict[str, object]:
    """Build a deterministic baseline from current unsuppressed findings."""
    return {
        "created_by": f"pyahead {__version__}",
        "findings": [
            {
                "fingerprint": finding.fingerprint,
                "path": finding.location.path.as_posix(),
                "rule_id": finding.rule_id,
                "subject": finding.subject,
            }
            for finding in report.findings
            if finding.suppression is None
        ],
        "registry_revision": report.registry_revision,
        "schema_version": 1,
    }


def render_baseline(report: ScanReport) -> str:
    """Serialize a byte-stable baseline file."""
    return (
        json.dumps(
            baseline_document(report),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "Baseline",
    "baseline_document",
    "load_baseline",
    "parse_baseline_document",
    "render_baseline",
]
