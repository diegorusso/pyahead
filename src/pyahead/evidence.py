"""Strict M7 warning-evidence ingestion and static/dynamic linking."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NoReturn, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

from pyahead.model import (
    ConfigurationError,
    EvidenceArtifact,
    EvidenceEnvironment,
    EvidenceFreshness,
    EvidenceLocation,
    EvidenceRelationship,
    EvidenceRelationshipKind,
    Finding,
    FindingState,
    ObservedWarning,
    ScanReport,
)
from pyahead.versions import PythonMinor

JsonScalar: TypeAlias = bool | int | str | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

_TOP_LEVEL_KEYS = frozenset(
    {"environment", "provider", "run", "schema_version", "source", "warnings"}
)
_PROVIDER_KEYS = frozenset({"name", "version"})
_SOURCE_KEYS = frozenset({"commit"})
_ENVIRONMENT_KEYS = frozenset({"implementation", "platform", "python_version"})
_RUN_KEYS = frozenset(
    {
        "exit_code",
        "framework",
        "framework_version",
        "tests_collected",
        "warnings_complete",
        "warnings_dropped",
    }
)
_WARNING_REQUIRED_KEYS = frozenset(
    {"category", "kind", "message", "occurrences", "phase"}
)
_WARNING_OPTIONAL_KEYS = frozenset({"location", "test_node"})
_LOCATION_KEYS = frozenset({"line", "path"})
_COMMIT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_PYTHON_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+._a-zA-Z0-9]*)?\Z")
_SUPPORTED_EVIDENCE_MAJOR = 3
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_WARNINGS = 100_000
MAX_EVIDENCE_ARTIFACTS = 64
MAX_TOTAL_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_EVIDENCE_WARNINGS = 100_000
MAX_EVIDENCE_CANDIDATE_CHECKS = 1_000_000
MAX_EVIDENCE_RELATIONSHIPS = 200_000
_MAX_MESSAGE_LENGTH = 16_384
_MAX_TEXT_LENGTH = 4_096
_SOURCE_COMMIT_ENVIRONMENT = ("PYAHEAD_COMMIT", "GITHUB_SHA", "CI_COMMIT_SHA")
_WARNING_KINDS = frozenset({"deprecation-warning", "pending-deprecation-warning"})
_WARNING_PHASES = frozenset({"collect", "config", "runtest"})


@dataclass(frozen=True)
class WarningEvidence:
    """One strict warning record from a pytest evidence artifact."""

    kind: str
    category: str
    message: str
    phase: str
    location: EvidenceLocation | None
    test_node: str | None
    occurrences: int


@dataclass(frozen=True)
class EvidenceDocument:
    """Validated schema-version-1 pytest warning artifact."""

    provider: str
    provider_version: str
    source_commit: str
    environment: EvidenceEnvironment
    framework: str
    framework_version: str
    tests_collected: int
    exit_code: int
    warnings_complete: bool
    warnings_dropped: int
    warnings: tuple[WarningEvidence, ...]


class EvidenceSizeError(ConfigurationError):
    """Raised when even an empty warning artifact cannot fit the byte contract."""


@dataclass(frozen=True)
class _LoadedEvidence:
    path: PurePosixPath
    artifact_id: str
    byte_count: int
    document: EvidenceDocument


@dataclass(frozen=True)
class _FindingInterval:
    ordinal: int
    start: int
    end: int
    finding: Finding


@dataclass(frozen=True)
class _FindingIntervalNode:
    center: int
    crossing_by_start: tuple[_FindingInterval, ...]
    crossing_by_end: tuple[_FindingInterval, ...]
    left: _FindingIntervalNode | None
    right: _FindingIntervalNode | None

    def query(self, line: int, matches: list[_FindingInterval]) -> None:
        """Append only intervals containing one line."""
        if line < self.center:
            for interval in self.crossing_by_start:
                if interval.start > line:
                    break
                matches.append(interval)
            if self.left is not None:
                self.left.query(line, matches)
            return
        if line > self.center:
            for interval in self.crossing_by_end:
                if interval.end < line:
                    break
                matches.append(interval)
            if self.right is not None:
                self.right.query(line, matches)
            return
        matches.extend(self.crossing_by_start)


@dataclass(frozen=True)
class _FindingLocationIndex:
    by_path: dict[PurePosixPath, _FindingIntervalNode]

    @classmethod
    def build(cls, findings: Sequence[Finding]) -> _FindingLocationIndex:
        """Build a deterministic interval tree for each repository path."""
        grouped: defaultdict[PurePosixPath, list[_FindingInterval]] = defaultdict(list)
        for ordinal, finding in enumerate(findings):
            grouped[finding.location.path].append(
                _FindingInterval(
                    ordinal=ordinal,
                    start=finding.location.region.start.line,
                    end=finding.location.region.end.line,
                    finding=finding,
                )
            )
        return cls(
            by_path={
                path: _build_interval_node(tuple(intervals))
                for path, intervals in grouped.items()
            }
        )

    def at(self, location: EvidenceLocation) -> tuple[Finding, ...]:
        """Return findings whose source interval contains the warning line."""
        node = self.by_path.get(location.path)
        if node is None:
            return ()
        matches: list[_FindingInterval] = []
        node.query(location.line, matches)
        return tuple(
            interval.finding
            for interval in sorted(matches, key=lambda item: item.ordinal)
        )


@dataclass
class _RelationshipBudget:
    candidate_checks: int = 0
    relationships: int = 0

    def reserve_candidates(self, count: int) -> None:
        """Fail before adversarial overlap can cause unbounded comparisons."""
        if count > MAX_EVIDENCE_CANDIDATE_CHECKS - self.candidate_checks:
            _raise_error(
                "--evidence",
                (
                    "relationship matching exceeds the aggregate limit of "
                    f"{MAX_EVIDENCE_CANDIDATE_CHECKS} candidate checks"
                ),
            )
        self.candidate_checks += count

    def reserve_relationships(self, count: int) -> None:
        """Fail before relationship expansion can exhaust report memory."""
        if count > MAX_EVIDENCE_RELATIONSHIPS - self.relationships:
            _raise_error(
                "--evidence",
                (
                    "relationship output exceeds the aggregate limit of "
                    f"{MAX_EVIDENCE_RELATIONSHIPS} records"
                ),
            )
        self.relationships += count


def _build_interval_node(
    intervals: tuple[_FindingInterval, ...],
) -> _FindingIntervalNode:
    """Build a balanced point-query interval tree."""
    center = sorted((item.start + item.end) // 2 for item in intervals)[
        len(intervals) // 2
    ]
    left: list[_FindingInterval] = []
    crossing: list[_FindingInterval] = []
    right: list[_FindingInterval] = []
    for interval in intervals:
        if interval.end < center:
            left.append(interval)
        elif interval.start > center:
            right.append(interval)
        else:
            crossing.append(interval)
    return _FindingIntervalNode(
        center=center,
        crossing_by_start=tuple(
            sorted(crossing, key=lambda item: (item.start, item.ordinal))
        ),
        crossing_by_end=tuple(
            sorted(crossing, key=lambda item: (-item.end, item.ordinal))
        ),
        left=_build_interval_node(tuple(left)) if left else None,
        right=_build_interval_node(tuple(right)) if right else None,
    )


def _raise_error(where: str, message: str) -> NoReturn:
    detail = f"{where}: {message}"
    raise ConfigurationError(detail)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            where = "evidence JSON"
            message = f"duplicate object member {key!r}"
            _raise_error(where, message)
        value[key] = item
    return value


def _mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _raise_error(where, "must be an object")
    return value


def _exact_keys(
    value: dict[str, object],
    keys: frozenset[str],
    where: str,
) -> None:
    if set(value) != keys:
        _raise_error(where, "has unknown or missing keys")


def _bounded_string(value: object, where: str, *, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        message = f"must be a non-empty string of at most {limit} characters"
        _raise_error(where, message)
    if "\x00" in value or "\r" in value or "\n" in value:
        _raise_error(where, "must not contain NUL or line-break characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _raise_error(where, "must contain valid Unicode without lone surrogates")
    return value


def _non_negative_integer(value: object, where: str) -> int:
    if type(value) is not int or value < 0:
        _raise_error(where, "must be a non-negative integer")
    return value


def _positive_integer(value: object, where: str) -> int:
    if type(value) is not int or value <= 0:
        _raise_error(where, "must be a positive integer")
    return value


def _boolean(value: object, where: str) -> bool:
    if type(value) is not bool:
        _raise_error(where, "must be a boolean")
    return value


def normalize_source_commit(value: object, where: str = "source commit") -> str:
    """Validate and normalize one full Git object ID."""
    commit = _bounded_string(value, where, limit=64).lower()
    if _COMMIT_RE.fullmatch(commit) is None:
        _raise_error(where, "must be a full 40- or 64-character hexadecimal commit")
    return commit


def resolve_source_commit(
    explicit: str | None,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Resolve an explicit or CI-provided commit without invoking Git."""
    if explicit is not None:
        return normalize_source_commit(explicit, "--source-commit")
    selected_environment = os.environ if environment is None else environment
    for name in _SOURCE_COMMIT_ENVIRONMENT:
        value = selected_environment.get(name)
        if value:
            return normalize_source_commit(value, name)
    names = ", ".join(_SOURCE_COMMIT_ENVIRONMENT)
    where = "source commit"
    message = f"provide --source-commit or one of {names}"
    _raise_error(where, message)


def _relative_path(value: object, where: str) -> PurePosixPath:
    text = _bounded_string(value, where, limit=_MAX_TEXT_LENGTH)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != text
        or "\\" in text
        or text in {"", "."}
    ):
        _raise_error(where, "must be a repository-relative POSIX path")
    return path


def _optional_location(value: object, where: str) -> EvidenceLocation:
    document = _mapping(value, where)
    _exact_keys(document, _LOCATION_KEYS, where)
    return EvidenceLocation(
        path=_relative_path(document["path"], f"{where}.path"),
        line=_positive_integer(document["line"], f"{where}.line"),
    )


def _parse_warning(value: object, index: int) -> WarningEvidence:
    where = f"evidence warning {index}"
    document = _mapping(value, where)
    keys = set(document)
    if not _WARNING_REQUIRED_KEYS.issubset(keys) or not keys.issubset(
        _WARNING_REQUIRED_KEYS | _WARNING_OPTIONAL_KEYS
    ):
        _raise_error(where, "has unknown or missing keys")
    kind = _bounded_string(document["kind"], f"{where}.kind", limit=64)
    if kind not in _WARNING_KINDS:
        _raise_error(where, "kind is not supported")
    phase = _bounded_string(document["phase"], f"{where}.phase", limit=16)
    if phase not in _WARNING_PHASES:
        _raise_error(where, "phase is not supported")
    test_node = (
        _bounded_string(
            document["test_node"],
            f"{where}.test_node",
            limit=_MAX_TEXT_LENGTH,
        )
        if "test_node" in document
        else None
    )
    return WarningEvidence(
        kind=kind,
        category=_bounded_string(
            document["category"],
            f"{where}.category",
            limit=512,
        ),
        message=_bounded_string(
            document["message"],
            f"{where}.message",
            limit=_MAX_MESSAGE_LENGTH,
        ),
        phase=phase,
        location=(
            _optional_location(document["location"], f"{where}.location")
            if "location" in document
            else None
        ),
        test_node=test_node,
        occurrences=_positive_integer(
            document["occurrences"],
            f"{where}.occurrences",
        ),
    )


def parse_evidence_document(value: object) -> EvidenceDocument:
    """Validate one closed-world evidence schema version 1 document."""
    document = _mapping(value, "evidence document")
    _exact_keys(document, _TOP_LEVEL_KEYS, "evidence document")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        _raise_error("evidence schema_version", "must equal 1")

    provider = _mapping(document["provider"], "evidence provider")
    _exact_keys(provider, _PROVIDER_KEYS, "evidence provider")
    provider_name = _bounded_string(
        provider["name"],
        "evidence provider.name",
        limit=64,
    )
    if provider_name != "pytest-warnings":
        _raise_error("evidence provider.name", "must equal 'pytest-warnings'")

    source = _mapping(document["source"], "evidence source")
    _exact_keys(source, _SOURCE_KEYS, "evidence source")

    environment = _mapping(document["environment"], "evidence environment")
    _exact_keys(environment, _ENVIRONMENT_KEYS, "evidence environment")
    python_version = _bounded_string(
        environment["python_version"],
        "evidence environment.python_version",
        limit=64,
    )
    if _PYTHON_VERSION_RE.fullmatch(python_version) is None:
        _raise_error(
            "evidence environment.python_version",
            "must be a concrete Python version",
        )

    run = _mapping(document["run"], "evidence run")
    _exact_keys(run, _RUN_KEYS, "evidence run")
    framework = _bounded_string(run["framework"], "evidence run.framework", limit=64)
    if framework != "pytest":
        _raise_error("evidence run.framework", "must equal 'pytest'")

    warnings = document["warnings"]
    if not isinstance(warnings, list):
        _raise_error("evidence warnings", "must be an array")
    if len(warnings) > MAX_EVIDENCE_WARNINGS:
        message = f"must contain at most {MAX_EVIDENCE_WARNINGS} items"
        _raise_error("evidence warnings", message)

    warnings_complete = _boolean(
        run["warnings_complete"],
        "evidence run.warnings_complete",
    )
    warnings_dropped = _non_negative_integer(
        run["warnings_dropped"],
        "evidence run.warnings_dropped",
    )
    if warnings_complete != (warnings_dropped == 0):
        _raise_error(
            "evidence run",
            "warnings_complete must be true exactly when warnings_dropped is zero",
        )

    return EvidenceDocument(
        provider=provider_name,
        provider_version=_bounded_string(
            provider["version"],
            "evidence provider.version",
            limit=64,
        ),
        source_commit=normalize_source_commit(
            source["commit"],
            "evidence source.commit",
        ),
        environment=EvidenceEnvironment(
            implementation=_bounded_string(
                environment["implementation"],
                "evidence environment.implementation",
                limit=64,
            ),
            python_version=python_version,
            platform=_bounded_string(
                environment["platform"],
                "evidence environment.platform",
                limit=128,
            ),
        ),
        framework=framework,
        framework_version=_bounded_string(
            run["framework_version"],
            "evidence run.framework_version",
            limit=64,
        ),
        tests_collected=_non_negative_integer(
            run["tests_collected"],
            "evidence run.tests_collected",
        ),
        exit_code=_non_negative_integer(run["exit_code"], "evidence run.exit_code"),
        warnings_complete=warnings_complete,
        warnings_dropped=warnings_dropped,
        warnings=tuple(
            _parse_warning(item, index) for index, item in enumerate(warnings)
        ),
    )


def _json_string_list(values: Sequence[str]) -> list[JsonValue]:
    result: list[JsonValue] = []
    result.extend(values)
    return result


def evidence_json_schema() -> dict[str, JsonValue]:
    """Return the versioned JSON Schema for pytest warning evidence."""
    bounded_text: dict[str, JsonValue] = {
        "maxLength": _MAX_TEXT_LENGTH,
        "minLength": 1,
        "pattern": ("^(?![\\s\\S]*[\\r\\n])(?!.*[\\ud800-\\udfff])[^\\u0000\\r\\n]+$"),
        "type": "string",
    }
    location: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "line": {"minimum": 1, "type": "integer"},
            "path": {
                **bounded_text,
                "pattern": (
                    "^(?![\\s\\S]*[\\r\\n])"
                    "(?!.*[\\ud800-\\udfff])"
                    "(?!\\.{1,2}(?:/|$))"
                    "(?!.*\\/\\.{1,2}(?:/|$))"
                    "[^\\u0000\\r\\n/\\\\]+"
                    "(?:/[^\\u0000\\r\\n/\\\\]+)*$"
                ),
            },
        },
        "required": ["line", "path"],
        "type": "object",
    }
    warning: dict[str, JsonValue] = {
        "additionalProperties": False,
        "properties": {
            "category": {**bounded_text, "maxLength": 512},
            "kind": {
                "enum": _json_string_list(sorted(_WARNING_KINDS)),
                "type": "string",
            },
            "location": location,
            "message": {**bounded_text, "maxLength": _MAX_MESSAGE_LENGTH},
            "occurrences": {"minimum": 1, "type": "integer"},
            "phase": {
                "enum": _json_string_list(sorted(_WARNING_PHASES)),
                "type": "string",
            },
            "test_node": bounded_text,
        },
        "required": _json_string_list(sorted(_WARNING_REQUIRED_KEYS)),
        "type": "object",
    }
    return {
        "$id": "https://github.com/diegorusso/pyahead/blob/main/docs/schema/evidence-v1.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "properties": {
            "environment": {
                "additionalProperties": False,
                "properties": {
                    "implementation": {**bounded_text, "maxLength": 64},
                    "platform": {**bounded_text, "maxLength": 128},
                    "python_version": {
                        "maxLength": 64,
                        "pattern": (
                            "^(?![\\s\\S]*[\\r\\n])"
                            + _PYTHON_VERSION_RE.pattern.removesuffix("\\Z")
                            + "$"
                        ),
                        "type": "string",
                    },
                },
                "required": _json_string_list(sorted(_ENVIRONMENT_KEYS)),
                "type": "object",
            },
            "provider": {
                "additionalProperties": False,
                "properties": {
                    "name": {"const": "pytest-warnings", "type": "string"},
                    "version": {**bounded_text, "maxLength": 64},
                },
                "required": _json_string_list(sorted(_PROVIDER_KEYS)),
                "type": "object",
            },
            "run": {
                "additionalProperties": False,
                "oneOf": [
                    {
                        "properties": {
                            "warnings_complete": {"const": True},
                            "warnings_dropped": {"const": 0},
                        }
                    },
                    {
                        "properties": {
                            "warnings_complete": {"const": False},
                            "warnings_dropped": {"minimum": 1},
                        }
                    },
                ],
                "properties": {
                    "exit_code": {"minimum": 0, "type": "integer"},
                    "framework": {"const": "pytest", "type": "string"},
                    "framework_version": {**bounded_text, "maxLength": 64},
                    "tests_collected": {"minimum": 0, "type": "integer"},
                    "warnings_complete": {"type": "boolean"},
                    "warnings_dropped": {"minimum": 0, "type": "integer"},
                },
                "required": _json_string_list(sorted(_RUN_KEYS)),
                "type": "object",
            },
            "schema_version": {"const": 1, "type": "integer"},
            "source": {
                "additionalProperties": False,
                "properties": {
                    "commit": {
                        "pattern": (
                            "^(?![\\s\\S]*[\\r\\n])[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$"
                        ),
                        "type": "string",
                    }
                },
                "required": ["commit"],
                "type": "object",
            },
            "warnings": {
                "items": warning,
                "maxItems": MAX_EVIDENCE_WARNINGS,
                "type": "array",
            },
        },
        "required": _json_string_list(sorted(_TOP_LEVEL_KEYS)),
        "title": "PyAhead pytest warning evidence schema version 1",
        "type": "object",
    }


def render_evidence_schema() -> str:
    """Serialize the evidence schema deterministically."""
    return json.dumps(evidence_json_schema(), indent=2, sort_keys=True) + "\n"


def render_evidence_document(document: Mapping[str, JsonValue]) -> str:
    """Validate, size-bound, and serialize one collector artifact."""
    parsed = parse_evidence_document(dict(document))
    if _serialized_size_within(parsed, MAX_EVIDENCE_BYTES):
        return _render_parsed_document(parsed)

    suffix_occurrences = [0] * (len(parsed.warnings) + 1)
    for index in range(len(parsed.warnings) - 1, -1, -1):
        suffix_occurrences[index] = (
            suffix_occurrences[index + 1] + parsed.warnings[index].occurrences
        )

    def truncated(keep: int) -> EvidenceDocument:
        return replace(
            parsed,
            warnings=parsed.warnings[:keep],
            warnings_complete=False,
            warnings_dropped=(parsed.warnings_dropped + suffix_occurrences[keep]),
        )

    if not _serialized_size_within(truncated(0), MAX_EVIDENCE_BYTES):
        message = f"evidence metadata exceeds {MAX_EVIDENCE_BYTES} bytes"
        raise EvidenceSizeError(message)

    low = 0
    high = len(parsed.warnings)
    while low < high:
        middle = (low + high + 1) // 2
        if _serialized_size_within(truncated(middle), MAX_EVIDENCE_BYTES):
            low = middle
        else:
            high = middle - 1
    return _render_parsed_document(truncated(low))


def _canonical_document(document: EvidenceDocument) -> dict[str, JsonValue]:
    return {
        "environment": {
            "implementation": document.environment.implementation,
            "platform": document.environment.platform,
            "python_version": document.environment.python_version,
        },
        "provider": {"name": document.provider, "version": document.provider_version},
        "run": {
            "exit_code": document.exit_code,
            "framework": document.framework,
            "framework_version": document.framework_version,
            "tests_collected": document.tests_collected,
            "warnings_complete": document.warnings_complete,
            "warnings_dropped": document.warnings_dropped,
        },
        "schema_version": 1,
        "source": {"commit": document.source_commit},
        "warnings": [
            {
                "category": warning.category,
                "kind": warning.kind,
                **(
                    {
                        "location": {
                            "line": warning.location.line,
                            "path": warning.location.path.as_posix(),
                        }
                    }
                    if warning.location is not None
                    else {}
                ),
                "message": warning.message,
                "occurrences": warning.occurrences,
                "phase": warning.phase,
                **(
                    {"test_node": warning.test_node}
                    if warning.test_node is not None
                    else {}
                ),
            }
            for warning in document.warnings
        ],
    }


def _render_parsed_document(document: EvidenceDocument) -> str:
    return (
        json.dumps(
            _canonical_document(document),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _serialized_size_within(document: EvidenceDocument, limit: int) -> bool:
    """Check encoded size incrementally without materializing oversized JSON."""
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True)
    byte_count = 1  # The canonical artifact has one trailing newline.
    for chunk in encoder.iterencode(_canonical_document(document)):
        byte_count += len(chunk.encode("utf-8"))
        if byte_count > limit:
            return False
    return True


def _artifact_id(document: EvidenceDocument) -> str:
    encoded = json.dumps(
        _canonical_document(document),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(b"pyahead-evidence-artifact-v1\0" + encoded).hexdigest()


def _load_evidence(path: Path, root: Path) -> _LoadedEvidence:
    label = path.name
    selected = path if path.is_absolute() else root / path
    try:
        resolved = selected.resolve(strict=True)
        relative = PurePosixPath(resolved.relative_to(root).as_posix())
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(resolved, flags)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode):
                _raise_error(label, "evidence is not a regular file")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = -1
                raw = stream.read(MAX_EVIDENCE_BYTES + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > MAX_EVIDENCE_BYTES:
            message = f"evidence exceeds {MAX_EVIDENCE_BYTES} bytes"
            _raise_error(label, message)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except FileNotFoundError:
        _raise_error(label, "evidence file does not exist")
    except json.JSONDecodeError:
        _raise_error(label, "evidence is not valid JSON")
    except ValueError as error:
        if isinstance(error, ConfigurationError):
            raise
        _raise_error(label, "evidence must remain beneath the project root")
    except (OSError, RuntimeError, UnicodeError):
        _raise_error(label, "unable to read evidence")
    document = parse_evidence_document(value)
    return _LoadedEvidence(
        path=relative,
        artifact_id=_artifact_id(document),
        byte_count=len(raw),
        document=document,
    )


def _warning_key(warning: WarningEvidence) -> tuple[object, ...]:
    return (
        warning.kind,
        warning.category,
        warning.message,
        warning.phase,
        warning.location.path.as_posix() if warning.location is not None else "",
        warning.location.line if warning.location is not None else 0,
        warning.test_node or "",
    )


def _observation_id(artifact_id: str, key: tuple[object, ...]) -> str:
    material = "\0".join(str(item) for item in key)
    return hashlib.sha256(
        f"pyahead-observation-v1\0{artifact_id}\0{material}".encode()
    ).hexdigest()


def _subject_correlates(warning: WarningEvidence, finding: Finding) -> bool:
    terms = {finding.rule_id, finding.subject}
    if "." in finding.subject:
        terms.add(finding.subject.rsplit(".", maxsplit=1)[-1])
    return any(
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])",
            warning.message,
        )
        is not None
        for term in terms
    )


def _observed_minor(environment: EvidenceEnvironment) -> PythonMinor | None:
    major, minor, _patch = environment.python_version.split(".", maxsplit=2)
    if int(major) != _SUPPORTED_EVIDENCE_MAJOR:
        return None
    return PythonMinor(major=int(major), minor=int(minor))


def _relationship_conflicts(
    warning: WarningEvidence,
    finding: Finding,
    report: ScanReport,
    environment: EvidenceEnvironment,
) -> tuple[str, ...]:
    del warning
    if environment.implementation.casefold() != "cpython":
        return ("non-cpython-environment",)
    observed_minor = _observed_minor(environment)
    if observed_minor is None or observed_minor not in report.policy.target_versions:
        return ("observed-python-outside-policy",)
    state = next(
        (
            item.state
            for item in finding.states
            if item.from_python <= observed_minor <= item.through_python
        ),
        None,
    )
    if state is None:
        return ("no-static-state-at-observed-python",)
    if state is not FindingState.DEPRECATED:
        return (f"deprecation-warning-conflicts-with-{state.value}-state",)
    return ()


def _relationships(
    warning: WarningEvidence,
    findings: _FindingLocationIndex,
    report: ScanReport,
    environment: EvidenceEnvironment,
    budget: _RelationshipBudget,
) -> tuple[EvidenceRelationship, ...]:
    if warning.location is None:
        return ()
    candidates = findings.at(warning.location)
    budget.reserve_candidates(len(candidates))
    correlated = tuple(
        finding for finding in candidates if _subject_correlates(warning, finding)
    )
    if len(correlated) == 1:
        budget.reserve_relationships(1)
        finding = correlated[0]
        conflicts = _relationship_conflicts(
            warning,
            finding,
            report,
            environment,
        )
        return (
            EvidenceRelationship(
                finding_fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                subject=finding.subject,
                kind=(
                    EvidenceRelationshipKind.CONFLICTS
                    if conflicts
                    else EvidenceRelationshipKind.CORROBORATES
                ),
                reasons=conflicts or ("subject-and-timeline-correlated",),
            ),
        )
    if not candidates:
        return ()
    budget.reserve_relationships(len(candidates))
    reason = "ambiguous-subject-correlation" if correlated else "subject-not-correlated"
    return tuple(
        EvidenceRelationship(
            finding_fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            subject=finding.subject,
            kind=EvidenceRelationshipKind.LOCATION_ONLY,
            reasons=(reason,),
        )
        for finding in candidates
    )


def _load_evidence_set(
    evidence_paths: Sequence[Path],
    root: Path,
) -> tuple[_LoadedEvidence, ...]:
    """Load, deduplicate, and enforce aggregate input budgets."""
    if len(evidence_paths) > MAX_EVIDENCE_ARTIFACTS:
        _raise_error(
            "--evidence",
            f"must select at most {MAX_EVIDENCE_ARTIFACTS} artifacts",
        )
    selected_paths: set[PurePosixPath] = set()
    unique_artifacts: dict[str, _LoadedEvidence] = {}
    total_bytes = 0
    total_warnings = 0
    for path in evidence_paths:
        item = _load_evidence(path, root)
        if item.path in selected_paths:
            _raise_error(
                "--evidence",
                "must not select the same artifact more than once",
            )
        selected_paths.add(item.path)
        total_bytes += item.byte_count
        if total_bytes > MAX_TOTAL_EVIDENCE_BYTES:
            _raise_error(
                "--evidence",
                (
                    "artifacts exceed the aggregate byte limit of "
                    f"{MAX_TOTAL_EVIDENCE_BYTES}"
                ),
            )
        total_warnings += len(item.document.warnings)
        if total_warnings > MAX_TOTAL_EVIDENCE_WARNINGS:
            _raise_error(
                "--evidence",
                (
                    "artifacts exceed the aggregate warning-record limit of "
                    f"{MAX_TOTAL_EVIDENCE_WARNINGS}"
                ),
            )
        unique_artifacts.setdefault(item.artifact_id, item)
    return tuple(
        sorted(
            unique_artifacts.values(),
            key=lambda candidate: candidate.path.as_posix(),
        )
    )


def merge_evidence(
    report: ScanReport,
    evidence_paths: Sequence[Path],
    *,
    root: Path,
    source_commit: str,
) -> ScanReport:
    """Ingest artifacts and evaluate warning-to-finding relationships."""
    current_commit = normalize_source_commit(source_commit)
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        _raise_error("evidence root", "does not exist or cannot be resolved")
    if not evidence_paths:
        _raise_error("--evidence", "requires at least one artifact")
    loaded = _load_evidence_set(evidence_paths, resolved_root)

    artifacts: list[EvidenceArtifact] = []
    observations: list[ObservedWarning] = []
    linkable_findings = report.visible_findings
    finding_index = _FindingLocationIndex.build(linkable_findings)
    relationship_budget = _RelationshipBudget()
    for item in loaded:
        document = item.document
        freshness = (
            EvidenceFreshness.CURRENT
            if document.source_commit == current_commit
            else EvidenceFreshness.STALE
        )
        warning_count = sum(warning.occurrences for warning in document.warnings)
        artifacts.append(
            EvidenceArtifact(
                artifact_id=item.artifact_id,
                path=item.path,
                provider=document.provider,
                provider_version=document.provider_version,
                source_commit=document.source_commit,
                freshness=freshness,
                environment=document.environment,
                framework=document.framework,
                framework_version=document.framework_version,
                tests_collected=document.tests_collected,
                exit_code=document.exit_code,
                warning_count=warning_count,
                warnings_complete=document.warnings_complete,
                warnings_dropped=document.warnings_dropped,
            )
        )

        grouped: defaultdict[tuple[object, ...], int] = defaultdict(int)
        representative: dict[tuple[object, ...], WarningEvidence] = {}
        for warning in document.warnings:
            key = _warning_key(warning)
            grouped[key] += warning.occurrences
            representative.setdefault(key, warning)
        for key in sorted(grouped, key=lambda candidate: tuple(map(str, candidate))):
            warning = representative[key]
            relationships = (
                _relationships(
                    warning,
                    finding_index,
                    report,
                    document.environment,
                    relationship_budget,
                )
                if freshness is EvidenceFreshness.CURRENT
                else ()
            )
            observations.append(
                ObservedWarning(
                    observation_id=_observation_id(item.artifact_id, key),
                    artifact_id=item.artifact_id,
                    provider=document.provider,
                    kind=warning.kind,
                    category=warning.category,
                    message=warning.message,
                    phase=warning.phase,
                    location=warning.location,
                    test_node=warning.test_node,
                    occurrences=grouped[key],
                    environment=document.environment,
                    source_commit=document.source_commit,
                    freshness=freshness,
                    relationships=relationships,
                )
            )

    return replace(
        report,
        source_commit=current_commit,
        evidence_artifacts=tuple(artifacts),
        observed_warnings=tuple(
            sorted(
                observations,
                key=lambda observation: (
                    observation.freshness.value,
                    observation.location.path.as_posix()
                    if observation.location is not None
                    else "",
                    observation.location.line
                    if observation.location is not None
                    else 0,
                    observation.category,
                    observation.message,
                    observation.observation_id,
                ),
            )
        ),
    )


__all__ = [
    "MAX_EVIDENCE_ARTIFACTS",
    "MAX_EVIDENCE_BYTES",
    "MAX_EVIDENCE_CANDIDATE_CHECKS",
    "MAX_EVIDENCE_RELATIONSHIPS",
    "MAX_EVIDENCE_WARNINGS",
    "MAX_TOTAL_EVIDENCE_BYTES",
    "MAX_TOTAL_EVIDENCE_WARNINGS",
    "EvidenceDocument",
    "EvidenceSizeError",
    "WarningEvidence",
    "evidence_json_schema",
    "merge_evidence",
    "normalize_source_commit",
    "parse_evidence_document",
    "render_evidence_document",
    "render_evidence_schema",
    "resolve_source_commit",
]
