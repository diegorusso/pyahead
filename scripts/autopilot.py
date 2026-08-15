"""Resumable, evidence-gated milestone orchestration for PyAhead development."""

# Operator-facing validation messages stay next to the checks that establish their
# context, and the explicit state machine keeps its transition logic together for
# auditability. These narrow style/complexity exceptions do not disable Ruff's
# correctness, subprocess, security, typing, or path-safety rules.
# ruff: noqa: C901, D102, D105, D107, E501, EM101, EM102, PLR0911, PLR0912, PLR0913, PLR0915, PLR2004, TRY003

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path, PurePosixPath
from string import Template
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence
    from typing import NoReturn, Self, TextIO

STATE_SCHEMA_VERSION = 2
MAX_RESULT_BYTES = 1024 * 1024
WORKFLOW_RUN_LIST_LIMIT = 100
CHILD_MARKER = "PYAHEAD_AUTOPILOT_CHILD"
DEFAULT_CONFIG = Path("automation/milestones.toml")
IMPLEMENTATION_SCHEMA = Path("automation/schemas/implementation-result.json")
REVIEW_SCHEMA = Path("automation/schemas/review-result.json")
CODEX_APPROVAL_OVERRIDE = 'approval_policy="never"'
ROLE_TEMPLATES = {
    "implementation": Path("automation/prompts/implement.md"),
    "review": Path("automation/prompts/review.md"),
    "repair": Path("automation/prompts/fix.md"),
}
VALID_PHASES = frozenset(
    {
        "branch_pending",
        "milestone_pending",
        "implementation_pending",
        "implementation_running",
        "verification_pending",
        "verification_running",
        "review_pending",
        "review_running",
        "repair_pending",
        "repair_running",
        "candidate_pending",
        "candidate_running",
        "candidate_publication_pending",
        "candidate_dispatch_pending",
        "candidate_dispatch_running",
        "candidate_checks_pending",
        "candidate_checks_running",
        "candidate_attach_pending",
        "candidate_attach_running",
        "commit_pending",
        "commit_running",
        "publication_pending",
        "milestone_complete",
        "awaiting_gate_C",
        "complete",
        "blocked",
        "failed",
        "repair_exhausted",
        "agent_failed",
    }
)
_MILESTONE_ID = re.compile(r"M(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_COMMAND_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
_NON_GIT_REPOSITORY_SELECTORS = frozenset(
    {
        "GH_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_REPO",
        "GITHUB_ENTERPRISE_TOKEN",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
    }
)
_AUTOPILOT_DISPATCH_TITLE = "PyAhead autopilot "
_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(https?://)[^/@:\s]+:[^/@\s]+@"),
)
_CODEX_PORTABLE_SCHEMA_UNSUPPORTED = frozenset(
    {
        "allOf",
        "dependentRequired",
        "dependentSchemas",
        "else",
        "format",
        "if",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "multipleOf",
        "not",
        "pattern",
        "patternProperties",
        "then",
        "uniqueItems",
    }
)


class ExitCode(IntEnum):
    """Stable process results for the repository automation command."""

    SUCCESS = 0
    INVALID_INPUT = 2
    BLOCKED = 3
    FAILED = 4
    INTERRUPTED = 5
    STATE_ERROR = 6
    PUBLICATION_FAILED = 7


class AutopilotError(Exception):
    """Base class for expected, concise operator-facing failures."""

    exit_code = ExitCode.FAILED


class InvalidInputError(AutopilotError):
    """Configuration, range, or command input is invalid."""

    exit_code = ExitCode.INVALID_INPUT


class BlockedError(AutopilotError):
    """Progress requires explicit external evidence or operator action."""

    exit_code = ExitCode.BLOCKED


class StateError(AutopilotError):
    """Persisted state no longer matches the repository safely."""

    exit_code = ExitCode.STATE_ERROR


class PublicationError(AutopilotError):
    """Local work is complete but publication must be retried."""

    exit_code = ExitCode.PUBLICATION_FAILED


class AutopilotInterruptedError(AutopilotError):
    """The operator interrupted a supervised child process."""

    exit_code = ExitCode.INTERRUPTED


class _DuplicateJSONKeyError(ValueError):
    """Internal marker for an ambiguous JSON object."""


@dataclass(frozen=True)
class CommandSpec:
    """One argv-safe command and its execution budget."""

    identifier: str
    command: tuple[str, ...]
    timeout_seconds: float


@dataclass(frozen=True)
class ProtectedPath:
    """A path child sessions may not change except in named milestones."""

    path: PurePosixPath
    allow_for: frozenset[str]


@dataclass(frozen=True)
class QualityGuard:
    """Selected TOML tables whose semantics are protected from weakening."""

    path: PurePosixPath
    tables: tuple[str, ...]
    allow_for: frozenset[str]


@dataclass(frozen=True)
class HostedVerification:
    """One exact-candidate GitHub Actions evidence policy."""

    identifier: str
    workflow: str
    dispatch_input: str
    required_jobs: tuple[str, ...]
    timeout_seconds: float
    poll_interval_seconds: float


@dataclass(frozen=True)
class GitHubRepository:
    """Canonical GitHub host and owner/repository derived from the Git remote."""

    host: str
    owner: str
    repository: str

    @property
    def name_with_owner(self) -> str:
        return f"{self.owner}/{self.repository}"

    @property
    def selector(self) -> str:
        return f"{self.host}/{self.name_with_owner}"


@dataclass(frozen=True)
class GitHubTransport:
    """Validated effective HTTPS transport for one configured Git remote."""

    repository: GitHubRepository
    fetch_url: str
    push_url: str


@dataclass(frozen=True)
class Milestone:
    """Automation policy for one product milestone."""

    identifier: str
    title: str
    heading: str
    policy: str
    extra_verification: tuple[str, ...]
    hosted_verification: str | None
    requires_publication: bool
    stop_after_gate: str | None
    required_design: PurePosixPath | None


@dataclass(frozen=True)
class Config:
    """Validated automation configuration loaded from TOML."""

    path: Path
    state_directory: PurePosixPath
    base_branch: str
    remote: str
    default_timeout_seconds: float
    codex_timeout_seconds: float
    max_repair_cycles: int
    branch_template: str
    commit_template: str
    tools: Mapping[str, tuple[str, ...]]
    protected_paths: tuple[ProtectedPath, ...]
    quality_guards: tuple[QualityGuard, ...]
    verification: tuple[CommandSpec, ...]
    milestone_verification: Mapping[str, CommandSpec]
    hosted_verification: Mapping[str, HostedVerification]
    milestones: tuple[Milestone, ...]

    def milestone(self, identifier: str) -> Milestone:
        """Return one configured milestone or reject an unknown identifier."""
        for milestone in self.milestones:
            if milestone.identifier == identifier:
                return milestone
        raise InvalidInputError(f"unknown milestone {identifier!r}")


@dataclass(frozen=True)
class CommandResult:
    """Complete separated output from one supervised subprocess."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    interrupted: bool = False

    @property
    def signal_number(self) -> int | None:
        """Return the terminating signal on platforms that encode one."""
        return -self.returncode if self.returncode < 0 else None

    @property
    def succeeded(self) -> bool:
        """Return whether the process completed normally with status zero."""
        return (
            self.returncode == 0
            and not self.timed_out
            and not self.interrupted
            and self.signal_number is None
        )


@dataclass(frozen=True)
class ImplementationResult:
    """Strictly validated structured output from an implementer or fixer."""

    milestone: str
    status: str
    summary: str
    files_changed: tuple[str, ...]
    acceptance_criteria_addressed: tuple[str, ...]
    commands_reportedly_run: tuple[str, ...]
    limitations: tuple[str, ...]
    blocking_reason: str | None


@dataclass(frozen=True)
class ReviewFinding:
    """One concrete independent-review finding."""

    severity: str
    file: str | None
    line: int | None
    explanation: str
    required_remediation: str


@dataclass(frozen=True)
class ReviewResult:
    """Strictly validated structured output from a reviewer."""

    milestone: str
    verdict: str
    findings: tuple[ReviewFinding, ...]
    acceptance_evidence_inspected: tuple[str, ...]
    blocking_reason: str | None


def _fail(message: str) -> NoReturn:
    raise InvalidInputError(message)


def _mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _fail(f"{context} must be a mapping with string keys")
    return cast("dict[str, object]", value)


def _sequence(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    return cast("list[object]", value)


def _string(value: object, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        _fail(f"{context} must be a non-empty string")
    if "\0" in value:
        _fail(f"{context} must not contain NUL")
    return value


def _number(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{context} must be a number")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        _fail(f"{context} must be greater than zero")
    return number


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _fail(f"{context} must be an integer greater than or equal to {minimum}")
    return value


def _exact_keys(data: Mapping[str, object], allowed: set[str], context: str) -> None:
    unexpected = sorted(set(data) - allowed)
    if unexpected:
        _fail(f"{context} contains unknown keys: {', '.join(unexpected)}")


def _string_tuple(value: object, context: str) -> tuple[str, ...]:
    items = _sequence(value, context)
    return tuple(
        _string(item, f"{context}[{index}]") for index, item in enumerate(items)
    )


def _command_tuple(value: object, context: str) -> tuple[str, ...]:
    command = _string_tuple(value, context)
    if not command:
        _fail(f"{context} must not be empty")
    return command


def _relative_path(value: object, context: str) -> PurePosixPath:
    raw = _string(value, context)
    path = PurePosixPath(raw)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or path == PurePosixPath(".")
    ):
        _fail(f"{context} must be a safe repository-relative POSIX path")
    return path


def _optional_string(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _string(value, context)


def _validate_codex_output_schema(schema: Mapping[str, object], context: str) -> None:
    """Reject constraints outside the portable strict Structured Outputs subset."""
    unsupported = sorted(set(schema) & _CODEX_PORTABLE_SCHEMA_UNSUPPORTED)
    if unsupported:
        raise InvalidInputError(
            f"{context} uses unsupported Codex output-schema keywords: "
            + ", ".join(unsupported)
        )
    schema_type = schema.get("type")
    if schema_type == "object":
        properties = _mapping(schema.get("properties"), f"{context}.properties")
        required = _string_tuple(schema.get("required"), f"{context}.required")
        if set(required) != set(properties) or len(required) != len(properties):
            raise InvalidInputError(
                f"{context} must require every object property exactly once"
            )
        if schema.get("additionalProperties") is not False:
            raise InvalidInputError(f"{context} must set additionalProperties to false")
        for name, child in properties.items():
            _validate_codex_output_schema(
                _mapping(child, f"{context}.properties.{name}"),
                f"{context}.properties.{name}",
            )
    items = schema.get("items")
    if items is not None:
        _validate_codex_output_schema(
            _mapping(items, f"{context}.items"), f"{context}.items"
        )
    any_of = schema.get("anyOf")
    if any_of is not None:
        for index, child in enumerate(_sequence(any_of, f"{context}.anyOf")):
            child_context = f"{context}.anyOf[{index}]"
            _validate_codex_output_schema(_mapping(child, child_context), child_context)
    definitions = schema.get("$defs")
    if definitions is not None:
        for name, child in _mapping(definitions, f"{context}.$defs").items():
            child_context = f"{context}.$defs.{name}"
            _validate_codex_output_schema(_mapping(child, child_context), child_context)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(f"duplicate JSON property {key!r}")
        result[key] = value
    return result


def _safe_https_url(value: str) -> bool:
    """Accept an HTTPS URL without credentials, controls, or whitespace."""
    parsed = urlsplit(value)
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.username is None
        and parsed.password is None
        and not any(character.isspace() or ord(character) < 32 for character in value)
    )


def _parse_github_repository_url(value: str) -> GitHubRepository:
    """Parse one ordinary HTTPS, SSH URL, or scp-style GitHub remote."""
    host: str | None = None
    path: str | None = None
    if "://" in value:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"https", "ssh"}
            or parsed.hostname is None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or (parsed.scheme == "https" and parsed.username is not None)
            or (parsed.scheme == "ssh" and parsed.username not in {None, "git"})
        ):
            raise InvalidInputError(
                "configured Git remote is not a supported credential-free GitHub URL"
            )
        host = parsed.hostname.lower()
        path = parsed.path.lstrip("/")
    else:
        matched = re.fullmatch(
            r"(?:git@)?(?P<host>[A-Za-z0-9.-]+):(?P<path>[^\s]+)", value
        )
        if matched is not None:
            host = matched.group("host").lower()
            path = matched.group("path")
    if host is None or path is None:
        raise InvalidInputError(
            "configured Git remote must identify a GitHub host and owner/repository"
        )
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) is None:
        raise InvalidInputError("configured Git remote has an invalid GitHub host")
    normalized = path.removesuffix(".git")
    parts = normalized.split("/")
    component = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")
    if len(parts) != 2 or any(component.fullmatch(part) is None for part in parts):
        raise InvalidInputError(
            "configured Git remote must contain exactly owner/repository"
        )
    return GitHubRepository(host=host, owner=parts[0], repository=parts[1])


def _parse_github_https_repository_url(value: str) -> GitHubRepository:
    """Require a credential-free HTTPS transport, not an SSH command surface."""
    parsed = urlsplit(value)
    if parsed.scheme != "https":
        raise InvalidInputError(
            "publication requires a credential-free HTTPS Git remote"
        )
    return _parse_github_repository_url(value)


def _github_repository_url(
    value: str,
    repository: GitHubRepository,
    *,
    area: str,
) -> bool:
    """Require an HTTPS URL inside the exact configured GitHub repository."""
    if not _safe_https_url(value):
        return False
    parsed = urlsplit(value)
    if parsed.hostname is None or parsed.hostname.lower() != repository.host:
        return False
    if parsed.port is not None or parsed.query or parsed.fragment:
        return False
    root = f"/{repository.owner}/{repository.repository}"
    if area == "repository":
        return parsed.path.rstrip("/") == root
    expected = {
        "actions": f"{root}/actions/runs/",
        "pull": f"{root}/pull/",
    }.get(area)
    return expected is not None and parsed.path.startswith(expected)


def _github_actions_job_url(
    value: str,
    repository: GitHubRepository,
    *,
    run_id: int,
    job_id: int,
) -> bool:
    """Bind a job URL to the exact configured repository, run, and job IDs."""
    if not _github_repository_url(value, repository, area="actions"):
        return False
    parsed = urlsplit(value)
    expected = (
        f"/{repository.owner}/{repository.repository}/actions/runs/"
        f"{run_id}/job/{job_id}"
    )
    return parsed.path.rstrip("/") == expected


def _load_command_specs(value: object, context: str) -> tuple[CommandSpec, ...]:
    specs: list[CommandSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(_sequence(value, context)):
        item_context = f"{context}[{index}]"
        data = _mapping(item, item_context)
        _exact_keys(data, {"id", "command", "timeout_seconds"}, item_context)
        identifier = _string(data.get("id"), f"{item_context}.id")
        if _COMMAND_IDENTIFIER.fullmatch(identifier) is None:
            _fail(f"{item_context}.id must be a safe filename identifier")
        if identifier in seen:
            _fail(f"duplicate command identifier {identifier!r}")
        seen.add(identifier)
        specs.append(
            CommandSpec(
                identifier=identifier,
                command=_command_tuple(data.get("command"), f"{item_context}.command"),
                timeout_seconds=_number(
                    data.get("timeout_seconds"), f"{item_context}.timeout_seconds"
                ),
            )
        )
    return tuple(specs)


def load_config(repo_root: Path, config_path: Path | None = None) -> Config:
    """Load and strictly validate the repository-owned automation policy."""
    relative_config = config_path or Path(
        os.environ.get("PYAHEAD_AUTOPILOT_CONFIG", DEFAULT_CONFIG.as_posix())
    )
    resolved = (
        relative_config
        if relative_config.is_absolute()
        else repo_root / relative_config
    ).resolve()
    try:
        resolved.relative_to(repo_root.resolve())
    except ValueError as error:
        raise InvalidInputError(
            "automation configuration must remain in the repository"
        ) from error
    try:
        with resolved.open("rb") as config_file:
            raw = cast("object", tomllib.load(config_file))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InvalidInputError(
            f"unable to load automation configuration: {error}"
        ) from error
    data = _mapping(raw, "automation configuration")
    allowed = {
        "schema_version",
        "state_directory",
        "base_branch",
        "remote",
        "default_timeout_seconds",
        "codex_timeout_seconds",
        "max_repair_cycles",
        "branch_template",
        "commit_template",
        "tools",
        "protected_path",
        "quality_guard",
        "verification",
        "milestone_verification",
        "hosted_verification",
        "milestone",
    }
    _exact_keys(data, allowed, "automation configuration")
    if data.get("schema_version") != 1:
        _fail("automation configuration schema_version must equal 1")

    tools_data = _mapping(data.get("tools"), "tools")
    _exact_keys(tools_data, {"codex", "git", "gh"}, "tools")
    tools = {
        name: _command_tuple(tools_data.get(name), f"tools.{name}")
        for name in ("codex", "git", "gh")
    }

    protected_paths: list[ProtectedPath] = []
    for index, item in enumerate(
        _sequence(data.get("protected_path"), "protected_path")
    ):
        context = f"protected_path[{index}]"
        record = _mapping(item, context)
        _exact_keys(record, {"path", "allow_for"}, context)
        protected_paths.append(
            ProtectedPath(
                path=_relative_path(record.get("path"), f"{context}.path"),
                allow_for=frozenset(
                    _string_tuple(record.get("allow_for"), f"{context}.allow_for")
                ),
            )
        )

    quality_guards: list[QualityGuard] = []
    for index, item in enumerate(_sequence(data.get("quality_guard"), "quality_guard")):
        context = f"quality_guard[{index}]"
        record = _mapping(item, context)
        _exact_keys(record, {"path", "tables", "allow_for"}, context)
        quality_guards.append(
            QualityGuard(
                path=_relative_path(record.get("path"), f"{context}.path"),
                tables=_string_tuple(record.get("tables"), f"{context}.tables"),
                allow_for=frozenset(
                    _string_tuple(record.get("allow_for"), f"{context}.allow_for")
                ),
            )
        )

    verification = _load_command_specs(data.get("verification"), "verification")
    milestone_specs = _load_command_specs(
        data.get("milestone_verification"), "milestone_verification"
    )
    milestone_verification = {spec.identifier: spec for spec in milestone_specs}

    hosted_verification: dict[str, HostedVerification] = {}
    hosted_keys = {
        "id",
        "workflow",
        "dispatch_input",
        "required_jobs",
        "timeout_seconds",
        "poll_interval_seconds",
    }
    for index, item in enumerate(
        _sequence(data.get("hosted_verification"), "hosted_verification")
    ):
        context = f"hosted_verification[{index}]"
        record = _mapping(item, context)
        _exact_keys(record, hosted_keys, context)
        identifier = _string(record.get("id"), f"{context}.id")
        if _COMMAND_IDENTIFIER.fullmatch(identifier) is None:
            _fail(f"{context}.id must be a safe filename identifier")
        if identifier in hosted_verification:
            _fail(f"duplicate hosted verification {identifier!r}")
        required_jobs = _string_tuple(
            record.get("required_jobs"), f"{context}.required_jobs"
        )
        if not required_jobs or len(required_jobs) != len(set(required_jobs)):
            _fail(f"{context}.required_jobs must be non-empty and unique")
        hosted_verification[identifier] = HostedVerification(
            identifier=identifier,
            workflow=_string(record.get("workflow"), f"{context}.workflow"),
            dispatch_input=_string(
                record.get("dispatch_input"), f"{context}.dispatch_input"
            ),
            required_jobs=required_jobs,
            timeout_seconds=_number(
                record.get("timeout_seconds"), f"{context}.timeout_seconds"
            ),
            poll_interval_seconds=_number(
                record.get("poll_interval_seconds"),
                f"{context}.poll_interval_seconds",
            ),
        )

    milestones: list[Milestone] = []
    seen_milestones: set[str] = set()
    milestone_keys = {
        "id",
        "title",
        "heading",
        "policy",
        "extra_verification",
        "hosted_verification",
        "requires_publication",
        "stop_after_gate",
        "required_design",
    }
    for index, item in enumerate(_sequence(data.get("milestone"), "milestone")):
        context = f"milestone[{index}]"
        record = _mapping(item, context)
        _exact_keys(record, milestone_keys, context)
        identifier = _string(record.get("id"), f"{context}.id")
        if _MILESTONE_ID.fullmatch(identifier) is None:
            _fail(f"{context}.id is not a milestone identifier")
        if identifier in seen_milestones:
            _fail(f"duplicate milestone {identifier!r}")
        seen_milestones.add(identifier)
        policy = _string(record.get("policy"), f"{context}.policy")
        if policy not in {
            "unattended",
            "gate_c",
            "external_repository",
            "design_required",
        }:
            _fail(f"{context}.policy is unsupported")
        extras = _string_tuple(
            record.get("extra_verification"), f"{context}.extra_verification"
        )
        missing_extras = sorted(set(extras) - set(milestone_verification))
        if missing_extras:
            _fail(
                f"{context} references unknown verification: {', '.join(missing_extras)}"
            )
        hosted_raw = record.get("hosted_verification")
        hosted = (
            _string(hosted_raw, f"{context}.hosted_verification")
            if hosted_raw is not None
            else None
        )
        if hosted is not None and hosted not in hosted_verification:
            _fail(f"{context} references unknown hosted verification {hosted!r}")
        requires_publication = record.get("requires_publication", False)
        if not isinstance(requires_publication, bool):
            _fail(f"{context}.requires_publication must be a boolean")
        required_design_raw = record.get("required_design")
        required_design = (
            _relative_path(required_design_raw, f"{context}.required_design")
            if required_design_raw is not None
            else None
        )
        milestones.append(
            Milestone(
                identifier=identifier,
                title=_string(record.get("title"), f"{context}.title"),
                heading=_string(record.get("heading"), f"{context}.heading"),
                policy=policy,
                extra_verification=extras,
                hosted_verification=hosted,
                requires_publication=requires_publication,
                stop_after_gate=_optional_string(
                    record.get("stop_after_gate"), f"{context}.stop_after_gate"
                ),
                required_design=required_design,
            )
        )

    if tuple(item.identifier for item in milestones) != tuple(
        f"M{number}" for number in range(2, 11)
    ):
        _fail("milestones must configure M2 through M10 exactly and in order")
    required_policies = {
        **{f"M{number}": "unattended" for number in range(2, 7)},
        "M7": "gate_c",
        "M8": "gate_c",
        "M9": "external_repository",
        "M10": "design_required",
    }
    for milestone in milestones:
        if milestone.policy != required_policies[milestone.identifier]:
            _fail(f"{milestone.identifier} has an unsafe automation policy")
        expected_gate = "C" if milestone.identifier == "M6" else None
        if milestone.stop_after_gate != expected_gate:
            _fail(f"{milestone.identifier} has an unsafe stop-after-gate policy")
        expected_publication = milestone.identifier == "M6"
        if milestone.requires_publication is not expected_publication:
            _fail(f"{milestone.identifier} has an unsafe publication policy")
        if expected_publication != (milestone.hosted_verification is not None):
            _fail(f"{milestone.identifier} has an unsafe hosted-evidence policy")
    m6 = milestones[4]
    required_m6_checks = {"m6-wheel-install", "m6-sdist-install", "m6-benchmark"}
    if not required_m6_checks.issubset(m6.extra_verification):
        _fail("M6 is missing required artifact or benchmark verification")
    m6_hosted = hosted_verification[cast("str", m6.hosted_verification)]
    if m6_hosted.dispatch_input != "pyahead_autopilot_token":
        _fail("M6 hosted verification must use the controller dispatch token")
    m10 = milestones[-1]
    if m10.required_design != PurePosixPath("docs/c-api-design.md"):
        _fail("M10 must require docs/c-api-design.md")

    required_protection = {
        PurePosixPath("automation"): frozenset(),
        PurePosixPath("scripts/autopilot.py"): frozenset(),
        PurePosixPath("docs/design.md"): frozenset(),
        PurePosixPath("AGENTS.md"): frozenset(),
        PurePosixPath(".github/workflows"): frozenset({"M6"}),
    }
    configured_protection = {
        item.path: item.allow_for
        for item in protected_paths
        if item.path in required_protection
    }
    if configured_protection != required_protection:
        _fail("required protected paths or exceptions are missing")
    required_quality_tables = {
        "tool.ruff",
        "tool.mypy",
        "tool.pytest.ini_options",
        "tool.coverage.run",
        "tool.coverage.report",
    }
    if not any(
        guard.path == PurePosixPath("pyproject.toml")
        and set(guard.tables) == required_quality_tables
        and not guard.allow_for
        for guard in quality_guards
    ):
        _fail("required pyproject quality-policy protection is missing")
    if not any(
        guard.path == PurePosixPath("pyproject.toml")
        and set(guard.tables) == {"build-system", "tool.hatch"}
        and guard.allow_for == frozenset({"M6"})
        for guard in quality_guards
    ):
        _fail("required build-backend protection is missing")

    max_repairs = _integer(
        data.get("max_repair_cycles"), "max_repair_cycles", minimum=1
    )
    if max_repairs > 3:
        _fail("max_repair_cycles must not exceed three")
    branch_template = _string(data.get("branch_template"), "branch_template")
    commit_template = _string(data.get("commit_template"), "commit_template")
    for required in ("{from_slug}", "{through_slug}"):
        if required not in branch_template:
            _fail(f"branch_template must contain {required}")
    for required in ("{milestone}", "{title}"):
        if required not in commit_template:
            _fail(f"commit_template must contain {required}")
    base_branch = _string(data.get("base_branch"), "base_branch")
    remote = _string(data.get("remote"), "remote")
    safe_git_name = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
    safe_remote_name = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
    if safe_git_name.fullmatch(base_branch) is None:
        _fail("base_branch must be a safe Git branch name")
    if safe_remote_name.fullmatch(remote) is None:
        _fail("remote must be a safe configured Git remote name")

    state_directory = _relative_path(data.get("state_directory"), "state_directory")
    if state_directory != PurePosixPath(".autopilot"):
        _fail("state_directory must be .autopilot")

    return Config(
        path=resolved,
        state_directory=state_directory,
        base_branch=base_branch,
        remote=remote,
        default_timeout_seconds=_number(
            data.get("default_timeout_seconds"), "default_timeout_seconds"
        ),
        codex_timeout_seconds=_number(
            data.get("codex_timeout_seconds"), "codex_timeout_seconds"
        ),
        max_repair_cycles=max_repairs,
        branch_template=branch_template,
        commit_template=commit_template,
        tools=tools,
        protected_paths=tuple(protected_paths),
        quality_guards=tuple(quality_guards),
        verification=verification,
        milestone_verification=milestone_verification,
        hosted_verification=hosted_verification,
        milestones=tuple(milestones),
    )


def _redact(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact_structure(value: object) -> object:
    """Produce a JSON-compatible copy safe for operator-facing state output."""
    if isinstance(value, str):
        return _redact(value)
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_structure(item) for key, item in value.items()}
    return value


def _redacted_command(command: Iterable[str]) -> tuple[str, ...]:
    return tuple(_redact(item) for item in command)


def _repository_environment() -> dict[str, str]:
    """Remove inherited selectors that can redirect Git or GitHub operations."""
    environment = os.environ.copy()
    for key in tuple(environment):
        if (
            key.startswith("GIT_")
            or key in _NON_GIT_REPOSITORY_SELECTORS
            or (key.startswith("GH_") and key != "GH_TOKEN")
        ):
            environment.pop(key, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_CONFIG_COUNT"] = "1"
    environment["GIT_CONFIG_KEY_0"] = "credential.interactive"
    environment["GIT_CONFIG_VALUE_0"] = "false"
    environment["GH_PROMPT_DISABLED"] = "1"
    environment["NO_COLOR"] = "1"
    return environment


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    if any(parent.is_symlink() for parent in path.parents):
        raise StateError("refusing an atomic write through a symlinked directory")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        if os.name != "nt" and hasattr(os, "O_DIRECTORY"):
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary.unlink()


def atomic_write_json(path: Path, value: Mapping[str, object]) -> None:
    """Write canonical state without exposing a partially written document."""
    try:
        content = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise StateError("state is not JSON serializable") from error
    _atomic_write_bytes(path, content)


def _command_sha256(command: Sequence[str]) -> str:
    """Hash an argv sequence without ambiguous joining or shell rendering."""
    encoded = json.dumps(
        list(command),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _command_evidence_paths(log_base: Path) -> tuple[Path, Path, Path, Path]:
    """Return the durable start, result, stdout, and stderr evidence paths."""
    return (
        log_base.with_suffix(".started.json"),
        log_base.with_suffix(".result.json"),
        log_base.with_suffix(".stdout.log"),
        log_base.with_suffix(".stderr.log"),
    )


def _terminate_process_tree(
    process: subprocess.Popen[str],
    *,
    force: bool,
) -> None:
    """Stop the supervised process group without invoking a shell."""
    process_id = getattr(process, "pid", None)
    if os.name != "nt" and isinstance(process_id, int):
        selected_signal = signal.SIGKILL if force else signal.SIGTERM
        try:
            os.killpg(process_id, selected_signal)
        except ProcessLookupError:
            return
        except PermissionError:
            pass
        else:
            return
    if os.name == "nt" and not force and hasattr(signal, "CTRL_BREAK_EVENT"):
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        except OSError:
            pass
        else:
            return
    if os.name == "nt" and force and isinstance(process_id, int):
        taskkill = shutil.which("taskkill")
        if taskkill is not None:
            try:
                termination = subprocess.run(  # noqa: S603 - fixed OS utility argv.
                    (taskkill, "/PID", str(process_id), "/T", "/F"),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                if termination.returncode == 0:
                    return
            except (OSError, subprocess.TimeoutExpired):
                pass
    if force:
        process.kill()
    else:
        process.terminate()


class CommandRunner:
    """Run argv-only subprocesses with deadlines and separated redacted logs."""

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> CommandResult:
        """Execute one process without a shell and preserve its complete output."""
        argv = tuple(command)
        if not argv or any(not item or "\0" in item for item in argv):
            raise InvalidInputError("subprocess argv contains an invalid value")
        started = time.monotonic()
        try:
            process = subprocess.Popen(  # noqa: S603 - argv is validated and never shelled.
                argv,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                start_new_session=os.name != "nt",
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    if os.name == "nt"
                    else 0
                ),
            )
        except FileNotFoundError:
            result = CommandResult(
                command=argv,
                returncode=127,
                stdout="",
                stderr=f"executable not found: {argv[0]}\n",
                duration_seconds=time.monotonic() - started,
            )
            self.write_logs(result, log_base)
            return result
        except OSError as error:
            result = CommandResult(
                command=argv,
                returncode=126,
                stdout="",
                stderr=_redact(f"unable to start executable {argv[0]!r}: {error}\n"),
                duration_seconds=time.monotonic() - started,
            )
            self.write_logs(result, log_base)
            return result
        if log_base is not None:
            started_path, _result_path, _stdout_path, _stderr_path = (
                _command_evidence_paths(log_base)
            )
            atomic_write_json(
                started_path,
                {
                    "command_sha256": _command_sha256(argv),
                    "schema_version": 1,
                },
            )
        try:
            stdout, stderr = process.communicate(
                input=input_text, timeout=timeout_seconds
            )
            result = CommandResult(
                command=argv,
                returncode=process.returncode,
                stdout=_redact(stdout),
                stderr=_redact(stderr),
                duration_seconds=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process, force=True)
            stdout, stderr = process.communicate()
            result = CommandResult(
                command=argv,
                returncode=process.returncode,
                stdout=_redact(stdout),
                stderr=_redact(stderr),
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )
        except KeyboardInterrupt as error:
            _terminate_process_tree(process, force=False)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_process_tree(process, force=True)
                stdout, stderr = process.communicate()
            result = CommandResult(
                command=argv,
                returncode=process.returncode,
                stdout=_redact(stdout),
                stderr=_redact(stderr),
                duration_seconds=time.monotonic() - started,
                interrupted=True,
            )
            self.write_logs(result, log_base)
            raise AutopilotInterruptedError(
                "interrupted while a child process was running"
            ) from error
        self.write_logs(result, log_base)
        return result

    @staticmethod
    def write_logs(result: CommandResult, log_base: Path | None) -> None:
        if log_base is None:
            return
        _started_path, result_path, stdout_path, stderr_path = _command_evidence_paths(
            log_base
        )
        _atomic_write_bytes(
            stdout_path,
            result.stdout.encode("utf-8", errors="backslashreplace"),
        )
        _atomic_write_bytes(
            stderr_path,
            result.stderr.encode("utf-8", errors="backslashreplace"),
        )
        atomic_write_json(
            result_path,
            {
                "command_sha256": _command_sha256(result.command),
                "interrupted": result.interrupted,
                "returncode": result.returncode,
                "schema_version": 1,
                "stderr_sha256": sha256_text(result.stderr),
                "stdout_sha256": sha256_text(result.stdout),
                "timed_out": result.timed_out,
            },
        )


class StateStore:
    """Atomic state storage and an exclusive cross-platform run lock."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state_path = root / "state.json"
        self.lock_path = root / "lock"
        self._owns_lock = False

    def read(self, *, required: bool = False) -> dict[str, object] | None:
        """Read bounded state, rejecting corrupt or unsupported documents."""
        if not self.state_path.exists():
            if required:
                raise StateError("no autopilot state exists; start with `run`")
            return None
        if self.state_path.is_symlink():
            raise StateError("autopilot state must not be a symlink")
        try:
            if self.state_path.stat().st_size > MAX_RESULT_BYTES:
                raise StateError("autopilot state exceeds the safe size limit")
            loaded = cast(
                "object",
                json.loads(
                    self.state_path.read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                ),
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
        ) as error:
            raise StateError("autopilot state is unreadable or malformed") from error
        try:
            state = _mapping(loaded, "autopilot state")
        except InvalidInputError as error:
            raise StateError("autopilot state root is malformed") from error
        if state.get("schema_version") != STATE_SCHEMA_VERSION:
            raise StateError("autopilot state schema is unsupported")
        for key in ("run_id", "branch", "base_commit", "current_phase"):
            if not isinstance(state.get(key), str) or not state[key]:
                raise StateError(f"autopilot state is missing {key}")
        return state

    def write(self, state: Mapping[str, object]) -> None:
        """Atomically persist one safe phase boundary."""
        atomic_write_json(self.state_path, state)

    def acquire(self, run_id: str) -> None:
        """Refuse overlapping runners without guessing whether a lock is stale."""
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as error:
            raise StateError(
                "another autopilot process may be active; inspect .autopilot/lock"
            ) from error
        with os.fdopen(descriptor, "w", encoding="utf-8") as lock_file:
            json.dump({"pid": os.getpid(), "run_id": run_id}, lock_file, sort_keys=True)
            lock_file.write("\n")
            lock_file.flush()
            os.fsync(lock_file.fileno())
        self._owns_lock = True

    def release(self) -> None:
        """Remove only the lock acquired by this process."""
        if not self._owns_lock:
            return
        with suppress(FileNotFoundError):
            self.lock_path.unlink()
        self._owns_lock = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def sha256_text(value: str) -> str:
    """Return the canonical UTF-8 SHA-256 digest of text."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_symlink():
        digest.update(b"symlink\0")
        digest.update(str(path.readlink()).encode("utf-8", errors="surrogateescape"))
        return digest.hexdigest()
    if not path.exists():
        return "missing"
    if not path.is_file():
        return "non-regular"
    digest.update(b"file\0")
    with path.open("rb") as source:
        while chunk := source.read(128 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def extract_milestone_contract(design: str, milestone: Milestone) -> str:
    """Extract exactly one configured backlog subsection from the design."""
    lines = design.splitlines(keepends=True)
    expected = f"### {milestone.heading}"
    matches = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == expected
    ]
    if len(matches) != 1:
        raise InvalidInputError(
            f"expected exactly one design heading {expected!r}, found {len(matches)}"
        )
    start = matches[0]
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].lstrip()
        if stripped.startswith("## ") or re.match(
            r"### M(?:[0-9]+(?:\.[0-9]+)?)\b", stripped
        ):
            end = index
            break
    contract = "".join(lines[start:end]).rstrip() + "\n"
    if "Deliverables:" not in contract:
        raise InvalidInputError(
            f"{milestone.identifier} has no deliverables in the design"
        )
    if "Acceptance:" not in contract:
        raise InvalidInputError(
            f"{milestone.identifier} has no acceptance criteria in the design"
        )
    return contract


def render_prompt(template_text: str, values: Mapping[str, str]) -> str:
    """Render a repository-owned prompt and fail on missing placeholders."""
    try:
        return Template(template_text).substitute(values)
    except KeyError as error:
        raise InvalidInputError(
            f"prompt template references missing value {error.args[0]!r}"
        ) from error


def _read_result_document(path: Path) -> dict[str, object]:
    try:
        if path.is_symlink() or not path.is_file():
            raise InvalidInputError(
                "Codex did not produce the required structured result"
            )
        if path.stat().st_size > MAX_RESULT_BYTES:
            raise InvalidInputError(
                "Codex structured result exceeds the safe size limit"
            )
        raw = cast(
            "object",
            json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            ),
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJSONKeyError,
    ) as error:
        raise InvalidInputError(
            "Codex structured result is missing or malformed"
        ) from error
    return _mapping(raw, "Codex structured result")


def _required_string_array(
    data: Mapping[str, object], key: str, *, unique: bool = False
) -> tuple[str, ...]:
    values = _string_tuple(data.get(key), key)
    if unique and len(values) != len(set(values)):
        raise InvalidInputError(f"{key} must not contain duplicates")
    return values


def _validate_changed_path(value: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InvalidInputError("agent result contains a control character in a path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise InvalidInputError("agent result contains an unsafe changed path")
    return path.as_posix()


def parse_implementation_result(
    path: Path,
    milestone: str,
    actual_changed_paths: Iterable[str],
) -> ImplementationResult:
    """Validate schema shape, semantics, milestone, and claimed file set."""
    data = _read_result_document(path)
    required = {
        "milestone",
        "status",
        "summary",
        "files_changed",
        "acceptance_criteria_addressed",
        "commands_reportedly_run",
        "limitations",
        "blocking_reason",
    }
    if set(data) != required:
        raise InvalidInputError(
            "implementation result properties do not match the schema"
        )
    result_milestone = _string(data.get("milestone"), "milestone")
    if result_milestone != milestone:
        raise InvalidInputError("implementation result names the wrong milestone")
    status = _string(data.get("status"), "status")
    if status not in {"completed", "blocked", "failed"}:
        raise InvalidInputError("implementation result has an unsupported status")
    blocking_reason = _optional_string(data.get("blocking_reason"), "blocking_reason")
    if status == "completed" and blocking_reason is not None:
        raise InvalidInputError(
            "a completed implementation cannot have a blocking reason"
        )
    if status in {"blocked", "failed"} and blocking_reason is None:
        raise InvalidInputError(f"a {status} implementation requires a blocking reason")
    files = tuple(
        _validate_changed_path(item)
        for item in _required_string_array(data, "files_changed", unique=True)
    )
    actual = tuple(sorted(set(actual_changed_paths)))
    if tuple(sorted(files)) != actual:
        raise InvalidInputError(
            "implementation result files_changed contradicts the Git worktree"
        )
    return ImplementationResult(
        milestone=result_milestone,
        status=status,
        summary=_string(data.get("summary"), "summary"),
        files_changed=files,
        acceptance_criteria_addressed=_required_string_array(
            data, "acceptance_criteria_addressed", unique=True
        ),
        commands_reportedly_run=_required_string_array(data, "commands_reportedly_run"),
        limitations=_required_string_array(data, "limitations"),
        blocking_reason=blocking_reason,
    )


def parse_review_result(path: Path, milestone: str) -> ReviewResult:
    """Validate exact reviewer schema and reject contradictory verdicts."""
    data = _read_result_document(path)
    required = {
        "milestone",
        "verdict",
        "findings",
        "acceptance_evidence_inspected",
        "blocking_reason",
    }
    if set(data) != required:
        raise InvalidInputError("review result properties do not match the schema")
    result_milestone = _string(data.get("milestone"), "milestone")
    if result_milestone != milestone:
        raise InvalidInputError("review result names the wrong milestone")
    verdict = _string(data.get("verdict"), "verdict")
    if verdict not in {"pass", "changes_requested", "blocked"}:
        raise InvalidInputError("review result has an unsupported verdict")
    findings: list[ReviewFinding] = []
    finding_keys = {
        "severity",
        "file",
        "line",
        "explanation",
        "required_remediation",
    }
    for index, item in enumerate(_sequence(data.get("findings"), "findings")):
        context = f"findings[{index}]"
        record = _mapping(item, context)
        if set(record) != finding_keys:
            raise InvalidInputError(f"{context} properties do not match the schema")
        severity = _string(record.get("severity"), f"{context}.severity")
        if severity not in {"critical", "high", "medium", "low"}:
            raise InvalidInputError(f"{context}.severity is unsupported")
        file_value = record.get("file")
        file = (
            None
            if file_value is None
            else _validate_changed_path(_string(file_value, f"{context}.file"))
        )
        line_value = record.get("line")
        if line_value is None:
            line = None
        elif (
            isinstance(line_value, bool)
            or not isinstance(line_value, int)
            or line_value < 1
        ):
            raise InvalidInputError(
                f"{context}.line must be a positive integer or null"
            )
        else:
            line = line_value
        findings.append(
            ReviewFinding(
                severity=severity,
                file=file,
                line=line,
                explanation=_string(
                    record.get("explanation"), f"{context}.explanation"
                ),
                required_remediation=_string(
                    record.get("required_remediation"),
                    f"{context}.required_remediation",
                ),
            )
        )
    blocking_reason = _optional_string(data.get("blocking_reason"), "blocking_reason")
    if verdict == "pass" and (findings or blocking_reason is not None):
        raise InvalidInputError(
            "a passing review cannot contain findings or a blocking reason"
        )
    if verdict == "changes_requested" and (not findings or blocking_reason is not None):
        raise InvalidInputError(
            "changes_requested requires findings and no blocking reason"
        )
    if verdict == "blocked" and blocking_reason is None:
        raise InvalidInputError("a blocked review requires a blocking reason")
    acceptance_evidence = _required_string_array(
        data, "acceptance_evidence_inspected", unique=True
    )
    if verdict == "pass" and not acceptance_evidence:
        raise InvalidInputError(
            "a passing review requires inspected acceptance evidence"
        )
    return ReviewResult(
        milestone=result_milestone,
        verdict=verdict,
        findings=tuple(findings),
        acceptance_evidence_inspected=acceptance_evidence,
        blocking_reason=blocking_reason,
    )


def _state_mapping(state: Mapping[str, object], key: str) -> dict[str, object]:
    value = state.get(key)
    if not isinstance(value, dict) or not all(isinstance(item, str) for item in value):
        raise StateError(f"autopilot state field {key!r} is malformed")
    return cast("dict[str, object]", value)


def _state_list(state: Mapping[str, object], key: str) -> list[object]:
    value = state.get(key)
    if not isinstance(value, list):
        raise StateError(f"autopilot state field {key!r} is malformed")
    return cast("list[object]", value)


def _github_repository_to_dict(repository: GitHubRepository) -> dict[str, object]:
    return {
        "host": repository.host,
        "owner": repository.owner,
        "repository": repository.repository,
    }


def _state_github_repository(state: Mapping[str, object]) -> GitHubRepository:
    raw = state.get("github_repository")
    if not isinstance(raw, dict) or set(raw) != {"host", "owner", "repository"}:
        raise StateError("state GitHub repository identity is malformed")
    data = cast("dict[str, object]", raw)
    try:
        repository = GitHubRepository(
            host=_string(data.get("host"), "github_repository.host"),
            owner=_string(data.get("owner"), "github_repository.owner"),
            repository=_string(data.get("repository"), "github_repository.repository"),
        )
        expected = _parse_github_repository_url(
            f"https://{repository.host}/{repository.name_with_owner}.git"
        )
    except InvalidInputError as error:
        raise StateError("state GitHub repository identity is malformed") from error
    if expected != repository:
        raise StateError("state GitHub repository identity is not canonical")
    return repository


def _metadata_ref_paths(reference: str) -> frozenset[str]:
    """Return one ref and only the parent directories its creation may add."""
    path = PurePosixPath(reference)
    if path.is_absolute() or not path.parts or path.parts[0] != "refs":
        raise StateError("controller produced an unsafe Git metadata reference")
    paths: set[str] = set()
    for index in range(2, len(path.parts) + 1):
        paths.add(PurePosixPath(*path.parts[:index]).as_posix())
    log_path = PurePosixPath("logs", *path.parts)
    for index in range(3, len(log_path.parts) + 1):
        paths.add(PurePosixPath(*log_path.parts[:index]).as_posix())
    return frozenset(paths)


def _path_from_repo(repo_root: Path, path: PurePosixPath) -> Path:
    return repo_root.joinpath(*path.parts)


def _assert_safe_directory_chain(repo_root: Path, path: Path, context: str) -> None:
    """Reject runtime paths that escape lexically or traverse a symlink."""
    try:
        relative = path.relative_to(repo_root)
    except ValueError as error:
        raise StateError(f"{context} is outside the repository") from error
    current = repo_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise StateError(f"{context} traverses a symlink")
        if current.exists() and not current.is_dir():
            raise StateError(f"{context} traverses a non-directory path")


def _contains_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


class GitRepository:
    """Read and mutate Git only through explicit parent-owned argv calls."""

    def __init__(
        self,
        root: Path,
        command: Sequence[str],
        runner: CommandRunner,
        timeout_seconds: float,
    ) -> None:
        self.root = root
        self.command = tuple(command)
        self.runner = runner
        self.timeout_seconds = timeout_seconds
        self._metadata_roots: tuple[Path, ...] | None = None

    def run(
        self,
        arguments: Sequence[str],
        *,
        timeout_seconds: float | None = None,
        log_base: Path | None = None,
        env_overrides: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run one Git subcommand without shell expansion."""
        environment = _repository_environment()
        if env_overrides is not None:
            environment.update(env_overrides)
        return self.runner.run(
            (*self.command, *arguments),
            cwd=self.root,
            timeout_seconds=timeout_seconds or self.timeout_seconds,
            env=environment,
            log_base=log_base,
        )

    def run_with_index(
        self,
        arguments: Sequence[str],
        *,
        index_path: Path,
        log_base: Path | None = None,
    ) -> CommandResult:
        """Run Git against one controller-owned temporary index."""
        try:
            relative = index_path.relative_to(self.root)
        except ValueError as error:
            raise StateError("temporary Git index is outside the repository") from error
        if not relative.parts or relative.parts[0] != ".autopilot":
            raise StateError("temporary Git index is outside autopilot state")
        _assert_safe_directory_chain(
            self.root,
            index_path.parent,
            "temporary Git index directory",
        )
        if index_path.is_symlink():
            raise StateError("temporary Git index must not be a symlink")
        environment = _repository_environment()
        environment["GIT_INDEX_FILE"] = str(index_path)
        return self.runner.run(
            (*self.command, *arguments),
            cwd=self.root,
            timeout_seconds=self.timeout_seconds,
            env=environment,
            log_base=log_base,
        )

    def require_output(self, arguments: Sequence[str], context: str) -> str:
        """Return stripped stdout or raise a state error with safe diagnostics."""
        result = self.run(arguments)
        if not result.succeeded:
            detail = (
                result.stderr.strip() or result.stdout.strip() or "Git command failed"
            )
            raise StateError(f"{context}: {detail}")
        return result.stdout.strip()

    def current_branch(self) -> str:
        return self.require_output(
            ("branch", "--show-current"), "unable to read branch"
        )

    def head(self) -> str:
        return self.require_output(("rev-parse", "HEAD"), "unable to read HEAD")

    def rev_parse(self, revision: str) -> str:
        return self.require_output(
            ("rev-parse", "--verify", f"{revision}^{{commit}}"),
            f"unable to resolve {revision}",
        )

    def changed_snapshot(self) -> dict[str, object]:
        """Hash every tracked or untracked worktree change without following links."""
        result = self.run(("status", "--porcelain=v1", "-z", "--untracked-files=all"))
        if not result.succeeded:
            raise StateError("unable to inspect Git worktree status")
        chunks = result.stdout.split("\0")
        records: dict[str, str] = {}
        index = 0
        while index < len(chunks):
            entry = chunks[index]
            index += 1
            if not entry:
                continue
            if len(entry) < 4 or entry[2] != " ":
                raise StateError("Git returned an unsupported porcelain status record")
            status = entry[:2]
            path = entry[3:]
            if _contains_surrogate(path):
                raise StateError("worktree contains a filename that is not valid UTF-8")
            safe = _validate_changed_path(PurePosixPath(path).as_posix())
            records[safe] = status
            if "R" in status or "C" in status:
                if index >= len(chunks) or not chunks[index]:
                    raise StateError("Git returned an incomplete rename status record")
                original = chunks[index]
                index += 1
                if _contains_surrogate(original):
                    raise StateError(
                        "worktree contains a filename that is not valid UTF-8"
                    )
                original_safe = _validate_changed_path(
                    PurePosixPath(original).as_posix()
                )
                records[original_safe] = status
        snapshot: dict[str, object] = {}
        for relative, status in sorted(records.items()):
            absolute = _path_from_repo(self.root, PurePosixPath(relative))
            snapshot[relative] = {"status": status, "hash": _hash_file(absolute)}
        return snapshot

    def staged_paths(self) -> tuple[str, ...]:
        result = self.run(("diff", "--cached", "--name-only", "-z"))
        if not result.succeeded:
            raise StateError("unable to inspect the Git index")
        paths = tuple(item for item in result.stdout.split("\0") if item)
        if any(_contains_surrogate(item) for item in paths):
            raise StateError("Git index contains a filename that is not valid UTF-8")
        return paths

    def semantic_index_snapshot(self) -> dict[str, object]:
        """Record every index entry, stage, mode, object, and index flag by path."""
        result = self.run(("ls-files", "--stage", "-v", "-z"))
        if not result.succeeded:
            raise StateError("unable to inspect the semantic Git index")
        records: dict[str, list[str]] = {}
        for raw in (item for item in result.stdout.split("\0") if item):
            metadata, separator, path = raw.partition("\t")
            if not separator or not metadata or not path:
                raise StateError("Git returned a malformed semantic index entry")
            if _contains_surrogate(path):
                raise StateError(
                    "Git index contains a filename that is not valid UTF-8"
                )
            safe = _validate_changed_path(PurePosixPath(path).as_posix())
            records.setdefault(safe, []).append(metadata)
        return {path: sorted(entries) for path, entries in sorted(records.items())}

    def ensure_ancestor(self, ancestor: str, descendant: str) -> None:
        result = self.run(("merge-base", "--is-ancestor", ancestor, descendant))
        if result.returncode != 0:
            raise StateError(
                "branch history no longer descends from the recorded base commit"
            )

    def branch_exists(self, branch: str) -> bool:
        result = self.run(("show-ref", "--verify", "--quiet", f"refs/heads/{branch}"))
        if result.returncode not in {0, 1}:
            raise StateError("unable to inspect existing branches")
        return result.returncode == 0

    def github_transport(self, remote: str) -> GitHubTransport:
        """Resolve one unredirected credential-free HTTPS fetch/push transport."""
        result = self.run(("config", "--get-all", f"remote.{remote}.url"))
        if not result.succeeded:
            raise InvalidInputError(
                f"configured Git remote {remote!r} has no readable URL"
            )
        urls = [line for line in result.stdout.splitlines() if line]
        if len(urls) != 1:
            raise InvalidInputError(
                f"configured Git remote {remote!r} must have exactly one URL"
            )
        fetch_url = urls[0]
        repository = _parse_github_https_repository_url(fetch_url)
        push_result = self.run(("config", "--get-all", f"remote.{remote}.pushurl"))
        if push_result.returncode not in {0, 1}:
            raise InvalidInputError(
                f"configured Git remote {remote!r} has unreadable push URLs"
            )
        push_urls = [line for line in push_result.stdout.splitlines() if line]
        if push_urls:
            if len(push_urls) != 1:
                raise InvalidInputError(
                    f"configured Git remote {remote!r} must have at most one push URL"
                )
            push_url = push_urls[0]
            if _parse_github_https_repository_url(push_url) != repository:
                raise InvalidInputError(
                    f"configured Git remote {remote!r} fetch and push URLs identify "
                    "different repositories"
                )
        else:
            push_url = fetch_url
        effective: dict[str, str] = {}
        for purpose, arguments, configured in (
            ("fetch", ("remote", "get-url", "--all", remote), fetch_url),
            ("push", ("remote", "get-url", "--push", "--all", remote), push_url),
        ):
            effective_result = self.run(arguments)
            if not effective_result.succeeded:
                raise InvalidInputError(
                    f"unable to resolve effective {purpose} URL for remote {remote!r}"
                )
            effective_urls = [
                line for line in effective_result.stdout.splitlines() if line
            ]
            if len(effective_urls) != 1:
                raise InvalidInputError(
                    f"configured Git remote {remote!r} must have exactly one effective "
                    f"{purpose} URL"
                )
            resolved = effective_urls[0]
            if (
                resolved != configured
                or _parse_github_https_repository_url(resolved) != repository
            ):
                raise InvalidInputError(
                    f"effective {purpose} transport for remote {remote!r} is redirected"
                )
            effective[purpose] = resolved
        return GitHubTransport(
            repository=repository,
            fetch_url=effective["fetch"],
            push_url=effective["push"],
        )

    def github_repository(self, remote: str) -> GitHubRepository:
        """Return the repository identity of a validated HTTPS transport."""
        return self.github_transport(remote).repository

    def assert_object_database_integrity(self) -> None:
        """Validate every Git object while suppressing harmless dangling notices."""
        result = self.run(("fsck", "--no-dangling"))
        if not result.succeeded:
            raise StateError("Git object database failed integrity validation")

    def metadata_digest(
        self,
        *,
        ignored_paths: frozenset[str] = frozenset(),
        ignored_prefixes: frozenset[str] = frozenset(),
        include_semantic_index: bool = True,
    ) -> str:
        """Hash stable Git control data and the semantic index contents."""
        if self._metadata_roots is None:
            git_directory = Path(
                self.require_output(
                    ("rev-parse", "--absolute-git-dir"),
                    "unable to locate Git metadata",
                )
            ).resolve()
            common_directory = Path(
                self.require_output(
                    ("rev-parse", "--path-format=absolute", "--git-common-dir"),
                    "unable to locate shared Git metadata",
                )
            ).resolve()
            roots = {git_directory, common_directory}
            if not all(path.is_dir() for path in roots):
                raise StateError("Git metadata directory is missing or not a directory")
            self._metadata_roots = tuple(sorted(roots, key=str))
        digest = hashlib.sha256()
        try:
            for root_index, root in enumerate(self._metadata_roots):
                digest.update(f"root:{root_index}\0".encode())
                for child in (root, *sorted(root.rglob("*"))):
                    relative = (
                        "." if child == root else child.relative_to(root).as_posix()
                    )
                    if relative in ignored_paths or any(
                        relative == prefix or relative.startswith(f"{prefix}/")
                        for prefix in ignored_prefixes
                    ):
                        continue
                    if relative == "index" or relative.startswith("sharedindex."):
                        continue
                    metadata = child.lstat()
                    digest.update(relative.encode("utf-8", errors="surrogateescape"))
                    digest.update(b"\0")
                    digest.update(str(metadata.st_mode).encode())
                    digest.update(b"\0")
                    digest.update(_hash_file(child).encode())
                    digest.update(b"\0")
        except OSError as error:
            raise StateError("unable to hash Git metadata safely") from error
        if include_semantic_index:
            index = self.run(("ls-files", "--stage", "-v", "-z"))
            if not index.succeeded:
                raise StateError("unable to hash the semantic Git index")
            digest.update(b"semantic-index\0")
            digest.update(index.stdout.encode("utf-8", errors="surrogateescape"))
            digest.update(b"\0")
        return digest.hexdigest()


def _table_value(data: Mapping[str, object], dotted: str) -> object:
    current: object = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            raise StateError(f"quality configuration table {dotted!r} is missing")
        current = cast("dict[str, object]", current)[part]
    return current


def quality_guard_hash(repo_root: Path, guard: QualityGuard) -> str:
    """Hash only configured quality-policy tables, not dependency declarations."""
    path = _path_from_repo(repo_root, guard.path)
    try:
        with path.open("rb") as source:
            data = _mapping(cast("object", tomllib.load(source)), guard.path.as_posix())
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StateError(
            f"unable to read quality configuration {guard.path}"
        ) from error
    selected = {table: _table_value(data, table) for table in guard.tables}
    canonical = json.dumps(
        selected,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256_text(canonical)


def protected_snapshot(
    repo_root: Path,
    config: Config,
    milestone: str,
    frozen_contract: Path | None = None,
) -> dict[str, str]:
    """Hash immutable harness, governance, contract, and quality policy inputs."""
    snapshot: dict[str, str] = {}
    for protected in config.protected_paths:
        if milestone in protected.allow_for:
            continue
        absolute = _path_from_repo(repo_root, protected.path)
        if absolute.is_dir() and not absolute.is_symlink():
            for child in sorted(absolute.rglob("*")):
                if child.is_dir() and not child.is_symlink():
                    continue
                relative = PurePosixPath(child.relative_to(repo_root).as_posix())
                snapshot[relative.as_posix()] = _hash_file(child)
        else:
            snapshot[protected.path.as_posix()] = _hash_file(absolute)
    for guard in config.quality_guards:
        if milestone not in guard.allow_for:
            key = f"quality:{guard.path.as_posix()}:{','.join(guard.tables)}"
            snapshot[key] = quality_guard_hash(repo_root, guard)
    if frozen_contract is not None:
        try:
            relative_contract = frozen_contract.relative_to(repo_root)
        except ValueError as error:
            raise StateError("frozen contract is outside the repository") from error
        snapshot[PurePosixPath(relative_contract.as_posix()).as_posix()] = _hash_file(
            frozen_contract
        )
    return dict(sorted(snapshot.items()))


def _changed_protected_paths(
    expected: Mapping[str, object], current: Mapping[str, str]
) -> tuple[str, ...]:
    keys = set(expected) | set(current)
    return tuple(sorted(key for key in keys if expected.get(key) != current.get(key)))


def _serialize_command_result(
    result: CommandResult, log_base: Path
) -> dict[str, object]:
    return {
        "command": list(result.command),
        "returncode": result.returncode,
        "duration_seconds": round(result.duration_seconds, 6),
        "timed_out": result.timed_out,
        "signal": result.signal_number,
        "stdout_log": log_base.with_suffix(".stdout.log").name,
        "stderr_log": log_base.with_suffix(".stderr.log").name,
        "succeeded": result.succeeded,
    }


def _format_command_failure(result: CommandResult) -> str:
    if result.timed_out:
        outcome = "timed out"
    elif result.signal_number is not None:
        outcome = f"terminated by signal {result.signal_number}"
    else:
        outcome = f"exited {result.returncode}"
    return (
        f"Command: {json.dumps(list(_redacted_command(result.command)))}\n"
        f"Outcome: {outcome}\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}\n"
    )


def _implementation_to_dict(result: ImplementationResult) -> dict[str, object]:
    return {
        "milestone": result.milestone,
        "status": result.status,
        "summary": result.summary,
        "files_changed": list(result.files_changed),
        "acceptance_criteria_addressed": list(result.acceptance_criteria_addressed),
        "commands_reportedly_run": list(result.commands_reportedly_run),
        "limitations": list(result.limitations),
        "blocking_reason": result.blocking_reason,
    }


def _review_to_dict(result: ReviewResult) -> dict[str, object]:
    return {
        "milestone": result.milestone,
        "verdict": result.verdict,
        "findings": [
            {
                "severity": finding.severity,
                "file": finding.file,
                "line": finding.line,
                "explanation": finding.explanation,
                "required_remediation": finding.required_remediation,
            }
            for finding in result.findings
        ],
        "acceptance_evidence_inspected": list(result.acceptance_evidence_inspected),
        "blocking_reason": result.blocking_reason,
    }


class Autopilot:
    """Parent-owned milestone state machine and trust boundary."""

    def __init__(
        self,
        repo_root: Path,
        config: Config,
        *,
        runner: CommandRunner | None = None,
        stdout: TextIO = sys.stdout,
        stderr: TextIO = sys.stderr,
    ) -> None:
        self.repo_root = repo_root.resolve()
        self.config = config
        self.runner = runner or CommandRunner()
        self.stdout = stdout
        self.stderr = stderr
        self.git = GitRepository(
            self.repo_root,
            config.tools["git"],
            self.runner,
            config.default_timeout_seconds,
        )
        self.state_root = _path_from_repo(self.repo_root, config.state_directory)
        _assert_safe_directory_chain(
            self.repo_root,
            self.state_root,
            "autopilot state directory",
        )
        self.store = StateStore(self.state_root)

    def _configured_github_repository(self) -> GitHubRepository:
        return self.git.github_repository(self.config.remote)

    def _remote_transport_url(
        self,
        state: Mapping[str, object],
        *,
        push: bool,
    ) -> str:
        """Revalidate and return the explicit HTTPS URL for one network operation."""
        transport = self.git.github_transport(self.config.remote)
        if transport.repository != _state_github_repository(state):
            raise StateError(
                "configured GitHub transport changed since the run started"
            )
        return transport.push_url if push else transport.fetch_url

    def _require_github_url(
        self,
        state: Mapping[str, object],
        value: object,
        *,
        area: str,
        context: str,
    ) -> str:
        if not isinstance(value, str) or not _github_repository_url(
            value, _state_github_repository(state), area=area
        ):
            raise StateError(f"{context} does not belong to the configured repository")
        return value

    def _write(self, message: str) -> None:
        self.stdout.write(message.rstrip() + "\n")
        self.stdout.flush()

    def _warn(self, message: str) -> None:
        self.stderr.write(f"autopilot: {message.rstrip()}\n")
        self.stderr.flush()

    def _design_text(self) -> str:
        try:
            return (self.repo_root / "docs/design.md").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise InvalidInputError("unable to read docs/design.md") from error

    def select_range(self, start: str, end: str) -> tuple[Milestone, ...]:
        """Resolve an ordered safe range and reject prohibited work before mutation."""
        identifiers = [milestone.identifier for milestone in self.config.milestones]
        if start not in identifiers:
            raise InvalidInputError(f"unknown milestone {start!r}")
        if end not in identifiers:
            raise InvalidInputError(f"unknown milestone {end!r}")
        start_index = identifiers.index(start)
        end_index = identifiers.index(end)
        if start_index > end_index:
            raise InvalidInputError("milestone range must not run in reverse")
        selected = self.config.milestones[start_index : end_index + 1]
        for milestone in selected:
            if milestone.policy == "external_repository":
                raise BlockedError(
                    f"{milestone.identifier} belongs in the separate private service repository"
                )
            if milestone.policy == "design_required":
                required = milestone.required_design
                if (
                    required is None
                    or not _path_from_repo(self.repo_root, required).is_file()
                ):
                    expected = (
                        required.as_posix()
                        if required
                        else "a dedicated design document"
                    )
                    raise BlockedError(
                        f"{milestone.identifier} is refused until {expected} exists"
                    )
        return selected

    def verification_for(self, milestone: Milestone) -> tuple[CommandSpec, ...]:
        extras = tuple(
            self.config.milestone_verification[identifier]
            for identifier in milestone.extra_verification
        )
        return (*self.config.verification, *extras)

    def branch_name(self, selected: Sequence[Milestone]) -> str:
        start = selected[0].identifier.lower().replace(".", "-")
        end = selected[-1].identifier.lower().replace(".", "-")
        branch = self.config.branch_template.format(from_slug=start, through_slug=end)
        if (
            not branch
            or branch.startswith("-")
            or ".." in branch
            or any(character.isspace() or ord(character) < 32 for character in branch)
        ):
            raise InvalidInputError(
                "branch_template produced an unsafe Git branch name"
            )
        validity = self.git.run(("check-ref-format", "--branch", branch))
        if not validity.succeeded:
            raise InvalidInputError(
                "branch_template produced an invalid Git branch name"
            )
        return branch

    def protected_labels(self, milestone: str) -> tuple[str, ...]:
        labels = [
            item.path.as_posix()
            for item in self.config.protected_paths
            if milestone not in item.allow_for
        ]
        labels.extend(
            f"{guard.path.as_posix()} tables: {', '.join(guard.tables)}"
            for guard in self.config.quality_guards
            if milestone not in guard.allow_for
        )
        labels.append("the frozen .autopilot/runs/<run-id>/contract file")
        return tuple(labels)

    def doctor(self, *, publication: bool = False) -> None:
        """Verify local CLI capabilities without contacting the Codex service."""
        checks: list[tuple[str, CommandResult]] = []
        codex_help = self.runner.run(
            (*self.config.tools["codex"], "--help"),
            cwd=self.repo_root,
            timeout_seconds=self.config.default_timeout_seconds,
        )
        checks.append(("Codex interface", codex_help))
        if codex_help.succeeded:
            help_text = f"{codex_help.stdout}\n{codex_help.stderr}"
            if (
                "--ask-for-approval" not in help_text
                or "never" not in help_text
                or "--config" not in help_text
            ):
                raise InvalidInputError(
                    "installed Codex lacks explicit approval-policy control"
                )
        codex_help = self.runner.run(
            (
                *self.config.tools["codex"],
                "--ask-for-approval",
                "never",
                "--config",
                CODEX_APPROVAL_OVERRIDE,
                "exec",
                "--help",
            ),
            cwd=self.repo_root,
            timeout_seconds=self.config.default_timeout_seconds,
        )
        checks.append(("Codex exec interface", codex_help))
        if codex_help.succeeded:
            help_text = f"{codex_help.stdout}\n{codex_help.stderr}"
            required = (
                "--ephemeral",
                "--sandbox",
                "workspace-write",
                "read-only",
                "--output-schema",
                "--output-last-message",
                "--color",
                "--cd",
            )
            missing = [flag for flag in required if flag not in help_text]
            if missing:
                raise InvalidInputError(
                    "installed Codex exec lacks required capabilities: "
                    + ", ".join(missing)
                )
        git_version = self.git.run(("--version",))
        checks.append(("Git", git_version))

        for relative in (
            *ROLE_TEMPLATES.values(),
            IMPLEMENTATION_SCHEMA,
            REVIEW_SCHEMA,
        ):
            path = self.repo_root / relative
            if not path.is_file():
                raise InvalidInputError(
                    f"required automation asset is missing: {relative}"
                )
        for schema_path in (IMPLEMENTATION_SCHEMA, REVIEW_SCHEMA):
            try:
                schema = _mapping(
                    cast(
                        "object",
                        json.loads(
                            (self.repo_root / schema_path).read_text(encoding="utf-8"),
                            object_pairs_hook=_reject_duplicate_json_keys,
                        ),
                    ),
                    schema_path.as_posix(),
                )
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
                _DuplicateJSONKeyError,
            ) as error:
                raise InvalidInputError(
                    f"invalid JSON schema: {schema_path}"
                ) from error
            if schema.get("type") != "object":
                raise InvalidInputError(
                    f"Codex output schema root must be an object: {schema_path}"
                )
            _validate_codex_output_schema(schema, schema_path.as_posix())

        if publication:
            github_transport = self.git.github_transport(self.config.remote)
            github_repository = github_transport.repository
            repository_environment = _repository_environment()
            gh_version = self.runner.run(
                (*self.config.tools["gh"], "--version"),
                cwd=self.repo_root,
                timeout_seconds=self.config.default_timeout_seconds,
                env=repository_environment,
            )
            checks.append(("GitHub CLI", gh_version))
            gh_capabilities = (
                (
                    "GitHub atomic ref creation",
                    ("api", "--help"),
                    ("--hostname", "--include", "--method", "--raw-field"),
                ),
                (
                    "GitHub workflow dispatch",
                    ("workflow", "run", "--help"),
                    ("--ref", "--field"),
                ),
                (
                    "GitHub run discovery",
                    ("run", "list", "--help"),
                    ("--branch", "--commit", "--event", "--json", "--workflow"),
                ),
                (
                    "GitHub run evidence",
                    ("run", "view", "--help"),
                    ("--job", "--json", "--log"),
                ),
            )
            for name, arguments, required_flags in gh_capabilities:
                capability = self.runner.run(
                    (*self.config.tools["gh"], *arguments),
                    cwd=self.repo_root,
                    timeout_seconds=self.config.default_timeout_seconds,
                    env=repository_environment,
                )
                checks.append((name, capability))
                if capability.succeeded:
                    help_text = f"{capability.stdout}\n{capability.stderr}"
                    missing = [flag for flag in required_flags if flag not in help_text]
                    if missing:
                        raise InvalidInputError(
                            f"installed GitHub CLI lacks {name.lower()} capabilities: "
                            + ", ".join(missing)
                        )
            gh_auth = self.runner.run(
                (
                    *self.config.tools["gh"],
                    "auth",
                    "status",
                    "--hostname",
                    github_repository.host,
                ),
                cwd=self.repo_root,
                timeout_seconds=self.config.default_timeout_seconds,
                env=repository_environment,
            )
            checks.append(("GitHub authentication", gh_auth))
            repository_view = self.runner.run(
                (
                    *self.config.tools["gh"],
                    "repo",
                    "view",
                    github_repository.selector,
                    "--json",
                    "nameWithOwner,url",
                ),
                cwd=self.repo_root,
                timeout_seconds=self.config.default_timeout_seconds,
                env=repository_environment,
            )
            checks.append(("GitHub repository binding", repository_view))
            if repository_view.succeeded:
                try:
                    repository_document = _mapping(
                        cast(
                            "object",
                            json.loads(
                                repository_view.stdout,
                                object_pairs_hook=_reject_duplicate_json_keys,
                            ),
                        ),
                        "GitHub repository binding",
                    )
                except (
                    json.JSONDecodeError,
                    _DuplicateJSONKeyError,
                    InvalidInputError,
                ) as error:
                    raise InvalidInputError(
                        "GitHub CLI returned malformed repository binding"
                    ) from error
                if (
                    repository_document.get("nameWithOwner")
                    != github_repository.name_with_owner
                    or not isinstance(repository_document.get("url"), str)
                    or not _github_repository_url(
                        cast("str", repository_document["url"]),
                        github_repository,
                        area="repository",
                    )
                ):
                    raise InvalidInputError(
                        "GitHub CLI repository binding contradicts the configured origin"
                    )
            git_auth = self.git.run(
                ("ls-remote", "--exit-code", github_transport.fetch_url, "HEAD")
            )
            checks.append(("Git remote authentication", git_auth))

        failures = [name for name, result in checks if not result.succeeded]
        for name, result in checks:
            outcome = "ok" if result.succeeded else "FAILED"
            self._write(f"{name}: {outcome}")
        if failures:
            raise InvalidInputError("doctor failed: " + ", ".join(failures))
        self._write("Automation assets and strict schemas: ok")

    def plan(
        self,
        start: str,
        end: str,
        *,
        detailed: bool = False,
        push: bool = False,
        draft_pr: bool = False,
    ) -> None:
        """Print range policy, frozen-contract hashes, and optional dry-run stages."""
        if draft_pr and not push:
            raise InvalidInputError("--draft-pr requires --push")
        selected = self.select_range(start, end)
        design = self._design_text()
        branch = self.branch_name(selected)
        self._write(f"Range: {start} through {end}")
        self._write(f"Branch: {branch}")
        self._write(f"Base: {self.config.base_branch}")
        if any(item.hosted_verification is not None for item in selected):
            self._write(
                "Hosted repository: " + self._configured_github_repository().selector
            )
        self._write("Milestones:")
        for milestone in selected:
            contract = extract_milestone_contract(design, milestone)
            self._write(
                f"  {milestone.identifier}: {milestone.title} "
                f"(contract sha256 {sha256_text(contract)})"
            )
            if milestone.policy == "gate_c":
                self._write("    requires recorded Gate C approval")
            if milestone.stop_after_gate:
                self._write(
                    f"    stops after commit at Gate {milestone.stop_after_gate}"
                )
            if milestone.requires_publication:
                self._write(
                    "    requires --push and exact-candidate hosted verification"
                )
            if detailed:
                self._print_dry_run_milestone(
                    milestone, contract, push=push, draft_pr=draft_pr
                )
        if any(item.identifier == "M6" for item in selected):
            self._write("Gate boundary: stop in awaiting_gate_C after M6")
        if detailed:
            self._write(
                "Dry run only: no Codex session, state write, Git mutation, push, or PR action occurred."
            )

    def _print_dry_run_milestone(
        self,
        milestone: Milestone,
        contract: str,
        *,
        push: bool,
        draft_pr: bool,
    ) -> None:
        verification = self.verification_for(milestone)
        protected = self.protected_labels(milestone.identifier)
        implementation_prompt = self._render_implementation_prompt(
            milestone,
            contract,
            sha256_text(contract),
            "planned previous milestone status",
        )
        review_prompt = render_prompt(
            (self.repo_root / ROLE_TEMPLATES["review"]).read_text(encoding="utf-8"),
            {
                "milestone": milestone.identifier,
                "contract": contract.rstrip(),
                "contract_hash": sha256_text(contract),
                "repository_instructions": self._repository_instructions(),
                "parent_commit": "<parent commit after the previous milestone>",
                "changed_paths": "- <complete agent-produced worktree path set>",
                "verification_evidence": "- <parent-owned command results and log paths>",
                "hosted_verification": self._hosted_verification_markdown(milestone),
            },
        )
        repair_prompt = render_prompt(
            (self.repo_root / ROLE_TEMPLATES["repair"]).read_text(encoding="utf-8"),
            {
                "milestone": milestone.identifier,
                "contract": contract.rstrip(),
                "contract_hash": sha256_text(contract),
                "failed_output": "<redacted failed-command output, when present>",
                "review_findings": "<concrete structured findings, when present>",
                "hosted_verification": self._hosted_verification_markdown(milestone),
                "protected_files": self._protected_markdown(milestone.identifier),
            },
        )
        stages = "implementation -> verification"
        if milestone.hosted_verification is not None:
            stages += " -> immutable candidate -> hosted checks"
        stages += " -> review -> repair (maximum 3) -> commit"
        self._write(f"    stages: {stages}")
        planned_prompts = {
            "implementation": implementation_prompt,
            "review": review_prompt,
            "repair": repair_prompt,
        }
        for role, prompt in planned_prompts.items():
            self._write(
                f"    {role} command: "
                + json.dumps(
                    _redacted_command(
                        self._codex_command(
                            role,
                            Path("<result>"),
                            Path("<milestone-schema>"),
                        )
                    )
                )
            )
            self._write(
                f"    {role} prompt: {ROLE_TEMPLATES[role].as_posix()} "
                f"(rendered sha256 {sha256_text(prompt)})"
            )
            self._write(f"    --- begin {role} prompt ---")
            for line in prompt.rstrip().splitlines():
                self._write(f"      {line}")
            self._write(f"    --- end {role} prompt ---")
        self._write("    verification commands:")
        for spec in verification:
            self._write(
                f"      {spec.identifier}: "
                f"{json.dumps(list(_redacted_command(spec.command)))}"
            )
        self._write("    protected files:")
        for path in protected:
            self._write(f"      {path}")
        if milestone.hosted_verification is not None:
            hosted = self._hosted_policy(milestone)
            transport = self.git.github_transport(self.config.remote)
            repository = transport.repository
            self._write(
                "    candidate ref: <range-branch>-candidate-"
                f"{milestone.identifier.lower()}-<run-id>-<repair-attempt> "
                "(immutable; never force-pushed)"
            )
            self._write(
                "    candidate object-upload command: "
                + json.dumps(
                    [
                        *self.config.tools["git"],
                        "push",
                        "--porcelain",
                        "--no-follow-tags",
                        "--recurse-submodules=no",
                        "--force-with-lease=refs/heads/<candidate-branch>-upload:",
                        transport.push_url,
                        "<candidate-sha>:refs/heads/<candidate-branch>-upload",
                    ]
                )
            )
            self._write(
                "    atomic candidate-ref command: "
                + json.dumps(
                    [
                        *self.config.tools["gh"],
                        "api",
                        "--hostname",
                        repository.host,
                        "--method",
                        "POST",
                        f"repos/{repository.name_with_owner}/git/refs",
                        "--include",
                        "--raw-field",
                        "ref=refs/heads/<candidate-branch>",
                        "--raw-field",
                        "sha=<candidate-sha>",
                    ]
                )
            )
            self._write(
                "    hosted dispatch command: "
                + json.dumps(
                    [
                        *self.config.tools["gh"],
                        "workflow",
                        "run",
                        hosted.workflow,
                        "--ref",
                        "<candidate-branch>",
                        "--field",
                        f"{hosted.dispatch_input}=<one-time-dispatch-token>",
                        "--repo",
                        self._configured_github_repository().selector,
                    ]
                )
            )
            self._write("    required hosted jobs:")
            for job in hosted.required_jobs:
                self._write(f"      {job}")
        message = self.config.commit_template.format(
            milestone=milestone.identifier,
            title=milestone.title,
        )
        self._write(f"    commit: {message}")
        if milestone.hosted_verification is not None:
            self._write(
                "    acceptance: attach the exact hosted candidate to the range branch after review"
            )
        if push:
            self._write(
                "    checkpoint push: git push --no-follow-tags "
                f"--recurse-submodules=no {self.config.remote} <branch> (never force)"
            )
        if draft_pr:
            self._write(
                "    draft PR: create or reuse one PR targeting main, then update its body"
            )

    def _gate_file(self) -> Path:
        return self.state_root / "gates.json"

    def gate_approved(self, gate: str) -> bool:
        """Return whether an explicit evidence-backed gate approval is recorded."""
        path = self._gate_file()
        if not path.is_file():
            return False
        if path.is_symlink():
            raise StateError("gate approval record must not be a symlink")
        try:
            loaded = cast(
                "object",
                json.loads(
                    path.read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                ),
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
        ) as error:
            raise StateError(
                "gate approval record is unreadable or malformed"
            ) from error
        data = _mapping(loaded, "gate approval record")
        gates = _mapping(data.get("gates"), "gate approval record.gates")
        record = gates.get(gate)
        if not isinstance(record, dict):
            return False
        evidence = cast("dict[str, object]", record)
        if not all(
            isinstance(evidence.get(key), str) and bool(evidence[key])
            for key in (
                "approved_by",
                "approved_at",
                "evidence_path",
                "evidence_sha256",
            )
        ):
            return False
        try:
            relative = _relative_path(
                evidence["evidence_path"],
                "Gate C evidence path",
            )
        except InvalidInputError as error:
            raise StateError("Gate C evidence path is malformed") from error
        evidence_path = _path_from_repo(self.repo_root, relative)
        if (
            evidence_path.is_symlink()
            or not evidence_path.is_file()
            or evidence_path.stat().st_size == 0
        ):
            raise StateError("recorded Gate C evidence is missing or unsafe")
        if _hash_file(evidence_path) != evidence["evidence_sha256"]:
            raise StateError("recorded Gate C evidence changed after approval")
        return True

    def approve_gate(self, gate: str, evidence_path: Path, approved_by: str) -> None:
        """Record human-owned external evidence without altering tracked files."""
        if gate != "C":
            raise InvalidInputError("only Gate C can currently be recorded")
        resolved = (
            evidence_path
            if evidence_path.is_absolute()
            else self.repo_root / evidence_path
        ).resolve()
        try:
            relative = resolved.relative_to(self.repo_root)
        except ValueError as error:
            raise InvalidInputError(
                "Gate C evidence must be inside the repository"
            ) from error
        if not resolved.is_file() or resolved.stat().st_size == 0:
            raise InvalidInputError("Gate C evidence must be a non-empty regular file")
        actor = approved_by.strip()
        if not actor or any(
            ord(character) < 32 or ord(character) == 127 for character in actor
        ):
            raise InvalidInputError(
                "--approved-by must be non-empty and contain no control characters"
            )
        run_id = f"gate-{uuid.uuid4().hex[:12]}"
        self.store.acquire(run_id)
        try:
            active_state = self.store.read()
            if active_state is not None and active_state.get("current_phase") not in {
                "awaiting_gate_C",
                "complete",
            }:
                raise StateError(
                    "Gate C approval cannot change during an active milestone phase"
                )
            existing: dict[str, object] = {"schema_version": 1, "gates": {}}
            if self._gate_file().is_file():
                if self._gate_file().is_symlink():
                    raise StateError("gate approval record must not be a symlink")
                try:
                    loaded = cast(
                        "object",
                        json.loads(
                            self._gate_file().read_text(encoding="utf-8"),
                            object_pairs_hook=_reject_duplicate_json_keys,
                        ),
                    )
                except (
                    OSError,
                    UnicodeError,
                    json.JSONDecodeError,
                    _DuplicateJSONKeyError,
                ) as error:
                    raise StateError(
                        "existing gate approval record is malformed"
                    ) from error
                existing = _mapping(loaded, "gate approval record")
            gates = _mapping(existing.get("gates", {}), "gate approval record.gates")
            gates[gate] = {
                "approved_by": actor,
                "approved_at": datetime.now(UTC).isoformat(),
                "evidence_path": PurePosixPath(relative.as_posix()).as_posix(),
                "evidence_sha256": _hash_file(resolved),
            }
            existing["schema_version"] = 1
            existing["gates"] = gates
            atomic_write_json(self._gate_file(), existing)
            if active_state is not None:
                active_state["gate_record_hash"] = _hash_file(self._gate_file())
                active_state["updated_at"] = datetime.now(UTC).isoformat()
                self.store.write(active_state)
        finally:
            self.store.release()
        self._write(
            f"Gate C approved by {actor}; evidence {PurePosixPath(relative.as_posix())} recorded."
        )

    def _active_state_blocks_new_run(self, state: Mapping[str, object]) -> bool:
        phase = state.get("current_phase")
        if phase == "complete":
            return False
        if phase == "awaiting_gate_C":
            current_index = state.get("current_index")
            requested = state.get("requested_milestones")
            return not (
                isinstance(current_index, int)
                and isinstance(requested, list)
                and current_index >= len(requested)
            )
        return True

    def _new_run_preconditions(
        self,
        selected: Sequence[Milestone],
        branch: str,
    ) -> str:
        existing = self.store.read()
        if existing is not None and self._active_state_blocks_new_run(existing):
            raise StateError(
                "an unfinished autopilot run exists; use `status` and `resume`"
            )
        current_branch = self.git.current_branch()
        if current_branch != self.config.base_branch:
            raise StateError(
                f"new runs must start on {self.config.base_branch!r}, not {current_branch!r}"
            )
        if self.git.changed_snapshot():
            raise StateError("normal run refused an unexpectedly dirty worktree")
        if self.git.staged_paths():
            raise StateError("normal run refused a non-empty Git index")
        head = self.git.head()
        base = self.git.rev_parse(self.config.base_branch)
        tracking = self.git.rev_parse(
            f"refs/remotes/{self.config.remote}/{self.config.base_branch}"
        )
        if head != base or head != tracking:
            raise StateError(
                f"{self.config.base_branch} must exactly match "
                f"{self.config.remote}/{self.config.base_branch}"
            )
        self.git.ensure_ancestor(head, head)
        if self.git.branch_exists(branch):
            raise StateError(f"planned branch already exists: {branch}")
        ignored = self.git.run(
            ("check-ignore", "--quiet", f"{self.config.state_directory}/state.json")
        )
        if ignored.returncode != 0:
            raise StateError(
                f"runtime state directory {self.config.state_directory} is not ignored"
            )
        first = selected[0]
        if first.policy == "gate_c" and not self.gate_approved("C"):
            raise BlockedError(
                "Gate C approval is required before starting M7 or M8; "
                "record it with `gate approve C`"
            )
        return head

    @staticmethod
    def _run_identifier() -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return f"{timestamp}-{uuid.uuid4().hex[:10]}"

    def _run_directory(self, state: Mapping[str, object]) -> Path:
        raw = state.get("run_directory")
        if not isinstance(raw, str):
            raise StateError("autopilot state has no run directory")
        relative = _relative_path(raw, "state.run_directory")
        run_id = state.get("run_id")
        if (
            not isinstance(run_id, str)
            or re.fullmatch(
                r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}",
                run_id,
            )
            is None
        ):
            raise StateError("autopilot run ID is malformed")
        expected = self.config.state_directory / "runs" / run_id
        if relative != expected:
            raise StateError("autopilot run directory does not match its run ID")
        path = _path_from_repo(self.repo_root, relative)
        _assert_safe_directory_chain(self.repo_root, path, "autopilot run directory")
        if not path.is_dir():
            raise StateError("autopilot run directory is missing")
        return path

    def _save(self, state: dict[str, object], phase: str | None = None) -> None:
        if phase is not None:
            state["current_phase"] = phase
        state["updated_at"] = datetime.now(UTC).isoformat()
        self.store.write(state)

    def run(
        self,
        start: str,
        end: str,
        *,
        push: bool,
        draft_pr: bool,
        dry_run: bool,
        timeout_override: float | None = None,
    ) -> ExitCode:
        """Create one range branch and drive it until completion or a safe stop."""
        if draft_pr and not push:
            raise InvalidInputError("--draft-pr requires --push")
        selected = self.select_range(start, end)
        if dry_run:
            self.plan(start, end, detailed=True, push=push, draft_pr=draft_pr)
            return ExitCode.SUCCESS
        if any(item.requires_publication for item in selected) and not push:
            raise InvalidInputError(
                "M6 requires --push so exact-candidate Linux, macOS, and Windows "
                "evidence can be verified before acceptance"
            )
        self.doctor(publication=push)
        branch = self.branch_name(selected)
        run_id = self._run_identifier()
        self.store.acquire(run_id)
        try:
            base_commit = self._new_run_preconditions(selected, branch)
            run_relative = self.config.state_directory / "runs" / run_id
            run_directory = _path_from_repo(self.repo_root, run_relative)
            for name in ("contract", "prompts", "results", "logs"):
                (run_directory / name).mkdir(parents=True, exist_ok=True)
            first = selected[0]
            github_repository = self._configured_github_repository() if push else None
            state: dict[str, object] = {
                "schema_version": STATE_SCHEMA_VERSION,
                "run_id": run_id,
                "run_directory": run_relative.as_posix(),
                "branch": branch,
                "base_branch": self.config.base_branch,
                "base_commit": base_commit,
                "expected_head": base_commit,
                "requested_milestones": [item.identifier for item in selected],
                "current_index": 0,
                "current_milestone": first.identifier,
                "current_phase": "branch_pending",
                "repair_count": 0,
                "completed_commits": [],
                "prompt_hashes": {},
                "contract_hashes": {},
                "protected_hashes": protected_snapshot(
                    self.repo_root, self.config, first.identifier
                ),
                "git_metadata_digest": self.git.metadata_digest(),
                "transition_git_metadata_digest": None,
                "transition_git_metadata_kind": None,
                "attachment_index_baseline": None,
                "gate_record_hash": _hash_file(self._gate_file()),
                "worktree_snapshot": {},
                "verification_results": [],
                "verification_index": 0,
                "review_findings": [],
                "failed_output_path": None,
                "agent_process_failures": [],
                "active_agent_attempt": None,
                "active_agent_retry": None,
                "active_result_path": None,
                "active_role": None,
                "pending_agent_retry": None,
                "session_baseline_snapshot": {},
                "session_git_metadata_digest": None,
                "candidate": {"active": None, "attempts": []},
                "hosted_evidence": None,
                "github_repository": (
                    _github_repository_to_dict(github_repository)
                    if github_repository is not None
                    else None
                ),
                "publication": {
                    "enabled": push,
                    "draft_pr": draft_pr,
                    "status": "not_started" if push else "disabled",
                    "pushed_commits": [],
                    "pr_url": None,
                },
                "timeout_override": timeout_override,
                "created_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
                "last_error": None,
            }
            self._save(state)
            return self._drive(state)
        finally:
            self.store.release()

    def resume(self) -> ExitCode:
        """Continue only from the exact repository and phase recorded in state."""
        state = self.store.read(required=True)
        if state is None:  # pragma: no cover - required=True already raises.
            raise StateError("no autopilot state exists")
        run_id = cast("str", state["run_id"])
        self.store.acquire(run_id)
        try:
            self._validate_resume_state(state)
            publication = _state_mapping(state, "publication")
            if publication.get("enabled") is True and state.get("current_phase") in {
                "candidate_publication_pending",
                "candidate_dispatch_pending",
                "candidate_dispatch_running",
                "candidate_checks_pending",
                "candidate_checks_running",
                "publication_pending",
            }:
                self.doctor(publication=True)
            return self._drive(state)
        finally:
            self.store.release()

    def status(self, *, as_json: bool = False) -> None:
        """Display persisted state without acquiring or changing the run lock."""
        state = self.store.read()
        if state is None:
            self._write("No autopilot state exists.")
            return
        if as_json:
            self._write(
                json.dumps(
                    _redact_structure(state),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        self._write(f"Run: {state['run_id']}")
        self._write(f"Branch: {state['branch']}")
        self._write(f"Phase: {state['current_phase']}")
        self._write(f"Milestone: {state.get('current_milestone') or '-'}")
        self._write(f"Repair cycles: {state.get('repair_count', 0)}")
        commits = _state_list(state, "completed_commits")
        self._write(f"Completed commits: {len(commits)}")
        publication = _state_mapping(state, "publication")
        self._write(f"Publication: {publication.get('status', 'unknown')}")
        candidate_value = state.get("candidate")
        active_candidate = (
            candidate_value.get("active") if isinstance(candidate_value, dict) else None
        )
        if isinstance(active_candidate, dict):
            self._write(
                "Candidate: "
                f"{active_candidate.get('sha', 'pending')} "
                f"({active_candidate.get('status', 'unknown')})"
            )
        if state.get("last_error"):
            self._write(f"Last error: {state['last_error']}")

    def _transition_metadata_digest(
        self,
        state: Mapping[str, object],
        kind: str,
    ) -> str:
        record = self._active_candidate(state)
        ignored_paths: set[str] = set()
        ignored_prefixes: set[str] = set()
        include_semantic_index = True
        if kind == "candidate_creation":
            ignored_paths.update(
                _metadata_ref_paths(
                    _string(record.get("local_ref"), "candidate.local_ref")
                )
            )
            ignored_prefixes.add("objects")
        elif kind == "candidate_publication":
            remote_branch = _string(
                record.get("remote_branch"), "candidate.remote_branch"
            )
            for branch in (remote_branch, f"{remote_branch}-upload"):
                ignored_paths.update(
                    _metadata_ref_paths(f"refs/remotes/{self.config.remote}/{branch}")
                )
        elif kind == "candidate_attachment":
            ignored_paths.update(_metadata_ref_paths(f"refs/heads/{state['branch']}"))
            ignored_paths.add("logs/HEAD")
            include_semantic_index = False
        else:
            raise StateError("state Git metadata transition kind is unsupported")
        return self.git.metadata_digest(
            ignored_paths=frozenset(ignored_paths),
            ignored_prefixes=frozenset(ignored_prefixes),
            include_semantic_index=include_semantic_index,
        )

    def _begin_transition_metadata_guard(
        self,
        state: dict[str, object],
        kind: str,
    ) -> None:
        if kind == "candidate_attachment":
            state["attachment_index_baseline"] = self.git.semantic_index_snapshot()
        state["transition_git_metadata_kind"] = kind
        state["transition_git_metadata_digest"] = self._transition_metadata_digest(
            state, kind
        )

    @staticmethod
    def _clear_transition_metadata_guard(state: dict[str, object]) -> None:
        state["transition_git_metadata_kind"] = None
        state["transition_git_metadata_digest"] = None
        state["attachment_index_baseline"] = None

    def _assert_attachment_index_transition(self, state: Mapping[str, object]) -> None:
        baseline_raw = state.get("attachment_index_baseline")
        if not isinstance(baseline_raw, dict) or not all(
            isinstance(path, str) and isinstance(entries, list)
            for path, entries in baseline_raw.items()
        ):
            raise StateError("candidate attachment index baseline is malformed")
        baseline = cast("dict[str, object]", baseline_raw)
        current = self.git.semantic_index_snapshot()
        candidate_paths = set(_state_mapping(state, "worktree_snapshot"))
        for path in set(baseline) | set(current):
            if path not in candidate_paths and baseline.get(path) != current.get(path):
                raise StateError(
                    "semantic Git index changed outside candidate attachment paths"
                )

    def _assert_transition_metadata_guard(
        self,
        state: Mapping[str, object],
        expected_kind: str,
    ) -> None:
        kind = state.get("transition_git_metadata_kind")
        expected = state.get("transition_git_metadata_digest")
        if kind != expected_kind or not isinstance(expected, str):
            raise StateError("state Git metadata transition guard is malformed")
        if self._transition_metadata_digest(state, expected_kind) != expected:
            raise StateError(
                "Git metadata changed outside the exact parent-owned transition"
            )
        if expected_kind == "candidate_attachment":
            self._assert_attachment_index_transition(state)

    def _validate_resume_state(self, state: dict[str, object]) -> None:
        state.setdefault("candidate", {"active": None, "attempts": []})
        state.setdefault("hosted_evidence", None)
        state.setdefault("agent_process_failures", [])
        state.setdefault("transition_git_metadata_digest", None)
        state.setdefault("transition_git_metadata_kind", None)
        state.setdefault("attachment_index_baseline", None)
        requested = state.get("requested_milestones")
        if (
            not isinstance(requested, list)
            or not requested
            or not all(isinstance(item, str) for item in requested)
        ):
            raise StateError("state requested_milestones is malformed")
        for identifier in cast("list[str]", requested):
            self.config.milestone(identifier)
        index = state.get("current_index")
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index <= len(requested)
        ):
            raise StateError("state current_index is malformed")
        phase = state.get("current_phase")
        if not isinstance(phase, str) or phase not in VALID_PHASES:
            raise StateError("state current_phase is unsupported")
        pending_retry_raw = state.get("pending_agent_retry")
        if pending_retry_raw is not None:
            pending_retry = _mapping(pending_retry_raw, "pending agent retry")
            retry_role = pending_retry.get("role")
            if retry_role not in ROLE_TEMPLATES:
                raise StateError("pending agent retry role is malformed")
            _integer(
                pending_retry.get("attempt"),
                "pending agent retry.attempt",
                minimum=0,
            )
            _integer(
                pending_retry.get("retry"),
                "pending agent retry.retry",
                minimum=1,
            )
            if phase != f"{retry_role}_pending":
                raise StateError("pending agent retry contradicts the current phase")
        repair_count = state.get("repair_count")
        if (
            isinstance(repair_count, bool)
            or not isinstance(repair_count, int)
            or not 0 <= repair_count <= self.config.max_repair_cycles
        ):
            raise StateError("state repair_count is malformed")
        verification_index = state.get("verification_index")
        if (
            isinstance(verification_index, bool)
            or not isinstance(verification_index, int)
            or verification_index < 0
        ):
            raise StateError("state verification_index is malformed")
        timeout_override = state.get("timeout_override")
        if timeout_override is not None and (
            isinstance(timeout_override, bool)
            or not isinstance(timeout_override, (int, float))
            or not math.isfinite(float(timeout_override))
            or timeout_override <= 0
        ):
            raise StateError("state timeout_override is malformed")
        gate_record_hash = state.get("gate_record_hash")
        if not isinstance(gate_record_hash, str):
            raise StateError("state Gate C record hash is malformed")
        if _hash_file(self._gate_file()) != gate_record_hash:
            raise StateError(
                "Gate C approval record changed outside an operator command"
            )
        for key in (
            "agent_process_failures",
            "completed_commits",
            "verification_results",
            "review_findings",
        ):
            _state_list(state, key)
        for key in (
            "prompt_hashes",
            "contract_hashes",
            "protected_hashes",
            "worktree_snapshot",
            "candidate",
            "publication",
        ):
            _state_mapping(state, key)
        candidate = _state_mapping(state, "candidate")
        if set(candidate) != {"active", "attempts"}:
            raise StateError("state candidate record is malformed")
        attempts = candidate.get("attempts")
        if not isinstance(attempts, list) or not all(
            isinstance(item, dict) for item in attempts
        ):
            raise StateError("state candidate attempts are malformed")
        active_candidate = candidate.get("active")
        if active_candidate is not None and not isinstance(active_candidate, dict):
            raise StateError("state active candidate is malformed")
        hosted_evidence = state.get("hosted_evidence")
        if hosted_evidence is not None and not isinstance(hosted_evidence, dict):
            raise StateError("state hosted evidence is malformed")
        current_milestone = state.get("current_milestone")
        expected_milestone = requested[index] if index < len(requested) else None
        if current_milestone != expected_milestone:
            raise StateError("state current_milestone contradicts its range index")
        candidate_phases = {
            "candidate_pending",
            "candidate_running",
            "candidate_publication_pending",
            "candidate_dispatch_pending",
            "candidate_dispatch_running",
            "candidate_checks_pending",
            "candidate_checks_running",
            "candidate_attach_pending",
            "candidate_attach_running",
        }
        if phase in candidate_phases:
            if (
                not isinstance(current_milestone, str)
                or self.config.milestone(current_milestone).hosted_verification is None
            ):
                raise StateError("candidate phase belongs to a non-hosted milestone")
            if phase != "candidate_pending" and not isinstance(active_candidate, dict):
                raise StateError("candidate phase has no active candidate")
        selected = tuple(
            self.config.milestone(item) for item in cast("list[str]", requested)
        )
        if state.get("branch") != self.branch_name(selected):
            raise StateError("state branch contradicts its requested range")
        if state.get("base_branch") != self.config.base_branch:
            raise StateError("state base branch contradicts automation policy")
        self._run_directory(state)
        publication = _state_mapping(state, "publication")
        required_publication = {
            "enabled",
            "draft_pr",
            "status",
            "pushed_commits",
            "pr_url",
        }
        if not required_publication.issubset(publication):
            raise StateError("state publication record is incomplete")
        if not isinstance(publication.get("enabled"), bool) or not isinstance(
            publication.get("draft_pr"), bool
        ):
            raise StateError("state publication flags are malformed")
        pushed_commits = publication.get("pushed_commits")
        if not isinstance(pushed_commits, list) or not all(
            isinstance(item, str) for item in pushed_commits
        ):
            raise StateError("state publication commits are malformed")
        if not isinstance(publication.get("status"), str):
            raise StateError("state publication status is malformed")
        if (
            any(item.requires_publication for item in selected)
            and publication.get("enabled") is not True
        ):
            raise StateError("state disables required exact-candidate publication")
        if publication.get("enabled") is True:
            github_repository = _state_github_repository(state)
            if github_repository != self._configured_github_repository():
                raise StateError(
                    "configured GitHub repository changed since the run started"
                )
        elif state.get("github_repository") is not None:
            raise StateError(
                "local-only state unexpectedly records a GitHub repository"
            )
        pr_url = publication.get("pr_url")
        if pr_url is not None and (
            publication.get("enabled") is not True
            or not isinstance(pr_url, str)
            or not _github_repository_url(
                pr_url, _state_github_repository(state), area="pull"
            )
        ):
            raise StateError("state publication URL is malformed")
        branch = cast("str", state["branch"])
        current_branch = self.git.current_branch()
        if phase == "branch_pending":
            if current_branch not in {self.config.base_branch, branch}:
                raise StateError("branch changed while branch creation was pending")
        elif current_branch != branch:
            raise StateError(
                f"resume requires branch {branch!r}; current branch is {current_branch!r}"
            )
        expected_head = state.get("expected_head")
        if not isinstance(expected_head, str):
            raise StateError("state expected_head is malformed")
        current_head = self.git.head()
        if phase == "commit_running":
            self._recover_commit_if_present(state, current_head)
            current_head = self.git.head()
            expected_head = cast("str", state["expected_head"])
            phase = cast("str", state["current_phase"])
        if phase == "candidate_attach_running":
            self._assert_transition_metadata_guard(state, "candidate_attachment")
            self._recover_candidate_attach_if_present(state, current_head)
            current_head = self.git.head()
            expected_head = cast("str", state["expected_head"])
            phase = cast("str", state["current_phase"])
        if current_head != expected_head:
            raise StateError(
                "branch HEAD moved outside the recorded autopilot transition"
            )
        self.git.ensure_ancestor(cast("str", state["base_commit"]), current_head)
        current_snapshot = self.git.changed_snapshot()
        expected_snapshot = _state_mapping(state, "worktree_snapshot")
        expected_metadata = state.get("git_metadata_digest")
        if not isinstance(expected_metadata, str):
            raise StateError("state Git metadata digest is malformed")
        metadata_changed = self.git.metadata_digest() != expected_metadata
        guarded_transition = False
        if phase == "candidate_running":
            self._assert_transition_metadata_guard(state, "candidate_creation")
            guarded_transition = True
        elif phase == "candidate_attach_running":
            self._assert_transition_metadata_guard(state, "candidate_attachment")
            guarded_transition = True
        elif (
            phase == "candidate_publication_pending"
            and state.get("transition_git_metadata_kind") == "candidate_publication"
        ):
            self._assert_transition_metadata_guard(state, "candidate_publication")
            guarded_transition = True
            if metadata_changed:
                state["_unconfirmed_candidate_push_metadata_change"] = True
        elif (
            state.get("transition_git_metadata_kind") is not None
            or state.get("transition_git_metadata_digest") is not None
        ):
            raise StateError(
                "state retained a Git metadata guard outside its transition"
            )
        if (
            state.get("transition_git_metadata_kind") != "candidate_attachment"
            and state.get("attachment_index_baseline") is not None
        ):
            raise StateError(
                "state retained a semantic index baseline outside attachment"
            )
        if phase != "commit_running" and not guarded_transition and metadata_changed:
            if (
                phase == "publication_pending"
                and publication.get("status") == "pushing"
            ):
                state["_unconfirmed_push_metadata_change"] = True
            else:
                raise StateError(
                    "Git metadata changed outside a parent-owned transition"
                )
        if phase in {"candidate_attach_running", "commit_running"}:
            if not self._snapshots_match_content(expected_snapshot, current_snapshot):
                raise StateError(
                    "commit transition worktree differs from recorded changes"
                )
        elif current_snapshot != expected_snapshot:
            raise StateError(
                "worktree differs from the exact changes recorded in state"
            )
        if (
            phase not in {"candidate_attach_running", "commit_running"}
            and self.git.staged_paths()
        ):
            raise StateError("Git index changed outside the parent-owned commit phase")
        if isinstance(active_candidate, dict) and isinstance(
            active_candidate.get("sha"), str
        ):
            local_ref = _string(
                active_candidate.get("local_ref"), "candidate.local_ref"
            )
            if self._local_ref_sha(local_ref) != active_candidate.get("sha"):
                raise StateError(
                    "immutable local candidate reference moved or vanished"
                )
            if index < len(requested):
                current_policy = self.config.milestone(cast("str", requested[index]))
                self._validate_candidate_commit(
                    state,
                    current_policy,
                    cast("str", active_candidate["sha"]),
                    _string(active_candidate.get("parent"), "candidate.parent"),
                    _string(active_candidate.get("tree"), "candidate.tree"),
                )
        if index < len(requested):
            milestone = cast("str", requested[index])
            contract_path = self._state_contract_path(state, required=False)
            current_protected = protected_snapshot(
                self.repo_root,
                self.config,
                milestone,
                contract_path,
            )
            expected_protected = _state_mapping(state, "protected_hashes")
            changed = _changed_protected_paths(expected_protected, current_protected)
            if changed:
                raise StateError(
                    "protected files changed while the run was paused: "
                    + ", ".join(changed)
                )

    def _assert_git_metadata_unchanged(
        self,
        state: dict[str, object],
        *,
        session: bool,
    ) -> None:
        key = "session_git_metadata_digest" if session else "git_metadata_digest"
        expected = state.get(key)
        if not isinstance(expected, str):
            raise StateError(f"state {key} is malformed")
        if self.git.metadata_digest() == expected:
            return
        state["last_error"] = (
            "child session modified Git metadata; changes were preserved"
            if session
            else "verification command modified Git metadata; changes were preserved"
        )
        self._save(state, "blocked")
        raise StateError(cast("str", state["last_error"]))

    @staticmethod
    def _snapshots_match_content(
        expected: Mapping[str, object], current: Mapping[str, object]
    ) -> bool:
        if set(expected) != set(current):
            return False
        for path in expected:
            expected_item = expected[path]
            current_item = current[path]
            if not isinstance(expected_item, dict) or not isinstance(
                current_item, dict
            ):
                return False
            if expected_item.get("hash") != current_item.get("hash"):
                return False
        return True

    def _state_contract_path(
        self, state: Mapping[str, object], *, required: bool
    ) -> Path | None:
        raw = state.get("contract_path")
        if raw is None:
            if required:
                raise StateError("state has no frozen contract path")
            return None
        if not isinstance(raw, str):
            raise StateError("state frozen contract path is malformed")
        relative = _relative_path(raw, "state.contract_path")
        milestone = state.get("current_milestone")
        if not isinstance(milestone, str):
            raise StateError("state frozen contract has no current milestone")
        run_directory = self._run_directory(state)
        expected = run_directory / "contract" / f"{milestone}.md"
        path = _path_from_repo(self.repo_root, relative)
        if path != expected:
            raise StateError("state frozen contract path is outside its run directory")
        if path.is_symlink() or not path.is_file():
            raise StateError(
                "frozen milestone contract is missing or not a regular file"
            )
        return path

    def _drive(self, state: dict[str, object]) -> ExitCode:
        while True:
            phase = cast("str", state["current_phase"])
            if phase == "branch_pending":
                self._ensure_range_branch(state)
                continue
            if phase == "milestone_pending":
                outcome = self._begin_milestone(state)
                if outcome is not None:
                    return outcome
                continue
            if phase == "agent_failed":
                self._queue_agent_retry(
                    state,
                    cast("str", state.get("active_role")),
                    "previous agent process failed",
                )
                continue
            if phase in {"implementation_pending", "implementation_running"}:
                self._run_or_recover_agent(state, "implementation")
                continue
            if phase in {"verification_pending", "verification_running"}:
                self._run_verification(state)
                continue
            if phase in {"review_pending", "review_running"}:
                self._run_or_recover_agent(state, "review")
                continue
            if phase in {"repair_pending", "repair_running"}:
                self._run_or_recover_agent(state, "repair")
                continue
            if phase in {"candidate_pending", "candidate_running"}:
                self._prepare_candidate(state)
                continue
            if phase == "candidate_publication_pending":
                self._publish_candidate(state)
                continue
            if phase in {"candidate_dispatch_pending", "candidate_dispatch_running"}:
                self._dispatch_candidate_workflow(state)
                continue
            if phase in {"candidate_checks_pending", "candidate_checks_running"}:
                self._wait_for_candidate_checks(state)
                continue
            if phase in {"candidate_attach_pending", "candidate_attach_running"}:
                self._attach_candidate(state)
                continue
            if phase in {"commit_pending", "commit_running"}:
                self._commit_current_milestone(state)
                continue
            if phase == "publication_pending":
                self._publish_current_checkpoint(state)
                continue
            if phase == "milestone_complete":
                outcome = self._advance_milestone(state)
                if outcome is not None:
                    return outcome
                continue
            if phase == "awaiting_gate_C":
                requested = cast("list[str]", state["requested_milestones"])
                index = cast("int", state["current_index"])
                if index >= len(requested):
                    return ExitCode.SUCCESS
                if not self.gate_approved("C"):
                    raise BlockedError(
                        "run is awaiting external Gate C approval; record evidence then resume"
                    )
                self._save(state, "milestone_pending")
                continue
            if phase == "complete":
                return ExitCode.SUCCESS
            if phase == "blocked":
                raise BlockedError(
                    str(state.get("last_error") or "agent reported a blocker")
                )
            if phase in {"failed", "repair_exhausted", "agent_failed"}:
                raise AutopilotError(
                    str(state.get("last_error") or "autopilot run failed")
                )
            raise StateError(f"state contains unsupported phase {phase!r}")

    def _ensure_range_branch(self, state: dict[str, object]) -> None:
        branch = cast("str", state["branch"])
        current = self.git.current_branch()
        expected_head = cast("str", state["expected_head"])
        if current == branch:
            if self.git.head() != expected_head:
                raise StateError("created branch does not point at the recorded base")
        elif current == self.config.base_branch:
            result = self.git.run(("switch", "-c", branch))
            if not result.succeeded:
                state["last_error"] = (
                    result.stderr.strip() or "unable to create range branch"
                )
                self._save(state)
                raise StateError(cast("str", state["last_error"]))
        else:
            raise StateError("branch changed before range branch creation completed")
        state["git_metadata_digest"] = self.git.metadata_digest()
        self._save(state, "milestone_pending")
        self._write(f"Created range branch {branch}.")

    def _begin_milestone(self, state: dict[str, object]) -> ExitCode | None:
        requested = cast("list[str]", state["requested_milestones"])
        index = cast("int", state["current_index"])
        if index >= len(requested):
            state["current_milestone"] = None
            self._save(state, "complete")
            self._update_pr_body_if_available(state, "requested range complete")
            return ExitCode.SUCCESS
        identifier = requested[index]
        milestone = self.config.milestone(identifier)
        if milestone.policy == "gate_c" and not self.gate_approved("C"):
            state["current_milestone"] = identifier
            state["last_error"] = "Gate C approval is required before this milestone"
            self._save(state, "awaiting_gate_C")
            raise BlockedError(cast("str", state["last_error"]))
        design = self._design_text()
        contract = extract_milestone_contract(design, milestone)
        contract_hash = sha256_text(contract)
        run_directory = self._run_directory(state)
        contract_path = run_directory / "contract" / f"{identifier}.md"
        _atomic_write_bytes(contract_path, contract.encode("utf-8"))
        state["current_milestone"] = identifier
        state["contract_path"] = PurePosixPath(
            contract_path.relative_to(self.repo_root).as_posix()
        ).as_posix()
        state["contract_hash"] = contract_hash
        hashes = _state_mapping(state, "contract_hashes")
        hashes[identifier] = contract_hash
        state["contract_hashes"] = hashes
        state["repair_count"] = 0
        state["verification_results"] = []
        state["verification_index"] = 0
        state["review_findings"] = []
        state["failed_output_path"] = None
        state["active_agent_attempt"] = None
        state["active_agent_retry"] = None
        state["active_result_path"] = None
        state["active_role"] = None
        state["pending_agent_retry"] = None
        state["session_baseline_snapshot"] = {}
        state["session_git_metadata_digest"] = None
        state["candidate"] = {"active": None, "attempts": []}
        state["hosted_evidence"] = None
        self._clear_transition_metadata_guard(state)
        state["last_error"] = None
        state["protected_hashes"] = protected_snapshot(
            self.repo_root,
            self.config,
            identifier,
            contract_path,
        )
        state["worktree_snapshot"] = self.git.changed_snapshot()
        self._save(state, "implementation_pending")
        self._write(f"Frozen {identifier} contract at {contract_hash}.")
        return None

    def _repository_instructions(self) -> str:
        try:
            return (self.repo_root / "AGENTS.md").read_text(encoding="utf-8").rstrip()
        except (OSError, UnicodeError) as error:
            raise StateError("unable to read protected AGENTS.md") from error

    def _previous_status(self, state: Mapping[str, object]) -> str:
        commits = _state_list(state, "completed_commits")
        if not commits:
            return (
                f"M1 is complete at base commit {state['base_commit']}. "
                "No milestone in this run has yet been committed."
            )
        lines = ["Completed and independently reviewed milestones in this run:"]
        for item in commits:
            record = _mapping(item, "completed commit")
            lines.append(f"- {record.get('milestone')}: {record.get('commit')}")
        return "\n".join(lines)

    def _verification_markdown(self, milestone: Milestone) -> str:
        return "\n".join(
            f"- `{shlex.join(_redacted_command(spec.command))}` "
            f"(timeout {spec.timeout_seconds:g}s)"
            for spec in self.verification_for(milestone)
        )

    def _hosted_verification_markdown(self, milestone: Milestone) -> str:
        if milestone.hosted_verification is None:
            return "- No hosted verification is configured for this milestone."
        policy = self._hosted_policy(milestone)
        jobs = "\n".join(f"  - `{name}`" for name in policy.required_jobs)
        return (
            f"- Workflow: `{policy.workflow}`.\n"
            f"- Declare `workflow_dispatch.inputs.{policy.dispatch_input}` and pass "
            "the controller-supplied one-time token through unchanged.\n"
            f"- Set the workflow `run-name` to exactly `PyAhead autopilot "
            f"${{{{ inputs.{policy.dispatch_input} }}}}` so the controller can bind "
            "the dispatch to one new run.\n"
            "- Required job names (exact):\n"
            f"{jobs}"
        )

    def _protected_markdown(self, milestone: str) -> str:
        return "\n".join(f"- `{path}`" for path in self.protected_labels(milestone))

    def _render_implementation_prompt(
        self,
        milestone: Milestone,
        contract: str,
        contract_hash: str,
        previous_status: str,
    ) -> str:
        template = (self.repo_root / ROLE_TEMPLATES["implementation"]).read_text(
            encoding="utf-8"
        )
        return render_prompt(
            template,
            {
                "milestone": milestone.identifier,
                "milestone_title": milestone.title,
                "contract": contract.rstrip(),
                "contract_hash": contract_hash,
                "repository_instructions": self._repository_instructions(),
                "previous_status": previous_status,
                "verification_commands": self._verification_markdown(milestone),
                "hosted_verification": self._hosted_verification_markdown(milestone),
                "protected_files": self._protected_markdown(milestone.identifier),
            },
        )

    def _render_review_prompt(
        self,
        state: Mapping[str, object],
        milestone: Milestone,
        contract: str,
    ) -> str:
        template = (self.repo_root / ROLE_TEMPLATES["review"]).read_text(
            encoding="utf-8"
        )
        changed = _state_mapping(state, "worktree_snapshot")
        changed_paths = "\n".join(f"- `{path}`" for path in sorted(changed)) or "- none"
        return render_prompt(
            template,
            {
                "milestone": milestone.identifier,
                "contract": contract.rstrip(),
                "contract_hash": cast("str", state["contract_hash"]),
                "repository_instructions": self._repository_instructions(),
                "parent_commit": cast("str", state["expected_head"]),
                "changed_paths": changed_paths,
                "verification_evidence": self._verification_evidence(state),
                "hosted_verification": self._hosted_verification_markdown(milestone),
            },
        )

    def _render_repair_prompt(
        self,
        state: Mapping[str, object],
        milestone: Milestone,
        contract: str,
    ) -> str:
        template = (self.repo_root / ROLE_TEMPLATES["repair"]).read_text(
            encoding="utf-8"
        )
        failure_path_raw = state.get("failed_output_path")
        if isinstance(failure_path_raw, str):
            failure_path = _path_from_repo(
                self.repo_root, _relative_path(failure_path_raw, "failed_output_path")
            )
            run_directory = self._run_directory(state)
            results_directory = run_directory / "results"
            _assert_safe_directory_chain(
                self.repo_root,
                results_directory,
                "autopilot results directory",
            )
            if (
                failure_path.parent != results_directory
                or failure_path.is_symlink()
                or not failure_path.is_file()
            ):
                raise StateError("recorded repair input path is unsafe")
            try:
                failed_output = failure_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise StateError("recorded repair input is unreadable") from error
        else:
            failed_output = "No verification command failed."
        review_findings = _state_list(state, "review_findings")
        findings_text = (
            json.dumps(review_findings, ensure_ascii=False, indent=2, sort_keys=True)
            if review_findings
            else "[]"
        )
        return render_prompt(
            template,
            {
                "milestone": milestone.identifier,
                "contract": contract.rstrip(),
                "contract_hash": cast("str", state["contract_hash"]),
                "failed_output": failed_output.rstrip(),
                "review_findings": findings_text,
                "hosted_verification": self._hosted_verification_markdown(milestone),
                "protected_files": self._protected_markdown(milestone.identifier),
            },
        )

    def _session_schema_text(self, role: str, milestone: str) -> str:
        base = REVIEW_SCHEMA if role == "review" else IMPLEMENTATION_SCHEMA
        try:
            raw = cast(
                "object",
                json.loads(
                    (self.repo_root / base).read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                ),
            )
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
        ) as error:
            raise StateError("unable to derive the session output schema") from error
        schema = _mapping(raw, "session output schema")
        properties = _mapping(schema.get("properties"), "session schema properties")
        milestone_property = _mapping(
            properties.get("milestone"), "session schema milestone property"
        )
        milestone_property["const"] = milestone
        properties["milestone"] = milestone_property
        schema["properties"] = properties
        _validate_codex_output_schema(schema, "session output schema")
        return (
            json.dumps(
                schema,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def _assert_session_schema(self, path: Path, role: str, milestone: str) -> None:
        expected = self._session_schema_text(role, milestone)
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise StateError(
                "session output schema is missing or unreadable"
            ) from error
        if path.is_symlink() or actual != expected:
            raise StateError("session output schema changed during the child session")

    def _codex_command(
        self,
        role: str,
        result_path: Path,
        schema_path: Path,
    ) -> tuple[str, ...]:
        sandbox = "read-only" if role == "review" else "workspace-write"
        return (
            *self.config.tools["codex"],
            "--ask-for-approval",
            "never",
            "--config",
            CODEX_APPROVAL_OVERRIDE,
            "exec",
            "--ephemeral",
            "--sandbox",
            sandbox,
            "--output-schema",
            str(schema_path.resolve()),
            "--output-last-message",
            str(result_path.resolve()),
            "--color",
            "never",
            "--cd",
            str(self.repo_root),
            "-",
        )

    def _agent_paths(
        self,
        state: Mapping[str, object],
        role: str,
        attempt: int,
        retry: int = 0,
    ) -> tuple[Path, Path, Path, Path]:
        milestone = cast("str", state["current_milestone"])
        run_directory = self._run_directory(state)
        stem = f"{milestone}-{role}-{attempt}"
        if retry:
            stem = f"{stem}-retry-{retry}"
        return (
            run_directory / "prompts" / f"{stem}.md",
            run_directory / "results" / f"{stem}.json",
            run_directory / "results" / f"{stem}.schema.json",
            run_directory / "logs" / stem,
        )

    def _run_or_recover_agent(self, state: dict[str, object], role: str) -> None:
        phase = cast("str", state["current_phase"])
        milestone = cast("str", state["current_milestone"])
        if phase == f"{role}_running":
            if state.get("active_role") != role:
                raise StateError("running agent phase contradicts its recorded role")
            result_raw = state.get("active_result_path")
            if not isinstance(result_raw, str):
                raise StateError("running agent phase has no result path")
            result_path = _path_from_repo(
                self.repo_root, _relative_path(result_raw, "active_result_path")
            )
            attempt, retry = self._active_agent_coordinates(state, role)
            _prompt_path, expected_result, schema_path, _log_base = self._agent_paths(
                state,
                role,
                attempt,
                retry,
            )
            if result_path != expected_result or result_path.is_symlink():
                raise StateError("running agent result path is unsafe")
            self._assert_session_schema(schema_path, role, milestone)
            if result_path.is_file():
                self._finish_agent_result(state, role, result_path)
                return
            baseline = _state_mapping(state, "session_baseline_snapshot")
            current = self.git.changed_snapshot()
            recorded = _state_mapping(state, "worktree_snapshot")
            if current in (baseline, recorded):
                self._queue_agent_retry(state, role, "interrupted agent session")
                return
            raise StateError("interrupted agent left unrecorded worktree changes")
        self._execute_agent(state, role)

    def _active_agent_coordinates(
        self,
        state: Mapping[str, object],
        role: str,
    ) -> tuple[int, int]:
        """Return the durable logical attempt and process-retry coordinates."""
        raw_attempt = state.get("active_agent_attempt")
        if raw_attempt is None:
            raw_attempt = 0 if role == "implementation" else state.get("repair_count")
        raw_retry = state.get("active_agent_retry", 0)
        if (
            isinstance(raw_attempt, bool)
            or not isinstance(raw_attempt, int)
            or raw_attempt < 0
            or isinstance(raw_retry, bool)
            or not isinstance(raw_retry, int)
            or raw_retry < 0
        ):
            raise StateError("active agent coordinates are malformed")
        return raw_attempt, raw_retry

    def _queue_agent_retry(
        self,
        state: dict[str, object],
        role: str,
        reason: str,
    ) -> None:
        """Queue one fresh process for the same logical agent role and attempt."""
        if role not in ROLE_TEMPLATES:
            raise StateError("failed agent state has no valid active role")
        attempt, retry = self._active_agent_coordinates(state, role)
        state["pending_agent_retry"] = {
            "attempt": attempt,
            "retry": retry + 1,
            "role": role,
        }
        state["active_result_path"] = None
        state["active_role"] = None
        state["last_error"] = f"{reason}; retrying {role} in a fresh session"
        self._save(state, f"{role}_pending")
        self._write(
            f"Retrying {role} attempt {attempt} in fresh process {retry + 1}; "
            "recorded work is preserved."
        )

    def _execute_agent(self, state: dict[str, object], role: str) -> None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        contract_path = self._state_contract_path(state, required=True)
        if contract_path is None:  # pragma: no cover - required=True raises.
            raise StateError("missing contract")
        contract = contract_path.read_text(encoding="utf-8")
        if sha256_text(contract) != state.get("contract_hash"):
            raise StateError("frozen milestone contract hash changed")
        pending_retry_raw = state.get("pending_agent_retry")
        pending_retry: dict[str, object] | None = None
        if pending_retry_raw is not None:
            pending_retry = dict(_mapping(pending_retry_raw, "pending agent retry"))
            if pending_retry.get("role") != role:
                raise StateError("pending agent retry contradicts its role")
            attempt = _integer(
                pending_retry.get("attempt"),
                "pending agent retry.attempt",
                minimum=0,
            )
            retry = _integer(
                pending_retry.get("retry"),
                "pending agent retry.retry",
                minimum=1,
            )
        else:
            retry = 0
        if role == "implementation":
            prompt = self._render_implementation_prompt(
                milestone,
                contract,
                cast("str", state["contract_hash"]),
                self._previous_status(state),
            )
            expected_attempt = 0
        elif role == "review":
            prompt = self._render_review_prompt(state, milestone, contract)
            expected_attempt = cast("int", state["repair_count"])
        else:
            if pending_retry is None:
                if cast("int", state["repair_count"]) >= self.config.max_repair_cycles:
                    state["last_error"] = "maximum repair-cycle count exhausted"
                    self._save(state, "repair_exhausted")
                    raise AutopilotError(cast("str", state["last_error"]))
                state["repair_count"] = cast("int", state["repair_count"]) + 1
            expected_attempt = cast("int", state["repair_count"])
            prompt = self._render_repair_prompt(state, milestone, contract)
        if pending_retry is None:
            attempt = expected_attempt
        elif attempt != expected_attempt:
            raise StateError("pending agent retry contradicts its logical attempt")
        prompt_path, result_path, schema_path, log_base = self._agent_paths(
            state,
            role,
            attempt,
            retry,
        )
        _atomic_write_bytes(prompt_path, prompt.encode("utf-8"))
        _atomic_write_bytes(
            schema_path,
            self._session_schema_text(role, milestone.identifier).encode("utf-8"),
        )
        with suppress(FileNotFoundError):
            result_path.unlink()
        hashes = _state_mapping(state, "prompt_hashes")
        prompt_key = f"{milestone.identifier}:{role}:{attempt}"
        if retry:
            prompt_key = f"{prompt_key}:retry:{retry}"
        hashes[prompt_key] = sha256_text(prompt)
        state["prompt_hashes"] = hashes
        baseline = self.git.changed_snapshot()
        if baseline != _state_mapping(state, "worktree_snapshot"):
            raise StateError("worktree changed before an agent session started")
        expected_metadata = state.get("git_metadata_digest")
        current_metadata = self.git.metadata_digest()
        if (
            not isinstance(expected_metadata, str)
            or current_metadata != expected_metadata
        ):
            state["last_error"] = "Git metadata changed before an agent session started"
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        if (
            self.git.current_branch() != state["branch"]
            or self.git.head() != state["expected_head"]
        ):
            raise StateError("Git identity changed before an agent session started")
        if self.git.staged_paths():
            raise StateError("agent session refused a non-empty Git index")
        state["session_baseline_snapshot"] = baseline
        state["session_git_metadata_digest"] = current_metadata
        state["active_result_path"] = PurePosixPath(
            result_path.relative_to(self.repo_root).as_posix()
        ).as_posix()
        state["active_agent_attempt"] = attempt
        state["active_agent_retry"] = retry
        state["active_role"] = role
        state["pending_agent_retry"] = None
        self._save(state, f"{role}_running")
        environment = _repository_environment()
        environment[CHILD_MARKER] = "1"
        timeout_override = state.get("timeout_override")
        timeout = (
            float(timeout_override)
            if isinstance(timeout_override, (int, float))
            and not isinstance(timeout_override, bool)
            else self.config.codex_timeout_seconds
        )
        try:
            command_result = self.runner.run(
                self._codex_command(role, result_path, schema_path),
                cwd=self.repo_root,
                timeout_seconds=timeout,
                input_text=prompt,
                env=environment,
                log_base=log_base,
            )
        except AutopilotInterruptedError:
            self._assert_git_metadata_unchanged(state, session=True)
            self._assert_session_schema(
                schema_path,
                role,
                milestone.identifier,
            )
            current = self.git.changed_snapshot()
            self._assert_child_boundaries(state, milestone, current)
            state["worktree_snapshot"] = current
            state["last_error"] = f"interrupted during {role} session"
            self._save(state)
            raise
        self._assert_git_metadata_unchanged(state, session=True)
        self._assert_session_schema(
            schema_path,
            role,
            milestone.identifier,
        )
        current = self.git.changed_snapshot()
        self._assert_child_boundaries(state, milestone, current)
        state["worktree_snapshot"] = current
        if not command_result.succeeded:
            reason = _format_command_failure(command_result)
            failure_path = self._write_agent_process_failure(state, role, reason)
            failures = _state_list(state, "agent_process_failures")
            attempt, retry = self._active_agent_coordinates(state, role)
            failures.append(
                {
                    "attempt": attempt,
                    "milestone": milestone.identifier,
                    "path": failure_path,
                    "retry": retry,
                    "role": role,
                    "sha256": sha256_text(reason),
                }
            )
            state["agent_process_failures"] = failures
            state["last_error"] = (
                f"{role} Codex session failed; complete logs were preserved"
            )
            self._save(state, "agent_failed")
            raise AutopilotError(cast("str", state["last_error"]))
        self._finish_agent_result(state, role, result_path)

    def _assert_child_boundaries(
        self,
        state: dict[str, object],
        milestone: Milestone,
        current_snapshot: Mapping[str, object],
    ) -> None:
        if self.git.current_branch() != state["branch"]:
            state["worktree_snapshot"] = dict(current_snapshot)
            state["last_error"] = "child session changed the Git branch"
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        if self.git.head() != state["expected_head"]:
            state["worktree_snapshot"] = dict(current_snapshot)
            state["last_error"] = "child session changed Git history"
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        if self.git.staged_paths():
            state["worktree_snapshot"] = dict(current_snapshot)
            state["last_error"] = "child session changed the Git index"
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        expected_gate_hash = state.get("gate_record_hash")
        if (
            not isinstance(expected_gate_hash, str)
            or _hash_file(self._gate_file()) != expected_gate_hash
        ):
            state["worktree_snapshot"] = dict(current_snapshot)
            state["last_error"] = (
                "child or verification process modified the external Gate C "
                "approval record; changes were preserved"
            )
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        contract_path = self._state_contract_path(state, required=True)
        current_protected = protected_snapshot(
            self.repo_root,
            self.config,
            milestone.identifier,
            contract_path,
        )
        expected = _state_mapping(state, "protected_hashes")
        changed = _changed_protected_paths(expected, current_protected)
        if changed:
            state["worktree_snapshot"] = dict(current_snapshot)
            state["last_error"] = (
                "child session modified protected files; changes were preserved: "
                + ", ".join(changed)
            )
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))

    def _finish_agent_result(
        self, state: dict[str, object], role: str, result_path: Path
    ) -> None:
        milestone = cast("str", state["current_milestone"])
        current_snapshot = self.git.changed_snapshot()
        self._assert_child_boundaries(
            state, self.config.milestone(milestone), current_snapshot
        )
        state["worktree_snapshot"] = current_snapshot
        try:
            if role == "review":
                review_result = parse_review_result(result_path, milestone)
                implementation_result = None
            else:
                review_result = None
                implementation_result = parse_implementation_result(
                    result_path,
                    milestone,
                    current_snapshot,
                )
        except InvalidInputError as error:
            reason = f"{role} structured result was invalid: {error}"
            state["failed_output_path"] = self._write_failure_input(state, reason)
            state["last_error"] = reason
            if role == "review":
                self._save(state, "agent_failed")
                raise AutopilotError(reason) from error
            self._schedule_repair(state, reason)
            return
        if role == "review":
            if review_result is None:  # pragma: no cover - established above.
                raise StateError("review result was not parsed")
            review = review_result
            state["review_result"] = _review_to_dict(review)
            if review.verdict == "pass":
                state["review_findings"] = []
                state["last_error"] = None
                current = self.config.milestone(milestone)
                self._save(
                    state,
                    "candidate_attach_pending"
                    if current.hosted_verification is not None
                    else "commit_pending",
                )
                self._write(f"Independent review passed for {milestone}.")
                return
            if review.verdict == "blocked":
                state["last_error"] = _redact(
                    review.blocking_reason or "reviewer blocked"
                )
                self._save(state, "blocked")
                raise BlockedError(cast("str", state["last_error"]))
            state["review_findings"] = _review_to_dict(review)["findings"]
            state["failed_output_path"] = self._write_failure_input(
                state, "All independent verification commands passed before review."
            )
            self._schedule_repair(state, "independent review requested changes")
            return
        if implementation_result is None:  # pragma: no cover - established above.
            raise StateError("implementation result was not parsed")
        implementation = implementation_result
        state[f"{role}_result"] = _implementation_to_dict(implementation)
        if implementation.status == "blocked":
            state["last_error"] = _redact(
                implementation.blocking_reason or "agent blocked"
            )
            self._save(state, "blocked")
            raise BlockedError(cast("str", state["last_error"]))
        if implementation.status == "failed":
            state["last_error"] = _redact(
                implementation.blocking_reason or "agent failed"
            )
            self._save(state, "failed")
            raise AutopilotError(cast("str", state["last_error"]))
        state["verification_results"] = []
        state["verification_index"] = 0
        state["last_error"] = None
        self._save(state, "verification_pending")
        self._write(f"Fresh {role} session completed for {milestone}.")

    def _write_failure_input(self, state: Mapping[str, object], content: str) -> str:
        run_directory = self._run_directory(state)
        milestone = cast("str", state["current_milestone"])
        repair = state.get("repair_count", 0)
        path = run_directory / "results" / f"{milestone}-failure-{repair}.txt"
        _atomic_write_bytes(
            path, _redact(content).encode("utf-8", errors="backslashreplace")
        )
        return PurePosixPath(path.relative_to(self.repo_root).as_posix()).as_posix()

    def _write_agent_process_failure(
        self,
        state: Mapping[str, object],
        role: str,
        content: str,
    ) -> str:
        """Record a process failure without replacing semantic repair evidence."""
        run_directory = self._run_directory(state)
        milestone = cast("str", state["current_milestone"])
        attempt, retry = self._active_agent_coordinates(state, role)
        stem = f"{milestone}-{role}-{attempt}"
        if retry:
            stem = f"{stem}-retry-{retry}"
        path = run_directory / "results" / f"{stem}.process-failure.txt"
        _atomic_write_bytes(
            path,
            _redact(content).encode("utf-8", errors="backslashreplace"),
        )
        return PurePosixPath(path.relative_to(self.repo_root).as_posix()).as_posix()

    def _schedule_repair(self, state: dict[str, object], reason: str) -> None:
        if cast("int", state["repair_count"]) >= self.config.max_repair_cycles:
            state["last_error"] = f"{reason}; maximum repair-cycle count exhausted"
            self._save(state, "repair_exhausted")
            raise AutopilotError(cast("str", state["last_error"]))
        self._supersede_candidate_for_repair(state)
        state["last_error"] = reason
        self._save(state, "repair_pending")
        self._write(
            f"Scheduling fresh repair cycle {cast('int', state['repair_count']) + 1}: {reason}."
        )

    def _run_verification(self, state: dict[str, object]) -> None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        specs = self.verification_for(milestone)
        index = state.get("verification_index")
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index <= len(specs)
        ):
            raise StateError("verification index is malformed")
        results = _state_list(state, "verification_results")
        baseline = _state_mapping(state, "worktree_snapshot")
        run_directory = self._run_directory(state)
        while index < len(specs):
            spec = specs[index]
            self._assert_git_metadata_unchanged(state, session=False)
            state["verification_index"] = index
            self._save(state, "verification_running")
            log_base = (
                run_directory
                / "logs"
                / f"{milestone.identifier}-verify-{cast('int', state['repair_count'])}-{index}-{spec.identifier}"
            )
            timeout_override = state.get("timeout_override")
            timeout = (
                float(timeout_override)
                if isinstance(timeout_override, (int, float))
                and not isinstance(timeout_override, bool)
                else spec.timeout_seconds
            )
            try:
                result = self.runner.run(
                    spec.command,
                    cwd=self.repo_root,
                    timeout_seconds=timeout,
                    env=_repository_environment(),
                    log_base=log_base,
                )
            except AutopilotInterruptedError:
                self._assert_git_metadata_unchanged(state, session=False)
                state["last_error"] = (
                    f"interrupted during verification command {spec.identifier}"
                )
                self._save(state)
                raise
            self._assert_git_metadata_unchanged(state, session=False)
            current = self.git.changed_snapshot()
            self._assert_child_boundaries(state, milestone, current)
            if current != baseline:
                result = CommandResult(
                    command=result.command,
                    returncode=result.returncode or 1,
                    stdout=result.stdout,
                    stderr=(
                        result.stderr
                        + "\nVerification command unexpectedly modified tracked worktree files.\n"
                    ),
                    duration_seconds=result.duration_seconds,
                    timed_out=result.timed_out,
                )
                CommandRunner.write_logs(result, log_base)
                state["worktree_snapshot"] = current
                baseline = current
            results.append(_serialize_command_result(result, log_base))
            state["verification_results"] = results
            index += 1
            state["verification_index"] = index
            self._save(state, "verification_running")
        failures: list[str] = []
        for result_item in results:
            record = _mapping(result_item, "verification result")
            if record.get("succeeded") is not True:
                command = tuple(
                    _string_tuple(record.get("command"), "verification command")
                )
                stdout_name = _string(record.get("stdout_log"), "stdout_log")
                stderr_name = _string(record.get("stderr_log"), "stderr_log")
                if any(
                    Path(name).name != name or PurePosixPath(name).name != name
                    for name in (stdout_name, stderr_name)
                ):
                    raise StateError("verification log path is unsafe")
                logs_directory = run_directory / "logs"
                _assert_safe_directory_chain(
                    self.repo_root,
                    logs_directory,
                    "autopilot logs directory",
                )
                stdout_log = logs_directory / stdout_name
                stderr_log = logs_directory / stderr_name
                if any(
                    path.is_symlink() or not path.is_file()
                    for path in (stdout_log, stderr_log)
                ):
                    raise StateError("verification log is missing or unsafe")
                try:
                    stdout = stdout_log.read_text(encoding="utf-8")
                    stderr = stderr_log.read_text(encoding="utf-8")
                except (OSError, UnicodeError) as error:
                    raise StateError("verification log is unreadable") from error
                failures.append(
                    f"Command: {json.dumps(list(_redacted_command(command)))}\n"
                    f"Return code: {record.get('returncode')}\n"
                    f"Timed out: {record.get('timed_out')}\n"
                    f"Signal: {record.get('signal')}\n"
                    f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}\n"
                )
        if failures:
            state["failed_output_path"] = self._write_failure_input(
                state, "\n".join(failures)
            )
            state["review_findings"] = []
            self._schedule_repair(state, "independent verification failed")
            return
        state["last_error"] = None
        self._save(
            state,
            "candidate_pending"
            if milestone.hosted_verification is not None
            else "review_pending",
        )
        self._write(f"Independent verification passed for {milestone.identifier}.")

    def _verification_evidence(self, state: Mapping[str, object]) -> str:
        results = _state_list(state, "verification_results")
        lines: list[str] = []
        for item in results:
            record = _mapping(item, "verification result")
            lines.append(
                "- "
                + json.dumps(_redact_structure(record.get("command")))
                + f": {'passed' if record.get('succeeded') else 'failed'}; "
                + f"returncode={record.get('returncode')}; "
                + f"timeout={record.get('timed_out')}; signal={record.get('signal')}; "
                + f"logs={record.get('stdout_log')}, {record.get('stderr_log')}"
            )
        hosted = state.get("hosted_evidence")
        if isinstance(hosted, dict):
            lines.append(
                "- exact-candidate hosted evidence: "
                + json.dumps(
                    _redact_structure(hosted),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        return "\n".join(lines) or "- no verification evidence"

    def _hosted_policy(self, milestone: Milestone) -> HostedVerification:
        identifier = milestone.hosted_verification
        if identifier is None:
            raise StateError("milestone has no hosted verification policy")
        try:
            return self.config.hosted_verification[identifier]
        except KeyError as error:  # pragma: no cover - configuration validates this.
            raise StateError("hosted verification policy is missing") from error

    def _active_candidate(self, state: Mapping[str, object]) -> dict[str, object]:
        candidate = _state_mapping(state, "candidate")
        active = candidate.get("active")
        if not isinstance(active, dict) or not all(
            isinstance(key, str) for key in active
        ):
            raise StateError("state has no active exact candidate")
        return cast("dict[str, object]", active)

    def _store_candidate(
        self,
        state: dict[str, object],
        record: Mapping[str, object],
    ) -> None:
        candidate = _state_mapping(state, "candidate")
        attempts_raw = candidate.get("attempts")
        if not isinstance(attempts_raw, list):
            raise StateError("state candidate attempts are malformed")
        attempt = record.get("attempt")
        attempts: list[object] = []
        replaced = False
        for item in attempts_raw:
            if isinstance(item, dict) and item.get("attempt") == attempt:
                attempts.append(dict(record))
                replaced = True
            else:
                attempts.append(item)
        if not replaced:
            attempts.append(dict(record))
        candidate["attempts"] = attempts
        candidate["active"] = dict(record)
        state["candidate"] = candidate

    def _supersede_candidate_for_repair(self, state: dict[str, object]) -> None:
        candidate = _state_mapping(state, "candidate")
        active = candidate.get("active")
        if not isinstance(active, dict):
            return
        record = cast("dict[str, object]", dict(active))
        record["status"] = "superseded_for_repair"
        self._store_candidate(state, record)

    def _candidate_references(
        self,
        state: Mapping[str, object],
        milestone: Milestone,
        attempt: int,
    ) -> tuple[str, str, str]:
        run_id = cast("str", state["run_id"])
        branch = cast("str", state["branch"])
        local_ref = (
            f"refs/pyahead/autopilot/candidates/{run_id}/"
            f"{milestone.identifier}/{attempt}"
        )
        remote_branch = (
            f"{branch}-candidate-{milestone.identifier.lower()}-"
            f"{run_id.lower()}-{attempt}"
        )
        remote_ref = f"refs/heads/{remote_branch}"
        for reference in (local_ref, remote_ref):
            valid = self.git.run(("check-ref-format", reference))
            if not valid.succeeded:
                raise StateError("controller produced an invalid candidate reference")
        return local_ref, remote_ref, remote_branch

    def _candidate_tree(
        self,
        state: Mapping[str, object],
        milestone: Milestone,
        attempt: int,
        parent: str,
        snapshot: Mapping[str, object],
    ) -> str:
        if not snapshot:
            raise StateError("refusing to create an empty exact candidate")
        run_directory = self._run_directory(state)
        index_path = (
            run_directory
            / "results"
            / f"{milestone.identifier}-candidate-{attempt}.index"
        )
        with suppress(FileNotFoundError):
            index_path.unlink()
        try:
            read_tree = self.git.run_with_index(
                ("read-tree", parent),
                index_path=index_path,
                log_base=run_directory
                / "logs"
                / f"{milestone.identifier}-candidate-{attempt}-read-tree",
            )
            if not read_tree.succeeded:
                raise StateError("unable to initialize the candidate Git index")
            for index, path in enumerate(sorted(snapshot)):
                added = self.git.run_with_index(
                    ("add", "-A", "--", path),
                    index_path=index_path,
                    log_base=run_directory
                    / "logs"
                    / f"{milestone.identifier}-candidate-{attempt}-add-{index}",
                )
                if not added.succeeded:
                    raise StateError(f"unable to stage candidate path {path!r}")
            tree_result = self.git.run_with_index(
                ("write-tree",),
                index_path=index_path,
                log_base=run_directory
                / "logs"
                / f"{milestone.identifier}-candidate-{attempt}-write-tree",
            )
            if not tree_result.succeeded:
                raise StateError("unable to write the exact candidate tree")
            tree = tree_result.stdout.strip().lower()
            if re.fullmatch(r"[0-9a-f]{40,64}", tree) is None:
                raise StateError("Git returned an invalid candidate tree")
            return tree
        finally:
            with suppress(FileNotFoundError):
                index_path.unlink()

    def _local_ref_sha(self, reference: str) -> str | None:
        result = self.git.run(
            ("rev-parse", "--verify", "--quiet", f"{reference}^{{commit}}")
        )
        if result.returncode == 1:
            return None
        if not result.succeeded:
            raise StateError("unable to inspect the local candidate reference")
        sha = result.stdout.strip().lower()
        if re.fullmatch(r"[0-9a-f]{40,64}", sha) is None:
            raise StateError("local candidate reference has an invalid commit")
        return sha

    def _validate_candidate_commit(
        self,
        state: Mapping[str, object],
        milestone: Milestone,
        sha: str,
        parent: str,
        tree: str,
    ) -> None:
        resolved = self.git.rev_parse(sha)
        if resolved.lower() != sha.lower():
            raise StateError(
                "candidate reference did not resolve to its recorded commit"
            )
        actual_parent = self.git.require_output(
            ("show", "-s", "--format=%P", sha),
            "unable to inspect candidate parent",
        )
        if actual_parent != parent:
            raise StateError("exact candidate has an unexpected parent")
        actual_tree = self.git.require_output(
            ("show", "-s", "--format=%T", sha),
            "unable to inspect candidate tree",
        )
        if actual_tree.lower() != tree.lower():
            raise StateError("exact candidate tree no longer matches state")
        message = self.git.require_output(
            ("show", "-s", "--format=%B", sha),
            "unable to inspect candidate message",
        )
        _, trailers = self._commit_message(milestone, cast("str", state["run_id"]))
        if not all(line in message.splitlines() for line in trailers.splitlines()):
            raise StateError("exact candidate lacks parent-owned milestone trailers")
        identity = self._candidate_commit_identity(state)
        actual_identity = self.git.require_output(
            (
                "show",
                "-s",
                "--format=%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%ai%x00%ci",
                sha,
            ),
            "unable to inspect candidate identity",
        ).split("\0")
        expected_timestamp = str(identity["timestamp"])
        if actual_identity != [
            identity["name"],
            identity["email"],
            expected_timestamp,
            identity["name"],
            identity["email"],
            expected_timestamp,
            identity["date_display"],
            identity["date_display"],
        ]:
            raise StateError("exact candidate identity no longer matches state")

    def _new_candidate_commit_identity(self) -> dict[str, object]:
        name = self.git.require_output(
            ("config", "user.name"), "candidate commit user.name is not configured"
        )
        email = self.git.require_output(
            ("config", "user.email"), "candidate commit user.email is not configured"
        )
        if any(character in name + email for character in ("\0", "\n", "\r")):
            raise StateError("candidate commit identity contains a control character")
        timestamp = int(time.time())
        display = datetime.fromtimestamp(timestamp, UTC).strftime(
            "%Y-%m-%d %H:%M:%S +0000"
        )
        return {
            "date_display": display,
            "email": email,
            "name": name,
            "timestamp": timestamp,
        }

    def _candidate_commit_identity(
        self, state: Mapping[str, object]
    ) -> dict[str, str | int]:
        raw = self._active_candidate(state).get("commit_identity")
        identity = _mapping(raw, "candidate.commit_identity")
        if set(identity) != {"date_display", "email", "name", "timestamp"}:
            raise StateError("candidate commit identity is malformed")
        name = _string(identity.get("name"), "candidate.commit_identity.name")
        email = _string(identity.get("email"), "candidate.commit_identity.email")
        display = _string(
            identity.get("date_display"), "candidate.commit_identity.date_display"
        )
        timestamp = identity.get("timestamp")
        if (
            type(timestamp) is not int
            or timestamp < 0
            or any(character in name + email for character in ("\n", "\r"))
            or datetime.fromtimestamp(timestamp, UTC).strftime(
                "%Y-%m-%d %H:%M:%S +0000"
            )
            != display
        ):
            raise StateError("candidate commit identity is invalid")
        return {
            "date_display": display,
            "email": email,
            "name": name,
            "timestamp": timestamp,
        }

    def _candidate_commit_environment(
        self, state: Mapping[str, object]
    ) -> dict[str, str]:
        identity = self._candidate_commit_identity(state)
        date = f"@{identity['timestamp']} +0000"
        return {
            "GIT_AUTHOR_DATE": date,
            "GIT_AUTHOR_EMAIL": cast("str", identity["email"]),
            "GIT_AUTHOR_NAME": cast("str", identity["name"]),
            "GIT_COMMITTER_DATE": date,
            "GIT_COMMITTER_EMAIL": cast("str", identity["email"]),
            "GIT_COMMITTER_NAME": cast("str", identity["name"]),
        }

    def _prepare_candidate(self, state: dict[str, object]) -> None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        self._hosted_policy(milestone)
        attempt = cast("int", state["repair_count"])
        parent = cast("str", state["expected_head"])
        snapshot = _state_mapping(state, "worktree_snapshot")
        if self.git.head() != parent or self.git.changed_snapshot() != snapshot:
            raise StateError("worktree changed before exact-candidate creation")
        local_ref, remote_ref, remote_branch = self._candidate_references(
            state, milestone, attempt
        )
        candidate_state = _state_mapping(state, "candidate")
        active = candidate_state.get("active")
        if not isinstance(active, dict) or active.get("attempt") != attempt:
            record: dict[str, object] = {
                "attempt": attempt,
                "check_polls": 0,
                "commit_identity": self._new_candidate_commit_identity(),
                "create_invocation": 0,
                "create_status": "not_started",
                "dispatch_baseline_ids": [],
                "dispatch_status": "not_started",
                "dispatch_token": uuid.uuid4().hex,
                "local_ref": local_ref,
                "parent": parent,
                "remote_branch": remote_branch,
                "remote_ref": remote_ref,
                "run_id": None,
                "run_url": None,
                "sha": None,
                "status": "creating",
                "tree": None,
                "upload_ref": f"{remote_ref}-upload",
                "upload_invocation": 0,
                "upload_status": "not_started",
            }
            self._store_candidate(state, record)
            state["hosted_evidence"] = None
        else:
            record = cast("dict[str, object]", dict(active))
        if state.get("current_phase") != "candidate_running":
            self._begin_transition_metadata_guard(state, "candidate_creation")
            self._save(state, "candidate_running")
        else:
            self._assert_transition_metadata_guard(state, "candidate_creation")
        tree = self._candidate_tree(
            state,
            milestone,
            attempt,
            parent,
            snapshot,
        )
        sha = self._local_ref_sha(local_ref)
        if sha is None:
            title, trailers = self._commit_message(
                milestone, cast("str", state["run_id"])
            )
            created = self.git.run(
                ("commit-tree", tree, "-p", parent, "-m", title, "-m", trailers),
                log_base=self._run_directory(state)
                / "logs"
                / f"{milestone.identifier}-candidate-{attempt}-commit-tree",
                env_overrides=self._candidate_commit_environment(state),
            )
            if not created.succeeded:
                raise StateError("unable to create the exact candidate commit")
            sha = created.stdout.strip().lower()
            if re.fullmatch(r"[0-9a-f]{40,64}", sha) is None:
                raise StateError("Git returned an invalid exact-candidate commit")
            updated = self.git.run(("update-ref", local_ref, sha, "0" * len(sha)))
            if not updated.succeeded:
                raise StateError("unable to create the immutable local candidate ref")
        self._validate_candidate_commit(state, milestone, sha, parent, tree)
        self.git.assert_object_database_integrity()
        self._assert_transition_metadata_guard(state, "candidate_creation")
        record.update({"sha": sha, "status": "created", "tree": tree})
        self._store_candidate(state, record)
        self._clear_transition_metadata_guard(state)
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = None
        self._save(state, "candidate_publication_pending")
        self._write(f"Created immutable {milestone.identifier} candidate {sha}.")

    def _candidate_publication_failure(
        self,
        state: dict[str, object],
        message: str,
    ) -> NoReturn:
        transition_kind = state.get("transition_git_metadata_kind")
        if isinstance(transition_kind, str):
            self._assert_transition_metadata_guard(state, transition_kind)
            self._clear_transition_metadata_guard(state)
            if transition_kind == "candidate_publication":
                record = self._active_candidate(state)
                record["status"] = "publication_failed"
                if record.get("upload_status") == "attempting":
                    record["upload_status"] = "indeterminate"
                self._store_candidate(state, record)
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = message
        self._save(state)
        raise PublicationError(message)

    def _invalidate_candidate(
        self,
        state: dict[str, object],
        message: str,
    ) -> NoReturn:
        """Permanently stop on a contradictory immutable-ref or dispatch identity."""
        transition_kind = state.get("transition_git_metadata_kind")
        if isinstance(transition_kind, str):
            self._assert_transition_metadata_guard(state, transition_kind)
            self._clear_transition_metadata_guard(state)
        record = self._active_candidate(state)
        record["create_status"] = "invalidated"
        record["upload_status"] = "invalidated"
        record["invalid_reason"] = message
        record["status"] = "invalidated"
        self._store_candidate(state, record)
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = message
        self._save(state, "blocked")
        raise StateError(message)

    def _read_command_evidence(
        self,
        log_base: Path,
        command: Sequence[str],
    ) -> tuple[bool, CommandResult | None]:
        """Read one durable process-start marker and optional completed result."""
        started_path, result_path, stdout_path, stderr_path = _command_evidence_paths(
            log_base
        )
        expected_command = _command_sha256(command)

        started = False
        if started_path.exists():
            if (
                started_path.is_symlink()
                or started_path.stat().st_size > MAX_RESULT_BYTES
            ):
                raise StateError("candidate command start evidence is unsafe")
            try:
                started_raw = cast(
                    "object",
                    json.loads(
                        started_path.read_text(encoding="utf-8"),
                        object_pairs_hook=_reject_duplicate_json_keys,
                    ),
                )
                started_document = _mapping(
                    started_raw, "candidate command start evidence"
                )
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
                _DuplicateJSONKeyError,
                InvalidInputError,
            ) as error:
                raise StateError(
                    "candidate command start evidence is malformed"
                ) from error
            if (
                set(started_document) != {"command_sha256", "schema_version"}
                or started_document.get("schema_version") != 1
                or started_document.get("command_sha256") != expected_command
            ):
                raise StateError("candidate command start evidence is contradictory")
            started = True

        if not result_path.exists():
            return started, None
        evidence_paths = (result_path, stdout_path, stderr_path)
        if any(
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > MAX_RESULT_BYTES
            for path in evidence_paths
        ):
            raise StateError("candidate command result evidence is unsafe")
        try:
            result_raw = cast(
                "object",
                json.loads(
                    result_path.read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                ),
            )
            result_document = _mapping(result_raw, "candidate command result evidence")
            stdout = stdout_path.read_text(encoding="utf-8")
            stderr = stderr_path.read_text(encoding="utf-8")
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
            InvalidInputError,
        ) as error:
            raise StateError(
                "candidate command result evidence is malformed"
            ) from error
        expected_keys = {
            "command_sha256",
            "interrupted",
            "returncode",
            "schema_version",
            "stderr_sha256",
            "stdout_sha256",
            "timed_out",
        }
        returncode = result_document.get("returncode")
        timed_out = result_document.get("timed_out")
        interrupted = result_document.get("interrupted")
        if (
            set(result_document) != expected_keys
            or result_document.get("schema_version") != 1
            or result_document.get("command_sha256") != expected_command
            or type(returncode) is not int
            or not isinstance(timed_out, bool)
            or not isinstance(interrupted, bool)
            or result_document.get("stdout_sha256") != sha256_text(stdout)
            or result_document.get("stderr_sha256") != sha256_text(stderr)
        ):
            raise StateError("candidate command result evidence is contradictory")
        return started, CommandResult(
            command=tuple(command),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=0.0,
            timed_out=timed_out,
            interrupted=interrupted,
        )

    @staticmethod
    def _included_http_response(result: CommandResult) -> tuple[int | None, str]:
        """Split gh --include output into its final HTTP status and JSON body."""
        remainder = result.stdout
        status: int | None = None
        while remainder.startswith("HTTP/"):
            separator = "\r\n\r\n" if "\r\n\r\n" in remainder else "\n\n"
            header, found, body = remainder.partition(separator)
            if not found:
                return None, result.stdout
            first_line = header.splitlines()[0] if header.splitlines() else ""
            matched = re.fullmatch(r"HTTP/\S+\s+([0-9]{3})(?:\s+.*)?", first_line)
            if matched is None:
                return None, result.stdout
            status = int(matched.group(1))
            remainder = body
        return status, remainder

    def _candidate_create_outcome(
        self,
        result: CommandResult,
        remote_ref: str,
        sha: str,
    ) -> str:
        """Classify one completed create-ref process from included HTTP evidence."""
        status, body = self._included_http_response(result)
        if status is not None and 400 <= status < 500:
            return "definite_rejection"
        if status is not None and status != 201 and status < 500:
            return "definite_rejection"
        if status is None:
            return "contradictory" if result.succeeded else "indeterminate"
        if status >= 500 or result.timed_out or result.interrupted:
            return "indeterminate"
        if not result.succeeded or result.signal_number is not None:
            return "contradictory"
        try:
            document = _mapping(
                cast(
                    "object",
                    json.loads(body, object_pairs_hook=_reject_duplicate_json_keys),
                ),
                "GitHub candidate-ref response",
            )
            git_object = _mapping(
                document.get("object"), "GitHub candidate-ref response object"
            )
        except (
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
            InvalidInputError,
        ):
            return "contradictory"
        if (
            document.get("ref") != remote_ref
            or git_object.get("sha") != sha
            or git_object.get("type") != "commit"
        ):
            return "contradictory"
        return "created"

    @staticmethod
    def _candidate_upload_outcome(
        result: CommandResult,
        upload_ref: str,
        sha: str,
    ) -> str:
        """Classify an expected-absent porcelain push without trusting a no-op."""
        if result.timed_out or result.interrupted or result.signal_number is not None:
            return "indeterminate"
        output = f"{result.stdout}\n{result.stderr}".lower()
        rejected = any(
            marker in output
            for marker in (
                "[rejected]",
                "already exists",
                "non-fast-forward",
                "stale info",
            )
        )
        if not result.succeeded:
            return "definite_rejection" if rejected else "indeterminate"
        status_lines = [
            line.split("\t") for line in result.stdout.splitlines() if "\t" in line
        ]
        if len(status_lines) != 1:
            return "contradictory"
        fields = status_lines[0]
        if len(fields) != 3 or fields[1] != f"{sha}:{upload_ref}":
            return "contradictory"
        flag = fields[0].strip()
        summary = fields[2].lower()
        if flag == "*" and ("[new branch]" in summary or "[new reference]" in summary):
            return "created"
        return "definite_rejection"

    def _remote_ref_sha(self, state: dict[str, object], reference: str) -> str | None:
        result = self.git.run(
            ("ls-remote", self._remote_transport_url(state, push=False), reference),
            timeout_seconds=self.config.default_timeout_seconds,
        )
        if not result.succeeded:
            self._candidate_publication_failure(
                state,
                result.stderr.strip() or "unable to inspect the remote candidate ref",
            )
        output = result.stdout.strip()
        if not output:
            return None
        lines = output.splitlines()
        if len(lines) != 1 or "\t" not in lines[0]:
            self._candidate_publication_failure(
                state, "remote returned an ambiguous candidate reference"
            )
        sha, returned_ref = lines[0].split("\t", maxsplit=1)
        if (
            returned_ref != reference
            or re.fullmatch(r"[0-9a-fA-F]{40,64}", sha) is None
        ):
            self._candidate_publication_failure(
                state, "remote returned an invalid candidate commit"
            )
        return sha.lower()

    def _assert_remote_candidate(
        self,
        state: dict[str, object],
        record: Mapping[str, object],
        boundary: str,
    ) -> None:
        sha = _string(record.get("sha"), "candidate.sha").lower()
        remote_ref = _string(record.get("remote_ref"), "candidate.remote_ref")
        if self._remote_ref_sha(state, remote_ref) != sha:
            self._invalidate_candidate(
                state, f"immutable candidate ref changed before {boundary}"
            )

    @staticmethod
    def _candidate_invocation(record: Mapping[str, object], key: str) -> int:
        value = record.get(key)
        if type(value) is not int or value < 0:
            raise StateError(f"candidate {key} is malformed")
        return value

    def _candidate_upload_spec(
        self,
        state: Mapping[str, object],
        record: Mapping[str, object],
    ) -> tuple[tuple[str, ...], tuple[str, ...], Path]:
        sha = _string(record.get("sha"), "candidate.sha").lower()
        upload_ref = _string(record.get("upload_ref"), "candidate.upload_ref")
        arguments = (
            "push",
            "--porcelain",
            "--no-follow-tags",
            "--recurse-submodules=no",
            f"--force-with-lease={upload_ref}:",
            self._remote_transport_url(state, push=True),
            f"{sha}:{upload_ref}",
        )
        invocation = self._candidate_invocation(record, "upload_invocation")
        log_base = (
            self._run_directory(state)
            / "logs"
            / f"{state['current_milestone']}-candidate-{record['attempt']}-upload-{invocation}"
        )
        return arguments, (*self.git.command, *arguments), log_base

    def _candidate_create_spec(
        self,
        state: Mapping[str, object],
        record: Mapping[str, object],
    ) -> tuple[tuple[str, ...], tuple[str, ...], Path]:
        repository = _state_github_repository(state)
        remote_ref = _string(record.get("remote_ref"), "candidate.remote_ref")
        sha = _string(record.get("sha"), "candidate.sha").lower()
        arguments = (
            "--method",
            "POST",
            f"repos/{repository.name_with_owner}/git/refs",
            "--include",
            "--raw-field",
            f"ref={remote_ref}",
            "--raw-field",
            f"sha={sha}",
        )
        invocation = self._candidate_invocation(record, "create_invocation")
        command = (
            *self.config.tools["gh"],
            "api",
            "--hostname",
            repository.host,
            *arguments,
        )
        log_base = (
            self._run_directory(state)
            / "logs"
            / f"{state['current_milestone']}-candidate-{record['attempt']}-create-ref-{invocation}"
        )
        return arguments, command, log_base

    def _publish_candidate(self, state: dict[str, object]) -> None:
        """Upload one commit object, then atomically create its final evidence ref."""
        unconfirmed_metadata = state.pop(
            "_unconfirmed_candidate_push_metadata_change", False
        )
        record = self._active_candidate(state)
        sha = _string(record.get("sha"), "candidate.sha").lower()
        remote_ref = _string(record.get("remote_ref"), "candidate.remote_ref")
        upload_ref = _string(record.get("upload_ref"), "candidate.upload_ref")
        if upload_ref != f"{remote_ref}-upload":
            raise StateError("candidate upload ref contradicts its immutable ref")
        create_status = _string(record.get("create_status"), "candidate.create_status")
        upload_status = _string(record.get("upload_status"), "candidate.upload_status")
        if create_status not in {
            "not_started",
            "api_attempting",
            "indeterminate",
            "confirmed",
        }:
            raise StateError("candidate create status is not resumable")
        if upload_status not in {
            "not_started",
            "attempting",
            "indeterminate",
            "confirmed",
        }:
            raise StateError("candidate upload status is not resumable")

        upload_arguments, upload_command, upload_log_base = self._candidate_upload_spec(
            state, record
        )
        upload_remote = self._remote_ref_sha(state, upload_ref)
        if upload_status == "not_started" and upload_remote is not None:
            self._invalidate_candidate(
                state, "candidate object-upload ref existed before its lease attempt"
            )
        if upload_remote is not None and upload_remote != sha:
            self._invalidate_candidate(
                state, "candidate object-upload ref points to a different commit"
            )
        if upload_status == "confirmed" and upload_remote != sha:
            self._invalidate_candidate(
                state, "confirmed candidate object-upload ref moved or vanished"
            )
        if upload_status in {"attempting", "indeterminate"}:
            started, durable_upload = self._read_command_evidence(
                upload_log_base, upload_command
            )
            if upload_remote == sha:
                if not started:
                    self._invalidate_candidate(
                        state,
                        "exact candidate object-upload ref appeared without a parent push",
                    )
                if durable_upload is None:
                    self._invalidate_candidate(
                        state,
                        "exact candidate object-upload ref appeared without a durable "
                        "completed parent push result",
                    )
                upload_outcome = self._candidate_upload_outcome(
                    durable_upload, upload_ref, sha
                )
                if upload_outcome != "created":
                    self._invalidate_candidate(
                        state,
                        "candidate object-upload ref appeared without strict new-ref "
                        "porcelain ownership evidence",
                    )
                record["upload_status"] = "confirmed"
                self._store_candidate(state, record)
                upload_status = "confirmed"
            elif not started and durable_upload is not None:
                self._invalidate_candidate(
                    state,
                    "candidate object-upload command returned without a process-start marker",
                )
            elif not started:
                record["upload_status"] = "not_started"
                self._store_candidate(state, record)
                upload_status = "not_started"
            elif durable_upload is None:
                self._candidate_publication_failure(
                    state,
                    "candidate object-upload process started without a completed result; "
                    "it will not be retried automatically",
                )
            else:
                upload_outcome = self._candidate_upload_outcome(
                    durable_upload, upload_ref, sha
                )
                if upload_outcome == "created":
                    self._invalidate_candidate(
                        state,
                        "created candidate object-upload ref moved or vanished",
                    )
                if upload_outcome in {"definite_rejection", "contradictory"}:
                    self._invalidate_candidate(
                        state,
                        "candidate object-upload ref update was definitely rejected",
                    )
                record["upload_invocation"] = (
                    self._candidate_invocation(record, "upload_invocation") + 1
                )
                record["upload_status"] = "not_started"
                record["status"] = "publication_failed"
                self._store_candidate(state, record)
                self._candidate_publication_failure(
                    state,
                    durable_upload.stderr.strip()
                    or "candidate object upload failed without creating its ref",
                )
        if unconfirmed_metadata is True and upload_remote != sha:
            raise StateError(
                "Git metadata changed during an unconfirmed candidate object upload, "
                "but the remote does not contain the exact object-upload ref"
            )
        if upload_status == "not_started":
            record["status"] = "uploading_object"
            record["upload_status"] = "attempting"
            self._store_candidate(state, record)
            if state.get("transition_git_metadata_kind") is None:
                self._begin_transition_metadata_guard(state, "candidate_publication")
            else:
                self._assert_transition_metadata_guard(state, "candidate_publication")
            self._save(state, "candidate_publication_pending")
            pushed = self.git.run(
                upload_arguments,
                timeout_seconds=self.config.default_timeout_seconds,
                log_base=upload_log_base,
            )
            self._assert_transition_metadata_guard(state, "candidate_publication")
            started, durable_upload = self._read_command_evidence(
                upload_log_base, upload_command
            )
            if not started or durable_upload is None:
                self._invalidate_candidate(
                    state,
                    "candidate object-upload command lacks durable process evidence",
                )
            upload_outcome = self._candidate_upload_outcome(
                durable_upload, upload_ref, sha
            )
            if upload_outcome in {"definite_rejection", "contradictory"}:
                self._invalidate_candidate(
                    state,
                    "candidate object-upload ref update was definitely rejected",
                )
            if upload_outcome != "created":
                upload_remote = self._remote_ref_sha(state, upload_ref)
                if upload_remote is not None and upload_remote != sha:
                    self._invalidate_candidate(
                        state,
                        "candidate object-upload ref appeared with another commit",
                    )
                if upload_remote == sha:
                    self._invalidate_candidate(
                        state,
                        "candidate object-upload ref appeared after an indeterminate "
                        "or unsuccessful parent push",
                    )
                record["upload_invocation"] = (
                    self._candidate_invocation(record, "upload_invocation") + 1
                )
                record["upload_status"] = "not_started"
                record["status"] = "publication_failed"
                self._store_candidate(state, record)
                message = pushed.stderr.strip() or "candidate object upload failed"
                self._candidate_publication_failure(state, message)
            else:
                upload_remote = self._remote_ref_sha(state, upload_ref)
                if upload_remote != sha:
                    self._invalidate_candidate(
                        state, "remote did not retain the exact candidate object upload"
                    )
                record["upload_status"] = "confirmed"
                self._store_candidate(state, record)

        if state.get("transition_git_metadata_kind") is not None:
            self._assert_transition_metadata_guard(state, "candidate_publication")
            self._clear_transition_metadata_guard(state)
        state["git_metadata_digest"] = self.git.metadata_digest()
        self._store_candidate(state, record)
        self._save(state, "candidate_publication_pending")

        create_status = _string(record.get("create_status"), "candidate.create_status")
        final_remote = self._remote_ref_sha(state, remote_ref)
        create_arguments, create_command, create_log_base = self._candidate_create_spec(
            state, record
        )
        if create_status == "not_started" and final_remote is not None:
            self._invalidate_candidate(
                state,
                "immutable candidate ref existed before its create-only attempt",
            )
        if final_remote is not None and final_remote != sha:
            self._invalidate_candidate(
                state, "immutable remote candidate ref points to a different commit"
            )
        if create_status == "confirmed" and final_remote != sha:
            self._invalidate_candidate(
                state, "confirmed immutable candidate ref moved or vanished"
            )
        if create_status in {"api_attempting", "indeterminate"}:
            started, durable_create = self._read_command_evidence(
                create_log_base, create_command
            )
            if final_remote == sha:
                if not started:
                    self._invalidate_candidate(
                        state,
                        "exact candidate ref appeared without a parent API invocation",
                    )
                if durable_create is not None:
                    outcome = self._candidate_create_outcome(
                        durable_create, remote_ref, sha
                    )
                    if outcome in {"definite_rejection", "contradictory"}:
                        self._invalidate_candidate(
                            state,
                            "atomic candidate-ref creation returned definite or "
                            "contradictory evidence",
                        )
                record["create_status"] = "confirmed"
                self._store_candidate(state, record)
                create_status = "confirmed"
            elif not started and durable_create is not None:
                self._invalidate_candidate(
                    state,
                    "candidate create-ref command returned without a process-start marker",
                )
            elif not started:
                record["create_status"] = "not_started"
                self._store_candidate(state, record)
                create_status = "not_started"
            elif durable_create is None:
                self._candidate_publication_failure(
                    state,
                    "candidate create-ref process started without a completed result; "
                    "it will not be retried automatically",
                )
            else:
                outcome = self._candidate_create_outcome(
                    durable_create, remote_ref, sha
                )
                if outcome in {"definite_rejection", "contradictory"}:
                    self._invalidate_candidate(
                        state,
                        "atomic candidate-ref creation returned definite or "
                        "contradictory evidence",
                    )
                if outcome == "created":
                    self._invalidate_candidate(
                        state,
                        "created immutable candidate ref moved or vanished",
                    )
                record["create_invocation"] = (
                    self._candidate_invocation(record, "create_invocation") + 1
                )
                record["create_status"] = "not_started"
                record["status"] = "publication_failed"
                self._store_candidate(state, record)
                self._candidate_publication_failure(
                    state,
                    durable_create.stderr.strip()
                    or "atomic candidate-ref creation was indeterminate and created no ref",
                )
        if create_status != "confirmed":
            record["status"] = "creating_remote_ref"
            record["create_status"] = "api_attempting"
            self._store_candidate(state, record)
            self._save(state, "candidate_publication_pending")
            created = self._gh_api_run(
                create_arguments,
                state,
                create_log_base.name,
            )
            started, durable_create = self._read_command_evidence(
                create_log_base, create_command
            )
            if not started or durable_create is None:
                self._invalidate_candidate(
                    state, "candidate create-ref command lacks durable process evidence"
                )
            outcome = self._candidate_create_outcome(durable_create, remote_ref, sha)
            if outcome in {"definite_rejection", "contradictory"}:
                self._invalidate_candidate(
                    state,
                    "atomic candidate-ref creation was definitely rejected or "
                    "returned contradictory evidence",
                )
            final_remote = self._remote_ref_sha(state, remote_ref)
            if outcome == "indeterminate":
                record["create_status"] = "indeterminate"
                record["status"] = "publication_indeterminate"
                self._store_candidate(state, record)
                if final_remote != sha:
                    if final_remote is not None:
                        self._invalidate_candidate(
                            state,
                            "immutable candidate ref appeared during atomic creation",
                        )
                    record["create_invocation"] = (
                        self._candidate_invocation(record, "create_invocation") + 1
                    )
                    record["create_status"] = "not_started"
                    self._store_candidate(state, record)
                    self._candidate_publication_failure(
                        state,
                        created.stderr.strip()
                        or "atomic candidate-ref creation was indeterminate",
                    )
            if final_remote != sha:
                if final_remote is not None:
                    self._invalidate_candidate(
                        state,
                        "immutable candidate ref changed after atomic creation",
                    )
                self._candidate_publication_failure(
                    state, "remote did not retain the atomic candidate ref"
                )
            record["create_status"] = "confirmed"
        record["status"] = "published"
        self._store_candidate(state, record)
        publication = _state_mapping(state, "publication")
        publication["status"] = "candidate_published"
        state["publication"] = publication
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = None
        self._save(state, "candidate_dispatch_pending")
        self._write(f"Published immutable candidate ref {remote_ref}.")

    def _candidate_runs(
        self,
        state: dict[str, object],
        policy: HostedVerification,
        record: Mapping[str, object],
    ) -> list[dict[str, object]]:
        sha = _string(record.get("sha"), "candidate.sha").lower()
        branch = _string(record.get("remote_branch"), "candidate.remote_branch")
        listed = self._gh_run(
            (
                "run",
                "list",
                "--workflow",
                policy.workflow,
                "--branch",
                branch,
                "--commit",
                sha,
                "--event",
                "workflow_dispatch",
                "--limit",
                str(WORKFLOW_RUN_LIST_LIMIT),
                "--json",
                "databaseId,displayTitle,headSha,status,conclusion,url,createdAt,workflowName,event",
            ),
            state,
            f"{state['current_milestone']}-candidate-run-list",
        )
        if not listed.succeeded:
            self._candidate_publication_failure(
                state, listed.stderr.strip() or "unable to discover candidate CI run"
            )
        try:
            loaded = cast(
                "object",
                json.loads(
                    listed.stdout or "[]",
                    object_pairs_hook=_reject_duplicate_json_keys,
                ),
            )
        except (json.JSONDecodeError, _DuplicateJSONKeyError):
            self._candidate_publication_failure(
                state, "GitHub returned malformed candidate run data"
            )
        if not isinstance(loaded, list):
            self._candidate_publication_failure(
                state, "GitHub returned invalid candidate run data"
            )
        if len(loaded) >= WORKFLOW_RUN_LIST_LIMIT:
            self._candidate_publication_failure(
                state,
                "candidate workflow-run enumeration may be truncated; uniqueness "
                "cannot be established",
            )
        runs: list[dict[str, object]] = []
        for index, item in enumerate(loaded):
            try:
                candidate = _mapping(item, f"candidate runs[{index}]")
            except InvalidInputError:
                self._candidate_publication_failure(
                    state, "GitHub returned malformed candidate run data"
                )
            run_id = candidate.get("databaseId")
            url = candidate.get("url")
            if (
                type(run_id) is not int
                or run_id <= 0
                or not isinstance(url, str)
                or not _github_repository_url(
                    url, _state_github_repository(state), area="actions"
                )
                or not isinstance(candidate.get("displayTitle"), str)
            ):
                self._candidate_publication_failure(
                    state, "GitHub returned unsafe candidate run identity"
                )
            if (
                candidate.get("headSha") == sha
                and candidate.get("event") == "workflow_dispatch"
                and candidate.get("workflowName") == policy.workflow
            ):
                runs.append(candidate)
        return sorted(runs, key=lambda item: cast("int", item["databaseId"]))

    @staticmethod
    def _expected_dispatch_title(record: Mapping[str, object]) -> str:
        return _AUTOPILOT_DISPATCH_TITLE + _string(
            record.get("dispatch_token"), "candidate.dispatch_token"
        )

    def _new_attributed_runs(
        self,
        runs: Sequence[Mapping[str, object]],
        record: Mapping[str, object],
    ) -> list[dict[str, object]]:
        baseline_raw = record.get("dispatch_baseline_ids")
        if not isinstance(baseline_raw, list) or not all(
            type(item) is int and item > 0 for item in baseline_raw
        ):
            raise StateError("candidate dispatch baseline is malformed")
        baseline = set(cast("list[int]", baseline_raw))
        expected_title = self._expected_dispatch_title(record)
        return [
            dict(candidate)
            for candidate in runs
            if cast("int", candidate["databaseId"]) not in baseline
            and candidate.get("displayTitle") == expected_title
        ]

    def _assert_unique_attributed_run(
        self,
        state: dict[str, object],
        policy: HostedVerification,
        record: Mapping[str, object],
        boundary: str,
    ) -> None:
        attributed = self._new_attributed_runs(
            self._candidate_runs(state, policy, record), record
        )
        if len(attributed) != 1 or attributed[0].get("databaseId") != record.get(
            "run_id"
        ):
            self._invalidate_candidate(
                state,
                f"candidate dispatch identity became ambiguous before {boundary}",
            )

    def _dispatch_candidate_workflow(self, state: dict[str, object]) -> None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        policy = self._hosted_policy(milestone)
        record = self._active_candidate(state)
        self._assert_remote_candidate(state, record, "workflow dispatch")
        dispatch_status = _string(
            record.get("dispatch_status"), "candidate.dispatch_status"
        )
        if state.get("current_phase") == "candidate_dispatch_pending":
            if dispatch_status != "not_started":
                raise StateError("candidate dispatch state is contradictory")
            baseline_runs = self._candidate_runs(state, policy, record)
            baseline_ids = [
                cast("int", candidate["databaseId"]) for candidate in baseline_runs
            ]
            record.update(
                {
                    "dispatch_baseline_ids": baseline_ids,
                    "dispatch_status": "prepared",
                    "status": "dispatch_prepared",
                }
            )
            self._store_candidate(state, record)
            self._save(state, "candidate_dispatch_running")
            dispatch_token = _string(
                record.get("dispatch_token"), "candidate.dispatch_token"
            )
            dispatched = self._gh_run(
                (
                    "workflow",
                    "run",
                    policy.workflow,
                    "--ref",
                    _string(record.get("remote_branch"), "candidate.remote_branch"),
                    "--field",
                    f"{policy.dispatch_input}={dispatch_token}",
                ),
                state,
                f"{milestone.identifier}-candidate-dispatch",
            )
            if not dispatched.succeeded:
                record["dispatch_status"] = "indeterminate"
                record["status"] = "dispatch_indeterminate"
                self._store_candidate(state, record)
                self._candidate_publication_failure(
                    state,
                    dispatched.stderr.strip()
                    or "candidate workflow dispatch result is indeterminate",
                )
            record["dispatch_status"] = "sent"
            record["status"] = "dispatch_sent"
            self._store_candidate(state, record)
            self._save(state, "candidate_dispatch_running")
        elif dispatch_status not in {"prepared", "sent", "indeterminate"}:
            raise StateError("candidate dispatch resume state is contradictory")
        deadline = time.monotonic() + min(60.0, policy.timeout_seconds)
        new_runs: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            runs = self._candidate_runs(state, policy, record)
            new_runs = self._new_attributed_runs(runs, record)
            if new_runs:
                time.sleep(policy.poll_interval_seconds)
                confirmed = self._candidate_runs(state, policy, record)
                new_runs = self._new_attributed_runs(confirmed, record)
                break
            time.sleep(policy.poll_interval_seconds)
        if not new_runs:
            record["dispatch_status"] = "indeterminate"
            record["status"] = "dispatch_indeterminate"
            self._store_candidate(state, record)
            self._candidate_publication_failure(
                state,
                "candidate workflow dispatch is indeterminate; the controller will "
                "not redispatch automatically",
            )
        if len(new_runs) != 1:
            self._invalidate_candidate(
                state, "candidate workflow dispatch produced ambiguous runs"
            )
        selected = new_runs[0]
        record.update(
            {
                "dispatch_status": "discovered",
                "run_id": selected["databaseId"],
                "run_url": selected["url"],
                "status": "dispatched",
            }
        )
        self._store_candidate(state, record)
        state["last_error"] = None
        self._save(state, "candidate_checks_pending")
        self._write(
            f"Dispatched {policy.workflow} for exact candidate {record['sha']}."
        )

    def _candidate_run_evidence(
        self,
        state: dict[str, object],
        policy: HostedVerification,
        record: Mapping[str, object],
    ) -> dict[str, object]:
        run_id = record.get("run_id")
        if type(run_id) is not int or run_id <= 0:
            raise StateError("candidate has no valid hosted run ID")
        poll = record.get("check_polls", 0)
        if type(poll) is not int or poll < 0:
            raise StateError("candidate hosted poll count is malformed")
        viewed = self._gh_run(
            (
                "run",
                "view",
                str(run_id),
                "--json",
                "databaseId,displayTitle,headSha,status,conclusion,url,jobs,workflowName,event",
            ),
            state,
            f"{state['current_milestone']}-candidate-run-view-{poll}",
        )
        if not viewed.succeeded:
            self._candidate_publication_failure(
                state, viewed.stderr.strip() or "unable to inspect candidate CI run"
            )
        try:
            document = _mapping(
                cast(
                    "object",
                    json.loads(
                        viewed.stdout,
                        object_pairs_hook=_reject_duplicate_json_keys,
                    ),
                ),
                "candidate run evidence",
            )
        except (
            json.JSONDecodeError,
            _DuplicateJSONKeyError,
            InvalidInputError,
        ):
            self._candidate_publication_failure(
                state, "GitHub returned malformed run evidence"
            )
        url = document.get("url")
        if not isinstance(url, str) or not _github_repository_url(
            url, _state_github_repository(state), area="actions"
        ):
            self._candidate_publication_failure(
                state, "GitHub returned an unsafe candidate run URL"
            )
        jobs_raw = document.get("jobs")
        if not isinstance(jobs_raw, list):
            self._candidate_publication_failure(
                state, "GitHub candidate run omitted job evidence"
            )
        jobs: list[dict[str, object]] = []
        names: set[str] = set()
        expected_run_id = run_id
        for index, raw_job in enumerate(jobs_raw):
            try:
                job = _mapping(raw_job, f"candidate jobs[{index}]")
                name = _string(job.get("name"), f"candidate jobs[{index}].name")
            except InvalidInputError:
                self._candidate_publication_failure(
                    state, "GitHub returned malformed candidate job evidence"
                )
            if name in names:
                self._candidate_publication_failure(
                    state, "GitHub candidate run repeated a job name"
                )
            names.add(name)
            job_url = job.get("url")
            job_id = job.get("databaseId")
            if (
                isinstance(job_id, bool)
                or not isinstance(job_id, int)
                or job_id <= 0
                or not isinstance(job_url, str)
                or not _github_actions_job_url(
                    job_url,
                    _state_github_repository(state),
                    run_id=expected_run_id,
                    job_id=job_id,
                )
            ):
                self._candidate_publication_failure(
                    state, "GitHub returned contradictory candidate job identity"
                )
            jobs.append(
                {
                    "conclusion": job.get("conclusion"),
                    "database_id": job_id,
                    "name": name,
                    "status": job.get("status"),
                    "url": job_url,
                }
            )
        return {
            "candidate_ref": record.get("remote_ref"),
            "candidate_sha": document.get("headSha"),
            "conclusion": document.get("conclusion"),
            "dispatch_title": document.get("displayTitle"),
            "event": document.get("event"),
            "jobs": jobs,
            "required_jobs": list(policy.required_jobs),
            "run_id": document.get("databaseId"),
            "status": document.get("status"),
            "url": url,
            "workflow": document.get("workflowName"),
        }

    def _collect_hosted_failure_logs(
        self,
        state: dict[str, object],
        evidence: Mapping[str, object],
        job_names: Sequence[str],
    ) -> dict[str, object]:
        """Persist complete redacted logs before a network-restricted repair."""
        run_id = evidence.get("run_id")
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
            raise StateError("hosted failure evidence has no valid run ID")
        jobs_raw = evidence.get("jobs")
        if not isinstance(jobs_raw, list):
            raise StateError("hosted failure evidence has no job list")
        jobs: dict[str, dict[str, object]] = {}
        for index, raw_job in enumerate(jobs_raw):
            if not isinstance(raw_job, dict):
                raise StateError(f"hosted failure evidence job {index} is malformed")
            job = cast("dict[str, object]", raw_job)
            name = job.get("name")
            if not isinstance(name, str) or not name:
                raise StateError("hosted failure evidence has an unnamed job")
            jobs[name] = job

        attempt = self._active_candidate(state).get("attempt")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            raise StateError("candidate attempt is malformed")
        milestone = cast("str", state["current_milestone"])
        run_directory = self._run_directory(state)
        records: list[dict[str, object]] = []
        for name in job_names:
            selected_job = jobs.get(name)
            if selected_job is None:
                raise StateError("hosted failure log job is absent from evidence")
            job_id = selected_job.get("database_id")
            if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
                raise StateError("hosted failure log job ID is malformed")
            log_name = f"{milestone}-candidate-{attempt}-hosted-job-{job_id}"
            result = self._gh_run(
                (
                    "run",
                    "view",
                    str(run_id),
                    "--job",
                    str(job_id),
                    "--log",
                ),
                state,
                log_name,
            )
            retrieval = "gh-run-view"
            selected_log_name = log_name
            if not result.succeeded or not result.stdout.strip():
                repository = _state_github_repository(state)
                api_log_name = f"{log_name}-api"
                endpoint = (
                    f"repos/{repository.name_with_owner}/actions/jobs/{job_id}/logs"
                )
                api_result = self._gh_api_run(
                    (endpoint,),
                    state,
                    api_log_name,
                )
                if not api_result.succeeded or not api_result.stdout.strip():
                    detail = api_result.stderr.strip() or result.stderr.strip()
                    if not detail:
                        detail = (
                            "GitHub returned an empty hosted failure log from both "
                            "the run-view and repository API interfaces"
                        )
                    self._candidate_publication_failure(state, detail)
                result = api_result
                retrieval = "github-api"
                selected_log_name = api_log_name
            log_base = run_directory / "logs" / selected_log_name
            started_path, result_path, stdout_path, stderr_path = (
                _command_evidence_paths(log_base)
            )

            def relative(path: Path) -> str:
                return PurePosixPath(
                    path.relative_to(self.repo_root).as_posix()
                ).as_posix()

            records.append(
                {
                    "database_id": job_id,
                    "job": name,
                    "retrieval": retrieval,
                    "result_log": relative(result_path),
                    "started_log": relative(started_path),
                    "stderr_log": relative(stderr_path),
                    "stderr_sha256": sha256_text(result.stderr),
                    "stdout_log": relative(stdout_path),
                    "stdout_sha256": sha256_text(result.stdout),
                }
            )
        updated = dict(evidence)
        updated["failure_logs"] = records
        state["hosted_evidence"] = updated
        self._save(state, "candidate_checks_running")
        return updated

    def _hosted_candidate_failure(
        self,
        state: dict[str, object],
        evidence: Mapping[str, object],
        reason: str,
    ) -> None:
        state["hosted_evidence"] = dict(evidence)
        state["failed_output_path"] = self._write_failure_input(
            state,
            reason
            + (
                "\nComplete redacted failed-job logs are stored at the safe "
                "repository-relative paths in hosted evidence.failure_logs. "
                "Inspect every listed stdout and stderr log before editing."
                if evidence.get("failure_logs")
                else ""
            )
            + "\nHosted evidence:\n"
            + json.dumps(
                _redact_structure(dict(evidence)),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
        )
        state["review_findings"] = []
        self._schedule_repair(state, reason)

    def _wait_for_candidate_checks(self, state: dict[str, object]) -> None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        policy = self._hosted_policy(milestone)
        record = self._active_candidate(state)
        timeout_override = state.get("timeout_override")
        timeout = (
            float(timeout_override)
            if isinstance(timeout_override, (int, float))
            and not isinstance(timeout_override, bool)
            else policy.timeout_seconds
        )
        deadline = time.monotonic() + timeout
        self._save(state, "candidate_checks_running")
        while True:
            self._assert_remote_candidate(state, record, "hosted evidence polling")
            evidence = self._candidate_run_evidence(state, policy, record)
            record["check_polls"] = cast("int", record.get("check_polls", 0)) + 1
            record["status"] = f"checks_{evidence.get('status')}"
            self._store_candidate(state, record)
            state["hosted_evidence"] = evidence
            self._save(state, "candidate_checks_running")
            expected_sha = _string(record.get("sha"), "candidate.sha").lower()
            if evidence.get("candidate_sha") != expected_sha:
                self._hosted_candidate_failure(
                    state,
                    evidence,
                    "hosted verification ran against a different candidate SHA",
                )
                return
            if (
                evidence.get("run_id") != record.get("run_id")
                or evidence.get("event") != "workflow_dispatch"
                or evidence.get("workflow") != policy.workflow
                or evidence.get("dispatch_title")
                != _AUTOPILOT_DISPATCH_TITLE
                + _string(record.get("dispatch_token"), "candidate.dispatch_token")
            ):
                self._hosted_candidate_failure(
                    state, evidence, "hosted verification identity is contradictory"
                )
                return
            if evidence.get("status") == "completed":
                self._assert_unique_attributed_run(
                    state, policy, record, "hosted evidence acceptance"
                )
                jobs = cast("list[dict[str, object]]", evidence["jobs"])
                by_name = {cast("str", job["name"]): job for job in jobs}
                missing = [name for name in policy.required_jobs if name not in by_name]
                unsuccessful = [
                    name
                    for name in policy.required_jobs
                    if name in by_name
                    and (
                        by_name[name].get("status") != "completed"
                        or by_name[name].get("conclusion") != "success"
                    )
                ]
                if evidence.get("conclusion") != "success" or missing or unsuccessful:
                    failed_job_names = [
                        cast("str", job["name"])
                        for job in jobs
                        if job.get("status") == "completed"
                        and job.get("conclusion") != "success"
                    ]
                    if failed_job_names:
                        evidence = self._collect_hosted_failure_logs(
                            state,
                            evidence,
                            failed_job_names,
                        )
                    details = []
                    if missing:
                        details.append("missing jobs: " + ", ".join(missing))
                    if unsuccessful:
                        details.append("unsuccessful jobs: " + ", ".join(unsuccessful))
                    self._hosted_candidate_failure(
                        state,
                        evidence,
                        "exact-candidate hosted verification failed"
                        + ("; " + "; ".join(details) if details else ""),
                    )
                    return
                self._assert_remote_candidate(
                    state, record, "hosted evidence acceptance"
                )
                record["status"] = "checks_passed"
                self._store_candidate(state, record)
                state["last_error"] = None
                self._save(state, "review_pending")
                self._write(
                    f"Hosted verification passed for exact candidate {expected_sha}."
                )
                return
            if time.monotonic() >= deadline:
                self._hosted_candidate_failure(
                    state,
                    evidence,
                    "exact-candidate hosted verification timed out",
                )
                return
            time.sleep(policy.poll_interval_seconds)

    def _commit_message(self, milestone: Milestone, run_id: str) -> tuple[str, str]:
        title = self.config.commit_template.format(
            milestone=milestone.identifier,
            title=milestone.title,
        )
        if "\n" in title or "\r" in title or "\0" in title:
            raise StateError("commit template produced an unsafe multi-line title")
        trailers = (
            f"PyAhead-Autopilot-Run: {run_id}\n"
            f"PyAhead-Milestone: {milestone.identifier}"
        )
        return title, trailers

    def _recover_candidate_attach_if_present(
        self,
        state: dict[str, object],
        current_head: str | None = None,
    ) -> bool:
        """Adopt the exact candidate once if branch attachment outlived state."""
        if state.get("current_phase") != "candidate_attach_running":
            return False
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        record = self._active_candidate(state)
        parent = _string(record.get("parent"), "candidate.parent")
        sha = _string(record.get("sha"), "candidate.sha").lower()
        tree = _string(record.get("tree"), "candidate.tree").lower()
        head = current_head or self.git.head()
        if head == parent:
            return False
        if head != sha:
            raise StateError("unexpected history movement during candidate attachment")
        policy = self._hosted_policy(milestone)
        self._assert_remote_candidate(state, record, "attachment recovery")
        self._assert_unique_attributed_run(state, policy, record, "attachment recovery")
        self._validate_candidate_commit(state, milestone, sha, parent, tree)
        if self.git.changed_snapshot() or self.git.staged_paths():
            raise StateError(
                "attached candidate did not leave a clean worktree and index"
            )
        record["status"] = "attached"
        self._store_candidate(state, record)
        self._record_completed_commit(state, milestone, sha)
        state["expected_head"] = sha
        state["worktree_snapshot"] = {}
        self._clear_transition_metadata_guard(state)
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = None
        publication = _state_mapping(state, "publication")
        self._save(
            state,
            "publication_pending"
            if publication.get("enabled") is True
            else "milestone_complete",
        )
        return True

    def _attach_candidate(self, state: dict[str, object]) -> None:
        if self._recover_candidate_attach_if_present(state):
            return
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        record = self._active_candidate(state)
        self._assert_remote_candidate(state, record, "candidate attachment")
        policy = self._hosted_policy(milestone)
        self._assert_unique_attributed_run(
            state, policy, record, "candidate attachment"
        )
        if record.get("status") != "checks_passed":
            raise StateError(
                "candidate attachment attempted without passing hosted checks"
            )
        evidence = state.get("hosted_evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("candidate_sha") != record.get("sha")
            or evidence.get("status") != "completed"
            or evidence.get("conclusion") != "success"
        ):
            raise StateError("candidate attachment lacks exact hosted evidence")
        review = state.get("review_result")
        if not isinstance(review, dict) or review.get("verdict") != "pass":
            raise StateError("candidate attachment attempted without passing review")
        verification = _state_list(state, "verification_results")
        if not verification or any(
            not isinstance(item, dict) or item.get("succeeded") is not True
            for item in verification
        ):
            raise StateError("candidate attachment lacks passing local verification")
        parent = _string(record.get("parent"), "candidate.parent")
        sha = _string(record.get("sha"), "candidate.sha").lower()
        tree = _string(record.get("tree"), "candidate.tree").lower()
        snapshot = self.git.changed_snapshot()
        recorded_snapshot = _state_mapping(state, "worktree_snapshot")
        if state.get("current_phase") == "candidate_attach_running":
            matches = self._snapshots_match_content(recorded_snapshot, snapshot)
        else:
            matches = snapshot == recorded_snapshot
        if not matches or not snapshot:
            raise StateError("worktree changed before candidate attachment")
        if self.git.head() != parent or state.get("expected_head") != parent:
            raise StateError("candidate parent moved before attachment")
        if state.get("current_phase") != "candidate_attach_running":
            state["commit_parent"] = parent
            self._begin_transition_metadata_guard(state, "candidate_attachment")
            self._save(state, "candidate_attach_running")
        else:
            self._assert_transition_metadata_guard(state, "candidate_attachment")
        current_tree = self._candidate_tree(
            state,
            milestone,
            cast("int", record["attempt"]),
            parent,
            recorded_snapshot,
        )
        if current_tree != tree:
            raise StateError(
                "live worktree no longer matches the hosted candidate tree"
            )
        run_directory = self._run_directory(state)
        for index, path in enumerate(sorted(recorded_snapshot)):
            added = self.git.run(
                ("add", "-A", "--", path),
                log_base=run_directory
                / "logs"
                / f"{milestone.identifier}-candidate-attach-add-{index}",
            )
            if not added.succeeded:
                state["last_error"] = f"unable to stage candidate path {path!r}"
                self._save(state)
                raise StateError(cast("str", state["last_error"]))
        staged = set(self.git.staged_paths())
        if not staged or not staged.issubset(set(recorded_snapshot)):
            raise StateError("candidate attachment staged an unexpected path set")
        staged_tree = self.git.require_output(
            ("write-tree",), "unable to inspect staged candidate tree"
        )
        if staged_tree.lower() != tree:
            raise StateError("staged worktree does not match the hosted candidate tree")
        self._assert_remote_candidate(state, record, "range-branch attachment")
        self._assert_unique_attributed_run(
            state, policy, record, "range-branch attachment"
        )
        updated = self.git.run(
            ("update-ref", f"refs/heads/{state['branch']}", sha, parent),
            log_base=run_directory
            / "logs"
            / f"{milestone.identifier}-candidate-attach-ref",
        )
        if not updated.succeeded:
            raise StateError("unable to attach the exact candidate to the range branch")
        self._assert_transition_metadata_guard(state, "candidate_attachment")
        if not self._recover_candidate_attach_if_present(state, sha):
            raise StateError("exact candidate attachment was not recoverable")
        self._write(f"Accepted {milestone.identifier} exact candidate {sha}.")

    def _recover_commit_if_present(
        self, state: dict[str, object], current_head: str | None = None
    ) -> bool:
        """Recognize exactly one parent-owned commit after an interrupted save."""
        if state.get("current_phase") != "commit_running":
            return False
        parent = state.get("commit_parent")
        if not isinstance(parent, str):
            raise StateError("commit recovery has no recorded parent")
        head = current_head or self.git.head()
        if head == parent:
            return False
        actual_parent = self.git.require_output(
            ("rev-parse", "HEAD^"), "unable to inspect interrupted commit parent"
        )
        if actual_parent != parent:
            raise StateError("unexpected history movement during commit recovery")
        message = self.git.require_output(
            ("show", "-s", "--format=%B", "HEAD"),
            "unable to inspect interrupted commit message",
        )
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        run_id = cast("str", state["run_id"])
        _, trailers = self._commit_message(milestone, run_id)
        if not all(line in message.splitlines() for line in trailers.splitlines()):
            raise StateError(
                "new HEAD is not the recorded parent-owned milestone commit"
            )
        self._record_completed_commit(state, milestone, head)
        state["expected_head"] = head
        state["worktree_snapshot"] = self.git.changed_snapshot()
        state["git_metadata_digest"] = self.git.metadata_digest()
        publication = _state_mapping(state, "publication")
        self._save(
            state,
            "publication_pending"
            if publication.get("enabled") is True
            else "milestone_complete",
        )
        return True

    def _record_completed_commit(
        self, state: dict[str, object], milestone: Milestone, commit: str
    ) -> None:
        completed = _state_list(state, "completed_commits")
        existing = [
            _mapping(item, "completed commit")
            for item in completed
            if isinstance(item, dict)
        ]
        if any(record.get("commit") == commit for record in existing):
            return
        if any(record.get("milestone") == milestone.identifier for record in existing):
            raise StateError(
                "state already records a different commit for this milestone"
            )
        completed.append(
            {
                "milestone": milestone.identifier,
                "title": milestone.title,
                "commit": commit,
                "contract_hash": state.get("contract_hash"),
                "repair_cycles": state.get("repair_count"),
                "verification": list(_state_list(state, "verification_results")),
                "hosted_evidence": state.get("hosted_evidence"),
                "candidate": state.get("candidate"),
            }
        )
        state["completed_commits"] = completed

    def _commit_current_milestone(self, state: dict[str, object]) -> None:
        if state.get(
            "current_phase"
        ) == "commit_running" and self._recover_commit_if_present(state):
            return
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        review = state.get("review_result")
        if not isinstance(review, dict) or review.get("verdict") != "pass":
            raise StateError("commit attempted without an independent passing review")
        verification = _state_list(state, "verification_results")
        if not verification or any(
            not isinstance(item, dict) or item.get("succeeded") is not True
            for item in verification
        ):
            raise StateError(
                "commit attempted without passing independent verification"
            )
        snapshot = self.git.changed_snapshot()
        recorded_snapshot = _state_mapping(state, "worktree_snapshot")
        if state.get("current_phase") == "commit_running":
            snapshot_matches = self._snapshots_match_content(
                recorded_snapshot,
                snapshot,
            )
        else:
            snapshot_matches = snapshot == recorded_snapshot
        if not snapshot_matches:
            raise StateError("worktree changed before commit")
        if not snapshot:
            raise StateError("refusing to create an empty milestone commit")
        parent = cast("str", state["expected_head"])
        if self.git.head() != parent:
            raise StateError("HEAD changed before commit")
        if state.get("current_phase") != "commit_running":
            state["commit_parent"] = parent
            self._save(state, "commit_running")
        run_directory = self._run_directory(state)
        for index, path in enumerate(sorted(snapshot)):
            log_base = (
                run_directory / "logs" / f"{milestone.identifier}-git-add-{index}"
            )
            result = self.git.run(("add", "-A", "--", path), log_base=log_base)
            if not result.succeeded:
                state["last_error"] = f"unable to stage milestone path {path!r}"
                self._save(state)
                raise StateError(cast("str", state["last_error"]))
        staged = set(self.git.staged_paths())
        if not staged or not staged.issubset(set(snapshot)):
            state["last_error"] = "staged paths do not match recorded milestone changes"
            self._save(state)
            raise StateError(cast("str", state["last_error"]))
        title, trailers = self._commit_message(milestone, cast("str", state["run_id"]))
        result = self.git.run(
            ("commit", "-m", title, "-m", trailers),
            timeout_seconds=self.config.default_timeout_seconds,
            log_base=run_directory / "logs" / f"{milestone.identifier}-git-commit",
        )
        if not result.succeeded:
            state["last_error"] = result.stderr.strip() or "Git commit failed"
            self._save(state)
            raise StateError(cast("str", state["last_error"]))
        commit = self.git.head()
        actual_parent = self.git.require_output(
            ("rev-parse", "HEAD^"), "unable to inspect new milestone commit"
        )
        if actual_parent != parent:
            raise StateError("milestone commit has an unexpected parent")
        remaining = self.git.changed_snapshot()
        if remaining:
            state["worktree_snapshot"] = remaining
            state["last_error"] = "worktree is not clean after milestone commit"
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        self._record_completed_commit(state, milestone, commit)
        state["expected_head"] = commit
        state["worktree_snapshot"] = {}
        state["git_metadata_digest"] = self.git.metadata_digest()
        state["last_error"] = None
        publication = _state_mapping(state, "publication")
        next_phase = (
            "publication_pending"
            if publication.get("enabled") is True
            else "milestone_complete"
        )
        self._save(state, next_phase)
        self._write(f"Committed {milestone.identifier} as {commit}.")

    def _publication_failure(
        self, state: dict[str, object], publication: dict[str, object], message: str
    ) -> NoReturn:
        state["git_metadata_digest"] = self.git.metadata_digest()
        publication["status"] = "failed"
        publication["last_error"] = message
        state["publication"] = publication
        state["last_error"] = message
        self._save(state, "publication_pending")
        raise PublicationError(message)

    def _remote_branch_sha(
        self, state: dict[str, object], publication: dict[str, object]
    ) -> str | None:
        branch = cast("str", state["branch"])
        result = self.git.run(
            (
                "ls-remote",
                "--heads",
                self._remote_transport_url(state, push=False),
                f"refs/heads/{branch}",
            ),
            timeout_seconds=self.config.default_timeout_seconds,
        )
        if not result.succeeded:
            self._publication_failure(
                state,
                publication,
                result.stderr.strip() or "unable to inspect remote checkpoint branch",
            )
        output = result.stdout.strip()
        if not output:
            return None
        lines = output.splitlines()
        if len(lines) != 1 or "\t" not in lines[0]:
            self._publication_failure(
                state, publication, "remote returned an ambiguous branch reference"
            )
        sha, _reference = lines[0].split("\t", maxsplit=1)
        if not re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
            self._publication_failure(
                state, publication, "remote returned an invalid branch commit"
            )
        return sha.lower()

    def _publish_current_checkpoint(self, state: dict[str, object]) -> None:
        unconfirmed_metadata = state.pop(
            "_unconfirmed_push_metadata_change",
            False,
        )
        publication = _state_mapping(state, "publication")
        if publication.get("enabled") is not True:
            self._save(state, "milestone_complete")
            return
        head = cast("str", state["expected_head"])
        pushed_values = publication.get("pushed_commits", [])
        if not isinstance(pushed_values, list) or not all(
            isinstance(item, str) for item in pushed_values
        ):
            raise StateError("publication pushed_commits is malformed")
        pushed = cast("list[str]", pushed_values)
        expected_remote = pushed[-1] if pushed else None
        remote_sha = self._remote_branch_sha(state, publication)
        if unconfirmed_metadata is True and remote_sha != head:
            state["last_error"] = (
                "Git metadata changed during an unconfirmed push, but the remote "
                "does not contain the exact expected checkpoint"
            )
            self._save(state, "blocked")
            raise StateError(cast("str", state["last_error"]))
        if head in pushed:
            if pushed[-1] != head or remote_sha != head:
                self._publication_failure(
                    state,
                    publication,
                    "recorded checkpoint no longer matches the remote branch",
                )
            needs_push = False
        elif remote_sha == head:
            pushed.append(head)
            state["git_metadata_digest"] = self.git.metadata_digest()
            publication["pushed_commits"] = pushed
            publication["status"] = "pushed"
            state["publication"] = publication
            state["last_error"] = None
            self._save(state, "publication_pending")
            needs_push = False
        elif remote_sha != expected_remote:
            self._publication_failure(
                state,
                publication,
                "remote branch moved or diverged from the last recorded checkpoint",
            )
        else:
            needs_push = True
        branch = cast("str", state["branch"])
        if needs_push:
            publication["status"] = "pushing"
            state["publication"] = publication
            self._save(state, "publication_pending")
            result = self.git.run(
                (
                    "push",
                    "--no-follow-tags",
                    "--recurse-submodules=no",
                    self._remote_transport_url(state, push=True),
                    branch,
                ),
                timeout_seconds=self.config.default_timeout_seconds,
                log_base=self._run_directory(state)
                / "logs"
                / f"{state['current_milestone']}-git-push",
            )
            if not result.succeeded:
                self._publication_failure(
                    state,
                    publication,
                    result.stderr.strip() or "Git checkpoint push failed",
                )
            pushed.append(head)
            state["git_metadata_digest"] = self.git.metadata_digest()
            publication["pushed_commits"] = pushed
            publication["status"] = "pushed"
            state["publication"] = publication
            self._save(state, "publication_pending")
        if publication.get("draft_pr") is True:
            self._ensure_draft_pr(state, publication)
        publication["status"] = "checkpoint_published"
        publication["last_error"] = None
        state["publication"] = publication
        state["last_error"] = None
        self._save(state, "milestone_complete")
        if publication.get("draft_pr") is True:
            self._update_pr_body_if_available(state, "checkpoint published")
        self._write(f"Published recoverable checkpoint {head}.")

    def _gh_run(
        self,
        arguments: Sequence[str],
        state: Mapping[str, object],
        name: str,
    ) -> CommandResult:
        repository = _state_github_repository(state)
        return self.runner.run(
            (
                *self.config.tools["gh"],
                *arguments,
                "--repo",
                repository.selector,
            ),
            cwd=self.repo_root,
            timeout_seconds=self.config.default_timeout_seconds,
            env=_repository_environment(),
            log_base=self._run_directory(state) / "logs" / name,
        )

    def _gh_api_run(
        self,
        arguments: Sequence[str],
        state: Mapping[str, object],
        name: str,
    ) -> CommandResult:
        """Call one repository-bound GitHub API endpoint without ambient selectors."""
        repository = _state_github_repository(state)
        return self.runner.run(
            (
                *self.config.tools["gh"],
                "api",
                "--hostname",
                repository.host,
                *arguments,
            ),
            cwd=self.repo_root,
            timeout_seconds=self.config.default_timeout_seconds,
            env=_repository_environment(),
            log_base=self._run_directory(state) / "logs" / name,
        )

    def _ensure_draft_pr(
        self, state: dict[str, object], publication: dict[str, object]
    ) -> None:
        pr_url = publication.get("pr_url")
        if pr_url is None:
            listed = self._gh_run(
                (
                    "pr",
                    "list",
                    "--head",
                    cast("str", state["branch"]),
                    "--base",
                    self.config.base_branch,
                    "--state",
                    "open",
                    "--json",
                    "url,isDraft",
                ),
                state,
                "gh-pr-list",
            )
            if not listed.succeeded:
                self._publication_failure(
                    state,
                    publication,
                    listed.stderr.strip() or "unable to discover existing pull request",
                )
            try:
                candidates = cast(
                    "object",
                    json.loads(
                        listed.stdout or "[]",
                        object_pairs_hook=_reject_duplicate_json_keys,
                    ),
                )
            except (json.JSONDecodeError, _DuplicateJSONKeyError):
                self._publication_failure(
                    state, publication, "GitHub CLI returned malformed PR metadata"
                )
            if not isinstance(candidates, list):
                self._publication_failure(
                    state, publication, "GitHub CLI returned invalid PR metadata"
                )
            if len(candidates) > 1:
                self._publication_failure(
                    state,
                    publication,
                    "multiple open pull requests use the range branch",
                )
            if candidates:
                candidate = _mapping(candidates[0], "GitHub pull request")
                if candidate.get("isDraft") is not True:
                    self._publication_failure(
                        state, publication, "existing pull request is not a draft"
                    )
                pr_url = _string(candidate.get("url"), "GitHub pull request URL")
                if not _github_repository_url(
                    pr_url, _state_github_repository(state), area="pull"
                ):
                    self._publication_failure(
                        state,
                        publication,
                        "GitHub CLI returned an unsafe pull request URL",
                    )
            else:
                body_path = self._write_pr_body(state, "checkpoint published")
                requested = cast("list[str]", state["requested_milestones"])
                title = f"Autopilot {requested[0]}-{requested[-1]}: PyAhead milestones"
                created = self._gh_run(
                    (
                        "pr",
                        "create",
                        "--draft",
                        "--base",
                        self.config.base_branch,
                        "--head",
                        cast("str", state["branch"]),
                        "--title",
                        title,
                        "--body-file",
                        str(body_path),
                    ),
                    state,
                    "gh-pr-create",
                )
                if not created.succeeded:
                    self._publication_failure(
                        state,
                        publication,
                        created.stderr.strip() or "draft pull request creation failed",
                    )
                urls = [
                    line.strip() for line in created.stdout.splitlines() if line.strip()
                ]
                if not urls or not _github_repository_url(
                    urls[-1], _state_github_repository(state), area="pull"
                ):
                    self._publication_failure(
                        state,
                        publication,
                        "GitHub CLI did not return a pull request URL",
                    )
                pr_url = urls[-1]
            publication["pr_url"] = pr_url
            state["publication"] = publication
            self._save(state, "publication_pending")

    def _write_pr_body(self, state: Mapping[str, object], stop_reason: str) -> Path:
        completed = _state_list(state, "completed_commits")
        lines = [
            "## PyAhead autonomous milestone run",
            "",
            f"- Branch: `{state['branch']}`",
            f"- Base commit: `{state['base_commit']}`",
            f"- Current phase: `{state['current_phase']}`",
            f"- Stop reason: {stop_reason}",
            "",
            "## Completed milestones",
            "",
        ]
        if completed:
            for item in completed:
                record = _mapping(item, "completed commit")
                lines.append(
                    f"- {record.get('milestone')}: `{record.get('commit')}` — "
                    "independent verification passed and reviewer returned `pass`."
                )
                verification = record.get("verification")
                if isinstance(verification, list):
                    for result_item in verification:
                        result = _mapping(result_item, "completed verification")
                        command = result.get("command")
                        lines.append(
                            "  - `"
                            + shlex.join(
                                _redacted_command(
                                    _string_tuple(command, "verification command")
                                )
                            )
                            + "`: "
                            + (
                                "passed"
                                if result.get("succeeded") is True
                                else "failed"
                            )
                            + f" (returncode={result.get('returncode')}, "
                            + f"timeout={result.get('timed_out')}, "
                            + f"signal={result.get('signal')})"
                        )
                hosted = record.get("hosted_evidence")
                if isinstance(hosted, dict):
                    lines.append(
                        "  - exact candidate `"
                        + str(hosted.get("candidate_sha"))
                        + "`: hosted workflow "
                        + str(hosted.get("conclusion"))
                        + " ("
                        + str(hosted.get("url"))
                        + ")"
                    )
        else:
            lines.append("- None yet.")
        lines.extend(
            [
                "",
                "This pull request is intentionally draft. The orchestrator never merges it,",
                "and external product gates cannot be satisfied by Codex output.",
                "",
            ]
        )
        body_path = self._run_directory(state) / "pr-body.md"
        _atomic_write_bytes(body_path, "\n".join(lines).encode("utf-8"))
        return body_path

    def _update_pr_body(
        self, state: dict[str, object], pr_url: str, stop_reason: str
    ) -> None:
        body_path = self._write_pr_body(state, stop_reason)
        edited = self._gh_run(
            ("pr", "edit", pr_url, "--body-file", str(body_path)),
            state,
            "gh-pr-edit",
        )
        if not edited.succeeded:
            publication = _state_mapping(state, "publication")
            self._publication_failure(
                state,
                publication,
                edited.stderr.strip() or "draft pull request update failed",
            )

    def _update_pr_body_if_available(
        self, state: dict[str, object], stop_reason: str
    ) -> None:
        publication = _state_mapping(state, "publication")
        pr_url = publication.get("pr_url")
        if isinstance(pr_url, str):
            self._update_pr_body(state, pr_url, stop_reason)

    def _advance_milestone(self, state: dict[str, object]) -> ExitCode | None:
        milestone = self.config.milestone(cast("str", state["current_milestone"]))
        requested = cast("list[str]", state["requested_milestones"])
        index = cast("int", state["current_index"]) + 1
        state["current_index"] = index
        state["contract_path"] = None
        state["contract_hash"] = None
        state["implementation_result"] = None
        state["repair_result"] = None
        state["review_result"] = None
        state["active_result_path"] = None
        state["active_role"] = None
        state["active_agent_attempt"] = None
        state["active_agent_retry"] = None
        state["pending_agent_retry"] = None
        state["session_baseline_snapshot"] = {}
        state["session_git_metadata_digest"] = None
        state["verification_results"] = []
        state["verification_index"] = 0
        state["review_findings"] = []
        state["failed_output_path"] = None
        state["repair_count"] = 0
        state["candidate"] = {"active": None, "attempts": []}
        state["hosted_evidence"] = None
        self._clear_transition_metadata_guard(state)
        state["worktree_snapshot"] = {}
        if index < len(requested):
            next_milestone = self.config.milestone(requested[index])
            state["current_milestone"] = next_milestone.identifier
            state["protected_hashes"] = protected_snapshot(
                self.repo_root, self.config, next_milestone.identifier
            )
        else:
            state["current_milestone"] = None
            state["protected_hashes"] = {}
        if milestone.stop_after_gate == "C":
            state["last_error"] = "awaiting external Gate C evidence"
            self._save(state, "awaiting_gate_C")
            self._update_pr_body_if_available(
                state, "awaiting external Gate C evidence"
            )
            self._write("M6 checkpoint complete; stopped at awaiting_gate_C.")
            return ExitCode.SUCCESS if index >= len(requested) else ExitCode.BLOCKED
        if index >= len(requested):
            state["last_error"] = None
            self._save(state, "complete")
            self._update_pr_body_if_available(state, "requested range complete")
            self._write("Requested milestone range completed.")
            return ExitCode.SUCCESS
        self._save(state, "milestone_pending")
        return None


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("timeout must be a number") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def build_parser() -> argparse.ArgumentParser:
    """Build the documented command interface and stable exit-code help."""
    parser = argparse.ArgumentParser(
        prog="autopilot.py",
        description=(
            "Run PyAhead design milestones through isolated implementation, "
            "verification, exact-candidate hosted evidence when configured, review, "
            "repair, commit, and publication phases."
        ),
        epilog=(
            "Exit codes: 0 success; 2 invalid input/capability; 3 external or agent "
            "blocker; 4 execution/review failure; 5 interrupted; 6 unsafe state or "
            "repository divergence; 7 publication failed with local work preserved."
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="repository-relative TOML policy (default: automation/milestones.toml)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor",
        help="verify local Codex, Git, schema, and optional publication capabilities",
    )
    doctor.add_argument(
        "--push",
        action="store_true",
        help="also require authenticated Git and GitHub CLI publication",
    )
    doctor.add_argument(
        "--draft-pr",
        action="store_true",
        help="verify draft-PR prerequisites (requires --push)",
    )

    plan = subparsers.add_parser(
        "plan",
        help="show an immutable milestone range plan without modifying state or Git",
    )
    plan.add_argument(
        "--from", dest="from_milestone", required=True, metavar="MILESTONE"
    )
    plan.add_argument(
        "--through", dest="through_milestone", required=True, metavar="MILESTONE"
    )

    run = subparsers.add_parser(
        "run",
        help="start and drive one new milestone range",
    )
    run.add_argument(
        "--from", dest="from_milestone", required=True, metavar="MILESTONE"
    )
    run.add_argument(
        "--through", dest="through_milestone", required=True, metavar="MILESTONE"
    )
    run.add_argument(
        "--push",
        action="store_true",
        help=(
            "push every accepted milestone as a recoverable checkpoint "
            "(required for M6 hosted evidence)"
        ),
    )
    run.add_argument(
        "--draft-pr",
        action="store_true",
        help="create or reuse one draft PR after the first push (requires --push)",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="print stages, argv, prompts, commits, gates, and protected files only",
    )
    run.add_argument(
        "--timeout-seconds",
        type=_positive_timeout,
        help="override every child and verification timeout for this run",
    )

    status = subparsers.add_parser("status", help="show the last persisted safe phase")
    status.add_argument("--json", action="store_true", help="print complete state JSON")

    subparsers.add_parser(
        "resume",
        help="resume the recorded run without duplicating sessions, commits, or pushes",
    )

    gate = subparsers.add_parser(
        "gate",
        help="record or inspect external product-gate evidence",
    )
    gate_subparsers = gate.add_subparsers(dest="gate_command", required=True)
    approve = gate_subparsers.add_parser(
        "approve",
        help="record an explicit evidence-backed external gate approval",
    )
    approve.add_argument("gate", choices=("C",), help="gate identifier")
    approve.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="non-empty repository file documenting external Gate C evidence",
    )
    approve.add_argument(
        "--approved-by",
        required=True,
        help="human or accountable group recording the approval",
    )
    gate_status = gate_subparsers.add_parser(
        "status",
        help="show whether an external gate approval is recorded",
    )
    gate_status.add_argument("gate", choices=("C",), help="gate identifier")
    return parser


def repository_root() -> Path:
    """Use the script's repository, independent of the caller's current directory."""
    root = Path(__file__).resolve().parents[1]
    if not (root / "docs/design.md").is_file():
        raise InvalidInputError(
            "scripts/autopilot.py is not inside a PyAhead repository"
        )
    return root


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the operator command with concise, stable failures."""
    if os.environ.get(CHILD_MARKER):
        sys.stderr.write(
            "autopilot: recursive invocation from a Codex child session is forbidden\n"
        )
        return int(ExitCode.STATE_ERROR)
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        root = repository_root()
        config = load_config(root, arguments.config)
        autopilot = Autopilot(root, config)
        if arguments.command == "doctor":
            if arguments.draft_pr and not arguments.push:
                raise InvalidInputError("--draft-pr requires --push")
            autopilot.doctor(publication=bool(arguments.push))
            return int(ExitCode.SUCCESS)
        if arguments.command == "plan":
            autopilot.plan(arguments.from_milestone, arguments.through_milestone)
            return int(ExitCode.SUCCESS)
        if arguments.command == "run":
            return int(
                autopilot.run(
                    arguments.from_milestone,
                    arguments.through_milestone,
                    push=bool(arguments.push),
                    draft_pr=bool(arguments.draft_pr),
                    dry_run=bool(arguments.dry_run),
                    timeout_override=arguments.timeout_seconds,
                )
            )
        if arguments.command == "status":
            autopilot.status(as_json=bool(arguments.json))
            return int(ExitCode.SUCCESS)
        if arguments.command == "resume":
            return int(autopilot.resume())
        if arguments.command == "gate":
            if arguments.gate_command == "approve":
                autopilot.approve_gate(
                    arguments.gate,
                    arguments.evidence,
                    arguments.approved_by,
                )
            else:
                approved = autopilot.gate_approved(arguments.gate)
                autopilot._write(  # noqa: SLF001 - CLI adapter owns presentation.
                    f"Gate {arguments.gate}: {'approved' if approved else 'not approved'}"
                )
            return int(ExitCode.SUCCESS)
        raise InvalidInputError("unsupported command")
    except KeyboardInterrupt:
        sys.stderr.write(
            "autopilot: interrupted; resume from the last recorded safe phase\n"
        )
        return int(ExitCode.INTERRUPTED)
    except AutopilotError as error:
        sys.stderr.write(f"autopilot: {error}\n")
        return int(error.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
