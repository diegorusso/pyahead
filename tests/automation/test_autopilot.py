"""Unit and offline integration tests for the autonomous milestone orchestrator."""

# The integration fixture launches explicit Python and Git argv in isolated temporary
# repositories; no command is interpreted by a shell.
# ruff: noqa: ARG002, EM101, PLR2004, S603, TRY003

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from io import BytesIO, StringIO
from pathlib import Path
from threading import Event
from typing import TYPE_CHECKING, Self, cast

import pytest

from pyahead import _human_text
from pyahead._human_text import escape_terminal_text
from scripts import autopilot

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

SOURCE_ROOT = Path(__file__).resolve().parents[2]
FAKE_CODEX = Path(__file__).with_name("fake_codex.py").resolve()
FAKE_GH = Path(__file__).with_name("fake_gh.py").resolve()
FAKE_GIT = Path(__file__).with_name("fake_git.py").resolve()
DEFAULT_VERIFICATION = (
    "from pathlib import Path; "
    "raise SystemExit(0 if Path('feature.txt').is_file() else 1)"
)
_HOSTILE_OPERATOR_TEXT = "line\nFORGED\x1b[2J\r\u202e\u2028\u2029"


def _capture_mismatch_diagnostic(
    *,
    actual: bytes,
    expected: bytes,
    details: Mapping[str, object],
) -> str:
    """Describe a capture mismatch without rendering its potentially huge body."""
    first_difference = next(
        (
            offset
            for offset, (actual_byte, expected_byte) in enumerate(
                zip(actual, expected, strict=False)
            )
            if actual_byte != expected_byte
        ),
        None,
    )
    if first_difference is None and len(actual) != len(expected):
        first_difference = min(len(actual), len(expected))
    return json.dumps(
        {
            "actual_edges_hex": {
                "first": actual[:16].hex(),
                "last": actual[-16:].hex(),
            },
            "actual_sha256": hashlib.sha256(actual).hexdigest(),
            "actual_size": len(actual),
            "expected_edges_hex": {
                "first": expected[:16].hex(),
                "last": expected[-16:].hex(),
            },
            "expected_sha256": hashlib.sha256(expected).hexdigest(),
            "expected_size": len(expected),
            "first_difference": first_difference,
            **details,
        },
        sort_keys=True,
    )


def _write_schema_one_command_result(
    log_base: Path,
    result: autopilot.CommandResult,
) -> None:
    """Write the exact legacy receipt shape retained for safe resume."""
    started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(result.command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    stdout_path.write_bytes(result.stdout.encode("utf-8"))
    stderr_path.write_bytes(result.stderr.encode("utf-8"))
    autopilot.atomic_write_json(
        result_path,
        {
            "command_sha256": autopilot._command_sha256(result.command),  # noqa: SLF001
            "interrupted": result.interrupted,
            "returncode": result.returncode,
            "schema_version": 1,
            "stderr_sha256": autopilot.sha256_text(result.stderr),
            "stdout_sha256": autopilot.sha256_text(result.stdout),
            "timed_out": result.timed_out,
        },
    )


class SimulatedCrashError(RuntimeError):
    """Test-only process loss immediately after one atomic state save."""


@dataclass(frozen=True)
class RepositoryFixture:
    """One isolated Git repository and its out-of-tree fake-service controls."""

    root: Path
    origin: Path
    plan_path: Path
    counter_path: Path
    codex_events_path: Path
    gh_events_path: Path
    gh_run_plan_path: Path
    gh_run_state_path: Path
    git_events_path: Path
    git: str

    def set_plan(self, actions: Sequence[Mapping[str, object]]) -> None:
        """Install a deterministic fresh-session action sequence."""
        self.plan_path.write_text(
            json.dumps(actions, indent=2) + "\n",
            encoding="utf-8",
        )
        self.counter_path.unlink(missing_ok=True)
        self.codex_events_path.unlink(missing_ok=True)

    def set_gh_run_plan(self, results: Sequence[Mapping[str, object]]) -> None:
        """Install deterministic hosted-check states for the fake GitHub CLI."""
        self.gh_run_plan_path.write_text(
            json.dumps(results, indent=2) + "\n",
            encoding="utf-8",
        )
        self.gh_run_state_path.unlink(missing_ok=True)

    def make_autopilot(self) -> autopilot.Autopilot:
        """Construct a fresh parent runner over persisted repository state."""
        return autopilot.Autopilot(
            self.root,
            autopilot.load_config(self.root),
            stdout=StringIO(),
            stderr=StringIO(),
        )

    def state(self) -> dict[str, object]:
        """Read the persisted state document."""
        loaded = cast(
            "object",
            json.loads(
                (self.root / ".autopilot/state.json").read_text(encoding="utf-8")
            ),
        )
        assert isinstance(loaded, dict)
        return cast("dict[str, object]", loaded)

    def codex_events(self) -> list[dict[str, object]]:
        """Read complete fake Codex invocation evidence."""
        loaded = cast(
            "object",
            json.loads(self.codex_events_path.read_text(encoding="utf-8")),
        )
        assert isinstance(loaded, list)
        assert all(isinstance(item, dict) for item in loaded)
        return cast("list[dict[str, object]]", loaded)


class CrashAfterSaveAutopilot(autopilot.Autopilot):
    """Lose the process once, immediately after a named safe phase is durable."""

    def __init__(self, *args: object, crash_phase: str, **kwargs: object) -> None:
        """Configure the phase whose durable save loses the process."""
        super().__init__(*args, **kwargs)
        self.crash_phase = crash_phase
        self.crashed = False

    def _save(self, state: dict[str, object], phase: str | None = None) -> None:
        super()._save(state, phase)
        if state["current_phase"] == self.crash_phase and not self.crashed:
            self.crashed = True
            raise SimulatedCrashError(self.crash_phase)


class CrashAfterCommitAutopilot(autopilot.Autopilot):
    """Lose the process after Git commits but before state records the new HEAD."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        """Configure a one-shot crash after the first milestone commit."""
        super().__init__(*args, **kwargs)
        self.crashed = False

    def _record_completed_commit(
        self,
        state: dict[str, object],
        milestone: autopilot.Milestone,
        commit: str,
    ) -> None:
        super()._record_completed_commit(state, milestone, commit)
        if not self.crashed:
            self.crashed = True
            raise SimulatedCrashError("after Git commit")


class CrashAfterSuccessfulPushRunner(autopilot.CommandRunner):
    """Lose the parent after the remote accepts a push but before state advances."""

    def __init__(self) -> None:
        """Configure one crash after the first successful Git push."""
        self.crashed = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Run normally, then lose only the successful checkpoint transition."""
        result = super().run(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
            env=env,
            log_base=log_base,
        )
        if (
            not self.crashed
            and len(command) > 1
            and "push" in command[1:3]
            and result.succeeded
        ):
            self.crashed = True
            raise SimulatedCrashError("after successful push")
        return result


class CrashAfterSuccessfulApiRefRunner(autopilot.CommandRunner):
    """Lose the parent after GitHub atomically creates the final candidate ref."""

    def __init__(self) -> None:
        """Configure one crash after the first successful create-ref API call."""
        self.crashed = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Run normally, then crash only after final ref creation succeeded."""
        result = super().run(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
            env=env,
            log_base=log_base,
        )
        if (
            not self.crashed
            and result.succeeded
            and "api" in command
            and "--method" in command
            and "POST" in command
            and any(item.endswith("/git/refs") for item in command)
        ):
            self.crashed = True
            raise SimulatedCrashError("after successful create-ref API call")
        return result


class CrashBeforeApiInvocationRunner(autopilot.CommandRunner):
    """Lose the parent after intent is saved but before the API process starts."""

    def __init__(self) -> None:
        """Configure one pre-invocation create-ref crash."""
        self.crashed = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Crash before delegating only the first create-ref API invocation."""
        if (
            not self.crashed
            and "api" in command
            and "--method" in command
            and "POST" in command
            and any(item.endswith("/git/refs") for item in command)
        ):
            self.crashed = True
            raise SimulatedCrashError("before create-ref process invocation")
        return super().run(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
            env=env,
            log_base=log_base,
        )


class ExactUploadRaceRunner(autopilot.CommandRunner):
    """Place an exact upload ref after durable start but without ownership proof."""

    def __init__(self, origin: Path, git: str, *, durable_result: bool) -> None:
        """Select a missing-result crash or an indeterminate completed result."""
        self.origin = origin
        self.git = git
        self.durable_result = durable_result
        self.triggered = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Emulate an external exact-SHA creator in the upload crash window."""
        is_upload = (
            not self.triggered
            and "push" in command
            and any(item.startswith("--force-with-lease=") for item in command)
            and command[-1].endswith("-upload")
        )
        if not is_upload:
            return super().run(
                command,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                input_text=input_text,
                env=env,
                log_base=log_base,
            )
        self.triggered = True
        assert log_base is not None
        started_path, _result_path, _stdout_path, _stderr_path = (
            autopilot._command_evidence_paths(log_base)  # noqa: SLF001
        )
        autopilot.atomic_write_json(
            started_path,
            {
                "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
                "schema_version": 1,
            },
        )
        _run(
            [
                self.git,
                "push",
                "--no-follow-tags",
                "--recurse-submodules=no",
                str(self.origin),
                command[-1],
            ],
            cwd=cwd,
        )
        if not self.durable_result:
            raise SimulatedCrashError("after candidate upload process start")
        result = autopilot.CommandResult(
            command=tuple(command),
            returncode=-9,
            stdout="",
            stderr="fixture indeterminate candidate upload\n",
            duration_seconds=0.01,
            timed_out=True,
        )
        self.write_logs(result, log_base)
        return result


class CrashAfterGitOperationRunner(autopilot.CommandRunner):
    """Lose the process immediately after one selected successful Git effect."""

    def __init__(
        self,
        operation: str,
        *,
        reference_fragment: str | None = None,
        real_index_only: bool = False,
    ) -> None:
        """Select an operation, optional ref fragment, and index context."""
        self.operation = operation
        self.reference_fragment = reference_fragment
        self.real_index_only = real_index_only
        self.crashed = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Run normally, then crash after the selected successful side effect."""
        result = super().run(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
            env=env,
            log_base=log_base,
        )
        matches = self.operation in command
        if self.reference_fragment is not None:
            matches = matches and any(
                self.reference_fragment in item for item in command
            )
        if self.real_index_only:
            matches = matches and (env is None or "GIT_INDEX_FILE" not in env)
        if not self.crashed and result.succeeded and matches:
            self.crashed = True
            message = f"after Git {self.operation}"
            raise SimulatedCrashError(message)
        return result


class CrashAfterWorkflowDispatchRunner(autopilot.CommandRunner):
    """Lose the process after GitHub accepts one workflow dispatch."""

    def __init__(self) -> None:
        """Configure one crash after the first accepted workflow dispatch."""
        self.crashed = False

    def run(  # noqa: PLR0913 - mirrors the supervised runner interface.
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        input_text: str | None = None,
        env: Mapping[str, str] | None = None,
        log_base: Path | None = None,
    ) -> autopilot.CommandResult:
        """Run normally, then crash only after the non-help dispatch."""
        result = super().run(
            command,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            input_text=input_text,
            env=env,
            log_base=log_base,
        )
        if (
            not self.crashed
            and result.succeeded
            and "workflow" in command
            and "run" in command
            and "--ref" in command
            and "--help" not in command
        ):
            self.crashed = True
            raise SimulatedCrashError("after workflow dispatch")
        return result


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run one explicit fixture command with separated captured output."""
    return subprocess.run(
        list(command),
        cwd=cwd,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _toml_array(values: Sequence[str]) -> str:
    """Render strings as a TOML-compatible JSON array."""
    return json.dumps(list(values))


def _milestone_toml() -> str:
    """Return the required M2-M10 policy for temporary repositories."""
    records: list[str] = []
    titles = {
        "M2": "Registry and matcher framework",
        "M3": "Version timeline and reachability",
        "M4": "Project configuration and CI reports",
        "M5": "CPython registry curation",
        "M6": "Public-alpha hardening",
        "M7": "First dynamic evidence provider",
        "M8": "Dependency compatibility",
        "M9": "Hosted GitHub private beta",
        "M10": "C API roadmap",
    }
    for number in range(2, 11):
        identifier = f"M{number}"
        if number <= 6:
            policy = "unattended"
        elif number <= 8:
            policy = "gate_c"
        elif number == 9:
            policy = "external_repository"
        else:
            policy = "design_required"
        lines = [
            "[[milestone]]",
            f'id = "{identifier}"',
            f'title = "{titles[identifier]}"',
            f'heading = "{identifier} — {titles[identifier]}"',
            f'policy = "{policy}"',
            "extra_verification = []",
        ]
        if identifier == "M6":
            lines[-1] = (
                'extra_verification = ["m6-wheel-install", '
                '"m6-sdist-install", "m6-benchmark"]'
            )
            lines.append('hosted_verification = "m6-supported-hosts"')
            lines.append("requires_publication = true")
            lines.append('stop_after_gate = "C"')
        if identifier == "M10":
            lines.append('required_design = "docs/c-api-design.md"')
        records.append("\n".join(lines))
    return "\n\n".join(records)


def _write_config(
    root: Path,
    *,
    default_timeout_seconds: int,
    git_command: Sequence[str],
    real_git: str,
    verification_code: str,
) -> None:
    """Write a small strict policy using only local deterministic commands."""
    content = f"""schema_version = 1
state_directory = ".autopilot"
base_branch = "main"
remote = "origin"
default_timeout_seconds = {default_timeout_seconds}
codex_timeout_seconds = 10
max_repair_cycles = 3
branch_template = "codex/{{from_slug}}-{{through_slug}}-autopilot"
commit_template = "Implement {{milestone}}: {{title}}"

[tools]
codex = {_toml_array([sys.executable, str(FAKE_CODEX)])}
git = {_toml_array(git_command)}
gh = {_toml_array([sys.executable, str(FAKE_GH)])}

[[protected_path]]
path = "automation"
allow_for = []

[[protected_path]]
path = "scripts/autopilot.py"
allow_for = []

[[protected_path]]
path = "docs/design.md"
allow_for = []

[[protected_path]]
path = "AGENTS.md"
allow_for = []

[[protected_path]]
path = ".github/workflows"
allow_for = ["M6"]

[[quality_guard]]
path = "pyproject.toml"
tables = [
  "tool.ruff",
  "tool.mypy",
  "tool.pytest.ini_options",
  "tool.coverage.run",
  "tool.coverage.report",
]
allow_for = []

[[quality_guard]]
path = "pyproject.toml"
tables = ["build-system", "tool.hatch"]
allow_for = ["M6"]

[[verification]]
id = "fixture-check"
command = {_toml_array([sys.executable, "-c", verification_code])}
timeout_seconds = 2

[[verification]]
id = "diff-check"
command = {_toml_array([real_git, "diff", "--check"])}
timeout_seconds = 2

[[milestone_verification]]
id = "m6-wheel-install"
command = {_toml_array([sys.executable, "-c", "raise SystemExit(0)"])}
timeout_seconds = 2

[[milestone_verification]]
id = "m6-sdist-install"
command = {_toml_array([sys.executable, "-c", "raise SystemExit(0)"])}
timeout_seconds = 2

[[milestone_verification]]
id = "m6-benchmark"
command = {_toml_array([sys.executable, "-c", "raise SystemExit(0)"])}
timeout_seconds = 2

[[hosted_verification]]
id = "m6-supported-hosts"
workflow = "CI"
dispatch_input = "pyahead_autopilot_token"
required_jobs = ["fixture-hosted"]
# The fake GitHub CLI starts several Python and Git subprocesses.  Keep this
# bounded, but allow enough time for process startup on slower Windows runners.
timeout_seconds = 30
poll_interval_seconds = 0.01

{_milestone_toml()}
"""
    (root / "automation/milestones.toml").write_text(content, encoding="utf-8")


def _design_text() -> str:
    """Build exact temporary milestone contracts for M2-M10."""
    titles = (
        "Registry and matcher framework",
        "Version timeline and reachability",
        "Project configuration and CI reports",
        "CPython registry curation",
        "Public-alpha hardening",
        "First dynamic evidence provider",
        "Dependency compatibility",
        "Hosted GitHub private beta",
        "C API roadmap",
    )
    sections = ["# Fixture design", "", "## 26. Backlog", ""]
    for number, title in enumerate(titles, start=2):
        sections.extend(
            [
                f"### M{number} — {title}",
                "",
                "Deliverables:",
                f"- Deterministic fixture deliverable for M{number}.",
                "",
                "Acceptance:",
                f"- The M{number} fixture is independently verified.",
                "",
            ]
        )
    return "\n".join(sections)


def _create_repository(  # noqa: PLR0915 - setup mirrors real preconditions.
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    default_timeout_seconds: int = 10,
    verification_code: str = DEFAULT_VERIFICATION,
    fail_push_once: bool = False,
) -> RepositoryFixture:
    """Create a clean main branch exactly tracking a local bare origin."""
    real_git = shutil.which("git")
    if real_git is None:
        pytest.skip("Git is required for orchestrator integration tests")
    root = tmp_path / "repo"
    origin = tmp_path / "origin.git"
    control = tmp_path / "control"
    root.mkdir()
    control.mkdir()
    shutil.copytree(SOURCE_ROOT / "automation", root / "automation")
    (root / "scripts").mkdir()
    shutil.copy2(SOURCE_ROOT / "scripts/autopilot.py", root / "scripts/autopilot.py")
    shutil.copy2(SOURCE_ROOT / "scripts/__init__.py", root / "scripts/__init__.py")
    (root / "docs").mkdir()
    (root / "docs/design.md").write_text(_design_text(), encoding="utf-8")
    (root / "AGENTS.md").write_text(
        "Implement only the frozen milestone; never alter the automation harness.\n",
        encoding="utf-8",
    )
    (root / ".gitignore").write_text(".autopilot/\n", encoding="utf-8")
    (root / "gate-evidence.md").write_text(
        "Fixture evidence reserved for explicit Gate C approval.\n",
        encoding="utf-8",
    )
    workflows = root / ".github/workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: fixture\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """[build-system]
requires = []
build-backend = "fixture"

[tool.hatch]
fixture = true

[tool.ruff]
line-length = 88

[tool.mypy]
strict = true

[tool.pytest.ini_options]
addopts = []

[tool.coverage.run]
branch = true

[tool.coverage.report]
fail_under = 90
""",
        encoding="utf-8",
    )
    git_command: Sequence[str] = [sys.executable, str(FAKE_GIT)]
    fail_sentinel = control / "fail-push-once"
    if fail_push_once:
        fail_sentinel.write_text("fail exactly once\n", encoding="utf-8")
    _write_config(
        root,
        default_timeout_seconds=default_timeout_seconds,
        git_command=git_command,
        real_git=real_git,
        verification_code=verification_code,
    )
    _run([real_git, "init", "--initial-branch=main", str(root)])
    _run([real_git, "config", "user.name", "PyAhead Test"], cwd=root)
    _run([real_git, "config", "user.email", "pyahead@example.invalid"], cwd=root)
    _run([real_git, "add", "."], cwd=root)
    _run([real_git, "commit", "-m", "fixture base"], cwd=root)
    _run([real_git, "init", "--bare", str(origin)])
    remote_url = "https://github.com/example/pyahead.git"
    _run([real_git, "remote", "add", "origin", remote_url], cwd=root)
    _run([real_git, "push", str(origin), "main:main"], cwd=root)
    _run([real_git, "update-ref", "refs/remotes/origin/main", "HEAD"], cwd=root)
    _run([real_git, "config", "branch.main.remote", "origin"], cwd=root)
    _run([real_git, "config", "branch.main.merge", "refs/heads/main"], cwd=root)
    _run(
        [real_git, "--git-dir", str(origin), "symbolic-ref", "HEAD", "refs/heads/main"]
    )

    plan_path = control / "codex-plan.json"
    counter_path = control / "codex-counter.json"
    codex_events_path = control / "codex-events.json"
    gh_events_path = control / "gh-events.json"
    gh_run_plan_path = control / "gh-run-plan.json"
    gh_run_state_path = control / "gh-run-state.json"
    git_events_path = control / "git-events.json"
    git_global_config_path = control / "gitconfig"
    git_global_config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_PLAN", str(plan_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_STATE", str(counter_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_EVENTS", str(codex_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_EVENTS", str(gh_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_RUN_PLAN", str(gh_run_plan_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_RUN_STATE", str(gh_run_state_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GIT", real_git)
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_REAL", real_git)
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_GLOBAL_CONFIG", str(git_global_config_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_REMOTE", str(origin))
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_EVENTS", str(git_events_path))
    if fail_push_once:
        monkeypatch.setenv("PYAHEAD_FAKE_GIT_FAIL_PUSH", str(fail_sentinel))
    else:
        monkeypatch.delenv("PYAHEAD_FAKE_GIT_FAIL_PUSH", raising=False)
    return RepositoryFixture(
        root=root,
        origin=origin,
        plan_path=plan_path,
        counter_path=counter_path,
        codex_events_path=codex_events_path,
        gh_events_path=gh_events_path,
        gh_run_plan_path=gh_run_plan_path,
        gh_run_state_path=gh_run_state_path,
        git_events_path=git_events_path,
        git=real_git,
    )


@pytest.fixture
def repo_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[..., RepositoryFixture]:
    """Return an isolated-repository factory for one test case."""

    def factory(**kwargs: object) -> RepositoryFixture:
        return _create_repository(tmp_path, monkeypatch, **kwargs)

    return factory


def _success_actions(
    *,
    content: str = "implemented\n",
    milestone: str = "M2",
) -> list[dict[str, object]]:
    """Return one implementation and one independent passing review."""
    return [
        {
            "role": "implementation",
            "outcome": "completed",
            "changes": {"feature.txt": content},
            "refresh_index": "AGENTS.md",
            "milestone": milestone,
        },
        {"role": "review", "outcome": "pass", "milestone": milestone},
    ]


def _run_one(pilot: autopilot.Autopilot) -> autopilot.ExitCode:
    """Run the M2 fixture without publication."""
    return pilot.run(
        "M2",
        "M2",
        push=False,
        draft_pr=False,
        dry_run=False,
    )


def test_range_parsing_and_policy_refusals(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Ranges are ordered, known, and policy-checked before mutation."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()

    assert [item.identifier for item in pilot.select_range("M2", "M6")] == [
        "M2",
        "M3",
        "M4",
        "M5",
        "M6",
    ]
    with pytest.raises(autopilot.InvalidInputError, match="reverse"):
        pilot.select_range("M6", "M2")
    with pytest.raises(autopilot.InvalidInputError, match="unknown"):
        pilot.select_range("M11", "M11")
    with pytest.raises(autopilot.BlockedError, match="separate private"):
        pilot.select_range("M9", "M9")
    with pytest.raises(autopilot.BlockedError, match="c-api-design"):
        pilot.select_range("M10", "M10")
    assert not (fixture.root / ".autopilot").exists()


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            'policy = "external_repository"',
            'policy = "unattended"',
            "unsafe automation policy",
        ),
        ('path = "AGENTS.md"', 'path = "AGENTS-renamed.md"', "protected paths"),
        (
            'id = "fixture-check"',
            'id = "../../escape"',
            "safe filename identifier",
        ),
        (
            'state_directory = ".autopilot"',
            'state_directory = ".git/autopilot"',
            "state_directory must be .autopilot",
        ),
        (
            "requires_publication = true",
            "requires_publication = false",
            "unsafe publication policy",
        ),
        (
            (
                'extra_verification = ["m6-wheel-install", '
                '"m6-sdist-install", "m6-benchmark"]'
            ),
            "extra_verification = []",
            "missing required artifact or benchmark",
        ),
    ],
)
def test_config_cannot_weaken_fixed_safety_policy(
    repo_factory: Callable[..., RepositoryFixture],
    old: str,
    new: str,
    message: str,
) -> None:
    """Repository policy remains configurable without making hard gates optional."""
    fixture = repo_factory()
    config_path = fixture.root / "automation/milestones.toml"
    content = config_path.read_text(encoding="utf-8")
    assert old in content
    config_path.write_text(content.replace(old, new, 1), encoding="utf-8")

    with pytest.raises(autopilot.InvalidInputError, match=message):
        autopilot.load_config(fixture.root)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--help"],
        ["doctor", "--help"],
        ["plan", "--help"],
        ["run", "--help"],
        ["status", "--help"],
        ["resume", "--help"],
        ["gate", "--help"],
        ["gate", "approve", "--help"],
        ["gate", "status", "--help"],
    ],
)
def test_every_command_has_useful_help(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every operator command exposes argparse-managed usage without side effects."""
    with pytest.raises(SystemExit) as exit_info:
        autopilot.build_parser().parse_args(arguments)

    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "usage:" in help_text
    assert "-h, --help" in help_text


@pytest.mark.parametrize(
    "value",
    [
        _HOSTILE_OPERATOR_TEXT,
        "normal café 雪 🚀",
        "surrogate\ud800value",
        "tag\U000e0001value",
    ],
)
def test_standalone_terminal_boundary_matches_the_product(value: str) -> None:
    """The bare controller duplicates semantics, not mutable package imports."""
    assert autopilot._escape_terminal_text(value) == escape_terminal_text(value)  # noqa: SLF001


def test_standalone_parser_escapes_untrusted_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bare-Python argparse failures cannot forge operator records."""
    with pytest.raises(SystemExit) as raised:
        autopilot.build_parser().parse_args(["status", _HOSTILE_OPERATOR_TEXT])

    assert raised.value.code == int(autopilot.ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _HOSTILE_OPERATOR_TEXT not in captured.err
    assert escape_terminal_text(_HOSTILE_OPERATOR_TEXT) in captured.err


def test_exit_codes_are_stable_and_documented() -> None:
    """The public result taxonomy remains fixed for scripts and operators."""
    assert {member.name: int(member) for member in autopilot.ExitCode} == {
        "SUCCESS": 0,
        "INVALID_INPUT": 2,
        "BLOCKED": 3,
        "FAILED": 4,
        "INTERRUPTED": 5,
        "STATE_ERROR": 6,
        "PUBLICATION_FAILED": 7,
    }
    help_text = autopilot.build_parser().format_help()
    for code in (0, 2, 3, 4, 5, 6, 7):
        assert f"{code} " in help_text


def test_contract_extraction_is_exact_and_deterministic() -> None:
    """Only the configured milestone subsection becomes the frozen contract."""
    milestone = autopilot.Milestone(
        identifier="M2",
        title="Registry",
        heading="M2 — Registry",
        policy="unattended",
        extra_verification=(),
        hosted_verification=None,
        requires_publication=False,
        stop_after_gate=None,
        required_design=None,
    )
    design = (
        "# Design\n\n### M2 — Registry\n\nDeliverables:\n- A.\n\n"
        "Acceptance:\n- Verified.\n\n"
        "### M3 — Next\nDeliverables:\n- B.\n"
    )

    contract = autopilot.extract_milestone_contract(design, milestone)

    assert contract == (
        "### M2 — Registry\n\nDeliverables:\n- A.\n\nAcceptance:\n- Verified.\n"
    )
    assert autopilot.sha256_text(contract) == autopilot.sha256_text(contract)
    with pytest.raises(autopilot.InvalidInputError, match="found 2"):
        autopilot.extract_milestone_contract(design + design, milestone)
    with pytest.raises(autopilot.InvalidInputError, match="no deliverables"):
        autopilot.extract_milestone_contract("### M2 — Registry\nNone.\n", milestone)
    with pytest.raises(autopilot.InvalidInputError, match="no acceptance criteria"):
        autopilot.extract_milestone_contract(
            "### M2 — Registry\nDeliverables:\n- A.\n",
            milestone,
        )


def test_prompt_rendering_requires_every_value() -> None:
    """Prompt substitution is deterministic and rejects missing contract inputs."""
    rendered = autopilot.render_prompt(
        "$role:$contract", {"role": "review", "contract": "M2"}
    )
    assert rendered == "review:M2"
    with pytest.raises(autopilot.InvalidInputError, match="missing value"):
        autopilot.render_prompt("$role:$contract", {"role": "review"})


def test_strict_result_parsing_rejects_schema_and_semantic_drift(
    tmp_path: Path,
) -> None:
    """Structured results must be closed-world and consistent with Git evidence."""
    implementation_path = tmp_path / "implementation.json"
    implementation = {
        "milestone": "M2",
        "status": "completed",
        "summary": "done",
        "files_changed": ["feature.txt"],
        "acceptance_criteria_addressed": ["fixture"],
        "commands_reportedly_run": [],
        "limitations": [],
        "blocking_reason": None,
    }
    implementation_path.write_text(json.dumps(implementation), encoding="utf-8")
    parsed = autopilot.parse_implementation_result(
        implementation_path,
        "M2",
        ["feature.txt"],
    )
    assert parsed.status == "completed"

    implementation["unexpected"] = True
    implementation_path.write_text(json.dumps(implementation), encoding="utf-8")
    with pytest.raises(autopilot.InvalidInputError, match="properties"):
        autopilot.parse_implementation_result(
            implementation_path,
            "M2",
            ["feature.txt"],
        )
    implementation.pop("unexpected")
    implementation["files_changed"] = ["other.txt"]
    implementation_path.write_text(json.dumps(implementation), encoding="utf-8")
    with pytest.raises(autopilot.InvalidInputError, match="contradicts"):
        autopilot.parse_implementation_result(
            implementation_path,
            "M2",
            ["feature.txt"],
        )

    review_path = tmp_path / "review.json"
    review_path.write_text(
        json.dumps(
            {
                "milestone": "M2",
                "verdict": "pass",
                "findings": [
                    {
                        "severity": "low",
                        "file": "feature.txt",
                        "line": 1,
                        "explanation": "contradiction",
                        "required_remediation": "none",
                    }
                ],
                "acceptance_evidence_inspected": ["logs"],
                "blocking_reason": None,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(autopilot.InvalidInputError, match="passing review"):
        autopilot.parse_review_result(review_path, "M2")

    review_path.write_text(
        json.dumps(
            {
                "milestone": "M2",
                "verdict": "pass",
                "findings": [],
                "acceptance_evidence_inspected": [],
                "blocking_reason": None,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(autopilot.InvalidInputError, match="requires inspected"):
        autopilot.parse_review_result(review_path, "M2")

    review_path.write_text(
        '{"milestone":"M2","milestone":"M3"}',
        encoding="utf-8",
    )
    with pytest.raises(autopilot.InvalidInputError, match="missing or malformed"):
        autopilot.parse_review_result(review_path, "M2")

    symlink_path = tmp_path / "result-link.json"
    try:
        symlink_path.symlink_to(review_path)
    except OSError:
        pass
    else:
        with pytest.raises(autopilot.InvalidInputError, match="required structured"):
            autopilot.parse_review_result(symlink_path, "M2")


def test_codex_schemas_use_portable_constraints_with_local_semantic_validation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """API schemas stay portable while the parent preserves stricter semantics."""
    fixture = repo_factory()
    fixture.make_autopilot().doctor()

    implementation_path = fixture.root / "implementation.json"
    implementation_path.write_text(
        json.dumps(
            {
                "milestone": "M2",
                "status": "completed",
                "summary": "done",
                "files_changed": ["feature.txt", "feature.txt"],
                "acceptance_criteria_addressed": ["fixture"],
                "commands_reportedly_run": [],
                "limitations": [],
                "blocking_reason": None,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(autopilot.InvalidInputError, match="duplicates"):
        autopilot.parse_implementation_result(
            implementation_path, "M2", ["feature.txt"]
        )


def test_doctor_rejects_an_api_incompatible_output_schema(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Unsupported strict-schema keywords fail locally before a Codex request."""
    fixture = repo_factory()
    schema_path = fixture.root / autopilot.IMPLEMENTATION_SCHEMA
    schema = cast("dict[str, object]", json.loads(schema_path.read_text()))
    properties = cast("dict[str, object]", schema["properties"])
    files_changed = cast("dict[str, object]", properties["files_changed"])
    files_changed["uniqueItems"] = True
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    with pytest.raises(autopilot.InvalidInputError, match="uniqueItems"):
        fixture.make_autopilot().doctor()


def test_successful_implement_verify_review_commit_flow(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A milestone commits only after parent verification and an isolated pass."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())

    outcome = _run_one(fixture.make_autopilot())

    assert outcome is autopilot.ExitCode.SUCCESS
    state = fixture.state()
    assert state["current_phase"] == "complete"
    completed = cast("list[dict[str, object]]", state["completed_commits"])
    assert len(completed) == 1
    assert completed[0]["milestone"] == "M2"
    assert len(cast("list[object]", completed[0]["verification"])) == 2
    events = fixture.codex_events()
    assert [event["role"] for event in events] == ["implementation", "review"]
    assert [event["sandbox"] for event in events] == ["workspace-write", "read-only"]
    assert all(event["approval"] == "never" for event in events)
    assert all(
        cast("list[str]", event["arguments"])[2:4]
        == ["--config", 'approval_policy="never"']
        for event in events
    )
    assert all(event["child_marker"] == "1" for event in events)
    log = _run([fixture.git, "log", "-1", "--format=%B"], cwd=fixture.root).stdout
    assert "Implement M2: Registry and matcher framework" in log
    assert "PyAhead-Milestone: M2" in log
    assert _run([fixture.git, "status", "--porcelain"], cwd=fixture.root).stdout == ""


def test_verification_failure_starts_fresh_repair(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Failed independent evidence reaches a fresh fixer before a new review."""
    verification = (
        "from pathlib import Path; "
        "raise SystemExit(0 if Path('feature.txt').read_text() == 'fixed\\n' else 1)"
    )
    fixture = repo_factory(verification_code=verification)
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "broken\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "fixed\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )

    assert _run_one(fixture.make_autopilot()) is autopilot.ExitCode.SUCCESS

    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "review",
    ]
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert completed[0]["repair_cycles"] == 1
    repair_prompt = next((fixture.root / ".autopilot/runs").rglob("M2-repair-1.md"))
    prompt_text = repair_prompt.read_text(encoding="utf-8")
    assert "independent verification failed" not in prompt_text
    assert "Return code: 1" in prompt_text


def test_review_requested_change_starts_fresh_repair_and_review(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Concrete review findings are the only review input supplied to a fixer."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "first\n"},
            },
            {"role": "review", "outcome": "changes_requested"},
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "second\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )

    assert _run_one(fixture.make_autopilot()) is autopilot.ExitCode.SUCCESS

    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
        "repair",
        "review",
    ]
    repair_prompt = next((fixture.root / ".autopilot/runs").rglob("M2-repair-1.md"))
    prompt_text = repair_prompt.read_text(encoding="utf-8")
    assert "fixture review finding" in prompt_text
    assert "replace the fixture content" in prompt_text


def test_blocked_agent_result_stops_without_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A child-reported blocker is preserved as an explicit stopped phase."""
    fixture = repo_factory()
    fixture.set_plan([{"role": "implementation", "outcome": "blocked"}])
    pilot = fixture.make_autopilot()

    with pytest.raises(autopilot.BlockedError, match="fixture blocked"):
        _run_one(pilot)

    assert fixture.state()["current_phase"] == "blocked"
    assert (
        len(
            _run(
                [fixture.git, "rev-list", "--count", "HEAD"], cwd=fixture.root
            ).stdout.strip()
        )
        > 0
    )
    assert (
        _run(
            [fixture.git, "rev-list", "--count", "HEAD"], cwd=fixture.root
        ).stdout.strip()
        == "1"
    )


def test_blocked_reviewer_result_stops_without_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """An independent external blocker remains distinct from requested repairs."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate\n"},
            },
            {"role": "review", "outcome": "blocked"},
        ]
    )

    with pytest.raises(autopilot.BlockedError, match="reviewer blocker"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "blocked"
    assert (
        _run(
            [fixture.git, "rev-list", "--count", "HEAD"], cwd=fixture.root
        ).stdout.strip()
        == "1"
    )


@pytest.mark.parametrize("behavior", ["malformed", "missing"])
def test_malformed_or_missing_implementation_output_is_repaired(
    repo_factory: Callable[..., RepositoryFixture],
    behavior: str,
) -> None:
    """Bad structured output never bypasses parsing and can enter a bounded repair."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "behavior": behavior,
                "changes": {"feature.txt": "partial\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "repaired\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )

    assert _run_one(fixture.make_autopilot()) is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "review",
    ]


@pytest.mark.parametrize("behavior", ["malformed", "missing"])
def test_malformed_or_missing_review_output_fails_closed(
    repo_factory: Callable[..., RepositoryFixture],
    behavior: str,
) -> None:
    """An invalid independent decision cannot be converted into a passing review."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate\n"},
            },
            {"role": "review", "behavior": behavior},
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="review structured result"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "agent_failed"
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
    ]


def test_maximum_repair_cycle_exhaustion(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A fourth repair is never launched after three failed repair cycles."""
    fixture = repo_factory(verification_code="raise SystemExit(1)")
    actions: list[dict[str, object]] = [
        {
            "role": "implementation",
            "outcome": "completed",
            "changes": {"feature.txt": "initial\n"},
        }
    ]
    actions.extend(
        {
            "role": "repair",
            "outcome": "completed",
            "changes": {"feature.txt": f"repair {number}\n"},
        }
        for number in range(1, 4)
    )
    fixture.set_plan(actions)

    with pytest.raises(autopilot.AutopilotError, match="maximum repair-cycle"):
        _run_one(fixture.make_autopilot())

    state = fixture.state()
    assert state["current_phase"] == "repair_exhausted"
    assert state["repair_count"] == 3
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "repair",
        "repair",
    ]


def test_protected_file_modification_stops_and_preserves_work(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Protected governance edits stop safely and are never auto-reverted."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"AGENTS.md": "suspicious edit\n"},
            }
        ]
    )

    with pytest.raises(autopilot.StateError, match="protected files"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "blocked"
    assert (fixture.root / "AGENTS.md").read_text(
        encoding="utf-8"
    ) == "suspicious edit\n"
    assert (
        "AGENTS.md"
        in _run(
            [fixture.git, "status", "--porcelain"],
            cwd=fixture.root,
        ).stdout
    )


def test_git_metadata_modification_stops_before_parent_git_mutation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A child cannot redirect remotes, install hooks, or alter Git control data."""
    fixture = repo_factory()
    config_path = fixture.root / ".git/config"
    original_config = config_path.read_text(encoding="utf-8")
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {".git/config": original_config + "# child edit\n"},
            }
        ]
    )

    with pytest.raises(autopilot.StateError, match="modified Git metadata"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "blocked"
    assert config_path.read_text(encoding="utf-8").endswith("# child edit\n")


def test_git_metadata_digest_ignores_stat_cache_but_protects_semantic_index(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Read-only index refreshes pass while flags and staged blobs remain guarded."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    baseline = pilot.git.metadata_digest()
    index_path = fixture.root / ".git/index"
    raw_index_before = index_path.read_bytes()
    tracked = fixture.root / "AGENTS.md"
    metadata = tracked.stat()
    os.utime(
        tracked,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
    )

    _run([fixture.git, "update-index", "--refresh"], cwd=fixture.root)

    assert index_path.read_bytes() != raw_index_before
    assert pilot.git.metadata_digest() == baseline

    _run(
        [fixture.git, "update-index", "--skip-worktree", "AGENTS.md"],
        cwd=fixture.root,
    )
    assert pilot.git.metadata_digest() != baseline
    _run(
        [fixture.git, "update-index", "--no-skip-worktree", "AGENTS.md"],
        cwd=fixture.root,
    )
    assert pilot.git.metadata_digest() == baseline

    tracked.write_text("staged child edit\n", encoding="utf-8")
    _run([fixture.git, "add", "--", "AGENTS.md"], cwd=fixture.root)
    assert pilot.git.metadata_digest() != baseline


def test_child_cannot_manufacture_gate_c_approval(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Ignored external-gate state is protected across every child boundary."""
    fixture = repo_factory()
    fabricated = json.dumps(
        {
            "schema_version": 1,
            "gates": {
                "C": {
                    "approved_by": "child",
                    "approved_at": "2099-01-01T00:00:00+00:00",
                    "evidence_path": "gate-evidence.md",
                    "evidence_sha256": "0" * 64,
                }
            },
        }
    )
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {
                    "feature.txt": "candidate\n",
                    ".autopilot/gates.json": fabricated,
                },
            }
        ]
    )

    with pytest.raises(autopilot.StateError, match="Gate C approval record"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "blocked"
    assert (fixture.root / ".autopilot/gates.json").read_text(
        encoding="utf-8"
    ) == fabricated


def test_repository_environment_discards_inherited_git_redirection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Parent and child Git operations cannot inherit another repository target."""
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "not-this-repository"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "not-this-worktree"))
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.worktree")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(tmp_path / "not-this-worktree"))
    monkeypatch.setenv("GIT_ASKPASS", str(tmp_path / "askpass"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "global-config"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "system-config"))
    monkeypatch.setenv("GIT_SSH_COMMAND", "sh -c 'touch redirected'")
    monkeypatch.setenv("SSH_ASKPASS", str(tmp_path / "ssh-askpass"))
    monkeypatch.setenv("SSH_ASKPASS_REQUIRE", "force")
    monkeypatch.setenv("GH_REPO", "attacker/other")
    monkeypatch.setenv("GH_HOST", "example.invalid")
    monkeypatch.setenv("GH_CONFIG_DIR", str(tmp_path / "gh-config"))
    monkeypatch.setenv("GH_TOKEN", "fixture-token")

    environment = autopilot._repository_environment()  # noqa: SLF001

    assert "GIT_DIR" not in environment
    assert "GIT_WORK_TREE" not in environment
    assert environment["GIT_CONFIG_KEY_0"] == "credential.interactive"
    assert environment["GIT_CONFIG_VALUE_0"] == "false"
    assert "GIT_ASKPASS" not in environment
    assert "GIT_CONFIG_GLOBAL" not in environment
    assert "GIT_CONFIG_SYSTEM" not in environment
    assert "GIT_SSH_COMMAND" not in environment
    assert "SSH_ASKPASS" not in environment
    assert "SSH_ASKPASS_REQUIRE" not in environment
    assert "GH_REPO" not in environment
    assert "GH_HOST" not in environment
    assert "GH_CONFIG_DIR" not in environment
    assert environment["GH_TOKEN"] == "fixture" + "-token"
    assert environment["GH_PROMPT_DISABLED"] == "1"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


def test_publication_rejects_a_push_url_for_another_repository(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A separate Git push URL cannot redirect candidate or checkpoint writes."""
    fixture = repo_factory()
    _run(
        [
            fixture.git,
            "config",
            "remote.origin.pushurl",
            "https://github.com/attacker/other.git",
        ],
        cwd=fixture.root,
    )

    with pytest.raises(autopilot.InvalidInputError, match="different repositories"):
        fixture.make_autopilot().doctor(publication=True)

    assert not fixture.gh_events_path.exists()


def test_publication_rejects_an_effectively_redirected_https_transport(
    repo_factory: Callable[..., RepositoryFixture],
    tmp_path: Path,
) -> None:
    """Repository config cannot redirect the validated HTTPS URL to another remote."""
    fixture = repo_factory()
    attacker = tmp_path / "attacker.git"
    _run([fixture.git, "init", "--bare", str(attacker)])
    _run(
        [
            fixture.git,
            "config",
            f"url.{attacker.as_posix()}.insteadOf",
            "https://github.com/example/pyahead.git",
        ],
        cwd=fixture.root,
    )

    with pytest.raises(autopilot.InvalidInputError, match=r"transport.*redirected"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert not (fixture.root / ".autopilot/state.json").exists()
    assert (
        _run(
            [fixture.git, "--git-dir", str(attacker), "show-ref"], check=False
        ).returncode
        == 1
    )


def test_dirty_worktree_refusal_precedes_branch_or_state_mutation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A normal run rejects unrelated changes without creating its range branch."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    (fixture.root / "unrelated.txt").write_text("operator work\n", encoding="utf-8")

    with pytest.raises(autopilot.StateError, match="dirty worktree"):
        _run_one(fixture.make_autopilot())

    assert not (fixture.root / ".autopilot/state.json").exists()
    assert (
        _run(
            [fixture.git, "branch", "--show-current"],
            cwd=fixture.root,
        ).stdout.strip()
        == "main"
    )


def test_symlinked_runtime_directory_is_refused_without_external_write(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Ignored state cannot redirect atomic writes outside the repository."""
    fixture = repo_factory()
    outside = fixture.root.parent / "outside-state"
    outside.mkdir()
    try:
        (fixture.root / ".autopilot").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the platform does not permit test symlinks")

    with pytest.raises(autopilot.StateError, match="traverses a symlink"):
        fixture.make_autopilot()

    assert list(outside.iterdir()) == []


def test_child_timeout_is_an_explicit_logged_failure(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Timed-out Codex sessions stop with state and complete separated logs."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "sleep_seconds": 1,
                "changes": {"feature.txt": "too late\n"},
            }
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="session failed"):
        fixture.make_autopilot().run(
            "M2",
            "M2",
            push=False,
            draft_pr=False,
            dry_run=False,
            timeout_override=0.05,
        )

    state = fixture.state()
    assert state["current_phase"] == "agent_failed"
    assert state["failed_output_path"] is None
    process_failures = cast("list[dict[str, object]]", state["agent_process_failures"])
    failure_path = fixture.root / cast("str", process_failures[0]["path"])
    assert "timed out" in failure_path.read_text(encoding="utf-8")
    logs = list((fixture.root / ".autopilot/runs").rglob("M2-implementation-0.*.log"))
    assert len(logs) == 2


def test_failed_implementation_process_resumes_in_a_fresh_session(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A failed implementer preserves edits and receives a unique retry path."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "behavior": "exit_failure",
                "changes": {"feature.txt": "partial\n"},
            },
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "complete\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="session failed"):
        _run_one(fixture.make_autopilot())

    assert fixture.state()["current_phase"] == "agent_failed"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "implementation",
        "review",
    ]
    assert next(
        (fixture.root / ".autopilot/runs").rglob("M2-implementation-0-retry-1.json")
    ).is_file()
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert completed[0]["repair_cycles"] == 0
    assert (fixture.root / "feature.txt").read_text(encoding="utf-8") == "complete\n"


def test_failed_repair_process_retries_the_same_repair_cycle(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A fixer retry retains the original failed verification and partial edits."""
    verification = (
        "from pathlib import Path; "
        "raise SystemExit(0 if Path('feature.txt').read_text() == "
        "'partial repair\\n' else 1)"
    )
    fixture = repo_factory(verification_code=verification)
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate\n"},
            },
            {
                "role": "repair",
                "behavior": "exit_failure",
                "changes": {"feature.txt": "partial repair\n"},
            },
            {"role": "repair", "outcome": "completed", "changes": {}},
            {"role": "review", "outcome": "pass"},
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="session failed"):
        _run_one(fixture.make_autopilot())

    failed_state = fixture.state()
    assert failed_state["current_phase"] == "agent_failed"
    assert failed_state["repair_count"] == 1
    semantic_failure = fixture.root / cast("str", failed_state["failed_output_path"])
    semantic_text = semantic_failure.read_text(encoding="utf-8")
    assert semantic_text.startswith("Command: ")
    assert "\nReturn code: 1\n" in semantic_text
    assert "\nSTDOUT:\n" in semantic_text
    assert "\nSTDERR:\n" in semantic_text
    process_failures = cast(
        "list[dict[str, object]]", failed_state["agent_process_failures"]
    )
    assert len(process_failures) == 1
    assert process_failures[0]["path"] != failed_state["failed_output_path"]
    process_failure_path = fixture.root / cast("str", process_failures[0]["path"])
    process_failure_text = process_failure_path.read_text(encoding="utf-8")
    assert process_failure_text.splitlines()[0].startswith("Command: ")
    assert process_failures[0]["sha256"] == autopilot.sha256_text(process_failure_text)
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "repair",
        "review",
    ]
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert completed[0]["repair_cycles"] == 1
    assert (fixture.root / "feature.txt").read_text(encoding="utf-8") == (
        "partial repair\n"
    )
    assert next(
        (fixture.root / ".autopilot/runs").rglob("M2-repair-1-retry-1.json")
    ).is_file()
    retry_prompt = next(
        (fixture.root / ".autopilot/runs").rglob("M2-repair-1-retry-1.md")
    ).read_text(encoding="utf-8")
    assert "Return code: 1" in retry_prompt


def test_failed_hosted_fixer_retry_retains_original_job_log_paths(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A failed fixer resumes with the complete oversized hosted fallback log."""
    fixture = repo_factory(default_timeout_seconds=30)
    fallback_log = (
        "HOSTED-RESUME-START\n"
        + "z" * (autopilot.MAX_RESULT_BYTES + 1)
        + "\nHOSTED-RESUME-END\n"
    )
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            },
            {
                "role": "repair",
                "behavior": "exit_failure",
                "changes": {"feature.txt": "partial repair\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-one\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "failure",
                "jobs": [
                    {
                        "conclusion": "failure",
                        "databaseId": 101,
                        "log": fallback_log,
                        "log_run_view_empty": True,
                        "name": "fixture-hosted",
                        "status": "completed",
                        "url": (
                            "https://github.com/example/pyahead/actions/runs/"
                            "9001/job/101"
                        ),
                    }
                ],
            },
            {"status": "completed", "conclusion": "success"},
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="session failed"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    failed_state = fixture.state()
    assert failed_state["repair_count"] == 1
    semantic_failure = fixture.root / cast("str", failed_state["failed_output_path"])
    semantic_text = semantic_failure.read_text(encoding="utf-8")
    assert "Complete redacted failed-job logs" in semantic_text
    assert "M6-candidate-0-hosted-job-101-api.stdout.log" in semantic_text
    process_failures = cast(
        "list[dict[str, object]]", failed_state["agent_process_failures"]
    )
    assert process_failures[0]["path"] != failed_state["failed_output_path"]
    hosted_log = next(
        (fixture.root / ".autopilot/runs").rglob(
            "M6-candidate-0-hosted-job-101-api.stdout.log"
        )
    )
    hosted_text = hosted_log.read_text(encoding="utf-8")
    assert hosted_text.startswith("HOSTED-RESUME-START\\u000a")
    assert hosted_text.endswith("\\u000aHOSTED-RESUME-END\\u000a")
    hosted_base = hosted_log.with_name(hosted_log.name.removesuffix(".stdout.log"))
    _started, durable = fixture.make_autopilot()._read_command_evidence(  # noqa: SLF001
        hosted_base,
        (
            *autopilot.load_config(fixture.root).tools["gh"],
            "api",
            "--hostname",
            "github.com",
            "repos/example/pyahead/actions/jobs/101/logs",
        ),
    )
    assert durable is not None
    assert durable.process_succeeded
    assert durable.stdout_overflow
    assert durable.human_stdout_size == len(hosted_text.encode("utf-8"))

    hosted_evidence = cast("dict[str, object]", failed_state["hosted_evidence"])
    failure_logs = cast("list[dict[str, object]]", hosted_evidence["failure_logs"])
    started_path = fixture.root / cast("str", failure_logs[0]["started_log"])
    missing_started = started_path.with_suffix(started_path.suffix + ".missing")
    started_path.replace(missing_started)
    try:
        with pytest.raises(autopilot.StateError, match="incomplete"):
            fixture.make_autopilot()._validate_hosted_failure_log_records(  # noqa: SLF001
                failed_state,
                hosted_evidence,
            )
    finally:
        missing_started.replace(started_path)

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    retry_prompt = next(
        (fixture.root / ".autopilot/runs").rglob("M6-repair-1-retry-1.md")
    ).read_text(encoding="utf-8")
    assert "Complete redacted failed-job logs" in retry_prompt
    assert "M6-candidate-0-hosted-job-101-api.stdout.log" in retry_prompt


def test_failed_reviewer_process_resumes_in_a_fresh_read_only_session(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Review transport failure is retried without launching a fixer."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate\n"},
            },
            {"role": "review", "behavior": "exit_failure"},
            {"role": "review", "outcome": "pass"},
        ]
    )

    with pytest.raises(autopilot.AutopilotError, match="session failed"):
        _run_one(fixture.make_autopilot())

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    events = fixture.codex_events()
    assert [event["role"] for event in events] == [
        "implementation",
        "review",
        "review",
    ]
    assert events[-1]["sandbox"] == "read-only"


def test_command_runner_interruption_and_signal_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keyboard interruption is explicit, logged, and distinct from a signal."""

    class InterruptingProcess:
        returncode = -15
        pid = None

        def __init__(self) -> None:
            self.calls = 0
            self.terminated = False
            self.stdin = None
            self.stdout = BytesIO(b"partial stdout")
            self.stderr = BytesIO(b"partial stderr")

        def wait(self, timeout: float | None = None) -> int:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True

        def send_signal(self, _signal_number: int) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.returncode = -9

    process = InterruptingProcess()
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    log_base = tmp_path / "interrupted"

    with pytest.raises(autopilot.AutopilotInterruptedError):
        autopilot.CommandRunner().run(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            timeout_seconds=1,
            log_base=log_base,
        )

    assert process.terminated
    _started, _result, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    assert stdout_path.read_text() == "partial stdout"
    signaled = autopilot.CommandResult(("fixture",), -15, "", "", 0.0)
    assert signaled.signal_number == 15
    assert not signaled.succeeded


@pytest.mark.skipif(os.name == "nt", reason="Windows uses taskkill process-tree tests")
def test_timeout_terminates_spawned_process_group(tmp_path: Path) -> None:
    """A timed-out supervisor does not leave a grandchild editing afterward."""
    marker = tmp_path / "late-write"
    child = (
        "import time; from pathlib import Path; time.sleep(0.4); "
        f"Path({str(marker)!r}).write_text('escaped', encoding='utf-8')"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(10)"
    )

    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", parent],
        cwd=tmp_path,
        timeout_seconds=0.1,
    )
    time.sleep(0.6)

    assert result.timed_out
    assert not marker.exists()


@pytest.mark.parametrize("inherited_pipe", ["stdout", "stderr"])
@pytest.mark.parametrize("evidence_mode", ["memory", "rooted-logs"])
def test_deadline_includes_workers_held_by_an_exited_childs_grandchild(
    tmp_path: Path,
    inherited_pipe: str,
    evidence_mode: str,
) -> None:
    """Detached inherited pipes cannot outlive the one command deadline."""
    late_text = f"late-{inherited_pipe}"
    target = f"sys.{inherited_pipe}"
    grandchild = (
        "import sys,time; time.sleep(0.25); "
        f"{target}.write({late_text!r}); {target}.flush()"
    )
    discarded = "stderr" if inherited_pipe == "stdout" else "stdout"
    stream_arguments = f"{discarded}=subprocess.DEVNULL, stdin=subprocess.DEVNULL"
    detached = ", start_new_session=True" if os.name != "nt" else ""
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}], "
        f"{stream_arguments}{detached})"
    )
    log_base = (
        tmp_path / "logs" / inherited_pipe if evidence_mode == "rooted-logs" else None
    )

    started = time.monotonic()
    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", parent],
        cwd=tmp_path,
        timeout_seconds=0.05,
        log_base=log_base,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 0.75
    assert result.timed_out
    assert not result.succeeded
    assert late_text not in result.stdout
    assert late_text not in result.stderr
    retained: dict[Path, bytes] = {}
    if log_base is not None:
        evidence_paths = (
            *autopilot._command_evidence_paths(log_base),  # noqa: SLF001
            autopilot._command_output_path(log_base),  # noqa: SLF001
        )
        retained = {path: path.read_bytes() for path in evidence_paths}
        receipt = json.loads(
            autopilot._command_evidence_paths(log_base)[1].read_text(  # noqa: SLF001
                encoding="utf-8"
            )
        )
        assert receipt["timed_out"] is True

    time.sleep(0.35)

    assert all(path.read_bytes() == content for path, content in retained.items())
    assert not list(tmp_path.rglob(".*.tmp"))


def test_preloaded_process_input_is_delivered_completely(tmp_path: Path) -> None:
    """The immutable stdin staging path preserves exact prompt bytes and EOF."""
    prompt = "first line\nprintable unicode: café\n"

    result = autopilot.CommandRunner().run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ],
        cwd=tmp_path,
        timeout_seconds=1,
        input_text=prompt,
    )

    assert result.succeeded
    assert result.stdout == prompt


def test_detached_stdin_holder_cannot_publish_incomplete_input_evidence(
    tmp_path: Path,
) -> None:
    """Unconsumed staged stdin returns boundedly without late publication."""
    log_base = tmp_path / "logs" / "detached-stdin"
    log_base.parent.mkdir(parents=True)
    _started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    prior = {
        result_path: b"prior result receipt",
        output_path: b"prior machine sidecar",
        stdout_path: b"prior stdout",
        stderr_path: b"prior stderr",
    }
    for path, content in prior.items():
        path.write_bytes(content)
    holder = "import time; time.sleep(0.25)"
    detached = ", start_new_session=True" if os.name != "nt" else ""
    parent = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {holder!r}], "
        "stdin=sys.stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL"
        f"{detached})"
    )

    started = time.monotonic()
    with pytest.raises(
        autopilot.StateError,
        match="input consumption could not be confirmed",
    ):
        autopilot.CommandRunner().run(
            [sys.executable, "-c", parent],
            cwd=tmp_path,
            timeout_seconds=0.5,
            input_text="x" * (4 * 1024 * 1024),
            log_base=log_base,
        )
    elapsed = time.monotonic() - started

    assert elapsed < 0.75
    assert all(path.read_bytes() == content for path, content in prior.items())
    time.sleep(0.35)
    assert all(path.read_bytes() == content for path, content in prior.items())
    assert not list(log_base.parent.glob(".*.tmp"))


def test_deadline_never_waits_for_or_publishes_a_busy_stream_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worker holding the mutation lock leaves only unpublished temporaries."""
    entered = Event()
    release = Event()
    original_write = autopilot._RootedStreamingFile.write  # noqa: SLF001

    def blocked_write(
        stream: autopilot._RootedStreamingFile,
        content: bytes,
    ) -> None:
        if content and not entered.is_set():
            entered.set()
            release.wait(timeout=5)
        original_write(stream, content)

    monkeypatch.setattr(autopilot._RootedStreamingFile, "write", blocked_write)  # noqa: SLF001
    chunk_size = 32
    monkeypatch.setattr(autopilot, "_CAPTURE_CHUNK_BYTES", chunk_size)
    log_base = tmp_path / "logs" / "busy-worker"
    log_base.parent.mkdir(parents=True)
    started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    stdout_path.write_bytes(b"prior stdout")
    stderr_path.write_bytes(b"prior stderr")
    command = (
        sys.executable,
        "-c",
        (
            "import sys,time; "
            f"sys.stdout.buffer.write(b'x' * {chunk_size}); "
            "sys.stdout.buffer.flush(); time.sleep(2)"
        ),
    )

    started = time.monotonic()
    try:
        with pytest.raises(
            autopilot.StateError,
            match="could not be frozen at its deadline",
        ):
            autopilot.CommandRunner().run(
                command,
                cwd=tmp_path,
                timeout_seconds=0.3,
                log_base=log_base,
            )
        elapsed = time.monotonic() - started
        assert entered.is_set()
        assert elapsed < 1.2
        assert started_path.is_file()
        assert not result_path.exists()
        assert not autopilot._command_output_path(log_base).exists()  # noqa: SLF001
        assert stdout_path.read_bytes() == b"prior stdout"
        assert stderr_path.read_bytes() == b"prior stderr"
        assert list(log_base.parent.glob(".*.tmp"))
    finally:
        release.set()

    cleanup_deadline = time.monotonic() + 2
    while list(log_base.parent.glob(".*.tmp")) and time.monotonic() < cleanup_deadline:
        time.sleep(0.01)
    assert not list(log_base.parent.glob(".*.tmp"))
    assert not result_path.exists()
    assert not autopilot._command_output_path(log_base).exists()  # noqa: SLF001
    assert stdout_path.read_bytes() == b"prior stdout"
    assert stderr_path.read_bytes() == b"prior stderr"


def test_atomic_state_write_leaves_only_complete_document(tmp_path: Path) -> None:
    """State replacement produces canonical JSON and removes temporary files."""
    state_path = tmp_path / ".autopilot/state.json"
    autopilot.atomic_write_json(
        state_path, {"phase": "safe", "count": 2}, root=tmp_path
    )

    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "count": 2,
        "phase": "safe",
    }
    assert list(state_path.parent.glob(".*.tmp")) == []


def test_atomic_state_write_rejects_non_json_numbers(tmp_path: Path) -> None:
    """Persisted state cannot contain JSON's non-portable NaN extension."""
    state_path = tmp_path / ".autopilot/state.json"

    with pytest.raises(autopilot.StateError, match="not JSON serializable"):
        autopilot.atomic_write_json(state_path, {"timeout": float("nan")})
    assert not state_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-race regression")
def test_command_evidence_parent_swap_cannot_redirect_rooted_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-intent ancestor swap fails closed without writing outside the run."""
    logs = tmp_path / ".autopilot" / "runs" / "race" / "logs"
    logs.mkdir(parents=True)
    retained_logs = logs.with_name("logs-retained")
    outside = tmp_path / "outside"
    outside.mkdir()
    log_base = logs / "command"
    real_popen = subprocess.Popen

    def swap_after_process_creation(*args: object, **kwargs: object) -> object:
        intent = autopilot._command_intent_path(log_base)  # noqa: SLF001
        started = autopilot._command_evidence_paths(log_base)[0]  # noqa: SLF001
        assert intent.is_file()
        assert not started.exists()
        process = real_popen(*args, **kwargs)
        logs.rename(retained_logs)
        logs.symlink_to(outside, target_is_directory=True)
        return process

    monkeypatch.setattr(subprocess, "Popen", swap_after_process_creation)

    with pytest.raises(autopilot.StateError, match="atomic output path changed"):
        autopilot.CommandRunner().run(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            timeout_seconds=2,
            log_base=log_base,
        )

    assert logs.is_symlink()
    assert list(outside.iterdir()) == []
    assert autopilot._command_intent_path(  # noqa: SLF001
        retained_logs / "command"
    ).is_file()
    assert not autopilot._command_evidence_paths(  # noqa: SLF001
        retained_logs / "command"
    )[0].exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-race regression")
def test_streaming_log_parent_swap_cannot_redirect_temp_or_final_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mid-stream ancestor swap leaves no output or receipt outside the root."""
    logs = tmp_path / ".autopilot" / "runs" / "stream-race" / "logs"
    logs.mkdir(parents=True)
    retained_logs = logs.with_name("logs-retained")
    outside = tmp_path / "outside-stream"
    outside.mkdir()
    log_base = logs / "command"
    original_write = autopilot._RootedStreamingFile.write  # noqa: SLF001
    swapped = False

    def swap_after_first_write(
        stream: autopilot._RootedStreamingFile,
        content: bytes,
    ) -> None:
        nonlocal swapped
        original_write(stream, content)
        if content and not swapped:
            logs.rename(retained_logs)
            logs.symlink_to(outside, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(autopilot._RootedStreamingFile, "write", swap_after_first_write)  # noqa: SLF001

    with pytest.raises(autopilot.StateError, match="could not be finalized"):
        autopilot.CommandRunner().run(
            [sys.executable, "-c", "print('safe streamed output')"],
            cwd=tmp_path,
            timeout_seconds=5,
            log_base=log_base,
        )

    assert swapped
    assert list(outside.iterdir()) == []
    assert not autopilot._command_evidence_paths(  # noqa: SLF001
        retained_logs / "command"
    )[1].exists()


@pytest.mark.skipif(os.name != "nt", reason="native Windows ADS test")
def test_windows_rooted_writes_reject_alternate_data_streams(
    tmp_path: Path,
) -> None:
    """Native Windows output cannot select an alternate data stream."""
    with pytest.raises(autopilot.StateError, match="alternate data stream"):
        autopilot._atomic_write_bytes(  # noqa: SLF001
            tmp_path / "evidence.json:stream", b"unsafe", root=tmp_path
        )


@pytest.mark.skipif(os.name != "nt", reason="native Windows junction test")
def test_windows_rooted_writes_reject_a_junction_ancestor(
    tmp_path: Path,
) -> None:
    """Native Windows output never traverses a directory junction ancestor."""
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    command_prompt = shutil.which("cmd.exe")
    if command_prompt is None:
        pytest.skip("Windows command processor is unavailable")
    created = subprocess.run(
        [command_prompt, "/d", "/c", "mklink", "/J", str(linked), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"directory junction creation is unavailable: {created.stderr}")

    with pytest.raises(autopilot.StateError):
        autopilot._atomic_write_bytes(  # noqa: SLF001
            linked / "evidence.json", b"unsafe", root=tmp_path
        )

    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="native Windows streaming ADS test")
def test_windows_rooted_streaming_rejects_alternate_data_streams(
    tmp_path: Path,
) -> None:
    """Native streaming output cannot select a Windows alternate data stream."""
    with (
        autopilot._RootedAtomicWriter(tmp_path, tmp_path) as writer,  # noqa: SLF001
        pytest.raises(autopilot.StateError, match="alternate data stream"),
    ):
        writer.open_stream(tmp_path / "evidence.log:stream")


@pytest.mark.skipif(os.name != "nt", reason="native Windows streaming junction test")
def test_windows_rooted_streaming_rejects_a_junction_ancestor(
    tmp_path: Path,
) -> None:
    """Native streaming handles never traverse a directory junction ancestor."""
    outside = tmp_path / "outside-stream"
    outside.mkdir()
    linked = tmp_path / "linked-stream"
    command_prompt = shutil.which("cmd.exe")
    if command_prompt is None:
        pytest.skip("Windows command processor is unavailable")
    created = subprocess.run(
        [command_prompt, "/d", "/c", "mklink", "/J", str(linked), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip(f"directory junction creation is unavailable: {created.stderr}")

    with (
        pytest.raises(autopilot.StateError),
        autopilot._RootedAtomicWriter(tmp_path, linked) as writer,  # noqa: SLF001
    ):
        writer.open_stream(linked / "evidence.log")
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("extra", [0, 1], ids=("exact-limit", "limit-plus-one"))
def test_scaled_command_capture_boundary_survives_delayed_small_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stream: str,
    extra: int,
) -> None:
    """Scheduling delays do not change exact and overflowing capture semantics."""
    boundary = 256
    original_feed = autopilot._StreamingRedactor.feed  # noqa: SLF001

    def delayed_feed(redactor: object, content: bytes) -> str:
        time.sleep(0.001)
        return original_feed(redactor, content)  # type: ignore[arg-type]

    monkeypatch.setattr(autopilot, "MAX_RESULT_BYTES", boundary)
    monkeypatch.setattr(autopilot, "_CAPTURE_CHUNK_BYTES", 7)
    monkeypatch.setattr(autopilot._StreamingRedactor, "feed", delayed_feed)  # noqa: SLF001
    size = boundary + extra
    expression = f"sys.{stream}.buffer.write(b'x' * {size})"
    log_base = tmp_path / f"scaled-delayed-{stream}-{extra}"

    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", f"import sys; {expression}"],
        cwd=tmp_path,
        timeout_seconds=5,
        log_base=log_base,
    )

    _started, receipt_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    output_document = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    human_path = stdout_path if stream == "stdout" else stderr_path
    mirror = base64.b64decode(output_document[f"{stream}_base64"])
    assert not result.timed_out
    assert result.process_succeeded
    assert human_path.read_bytes() == b"x" * size
    assert mirror == b"x" * boundary
    assert receipt[f"{stream}_size_bytes"] == size
    assert receipt[f"{stream}_overflow"] is bool(extra)
    assert output_document[f"{stream}_overflow"] is bool(extra)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("extra", [0, 1], ids=("exact-limit", "limit-plus-one"))
def test_command_capture_keeps_complete_human_log_and_bounded_machine_mirror(
    tmp_path: Path,
    stream: str,
    extra: int,
) -> None:
    """Machine mirrors stop at 1 MiB while complete human evidence is retained."""
    assert autopilot.MAX_RESULT_BYTES == 1024 * 1024
    size = autopilot.MAX_RESULT_BYTES + extra
    expression = f"sys.{stream}.buffer.write(b'x' * {size})"
    log_base = tmp_path / f"capture-{stream}-{extra}"

    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", f"import sys; {expression}"],
        cwd=tmp_path,
        # Coverage traces the byte-oriented streaming sanitizer and can make
        # draining this stress payload much slower than the child itself.
        timeout_seconds=30,
        log_base=log_base,
    )

    output_document = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    retained_stdout = base64.b64decode(output_document["stdout_base64"])
    retained_stderr = base64.b64decode(output_document["stderr_base64"])
    human_path = autopilot._command_evidence_paths(log_base)[  # noqa: SLF001
        2 if stream == "stdout" else 3
    ]
    human_bytes = human_path.read_bytes()
    receipt = json.loads(
        autopilot._command_evidence_paths(log_base)[1].read_text(encoding="utf-8")  # noqa: SLF001
    )
    retained = retained_stdout if stream == "stdout" else retained_stderr
    expected_human = b"x" * size
    mismatch = _capture_mismatch_diagnostic(
        actual=human_bytes,
        expected=expected_human,
        details={
            "mirror_overflow": output_document[f"{stream}_overflow"],
            "mirror_sha256": hashlib.sha256(retained).hexdigest(),
            "mirror_size": len(retained),
            "receipt_overflow": receipt[f"{stream}_overflow"],
            "receipt_sha256": receipt[f"{stream}_sha256"],
            "receipt_size": receipt[f"{stream}_size_bytes"],
            "returncode": result.returncode,
            "timed_out": result.timed_out,
        },
    )
    assert not result.timed_out, mismatch
    human_matches = human_bytes == expected_human
    assert human_matches, mismatch
    assert receipt[f"{stream}_size_bytes"] == size
    assert receipt[f"{stream}_sha256"] == hashlib.sha256(human_bytes).hexdigest()
    if extra == 0:
        assert result.succeeded
        retained_matches = retained == b"x" * autopilot.MAX_RESULT_BYTES
        assert retained_matches, mismatch
        assert output_document[f"{stream}_overflow"] is False
    else:
        assert not result.succeeded
        assert result.process_succeeded
        retained_matches = retained == b"x" * autopilot.MAX_RESULT_BYTES
        assert retained_matches, mismatch
        assert output_document[f"{stream}_overflow"] is True
        assert receipt[f"{stream}_overflow"] is True


def test_large_stdout_and_stderr_survive_receipt_authenticated_resume(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both complete human streams survive bounded-machine overflow and resume."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    # Keep the scaled mirror above the fixed receipt-document size so resume
    # still exercises the ordinary rooted reader limits.
    boundary = 4096
    monkeypatch.setattr(autopilot, "MAX_RESULT_BYTES", boundary)
    command = (
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.stdout.buffer.write(b'OUT-START|' + b'o' * {boundary} + "
            "b'|OUT-END'); "
            f"sys.stderr.buffer.write(b'ERR-START|' + b'e' * {boundary} + "
            "b'|ERR-END')"
        ),
    )
    log_base = fixture.root / ".autopilot" / "runs" / "large-resume" / "logs" / "both"

    result = pilot.runner.run(
        command,
        cwd=fixture.root,
        timeout_seconds=10,
        log_base=log_base,
    )
    started, durable = pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    process_succeeded = result.process_succeeded
    assert process_succeeded, json.dumps(
        {
            "returncode": result.returncode,
            "stderr_size": result.human_stderr_size,
            "stdout_size": result.human_stdout_size,
            "timed_out": result.timed_out,
        },
        sort_keys=True,
    )
    assert not result.succeeded
    assert result.stdout_overflow
    assert result.stderr_overflow
    assert started
    assert durable is not None
    assert durable.process_succeeded
    assert not durable.succeeded
    assert durable.stdout_overflow
    assert durable.stderr_overflow
    stdout_path = autopilot._command_evidence_paths(log_base)[2]  # noqa: SLF001
    stderr_path = autopilot._command_evidence_paths(log_base)[3]  # noqa: SLF001
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    assert bool(stdout.startswith(b"OUT-START|"))
    assert bool(stdout.endswith(b"|OUT-END"))
    assert bool(stderr.startswith(b"ERR-START|"))
    assert bool(stderr.endswith(b"|ERR-END"))
    output = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    assert len(base64.b64decode(output["stdout_base64"])) == boundary
    assert len(base64.b64decode(output["stderr_base64"])) == boundary


def test_streaming_redaction_covers_every_byte_boundary_and_long_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chunk boundaries, controls, escapes, and invalid UTF-8 cannot leak secrets."""
    secrets = (
        b"raw-authorization-secret",
        b"escaped-authorization-secret",
        b"userinfo-secret",
        b"query-secret",
        b"control-secret",
        b"invalid-secret",
        b"ghp_TokenSecret012345678901234567890",
    )
    payload = (
        b"Authorization: Bearer raw-authorization-secret safe-one\n"
        b'{\\"Authorization\\":\\"Bearer escaped-authorization-secret\\",'
        b'\\"safe\\":\\"safe-two\\"}\n'
        b"https://user:userinfo-secret@example.invalid/safe-three\n"
        b"https://example.invalid/?to\\u006ben=query-secret&safe=safe-four\n"
        b"Authori\x1bzation:\x1bBearer\x1bcontrol-secret\nsafe-five\n"
        b"https://example.invalid/?token=invalid-secret\xfftail&safe=safe-six\n"
        b"ghp_TokenSecret012345678901234567890 safe-seven\n"
    )
    monkeypatch.setattr(autopilot, "_CAPTURE_CHUNK_BYTES", 1)
    stress_timeout_seconds = 30
    log_base = tmp_path / "every-byte"

    result = autopilot.CommandRunner().run(
        [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write({payload!r})",
        ],
        cwd=tmp_path,
        timeout_seconds=stress_timeout_seconds,
        log_base=log_base,
    )

    assert not result.timed_out
    human = autopilot._command_evidence_paths(log_base)[2].read_bytes()  # noqa: SLF001
    sidecar = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    machine = base64.b64decode(sidecar["stdout_base64"])
    assert result.succeeded
    assert all(secret not in human and secret not in machine for secret in secrets)
    for suffix in (
        b"safe-one",
        b"safe-two",
        b"safe-three",
        b"safe-four",
        b"safe-five",
        b"safe-six",
        b"safe-seven",
    ):
        assert suffix in human
        assert suffix in machine

    long_size = autopilot.MAX_RESULT_BYTES + 1
    long_base = tmp_path / "long-secret"
    long_result = autopilot.CommandRunner().run(
        [
            sys.executable,
            "-c",
            (
                "print('https://example.invalid/?token=' + "
                f"'s' * {long_size} + '&safe=long-tail')"
            ),
        ],
        cwd=tmp_path,
        timeout_seconds=stress_timeout_seconds,
        log_base=long_base,
    )
    assert not long_result.timed_out
    long_human = autopilot._command_evidence_paths(long_base)[2].read_text()  # noqa: SLF001
    assert long_result.succeeded
    assert "s" * 100 not in long_human
    assert long_human.count("[REDACTED]") == 1
    assert "&safe=long-tail" in long_human


def test_streaming_redactor_preserves_next_prefix_after_oversized_secrets() -> None:
    """A completed huge secret cannot erase a following partial credential prefix."""

    def rendered(first: bytes, second: bytes) -> str:
        redactor = autopilot._StreamingRedactor()  # noqa: SLF001
        return redactor.feed(first) + redactor.feed(second) + redactor.finish()

    huge = b"A" * (autopilot.MAX_RESULT_BYTES + 16)
    cases = (
        (
            b"?token=" + huge + b"&tok",
            b"en=NEXTQUERYSECRET&safe=query-tail\n",
            "NEXTQUERYSECRET",
            "query-tail",
        ),
        (
            b"Authorization=" + huge + b"\nAuthori",
            b"zation=NEXTAUTHSECRET\nsafe-auth-tail\n",
            "NEXTAUTHSECRET",
            "safe-auth-tail",
        ),
        (
            b'{"Authorization":"' + huge + b'","safe":1}\n{"Authori',
            b'zation":"NEXTQUOTEDSECRET","tail":2}\n',
            "NEXTQUOTEDSECRET",
            '"tail":2',
        ),
        (
            b"https://" + huge + b"@example.invalid/\nhttps:/",
            b"/NEXTURLSECRET@example.invalid/url-tail\n",
            "NEXTURLSECRET",
            "url-tail",
        ),
        (
            b"ghp_" + huge + b" ghp_SHOR",
            b"TNEXTTOKENSECRET012345678901234567890 token-tail\n",
            "NEXTTOKENSECRET",
            "token-tail",
        ),
    )
    for first, second, secret, tail in cases:
        output = rendered(first, second)
        assert secret not in output
        assert tail in output
        assert output.count("[REDACTED]") >= 2


@pytest.mark.parametrize(
    ("first", "second", "secret", "tail"),
    [
        pytest.param(
            b'{"Authorization":"' + b"A" * 2048,
            b' QUOTEDSPACELEAK","safe":1}\n',
            "QUOTEDSPACELEAK",
            '"safe":1',
            id="quoted-space",
        ),
        pytest.param(
            b'{"Authorization":"' + b"A" * 2048,
            b',"QUOTEDCOMMALEAK","safe":1}\n',
            "QUOTEDCOMMALEAK",
            '"safe":1',
            id="quoted-comma",
        ),
        pytest.param(
            b'{"Authorization":"' + b"A" * 2048,
            b'\\"QUOTEDESCAPELEAK","safe":1}\n',
            "QUOTEDESCAPELEAK",
            '"safe":1',
            id="quoted-escape",
        ),
        pytest.param(
            b"Authorization: Bearer " + b"A" * 2048,
            b'"RAWAUTHLEAK\nsafe-raw-tail\n',
            "RAWAUTHLEAK",
            "safe-raw-tail",
            id="raw-quote",
        ),
        pytest.param(
            b"Authorization=" + b"A" * 2048,
            b" GENERICAUTHLEAK\nsafe-generic-tail\n",
            "GENERICAUTHLEAK",
            "safe-generic-tail",
            id="generic-space",
        ),
    ],
)
def test_active_authorization_uses_structural_boundaries(
    first: bytes,
    second: bytes,
    secret: str,
    tail: str,
) -> None:
    """Spaces, quotes, and commas inside active values never reopen retention."""
    redactor = autopilot._StreamingRedactor()  # noqa: SLF001
    output = redactor.feed(first) + redactor.feed(second) + redactor.finish()

    assert secret not in output
    assert tail in output
    assert autopilot._redact(output) == output  # noqa: SLF001


def test_active_token_canonicalizes_json_escaped_continuation() -> None:
    """A JSON escape cannot terminate an already recognized token."""
    redactor = autopilot._StreamingRedactor()  # noqa: SLF001
    output = (
        redactor.feed(b"ghp_" + b"A" * 2048)
        + redactor.feed(b"\\u0042TOKENESCAPELEAK012345678901234567890 safe-tail\n")
        + redactor.finish()
    )

    assert "TOKENESCAPELEAK" not in output
    assert "safe-tail" in output
    assert output.count("[REDACTED]") == 1


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            b"ghp_ABCDEFGHIJ\nKLMNOPQRSTUVWXYZ0123456789 tail\n",
            id="github-candidate-lf",
        ),
        pytest.param(
            b"sk-ABCDEFGHIJ\r\nKLMNOPQRSTUVWXYZ0123456789 tail\n",
            id="openai-candidate-crlf",
        ),
        pytest.param(
            b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\nTOKENCONTINUATION0123456789 tail\n",
            id="github-active-lf",
        ),
        pytest.param(
            b"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\r\n"
            b"TOKENCONTINUATION-0123456789 tail\n",
            id="openai-active-crlf",
        ),
    ],
)
def test_streaming_tokens_treat_crlf_as_credential_control_gaps(
    payload: bytes,
) -> None:
    """Recognized tokens cannot expose continuations split by line controls."""
    expected = autopilot._redact(  # noqa: SLF001
        payload.decode("utf-8", errors="surrogateescape")
    )
    assert expected == "[REDACTED] tail\n"

    for split in range(len(payload) + 1):
        redactor = autopilot._StreamingRedactor()  # noqa: SLF001
        output = (
            redactor.feed(payload[:split])
            + redactor.feed(payload[split:])
            + redactor.finish()
        )
        assert output == expected


@pytest.mark.parametrize(
    "payload",
    [
        b"Authorization: Bearer secret-value\n",
        b"Authorization: [REDACTED]\n",
        b'{"Authorization":"secret-value","safe":1}\n',
        b"https://user:secret@example.invalid/path\n",
        b"https://example.invalid/?token=secret&safe=tail\n",
        b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 tail\n",
    ],
)
def test_streaming_redaction_is_idempotent(payload: bytes) -> None:
    """Passing already-redacted output through the boundary changes nothing."""

    def transform(value: bytes) -> str:
        redactor = autopilot._StreamingRedactor()  # noqa: SLF001
        return redactor.feed(value) + redactor.finish()

    once = transform(payload)
    twice = transform(once.encode("utf-8", errors="surrogateescape"))

    assert twice == once


@pytest.mark.parametrize(
    ("payload", "secret", "tail"),
    [
        pytest.param(
            b"?t"
            + b"\xff" * (autopilot._CAPTURE_CHUNK_BYTES + 600)  # noqa: SLF001
            + b"oken=INVALIDGAPLEAK&tail=invalid\n",
            "INVALIDGAPLEAK",
            "tail=invalid",
            id="invalid-gap",
        ),
        pytest.param(
            b"?t"
            + b"\x1b" * (autopilot._CAPTURE_CHUNK_BYTES + 600)  # noqa: SLF001
            + b"oken=CONTROLGAPLEAK&tail=control\n",
            "CONTROLGAPLEAK",
            "tail=control",
            id="control-gap",
        ),
        pytest.param(
            b"a"
            + b"+" * (autopilot._CAPTURE_CHUNK_BYTES + 600)  # noqa: SLF001
            + b"://URLSCHEMELEAK@example.invalid/tail=url\n",
            "URLSCHEMELEAK",
            "tail=url",
            id="unbounded-url-scheme",
        ),
    ],
)
def test_streaming_prefix_state_outlives_raw_lookbehind(
    payload: bytes,
    secret: str,
    tail: str,
) -> None:
    """Control gaps and URL schemes retain finite matching state across chunks."""
    redactor = autopilot._StreamingRedactor()  # noqa: SLF001
    chunk_size = autopilot._CAPTURE_CHUNK_BYTES  # noqa: SLF001
    rendered = [
        redactor.feed(payload[start : start + chunk_size])
        for start in range(0, len(payload), chunk_size)
    ]
    rendered.append(redactor.finish())
    output = "".join(rendered)

    assert secret not in output
    assert tail in output
    assert len(redactor._escape_pending) <= 5  # noqa: SLF001
    assert redactor._token_bytes <= autopilot._STREAM_CANDIDATE_BYTES  # noqa: SLF001
    assert redactor._url_authority_bytes <= autopilot._STREAM_CANDIDATE_BYTES  # noqa: SLF001


def test_streaming_authorization_path_never_calls_quadratic_batch_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated malformed fields use only the one-pass streaming automaton."""
    calls = 0

    def forbidden_scan(*_arguments: object, **_keywords: object) -> None:
        nonlocal calls
        calls += 1
        raise AssertionError("streaming redaction called a batch credential scan")

    monkeypatch.setattr(autopilot, "_credential_match_view", forbidden_scan)
    monkeypatch.setattr(autopilot, "_canonical_assignment_value_span", forbidden_scan)
    redactor = autopilot._StreamingRedactor()  # noqa: SLF001
    payload = (b"Authorization=x " * 4096) + b"\nlinear-tail\n"
    output = redactor.feed(payload) + redactor.finish()

    assert calls == 0
    assert "linear-tail" in output
    assert "x " not in output


@pytest.mark.parametrize("line_break", ["\n", "\r\n"], ids=("lf", "crlf"))
def test_nested_authorization_crossing_line_frontier_is_redacted_everywhere(
    line_break: str,
) -> None:
    """An outer value cannot hide a nested assignment after its line frontier."""
    synthetic_value = "SYNTHETICNESTEDSECRET"
    payload = f"authorization=x authorization{line_break}=Bearer {synthetic_value}"
    expected = f"authorization=[REDACTED]{line_break}=[REDACTED]"

    assert autopilot._redact(payload) == expected  # noqa: SLF001
    assert autopilot._redact_structure({"summary": payload}) == {  # noqa: SLF001
        "summary": expected
    }
    raw = payload.encode("utf-8")
    for split in range(len(raw) + 1):
        redactor = autopilot._StreamingRedactor()  # noqa: SLF001
        output = (
            redactor.feed(raw[:split]) + redactor.feed(raw[split:]) + redactor.finish()
        )
        assert output == expected

    bytewise = autopilot._StreamingRedactor()  # noqa: SLF001
    output = "".join(bytewise.feed(raw[index : index + 1]) for index in range(len(raw)))
    output += bytewise.finish()
    assert output == expected
    second = autopilot._StreamingRedactor()  # noqa: SLF001
    assert second.feed(output.encode("utf-8")) + second.finish() == expected


@pytest.mark.parametrize("line_break", ["\n", "\r\n"], ids=("lf", "crlf"))
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_command_capture_redacts_nested_authorization_in_every_retained_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    line_break: str,
    stream: str,
) -> None:
    """Streaming human logs and machine sidecars share the crossing fix."""
    synthetic_value = "SYNTHETICNESTEDSECRET"
    payload = f"authorization=x authorization{line_break}=Bearer {synthetic_value}"
    expected = f"authorization=[REDACTED]{line_break}=[REDACTED]"
    monkeypatch.setattr(autopilot, "_CAPTURE_CHUNK_BYTES", 1)
    log_base = tmp_path / f"nested-{stream}-{len(line_break)}"
    command = (
        sys.executable,
        "-c",
        f"import sys; sys.{stream}.write({payload!r}); sys.{stream}.flush()",
    )

    result = autopilot.CommandRunner().run(
        command,
        cwd=tmp_path,
        timeout_seconds=10,
        log_base=log_base,
    )

    selected = result.stdout if stream == "stdout" else result.stderr
    human_path = autopilot._command_evidence_paths(log_base)[  # noqa: SLF001
        2 if stream == "stdout" else 3
    ]
    human = human_path.read_text(encoding="utf-8")
    sidecar = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    machine = base64.b64decode(sidecar[f"{stream}_base64"]).decode("utf-8")
    assert not result.timed_out
    assert selected == expected
    assert machine == expected
    assert human == autopilot._escape_terminal_text(expected)  # noqa: SLF001
    assert synthetic_value not in selected
    assert synthetic_value not in machine
    assert synthetic_value not in human


def test_monotonic_batch_redaction_matches_bounded_exhaustive_reference() -> None:
    """The linear frontier preserves exhaustive semantics on a broad corpus."""

    def exhaustive(value: str) -> str:
        view = autopilot._credential_match_view(value)  # noqa: SLF001
        spans: list[tuple[int, int]] = []
        search_from = 0
        while match := autopilot._CANONICAL_AUTHORIZATION.search(  # noqa: SLF001
            view.text, search_from
        ):
            search_from = match.end()
            assignment = autopilot._canonical_assignment_value_start(  # noqa: SLF001
                view, match.end()
            )
            if assignment is None:
                continue
            _separator, value_start = assignment
            _start, value_end = autopilot._canonical_assignment_value_span(  # noqa: SLF001
                view, value, value_start
            )
            normalized = (
                view.text[value_start:value_end]
                .replace(autopilot._CREDENTIAL_CONTROL_SENTINEL, "")  # noqa: SLF001
                .strip(" \t\"'")
            )
            if normalized == autopilot._REDACTED or re.fullmatch(  # noqa: SLF001
                rf"(?i)(?:basic|bearer|token)\s+{re.escape(autopilot._REDACTED)}",  # noqa: SLF001
                normalized,
            ):
                continue
            projected = autopilot._project_credential_span(  # noqa: SLF001
                view, value_start, value_end
            )
            if projected is not None:
                spans.append(projected)
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        parts: list[str] = []
        cursor = 0
        for start, end in merged:
            parts.extend((value[cursor:start], autopilot._REDACTED))  # noqa: SLF001
            cursor = end
        parts.append(value[cursor:])
        return "".join(parts)

    names = ("authorization", "Authorization", "Proxy-Authorization")
    separators = ("=", ":", " : ")
    values = ("secret", "Bearer secret", "[REDACTED]")
    corpus = [
        f"{name}{separator}{value}{ending}safe=tail"
        for name in names
        for separator in separators
        for value in values
        for ending in ("\n", "\r\n", ";")
    ]
    corpus.extend(
        [
            "authorization=x authorization\n=Bearer crossing",
            "authorization=x authorization\r\n=Bearer crossing",
            "Authorization: Bearer authorization = crossing",
            "authorization=x authorization=\ncrossing",
            "authorization=x authorization=same-line",
        ]
    )

    for payload in corpus:
        expected = exhaustive(payload)
        assert autopilot._redact_structural_credentials(payload) == expected  # noqa: SLF001

    negative = '{"Authorization":"x Authorization","safe":"keep"}\n'
    redacted = autopilot._redact(negative)  # noqa: SLF001
    stream = autopilot._StreamingRedactor()  # noqa: SLF001
    streamed = stream.feed(negative.encode("utf-8")) + stream.finish()
    assert '"safe":"keep"' in redacted
    assert '"safe":"keep"' in streamed
    assert autopilot._redact(redacted) == redacted  # noqa: SLF001


def test_existing_redaction_markers_use_only_fixed_width_position_checks() -> None:
    """Many retained markers never copy each growing value prefix."""

    class PositionTrackingText(str):
        __slots__ = ("checks", "slices")

        slices: list[slice]
        checks: list[tuple[int, int | None]]

        def __new__(cls, value: str) -> Self:
            instance = super().__new__(cls, value)
            instance.slices = []
            instance.checks = []
            return instance

        def __getitem__(self, key: int | slice) -> str:
            if isinstance(key, slice):
                self.slices.append(key)
            return super().__getitem__(key)

        def startswith(
            self,
            prefix: str | tuple[str, ...],
            start: int = 0,
            end: int | None = None,
        ) -> bool:
            self.checks.append((start, end))
            return super().startswith(prefix, start, end)

    marker_count = 4096
    tracked = PositionTrackingText(autopilot._REDACTED * marker_count + "tail")  # noqa: SLF001
    view = autopilot._CredentialMatchView(  # noqa: SLF001
        tracked,
        tuple(range(len(tracked))),
        tuple(range(1, len(tracked) + 1)),
    )

    span = autopilot._canonical_assignment_value_span(  # noqa: SLF001
        view,
        str(tracked),
        0,
    )

    assert span == (0, len(tracked))
    assert tracked.slices == []
    assert len(tracked.checks) == marker_count
    assert all(
        end is not None and end - start == len(autopilot._REDACTED)  # noqa: SLF001
        for start, end in tracked.checks
    )


def test_command_log_writer_streams_oversize_complete_human_evidence(
    tmp_path: Path,
) -> None:
    """Direct complete results also separate human logs from machine mirrors."""
    log_base = tmp_path / "oversize"
    result = autopilot.CommandResult(
        ("fixture",),
        0,
        "x" * (autopilot.MAX_RESULT_BYTES + 1),
        "",
        0.0,
    )

    persisted = autopilot.CommandRunner.write_logs(result, log_base, root=tmp_path)

    output = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    assert persisted.stdout_overflow is True
    assert not persisted.succeeded
    assert autopilot._command_evidence_paths(log_base)[2].read_text() == result.stdout  # noqa: SLF001
    assert len(base64.b64decode(output["stdout_base64"])) == (
        autopilot.MAX_RESULT_BYTES
    )


def test_command_log_paths_cannot_escape_or_select_a_run_results_directory(
    tmp_path: Path,
) -> None:
    """Command receipts remain in their rooted run's immediate logs directory."""
    result = autopilot.CommandResult(("fixture",), 0, "safe", "", 0.0)

    with pytest.raises(autopilot.StateError, match="outside the trusted root"):
        autopilot.CommandRunner.write_logs(
            result,
            tmp_path.parent / "outside-command",
            root=tmp_path,
        )
    with pytest.raises(autopilot.StateError, match="run logs directory"):
        autopilot.CommandRunner.write_logs(
            result,
            tmp_path / ".autopilot" / "runs" / "one-run" / "results" / "command",
            root=tmp_path,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink regression")
def test_rooted_atomic_write_rejects_a_symlink_leaf_without_replacing_it(
    tmp_path: Path,
) -> None:
    """An existing symlink leaf is rejected and its outside target is unchanged."""
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    destination = tmp_path / "evidence.json"
    destination.symlink_to(outside)

    with pytest.raises(autopilot.StateError, match="unsafe"):
        autopilot._atomic_write_bytes(  # noqa: SLF001
            destination, b"replacement", root=tmp_path
        )

    assert destination.is_symlink()
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_pre_hardening_state_schema_is_rejected(tmp_path: Path) -> None:
    """M1.5 state cannot be interpreted under the stronger M1.5.1 semantics."""
    state_root = tmp_path / ".autopilot"
    autopilot.atomic_write_json(
        state_root / "state.json",
        {
            "base_commit": "a" * 40,
            "branch": "codex/m6-m6-autopilot",
            "current_phase": "candidate_publication_pending",
            "run_id": "old-run",
            "schema_version": 1,
        },
        root=tmp_path,
    )

    with pytest.raises(autopilot.StateError, match="schema is unsupported"):
        autopilot.StateStore(state_root).read(required=True)


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1"])
def test_cli_timeout_requires_a_finite_positive_number(value: str) -> None:
    """Timeout overrides cannot disable supervision through special floats."""
    with pytest.raises(argparse.ArgumentTypeError, match="greater than zero"):
        autopilot._positive_timeout(value)  # noqa: SLF001


def test_state_lock_refuses_concurrent_runner(tmp_path: Path) -> None:
    """Only the process owning an exclusive lock may drive persisted state."""
    first = autopilot.StateStore(tmp_path / ".autopilot")
    second = autopilot.StateStore(tmp_path / ".autopilot")
    first.acquire("first")
    try:
        with pytest.raises(autopilot.StateError, match="another autopilot"):
            second.acquire("second")
    finally:
        first.release()

    assert not first.lock_path.exists()


@pytest.mark.parametrize(
    "phase",
    [
        "branch_pending",
        "milestone_pending",
        "implementation_pending",
        "implementation_running",
        "verification_pending",
        "verification_running",
        "review_pending",
        "review_running",
        "commit_pending",
        "commit_running",
        "milestone_complete",
    ],
)
def test_resume_from_each_material_happy_path_phase(
    repo_factory: Callable[..., RepositoryFixture],
    phase: str,
) -> None:
    """Every durable happy-path boundary resumes without repeating a commit."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    base = fixture.make_autopilot()
    crashing = CrashAfterSaveAutopilot(
        fixture.root,
        base.config,
        runner=base.runner,
        stdout=StringIO(),
        stderr=StringIO(),
        crash_phase=phase,
    )

    with pytest.raises(SimulatedCrashError, match=phase):
        _run_one(crashing)
    assert fixture.state()["current_phase"] == phase

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert fixture.state()["current_phase"] == "complete"
    subjects = _run(
        [fixture.git, "log", "--format=%s", "main..HEAD"],
        cwd=fixture.root,
    ).stdout.splitlines()
    assert subjects == ["Implement M2: Registry and matcher framework"]


@pytest.mark.parametrize("phase", ["repair_pending", "repair_running"])
def test_resume_from_material_repair_phases(
    repo_factory: Callable[..., RepositoryFixture],
    phase: str,
) -> None:
    """A paused requested-change repair continues in a fresh fixer context."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "first\n"},
            },
            {"role": "review", "outcome": "changes_requested"},
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "fixed\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    base = fixture.make_autopilot()
    crashing = CrashAfterSaveAutopilot(
        fixture.root,
        base.config,
        runner=base.runner,
        stdout=StringIO(),
        stderr=StringIO(),
        crash_phase=phase,
    )

    with pytest.raises(SimulatedCrashError, match=phase):
        _run_one(crashing)

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert fixture.state()["current_phase"] == "complete"


def test_interrupted_commit_recovery_prevents_duplicate_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A trailer-authenticated commit is adopted once after a lost state save."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    base = fixture.make_autopilot()
    crashing = CrashAfterCommitAutopilot(
        fixture.root,
        base.config,
        runner=base.runner,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after Git commit"):
        _run_one(crashing)
    assert fixture.state()["current_phase"] == "commit_running"
    head_after_crash = _run([fixture.git, "rev-parse", "HEAD"], cwd=fixture.root).stdout

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert (
        _run([fixture.git, "rev-parse", "HEAD"], cwd=fixture.root).stdout
        == head_after_crash
    )
    assert (
        _run(
            [fixture.git, "rev-list", "--count", "main..HEAD"],
            cwd=fixture.root,
        ).stdout.strip()
        == "1"
    )


def test_resume_completes_a_partially_staged_parent_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Required parent staging can be resumed without reset or lost work."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    base = fixture.make_autopilot()
    crashing = CrashAfterSaveAutopilot(
        fixture.root,
        base.config,
        runner=base.runner,
        stdout=StringIO(),
        stderr=StringIO(),
        crash_phase="commit_running",
    )
    with pytest.raises(SimulatedCrashError, match="commit_running"):
        _run_one(crashing)
    _run([fixture.git, "add", "--", "feature.txt"], cwd=fixture.root)

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert (
        _run(
            [fixture.git, "rev-list", "--count", "main..HEAD"],
            cwd=fixture.root,
        ).stdout.strip()
        == "1"
    )


def test_push_failure_resumes_publication_only_and_creates_draft_pr(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A failed checkpoint leaves the local commit and retries no Codex role."""
    fixture = repo_factory(fail_push_once=True)
    fixture.set_plan(_success_actions())
    pilot = fixture.make_autopilot()

    with pytest.raises(autopilot.PublicationError, match="fixture checkpoint"):
        pilot.run(
            "M2",
            "M2",
            push=True,
            draft_pr=True,
            dry_run=False,
        )

    state = fixture.state()
    assert state["current_phase"] == "publication_pending"
    local_head = _run(
        [fixture.git, "rev-parse", "HEAD"], cwd=fixture.root
    ).stdout.strip()
    assert len(fixture.codex_events()) == 2

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS

    assert len(fixture.codex_events()) == 2
    published = fixture.state()
    assert published["current_phase"] == "complete"
    publication = cast("dict[str, object]", published["publication"])
    assert publication["pr_url"] == "https://github.com/example/pyahead/pull/1"
    remote_head = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            "refs/heads/codex/m2-m2-autopilot",
        ],
    ).stdout.strip()
    assert remote_head == local_head
    gh_events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    assert ["pr", "create"] in [event[:2] for event in gh_events]
    pr_body = next((fixture.root / ".autopilot/runs").rglob("pr-body.md"))
    body_text = pr_body.read_text(encoding="utf-8")
    assert "returncode=0, timeout=False, signal=None" in body_text


def test_draft_pr_body_escapes_every_dynamic_value(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Persisted state and commands cannot forge lines in operator Markdown."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_id = "20260828T120000Z-0123456789"
    run_directory = fixture.root / ".autopilot" / "runs" / run_id
    run_directory.mkdir(parents=True)
    state: dict[str, object] = {
        "base_commit": _HOSTILE_OPERATOR_TEXT,
        "branch": _HOSTILE_OPERATOR_TEXT,
        "completed_commits": [
            {
                "commit": _HOSTILE_OPERATOR_TEXT,
                "hosted_evidence": {
                    "candidate_sha": _HOSTILE_OPERATOR_TEXT,
                    "conclusion": _HOSTILE_OPERATOR_TEXT,
                    "url": _HOSTILE_OPERATOR_TEXT,
                },
                "milestone": _HOSTILE_OPERATOR_TEXT,
                "verification": [
                    {
                        "command": [_HOSTILE_OPERATOR_TEXT],
                        "returncode": _HOSTILE_OPERATOR_TEXT,
                        "signal": _HOSTILE_OPERATOR_TEXT,
                        "succeeded": True,
                        "timed_out": _HOSTILE_OPERATOR_TEXT,
                    }
                ],
            }
        ],
        "current_phase": _HOSTILE_OPERATOR_TEXT,
        "run_directory": f".autopilot/runs/{run_id}",
        "run_id": run_id,
    }

    body_path = pilot._write_pr_body(state, _HOSTILE_OPERATOR_TEXT)  # noqa: SLF001

    body = body_path.read_text(encoding="utf-8")
    assert "\\u000aFORGED" in body
    assert "\r" not in body
    assert "\t" not in body
    assert "\x1b" not in body
    assert "\u202e" not in body
    assert "\u2028" not in body
    assert "\u2029" not in body
    assert "FORGED" not in set(body.splitlines())


def test_resume_adopts_exact_remote_checkpoint_after_unrecorded_push(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A crash after remote acceptance neither diverges nor repeats Codex work."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    config = autopilot.load_config(fixture.root)
    crashing = autopilot.Autopilot(
        fixture.root,
        config,
        runner=CrashAfterSuccessfulPushRunner(),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after successful push"):
        crashing.run(
            "M2",
            "M2",
            push=True,
            draft_pr=False,
            dry_run=False,
        )

    state = fixture.state()
    assert state["current_phase"] == "publication_pending"
    publication = cast("dict[str, object]", state["publication"])
    assert publication["pushed_commits"] == []
    assert len(fixture.codex_events()) == 2

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    resumed = cast("dict[str, object]", fixture.state()["publication"])
    assert resumed["pushed_commits"] == [fixture.state()["expected_head"]]
    assert len(fixture.codex_events()) == 2


def test_publication_reuses_one_existing_draft_pr(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A matching draft is updated rather than duplicated or merged."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    url = "https://github.com/example/pyahead/pull/7"
    monkeypatch.setenv(
        "PYAHEAD_FAKE_GH_PR_LIST",
        json.dumps([{"url": url, "isDraft": True}]),
    )

    outcome = fixture.make_autopilot().run(
        "M2",
        "M2",
        push=True,
        draft_pr=True,
        dry_run=False,
    )

    assert outcome is autopilot.ExitCode.SUCCESS
    publication = cast("dict[str, object]", fixture.state()["publication"])
    assert publication["pr_url"] == url
    gh_events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    commands = [event[:2] for event in gh_events]
    assert ["pr", "list"] in commands
    assert ["pr", "edit"] in commands
    assert ["pr", "create"] not in commands


def test_m6_refuses_local_only_run_before_mutation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Cross-platform M6 evidence cannot be claimed without publication."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(milestone="M6"))

    with pytest.raises(autopilot.InvalidInputError, match="M6 requires --push"):
        fixture.make_autopilot().run(
            "M6",
            "M6",
            push=False,
            draft_pr=False,
            dry_run=False,
        )

    assert not (fixture.root / ".autopilot").exists()
    assert not fixture.codex_events_path.exists()
    assert (
        _run([fixture.git, "branch", "--show-current"], cwd=fixture.root).stdout.strip()
        == "main"
    )


def test_m6_policy_keeps_artifact_benchmark_and_hosted_gates(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Configuration cannot assert M6 without every deterministic evidence class."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M6")

    assert milestone.requires_publication is True
    assert milestone.hosted_verification == "m6-supported-hosts"
    assert {spec.identifier for spec in pilot.verification_for(milestone)} >= {
        "m6-wheel-install",
        "m6-sdist-install",
        "m6-benchmark",
    }
    hosted = pilot.config.hosted_verification["m6-supported-hosts"]
    assert hosted.required_jobs == ("fixture-hosted",)
    rendered = pilot._hosted_verification_markdown(milestone)  # noqa: SLF001
    assert "workflow_dispatch.inputs.pyahead_autopilot_token" in rendered
    assert "PyAhead autopilot ${{ inputs.pyahead_autopilot_token }}" in rendered
    assert "`fixture-hosted`" in rendered


def test_repository_m6_policy_names_real_artifact_and_supported_host_evidence() -> None:
    """The checked-in policy demonstrates every M6 acceptance evidence class."""
    config = autopilot.load_config(SOURCE_ROOT)
    milestone = config.milestone("M6")
    commands = {
        identifier: config.milestone_verification[identifier].command
        for identifier in milestone.extra_verification
    }

    assert commands["m6-wheel-install"][-2:] == ("--kind", "wheel")
    assert commands["m6-sdist-install"][-2:] == ("--kind", "sdist")
    assert "scripts/install_smoke.py" in commands["m6-wheel-install"]
    assert "scripts/install_smoke.py" in commands["m6-sdist-install"]
    assert "scripts/benchmark.py" in commands["m6-benchmark"]
    assert commands["m6-benchmark"][-2:] == ("--output", "-")
    hosted = config.hosted_verification[cast("str", milestone.hosted_verification)]
    assert any("ubuntu-latest" in name for name in hosted.required_jobs)
    assert any("macos-latest" in name for name in hosted.required_jobs)
    assert any("windows-latest" in name for name in hosted.required_jobs)
    assert "Build wheel and sdist" in hosted.required_jobs


def test_m6_uses_one_exact_candidate_for_ci_review_commit_and_push(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Pending hosted evidence is polled and the proven SHA is attached unchanged."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    fixture.set_gh_run_plan(
        [
            {"status": "in_progress", "conclusion": None},
            {"status": "completed", "conclusion": "success"},
        ]
    )

    outcome = fixture.make_autopilot().run(
        "M6", "M6", push=True, draft_pr=False, dry_run=False
    )

    assert outcome is autopilot.ExitCode.SUCCESS
    state = fixture.state()
    assert state["current_phase"] == "awaiting_gate_C"
    completed = cast("list[dict[str, object]]", state["completed_commits"])
    assert len(completed) == 1
    commit = cast("str", completed[0]["commit"])
    evidence = cast("dict[str, object]", completed[0]["hosted_evidence"])
    assert evidence["candidate_sha"] == commit
    assert evidence["conclusion"] == "success"
    assert evidence["status"] == "completed"
    candidate = cast("dict[str, object]", completed[0]["candidate"])
    attempts = cast("list[dict[str, object]]", candidate["attempts"])
    assert len(attempts) == 1
    assert attempts[0]["sha"] == commit
    assert attempts[0]["status"] == "attached"
    remote_ref = cast("str", attempts[0]["remote_ref"])
    upload_ref = cast("str", attempts[0]["upload_ref"])
    remote_candidate = _run(
        [fixture.git, "--git-dir", str(fixture.origin), "rev-parse", remote_ref]
    ).stdout.strip()
    assert remote_candidate == commit
    remote_branch = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            "refs/heads/codex/m6-m6-autopilot",
        ]
    ).stdout.strip()
    assert remote_branch == commit
    gh_events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    assert (
        sum(
            event[:2] == ["run", "view"] and event[2] != "--help" for event in gh_events
        )
        == 2
    )
    git_events = json.loads(fixture.git_events_path.read_text(encoding="utf-8"))
    assert any("fsck" in event and "--no-dangling" in event for event in git_events)
    pushes = [event for event in git_events if "push" in event[:3]]
    assert len(pushes) == 2
    assert all("--force" not in event for event in pushes)
    assert all("--no-follow-tags" in event for event in pushes)
    assert all("--recurse-submodules=no" in event for event in pushes)
    candidate_push = next(event for event in pushes if "--porcelain" in event)
    assert f"--force-with-lease={upload_ref}:" in candidate_push
    assert candidate_push[-1] == f"{commit}:{upload_ref}"
    checkpoint_push = next(event for event in pushes if "--porcelain" not in event)
    assert not any(item.startswith("--force-with-lease") for item in checkpoint_push)
    assert any(
        event[:5] == ["api", "--hostname", "github.com", "--method", "POST"]
        and f"ref={remote_ref}" in event
        and f"sha={commit}" in event
        for event in gh_events
    )


def test_all_pushes_override_ambient_tag_and_submodule_publication(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Explicit push policy prevents inherited settings from adding remote effects."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    _run([fixture.git, "config", "push.followTags", "true"], cwd=fixture.root)
    _run(
        [fixture.git, "config", "push.recurseSubmodules", "only"],
        cwd=fixture.root,
    )
    _run(
        [
            fixture.git,
            "tag",
            "-a",
            "unpublished-autopilot-tag",
            "-m",
            "must remain local",
        ],
        cwd=fixture.root,
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )

    remote_tag = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "show-ref",
            "--verify",
            "--quiet",
            "refs/tags/unpublished-autopilot-tag",
        ],
        check=False,
    )
    assert remote_tag.returncode == 1
    pushes = [
        event
        for event in json.loads(fixture.git_events_path.read_text(encoding="utf-8"))
        if "push" in event[:3]
    ]
    assert len(pushes) == 2
    assert all("--no-follow-tags" in event for event in pushes)
    assert all("--recurse-submodules=no" in event for event in pushes)


def test_candidate_upload_porcelain_rejects_additional_ref_updates() -> None:
    """One owned upload cannot hide an additional tag or branch side effect."""
    sha = "a" * 40
    upload_ref = "refs/heads/candidate-upload"
    result = autopilot.CommandResult(
        command=("git", "push"),
        returncode=0,
        stdout=(
            "To https://github.com/example/pyahead.git\n"
            f"*\t{sha}:{upload_ref}\t[new branch]\n"
            "*\trefs/tags/unexpected:refs/tags/unexpected\t[new tag]\n"
            "Done\n"
        ),
        stderr="",
        duration_seconds=0.01,
    )

    assert (
        autopilot.Autopilot._candidate_upload_outcome(  # noqa: SLF001
            result, upload_ref, sha
        )
        == "contradictory"
    )


def test_hosted_failure_starts_fresh_repair_and_unique_candidate(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A failed candidate is retained while a fixer produces a new immutable ref."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-one\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "failure",
                "jobs": [
                    {
                        "conclusion": "failure",
                        "databaseId": 101,
                        "log": "windows fixture traceback\n",
                        "name": "fixture-hosted",
                        "status": "completed",
                        "url": (
                            "https://github.com/example/pyahead/actions/runs/"
                            "9001/job/101"
                        ),
                    }
                ],
            },
            {"status": "completed", "conclusion": "success"},
        ]
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )

    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])[0]
    candidate = cast("dict[str, object]", completed["candidate"])
    attempts = cast("list[dict[str, object]]", candidate["attempts"])
    assert [attempt["attempt"] for attempt in attempts] == [0, 1]
    assert attempts[0]["status"] == "superseded_for_repair"
    assert attempts[1]["status"] == "attached"
    assert attempts[0]["remote_ref"] != attempts[1]["remote_ref"]
    assert attempts[0]["sha"] != attempts[1]["sha"]
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "review",
    ]
    repair_prompt = next(
        (fixture.root / ".autopilot/runs").rglob("M6-repair-1.md")
    ).read_text(encoding="utf-8")
    assert "hosted evidence.failure_logs" in repair_prompt
    assert ".autopilot/runs/" in repair_prompt
    hosted_log = next(
        (fixture.root / ".autopilot/runs").rglob(
            "M6-candidate-0-hosted-job-101.stdout.log"
        )
    )
    assert hosted_log.read_text(encoding="utf-8") == "windows fixture traceback\\u000a"
    gh_events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    assert any(
        event[:6] == ["run", "view", "9001", "--job", "101", "--log"]
        for event in gh_events
    )


def test_empty_run_view_log_uses_repository_api_fallback(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """An empty successful CLI log is not mistaken for complete evidence."""
    fixture = repo_factory(default_timeout_seconds=30)
    fallback_log = (
        "API-FALLBACK-START\n"
        + "x" * (autopilot.MAX_RESULT_BYTES + 1)
        + "\nAPI-FALLBACK-END\n"
    )
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-one\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "failure",
                "jobs": [
                    {
                        "conclusion": "failure",
                        "databaseId": 101,
                        "log": fallback_log,
                        "log_run_view_empty": True,
                        "name": "fixture-hosted",
                        "status": "completed",
                        "url": (
                            "https://github.com/example/pyahead/actions/runs/"
                            "9001/job/101"
                        ),
                    }
                ],
            },
            {"status": "completed", "conclusion": "success"},
        ]
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )

    api_log = next(
        (fixture.root / ".autopilot/runs").rglob(
            "M6-candidate-0-hosted-job-101-api.stdout.log"
        )
    )
    complete_log = api_log.read_text(encoding="utf-8")
    assert complete_log.startswith("API-FALLBACK-START\\u000a")
    assert complete_log.endswith("\\u000aAPI-FALLBACK-END\\u000a")
    sidecar = json.loads(
        autopilot._command_output_path(  # noqa: SLF001
            api_log.with_name(api_log.name.removesuffix(".stdout.log"))
        ).read_text(encoding="ascii")
    )
    assert sidecar["stdout_overflow"] is True
    repair_prompt = next(
        (fixture.root / ".autopilot/runs").rglob("M6-repair-1.md")
    ).read_text(encoding="utf-8")
    assert "github-api" in repair_prompt
    assert api_log.relative_to(fixture.root).as_posix() in repair_prompt
    gh_events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    assert [
        "api",
        "--hostname",
        "github.com",
        "repos/example/pyahead/actions/jobs/101/logs",
    ] in gh_events


@pytest.mark.parametrize(
    "mode",
    ["empty", "whitespace-only"],
)
def test_empty_logs_from_both_interfaces_stop_before_repair(
    repo_factory: Callable[..., RepositoryFixture],
    mode: str,
) -> None:
    """Empty or whitespace-only responses remain a resumable failure."""
    fixture = repo_factory()
    log = "unused fixture log\n" if mode == "empty" else " \t\r\n"
    empty_interfaces = mode == "empty"
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            }
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "failure",
                "jobs": [
                    {
                        "conclusion": "failure",
                        "databaseId": 101,
                        "log": log,
                        "log_api_empty": empty_interfaces,
                        "log_run_view_empty": empty_interfaces,
                        "name": "fixture-hosted",
                        "status": "completed",
                        "url": (
                            "https://github.com/example/pyahead/actions/runs/"
                            "9001/job/101"
                        ),
                    }
                ],
            }
        ]
    )

    with pytest.raises(autopilot.PublicationError, match="empty hosted failure log"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    assert state["current_phase"] == "candidate_checks_running"
    assert state["repair_count"] == 0
    assert [event["role"] for event in fixture.codex_events()] == ["implementation"]


def test_hosted_log_failure_resumes_without_consuming_repair(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Unavailable diagnostics pause safely before a fixer receives evidence."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-one\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    failed_run = {
        "status": "completed",
        "conclusion": "failure",
        "jobs": [
            {
                "conclusion": "failure",
                "databaseId": 101,
                "log": "actionable hosted failure\n",
                "log_api_error_once": True,
                "log_error_once": True,
                "name": "fixture-hosted",
                "status": "completed",
                "url": ("https://github.com/example/pyahead/actions/runs/9001/job/101"),
            }
        ],
    }
    fixture.set_gh_run_plan(
        [failed_run, failed_run, {"status": "completed", "conclusion": "success"}]
    )

    with pytest.raises(
        autopilot.PublicationError,
        match="transient fake GitHub API job-log failure",
    ):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    assert state["current_phase"] == "candidate_checks_running"
    assert state["repair_count"] == 0
    assert [event["role"] for event in fixture.codex_events()] == ["implementation"]

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "review",
    ]
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert completed[0]["repair_cycles"] == 1


def test_contradictory_hosted_job_identity_fails_before_repair(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A job URL cannot identify a different job than its database ID."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "candidate-zero\n"},
            }
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "failure",
                "jobs": [
                    {
                        "conclusion": "failure",
                        "databaseId": 102,
                        "name": "fixture-hosted",
                        "status": "completed",
                        "url": (
                            "https://github.com/example/pyahead/actions/runs/"
                            "9001/job/101"
                        ),
                    }
                ],
            }
        ]
    )

    with pytest.raises(
        autopilot.PublicationError,
        match="contradictory candidate job identity",
    ):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["repair_count"] == 0
    assert [event["role"] for event in fixture.codex_events()] == ["implementation"]


def test_wrong_hosted_sha_fails_closed_then_rechecks_repair(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A successful workflow for any other commit is not candidate evidence."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "first\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "second\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {
                "status": "completed",
                "conclusion": "success",
                "headSha": "0" * 40,
            },
            {"status": "completed", "conclusion": "success"},
        ]
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])[0]
    attempts = cast(
        "list[dict[str, object]]",
        cast("dict[str, object]", completed["candidate"])["attempts"],
    )
    assert len(attempts) == 2
    evidence = cast("dict[str, object]", completed["hosted_evidence"])
    assert evidence["candidate_sha"] == completed["commit"]


def test_missing_required_hosted_job_enters_repair_cycle(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Workflow success cannot conceal a missing supported-host acceptance job."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "first\n"},
            },
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "second\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {"status": "completed", "conclusion": "success", "jobs": []},
            {"status": "completed", "conclusion": "success"},
        ]
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "repair",
        "review",
    ]


def test_candidate_push_failure_resumes_before_hosted_review(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A failed immutable-ref push retries without repeating implementation."""
    fixture = repo_factory(fail_push_once=True)
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))

    with pytest.raises(autopilot.PublicationError, match="checkpoint push failure"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["current_phase"] == "candidate_publication_pending"
    assert [event["role"] for event in fixture.codex_events()] == ["implementation"]
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
    ]


def test_review_requested_repair_rechecks_a_new_candidate(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A reviewer cannot approve edits made after an earlier hosted run."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "first\n"},
            },
            {"role": "review", "outcome": "changes_requested"},
            {
                "role": "repair",
                "outcome": "completed",
                "changes": {"feature.txt": "second\n"},
            },
            {"role": "review", "outcome": "pass"},
        ]
    )
    fixture.set_gh_run_plan(
        [
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "success"},
        ]
    )

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])[0]
    attempts = cast(
        "list[dict[str, object]]",
        cast("dict[str, object]", completed["candidate"])["attempts"],
    )
    assert len(attempts) == 2
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
        "repair",
        "review",
    ]


def test_wrong_milestone_result_is_repaired_under_exact_session_schema(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """The API schema and parent parser both require the bare milestone label."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "implemented\n"},
                "result_milestone": "M2 — Registry and matcher framework",
            },
            {"role": "repair", "outcome": "completed"},
            {"role": "review", "outcome": "pass"},
        ]
    )

    assert _run_one(fixture.make_autopilot()) is autopilot.ExitCode.SUCCESS
    events = fixture.codex_events()
    assert [event["schema_milestone"] for event in events] == ["M2", "M2", "M2"]
    assert [event["role"] for event in events] == [
        "implementation",
        "repair",
        "review",
    ]


@pytest.mark.parametrize(
    "phase",
    [
        "candidate_pending",
        "candidate_running",
        "candidate_publication_pending",
        "candidate_dispatch_pending",
        "candidate_checks_pending",
        "candidate_checks_running",
        "candidate_attach_pending",
        "candidate_attach_running",
    ],
)
def test_resume_from_every_exact_candidate_phase(
    repo_factory: Callable[..., RepositoryFixture],
    phase: str,
) -> None:
    """Every durable exact-candidate boundary resumes without another role or commit."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase=phase,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match=phase):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == phase
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert len(completed) == 1
    assert (
        _run(
            [
                fixture.git,
                "rev-list",
                "--count",
                "main..codex/m6-m6-autopilot",
            ],
            cwd=fixture.root,
        ).stdout.strip()
        == "1"
    )


def test_resume_does_not_redispatch_an_indeterminate_prepared_attempt(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A crash at the dispatch boundary stops safely if no run can be attributed."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase="candidate_dispatch_running",
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="candidate_dispatch_running"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    with pytest.raises(autopilot.PublicationError, match="will not redispatch"):
        fixture.make_autopilot().resume()
    events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    dispatches = [
        event
        for event in events
        if event[:2] == ["workflow", "run"] and "--ref" in event
    ]
    assert dispatches == []
    assert fixture.state()["current_phase"] == "candidate_dispatch_running"


def test_resume_attributes_the_one_run_created_before_dispatch_crash(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A post-dispatch crash adopts only the uniquely tokened post-baseline run."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterWorkflowDispatchRunner(),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after workflow dispatch"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "candidate_dispatch_running"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert len(completed) == 1
    events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    dispatches = [
        event
        for event in events
        if event[:2] == ["workflow", "run"] and "--ref" in event
    ]
    assert len(dispatches) == 1


def test_duplicate_post_dispatch_runs_fail_closed(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two runs after one dispatch are ambiguous even when both share the SHA."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_DUPLICATE_DISPATCH", "1")

    with pytest.raises(autopilot.StateError, match="ambiguous runs"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["current_phase"] == "blocked"


def test_delayed_duplicate_dispatch_invalidates_candidate_before_acceptance(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second token-titled run appearing during polling can never be accepted."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_DELAYED_DUPLICATE", "1")

    with pytest.raises(autopilot.StateError, match="identity became ambiguous"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["current_phase"] == "blocked"
    assert fixture.state()["completed_commits"] == []


def test_more_than_twenty_runs_cannot_hide_an_exact_token_duplicate(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete bounded enumeration sees a duplicate hidden from the old window."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_CROWDED_DUPLICATE", "25")

    with pytest.raises(autopilot.StateError, match="ambiguous runs"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["current_phase"] == "blocked"
    list_calls = [
        event
        for event in json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
        if event[:2] == ["run", "list"] and "--help" not in event
    ]
    assert list_calls
    assert all(
        event[event.index("--limit") + 1] == str(autopilot.WORKFLOW_RUN_LIST_LIMIT)
        for event in list_calls
    )


def test_saturated_workflow_run_window_fails_closed(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full result window is treated as potentially truncated, never complete."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv(
        "PYAHEAD_FAKE_GH_CROWDED_DUPLICATE",
        str(autopilot.WORKFLOW_RUN_LIST_LIMIT),
    )

    with pytest.raises(autopilot.PublicationError, match="may be truncated"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    assert fixture.state()["completed_commits"] == []


def test_unrelated_post_baseline_manual_run_is_not_token_attributed(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A different-title run on the exact SHA neither supplies nor blocks evidence."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_UNRELATED_DISPATCH", "1")

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert len(completed) == 1


def test_preexisting_matching_run_is_baselined_not_adopted(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A manual run on the same ref/SHA cannot become controller evidence."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase="candidate_dispatch_pending",
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="candidate_dispatch_pending"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    active = cast(
        "dict[str, object]",
        cast("dict[str, object]", fixture.state()["candidate"])["active"],
    )
    _run(
        [
            sys.executable,
            str(FAKE_GH),
            "workflow",
            "run",
            "CI",
            "--ref",
            cast("str", active["remote_branch"]),
            "--field",
            "pyahead_autopilot_token=manual-run",
            "--repo",
            "github.com/example/pyahead",
        ],
        cwd=fixture.root,
    )

    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])[0]
    evidence = cast("dict[str, object]", completed["hosted_evidence"])
    assert evidence["run_id"] == 9002
    assert evidence["dispatch_title"] != "PyAhead autopilot manual-run"


@pytest.mark.parametrize(
    ("operation", "reference_fragment"),
    [
        ("commit-tree", None),
        ("update-ref", "refs/pyahead/autopilot/candidates"),
    ],
)
def test_candidate_creation_recovers_only_its_expected_git_effects(
    repo_factory: Callable[..., RepositoryFixture],
    operation: str,
    reference_fragment: str | None,
) -> None:
    """Object/ref crashes resume while the transition guard stays exact."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterGitOperationRunner(
            operation, reference_fragment=reference_fragment
        ),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match=f"after Git {operation}"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "candidate_running"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert (
        len(cast("list[dict[str, object]]", fixture.state()["completed_commits"])) == 1
    )


def test_commit_tree_replay_uses_one_persisted_identity_without_orphan_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A crash before update-ref replays the identical commit across wall-clock time."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterGitOperationRunner("commit-tree"),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after Git commit-tree"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    identity = cast(
        "dict[str, object]",
        cast(
            "dict[str, object]",
            cast("dict[str, object]", fixture.state()["candidate"])["active"],
        )["commit_identity"],
    )
    time.sleep(1.1)
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert len(completed) == 1
    assert identity["timestamp"] <= int(time.time()) - 1
    unreachable = _run(
        [fixture.git, "fsck", "--no-reflogs", "--unreachable"], cwd=fixture.root
    )
    assert "unreachable commit" not in unreachable.stdout


@pytest.mark.parametrize(
    ("operation", "reference_fragment", "index_mode"),
    [
        ("add", None, "real"),
        ("update-ref", "refs/heads/codex/m6-m6-autopilot", "any"),
    ],
)
def test_candidate_attachment_recovers_partial_stage_or_branch_update(
    repo_factory: Callable[..., RepositoryFixture],
    operation: str,
    reference_fragment: str | None,
    index_mode: str,
) -> None:
    """Attachment resumes exact staging/ref effects without a duplicate commit."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterGitOperationRunner(
            operation,
            reference_fragment=reference_fragment,
            real_index_only=index_mode == "real",
        ),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match=f"after Git {operation}"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "candidate_attach_running"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert (
        _run(
            [
                fixture.git,
                "rev-list",
                "--count",
                "main..codex/m6-m6-autopilot",
            ],
            cwd=fixture.root,
        ).stdout.strip()
        == "1"
    )


def test_candidate_push_crash_is_confirmed_without_reimplementation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A remote-accepted create survives a crash without rewriting its ref."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterSuccessfulPushRunner(),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after successful push"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "candidate_publication_pending"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
    ]


def test_upload_ref_after_start_without_completed_result_is_never_adopted(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A durable start receipt alone cannot prove ownership of an exact ref."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=ExactUploadRaceRunner(fixture.origin, fixture.git, durable_result=False),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(
        SimulatedCrashError, match="after candidate upload process start"
    ):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    with pytest.raises(autopilot.StateError, match="durable completed parent push"):
        fixture.make_autopilot().resume()
    assert fixture.state()["current_phase"] == "blocked"


def test_indeterminate_upload_cannot_adopt_an_external_exact_ref(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Timeout evidence plus an exact remote SHA is not new-ref ownership proof."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=ExactUploadRaceRunner(fixture.origin, fixture.git, durable_result=True),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(autopilot.StateError, match="indeterminate or unsuccessful"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "blocked"
    assert fixture.state()["completed_commits"] == []


def test_candidate_api_crash_recovers_only_the_recorded_exact_ref(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """An API-accepted final ref survives a crash without another create attempt."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterSuccessfulApiRefRunner(),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after successful create-ref"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    state = fixture.state()
    assert state["current_phase"] == "candidate_publication_pending"
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    assert active["create_status"] == "api_attempting"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    api_calls = [
        event
        for event in json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
        if event and event[0] == "api" and "--method" in event
    ]
    assert len(api_calls) == 1
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
    ]


def test_pre_api_invocation_crash_cannot_adopt_an_external_exact_ref(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Write-ahead intent without a process marker never attributes a raced ref."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashBeforeApiInvocationRunner(),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="before create-ref"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    assert active["create_status"] == "api_attempting"
    _run(
        [
            fixture.git,
            "push",
            str(fixture.origin),
            f"{active['sha']}:{active['remote_ref']}",
        ],
        cwd=fixture.root,
    )

    with pytest.raises(autopilot.StateError, match="without a parent API invocation"):
        fixture.make_autopilot().resume()

    assert fixture.state()["current_phase"] == "blocked"
    api_calls = [
        event
        for event in json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
        if event and event[0] == "api" and "--method" in event
    ]
    assert api_calls == []


@pytest.mark.parametrize(
    "result_mode",
    [
        "alternate-422",
        "400",
        "403",
        "malformed-success",
        "missing-type-success",
        "wrong-type-success",
    ],
)
def test_definite_or_malformed_create_ref_results_never_adopt_an_exact_ref(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    result_mode: str,
) -> None:
    """Machine-readable rejections and malformed success bodies fail closed."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "m6\n"},
            }
        ]
    )
    monkeypatch.setenv("PYAHEAD_FAKE_GH_CREATE_REF_RESULT", result_mode)
    if result_mode in {"alternate-422", "400", "403"}:
        sentinel = tmp_path / f"race-{result_mode}"
        sentinel.write_text("race once\n", encoding="utf-8")
        monkeypatch.setenv("PYAHEAD_FAKE_GH_RACE_EXACT_REF", str(sentinel))

    with pytest.raises(
        autopilot.StateError, match=r"definitely rejected|contradictory evidence"
    ):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    remote = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            cast("str", active["remote_ref"]),
        ]
    ).stdout.strip()
    assert remote == active["sha"]
    assert state["current_phase"] == "blocked"


def test_candidate_object_upload_ref_is_created_with_an_expected_absent_lease(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A racing upload ref is retained and the final candidate is never created."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "m6\n"},
            }
        ]
    )
    sentinel = tmp_path / "race-candidate-push"
    sentinel.write_text("race once\n", encoding="utf-8")
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_RACE_CANDIDATE_PUSH", str(sentinel))

    with pytest.raises(autopilot.StateError, match="definitely rejected"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    remote = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            cast("str", active["upload_ref"]),
        ]
    ).stdout.strip()
    assert remote == active["parent"]
    assert remote != active["sha"]
    assert (
        _run(
            [
                fixture.git,
                "--git-dir",
                str(fixture.origin),
                "show-ref",
                "--verify",
                cast("str", active["remote_ref"]),
            ],
            check=False,
        ).returncode
        != 0
    )
    assert [event["role"] for event in fixture.codex_events()] == ["implementation"]


def test_preexisting_exact_upload_ref_is_never_adopted(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """An exact upload ref predating the lease attempt has no controller provenance."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase="candidate_publication_pending",
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="candidate_publication_pending"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    active = cast(
        "dict[str, object]",
        cast("dict[str, object]", fixture.state()["candidate"])["active"],
    )
    _run(
        [
            fixture.git,
            "push",
            str(fixture.origin),
            f"{active['sha']}:{active['upload_ref']}",
        ],
        cwd=fixture.root,
    )

    with pytest.raises(autopilot.StateError, match="existed before its lease"):
        fixture.make_autopilot().resume()

    assert fixture.state()["current_phase"] == "blocked"


def test_exact_sha_upload_race_is_a_definite_lease_rejection(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A concurrent exact-SHA upload ref cannot impersonate the lease owner."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "m6\n"},
            }
        ]
    )
    sentinel = tmp_path / "race-exact-upload"
    sentinel.write_text("race once\n", encoding="utf-8")
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_RACE_EXACT_CANDIDATE_PUSH", str(sentinel))

    with pytest.raises(autopilot.StateError, match="definitely rejected"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    remote = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            cast("str", active["upload_ref"]),
        ]
    ).stdout.strip()
    assert remote == active["sha"]
    assert state["current_phase"] == "blocked"


def test_preexisting_exact_candidate_ref_is_never_adopted(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """An exact-SHA ref is evidence only after a durable parent create attempt."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase="candidate_publication_pending",
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="candidate_publication_pending"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    active = cast(
        "dict[str, object]",
        cast("dict[str, object]", fixture.state()["candidate"])["active"],
    )
    _run(
        [
            fixture.git,
            "push",
            str(fixture.origin),
            f"{active['sha']}:{active['remote_ref']}",
        ],
        cwd=fixture.root,
    )
    with pytest.raises(autopilot.StateError, match="existed before"):
        fixture.make_autopilot().resume()

    assert fixture.state()["current_phase"] == "blocked"
    assert fixture.state()["completed_commits"] == []


def test_exact_sha_race_is_a_definite_rejection_not_recovery(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A concurrent exact-SHA creator cannot impersonate the parent push attempt."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "m6\n"},
            }
        ]
    )
    sentinel = tmp_path / "race-exact-candidate-api"
    sentinel.write_text("race once\n", encoding="utf-8")
    monkeypatch.setenv("PYAHEAD_FAKE_GH_RACE_EXACT_REF", str(sentinel))

    with pytest.raises(autopilot.StateError, match="definitely rejected"):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    remote = _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "rev-parse",
            cast("str", active["remote_ref"]),
        ]
    ).stdout.strip()
    assert remote == active["sha"]
    assert state["current_phase"] == "blocked"


def test_remote_candidate_movement_after_review_prevents_attachment(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Passing hosted evidence cannot attach a ref rewritten during review."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            {
                "role": "implementation",
                "outcome": "completed",
                "changes": {"feature.txt": "m6\n"},
            },
            {
                "role": "review",
                "outcome": "pass",
                "move_remote_candidate": True,
            },
        ]
    )

    with pytest.raises(
        autopilot.StateError, match="changed before candidate attachment"
    ):
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )

    state = fixture.state()
    assert state["current_phase"] == "blocked"
    assert fixture.state()["completed_commits"] == []
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "update-ref",
            cast("str", active["remote_ref"]),
            cast("str", active["sha"]),
        ]
    )
    with pytest.raises(autopilot.BlockedError, match="changed before"):
        fixture.make_autopilot().resume()


def test_remote_movement_after_branch_update_blocks_recovery_without_reset(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Attachment recovery rechecks the ref and preserves an already-moved branch."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        runner=CrashAfterGitOperationRunner(
            "update-ref",
            reference_fragment="refs/heads/codex/m6-m6-autopilot",
        ),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after Git update-ref"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    state = fixture.state()
    active = cast(
        "dict[str, object]", cast("dict[str, object]", state["candidate"])["active"]
    )
    _run(
        [
            fixture.git,
            "--git-dir",
            str(fixture.origin),
            "update-ref",
            cast("str", active["remote_ref"]),
            cast("str", active["parent"]),
        ]
    )
    with pytest.raises(
        autopilot.StateError, match="changed before attachment recovery"
    ):
        fixture.make_autopilot().resume()

    assert fixture.state()["current_phase"] == "blocked"
    assert (
        _run(
            [fixture.git, "rev-parse", "codex/m6-m6-autopilot"], cwd=fixture.root
        ).stdout.strip()
        == active["sha"]
    )


def test_hosted_run_is_bound_to_origin_despite_poisoned_environment(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Inherited Git/GitHub selectors cannot redirect dispatch or evidence."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    monkeypatch.setenv("GH_REPO", "attacker/other")
    monkeypatch.setenv("GH_HOST", "example.invalid")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "attacker.gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "attacker-system.gitconfig"))
    monkeypatch.setenv("GIT_SSH_COMMAND", "sh -c 'exit 97'")

    assert (
        fixture.make_autopilot().run(
            "M6", "M6", push=True, draft_pr=False, dry_run=False
        )
        is autopilot.ExitCode.SUCCESS
    )
    events = json.loads(fixture.gh_events_path.read_text(encoding="utf-8"))
    hosted = [
        event
        for event in events
        if event[:2] in (["workflow", "run"], ["run", "view"]) and "--help" not in event
    ]
    assert hosted
    assert all(
        event[event.index("--repo") + 1] == "github.com/example/pyahead"
        for event in hosted
    )


@pytest.mark.parametrize("phase", ["candidate_running", "candidate_attach_running"])
def test_candidate_transition_rejects_unrelated_git_metadata_tampering(
    repo_factory: Callable[..., RepositoryFixture],
    phase: str,
) -> None:
    """A paused candidate transition never absorbs config or unrelated ref edits."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase=phase,
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match=phase):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    if phase == "candidate_running":
        _run(
            [fixture.git, "config", "autopilot.unrelated", "changed"],
            cwd=fixture.root,
        )
    else:
        _run(
            [
                fixture.git,
                "update-ref",
                "refs/heads/unrelated-paused-ref",
                "HEAD",
            ],
            cwd=fixture.root,
        )
    with pytest.raises(
        autopilot.StateError, match="outside the exact parent-owned transition"
    ):
        fixture.make_autopilot().resume()


@pytest.mark.parametrize("flag", ["--skip-worktree", "--assume-unchanged"])
def test_candidate_attachment_rejects_unrelated_index_flag_changes(
    repo_factory: Callable[..., RepositoryFixture],
    flag: str,
) -> None:
    """Attachment cannot absorb index flags changed on an untouched tracked path."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterSaveAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        crash_phase="candidate_attach_running",
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="candidate_attach_running"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    _run([fixture.git, "update-index", flag, "AGENTS.md"], cwd=fixture.root)
    with pytest.raises(autopilot.StateError, match="semantic Git index changed"):
        fixture.make_autopilot().resume()


def test_interrupted_candidate_attachment_prevents_duplicate_commit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A branch ref advanced before state save is adopted exactly once."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions(content="m6\n", milestone="M6"))
    pilot = CrashAfterCommitAutopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        stdout=StringIO(),
        stderr=StringIO(),
    )

    with pytest.raises(SimulatedCrashError, match="after Git commit"):
        pilot.run("M6", "M6", push=True, draft_pr=False, dry_run=False)

    assert fixture.state()["current_phase"] == "candidate_attach_running"
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    completed = cast("list[dict[str, object]]", fixture.state()["completed_commits"])
    assert len(completed) == 1
    assert (
        _run(
            [
                fixture.git,
                "rev-list",
                "--count",
                "main..codex/m6-m6-autopilot",
            ],
            cwd=fixture.root,
        ).stdout.strip()
        == "1"
    )


def test_gate_c_stops_after_m6_and_requires_recorded_approval(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """M6 commits before an explicit stop; M7 cannot start without evidence."""
    fixture = repo_factory()
    fixture.set_plan(
        [
            *_success_actions(content="m6\n", milestone="M6"),
            *_success_actions(content="m7\n", milestone="M7"),
        ]
    )
    pilot = fixture.make_autopilot()

    outcome = pilot.run(
        "M6",
        "M7",
        push=True,
        draft_pr=False,
        dry_run=False,
    )

    assert outcome is autopilot.ExitCode.BLOCKED
    assert fixture.state()["current_phase"] == "awaiting_gate_C"
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
    ]
    with pytest.raises(autopilot.BlockedError, match="awaiting accountable"):
        fixture.make_autopilot().resume()

    fixture.make_autopilot().approve_gate(
        "C",
        Path("gate-evidence.md"),
        "release council",
    )
    assert fixture.make_autopilot().resume() is autopilot.ExitCode.SUCCESS
    assert fixture.state()["current_phase"] == "complete"
    assert [event["role"] for event in fixture.codex_events()] == [
        "implementation",
        "review",
        "implementation",
        "review",
    ]
    (fixture.root / "gate-evidence.md").write_text(
        "evidence changed after approval\n",
        encoding="utf-8",
    )
    with pytest.raises(autopilot.StateError, match="changed after approval"):
        fixture.make_autopilot().gate_approved("C")


def test_dry_run_prints_full_plan_without_mutation(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Dry-run output includes trust boundaries and causes no Git or state change."""
    fixture = repo_factory()
    fixture.set_plan(_success_actions())
    output = StringIO()
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        stdout=output,
        stderr=StringIO(),
    )
    original_head = pilot.git.head()

    result = pilot.run(
        "M2",
        "M6",
        push=True,
        draft_pr=True,
        dry_run=True,
    )

    assert result is autopilot.ExitCode.SUCCESS
    text = output.getvalue()
    assert "implementation command" in text
    assert "verification commands" in text
    assert "protected files" in text
    assert "checkpoint push" in text
    assert "draft PR" in text
    assert "awaiting_gate_C" in text
    assert pilot.git.head() == original_head
    assert pilot.git.current_branch() == "main"
    assert not (fixture.root / ".autopilot").exists()
    assert not fixture.codex_events_path.exists()


def test_dry_run_splits_only_renderer_owned_linefeeds(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unsafe separators in a prompt remain visible data, not output structure."""
    fixture = repo_factory()
    output = StringIO()
    pilot = autopilot.Autopilot(
        fixture.root,
        autopilot.load_config(fixture.root),
        stdout=output,
        stderr=StringIO(),
    )
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    hostile = "payload\rNEL\u0085ZL\u2028ZP\u2029VT\vFF\fESC\x1bEND"
    monkeypatch.setattr(
        pilot,
        "_render_implementation_prompt",
        lambda *_args, **_kwargs: f"trusted\n{hostile}\n",
    )

    pilot._print_dry_run_milestone(  # noqa: SLF001
        milestone,
        contract,
        push=False,
        draft_pr=False,
    )

    rendered = output.getvalue()
    assert f"      {escape_terminal_text(hostile)}\n" in rendered
    assert all(
        character not in rendered for character in hostile if ord(character) < 32
    )
    assert "\u0085" not in rendered
    assert "\u2028" not in rendered
    assert "\u2029" not in rendered


def test_recursive_child_invocation_is_refused_before_repository_access(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The inherited child marker prevents an agent from nesting the runner."""
    monkeypatch.setenv(autopilot.CHILD_MARKER, "1")

    result = autopilot.main(["status"])

    assert result == int(autopilot.ExitCode.STATE_ERROR)
    assert "recursive invocation" in capsys.readouterr().err


def test_expected_controller_errors_are_terminal_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Expected failures cross the native boundary before reaching stderr."""

    def fail_root() -> Path:
        raise autopilot.InvalidInputError(_HOSTILE_OPERATOR_TEXT)

    monkeypatch.setattr(autopilot, "repository_root", fail_root)

    result = autopilot.main(["status"])

    assert result == int(autopilot.ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"autopilot: {escape_terminal_text(_HOSTILE_OPERATOR_TEXT)}\n"
    )


def test_controller_human_writers_add_only_their_own_line_endings(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Human writers escape child controls before adding one structural newline."""
    pilot = repo_factory().make_autopilot()

    pilot._write(_HOSTILE_OPERATOR_TEXT)  # noqa: SLF001
    pilot._warn(f"{_HOSTILE_OPERATOR_TEXT}\tfield")  # noqa: SLF001

    assert cast("StringIO", pilot.stdout).getvalue() == (
        escape_terminal_text(_HOSTILE_OPERATOR_TEXT) + "\n"
    )
    assert cast("StringIO", pilot.stderr).getvalue() == (
        "autopilot: " + escape_terminal_text(f"{_HOSTILE_OPERATOR_TEXT}\tfield") + "\n"
    )


def test_human_status_is_safe_and_json_status_is_byte_preserving(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Human status escapes values while JSON remains machine data."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    state: dict[str, object] = {
        "branch": "codex/m2-m2-autopilot",
        "candidate": {"active": None},
        "completed_commits": [],
        "current_milestone": "M2",
        "current_phase": "blocked",
        "last_error": _HOSTILE_OPERATOR_TEXT,
        "publication": {"status": "local"},
        "repair_count": _HOSTILE_OPERATOR_TEXT,
        "run_id": "test-run",
    }
    monkeypatch.setattr(pilot.store, "read", lambda **_kwargs: state)

    pilot.status()

    output = cast("StringIO", pilot.stdout)
    human = output.getvalue()
    assert _HOSTILE_OPERATOR_TEXT not in human
    assert f"Last error: {escape_terminal_text(_HOSTILE_OPERATOR_TEXT)}\n" in human
    assert f"Repair cycles: {escape_terminal_text(_HOSTILE_OPERATOR_TEXT)}\n" in human
    output.seek(0)
    output.truncate()

    pilot.status(as_json=True)

    assert output.getvalue() == (
        json.dumps(
            autopilot._redact_structure(state),  # noqa: SLF001
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


@pytest.mark.parametrize("line_break", ["\n", "\r\n"], ids=("lf", "crlf"))
def test_parsed_implementation_and_json_status_redact_nested_authorization(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
    line_break: str,
) -> None:
    """Raw structured results stay parseable but operator JSON cannot leak them."""
    fixture = repo_factory()
    synthetic_value = "SYNTHETICNESTEDSECRET"
    payload = f"authorization=x authorization{line_break}=Bearer {synthetic_value}"
    expected = f"authorization=[REDACTED]{line_break}=[REDACTED]"
    result_path = fixture.root / "implementation.json"
    result_path.write_text(
        json.dumps(
            {
                "milestone": "M2",
                "status": "completed",
                "summary": payload,
                "files_changed": [],
                "acceptance_criteria_addressed": [],
                "commands_reportedly_run": [],
                "limitations": [],
                "blocking_reason": None,
            }
        ),
        encoding="utf-8",
    )

    parsed = autopilot.parse_implementation_result(result_path, "M2", [])
    assert parsed.summary == payload
    implementation = autopilot._implementation_to_dict(parsed)  # noqa: SLF001
    assert (
        cast(
            "dict[str, object]",
            autopilot._redact_structure(implementation),  # noqa: SLF001
        )["summary"]
        == expected
    )
    state: dict[str, object] = {
        "branch": "codex/m2-m2-autopilot",
        "candidate": {"active": None},
        "completed_commits": [],
        "current_milestone": "M2",
        "current_phase": "blocked",
        "implementation_result": implementation,
        "publication": {"status": "local"},
        "repair_count": 0,
        "run_id": "test-run",
    }
    pilot = fixture.make_autopilot()
    monkeypatch.setattr(pilot.store, "read", lambda **_kwargs: state)

    pilot.status(as_json=True)

    output = json.loads(cast("StringIO", pilot.stdout).getvalue())
    retained = cast("dict[str, object]", output["implementation_result"])
    assert retained["summary"] == expected
    assert synthetic_value not in json.dumps(output)


def test_json_status_redacts_adversarial_result_with_one_monotonic_value_scan(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated names inside one malformed result value cannot cause rescans."""
    fixture = repo_factory()
    result_path = fixture.root / "implementation.json"
    repeated = "authorization=[REDACTED] x " * 4096
    result_path.write_text(
        json.dumps(
            {
                "milestone": "M2",
                "status": "completed",
                "summary": repeated,
                "files_changed": [],
                "acceptance_criteria_addressed": [],
                "commands_reportedly_run": [],
                "limitations": [],
                "blocking_reason": None,
            }
        ),
        encoding="utf-8",
    )
    parsed = autopilot.parse_implementation_result(result_path, "M2", [])
    state: dict[str, object] = {
        "branch": "codex/m2-m2-autopilot",
        "candidate": {"active": None},
        "completed_commits": [],
        "current_milestone": "M2",
        "current_phase": "blocked",
        "implementation_result": autopilot._implementation_to_dict(parsed),  # noqa: SLF001
        "publication": {"status": "local"},
        "repair_count": 0,
        "run_id": "test-run",
    }
    pilot = fixture.make_autopilot()
    monkeypatch.setattr(pilot.store, "read", lambda **_kwargs: state)
    original = autopilot._canonical_assignment_value_span  # noqa: SLF001
    scans = 0

    def counted_scan(
        view: autopilot._CredentialMatchView,
        source: str,
        name_end: int,
    ) -> tuple[int, int] | None:
        nonlocal scans
        scans += 1
        return original(view, source, name_end)

    monkeypatch.setattr(autopilot, "_canonical_assignment_value_span", counted_scan)

    pilot.status(as_json=True)

    output = json.loads(cast("StringIO", pilot.stdout).getvalue())
    implementation = cast("dict[str, object]", output["implementation_result"])
    assert implementation["summary"] == "authorization=[REDACTED]"
    assert scans == 1


def test_batch_authorization_matching_never_copies_each_remaining_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many bounded fields match against one canonical buffer at rising offsets."""
    field_count = 4096
    payload = ",".join("authorization=[REDACTED]" for _ in range(field_count))
    original = autopilot._CANONICAL_AUTHORIZATION_VALUE  # noqa: SLF001
    calls: list[tuple[int, int]] = []

    class MatchRecorder:
        def match(self, text: str, position: int = 0) -> re.Match[str] | None:
            calls.append((len(text), position))
            return original.match(text, position)

    monkeypatch.setattr(autopilot, "_CANONICAL_AUTHORIZATION_VALUE", MatchRecorder())

    rendered = autopilot._redact_structure({"summary": payload})  # noqa: SLF001

    assert rendered == {"summary": payload}
    assert len(calls) == field_count
    assert {length for length, _position in calls} == {len(payload)}
    positions = [position for _length, position in calls]
    assert positions == sorted(positions)


def test_review_prompt_escapes_child_paths_commands_and_hosted_evidence(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A child-controlled value cannot forge persisted reviewer prompt lines."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    state: dict[str, object] = {
        "contract_hash": "a" * 64,
        "expected_head": "b" * 40,
        "hosted_evidence": {"job": _HOSTILE_OPERATOR_TEXT},
        "verification_results": [
            {
                "command": [sys.executable, _HOSTILE_OPERATOR_TEXT],
                "returncode": _HOSTILE_OPERATOR_TEXT,
                "signal": _HOSTILE_OPERATOR_TEXT,
                "stderr_log": _HOSTILE_OPERATOR_TEXT,
                "stdout_log": _HOSTILE_OPERATOR_TEXT,
                "succeeded": True,
                "timed_out": _HOSTILE_OPERATOR_TEXT,
            }
        ],
        "worktree_snapshot": {_HOSTILE_OPERATOR_TEXT: {"kind": "untracked"}},
    }

    prompt = pilot._render_review_prompt(state, milestone, contract)  # noqa: SLF001

    assert "\\u000aFORGED" in prompt
    assert "\nFORGED" not in prompt
    assert "\r" not in prompt
    assert "\t" not in prompt
    assert "\x1b" not in prompt
    assert "\u202e" not in prompt
    assert "\u2028" not in prompt
    assert "\u2029" not in prompt


def test_repair_prompt_escapes_structured_review_findings(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Reviewer-controlled text remains data in the persisted fixer prompt."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    state: dict[str, object] = {
        "contract_hash": "a" * 64,
        "failed_output_path": None,
        "review_findings": [
            {
                "explanation": _HOSTILE_OPERATOR_TEXT,
                "file": _HOSTILE_OPERATOR_TEXT,
                "line": None,
                "required_remediation": _HOSTILE_OPERATOR_TEXT,
                "severity": "high",
            }
        ],
    }

    prompt = pilot._render_repair_prompt(state, milestone, contract)  # noqa: SLF001

    assert "\\u000aFORGED" in prompt
    assert "\nFORGED" not in prompt
    assert "\r" not in prompt
    assert "\t" not in prompt
    assert "\x1b" not in prompt
    assert "\u202e" not in prompt
    assert "\u2028" not in prompt
    assert "\u2029" not in prompt


def test_repair_prompt_preserves_authenticated_structural_lines(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """New safe failure documents retain headings while legacy input is escaped."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    run_id = "20260828T000000Z-aaaaaaaaaa"
    run_directory = fixture.root / ".autopilot" / "runs" / run_id
    (run_directory / "results").mkdir(parents=True)
    state: dict[str, object] = {
        "contract_hash": "a" * 64,
        "current_milestone": "M2",
        "failed_output_path": None,
        "repair_count": 1,
        "review_findings": [],
        "run_directory": f".autopilot/runs/{run_id}",
        "run_id": run_id,
    }
    content = "Command: fixture\nSTDOUT:\nsafe\\u000aoutput\nSTDERR:\nnone\n"
    state["failed_output_path"] = pilot._write_failure_input(  # noqa: SLF001
        state, content
    )

    prompt = pilot._render_repair_prompt(state, milestone, contract)  # noqa: SLF001

    assert "Command: fixture\nSTDOUT:\nsafe\\u000aoutput\nSTDERR:\nnone" in prompt
    assert "Command: fixture\\u000aSTDOUT:" not in prompt


def test_failure_document_bound_is_exact_and_resume_uses_bounded_evidence(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """The writer and pinned resume reader share one aggregate byte ceiling."""
    exact = "x" * autopilot.MAX_FAILURE_DOCUMENT_BYTES
    exact_builder = autopilot._FailureDocumentBuilder()  # noqa: SLF001
    exact_builder.append(exact)
    assert exact_builder.render_bytes() == exact.encode()

    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    run_id = "20260828T000000Z-cccccccccc"
    results = fixture.root / ".autopilot" / "runs" / run_id / "results"
    results.mkdir(parents=True)
    exact_path = results / "exact-limit.txt"
    autopilot._atomic_write_bytes(  # noqa: SLF001
        exact_path, exact.encode(), root=fixture.root
    )
    assert (
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            fixture.root,
            exact_path,
            autopilot.MAX_FAILURE_DOCUMENT_BYTES,
            context="exact failure document",
        )
        == exact.encode()
    )
    autopilot._atomic_write_bytes(  # noqa: SLF001
        exact_path, f"{exact}y".encode(), root=fixture.root
    )
    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            fixture.root,
            exact_path,
            autopilot.MAX_FAILURE_DOCUMENT_BYTES,
            context="oversize failure document",
        )
    state: dict[str, object] = {
        "contract_hash": "a" * 64,
        "current_milestone": "M2",
        "failed_output_path": None,
        "repair_count": 1,
        "review_findings": [],
        "run_directory": f".autopilot/runs/{run_id}",
        "run_id": run_id,
    }
    state["failed_output_path"] = pilot._write_failure_input(  # noqa: SLF001
        state, exact + "y"
    )
    failure_path = fixture.root / cast("str", state["failed_output_path"])
    persisted = failure_path.read_bytes()

    assert len(persisted) <= autopilot.MAX_FAILURE_DOCUMENT_BYTES
    assert persisted.endswith(autopilot._FAILURE_OMISSION.encode("ascii"))  # noqa: SLF001
    prompt = pilot._render_repair_prompt(state, milestone, contract)  # noqa: SLF001
    assert autopilot._FAILURE_OMISSION.strip() in prompt  # noqa: SLF001


def test_repair_prompt_escapes_every_legacy_failure_linefeed(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Unversioned paused-run text cannot forge fixer prompt structure."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    milestone = pilot.config.milestone("M2")
    contract = autopilot.extract_milestone_contract(
        (fixture.root / "docs/design.md").read_text(encoding="utf-8"), milestone
    )
    run_id = "20260828T000000Z-bbbbbbbbbb"
    run_directory = fixture.root / ".autopilot" / "runs" / run_id
    results_directory = run_directory / "results"
    results_directory.mkdir(parents=True)
    failure_path = results_directory / "M2-failure-1.txt"
    failure_path.write_text("trusted\nFORGED\u2028line\n", encoding="utf-8")
    state: dict[str, object] = {
        "contract_hash": "a" * 64,
        "current_milestone": "M2",
        "failed_output_path": failure_path.relative_to(fixture.root).as_posix(),
        "repair_count": 1,
        "review_findings": [],
        "run_directory": f".autopilot/runs/{run_id}",
        "run_id": run_id,
    }

    prompt = pilot._render_repair_prompt(state, milestone, contract)  # noqa: SLF001

    assert "trusted\\u000aFORGED\\u2028line\\u000a" in prompt
    assert "\nFORGED" not in prompt


def test_subprocess_arguments_are_never_shell_interpreted(tmp_path: Path) -> None:
    """Metacharacters remain one inert argv value and cannot create a file."""
    marker = tmp_path / "must-not-exist"
    payload = f"; touch {marker}"
    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", payload],
        cwd=tmp_path,
        timeout_seconds=2,
    )

    assert result.succeeded
    assert result.stdout == payload + "\n"
    assert not marker.exists()
    with pytest.raises(autopilot.InvalidInputError, match="invalid value"):
        autopilot.CommandRunner().run(
            [sys.executable, "bad\0argument"],
            cwd=tmp_path,
            timeout_seconds=2,
        )


def test_subprocess_logs_and_state_output_redact_common_credentials(
    tmp_path: Path,
) -> None:
    """Known credential forms never reach logs or operator-facing JSON state."""
    token = "gh" + "p_" + ("a" * 24)
    basic = "c3ludGhldGljLWJhc2ljOnNlY3JldA=="
    proxy_basic = "c3ludGhldGljLXByb3h5OnNlY3JldA=="
    url_userinfo = (
        "https-user:https-password",
        "ssh-user:ssh-password",
        "custom-user:custom-password",
    )
    query_values = (
        "query-token-value",
        "query-access-token-value",
        "query-api-underscore-value",
        "query-api-dash-value",
        "query-apikey-value",
        "query-password-value",
        "query-secret-value",
        "query-auth-value",
        "query-credential-value",
        "query-fragment-value",
        "query-quote-value",
        "query-backslash-value",
        "query-whitespace-value",
    )
    boundary_suffixes = (
        "#fragment-is-safe",
        '"quote-is-safe',
        "\\backslash-is-safe",
        " whitespace-is-safe",
    )
    payload = "\n".join(
        (
            token,
            f"Authorization: Basic {basic}",
            f"Proxy-Authorization: Basic {proxy_basic}",
            f"https://{url_userinfo[0]}@example.invalid/simple",
            f"ssh://{url_userinfo[1]}@example.invalid/repository",
            f"custom+tls://{url_userinfo[2]}@example.invalid/resource",
            f"https://example.invalid/?token={query_values[0]}&safe=keep",
            f"https://example.invalid/?ACCESS_TOKEN={query_values[1]}&safe=keep",
            f"https://example.invalid/?api_key={query_values[2]}&safe=keep",
            f"https://example.invalid/?safe=keep&api-key={query_values[3]}&later=safe-too",
            f"https://example.invalid/?apikey={query_values[4]}&safe=keep",
            f"https://example.invalid/?password={query_values[5]}&safe=keep",
            f"https://example.invalid/?secret={query_values[6]}&safe=keep",
            f"https://example.invalid/?auth={query_values[7]}&safe=keep",
            f"https://example.invalid/?credential={query_values[8]}&safe=keep",
            f"https://example.invalid/?token={query_values[9]}{boundary_suffixes[0]}",
            f"https://example.invalid/?token={query_values[10]}{boundary_suffixes[1]}",
            f"https://example.invalid/?token={query_values[11]}{boundary_suffixes[2]}",
            f"https://example.invalid/?token={query_values[12]}{boundary_suffixes[3]}",
            "token=ordinary-non-url-setting",
        )
    )
    log_base = tmp_path / "credential-output"
    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", f"print({payload!r})"],
        cwd=tmp_path,
        timeout_seconds=2,
        log_base=log_base,
    )

    _started, result_path, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    stdout_log = stdout_path.read_text(encoding="utf-8")
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    output_bytes = output_path.read_bytes()
    output_document = json.loads(output_bytes)
    result_document = json.loads(result_path.read_text(encoding="utf-8"))
    retained_stdout = base64.b64decode(output_document["stdout_base64"]).decode()
    redacted_state = json.dumps(
        autopilot._redact_structure({"nested": [payload]})  # noqa: SLF001
    )
    redacted_payload = autopilot._redact(payload)  # noqa: SLF001
    assert result.succeeded
    for secret in (token, basic, proxy_basic, *url_userinfo, *query_values):
        assert secret not in result.stdout
        assert secret not in stdout_log
        assert secret not in retained_stdout
        assert secret not in redacted_state
    for view in (result.stdout, stdout_log, retained_stdout, redacted_state):
        assert "safe=keep" in view
        assert "ordinary-non-url-setting" in view
        for suffix in boundary_suffixes:
            assert suffix in view
    assert output_document["schema_version"] == 2
    assert result_document["schema_version"] == 3
    assert result_document["output_sha256"] == hashlib.sha256(output_bytes).hexdigest()
    assert retained_stdout == result.stdout
    assert autopilot._redact(redacted_payload) == redacted_payload  # noqa: SLF001
    assert "?token=[REDACTED]&safe=keep" in retained_stdout
    assert "?safe=keep&api-key=[REDACTED]&later=safe-too" in retained_stdout
    assert "[REDACTED]" in stdout_log
    assert "[REDACTED]" in retained_stdout


def test_structural_and_control_split_credentials_are_redacted_before_retention(
    tmp_path: Path,
) -> None:
    """Serialized and control-split credentials never cross a durable boundary."""
    secrets = (
        "synthetic-json-auth",
        "synthetic-escaped-auth",
        "synthetic-url-user",
        "synthetic-url-pass",
        "synthetic-control-auth",
        "synthetic-split-user",
        "synthetic-pass-left",
        "synthetic-pass-right",
        "synthetic-query-left",
        "synthetic-query-right",
    )
    payload = (
        '{"Authorization":"Bearer synthetic-json-auth","safe":"keep-json"}\n'
        r"{\"Authorization\":\"Bearer synthetic-escaped-auth\","
        r"\"safe\":\"keep-escaped\"}"
        "\n"
        r"https:\/\/synthetic-url-user:synthetic-url-pass@example.invalid/path"
        "\nAuthorization:\x1b Bearer synthetic-control-auth\n"
        "https://synthetic-split-user:synthetic-pass-left\n"
        "synthetic-pass-right@example.invalid/path\n"
        "https://example.invalid/?token=synthetic-query-left\n"
        "synthetic-query-right&safe=keep-query"
    )
    log_base = tmp_path / "structural-credentials"

    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", f"print({payload!r})"],
        cwd=tmp_path,
        timeout_seconds=2,
        log_base=log_base,
    )

    stdout_path = autopilot._command_evidence_paths(log_base)[2]  # noqa: SLF001
    human_log = stdout_path.read_text(encoding="utf-8")
    output_document = json.loads(
        autopilot._command_output_path(log_base).read_text(encoding="ascii")  # noqa: SLF001
    )
    sidecar = base64.b64decode(output_document["stdout_base64"]).decode()
    state_text = json.dumps(
        autopilot._redact_structure({"result": [payload]})  # noqa: SLF001
    )
    redacted = autopilot._redact(payload)  # noqa: SLF001

    assert result.succeeded
    for retained in (result.stdout, human_log, sidecar, state_text, redacted):
        assert all(secret not in retained for secret in secrets)
        assert "keep-json" in retained
        assert "keep-escaped" in retained
        assert "keep-query" in retained
        assert "[REDACTED]" in retained
    assert "\\u001b" in human_log
    assert autopilot._redact(redacted) == redacted  # noqa: SLF001


def test_dotted_command_log_bases_retain_complete_unique_names(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Dotted milestones and adjacent commands cannot collapse onto one receipt."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "dotted-evidence"
    bases = (
        run_directory / "logs" / "M8.5-verify-0-0-ruff",
        run_directory / "logs" / "M8.5-verify-0-1-mypy",
    )
    commands = (("ruff", "check"), ("mypy", "src"))
    records: list[dict[str, object]] = []
    for index, (log_base, command) in enumerate(zip(bases, commands, strict=True)):
        result = autopilot.CommandResult(
            command,
            0,
            f"command-{index}",
            "",
            0.01,
        )
        pilot.runner.write_logs(result, log_base)
        records.append(
            autopilot._serialize_command_result(result, log_base)  # noqa: SLF001
        )

    all_paths = {
        path
        for log_base in bases
        for path in (
            *autopilot._command_evidence_paths(log_base),  # noqa: SLF001
            autopilot._command_output_path(log_base),  # noqa: SLF001
        )
    }
    assert len(all_paths) == 10
    assert all(path.name.startswith("M8.5-verify-") for path in all_paths)
    assert not (run_directory / "logs" / "M8.stdout.log").exists()
    agent_base = run_directory / "logs" / "M8.5-implementation-0"
    assert {
        path.name
        for path in (
            *autopilot._command_evidence_paths(agent_base),  # noqa: SLF001
            autopilot._command_output_path(agent_base),  # noqa: SLF001
        )
    } == {
        "M8.5-implementation-0.output.json",
        "M8.5-implementation-0.result.json",
        "M8.5-implementation-0.started.json",
        "M8.5-implementation-0.stderr.log",
        "M8.5-implementation-0.stdout.log",
    }
    plain_base = run_directory / "logs" / "M8-verify"
    assert autopilot._command_evidence_paths(plain_base)[2].name == (  # noqa: SLF001
        "M8-verify.stdout.log"
    )
    for log_base, record in zip(bases, records, strict=True):
        durable = pilot._read_verification_evidence(  # noqa: SLF001
            run_directory,
            record,
            expected_log_base=log_base,
        )
        assert durable.command == tuple(record["command"])


def test_process_failure_preserves_renderer_lines_and_escapes_child_controls() -> None:
    """Failure headings stay readable without permitting child-created records."""
    result = autopilot.CommandResult(
        command=("fixture", _HOSTILE_OPERATOR_TEXT),
        returncode=1,
        stdout=f"{_HOSTILE_OPERATOR_TEXT}\tstdout",
        stderr=f"error\n{_HOSTILE_OPERATOR_TEXT}\tstderr",
        duration_seconds=0.01,
    )

    rendered = autopilot._format_command_failure(result)  # noqa: SLF001

    lines = rendered.splitlines()
    assert lines[0].startswith("Command: ")
    assert lines[1] == "Outcome: exited 1"
    assert lines[2] == "STDOUT:"
    assert lines[4] == "STDERR:"
    assert "\\u000aFORGED" in lines[3]
    assert "\\u0009stdout" in lines[3]
    assert "\\u0009stderr" in lines[5]
    assert "\r" not in rendered
    assert "\t" not in rendered
    assert "\x1b" not in rendered
    assert "FORGED" not in set(lines)


def test_subprocess_logs_escape_every_child_control(
    tmp_path: Path,
) -> None:
    """A child cannot forge records or alignment in human forensic logs."""
    log_base = tmp_path / "control-output"
    child_output = f"{_HOSTILE_OPERATOR_TEXT}\tfield"
    result = autopilot.CommandRunner().run(
        [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.write({child_output!r})",
        ],
        cwd=tmp_path,
        timeout_seconds=2,
        log_base=log_base,
    )

    _started, result_path, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    stdout_log = stdout_path.read_text(encoding="utf-8")
    result_document = json.loads(result_path.read_text(encoding="utf-8"))
    output_document_bytes = autopilot._command_output_path(log_base).read_bytes()  # noqa: SLF001
    output_document = json.loads(output_document_bytes)
    assert result.succeeded
    assert "\x1b" in result.stdout
    assert "\u202e" in result.stdout
    expected = autopilot._safe_log_text(result.stdout)  # noqa: SLF001
    assert stdout_log == expected
    assert "\n" not in stdout_log
    assert "\t" not in stdout_log
    assert "\\u000aFORGED" in stdout_log
    assert "\\u0009field" in stdout_log
    assert "\x1b" not in stdout_log
    assert result_document["schema_version"] == 3
    assert result_document["stdout_sha256"] == autopilot.sha256_text(expected)
    assert (
        result_document["output_sha256"]
        == hashlib.sha256(output_document_bytes).hexdigest()
    )
    assert base64.b64decode(output_document["stdout_base64"]).decode() == result.stdout


def test_controller_uses_the_product_pinned_unicode_safety_table() -> None:
    """Standalone bootstrap behavior cannot drift with the running Python UCD."""
    assert autopilot._UNSAFE_CODEPOINT_RANGES == (  # noqa: SLF001
        _human_text._UNSAFE_CODEPOINT_RANGES  # noqa: SLF001
    )
    fixture = "normal café 雪 \U00013439 after"
    expected = "normal café 雪 \\U00013439 after"

    assert autopilot._escape_terminal_text(fixture) == expected  # noqa: SLF001
    assert escape_terminal_text(fixture) == expected


def test_durable_command_evidence_preserves_crlf_http_semantics(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Opaque machine evidence, not human logs, retains HTTP framing."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "repos/example/pyahead/git/refs")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "create"
    started_path, _result_path, stdout_path, _stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    remote_ref = "refs/heads/codex/candidate"
    sha = "a" * 40
    body = json.dumps({"object": {"sha": sha, "type": "commit"}, "ref": remote_ref})
    result = autopilot.CommandResult(
        command=command,
        returncode=0,
        stdout=(
            f"HTTP/2.0 201 Created\r\nContent-Type: application/json\r\n\r\n{body}\r\n"
        ),
        stderr="",
        duration_seconds=0.01,
    )

    pilot.runner.write_logs(result, log_base)
    started, durable = pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    assert started
    assert durable is not None
    visible_stdout = stdout_path.read_text(encoding="utf-8")
    assert "\r" not in visible_stdout
    assert "\n" not in visible_stdout
    assert "\\u000d\\u000a" in visible_stdout
    assert durable.stdout == result.stdout
    assert pilot._candidate_create_outcome(durable, remote_ref, sha) == "created"  # noqa: SLF001


def test_legacy_command_receipt_remains_resumable(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A paused schema-1 publication command keeps its established semantics."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("git", "push", "--porcelain")
    log_base = fixture.root / ".autopilot" / "runs" / "legacy" / "logs" / "push"
    started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    stdout = "To example\n\t[new branch]\tobject -> candidate\n"
    stderr = ""
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    autopilot.atomic_write_json(
        result_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "interrupted": False,
            "returncode": 0,
            "schema_version": 1,
            "stderr_sha256": autopilot.sha256_text(stderr),
            "stdout_sha256": autopilot.sha256_text(stdout),
            "timed_out": False,
        },
    )

    started, durable = pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    assert started
    assert durable is not None
    assert durable.stdout == stdout
    assert durable.stderr == stderr


def test_legacy_command_receipt_preserves_crlf_http_streams(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Schema-1 resume hashes and parses exact CRLF bytes without translation."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "repos/example/pyahead/git/refs")
    log_base = fixture.root / ".autopilot" / "runs" / "legacy" / "logs" / "create"
    started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    remote_ref = "refs/heads/codex/candidate"
    sha = "a" * 40
    body = json.dumps({"object": {"sha": sha, "type": "commit"}, "ref": remote_ref})
    stdout = f"HTTP/2.0 201 Created\r\nContent-Type: application/json\r\n\r\n{body}\r\n"
    stderr = "diagnostic line one\r\ndiagnostic line two\r\n"
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    stdout_path.write_bytes(stdout.encode())
    stderr_path.write_bytes(stderr.encode())
    autopilot.atomic_write_json(
        result_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "interrupted": False,
            "returncode": 0,
            "schema_version": 1,
            "stderr_sha256": autopilot.sha256_text(stderr),
            "stdout_sha256": autopilot.sha256_text(stdout),
            "timed_out": False,
        },
    )

    started, durable = pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    assert started
    assert durable is not None
    assert durable.stdout == stdout
    assert durable.stderr == stderr
    assert pilot._candidate_create_outcome(durable, remote_ref, sha) == "created"  # noqa: SLF001


def test_failed_verification_uses_safe_exact_schema_one_crlf_evidence(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Legacy multiline streams remain data below controller-owned headings."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "legacy-verification"
    log_base = run_directory / "logs" / "M2-verify-0-0-tests"
    result = autopilot.CommandResult(
        command=(sys.executable, "-c", "raise SystemExit(1)"),
        returncode=1,
        stdout="first\r\nFORGED STDOUT\nlast",
        stderr="error one\r\nFORGED STDERR\rfinal",
        duration_seconds=0.01,
    )
    _write_schema_one_command_result(log_base, result)
    record = autopilot._serialize_command_result(result, log_base)  # noqa: SLF001

    durable = pilot._read_verification_evidence(  # noqa: SLF001
        run_directory,
        record,
    )
    rendered = autopilot._format_verification_failure(durable)  # noqa: SLF001

    assert durable.stdout == result.stdout
    assert durable.stderr == result.stderr
    assert "\r" not in rendered
    assert "\\u000d\\u000aFORGED STDOUT\\u000a" in rendered
    assert "\\u000d\\u000aFORGED STDERR\\u000d" in rendered
    assert "FORGED STDOUT" not in set(rendered.splitlines())
    assert "FORGED STDERR" not in set(rendered.splitlines())


@pytest.mark.parametrize(
    ("field", "contradiction"),
    [
        ("command", ["different"]),
        ("returncode", 2),
        ("timed_out", True),
        ("signal", 9),
        ("succeeded", True),
    ],
)
def test_verification_record_must_agree_with_durable_result(
    repo_factory: Callable[..., RepositoryFixture],
    field: str,
    contradiction: object,
) -> None:
    """Mutable state cannot contradict the integrity-protected command receipt."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "record-contradiction"
    log_base = run_directory / "logs" / "M2-verify-0-0-tests"
    result = autopilot.CommandResult(("verify",), 1, "output", "error", 0.01)
    pilot.runner.write_logs(result, log_base)
    record = autopilot._serialize_command_result(result, log_base)  # noqa: SLF001
    record[field] = contradiction

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_verification_evidence(run_directory, record)  # noqa: SLF001


@pytest.mark.parametrize(
    "unsafe_stem",
    [
        ".",
        "..",
        ".hidden",
        "../outside",
        "nested/../alias",
        "M2-verify-0-0-tests\nFORGED",
        "M2 verify 0",
        "\uff2d2-verify-0-0-tests",
    ],
)
def test_verification_evidence_rejects_noncanonical_or_unconfined_stems(
    repo_factory: Callable[..., RepositoryFixture],
    unsafe_stem: str,
) -> None:
    """Persisted log names cannot select aliases or escape the immediate log dir."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "unsafe-log-stem"
    log_base = run_directory / "logs" / "M2-verify-0-0-tests"
    result = autopilot.CommandResult(("verify",), 1, "output", "error", 0.01)
    pilot.runner.write_logs(result, log_base)
    record = autopilot._serialize_command_result(result, log_base)  # noqa: SLF001
    record["stdout_log"] = f"{unsafe_stem}.stdout.log"
    record["stderr_log"] = f"{unsafe_stem}.stderr.log"

    with pytest.raises(autopilot.StateError, match="log path is unsafe"):
        pilot._read_verification_evidence(run_directory, record)  # noqa: SLF001


def test_verification_evidence_rejects_valid_alias_of_expected_command(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Even valid evidence cannot replace the generated command-specific basename."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "log-alias"
    expected_base = run_directory / "logs" / "M2-verify-0-0-tests"
    alias_base = run_directory / "logs" / "M2-verify-0-1-tests"
    result = autopilot.CommandResult(("verify",), 1, "output", "error", 0.01)
    pilot.runner.write_logs(result, alias_base)
    record = autopilot._serialize_command_result(result, alias_base)  # noqa: SLF001

    with pytest.raises(autopilot.StateError, match="log path is unsafe"):
        pilot._read_verification_evidence(  # noqa: SLF001
            run_directory,
            record,
            expected_log_base=expected_base,
        )


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is privileged on Windows")
@pytest.mark.parametrize("tamper", ["rewrite", "symlink"])
def test_verification_evidence_refuses_tampered_or_symlinked_logs(
    repo_factory: Callable[..., RepositoryFixture],
    tamper: str,
) -> None:
    """Failed verification aggregation cannot read detached human-log content."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / f"log-{tamper}"
    log_base = run_directory / "logs" / "M2-verify-0-0-tests"
    result = autopilot.CommandResult(("verify",), 1, "original", "", 0.01)
    pilot.runner.write_logs(result, log_base)
    record = autopilot._serialize_command_result(result, log_base)  # noqa: SLF001
    _started, _result, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    if tamper == "rewrite":
        stdout_path.write_text("forged", encoding="utf-8")
    else:
        outside = fixture.root / "outside-verification.log"
        stdout_path.replace(outside)
        stdout_path.symlink_to(outside)

    with pytest.raises(autopilot.StateError):
        pilot._read_verification_evidence(run_directory, record)  # noqa: SLF001


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX descriptor reads")
def test_verification_evidence_refuses_in_place_log_mutation(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A log changed through its path during a pinned read fails closed."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    run_directory = fixture.root / ".autopilot" / "runs" / "log-mutation"
    log_base = run_directory / "logs" / "M2-verify-0-0-tests"
    result = autopilot.CommandResult(
        ("verify",),
        1,
        "a" * 70_000,
        "",
        0.01,
    )
    _write_schema_one_command_result(log_base, result)
    record = autopilot._serialize_command_result(result, log_base)  # noqa: SLF001
    _started, _result, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    target = stdout_path.stat()
    original_read = autopilot.os.read
    mutated = False

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        opened = os.fstat(descriptor)
        if (
            not mutated
            and chunk
            and (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino)
        ):
            stdout_path.write_bytes(b"b" * 70_000)
            mutated = True
        return chunk

    monkeypatch.setattr(autopilot.os, "read", mutate_after_read)

    with pytest.raises(autopilot.StateError):
        pilot._read_verification_evidence(run_directory, record)  # noqa: SLF001
    assert mutated is True


def test_durable_command_reader_pins_all_six_artifacts(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Structural documents stay bounded while complete human logs stream."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "wired"
    started_path, result_path, stdout_path, stderr_path = (
        autopilot._command_evidence_paths(log_base)  # noqa: SLF001
    )
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "output", "", 0.01),
        log_base,
    )
    original = autopilot._read_pinned_file_bytes  # noqa: SLF001
    original_inspector = autopilot._inspect_pinned_human_log  # noqa: SLF001
    calls: list[tuple[Path, int]] = []
    inspected: list[Path] = []

    def recording_reader(
        root: Path,
        path: Path,
        limit: int,
        *,
        context: str,
    ) -> bytes:
        calls.append((path, limit))
        return original(root, path, limit, context=context)

    def recording_inspector(
        root: Path,
        path: Path,
        *,
        expected_size: int,
        expected_sha256: str,
        context: str,
    ) -> autopilot._PinnedHumanLogInspection:
        inspected.append(path)
        return original_inspector(
            root,
            path,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            context=context,
        )

    monkeypatch.setattr(autopilot, "_read_pinned_file_bytes", recording_reader)
    monkeypatch.setattr(autopilot, "_inspect_pinned_human_log", recording_inspector)

    started, durable = pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    assert started
    assert durable is not None
    assert calls == [
        (
            autopilot._command_intent_path(log_base),  # noqa: SLF001
            autopilot.MAX_RESULT_BYTES,
        ),
        (started_path, autopilot.MAX_RESULT_BYTES),
        (result_path, autopilot.MAX_RESULT_BYTES),
        (
            autopilot._command_output_path(log_base),  # noqa: SLF001
            autopilot.MAX_COMMAND_OUTPUT_DOCUMENT_BYTES,
        ),
        (stdout_path, autopilot.MAX_COMMAND_LOG_BYTES),
        (stderr_path, autopilot.MAX_COMMAND_LOG_BYTES),
    ]
    assert inspected == [stdout_path, stderr_path]


def test_pinned_runtime_reader_enforces_exact_byte_limit(tmp_path: Path) -> None:
    """A durable file may reach the cap but cannot exceed it by one byte."""
    selected = tmp_path / "run" / "evidence.log"
    selected.parent.mkdir()
    selected.write_bytes(b"abcd")

    assert (
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            selected,
            4,
            context="runtime evidence",
        )
        == b"abcd"
    )
    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            selected,
            3,
            context="runtime evidence",
        )


def test_pinned_runtime_reader_rejects_unsafe_path_kinds(tmp_path: Path) -> None:
    """Escapes, directories, symlinks, and FIFOs cannot become durable input."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.write_bytes(b"outside")
    directory = tmp_path / "directory"
    directory.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"target")
    outside_directory = tmp_path.parent / f"{tmp_path.name}-outside-directory"
    outside_directory.mkdir()
    (outside_directory / "secret").write_bytes(b"secret")

    with pytest.raises(autopilot.StateError, match="outside the repository"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            outside,
            64,
            context="runtime evidence",
        )
    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            directory,
            64,
            context="runtime evidence",
        )
    if os.name != "nt":
        symlink = tmp_path / "symlink"
        symlink.symlink_to(target)
        with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
            autopilot._read_pinned_file_bytes(  # noqa: SLF001
                tmp_path,
                symlink,
                64,
                context="runtime evidence",
            )
        ancestor = tmp_path / "ancestor"
        ancestor.symlink_to(outside_directory, target_is_directory=True)
        with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
            autopilot._read_pinned_file_bytes(  # noqa: SLF001
                tmp_path,
                ancestor / "secret",
                64,
                context="runtime evidence",
            )
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo)
        with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
            autopilot._read_pinned_file_bytes(  # noqa: SLF001
                tmp_path,
                fifo,
                64,
                context="runtime evidence",
            )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX descriptor reads")
@pytest.mark.parametrize("mutation", ["replace", "rewrite", "grow"])
def test_pinned_runtime_reader_detects_leaf_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    """Replacement, same-size rewriting, and growth fail closed after a read."""
    selected = tmp_path / "run" / "evidence.log"
    selected.parent.mkdir()
    selected.write_bytes(b"a" * 70_000)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"b" * 70_000)
    original_read = autopilot.os.read
    mutated = False

    def mutate_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if chunk and not mutated:
            if mutation == "replace":
                replacement.replace(selected)
            elif mutation == "rewrite":
                selected.write_bytes(b"b" * 70_000)
            else:
                with selected.open("ab") as output:
                    output.write(b"grown")
            mutated = True
        return chunk

    monkeypatch.setattr(autopilot.os, "read", mutate_after_first_chunk)

    with pytest.raises(autopilot.StateError, match="unsafe or unreadable") as raised:
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            selected,
            100_000,
            context="runtime evidence",
        )
    assert mutated is True
    assert raised.value.__cause__ is not None
    assert "changed while being read" in str(raised.value.__cause__)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX descriptor reads")
def test_pinned_runtime_reader_detects_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A replaced logical ancestor cannot redirect a pinned evidence read."""
    parent = tmp_path / "run"
    archived = tmp_path / "run-before-swap"
    parent.mkdir()
    selected = parent / "evidence.log"
    selected.write_bytes(b"a" * 70_000)
    original_read = autopilot.os.read
    swapped = False

    def swap_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        chunk = original_read(descriptor, size)
        if chunk and not swapped:
            parent.rename(archived)
            parent.mkdir()
            (parent / "evidence.log").write_bytes(b"redirected")
            swapped = True
        return chunk

    monkeypatch.setattr(autopilot.os, "read", swap_after_first_chunk)

    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            selected,
            100_000,
            context="runtime evidence",
        )
    assert swapped is True


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX descriptor reads")
def test_pinned_runtime_reader_checks_mutation_before_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raced oversized file is classified as changed, never merely too large."""
    selected = tmp_path / "evidence.log"
    selected.write_bytes(b"a" * 70_000)
    original_read = autopilot.os.read
    mutated = False

    def rewrite_after_first_chunk(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, size)
        if chunk and not mutated:
            selected.write_bytes(b"b" * 70_000)
            mutated = True
        return chunk

    monkeypatch.setattr(autopilot.os, "read", rewrite_after_first_chunk)

    with pytest.raises(autopilot.StateError) as raised:
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            tmp_path,
            selected,
            65_000,
            context="runtime evidence",
        )
    assert mutated is True
    assert raised.value.__cause__ is not None
    assert "changed while being read" in str(raised.value.__cause__)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX descriptor reads")
def test_optional_command_marker_disappearing_after_lookup_is_unsafe(
    repo_factory: Callable[..., RepositoryFixture],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only an initially absent marker is optional; a raced marker is unsafe."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "vanish"
    started_path, _result, _stdout, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    autopilot.atomic_write_json(
        started_path,
        {
            "command_sha256": autopilot._command_sha256(command),  # noqa: SLF001
            "schema_version": 1,
        },
    )
    original_open = autopilot.os.open
    removed = False

    def remove_before_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal removed
        if os.fspath(path) == started_path.name and dir_fd is not None and not removed:
            started_path.unlink()
            removed = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(autopilot.os, "open", remove_before_open)
    monkeypatch.setattr(autopilot, "_supports_pinned_descriptor_reads", lambda: True)

    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001
    assert removed is True


def test_windows_pinned_runtime_reader_rejects_invalid_native_read_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A contradictory native byte count cannot underflow the bounded loop."""

    def invalid_read(
        _handle: object,
        _buffer: object,
        requested: int,
        count: object,
        _overlapped: object,
    ) -> int:
        count._obj.value = requested + 1  # type: ignore[attr-defined]  # noqa: SLF001
        return 1

    api = cast(
        "autopilot._ControllerWindowsAPI",  # noqa: SLF001
        argparse.Namespace(read_file=invalid_read),
    )
    chain = autopilot._ControllerWindowsDirectoryChain(  # noqa: SLF001
        (1,), ((1, b"a" * 16, 0),)
    )
    snapshot = autopilot._ControllerWindowsFileSnapshot(  # noqa: SLF001
        attributes=0,
        volume_serial_number=1,
        file_id=b"a" * 16,
        file_size=1,
        creation_time=1,
        last_write_time=1,
        change_time=1,
    )
    monkeypatch.setattr(autopilot, "_controller_windows_api", lambda: api)
    monkeypatch.setattr(
        autopilot,
        "_controller_windows_open_directory_chain",
        lambda *_args: chain,
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_open_relative", lambda *_args, **_kwargs: 2
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_is_real_file", lambda *_args: True
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_file_snapshot", lambda *_args: snapshot
    )
    monkeypatch.setattr(
        autopilot, "_controller_close_windows_handle", lambda *_args: None
    )

    with pytest.raises(OSError, match="invalid byte count"):
        autopilot._controller_read_windows_pinned_file(  # noqa: SLF001
            tmp_path,
            Path("evidence.log"),
            4,
        )


def test_windows_pinned_runtime_reader_rejects_snapshot_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows file identity and mutation metadata must remain stable."""

    def end_of_file(
        _handle: object,
        _buffer: object,
        _requested: int,
        count: object,
        _overlapped: object,
    ) -> int:
        count._obj.value = 0  # type: ignore[attr-defined]  # noqa: SLF001
        return 1

    api = cast(
        "autopilot._ControllerWindowsAPI",  # noqa: SLF001
        argparse.Namespace(read_file=end_of_file),
    )
    chain = autopilot._ControllerWindowsDirectoryChain(  # noqa: SLF001
        (1,), ((1, b"a" * 16, 0),)
    )
    initial = autopilot._ControllerWindowsFileSnapshot(  # noqa: SLF001
        attributes=0,
        volume_serial_number=1,
        file_id=b"a" * 16,
        file_size=0,
        creation_time=1,
        last_write_time=1,
        change_time=1,
    )
    changed = autopilot._ControllerWindowsFileSnapshot(  # noqa: SLF001
        attributes=0,
        volume_serial_number=1,
        file_id=b"a" * 16,
        file_size=1,
        creation_time=1,
        last_write_time=2,
        change_time=2,
    )
    snapshots = iter((initial, changed))
    monkeypatch.setattr(autopilot, "_controller_windows_api", lambda: api)
    monkeypatch.setattr(
        autopilot,
        "_controller_windows_open_directory_chain",
        lambda *_args: chain,
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_open_relative", lambda *_args, **_kwargs: 2
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_is_real_file", lambda *_args: True
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_file_snapshot", lambda *_args: next(snapshots)
    )
    monkeypatch.setattr(
        autopilot, "_controller_windows_is_real_directory", lambda *_args: True
    )
    monkeypatch.setattr(
        autopilot, "_controller_close_windows_handle", lambda *_args: None
    )

    with pytest.raises(OSError, match="changed while being read"):
        autopilot._controller_read_windows_pinned_file(  # noqa: SLF001
            tmp_path,
            Path("evidence.log"),
            4,
        )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handles")
@pytest.mark.parametrize("component", ["ancestor", "leaf"])
def test_windows_pinned_runtime_reader_rejects_reparse_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component: str,
) -> None:
    """Native relative handles reject swapped ancestor and leaf reparse points."""
    root = tmp_path / "root"
    parent = root / "parent"
    outside = tmp_path / "outside"
    root.mkdir()
    parent.mkdir()
    outside.mkdir()
    selected = parent / "evidence.log"
    selected.write_bytes(b"inside")
    (outside / "evidence.log").write_bytes(b"outside")
    probe = root / "probe"
    try:
        probe.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("the Windows runner cannot create symlinks")
    probe.unlink()
    swapped = False
    if component == "ancestor":
        original_chain = autopilot._controller_windows_open_directory_chain  # noqa: SLF001

        def swap_ancestor(
            api: autopilot._ControllerWindowsAPI,
            opened_root: Path,
            relative_parent: Path,
        ) -> autopilot._ControllerWindowsDirectoryChain:
            nonlocal swapped
            archived = root / "parent-before-swap"
            parent.rename(archived)
            parent.symlink_to(outside, target_is_directory=True)
            swapped = True
            return original_chain(api, opened_root, relative_parent)

        monkeypatch.setattr(
            autopilot,
            "_controller_windows_open_directory_chain",
            swap_ancestor,
        )
    else:
        original_relative = autopilot._controller_windows_open_relative  # noqa: SLF001

        def swap_leaf(
            api: autopilot._ControllerWindowsAPI,
            parent_handle: int,
            name: str,
            creation: autopilot._ControllerNtCreateOptions,
            *,
            missing_leaf: bool = False,
        ) -> int:
            nonlocal swapped
            if name == selected.name and missing_leaf and not swapped:
                archived = parent / "evidence-before-swap.log"
                selected.rename(archived)
                selected.symlink_to(outside / "evidence.log")
                swapped = True
            return original_relative(
                api,
                parent_handle,
                name,
                creation,
                missing_leaf=missing_leaf,
            )

        monkeypatch.setattr(
            autopilot,
            "_controller_windows_open_relative",
            swap_leaf,
        )

    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        autopilot._read_pinned_file_bytes(  # noqa: SLF001
            root,
            selected,
            64,
            context="runtime evidence",
        )
    assert swapped is True


def test_command_output_sidecar_hash_detects_tampering(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A changed machine sidecar cannot be accepted under an old receipt."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "sidecar"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "original\n", "", 0.01),
        log_base,
    )
    autopilot._command_output_path(log_base).write_text(  # noqa: SLF001
        '{"schema_version": 1}\n', encoding="ascii"
    )

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_overflow_receipt_flags_and_complete_human_logs_fail_closed_on_tamper(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Resume rejects missing finals, partial temps, and overflow contradictions."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = (sys.executable, "-c", "print('x' * 1048577, end='')")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "flags"
    result = pilot.runner.run(
        command,
        cwd=fixture.root,
        # Coverage traces the byte-oriented streaming sanitizer and can make
        # draining this stress payload much slower than the child itself.
        timeout_seconds=30,
        log_base=log_base,
    )
    assert not result.timed_out
    assert result.stdout_overflow
    evidence_paths = autopilot._command_evidence_paths  # noqa: SLF001
    _started, result_path, stdout_path, _stderr = evidence_paths(log_base)
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["stdout_overflow"] = False
    autopilot.atomic_write_json(result_path, receipt)
    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001

    receipt["stdout_overflow"] = True
    autopilot.atomic_write_json(result_path, receipt)
    partial = stdout_path.with_name(f".{stdout_path.name}.partial.tmp")
    stdout_path.replace(partial)
    with pytest.raises(autopilot.StateError, match="unsafe or unreadable"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001
    assert partial.is_file()


def test_whitespace_receipt_cannot_claim_nonempty_hosted_output(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """The authenticated sidecar rejects a forged human non-whitespace flag."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = (sys.executable, "-c", "import sys; sys.stdout.write(' \\t\\n')")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "space"
    result = pilot.runner.run(
        command,
        cwd=fixture.root,
        timeout_seconds=10,
        log_base=log_base,
    )
    assert result.human_stdout_non_whitespace is False
    result_path = autopilot._command_evidence_paths(log_base)[1]  # noqa: SLF001
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["stdout_non_whitespace"] = True
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_overflowed_whitespace_log_rejects_coordinated_metadata_tamper(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """The complete human log disproves forged sidecar and receipt flags."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = (
        sys.executable,
        "-c",
        f"import sys; sys.stdout.write(' ' * {autopilot.MAX_RESULT_BYTES + 1})",
    )
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "spaces"
    result = pilot.runner.run(
        command,
        cwd=fixture.root,
        # Coverage traces the byte-oriented streaming sanitizer and can make
        # draining this stress payload much slower than the child itself.
        timeout_seconds=30,
        log_base=log_base,
    )
    assert not result.timed_out
    assert result.stdout_overflow
    assert result.human_stdout_non_whitespace is False

    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    output_document = json.loads(output_path.read_text(encoding="ascii"))
    output_document["stdout_non_whitespace"] = True
    autopilot.atomic_write_json(output_path, output_document)
    result_path = autopilot._command_evidence_paths(log_base)[1]  # noqa: SLF001
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["stdout_non_whitespace"] = True
    receipt["output_sha256"] = hashlib.sha256(output_path.read_bytes()).hexdigest()
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


@pytest.mark.parametrize("mutation", ["extra-key", "boolean-version"])
def test_command_output_sidecar_requires_a_strict_document(
    repo_factory: Callable[..., RepositoryFixture],
    mutation: str,
) -> None:
    """Unknown fields and JSON booleans cannot masquerade as schema data."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / mutation
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "original", "", 0.01),
        log_base,
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    document = json.loads(output_path.read_text(encoding="ascii"))
    if mutation == "extra-key":
        document["extra"] = "unexpected"
    else:
        document["schema_version"] = True
    autopilot.atomic_write_json(output_path, document)
    _started, result_path, _stdout, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["output_sha256"] = hashlib.sha256(output_path.read_bytes()).hexdigest()
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


@pytest.mark.parametrize("failure", ["missing", "oversized"])
def test_command_output_sidecar_refuses_missing_or_oversized_files(
    repo_factory: Callable[..., RepositoryFixture],
    failure: str,
) -> None:
    """Resume fails closed before parsing an absent or oversized sidecar."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / failure
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "original", "", 0.01),
        log_base,
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    if failure == "missing":
        output_path.unlink()
    else:
        output_path.write_bytes(
            b"x" * (autopilot.MAX_COMMAND_OUTPUT_DOCUMENT_BYTES + 1)
        )

    with pytest.raises(autopilot.StateError, match="output evidence is unsafe"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


@pytest.mark.skipif(os.name == "nt", reason="symlink creation is privileged on Windows")
def test_command_output_sidecar_refuses_a_symlink(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A resumable machine-evidence path cannot redirect outside its run."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "symlink"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "original", "", 0.01),
        log_base,
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    target = fixture.root / "outside-output.json"
    output_path.replace(target)
    output_path.symlink_to(target)

    with pytest.raises(autopilot.StateError, match="output evidence is unsafe"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_command_output_sidecar_rejects_invalid_base64_with_matching_hash(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A recomputed receipt does not make malformed stream encoding valid."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "base64"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "original", "", 0.01),
        log_base,
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    autopilot.atomic_write_json(
        output_path,
        {
            "schema_version": 2,
            "stderr_base64": "",
            "stderr_non_whitespace": False,
            "stderr_overflow": False,
            "stdout_base64": "not-base64!",
            "stdout_non_whitespace": True,
            "stdout_overflow": False,
        },
    )
    _started, result_path, _stdout, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["output_sha256"] = hashlib.sha256(output_path.read_bytes()).hexdigest()
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="stdout evidence is malformed"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_command_output_sidecar_and_human_log_must_agree(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Individually hashed human and machine views cannot contradict each other."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "views"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "machine\n", "", 0.01),
        log_base,
    )
    _started, result_path, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    stdout_path.write_text("different", encoding="utf-8")
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["stdout_sha256"] = autopilot.sha256_text("different")
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_command_output_sidecar_must_itself_be_redacted(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """A forged receipt cannot reintroduce a credential through resume parsing."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    token = "gh" + "p_" + ("a" * 24)
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "secret"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "safe", "", 0.01),
        log_base,
    )
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    output_document = autopilot._command_output_document(token, "")  # noqa: SLF001
    output_path.write_bytes(output_document)
    visible = autopilot._safe_log_text(token)  # noqa: SLF001
    _started, result_path, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    stdout_path.write_text(visible, encoding="utf-8")
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["output_sha256"] = hashlib.sha256(output_document).hexdigest()
    receipt["stdout_sha256"] = autopilot.sha256_text(visible)
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="contradictory"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001


def test_command_output_sidecar_enforces_decoded_stream_limit(
    repo_factory: Callable[..., RepositoryFixture],
) -> None:
    """Base64 expansion cannot bypass the established one-megabyte stream cap."""
    fixture = repo_factory()
    pilot = fixture.make_autopilot()
    command = ("gh", "api", "fixture")
    log_base = fixture.root / ".autopilot" / "runs" / "test" / "logs" / "oversized"
    pilot.runner.write_logs(
        autopilot.CommandResult(command, 0, "safe", "", 0.01),
        log_base,
    )
    oversized = "x" * (autopilot.MAX_RESULT_BYTES + 1)
    output_path = autopilot._command_output_path(log_base)  # noqa: SLF001
    output_document = autopilot._command_output_document(oversized, "")  # noqa: SLF001
    output_path.write_bytes(output_document)
    visible = autopilot._safe_log_text(oversized)  # noqa: SLF001
    _started, result_path, stdout_path, _stderr = autopilot._command_evidence_paths(  # noqa: SLF001
        log_base
    )
    stdout_path.write_text(visible, encoding="utf-8")
    receipt = json.loads(result_path.read_text(encoding="utf-8"))
    receipt["output_sha256"] = hashlib.sha256(output_document).hexdigest()
    receipt["stdout_sha256"] = autopilot.sha256_text(visible)
    autopilot.atomic_write_json(result_path, receipt)

    with pytest.raises(autopilot.StateError, match="stdout evidence is unsafe"):
        pilot._read_command_evidence(log_base, command)  # noqa: SLF001
