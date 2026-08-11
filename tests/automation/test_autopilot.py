"""Unit and offline integration tests for the autonomous milestone orchestrator."""

# The integration fixture launches explicit Python and Git argv in isolated temporary
# repositories; no command is interpreted by a shell.
# ruff: noqa: ARG002, EM101, PLR2004, S603, TRY003

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

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
    git_command: Sequence[str],
    real_git: str,
    verification_code: str,
) -> None:
    """Write a small strict policy using only local deterministic commands."""
    content = f"""schema_version = 1
state_directory = ".autopilot"
base_branch = "main"
remote = "origin"
default_timeout_seconds = 3
codex_timeout_seconds = 3
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
timeout_seconds = 2
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
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_PLAN", str(plan_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_STATE", str(counter_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_EVENTS", str(codex_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_EVENTS", str(gh_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_RUN_PLAN", str(gh_run_plan_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_RUN_STATE", str(gh_run_state_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GIT", real_git)
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_REAL", real_git)
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
    failure_path = fixture.root / cast("str", state["failed_output_path"])
    assert "timed out" in failure_path.read_text(encoding="utf-8")
    logs = list((fixture.root / ".autopilot/runs").rglob("M2-implementation-0.*.log"))
    assert len(logs) == 2


def test_command_runner_interruption_and_signal_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keyboard interruption is explicit, logged, and distinct from a signal."""

    class InterruptingProcess:
        returncode = -15

        def __init__(self) -> None:
            self.calls = 0
            self.terminated = False

        def communicate(
            self,
            input: str | None = None,  # noqa: A002 - mirrors subprocess API.
            timeout: float | None = None,
        ) -> tuple[str, str]:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return "partial stdout", "partial stderr"

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
    assert log_base.with_suffix(".stdout.log").read_text() == "partial stdout"
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


def test_atomic_state_write_leaves_only_complete_document(tmp_path: Path) -> None:
    """State replacement produces canonical JSON and removes temporary files."""
    state_path = tmp_path / ".autopilot/state.json"
    autopilot.atomic_write_json(state_path, {"phase": "safe", "count": 2})

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
            {"status": "completed", "conclusion": "failure"},
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
    with pytest.raises(autopilot.BlockedError, match="awaiting external"):
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


def test_recursive_child_invocation_is_refused_before_repository_access(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The inherited child marker prevents an agent from nesting the runner."""
    monkeypatch.setenv(autopilot.CHILD_MARKER, "1")

    result = autopilot.main(["status"])

    assert result == int(autopilot.ExitCode.STATE_ERROR)
    assert "recursive invocation" in capsys.readouterr().err


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
    log_base = tmp_path / "credential-output"
    result = autopilot.CommandRunner().run(
        [sys.executable, "-c", f"print({token!r})"],
        cwd=tmp_path,
        timeout_seconds=2,
        log_base=log_base,
    )

    stdout_log = log_base.with_suffix(".stdout.log").read_text(encoding="utf-8")
    redacted_state = json.dumps(
        autopilot._redact_structure({"nested": [token]})  # noqa: SLF001
    )
    assert result.succeeded
    assert token not in result.stdout
    assert token not in stdout_log
    assert token not in redacted_state
    assert "[REDACTED]" in stdout_log
