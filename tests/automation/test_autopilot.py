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
    git: str

    def set_plan(self, actions: Sequence[Mapping[str, object]]) -> None:
        """Install a deterministic fresh-session action sequence."""
        self.plan_path.write_text(
            json.dumps(actions, indent=2) + "\n",
            encoding="utf-8",
        )
        self.counter_path.unlink(missing_ok=True)
        self.codex_events_path.unlink(missing_ok=True)

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
            and command[1] == "push"
            and result.succeeded
        ):
            self.crashed = True
            raise SimulatedCrashError("after successful push")
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
milestone_verification = []

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
    git_command: Sequence[str] = [real_git]
    fail_sentinel = control / "fail-push-once"
    if fail_push_once:
        git_command = [sys.executable, str(FAKE_GIT)]
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
    _run([real_git, "remote", "add", "origin", str(origin)], cwd=root)
    _run([real_git, "push", "--set-upstream", "origin", "main"], cwd=root)
    _run(
        [real_git, "--git-dir", str(origin), "symbolic-ref", "HEAD", "refs/heads/main"]
    )

    plan_path = control / "codex-plan.json"
    counter_path = control / "codex-counter.json"
    codex_events_path = control / "codex-events.json"
    gh_events_path = control / "gh-events.json"
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_PLAN", str(plan_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_STATE", str(counter_path))
    monkeypatch.setenv("PYAHEAD_FAKE_CODEX_EVENTS", str(codex_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GH_EVENTS", str(gh_events_path))
    monkeypatch.setenv("PYAHEAD_FAKE_GIT", real_git)
    monkeypatch.setenv("PYAHEAD_FAKE_GIT_REAL", real_git)
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

    environment = autopilot._repository_environment()  # noqa: SLF001

    assert "GIT_DIR" not in environment
    assert "GIT_WORK_TREE" not in environment
    assert "GIT_CONFIG_KEY_0" not in environment
    assert "GIT_CONFIG_VALUE_0" not in environment
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"


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
    assert publication["pr_url"] == "https://example.invalid/diegorusso/pyahead/pull/1"
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
    url = "https://example.invalid/diegorusso/pyahead/pull/7"
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
        push=False,
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
