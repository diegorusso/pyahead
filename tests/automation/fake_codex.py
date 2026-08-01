"""Deterministic offline stand-in for the Codex CLI used by orchestrator tests."""

# The fake deliberately launches Git from an explicit argv and prints CLI help.
# ruff: noqa: EM101, EM102, S603, T201, TRY003, TRY004

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from typing import cast

PLAN_ENV = "PYAHEAD_FAKE_CODEX_PLAN"
STATE_ENV = "PYAHEAD_FAKE_CODEX_STATE"
EVENTS_ENV = "PYAHEAD_FAKE_CODEX_EVENTS"
GIT_ENV = "PYAHEAD_FAKE_GIT"
CHILD_ENV = "PYAHEAD_AUTOPILOT_CHILD"


def _write_json(path: Path, value: object) -> None:
    """Replace a small fake-control document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _read_plan() -> list[dict[str, object]]:
    """Read the test-owned sequence of expected role actions."""
    plan_path = Path(os.environ[PLAN_ENV])
    loaded = cast("object", json.loads(plan_path.read_text(encoding="utf-8")))
    if not isinstance(loaded, list) or not all(
        isinstance(item, dict) for item in loaded
    ):
        raise RuntimeError("fake Codex plan must be a list of objects")
    return cast("list[dict[str, object]]", loaded)


def _next_action() -> tuple[int, dict[str, object]]:
    """Consume exactly one action from the external counter."""
    state_path = Path(os.environ[STATE_ENV])
    index = 0
    if state_path.exists():
        loaded = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, int) or isinstance(loaded, bool):
            raise RuntimeError("fake Codex counter is malformed")
        index = loaded
    actions = _read_plan()
    if index >= len(actions):
        raise RuntimeError(f"fake Codex plan exhausted at invocation {index}")
    _write_json(state_path, index + 1)
    return index, actions[index]


def _option(arguments: list[str], name: str) -> str:
    """Return one required two-token option value."""
    index = arguments.index(name)
    return arguments[index + 1]


def _role(prompt: str) -> str:
    """Read the repository-owned role marker from the prompt."""
    match = re.search(
        r"^PYAHEAD_AUTOPILOT_ROLE: (implementation|review|repair)$",
        prompt,
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError("prompt has no autopilot role marker")
    return match.group(1)


def _milestone(prompt: str) -> str:
    """Extract the selected milestone from the rendered heading."""
    match = re.search(
        r"^# (?:Implement|Repair|Independently review) (M[0-9]+)", prompt, re.MULTILINE
    )
    if match is None:
        raise RuntimeError("prompt has no milestone heading")
    return match.group(1)


def _safe_path(root: Path, value: str) -> Path:
    """Keep fake scenario edits inside its temporary repository."""
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError("fake scenario contains an unsafe path")
    return root.joinpath(*relative.parts)


def _apply_changes(root: Path, action: dict[str, object]) -> None:
    """Apply the action's deterministic worktree edits."""
    changes = action.get("changes", {})
    if not isinstance(changes, dict):
        raise RuntimeError("fake changes must be an object")
    for raw_path, raw_content in changes.items():
        if not isinstance(raw_path, str):
            raise RuntimeError("fake changed path must be a string")
        path = _safe_path(root, raw_path)
        if raw_content is None:
            path.unlink(missing_ok=True)
            continue
        if not isinstance(raw_content, str):
            raise RuntimeError("fake changed content must be a string or null")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw_content, encoding="utf-8")


def _refresh_index_stat_cache(root: Path, action: dict[str, object]) -> None:
    """Emulate a read-only Git status refreshing physical index stat data."""
    raw_path = action.get("refresh_index")
    if raw_path is None:
        return
    if not isinstance(raw_path, str):
        raise RuntimeError("fake refresh_index must be a path string")
    path = _safe_path(root, raw_path)
    metadata = path.stat()
    os.utime(
        path,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000),
    )
    git = os.environ.get(GIT_ENV, "git")
    subprocess.run(
        [git, "status", "--porcelain=v1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _changed_paths(root: Path) -> list[str]:
    """Return the complete current worktree path set like the real agent must."""
    git = os.environ.get(GIT_ENV, "git")
    result = subprocess.run(
        [git, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    paths: set[str] = set()
    records = result.stdout.split("\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        status = record[:2]
        paths.add(record[3:])
        if "R" in status or "C" in status:
            paths.add(records[index])
            index += 1
    return sorted(paths)


def _result(role: str, milestone: str, root: Path, action: dict[str, object]) -> object:
    """Build one schema-conforming or intentionally contradictory result."""
    outcome = action.get("outcome", "pass" if role == "review" else "completed")
    if not isinstance(outcome, str):
        raise RuntimeError("fake outcome must be a string")
    if role == "review":
        findings: list[dict[str, object]] = []
        blocking_reason: str | None = None
        if outcome == "changes_requested":
            findings.append(
                {
                    "severity": "high",
                    "file": "feature.txt",
                    "line": 1,
                    "explanation": "fixture review finding",
                    "required_remediation": "replace the fixture content",
                }
            )
        elif outcome == "blocked":
            blocking_reason = "fixture reviewer blocker"
        return {
            "milestone": milestone,
            "verdict": outcome,
            "findings": findings,
            "acceptance_evidence_inspected": ["fixture verification logs"],
            "blocking_reason": blocking_reason,
        }
    blocking_reason = None
    if outcome in {"blocked", "failed"}:
        blocking_reason = f"fixture {outcome} result"
    files = _changed_paths(root)
    if action.get("contradict_files") is True:
        files = ["not-the-worktree.txt"]
    return {
        "milestone": milestone,
        "status": outcome,
        "summary": "fixture agent result",
        "files_changed": files,
        "acceptance_criteria_addressed": ["fixture criterion"],
        "commands_reportedly_run": [],
        "limitations": [],
        "blocking_reason": blocking_reason,
    }


def _record_event(
    index: int,
    role: str,
    prompt: str,
    arguments: list[str],
) -> None:
    """Append invocation evidence outside the Git worktree."""
    events_path = Path(os.environ[EVENTS_ENV])
    events: list[object] = []
    if events_path.exists():
        loaded = cast("object", json.loads(events_path.read_text(encoding="utf-8")))
        if not isinstance(loaded, list):
            raise RuntimeError("fake event log is malformed")
        events = loaded
    events.append(
        {
            "index": index,
            "role": role,
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "sandbox": _option(arguments, "--sandbox"),
            "approval": _option(arguments, "--ask-for-approval"),
            "child_marker": os.environ.get(CHILD_ENV),
            "arguments": arguments,
        }
    )
    _write_json(events_path, events)


def _help(arguments: list[str]) -> int | None:
    """Emulate only the documented CLI capability probes."""
    if arguments == ["--help"]:
        print("--ask-for-approval <untrusted|on-request|never> --config exec")
        return 0
    if arguments in (
        ["exec", "--help"],
        ["--ask-for-approval", "never", "exec", "--help"],
        [
            "--ask-for-approval",
            "never",
            "--config",
            'approval_policy="never"',
            "exec",
            "--help",
        ],
    ):
        print(
            "--ephemeral --sandbox workspace-write read-only --output-schema "
            "--output-last-message --color --cd"
        )
        return 0
    return None


def main(arguments: list[str] | None = None) -> int:
    """Execute one deterministic fake Codex invocation."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    help_result = _help(argv)
    if help_result is not None:
        return help_result
    if argv[:5] != [
        "--ask-for-approval",
        "never",
        "--config",
        'approval_policy="never"',
        "exec",
    ]:
        raise RuntimeError("orchestrator did not set the explicit approval policy")
    prompt = sys.stdin.read()
    role = _role(prompt)
    milestone = _milestone(prompt)
    index, action = _next_action()
    expected_role = action.get("role")
    if expected_role != role:
        raise RuntimeError(f"expected role {expected_role!r}, received {role!r}")
    root = Path(_option(argv, "--cd")).resolve()
    expected_sandbox = "read-only" if role == "review" else "workspace-write"
    if _option(argv, "--sandbox") != expected_sandbox:
        raise RuntimeError("orchestrator selected the wrong sandbox")
    _record_event(index, role, prompt, argv)
    sleep_seconds = action.get("sleep_seconds", 0)
    if not isinstance(sleep_seconds, (int, float)) or isinstance(sleep_seconds, bool):
        raise RuntimeError("fake sleep_seconds must be numeric")
    if sleep_seconds:
        time.sleep(float(sleep_seconds))
    _apply_changes(root, action)
    _refresh_index_stat_cache(root, action)
    behavior = action.get("behavior", "result")
    if behavior == "exit_failure":
        return 19
    output_path = Path(_option(argv, "--output-last-message"))
    if behavior == "missing":
        return 0
    if behavior == "malformed":
        output_path.write_text("{not-json", encoding="utf-8")
        return 0
    result = _result(role, milestone, root, action)
    _write_json(output_path, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
