"""Portable Git proxy that can fail exactly one checkpoint push."""

# The fixture forwards an explicit argv to the real Git executable.
# ruff: noqa: EM101, S603, TRY003

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REAL_GIT_ENV = "PYAHEAD_FAKE_GIT_REAL"
FAIL_PUSH_ENV = "PYAHEAD_FAKE_GIT_FAIL_PUSH"
RACE_CANDIDATE_PUSH_ENV = "PYAHEAD_FAKE_GIT_RACE_CANDIDATE_PUSH"
RACE_EXACT_CANDIDATE_PUSH_ENV = "PYAHEAD_FAKE_GIT_RACE_EXACT_CANDIDATE_PUSH"
EVENTS_ENV = "PYAHEAD_FAKE_GIT_EVENTS"
REMOTE_ENV = "PYAHEAD_FAKE_GIT_REMOTE"
LOGICAL_REMOTE = "https://github.com/example/pyahead.git"


def _record(arguments: list[str]) -> None:
    path_value = os.environ.get(EVENTS_ENV)
    if path_value is None:
        return
    path = Path(path_value)
    events: list[object] = []
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, list):
            raise RuntimeError("fake Git event log is malformed")
        events = loaded
    events.append(arguments)
    path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")


def main(arguments: list[str] | None = None) -> int:
    """Forward Git, except for one sentinel-controlled push failure."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    if argv and argv[0] in {"fsck", "push"}:
        _record(argv)
    sentinel_value = os.environ.get(FAIL_PUSH_ENV)
    if argv and argv[0] == "push" and sentinel_value:
        sentinel = Path(sentinel_value)
        if sentinel.exists():
            sentinel.unlink()
            sys.stderr.write("fixture checkpoint push failure\n")
            return 31
    real_git = os.environ[REAL_GIT_ENV]
    remote_path = os.environ.get(REMOTE_ENV)
    race_value = os.environ.get(RACE_CANDIDATE_PUSH_ENV)
    exact_race_value = os.environ.get(RACE_EXACT_CANDIDATE_PUSH_ENV)
    if (
        argv
        and argv[0] == "push"
        and any(item.startswith("--force-with-lease=refs/heads/") for item in argv)
        and race_value
    ):
        sentinel = Path(race_value)
        if sentinel.exists():
            sentinel.unlink()
            source, remote_ref = argv[-1].split(":", maxsplit=1)
            parent = subprocess.run(
                [real_git, "rev-parse", f"{source}^"],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            ).stdout.strip()
            subprocess.run(
                [real_git, "push", remote_path or argv[-2], f"{parent}:{remote_ref}"],
                check=True,
            )
    if (
        argv
        and argv[0] == "push"
        and any(item.startswith("--force-with-lease=refs/heads/") for item in argv)
        and exact_race_value
    ):
        sentinel = Path(exact_race_value)
        if sentinel.exists():
            sentinel.unlink()
            source, remote_ref = argv[-1].split(":", maxsplit=1)
            subprocess.run(
                [real_git, "push", remote_path or argv[-2], f"{source}:{remote_ref}"],
                check=True,
            )
    forwarded = list(argv)
    if forwarded and forwarded[0] in {"fetch", "ls-remote", "push"} and remote_path:
        forwarded = [
            remote_path if item in {"origin", LOGICAL_REMOTE} else item
            for item in forwarded
        ]
    result = subprocess.run([real_git, *forwarded], check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
