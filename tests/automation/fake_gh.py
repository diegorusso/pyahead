"""Offline GitHub CLI stand-in for publication tests."""

# This module is an executable fixture and intentionally prints CLI responses.
# ruff: noqa: EM101, T201, TRY003

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import cast

EVENTS_ENV = "PYAHEAD_FAKE_GH_EVENTS"
PR_LIST_ENV = "PYAHEAD_FAKE_GH_PR_LIST"


def _record(arguments: list[str]) -> None:
    """Append a fake GitHub invocation to the external test log."""
    path_value = os.environ.get(EVENTS_ENV)
    if path_value is None:
        return
    path = Path(path_value)
    events: list[object] = []
    if path.exists():
        loaded = cast("object", json.loads(path.read_text(encoding="utf-8")))
        if not isinstance(loaded, list):
            raise RuntimeError("fake GitHub event log is malformed")
        events = loaded
    events.append(arguments)
    path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")


def main(arguments: list[str] | None = None) -> int:
    """Implement the authenticated draft-PR calls used by the orchestrator."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    _record(argv)
    if argv == ["--version"]:
        print("gh version fixture")
        return 0
    if argv == ["auth", "status"]:
        return 0
    if argv[:2] == ["pr", "list"]:
        print(os.environ.get(PR_LIST_ENV, "[]"))
        return 0
    if argv[:2] == ["pr", "create"]:
        print("https://example.invalid/diegorusso/pyahead/pull/1")
        return 0
    if argv[:2] == ["pr", "edit"]:
        return 0
    return 41


if __name__ == "__main__":
    raise SystemExit(main())
