"""Portable Git proxy that can fail exactly one checkpoint push."""

# The fixture forwards an explicit argv to the real Git executable.
# ruff: noqa: S603

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REAL_GIT_ENV = "PYAHEAD_FAKE_GIT_REAL"
FAIL_PUSH_ENV = "PYAHEAD_FAKE_GIT_FAIL_PUSH"


def main(arguments: list[str] | None = None) -> int:
    """Forward Git, except for one sentinel-controlled push failure."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    sentinel_value = os.environ.get(FAIL_PUSH_ENV)
    if argv and argv[0] == "push" and sentinel_value:
        sentinel = Path(sentinel_value)
        if sentinel.exists():
            sentinel.unlink()
            sys.stderr.write("fixture checkpoint push failure\n")
            return 31
    real_git = os.environ[REAL_GIT_ENV]
    result = subprocess.run([real_git, *argv], check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
