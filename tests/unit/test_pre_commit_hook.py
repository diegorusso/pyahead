"""The repository's pre-commit hook runs the whole-project scan."""

import re
import shlex
import tomllib
from pathlib import Path
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).parents[2]
HOOKS = ROOT / ".pre-commit-hooks.yaml"


def _hook() -> dict[str, object]:
    document = yaml.safe_load(HOOKS.read_text(encoding="utf-8"))
    assert isinstance(document, list)
    assert len(document) == 1
    return cast("dict[str, object]", document[0])


def test_the_hook_runs_the_installed_check_command() -> None:
    """`entry` names the console script the package installs."""
    hook = _hook()
    assert hook["id"] == "pyahead"
    assert hook["language"] == "python"
    entry = shlex.split(cast("str", hook["entry"]))
    assert entry == ["pyahead", "check"]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert entry[0] in project["project"]["scripts"]


def test_the_hook_scans_the_project_not_the_staged_files() -> None:
    """Filenames would be read as project roots, so none are passed."""
    hook = _hook()
    assert hook["pass_filenames"] is False
    assert hook["require_serial"] is True


@pytest.mark.parametrize(
    ("path", "runs"),
    [
        ("app.py", True),
        ("src/pkg/stubs.pyi", True),
        ("pyproject.toml", True),
        ("sub/pyproject.toml", True),
        ("README.md", False),
        ("mypyproject.toml", False),
        ("setup.cfg", False),
        ("notes.pyc", False),
    ],
)
def test_the_hook_runs_when_python_or_its_configuration_changes(
    path: str,
    runs: bool,  # noqa: FBT001 - a parametrized expectation.
) -> None:
    """pre-commit matches `files` with `re.search` against each staged path."""
    pattern = cast("str", _hook()["files"])
    assert (re.search(pattern, path) is not None) is runs
