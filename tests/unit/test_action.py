"""The repository's GitHub Action keeps its safety and gate contracts."""

import re
from pathlib import Path
from typing import cast

import yaml

ACTION = Path(__file__).parents[2] / "action.yml"


def _action() -> dict[str, object]:
    document = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return cast("dict[str, object]", document)


def _steps() -> list[dict[str, object]]:
    runs = cast("dict[str, object]", _action()["runs"])
    assert runs["using"] == "composite"
    return cast("list[dict[str, object]]", runs["steps"])


def test_no_input_is_interpolated_into_a_shell_script() -> None:
    """Inputs reach scripts through the environment, never as code."""
    for step in _steps():
        script = step.get("run")
        if script is None:
            continue
        assert isinstance(script, str)
        assert "${{" not in script, step["name"]


def test_every_documented_input_reaches_the_steps() -> None:
    """An input nobody reads would be a silent no-op for the user."""
    inputs = cast("dict[str, object]", _action()["inputs"])
    used = ACTION.read_text(encoding="utf-8")
    for name in inputs:
        assert f"inputs.{name}" in used, name


def test_the_gate_runs_after_the_upload() -> None:
    """Findings reach code scanning even when they fail the job."""
    names = [step["name"] for step in _steps()]
    assert names.index("Scan") < names.index("Upload to code scanning")
    assert names.index("Upload to code scanning") < names.index("Apply the gate")
    scan = next(step for step in _steps() if step["name"] == "Scan")
    script = cast("str", scan["run"])
    assert "set +e" in script
    assert script.rstrip().endswith("exit 0")
    assert 'rm -f -- "$PYAHEAD_SARIF"' in script
    assert "--root ." in script


def test_used_actions_are_first_party_and_version_pinned() -> None:
    """Only GitHub's own actions, each at an explicit major or commit."""
    for step in _steps():
        uses = step.get("uses")
        if uses is None:
            continue
        assert isinstance(uses, str)
        owner_and_ref = re.fullmatch(r"(?P<owner>[^/]+)/[^@]+@(?P<ref>.+)", uses)
        assert owner_and_ref is not None, uses
        assert owner_and_ref.group("owner") in {"actions", "github"}, uses
        assert re.fullmatch(r"v\d+|[0-9a-f]{40}", owner_and_ref.group("ref")), uses
