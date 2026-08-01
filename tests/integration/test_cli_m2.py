"""Integration tests for M2 registry inspection commands."""

import json
from pathlib import Path
from typing import NoReturn, cast

import pytest
import yaml

from pyahead.cli import main
from pyahead.model import ExitCode

_BUNDLED_RULE = (
    Path(__file__).parents[2] / "src/pyahead/data/registry/cpython/CPY0001.yaml"
)


def _write_call_shape_registry(root: Path) -> Path:
    """Create a sourced strict registry that evaluates one literal predicate."""
    registry = root / "registry"
    rule_directory = registry / "cpython"
    rule_directory.mkdir(parents=True)
    loaded = yaml.safe_load(_BUNDLED_RULE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    rule = cast("dict[str, object]", loaded)
    rule["subject"] = {"kind": "function", "name": "targetpkg.old_call"}
    rule["matchers"] = [
        {
            "kind": "call-shape",
            "literal_arguments": [{"position": 0, "equals": "legacy"}],
            "qualified_name": "targetpkg.old_call",
        }
    ]
    (registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "retired_ids: []\n"
            "rules: [cpython/CPY0001.yaml]\n"
        ),
        encoding="utf-8",
    )
    (rule_directory / "CPY0001.yaml").write_text(
        yaml.safe_dump(rule, sort_keys=False),
        encoding="utf-8",
    )
    return registry


@pytest.mark.parametrize(
    "source",
    [
        ('from importlib import import_module as load_module\n\nload_module("cgi")\n'),
        (
            "use_standard_library = False\n\n"
            "if use_standard_library:\n"
            "    from importlib import import_module as load_module\n"
            "else:\n"
            "    from replacement import import_module as load_module\n\n"
            'load_module("cgi")\n'
        ),
    ],
)
def test_literal_dynamic_import_cannot_cross_default_high_confidence_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source: str,
) -> None:
    """Literal and ambiguous dynamic evidence stays below the M2 boundary."""
    (tmp_path / "source.py").write_text(source, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "check",
            "source.py",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--format",
            "json",
        ]
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    gate = cast("dict[str, object]", document["gate"])

    assert result == int(ExitCode.SUCCESS)
    assert document["findings"] == []
    assert gate["failed"] is False
    assert captured.err == ""


def test_malformed_call_shape_literal_is_cli_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A matcher literal failure produces PYA1003 and exit three, never four."""
    registry = _write_call_shape_registry(tmp_path)
    (tmp_path / "source.py").write_text(
        'import targetpkg\ntargetpkg.old_call("\\xzz")\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = main(
        [
            "check",
            "source.py",
            "--baseline-python",
            "3.11",
            "--horizon-python",
            "3.13",
            "--format",
            "json",
            "--registry",
            str(registry),
        ]
    )
    captured = capsys.readouterr()
    document = cast("dict[str, object]", json.loads(captured.out))
    diagnostics = cast("list[dict[str, object]]", document["diagnostics"])

    assert result == int(ExitCode.INCOMPLETE)
    assert [diagnostic["code"] for diagnostic in diagnostics] == ["PYA1003"]
    assert captured.err == ""


def test_registry_validate_and_list_use_the_bundled_snapshot(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Both registry subcommands are deterministic scan-free operations."""
    assert main(["registry", "validate"]) == int(ExitCode.SUCCESS)
    validated = capsys.readouterr()
    assert validated.out.startswith("Registry 2026.07.31 (")
    assert validated.out.endswith(": 1 rule valid.\n")
    assert validated.err == ""

    assert main(["registry", "list"]) == int(ExitCode.SUCCESS)
    listed = capsys.readouterr()
    assert "CPY0001  The cgi module is removed" in listed.out
    assert "Matchers: literal-dynamic-import, module-import" in listed.out
    assert listed.err == ""


def test_explain_works_without_scanning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Rule explanation reads only the registry and never discovers source."""

    def fail_if_scanned(_request: object) -> NoReturn:
        message = "explain must not scan"
        raise AssertionError(message)

    monkeypatch.setattr("pyahead.cli.scan", fail_if_scanned)

    assert main(["explain", "CPY0001"]) == int(ExitCode.SUCCESS)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("CPY0001 — The cgi module is removed\n")
    assert "Python 3.11: deprecated" in captured.out
    assert "Python 3.13: removed" in captured.out
    assert "module-import: module=cgi" in captured.out
    assert 'Example: importlib.import_module("cgi")' in captured.out
    assert "pep-0594:" in captured.out


def test_unknown_rule_and_invalid_registry_exit_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Registry errors stay on stderr and never produce partial output."""
    assert main(["explain", "CPY9999"]) == int(ExitCode.INVALID_INPUT)
    unknown = capsys.readouterr()
    assert unknown.out == ""
    assert "unknown registry rule ID" in unknown.err

    (tmp_path / "index.yaml").write_text(
        "schema_version: 1\nrelease: test\nrules: []\n",
        encoding="utf-8",
    )
    assert main(["registry", "validate", str(tmp_path)]) == int(ExitCode.INVALID_INPUT)
    invalid = capsys.readouterr()
    assert invalid.out == ""
    assert "rules must not be empty" in invalid.err

    assert main(["explain", "CPY0001", "--registry", str(tmp_path)]) == int(
        ExitCode.INVALID_INPUT
    )
    invalid_explain = capsys.readouterr()
    assert invalid_explain.out == ""
    assert "rules must not be empty" in invalid_explain.err


def test_duplicate_yaml_key_is_cli_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Duplicate registry fields fail at the CLI boundary with exit status two."""
    (tmp_path / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: first\n"
            "release: second\n"
            "rules: [cpython/CPY0001.yaml]\n"
        ),
        encoding="utf-8",
    )

    assert main(["registry", "validate", str(tmp_path)]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "not valid YAML" in captured.err


def test_malformed_registry_url_is_cli_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A URL parser failure produces exit two and no partial standard output."""
    rule_directory = tmp_path / "cpython"
    rule_directory.mkdir()
    (tmp_path / "index.yaml").write_text(
        ("schema_version: 1\nrelease: test\nrules: [cpython/CPY0001.yaml]\n"),
        encoding="utf-8",
    )
    rule_text = _BUNDLED_RULE.read_text(encoding="utf-8").replace(
        "https://peps.python.org/pep-0594/",
        "https://[invalid",
        1,
    )
    (rule_directory / "CPY0001.yaml").write_text(rule_text, encoding="utf-8")

    assert main(["registry", "validate", str(tmp_path)]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "direct HTTPS URL" in captured.err


def test_oversized_registry_python_minor_is_cli_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An oversized quoted timeline version returns exit two, never four."""
    rule_directory = tmp_path / "cpython"
    rule_directory.mkdir()
    (tmp_path / "index.yaml").write_text(
        "schema_version: 1\nrelease: test\nrules: [cpython/CPY0001.yaml]\n",
        encoding="utf-8",
    )
    oversized = "3." + ("9" * 5_000)
    rule_text = _BUNDLED_RULE.read_text(encoding="utf-8").replace(
        'python: "3.11"',
        f'python: "{oversized}"',
        1,
    )
    (rule_directory / "CPY0001.yaml").write_text(rule_text, encoding="utf-8")

    assert main(["registry", "validate", str(tmp_path)]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "must be a Python minor" in captured.err


@pytest.mark.parametrize(
    ("case", "index_text"),
    [
        (
            "implicit-huge-integer",
            "schema_version: " + ("9" * 5_000) + "\nrelease: test\nrules: [a.yaml]\n",
        ),
        (
            "deep-sequence",
            "schema_version: 1\nrelease: "
            + ("[" * 80)
            + "test"
            + ("]" * 80)
            + "\nrules: [a.yaml]\n",
        ),
        (
            "alias",
            "schema_version: 1\nrelease: &label test\nrules: [*label]\n",
        ),
        (
            "cycle",
            "schema_version: 1\nrelease: &cycle [*cycle]\nrules: [a.yaml]\n",
        ),
        (
            "lone-surrogate",
            'schema_version: 1\nrelease: "\\uD800"\nrules: [a.yaml]\n',
        ),
        (
            "node-count",
            "schema_version: 1\nrelease: test\nrules:\n" + ("  - a.yaml\n" * 10_100),
        ),
    ],
)
def test_adversarial_yaml_is_cli_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: str,
    index_text: str,
) -> None:
    """Constructor, graph, and Unicode failures stay inside the exit-two boundary."""
    del case
    (tmp_path / "index.yaml").write_text(index_text, encoding="utf-8")

    assert main(["registry", "validate", str(tmp_path)]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("pyahead:")
    assert "PYA9000" not in captured.err


def test_registry_source_forms_and_subcommand_help(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A source has one unambiguous spelling and bare registry prints help."""
    assert main(["registry"]) == int(ExitCode.SUCCESS)
    help_output = capsys.readouterr()
    assert "{validate,list}" in help_output.out

    assert main(
        [
            "registry",
            "validate",
            str(tmp_path),
            "--registry",
            str(tmp_path),
        ]
    ) == int(ExitCode.INVALID_INPUT)
    duplicate = capsys.readouterr()
    assert duplicate.out == ""
    assert "PATH or --registry" in duplicate.err


@pytest.mark.parametrize("source_kind", ["file", "directory", "parent"])
def test_registry_source_symlinks_are_invalid_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    source_kind: str,
) -> None:
    """Explicit registry aliases fail at the CLI boundary without an internal."""
    registry = _write_call_shape_registry(tmp_path / "target")
    alias = tmp_path / f"{source_kind}-link"
    if source_kind == "file":
        target = registry / "index.yaml"
        source = alias
        target_is_directory = False
    elif source_kind == "directory":
        target = registry
        source = alias
        target_is_directory = True
    else:
        target = registry.parent
        source = alias / registry.name / "index.yaml"
        target_is_directory = True
    try:
        alias.symlink_to(target, target_is_directory=target_is_directory)
    except OSError:
        pytest.skip("the platform does not permit symlinks")

    assert main(["registry", "validate", str(source)]) == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "must not traverse symlinks" in captured.err
    assert "PYA9000" not in captured.err


def test_registry_internal_failure_uses_reserved_exit_four(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unexpected registry-tool failures do not expose exception details."""

    def fail(_source: object) -> NoReturn:
        message = "sensitive detail"
        raise RuntimeError(message)

    monkeypatch.setattr("pyahead.cli.load_registry", fail)

    assert main(["registry", "list"]) == int(ExitCode.INTERNAL_ERROR)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "pyahead: PYA9000: unexpected internal error\n"
