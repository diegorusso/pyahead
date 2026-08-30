"""Terminal-safety tests for CLI-owned human-readable output."""

from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

import pyahead.cli as cli_module
from pyahead._human_text import SafeArgumentParser
from pyahead.analysis import ScanRequest
from pyahead.model import (
    ConfigurationError,
    Diagnostic,
    DiagnosticCategory,
    EffectiveConfiguration,
    ExitCode,
    PerFileIgnore,
    Policy,
    PolicyProvenance,
    Registry,
    ScanCounts,
    ScanReport,
    SourceLocation,
    SourcePosition,
    SourceRegion,
)

_ARGPARSE_ERROR = 2
_COLLIDING_PATTERNS = 2
_CARRIAGE_RETURN = chr(0x0D)
_ESCAPE = chr(0x1B)
_LINE_SEPARATOR = chr(0x2028)
_PARAGRAPH_SEPARATOR = chr(0x2029)
_RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
_HOSTILE_TEXT = (
    f"line{chr(0x0A)}forged{_CARRIAGE_RETURN}return{_ESCAPE}[2J"
    f"{_LINE_SEPARATOR}split{_PARAGRAPH_SEPARATOR}paragraph"
    f"{_RIGHT_TO_LEFT_OVERRIDE}reordered"
)
_HOSTILE_CONTROLS = (
    _CARRIAGE_RETURN,
    _ESCAPE,
    _LINE_SEPARATOR,
    _PARAGRAPH_SEPARATOR,
    _RIGHT_TO_LEFT_OVERRIDE,
)


def _report() -> ScanReport:
    return ScanReport(
        schema_version=1,
        tool_version="0.1.0a2",
        registry_release="test",
        registry_revision="a" * 64,
        policy=Policy.parse("3.11", "3.13"),
        root_label=".",
        counts=ScanCounts(
            files_discovered=0,
            files_analyzed=0,
            files_incomplete=0,
        ),
        findings=(),
        diagnostics=(),
        inferences=(),
    )


def _assert_hostile_text_is_one_safe_line(text: str) -> None:
    assert "\nforged" not in text
    for control in _HOSTILE_CONTROLS:
        assert control not in text
    for escape in ("u000a", "u000d", "u001b", "u2028", "u2029", "u202e"):
        assert escape in text


def test_argument_parser_and_nested_parser_escape_error_details(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The parser class inherited by subcommands owns a safe error boundary."""
    parser = cli_module._build_parser()  # noqa: SLF001

    with pytest.raises(SystemExit) as raised:
        parser.parse_args(["check", "--format", _HOSTILE_TEXT])

    assert raised.value.code == _ARGPARSE_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "\nforged" not in captured.err
    for control in _HOSTILE_CONTROLS:
        assert control not in captured.err

    subparsers = parser._subparsers  # noqa: SLF001
    assert subparsers is not None
    check_parser = subparsers._group_actions[0].choices["check"]  # noqa: SLF001
    assert isinstance(check_parser, SafeArgumentParser)
    with pytest.raises(SystemExit) as raised:
        check_parser.error(_HOSTILE_TEXT)

    assert raised.value.code == _ARGPARSE_ERROR
    captured = capsys.readouterr()
    _assert_hostile_text_is_one_safe_line(captured.err)


def test_expected_cli_exception_is_escaped(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Caught domain exceptions cannot create forged CLI error records."""

    def fail_scan_request(_arguments: object) -> ScanRequest:
        raise ConfigurationError(_HOSTILE_TEXT)

    monkeypatch.setattr(cli_module, "_scan_request", fail_scan_request)

    result = cli_module._run_check(  # noqa: SLF001
        cli_module.Namespace(
            evidence=[],
            output_format="text",
            source_commit=None,
        )
    )

    assert result == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("\n") == 1
    _assert_hostile_text_is_one_safe_line(captured.err)


@pytest.mark.parametrize("command", ["quiet", "baseline"])
def test_quiet_and_baseline_diagnostics_escape_untrusted_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    """Both diagnostic-only paths preserve their own single line boundary."""
    location = SourceLocation(
        path=PurePosixPath(f"source-{_HOSTILE_TEXT}.py"),
        region=SourceRegion(
            start=SourcePosition(line=1, column=1),
            end=SourcePosition(line=1, column=2),
        ),
    )
    diagnostic = Diagnostic(
        code=f"PYA-{_HOSTILE_TEXT}",
        category=DiagnosticCategory.DISCOVERY,
        message=_HOSTILE_TEXT,
        location=location,
        incomplete=True,
    )
    report = replace(_report(), diagnostics=(diagnostic,))
    request = ScanRequest(
        root=tmp_path,
        baseline_python="3.11",
        horizon_python="3.13",
    )
    monkeypatch.setattr(cli_module, "_scan_request", lambda _arguments: request)
    monkeypatch.setattr(cli_module, "scan", lambda _request: report)

    if command == "quiet":
        result = cli_module._run_check(  # noqa: SLF001
            cli_module.Namespace(
                evidence=[],
                output_format="text",
                source_commit=None,
                quiet=True,
                output=None,
                verbose=False,
            )
        )
    else:
        result = cli_module._run_baseline_create(  # noqa: SLF001
            cli_module.Namespace(output=Path("-"), verbose=False)
        )

    assert result == int(ExitCode.SUCCESS)
    captured = capsys.readouterr()
    assert captured.err.count("\n") == 1
    _assert_hostile_text_is_one_safe_line(captured.err)
    assert "\x1b" not in captured.out


def test_verbose_configuration_escapes_every_caller_controlled_string(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verbose policy output cannot be split or reordered by configuration."""
    configuration = EffectiveConfiguration(
        include=(f"include-{_HOSTILE_TEXT}",),
        exclude=(f"exclude-{_HOSTILE_TEXT}",),
        source_roots=(f"root-{_HOSTILE_TEXT}",),
        source_roots_provenance=f"source-{_HOSTILE_TEXT}",
        per_file_ignores=(
            PerFileIgnore(
                pattern=f"pattern-{_HOSTILE_TEXT}",
                rule_ids=(f"rule-{_HOSTILE_TEXT}",),
            ),
        ),
    )
    provenance = PolicyProvenance(
        baseline_python=f"baseline-{_HOSTILE_TEXT}",
        horizon_python=f"horizon-{_HOSTILE_TEXT}",
    )
    report = replace(
        _report(),
        configuration=configuration,
        policy_provenance=provenance,
    )

    cli_module._write_verbose_configuration(report)  # noqa: SLF001

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("\n") == 1
    _assert_hostile_text_is_one_safe_line(captured.err)


def test_verbose_configuration_preserves_sanitized_key_collisions(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Distinct ignore patterns remain visible when their safe text collides."""
    configuration = EffectiveConfiguration(
        per_file_ignores=(
            PerFileIgnore(pattern="pkg\n*.py", rule_ids=("CPY0001",)),
            PerFileIgnore(pattern=r"pkg\u000a*.py", rule_ids=("CPY0002",)),
        )
    )

    cli_module._write_verbose_configuration(  # noqa: SLF001
        replace(_report(), configuration=configuration)
    )

    rendered = capsys.readouterr().err
    assert rendered.count("pkg\\\\u000a*.py") == _COLLIDING_PATTERNS
    assert rendered.count("CPY0001") == 1
    assert rendered.count("CPY0002") == 1


def test_registry_validation_and_unknown_rule_escape_dynamic_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Registry-owned and command-line values cannot forge output records."""
    registry = Registry(
        release=f"release-{_HOSTILE_TEXT}",
        revision=f"rev-{_HOSTILE_TEXT}",
        retired_ids=(),
        rules=(),
    )
    monkeypatch.setattr(cli_module, "load_registry", lambda _source: registry)

    result = cli_module._run_registry(  # noqa: SLF001
        cli_module.Namespace(
            registry_path=None,
            registry_option=None,
            registry_command="validate",
        )
    )

    assert result == int(ExitCode.SUCCESS)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.count("\n") == 1
    _assert_hostile_text_is_one_safe_line(captured.out)

    result = cli_module._run_explain(  # noqa: SLF001
        cli_module.Namespace(registry=None, rule_id=_HOSTILE_TEXT)
    )

    assert result == int(ExitCode.INVALID_INPUT)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("\n") == 1
    _assert_hostile_text_is_one_safe_line(captured.err)


def test_machine_output_bytes_bypass_the_human_text_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI writes already-rendered JSON or SARIF bytes without alteration."""
    rendered = f'{{"message":"line\\nraw{_LINE_SEPARATOR}separator"}}\n'

    cli_module._write_output(rendered, None)  # noqa: SLF001

    captured = capsys.readouterr()
    assert captured.out == rendered
    assert captured.err == ""
