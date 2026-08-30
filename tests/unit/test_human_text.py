"""Tests for the single terminal-safe text boundary."""

import pytest

from pyahead._human_text import SafeArgumentParser, escape_terminal_text

_ARGPARSE_ERROR = 2
_PROGRAM_AND_DETAIL = 2


@pytest.mark.parametrize(
    ("value", "escaped"),
    [
        ("line\nnext", r"line\u000anext"),
        ("return\rnext", r"return\u000dnext"),
        ("escape\x1b[2J", r"escape\u001b[2J"),
        ("nul\x00byte", r"nul\u0000byte"),
        ("next\u0085line", r"next\u0085line"),
        ("line\u2028separator", r"line\u2028separator"),
        ("paragraph\u2029separator", r"paragraph\u2029separator"),
        ("bidi\u202eoverride", r"bidi\u202eoverride"),
        ("joiner\u200dvalue", r"joiner\u200dvalue"),
        ("surrogate\ud800value", r"surrogate\ud800value"),
        ("tag\U000e0001value", r"tag\U000e0001value"),
        ("new-format\U00013439value", r"new-format\U00013439value"),
    ],
)
def test_terminal_controls_are_escaped(value: str, escaped: str) -> None:
    """Controls cannot add lines, terminal commands, or misleading direction."""
    assert escape_terminal_text(value) == escaped


def test_normal_printable_unicode_is_preserved() -> None:
    """The safety boundary does not make ordinary international text unreadable."""
    value = "café 雪 🚀\u00a0space"

    assert escape_terminal_text(value) == value


def test_argument_parser_escapes_program_name_in_help_and_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Argparse cannot reintroduce controls through its generated usage text."""
    hostile = "tool\nFORGED\x1b[2J\u202e"
    parser = SafeArgumentParser(prog=hostile)

    help_text = parser.format_help()

    assert hostile not in help_text
    assert escape_terminal_text(hostile) in help_text
    with pytest.raises(SystemExit) as raised:
        parser.error(hostile)
    assert raised.value.code == _ARGPARSE_ERROR
    error_text = capsys.readouterr().err
    assert hostile not in error_text
    assert error_text.count(escape_terminal_text(hostile)) >= _PROGRAM_AND_DETAIL
