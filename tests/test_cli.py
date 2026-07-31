"""Smoke tests for the bootstrap command-line interface."""

import runpy
import sys

import pytest

from pyahead import __version__
from pyahead.cli import main


def test_version_command(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The module entry point reports the package version and succeeds."""
    monkeypatch.setattr(sys, "argv", ["pyahead", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("pyahead", run_name="__main__")

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out == f"pyahead {__version__}\n"
    assert captured.err == ""


def test_main_accepts_no_arguments() -> None:
    """The root command remains a successful help path."""
    assert main([]) == 0


def test_version_subcommand(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The spelled-out version command matches the global alias."""
    assert main(["version"]) == 0
    assert capsys.readouterr().out == f"pyahead {__version__}\n"
