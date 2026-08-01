"""Command-line interface for the M1 vertical static-analysis slice."""

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from pyahead import __version__
from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import DiscoveryError
from pyahead.model import ConfigurationError, ExitCode
from pyahead.registry import RegistryError
from pyahead.reporting import render_json, render_text
from pyahead.versions import InvalidPythonMinorError


def _build_parser() -> ArgumentParser:
    """Create the M1 command-line parser."""
    parser = ArgumentParser(prog="pyahead")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("version", help="show the installed version")

    check = subparsers.add_parser("check", help="scan Python source")
    check.add_argument("paths", nargs="*", type=Path, metavar="PATH")
    check.add_argument(
        "--baseline-python",
        required=True,
        metavar="VERSION",
        help="oldest supported Python minor, such as 3.11",
    )
    check.add_argument(
        "--horizon-python",
        required=True,
        metavar="VERSION",
        help="latest Python minor to forecast, such as 3.13",
    )
    check.add_argument(
        "--registry",
        type=Path,
        metavar="PATH",
        help="registry directory or index YAML (defaults to bundled data)",
    )
    check.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
    )
    return parser


def _run_check(arguments: Namespace) -> int:
    request = ScanRequest(
        root=Path.cwd(),
        baseline_python=arguments.baseline_python,
        horizon_python=arguments.horizon_python,
        paths=tuple(arguments.paths),
        registry_source=arguments.registry,
    )
    try:
        report = scan(request)
        rendered = (
            render_json(report)
            if arguments.output_format == "json"
            else render_text(report)
        )
    except (
        ConfigurationError,
        DiscoveryError,
        InvalidPythonMinorError,
        RegistryError,
    ) as error:
        sys.stderr.write(f"pyahead: error: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 - the CLI contract reserves exit code 4.
        sys.stderr.write("pyahead: PYA9000: unexpected internal error\n")
        return int(ExitCode.INTERNAL_ERROR)

    sys.stdout.write(rendered)
    return int(report.exit_code)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return its stable exit code."""
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "check":
        return _run_check(arguments)
    if arguments.command == "version":
        sys.stdout.write(f"pyahead {__version__}\n")
        return int(ExitCode.SUCCESS)
    if arguments.command is None:
        parser.print_help()
        return int(ExitCode.SUCCESS)
    return int(ExitCode.INTERNAL_ERROR)
