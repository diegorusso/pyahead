"""Command-line interface for static analysis and registry inspection."""

import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import cast

from pyahead import __version__
from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import DiscoveryError
from pyahead.model import ConfigurationError, ExitCode
from pyahead.registry import RegistryError, load_registry
from pyahead.registry.presentation import (
    render_registry_list,
    render_rule_explanation,
)
from pyahead.reporting import render_json, render_text
from pyahead.versions import InvalidPythonMinorError


def _registry_source_options(parser: ArgumentParser) -> None:
    parser.add_argument(
        "registry_path",
        nargs="?",
        type=Path,
        metavar="PATH",
        help="registry directory or index YAML (defaults to bundled data)",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        dest="registry_option",
        metavar="PATH",
        help="registry directory or index YAML (alternative to PATH)",
    )


def _build_parser() -> ArgumentParser:
    """Create the command-line parser."""
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

    registry = subparsers.add_parser("registry", help="inspect registry data")
    registry.set_defaults(command_parser=registry)
    registry_subparsers = registry.add_subparsers(dest="registry_command")
    registry_validate = registry_subparsers.add_parser(
        "validate", help="validate every registry file"
    )
    _registry_source_options(registry_validate)
    registry_list = registry_subparsers.add_parser(
        "list", help="list canonical registry rules"
    )
    _registry_source_options(registry_list)

    explain = subparsers.add_parser("explain", help="explain one registry rule")
    explain.add_argument("rule_id", metavar="RULE_ID")
    explain.add_argument(
        "--registry",
        type=Path,
        metavar="PATH",
        help="registry directory or index YAML (defaults to bundled data)",
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


def _selected_registry_source(arguments: Namespace) -> Path | None:
    path = cast("Path | None", arguments.registry_path)
    option = cast("Path | None", arguments.registry_option)
    if path is not None and option is not None:
        message = "provide a registry as PATH or --registry, not both"
        raise RegistryError(message)
    return option if option is not None else path


def _run_registry(arguments: Namespace) -> int:
    try:
        registry = load_registry(_selected_registry_source(arguments))
        if arguments.registry_command == "validate":
            noun = "rule" if len(registry.rules) == 1 else "rules"
            rendered = (
                f"Registry {registry.release} ({registry.revision[:12]}): "
                f"{len(registry.rules)} {noun} valid.\n"
            )
        elif arguments.registry_command == "list":
            rendered = render_registry_list(registry)
        else:
            return int(ExitCode.INTERNAL_ERROR)
    except RegistryError as error:
        sys.stderr.write(f"pyahead: error: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 - the CLI contract reserves exit code 4.
        sys.stderr.write("pyahead: PYA9000: unexpected internal error\n")
        return int(ExitCode.INTERNAL_ERROR)
    sys.stdout.write(rendered)
    return int(ExitCode.SUCCESS)


def _run_explain(arguments: Namespace) -> int:
    try:
        registry = load_registry(arguments.registry)
        rule = registry.find_rule(arguments.rule_id)
        if rule is not None:
            rendered = render_rule_explanation(registry, rule)
    except RegistryError as error:
        sys.stderr.write(f"pyahead: error: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 - the CLI contract reserves exit code 4.
        sys.stderr.write("pyahead: PYA9000: unexpected internal error\n")
        return int(ExitCode.INTERNAL_ERROR)
    if rule is None:
        sys.stderr.write(
            f"pyahead: error: unknown registry rule ID {arguments.rule_id!r}\n"
        )
        return int(ExitCode.INVALID_INPUT)
    sys.stdout.write(rendered)
    return int(ExitCode.SUCCESS)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return its stable exit code."""
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "check":
        result = _run_check(arguments)
    elif arguments.command == "explain":
        result = _run_explain(arguments)
    elif arguments.command == "registry":
        if arguments.registry_command is None:
            arguments.command_parser.print_help()
            result = int(ExitCode.SUCCESS)
        else:
            result = _run_registry(arguments)
    elif arguments.command == "version":
        sys.stdout.write(f"pyahead {__version__}\n")
        result = int(ExitCode.SUCCESS)
    elif arguments.command is None:
        parser.print_help()
        result = int(ExitCode.SUCCESS)
    else:
        result = int(ExitCode.INTERNAL_ERROR)
    return result
