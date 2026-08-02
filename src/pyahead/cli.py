"""Command-line interface for static analysis and registry inspection."""

import os
import sys
from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from pathlib import Path
from typing import cast

from pyahead import __version__
from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import DiscoveryError
from pyahead.baseline import render_baseline
from pyahead.config import resolve_project_root
from pyahead.model import (
    ConfigurationError,
    ExitCode,
    PerFileIgnore,
    Registry,
    ScanReport,
)
from pyahead.output import OutputError, write_text_atomic
from pyahead.registry import RegistryError, load_registry
from pyahead.registry.presentation import (
    render_registry_coverage,
    render_registry_list,
    render_rule_explanation,
)
from pyahead.reporting import (
    render_json,
    render_quiet_text,
    render_sarif,
    render_text,
)
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


def _scan_options(
    parser: ArgumentParser,
    *,
    include_report_output: bool,
) -> None:
    parser.add_argument("paths", nargs="*", type=Path, metavar="PATH")
    parser.add_argument(
        "--baseline-python",
        metavar="VERSION",
        help="oldest supported Python minor, such as 3.11",
    )
    parser.add_argument(
        "--horizon-python",
        metavar="VERSION",
        help="latest Python minor to forecast, such as 3.15",
    )
    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="strict TOML configuration beneath the selected root",
    )
    parser.add_argument(
        "--root",
        type=Path,
        metavar="PATH",
        help="project root (otherwise inferred from the current directory)",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        metavar="PATH",
        help="registry directory or index YAML (defaults to bundled data)",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=None,
        metavar="PATTERN",
        help="replace configured include patterns (repeatable)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATTERN",
        help="replace configured exclude patterns (repeatable)",
    )
    parser.add_argument(
        "--source-root",
        action="append",
        default=None,
        dest="source_roots",
        metavar="PATH",
        help="replace configured import source roots (repeatable)",
    )
    parser.add_argument(
        "--respect-gitignore",
        action=BooleanOptionalAction,
        default=None,
        help="respect hierarchical .gitignore rules (default: true)",
    )
    parser.add_argument(
        "--minimum-confidence",
        choices=("high", "medium"),
        default=None,
    )
    parser.add_argument(
        "--fail-on",
        choices=("never", "breaking", "risk", "deprecated", "any"),
        default=None,
    )
    parser.add_argument(
        "--show-unscheduled",
        action=BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--max-file-size-bytes",
        type=int,
        default=None,
        metavar="BYTES",
    )
    parser.add_argument(
        "--per-file-ignore",
        action="append",
        default=[],
        metavar="PATTERN=RULE_ID[,RULE_ID]",
        help="add rule-specific ignores for one path pattern",
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="retain suppressed findings in reports",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="retain incomplete diagnostics without forcing exit code 3",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true")
    verbosity.add_argument("--quiet", action="store_true")
    if include_report_output:
        parser.add_argument(
            "--format",
            choices=("text", "json", "sarif"),
            default="text",
            dest="output_format",
        )
        parser.add_argument(
            "--output",
            type=Path,
            metavar="PATH",
            help="write complete output atomically; use - for stdout",
        )
        parser.add_argument(
            "--baseline-file",
            type=Path,
            metavar="PATH",
            help="baseline beneath the selected root (relative paths use the root)",
        )
        parser.add_argument("--fail-new-only", action="store_true")


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
    _scan_options(check, include_report_output=True)

    baseline = subparsers.add_parser(
        "baseline", help="create deterministic finding baselines"
    )
    baseline.set_defaults(command_parser=baseline)
    baseline_subparsers = baseline.add_subparsers(dest="baseline_command")
    baseline_create = baseline_subparsers.add_parser(
        "create", help="scan and create a baseline"
    )
    _scan_options(baseline_create, include_report_output=False)
    baseline_create.add_argument(
        "--output",
        type=Path,
        default=Path(".pyahead-baseline.json"),
        metavar="PATH",
        help="destination beneath the selected root (relative paths use the root)",
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
    registry_coverage = registry_subparsers.add_parser(
        "coverage", help="report authoritative-source coverage"
    )
    _registry_source_options(registry_coverage)

    explain = subparsers.add_parser("explain", help="explain one registry rule")
    explain.add_argument("rule_id", metavar="RULE_ID")
    explain.add_argument(
        "--registry",
        type=Path,
        metavar="PATH",
        help="registry directory or index YAML (defaults to bundled data)",
    )
    return parser


def _per_file_ignores(values: list[str]) -> tuple[PerFileIgnore, ...]:
    parsed: list[PerFileIgnore] = []
    for value in values:
        pattern, separator, identifiers = value.partition("=")
        rule_ids = tuple(
            dict.fromkeys(
                identifier.strip()
                for identifier in identifiers.split(",")
                if identifier.strip()
            )
        )
        if not separator or not pattern or not rule_ids:
            message = "--per-file-ignore must use PATTERN=RULE_ID[,RULE_ID]"
            raise ConfigurationError(message)
        parsed.append(PerFileIgnore(pattern=pattern, rule_ids=rule_ids))
    return tuple(parsed)


def _scan_request(arguments: Namespace) -> ScanRequest:
    root = resolve_project_root(Path.cwd(), arguments.root)
    current = Path.cwd()
    paths = tuple(
        path if path.is_absolute() else current / path for path in arguments.paths
    )
    return ScanRequest(
        root=root,
        baseline_python=arguments.baseline_python,
        horizon_python=arguments.horizon_python,
        paths=paths,
        registry_source=arguments.registry,
        config_path=arguments.config,
        include=(tuple(arguments.include) if arguments.include is not None else None),
        exclude=(tuple(arguments.exclude) if arguments.exclude is not None else None),
        source_roots=(
            tuple(arguments.source_roots)
            if arguments.source_roots is not None
            else None
        ),
        respect_gitignore=arguments.respect_gitignore,
        minimum_confidence=arguments.minimum_confidence,
        fail_on=getattr(arguments, "fail_on", None),
        show_unscheduled=arguments.show_unscheduled,
        max_file_size_bytes=arguments.max_file_size_bytes,
        per_file_ignores=_per_file_ignores(arguments.per_file_ignore),
        baseline_file=getattr(arguments, "baseline_file", None),
        fail_new_only=getattr(arguments, "fail_new_only", False),
        show_suppressed=arguments.show_suppressed,
        allow_incomplete=arguments.allow_incomplete,
    )


def _write_verbose_configuration(report: ScanReport) -> None:
    configuration = report.configuration
    per_file_ignores = {
        item.pattern: list(item.rule_ids) for item in configuration.per_file_ignores
    }
    sys.stderr.write(
        "pyahead: configuration: "
        f"baseline={report.policy.baseline_python} "
        f"({report.policy_provenance.baseline_python}); "
        f"horizon={report.policy.horizon_python} "
        f"({report.policy_provenance.horizon_python}); "
        f"include={list(configuration.include)!r}; "
        f"exclude={list(configuration.exclude)!r}; "
        f"source-roots={list(configuration.source_roots)!r} "
        f"({configuration.source_roots_provenance}); "
        f"minimum-confidence={configuration.minimum_confidence.value}; "
        f"fail-on={configuration.fail_on.value}; "
        f"respect-gitignore={str(configuration.respect_gitignore).lower()}; "
        f"show-unscheduled={str(configuration.show_unscheduled).lower()}; "
        f"max-file-size-bytes={configuration.max_file_size_bytes}; "
        f"per-file-ignores={per_file_ignores!r}; "
        f"fail-new-only={str(configuration.fail_new_only).lower()}; "
        f"show-suppressed={str(configuration.show_suppressed).lower()}; "
        f"allow-incomplete={str(configuration.allow_incomplete).lower()}\n"
    )


def _write_scan_diagnostics(report: ScanReport) -> None:
    """Write baseline-scan diagnostics without contaminating baseline JSON."""
    for diagnostic in report.diagnostics:
        if diagnostic.location is None:
            location = ""
        else:
            start = diagnostic.location.region.start
            location = (
                f" {diagnostic.location.path.as_posix()}:{start.line}:{start.column}"
            )
        incomplete = " [incomplete analysis]" if diagnostic.incomplete else ""
        sys.stderr.write(
            f"pyahead: {diagnostic.code}{location}: {diagnostic.message}{incomplete}\n"
        )


def _write_output(
    rendered: str,
    output: Path | None,
    *,
    root: Path | None = None,
) -> None:
    if output is None or output == Path("-"):
        sys.stdout.write(rendered)
        return
    selected = output if output.is_absolute() else Path.cwd() / output
    write_text_atomic(selected, rendered, root=root)


def _root_bounded_output_path(
    output: Path | None,
    root: Path,
    *,
    label: str,
) -> Path | None:
    """Resolve an optional destination beneath the selected project root."""
    if output is None or output == Path("-"):
        return output
    selected = output if output.is_absolute() else root / output
    try:
        logical_path = Path(os.path.abspath(selected))  # noqa: PTH100
        logical_path.relative_to(root)
        logical_path.resolve().relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        message = f"{label} output must remain beneath the project root"
        raise OutputError(message) from error
    return logical_path


def _render_check(arguments: Namespace, report: ScanReport) -> str:
    if arguments.output_format == "json":
        return render_json(report)
    if arguments.output_format == "sarif":
        return render_sarif(report)
    if arguments.quiet:
        return render_quiet_text(report)
    return render_text(report)


def _run_check(arguments: Namespace) -> int:
    try:
        request = _scan_request(arguments)
        report = scan(request)
        rendered = _render_check(arguments, report)
        _write_output(
            rendered,
            _root_bounded_output_path(
                arguments.output,
                request.root,
                label="report",
            ),
            root=request.root,
        )
        if arguments.output_format == "text" and arguments.quiet:
            _write_scan_diagnostics(report)
    except (
        ConfigurationError,
        DiscoveryError,
        InvalidPythonMinorError,
        OutputError,
        RegistryError,
    ) as error:
        sys.stderr.write(f"pyahead: error: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 - the CLI contract reserves exit code 4.
        sys.stderr.write("pyahead: PYA9000: unexpected internal error\n")
        return int(ExitCode.INTERNAL_ERROR)

    if arguments.verbose:
        _write_verbose_configuration(report)
    return int(report.exit_code)


def _run_baseline_create(arguments: Namespace) -> int:
    try:
        request = _scan_request(arguments)
        report = scan(request)
        _write_scan_diagnostics(report)
        if report.counts.files_incomplete and not report.configuration.allow_incomplete:
            sys.stderr.write(
                "pyahead: error: refusing to create a baseline from an "
                "incomplete scan\n"
            )
            return int(ExitCode.INCOMPLETE)
        if report.counts.files_incomplete:
            sys.stderr.write(
                "pyahead: warning: source scan is incomplete; baseline contains "
                "only findings from analyzed files\n"
            )
        rendered = render_baseline(report)
        _write_output(
            rendered,
            _root_bounded_output_path(
                arguments.output,
                request.root,
                label="baseline",
            ),
            root=request.root,
        )
    except (
        ConfigurationError,
        DiscoveryError,
        InvalidPythonMinorError,
        OutputError,
        RegistryError,
    ) as error:
        sys.stderr.write(f"pyahead: error: {error}\n")
        return int(ExitCode.INVALID_INPUT)
    except Exception:  # noqa: BLE001 - the CLI contract reserves exit code 4.
        sys.stderr.write("pyahead: PYA9000: unexpected internal error\n")
        return int(ExitCode.INTERNAL_ERROR)
    if arguments.verbose:
        _write_verbose_configuration(report)
    return int(ExitCode.SUCCESS)


def _selected_registry_source(arguments: Namespace) -> Path | None:
    path = cast("Path | None", arguments.registry_path)
    option = cast("Path | None", arguments.registry_option)
    if path is not None and option is not None:
        message = "provide a registry as PATH or --registry, not both"
        raise RegistryError(message)
    return option if option is not None else path


def _render_registry_coverage(registry: Registry) -> str:
    if not registry.coverage:
        message = "registry declares no authoritative-source coverage manifests"
        raise RegistryError(message)
    return render_registry_coverage(registry)


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
        elif arguments.registry_command == "coverage":
            rendered = _render_registry_coverage(registry)
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
    elif arguments.command == "baseline":
        if arguments.baseline_command is None:
            arguments.command_parser.print_help()
            result = int(ExitCode.SUCCESS)
        else:
            result = _run_baseline_create(arguments)
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
