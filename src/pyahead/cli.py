"""Minimal command-line interface for the repository bootstrap."""

from argparse import ArgumentParser

from pyahead import __version__


def _build_parser() -> ArgumentParser:
    """Create the bootstrap command-line parser."""
    parser = ArgumentParser(prog="pyahead")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the bootstrap command-line interface."""
    _build_parser().parse_args(argv)
    return 0
