"""Terminal-safe escaping for untrusted human-readable values."""

import sys
from argparse import ArgumentParser
from bisect import bisect_right
from typing import NoReturn

_UNICODE_BMP_MAX = 0xFFFF
# Generated from the Unicode 16.0.0 General_Category data by merging the Cc,
# Cf, Cs, Zl, and Zp code points into closed intervals.  Keep the standalone
# controller copy byte-for-byte equivalent; its bootstrap contract forbids a
# project-runtime import.
_UNSAFE_CODEPOINT_RANGES = (
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xD800, 0xDFFF),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)
_UNSAFE_CODEPOINT_BOUNDARIES = tuple(
    boundary for start, end in _UNSAFE_CODEPOINT_RANGES for boundary in (start, end + 1)
)


def _is_unsafe_terminal_codepoint(codepoint: int) -> bool:
    """Use the pinned Unicode contract instead of the host Unicode database."""
    return bool(bisect_right(_UNSAFE_CODEPOINT_BOUNDARIES, codepoint) & 1)


def escape_terminal_text(value: str) -> str:
    """Escape controls without consuming renderer-owned structural newlines.

    Callers apply this boundary to individual untrusted values before adding
    headings, indentation, separators, or line endings of their own.
    """
    rendered: list[str] = []
    for character in value:
        codepoint = ord(character)
        if not _is_unsafe_terminal_codepoint(codepoint):
            rendered.append(character)
            continue
        rendered.append(
            f"\\u{codepoint:04x}"
            if codepoint <= _UNICODE_BMP_MAX
            else f"\\U{codepoint:08x}"
        )
    return "".join(rendered)


class SafeArgumentParser(ArgumentParser):
    """Keep argparse help and failures safe without changing parser semantics."""

    def format_usage(self) -> str:
        """Format structural usage lines with a terminal-safe program name."""
        original = self.prog
        self.prog = escape_terminal_text(original)
        try:
            return super().format_usage()
        finally:
            self.prog = original

    def format_help(self) -> str:
        """Format structural help lines with a terminal-safe program name."""
        original = self.prog
        self.prog = escape_terminal_text(original)
        try:
            return super().format_help()
        finally:
            self.prog = original

    def error(self, message: str) -> NoReturn:
        """Report escaped caller-controlled details with argparse's exit code."""
        self.print_usage(sys.stderr)
        program = escape_terminal_text(self.prog)
        detail = escape_terminal_text(message)
        self.exit(2, f"{program}: error: {detail}\n")
