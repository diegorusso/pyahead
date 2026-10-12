"""The single token pass decides exactly as the former two passes did."""

import io
import random
import tokenize
from pathlib import PurePosixPath

import pytest

from pyahead.analysis.engine import (
    MAX_CST_DEPTH,
    MAX_PARSE_NESTING,
    _token_nesting_diagnostic,
)

_PATH = PurePosixPath("m.py")
_RISKY = {"~", "**", "*", "/", "//", "%", "+", "-", "<<", ">>", "&", "^", "|"}


def _delimiter_pass(source: str) -> str | None:
    depth = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type != tokenize.OP:
                continue
            if token.string in {"(", "[", "{"}:
                depth += 1
                if depth > MAX_PARSE_NESTING:
                    return "delimiter"
            elif token.string in {")", "]", "}"} and depth:
                depth -= 1
    except tokenize.TokenError:
        if depth >= MAX_PARSE_NESTING:
            return "delimiter"
    except IndentationError:
        pass
    return None


def _operator_pass(source: str) -> str | None:
    nesting = 0
    line_tokens = {tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT, tokenize.INDENT}
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in line_tokens:
                nesting = 0
            elif token.type != tokenize.OP:
                continue
            elif token.string in _RISKY:
                nesting += 1
                if nesting > MAX_CST_DEPTH:
                    return "concrete syntax tree"
            else:
                nesting = 0
    except (tokenize.TokenError, IndentationError):
        return None
    return None


def _two_pass_reference(source: str) -> str | None:
    """Decide as 0.6.0 did: the delimiter pass, then the operator pass."""
    return _delimiter_pass(source) or _operator_pass(source)


def _decision(source: str) -> str | None:
    diagnostic = _token_nesting_diagnostic(source, _PATH)
    if diagnostic is None:
        return None
    return diagnostic.message.split(": ", 1)[1].split(" nesting", 1)[0]


def _generated_sources(count: int) -> list[str]:
    rng = random.Random(20261012)  # noqa: S311 - deterministic test data.
    pieces = ["(", ")", "[", "]", "{", "}", " + ", " - ", "~", " ** ", " , ", "1"]
    pieces += ["\n", "\n    ", " x", " = ", " if ", ":", " 'a'", '"""', "\\\n"]
    sources = []
    for _ in range(count):
        size = rng.choice((5, 50, 300, 700))
        weights = rng.choice(
            ((8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2), (1, 1, 1, 1, 1, 1, 9, 9, 3, 3, 1, 2))
        )
        body = rng.choices(pieces[:12], weights=weights, k=size)
        if rng.random() < 0.3:  # noqa: PLR2004 - a third get long operator runs.
            run = rng.randrange(MAX_CST_DEPTH - 5, MAX_CST_DEPTH + 5)
            body.insert(rng.randrange(len(body) + 1), " -" * run + " 1")
        body += rng.choices(pieces, k=rng.randrange(0, 5))
        sources.append("value = " + "".join(body))
    return sources


@pytest.mark.parametrize(
    "source",
    [
        "x = " + "(" * (MAX_PARSE_NESTING + 1) + ")" * (MAX_PARSE_NESTING + 1),
        "x = " + "(" * MAX_PARSE_NESTING,
        "x = " + "(" * (MAX_PARSE_NESTING - 1),
        "x = " + "1 ** " * (MAX_CST_DEPTH + 1) + "1\n",
        "x = " + "1 ** " * (MAX_CST_DEPTH + 1) + "(" * MAX_PARSE_NESTING,
        "x = " + "-" * (MAX_CST_DEPTH + 1) + "1\n" + "if x:\n  a\n b\n",
        "if x:\n    a = 1\n  b = 2\n",
        "x = 1\n",
    ],
)
def test_boundary_sources_match_the_two_pass_reference(source: str) -> None:
    """Limits, unterminated brackets, dedent errors and precedence agree."""
    assert _decision(source) == _two_pass_reference(source)


def test_generated_sources_match_the_two_pass_reference() -> None:
    """Thousands of bracket and operator mixes reach the same decision."""
    decisions = set()
    for source in _generated_sources(3000):
        expected = _two_pass_reference(source)
        assert _decision(source) == expected, source[:120]
        decisions.add(expected)
    assert decisions == {None, "delimiter", "concrete syntax tree"}
