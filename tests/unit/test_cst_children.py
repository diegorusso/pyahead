"""The depth guard sees exactly the children LibCST reports."""

from pathlib import Path

import libcst as cst

from pyahead.analysis.engine import _child_nodes

_SOURCES = sorted((Path(__file__).parents[2] / "src/pyahead").rglob("*.py"))


def test_field_children_match_libcst_children_on_real_code() -> None:
    """Every node in PyAhead's own source has the same set of children."""
    checked = 0
    for path in _SOURCES:
        stack: list[cst.CSTNode] = [cst.parse_module(path.read_text("utf-8"))]
        while stack:
            node = stack.pop()
            expected = node.children
            assert {id(child) for child in _child_nodes(node)} == {
                id(child) for child in expected
            }, (path, type(node).__name__)
            assert len(list(_child_nodes(node))) == len(expected)
            stack.extend(expected)
            checked += 1
    assert checked > 100_000  # noqa: PLR2004
