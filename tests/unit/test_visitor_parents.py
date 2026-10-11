"""The visitor's ancestor stack answers parent lookups as LibCST would."""

from collections.abc import Mapping
from pathlib import Path, PurePosixPath

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider

from pyahead.analysis.discovery import DiscoveredFile
from pyahead.analysis.engine import _MatcherVisitor
from pyahead.analysis.matchers import build_matcher_index
from pyahead.model import Policy, Registry

_SOURCE = """\
import os

class C(Base, metaclass=M):
    x: "int" = os.sep

    @decorator(arg)
    def f(self, a: int = 1) -> list[str]:
        if hasattr(os, "fspath") and os.fspath(a):
            return [y async for y in z if y]
        return {k: v for k, v in a.items()}
"""


class _Recorder(_MatcherVisitor):
    """Compare every parent lookup the visitor could make with LibCST's."""

    def __init__(
        self, parents: Mapping[cst.CSTNode, cst.CSTNode] | None = None
    ) -> None:
        empty = Registry(release="t", revision="t", retired_ids=(), rules=())
        super().__init__(
            DiscoveredFile(
                absolute_path=Path("/project/m.py"),
                relative_path=PurePosixPath("m.py"),
            ),
            build_matcher_index(empty),
            {},
            Policy.parse("3.11", "3.13").target_versions,
            (".",),
        )
        self.checked = 0
        self._expected_parents = parents or {}

    def on_visit(self, node: cst.CSTNode) -> bool:
        result = super().on_visit(node)
        expected = self._expected_parents.get(node)
        assert self._parent(node) is expected
        for child in node.children:
            assert self._parent(child) is node
        self.checked += 1
        return result


def test_parent_lookups_match_libcst_for_every_node() -> None:
    """Current nodes and their direct children resolve from the stack."""
    wrapper = MetadataWrapper(cst.parse_module(_SOURCE), unsafe_skip_copy=True)
    visitor = _Recorder(wrapper.resolve(ParentNodeProvider))
    wrapper.visit(visitor)
    assert visitor.checked > 100  # noqa: PLR2004


def test_a_node_off_the_stack_falls_back_to_a_full_parent_map() -> None:
    """A lookup outside the current path still answers, never guesses."""
    module = cst.parse_module(_SOURCE)
    visitor = _Recorder()
    visitor._ancestors.append(module)  # noqa: SLF001
    visitor._ancestor_positions[id(module)] = 0  # noqa: SLF001
    class_def = module.body[1]
    assert isinstance(class_def, cst.ClassDef)
    name = class_def.name
    assert visitor._parent(name) is class_def  # noqa: SLF001
    assert visitor._parent(cst.Name("detached")) is None  # noqa: SLF001
