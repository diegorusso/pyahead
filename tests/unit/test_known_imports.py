"""The known-import table only names things every CPython in the window has."""

import importlib
import sys

import pytest

from pyahead.analysis.known_imports import KNOWN_IMPORTS
from pyahead.model import (
    ChangeEventKind,
    ModuleImportMatcher,
    QualifiedReferenceMatcher,
)
from pyahead.registry import load_registry
from pyahead.versions import PythonMinor

REGISTRY = load_registry()
_HOST = PythonMinor(major=3, minor=sys.version_info.minor)
_NEWEST_RELEASE = max(release.python for release in REGISTRY.releases)


def test_no_entry_is_something_the_registry_says_goes_away() -> None:
    """A fallback around a removed import is the case the handler exists for."""
    removed: set[str] = set()
    for rule in REGISTRY.rules:
        if not any(event.kind is ChangeEventKind.REMOVED for event in rule.events):
            continue
        for matcher in rule.matchers:
            if isinstance(matcher, ModuleImportMatcher):
                removed.add(matcher.module)
            elif isinstance(matcher, QualifiedReferenceMatcher):
                removed.add(matcher.qualified_name)
    assert not removed.intersection(KNOWN_IMPORTS)


def test_entries_are_dotted_names_with_versions_inside_the_release_list() -> None:
    """Every entry is a plain dotted name with a first version CPython has shipped."""
    for name, since in KNOWN_IMPORTS.items():
        assert all(part.isidentifier() for part in name.split(".")), name
        assert PythonMinor.parse("3.0") <= since <= _NEWEST_RELEASE, name


@pytest.mark.parametrize(
    "name",
    sorted(name for name, since in KNOWN_IMPORTS.items() if since <= _HOST),
)
def test_entry_imports_on_the_host_that_should_have_it(name: str) -> None:
    """A listed name resolves on this interpreter, as a module or an attribute.

    This is the one place the table is checked against a real interpreter; the
    analyser itself never imports the code it scans.
    """
    module_name, _, attribute = name.rpartition(".")
    try:
        importlib.import_module(name)
    except ImportError:
        assert module_name, name
        module = importlib.import_module(module_name)
        assert hasattr(module, attribute), name
