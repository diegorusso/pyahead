"""The harness reads how a site spells its name, and the import binding it."""

import sys
from pathlib import Path

import pytest

if sys.platform != "linux":  # pragma: no cover - CI platform guard
    pytest.skip("the PyPI harness is Linux-only", allow_module_level=True)

from scripts.pypi_validate._import_sites import ImportSite
from scripts.pypi_validate._site_names import (
    SiteName,
    SourceBinding,
    site_name,
    site_names,
    statement_binding,
)

_TYPING_T = SourceBinding("typing", "typing", None)


def test_an_alias_is_probed_as_the_site_spells_it() -> None:
    """`import typing as t` then `t.AnyStr`: walk `AnyStr` from `t`."""
    source = "import typing as t\n\ndef f(x: t.IO[t.AnyStr]) -> None: ...\n"
    assert site_name(source, 3, 15, "typing.AnyStr") == SiteName(
        "t", ("AnyStr",), _TYPING_T
    )


def test_a_function_local_import_is_the_heads_binding() -> None:
    """A local `import asyncio` is what `asyncio` means inside that function."""
    source = "def f():\n    import asyncio\n    return asyncio.iscoroutinefunction(f)\n"
    assert site_name(source, 3, 12, "asyncio.iscoroutinefunction") == SiteName(
        "asyncio",
        ("iscoroutinefunction",),
        SourceBinding("asyncio", "asyncio", None),
    )


def test_a_type_checking_import_is_the_annotations_binding() -> None:
    """`from typing import Text` under TYPE_CHECKING still names typing.Text."""
    source = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from typing import Text\n"
        "class C:\n"
        "    def m(self, x: 'Text') -> 'Text': ...\n"
        "    y: Text\n"
    )
    assert site_name(source, 6, 8, "typing.Text") == SiteName(
        "Text", (), SourceBinding("typing", "typing", "Text")
    )


def test_a_dotted_import_binds_its_top_package() -> None:
    """`import os.path` binds `os`; `import os.path as p` binds `os.path`."""
    plain = "def f():\n    import os.path\n    return os.path.join\n"
    aliased = "def f():\n    import os.path as p\n    return p.join\n"
    assert site_name(plain, 3, 12, "os.path.join") == SiteName(
        "os", ("path", "join"), SourceBinding("os.path", "os", None)
    )
    assert site_name(aliased, 3, 12, "os.path.join") == SiteName(
        "p", ("join",), SourceBinding("os.path", "os.path", None)
    )


@pytest.mark.parametrize(
    "source",
    [
        # Bound twice: which binding the site sees depends on control flow.
        "try:\n    import asyncio as a\nexcept ImportError:\n    a = None\nx = a.run\n",
        # Bound by something other than an import.
        "a = __import__('asyncio')\nx = a.run\n",
        # A relative import names a project module, not one the probe can import.
        "from . import a\nx = a.run\n",
        # A star import might bind it too.
        "from os import *\nimport asyncio as a\nx = a.run\n",
        # Never bound at all.
        "x = a.run\n",
    ],
)
def test_only_a_single_absolute_import_is_a_source_binding(source: str) -> None:
    """Anything less certain keeps the name as visible as it already was."""
    line = source.count("\n")
    name = site_name(source, line, 5, "asyncio.run")
    assert name == SiteName("a", ("run",), None)


def test_a_parameter_shadows_the_module_import() -> None:
    """A parameter of the same name is the binding, so there is none from source."""
    source = "import typing as t\ndef f(t):\n    return t.AnyStr\n"
    assert site_name(source, 3, 12, "typing.AnyStr") == SiteName("t", ("AnyStr",), None)


def test_global_and_class_scopes_follow_python_lookup() -> None:
    """`global` reaches the module; a class body is not an enclosing scope."""
    source = (
        "import asyncio as a\n"
        "class C:\n"
        "    a = 1\n"
        "    def m(self):\n"
        "        return a.run\n"
        "def g():\n"
        "    global a\n"
        "    return a.run\n"
    )
    module_import = SourceBinding("asyncio", "asyncio", None)
    assert site_name(source, 5, 16, "asyncio.run") == SiteName(
        "a", ("run",), module_import
    )
    assert site_name(source, 8, 12, "asyncio.run") == SiteName(
        "a", ("run",), module_import
    )


def test_an_annotation_is_looked_up_outside_its_function() -> None:
    """A parameter annotation is evaluated where the `def` is, not inside it."""
    source = "import typing as t\ndef f(x: t.AnyStr):\n    import json as t\n"
    assert site_name(source, 2, 10, "typing.AnyStr") == SiteName(
        "t", ("AnyStr",), _TYPING_T
    )


def test_nothing_at_the_location_reads_nothing() -> None:
    """A location with no matching reference, or unparsable source, gives None."""
    assert site_name("x = 1\n", 1, 1, "typing.AnyStr") is None
    assert site_name("def (:\n", 1, 1, "typing.AnyStr") is None


def test_a_function_local_import_finding_is_its_own_binding() -> None:
    """An unconditional local import binds exactly what it names."""
    source = (
        "def f(app=None):\n"
        "    import wx\n"
        "    from distutils.version import LooseVersion as V\n"
    )
    assert statement_binding(source, 3, 5, "V") == SourceBinding(
        "distutils.version", "distutils.version", "LooseVersion"
    )


_SKIPPABLE = {
    # At module level the probe sees the binding itself.
    "module level": ("from imp import load_source\n", 1, 1, "load_source"),
    "version test": (
        "def f():\n    if sys.version_info < (3, 12):\n        import imp\n",
        3,
        9,
        "imp",
    ),
    "early return": (
        (
            "def f():\n"
            "    if sys.version_info >= (3, 12):\n"
            "        return None\n"
            "    import imp\n"
        ),
        4,
        5,
        "imp",
    ),
    "except block": (
        "def f():\n    try:\n        pass\n    except ImportError:\n        import imp",
        5,
        9,
        "imp",
    ),
    "after a try statement": (
        (
            "def f():\n"
            "    try:\n"
            "        unicode = unicode\n"
            "        import imp\n"
            "    except NameError:\n"
            "        pass\n"
        ),
        4,
        9,
        "imp",
    ),
    "bound twice": ("def f():\n    import imp\n    imp = None\n", 2, 5, "imp"),
}


@pytest.mark.parametrize("case", _SKIPPABLE.values(), ids=_SKIPPABLE.keys())
def test_a_local_import_the_source_may_skip_has_no_binding(
    case: tuple[str, int, int, str],
) -> None:
    """Whatever might stop the import from running leaves it not visible."""
    source, line, column, name = case
    assert statement_binding(source, line, column, name) is None


def test_an_earlier_test_that_cannot_exit_does_not_decide() -> None:
    """`if TYPE_CHECKING:` imports above a function do not guard its body."""
    source = "if TYPE_CHECKING:\n    from x import Y\ndef f():\n    import imp\n"
    assert statement_binding(source, 4, 5, "imp") == SourceBinding("imp", "imp", None)


def _finding(
    fingerprint: str, kind: str, line: int, column: int, **evidence: object
) -> dict[str, object]:
    return {
        "fingerprint": fingerprint,
        "match": {"kind": kind, "evidence": evidence},
        "location": {
            "path": "m.py",
            "region": {"start": {"line": line, "column": column}},
        },
    }


def test_site_names_reads_each_finding_from_the_installed_source(
    tmp_path: Path,
) -> None:
    """References get site names; local import findings get statement bindings."""
    (tmp_path / "m.py").write_text(
        "import typing as t\ndef f(x: t.AnyStr):\n    from crypt import crypt as c\n",
        encoding="utf-8",
    )
    findings = [
        _finding("r", "qualified-reference", 2, 10, qualified_names=["typing.AnyStr"]),
        _finding("i", "module-import", 3, 5, bound_names=["c"], syntax="from-import"),
        _finding("p", "module-import", 3, 5, bound_names=["x"], syntax="from-import"),
        _finding("missing", "qualified-reference", 9, 1, qualified_names=["a.b"]),
    ]
    sites = {"p": ImportSite("crypt", "c", platform_conditional=False)}
    names, bindings = site_names(findings, tmp_path, sites)
    assert names == {"r": SiteName("t", ("AnyStr",), _TYPING_T)}
    crypt = SourceBinding("crypt", "crypt", "crypt")
    assert bindings == {"i": crypt, "p": crypt}


def test_site_names_skips_unreadable_sources(tmp_path: Path) -> None:
    """A missing or undecodable file reads as nothing, never as an error."""
    (tmp_path / "m.py").write_bytes(b"\xff\xfe")
    finding = _finding("r", "qualified-reference", 1, 1, qualified_names=["a.b"])
    assert site_names([finding], tmp_path, {}) == ({}, {})
    assert site_names([finding], tmp_path / "gone", {}) == ({}, {})
