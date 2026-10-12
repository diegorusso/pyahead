"""The harness reads what a from-import really binds before probing it."""

import sys

import pytest

if sys.platform != "linux":  # pragma: no cover - CI platform guard
    pytest.skip("the PyPI harness is Linux-only", allow_module_level=True)

from scripts.pypi_validate._import_sites import ImportSite, import_site


def test_an_alias_probes_the_original_attribute() -> None:
    """`from crypt import crypt as _crypt` compares `_crypt` with crypt.crypt."""
    source = (
        "try:\n"
        "    from crypt import crypt as _crypt\n"
        "except ImportError:\n"
        "    _crypt = None\n"
    )
    assert import_site(source, 2, 5) == ImportSite(
        "crypt", "_crypt", platform_conditional=False, import_error_fallback=True
    )


def test_a_name_the_module_redefines_is_not_probed() -> None:
    """`main` is replaced by a local def, so `warn` shows whether the import ran."""
    source = (
        "from lib2to3.main import main, warn, StdoutRefactoringTool\n"
        "\n"
        "def main(args=None):\n"
        "    return 0\n"
    )
    assert import_site(source, 1, 1) == ImportSite(
        "warn", "warn", platform_conditional=False
    )


def test_every_name_rebound_falls_back_to_the_first() -> None:
    """With nothing better to probe, the first binding is still the honest choice."""
    source = "from a import b\nb = 1\n"
    expected = ImportSite("b", "b", platform_conditional=False)
    assert import_site(source, 1, 1) == expected


@pytest.mark.parametrize(
    "test",
    [
        "os.name == 'nt'",
        "sys.platform.startswith('win')",
        "platform.system() == 'Windows'",
        "not sys.platform == 'darwin'",
    ],
)
def test_a_platform_condition_marks_the_site(test: str) -> None:
    """An import the probe host never runs cannot be refuted there."""
    source = f"if {test}:\n    from nturl2path import url2pathname\n"
    site = import_site(source, 2, 5)
    assert site is not None
    assert site.platform_conditional


def test_a_version_or_other_condition_does_not() -> None:
    """Only platform tests are excused; `if PY2:` mismatches still refute."""
    source = "if PY2:\n    from cgi import escape\n"
    site = import_site(source, 2, 5)
    assert site is not None
    assert not site.platform_conditional


def test_names_bound_in_a_function_scope_only_count_there() -> None:
    """A module-level rebinding does not hide a name imported in a function."""
    source = "def f():\n    from a import b\n    return b\n\nb = 1\n"
    expected = ImportSite("b", "b", platform_conditional=False)
    assert import_site(source, 2, 5) == expected


@pytest.mark.parametrize(
    ("source", "line", "column"),
    [
        ("from a import b\n", 2, 1),
        ("from a import b\n", 1, 3),
        ("from a import *\n", 1, 1),
        ("def broken(:\n", 1, 1),
    ],
)
def test_anything_unreadable_leaves_the_static_evidence_in_charge(
    source: str, line: int, column: int
) -> None:
    """No statement at that spot, a star import or a syntax error: no site."""
    assert import_site(source, line, column) is None


@pytest.mark.parametrize(
    ("handler", "fallback"),
    [
        ("except ImportError:", True),
        ("except (ValueError, ModuleNotFoundError):", True),
        ("except Exception:", True),
        ("except:", True),
        ("except ValueError:", False),
    ],
)
def test_an_import_error_handler_marks_the_site(handler: str, fallback: bool) -> None:  # noqa: FBT001
    """Only handlers that catch a failed import make the try a fallback."""
    source = (
        f"try:\n    from crypt import crypt as _crypt\n{handler}\n    _crypt = None\n"
    )
    site = import_site(source, 2, 5)
    assert site is not None
    assert site.import_error_fallback is fallback


def test_an_import_in_the_handler_is_not_a_fallback_site() -> None:
    """The fallback's own import is the alternative, not the guarded one."""
    source = "try:\n    import a\nexcept ImportError:\n    from crypt import crypt\n"
    site = import_site(source, 4, 5)
    assert site is not None
    assert not site.import_error_fallback
