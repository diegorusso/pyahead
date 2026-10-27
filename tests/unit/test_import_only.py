"""Removed-symbol imports fill gaps without duplicating existing findings."""

from pathlib import Path

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import MatchConfidence, ScanReport


def _scan(tmp_path: Path, source: str, *, confidence: str = "high") -> ScanReport:
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    return scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
            minimum_confidence=confidence,
        )
    )


@pytest.mark.parametrize("alias", ["getargspec", "getargspec as legacy"])
def test_unused_removed_symbol_is_reported(tmp_path: Path, alias: str) -> None:
    """Importing a removed symbol fails even if the name is never used."""
    report = _scan(tmp_path, f"from inspect import {alias}\n")
    (finding,) = report.findings
    assert finding.rule_id == "CPY0201"
    assert finding.location.region.start.line == 1
    assert finding.match_confidence is MatchConfidence.HIGH
    assert finding.impact.value == "breaking"


def test_reported_use_covers_its_import(tmp_path: Path) -> None:
    """Keep the existing use site and its released fingerprint."""
    report = _scan(
        tmp_path, "from inspect import getargspec\ngetargspec(lambda: None)\n"
    )
    (finding,) = report.findings
    assert finding.location.region.start.line == 2  # noqa: PLR2004
    assert finding.fingerprint == (
        "151a3854ff68b9b2f7e0128539475772ca3769bc3a52266957c702091151c20a"
    )


def test_multiple_aliases_share_the_imports_reported_uses(tmp_path: Path) -> None:
    """A use of either binding covers their shared import statement."""
    report = _scan(
        tmp_path, "from inspect import getargspec as a, getargspec as b\nb(1)\n"
    )
    (finding,) = report.findings
    assert finding.location.region.start.line == 2  # noqa: PLR2004


@pytest.mark.parametrize("confidence", ["high", "medium"])
def test_unknown_patch_on_one_target_keeps_proven_failures_on_others(
    tmp_path: Path, confidence: str
) -> None:
    """Adding an uncertain target cannot erase a known failure on a later one."""
    source = (
        "import sys\nif sys.version_info >= (3, 12, 1):\n"
        "    from inspect import getargspec\n"
    )
    (finding,) = _scan(tmp_path, source, confidence=confidence).findings
    assert tuple(map(str, finding.reachable_versions)) == (
        ("3.13",) if confidence == "high" else ("3.12", "3.13")
    )
    assert finding.match_confidence is MatchConfidence(confidence)


def test_guarded_use_cannot_hide_unconditional_import(tmp_path: Path) -> None:
    """A use guarded away after removal cannot cover the import's failure."""
    report = _scan(
        tmp_path,
        "import sys\nfrom inspect import getargspec\n"
        "if sys.version_info < (3, 11):\n    getargspec(lambda: None)\n",
    )
    (finding,) = report.findings
    assert finding.location.region.start.line == 2  # noqa: PLR2004


def test_import_only_covers_versions_missing_from_a_reported_use(
    tmp_path: Path,
) -> None:
    """An import and a partial use report disjoint failing target sets."""
    report = _scan(
        tmp_path,
        "import sys\nfrom inspect import getargspec\n"
        "if sys.version_info < (3, 12):\n    getargspec(lambda: None)\n",
    )
    by_line = {
        finding.location.region.start.line: tuple(map(str, finding.reachable_versions))
        for finding in report.findings
    }
    assert by_line == {2: ("3.12", "3.13"), 4: ("3.11",)}


def test_unrelated_binding_does_not_cover_an_import(tmp_path: Path) -> None:
    """A use of the same API in another function does not use this binding."""
    report = _scan(
        tmp_path,
        "def first():\n    from inspect import getargspec\n"
        "def second():\n    from inspect import getargspec\n"
        "    getargspec(lambda: None)\n",
    )
    assert {finding.location.region.start.line for finding in report.findings} == {2, 5}


@pytest.mark.parametrize(
    "source",
    [
        "from .inspect import getargspec\n",
        "from inspect import *\n",
        "from typing import Text\n",
        (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
            "    from inspect import getargspec\n"
        ),
        (
            "import sys\nPY2 = sys.version_info[0] == 2\n"
            "if PY2:\n    from inspect import getargspec\n"
        ),
        (
            "import sys\nPY2 = sys.version_info[0] == 2\n"
            "if not PY2:\n    pass\nelse:\n    from inspect import getargspec\n"
        ),
        (
            "import sys\npy = sys.version_info\npy3k = py >= (3, 0, 0)\n"
            "if py3k:\n    if py < (3, 3, 0):\n"
            "        from collections import MutableMapping\n"
            "else:\n    from collections import MutableMapping\n"
        ),
    ],
)
def test_unreachable_or_unresolved_imports_stay_unreported(
    tmp_path: Path, source: str
) -> None:
    """Python 2 aliases and existing origin boundaries hold at both thresholds."""
    assert not _scan(tmp_path, source, confidence="medium").findings


def test_local_module_can_provide_a_removed_stdlib_symbol(tmp_path: Path) -> None:
    """A competing module prevents an exact stdlib-origin claim."""
    (tmp_path / "inspect.py").write_text("getargspec = 1\n", encoding="utf-8")
    assert not _scan(tmp_path, "from inspect import getargspec\n").findings


@pytest.mark.parametrize(
    "condition",
    ["enabled", "PY2"],
)
def test_unknown_import_guards_are_not_high_confidence(
    tmp_path: Path, condition: str
) -> None:
    """Unknown constants cannot introduce exact import-only blockers."""
    source = f"if {condition}:\n    from inspect import getargspec\n"
    assert not _scan(tmp_path, source).findings
    (finding,) = _scan(tmp_path, source, confidence="medium").findings
    assert finding.match_confidence is MatchConfidence.MEDIUM


@pytest.mark.parametrize("handler", ["except ImportError", "except* ImportError"])
def test_unproven_fallback_handler_import_is_not_high_confidence(
    tmp_path: Path, handler: str
) -> None:
    """An extra statement in a working compatibility fallback cannot add blockers."""
    source = (
        "try:\n    from collections.abc import Iterator\n    xrange = range\n"
        f"{handler}:\n    from collections import Iterator\n"
    )
    assert not _scan(tmp_path, source).findings
    (finding,) = _scan(tmp_path, source, confidence="medium").findings
    assert finding.rule_id == "CPY0148"
    assert finding.match_confidence is MatchConfidence.MEDIUM


@pytest.mark.parametrize(
    "decorator",
    [
        "pytest.mark.skipif(sys.version_info >= (3, 9), reason='unsupported')",
        "disabled",
    ],
)
def test_decorated_function_import_requires_medium_confidence(
    tmp_path: Path, decorator: str
) -> None:
    """Decorators can prevent execution, as in srsly's version-skipped test."""
    source = (
        f"import sys\nimport pytest\n@{decorator}\ndef test_deprecation():\n"
        "    with pytest.warns(DeprecationWarning):\n"
        "        from collections import Hashable\n"
    )
    assert not _scan(tmp_path, source).findings
    (finding,) = _scan(tmp_path, source, confidence="medium").findings
    assert finding.rule_id == "CPY0146"
    assert finding.match_confidence is MatchConfidence.MEDIUM


@pytest.mark.parametrize(
    "source",
    [
        (
            "import sys\nPY2 = sys.version_info[0] == 2\nPY2 = enabled\n"
            "if PY2:\n    from inspect import getargspec\n"
        ),
        (
            "import sys\nif enabled:\n    PY2 = sys.version_info[0] == 2\n"
            "if PY2:\n    from inspect import getargspec\n"
        ),
        (
            "import sys\nPY2 = sys.version_info[0] == 2\n"
            "def use(PY2):\n    if PY2:\n        from inspect import getargspec\n"
        ),
        ("import sys\nA = B\nB = A\nif A:\n    from inspect import getargspec\n"),
    ],
)
def test_alias_proofs_reject_rebinding_conditional_writes_and_shadowing(
    tmp_path: Path, source: str
) -> None:
    """Unproven aliases stay uncertain, including cyclic assignment chains."""
    assert not _scan(tmp_path, source).findings
    (finding,) = _scan(tmp_path, source, confidence="medium").findings
    assert finding.match_confidence is MatchConfidence.MEDIUM


@pytest.mark.parametrize("guard", ["True", "not TYPE_CHECKING", "PY3 and not PY2"])
def test_proven_runtime_branch_reports_its_import(tmp_path: Path, guard: str) -> None:
    """Boolean aliases and typing-only exclusions cannot hide a runtime import."""
    source = (
        "import sys\nfrom typing import TYPE_CHECKING\n"
        "PY2 = sys.version_info[0] == 2\nPY3 = not PY2\n"
        f"if {guard}:\n    from inspect import getargspec\n"
    )
    (finding,) = _scan(tmp_path, source).findings
    assert finding.match_confidence is MatchConfidence.HIGH


def test_import_identity_does_not_steal_an_unrelated_uses_fingerprint(
    tmp_path: Path,
) -> None:
    """Unused and used aliases have separate identities in the same scope."""
    report = _scan(
        tmp_path,
        "from inspect import getargspec as unused\n"
        "from inspect import getargspec as used\nused(1)\n",
    )
    by_line = {
        finding.location.region.start.line: finding for finding in report.findings
    }
    assert set(by_line) == {1, 3}
    assert by_line[3].fingerprint == (
        "151a3854ff68b9b2f7e0128539475772ca3769bc3a52266957c702091151c20a"
    )
    assert by_line[1].fingerprint != by_line[3].fingerprint


def test_import_identity_is_stable_across_lines_and_target_windows(
    tmp_path: Path,
) -> None:
    """New identities follow the existing line-independent baseline contract."""
    source = "from inspect import getargspec\n"
    (first,) = _scan(tmp_path, source).findings
    (second,) = _scan(tmp_path, "\n\n" + source).findings
    assert first.fingerprint == second.fingerprint
    report = scan(
        ScanRequest(root=tmp_path, baseline_python="3.12", horizon_python="3.14")
    )
    assert first.fingerprint == report.findings[0].fingerprint
    assert not scan(
        ScanRequest(root=tmp_path, baseline_python="3.8", horizon_python="3.10")
    ).findings


def test_suppressing_the_existing_use_does_not_create_an_import_blocker(
    tmp_path: Path,
) -> None:
    """An explicit suppression keeps the same scope after import-only detection."""
    report = _scan(
        tmp_path,
        "from inspect import getargspec\ngetargspec(1)  # pyahead: ignore[CPY0201]\n",
    )
    (finding,) = report.findings
    assert finding.suppression is not None
    assert report.exit_code == 0


@pytest.mark.parametrize(
    "handler", ["ImportError", "Exception", "(ValueError, ImportError)", ""]
)
def test_optional_symbol_import_with_a_fallback_is_not_a_blocker(
    tmp_path: Path, handler: str
) -> None:
    """The pip/distlib SSL fallback handles the removed symbol's import error."""
    source = (
        "try:\n    from ssl import match_hostname\n"
        f"except {handler}:\n    def match_hostname(*args):\n        pass\n"
    )
    assert not _scan(tmp_path, source, confidence="medium").findings


@pytest.mark.parametrize(
    "source",
    [
        "try:\n    from inspect import getargspec\nexcept ImportError:\n    raise\n",
        (
            "try:\n    from inspect import getargspec\n"
            "except ModuleNotFoundError:\n    pass\n"
        ),
        (
            "try:\n    def load():\n        from inspect import getargspec\n"
            "except ImportError:\n    pass\n"
        ),
    ],
)
def test_unhandled_import_errors_still_report(tmp_path: Path, source: str) -> None:
    """Re-raising, a narrower exception, or a try around a def cannot recover."""
    (finding,) = _scan(tmp_path, source).findings
    assert finding.rule_id == "CPY0201"


def test_an_outer_handler_can_recover_a_reraised_import(tmp_path: Path) -> None:
    """Follow enclosing handlers after an inner handler re-raises."""
    source = (
        "from builtins import ImportError as Missing\n"
        "try:\n    try:\n        from inspect import getargspec\n"
        "    except ImportError:\n        raise\nexcept Missing:\n    pass\n"
    )
    assert not _scan(tmp_path, source).findings


def test_exception_group_handler_can_recover_the_import(tmp_path: Path) -> None:
    """Except-star also catches an ordinary import failure."""
    source = (
        "try:\n    from inspect import getargspec\nexcept* ImportError:\n    pass\n"
    )
    assert not _scan(tmp_path, source).findings
