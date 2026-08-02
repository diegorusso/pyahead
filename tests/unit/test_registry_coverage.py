"""Executable contracts for the curated M5 CPython registry."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from pyahead.analysis import ScanRequest, scan
from pyahead.model import CoverageDisposition, ScanReport
from pyahead.registry import load_registry

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures/rules"
REGISTRY = load_registry()
RULE_IDS = tuple(rule.id for rule in REGISTRY.rules)
_NTURL2PATH_MATCHER_COUNT = 2
_IMPORTLIB_ABC_LOADERS = (
    "Loader",
    "ResourceLoader",
    "InspectLoader",
    "ExecutionLoader",
    "FileLoader",
    "SourceLoader",
)
_IMPORTLIB_MACHINERY_LOADERS = (
    "BuiltinImporter",
    "FrozenImporter",
    "SourceFileLoader",
    "SourcelessFileLoader",
    "ExtensionFileLoader",
    "NamespaceLoader",
    "AppleFrameworkLoader",
)
_IMPORTLIB_UTIL_LOADERS = ("LazyLoader",)

# Independent pins from the 2026-08-02 manual census of the authoritative
# pages. These constants deliberately do not derive from coverage entries, so
# deleting a source item and its classification together still fails a test.
_PINNED_SOURCE_INVENTORIES = {
    "cpython-84131": (
        1,
        "57de535c1ce0dc9b8e9bd35b9d3fe29a684bf51d2c112522dd2a2e64a6b3499a",
    ),
    "cpython-94101": (
        1,
        "212a89c9a10b2ef3b9883d1c8f57c446782aca7359ee0a06f8a1834ca2f0d746",
    ),
    "cpython-94352": (
        1,
        "32d9cad7e06baaf9dba49a89fd786971be36edb2e84e0c3d38d29af3f84a0c2f",
    ),
    "cpython-97670": (
        1,
        "71d85ee49c89fa58bf2a08d59603060b8f11fb8b5d060dbcd5a6e7e5a6b46264",
    ),
    "cpython-101773": (
        1,
        "ff2f3652d0b7bde6adf93b65c86a61d33bb7918fc52aaecf267c8ba9330d8b0d",
    ),
    "pep-0594": (
        22,
        "885ef0ae29b74c6088ba445ba1cf69ac56ee5696ebb12fe4429f5c21872077d9",
    ),
    "python-3.12-removed": (
        51,
        "17d0a7d3d8516abd8d80321adfe8eb2df3df3d7cdb58afd7ade06d62b205156e",
    ),
    "python-3.12-deprecated": (
        42,
        "fc54c66609dead2063aac56e20a9bd484a817bfae3deaaef4a9bfad822e6cd5c",
    ),
    "python-3.13-removed": (
        67,
        "a4a026684128efa68e42851c164ccb60a147ee271407f6118a4b0231c78c6d6a",
    ),
    "python-3.13-deprecated": (
        27,
        "a007753db26811f295fa2ca0a7b38f84a6e604116686bb3ffee648201439f4b7",
    ),
    "python-3.14-removed": (
        37,
        "a6e867afeffcafeda7bd8e00c7bb7b2f1966ba27f87169e4baa7726632553db7",
    ),
    "python-3.14-deprecated": (
        26,
        "48afacb5cddeb062c909c774a64c0e8fddbc69cbb5402a7bb37eef81ef892fb1",
    ),
    "python-deprecations": (
        100,
        "3a237a2a8ef2fc9a4e1d169ecd95a1d5b4df1bdde34aa9bca94ff399fb20d97e",
    ),
}


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return cast("dict[str, object]", value)


def _sequence(value: object) -> Sequence[object]:
    assert isinstance(value, list)
    return cast("list[object]", value)


def _string(value: object) -> str:
    assert isinstance(value, str)
    return value


def _string_list(value: object) -> list[str]:
    values = _sequence(value)
    assert all(isinstance(item, str) for item in values)
    return cast("list[str]", values)


def _finding_records(report: ScanReport) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for finding in report.findings:
        resolution = dict(finding.match_evidence).get("resolution")
        assert isinstance(resolution, str)
        records.append(
            {
                "action_version": str(finding.action_version),
                "confidence": finding.match_confidence.value,
                "impact": finding.impact.value,
                "reachable_versions": [
                    str(version) for version in finding.reachable_versions
                ],
                "resolution": resolution,
                "rule_id": finding.rule_id,
                "usage_contexts": [context.value for context in finding.usage_contexts],
            }
        )
    return records


def test_every_rule_has_source_coverage_and_a_fixture_manifest() -> None:
    """Curated rules and executable fixture directories form the same set."""
    fixture_ids = {
        path.name
        for path in FIXTURE_ROOT.iterdir()
        if path.is_dir() and (path / "expected.json").is_file()
    }
    covered_ids = {
        rule_id
        for manifest in REGISTRY.coverage
        for entry in manifest.entries
        if entry.disposition
        in {CoverageDisposition.IMPLEMENTED, CoverageDisposition.PARTIAL}
        for rule_id in entry.rules
    }

    assert fixture_ids == set(RULE_IDS)
    assert covered_ids == set(RULE_IDS)


def test_authoritative_source_inventories_match_independent_pins() -> None:
    """A source item cannot disappear together with its manifest entry."""
    actual: dict[str, tuple[int, str]] = {}
    for manifest in REGISTRY.coverage:
        inventory = "\n".join(manifest.source_keys).encode()
        actual[manifest.source.id] = (
            len(manifest.source_keys),
            hashlib.sha256(inventory).hexdigest(),
        )

    assert actual == _PINNED_SOURCE_INVENTORIES


def test_released_removed_censuses_retain_independently_audited_entries() -> None:
    """Regression names make the previously omitted source items reviewable."""
    keys_by_source = {
        manifest.source.id: set(manifest.source_keys) for manifest in REGISTRY.coverage
    }

    assert {
        "enum-enummeta-getattr",
        "configparser-parsingerror-filename",
        "ftplib-ftp-tls-ssl-version",
    } <= keys_by_source["python-3.12-removed"]
    assert {
        "frame-clear-suspended",
        "importlib-metadata-entrypoint-subscript",
        "opcode-pseudo-apis",
        "typing-typeddict-keyword-fields",
    } <= keys_by_source["python-3.13-removed"]
    assert {
        "argparse-nested-groups",
        "asyncio-get-event-loop-no-current-loop",
        "pathlib-path-extra-keywords",
        "sqlite3-named-placeholders-sequence",
    } <= keys_by_source["python-3.14-removed"]


def test_reviewed_source_fidelity_regressions() -> None:
    """High-risk reviewed timelines and exact subjects stay source-faithful."""
    events = {
        rule.id: [(str(event.python), event.kind.value) for event in rule.events]
        for rule in REGISTRY.rules
    }

    assert events["CPY0044"] == [("3.12", "deprecated")]
    assert events["CPY0040"] == [
        ("3.12", "deprecated"),
        ("3.14", "removed"),
    ]
    assert events["CPY0064"] == [
        ("3.12", "deprecated"),
        ("3.14", "removed"),
    ]
    assert events["CPY0057"] == [
        ("3.14", "deprecated"),
        ("3.15", "signature_changed"),
    ]
    assert events["CPY0058"] == [
        ("3.12", "deprecated"),
        ("3.15", "signature_changed"),
    ]
    ctypes_array_rule = REGISTRY.find_rule("CPY0051")
    assert ctypes_array_rule is not None
    assert "soft-deprecated" in ctypes_array_rule.summary
    assert [event.source_id for event in ctypes_array_rule.events] == [
        "python-3.13-deprecated"
    ]
    assert [(source.id, source.url) for source in ctypes_array_rule.sources] == [
        (
            "python-3.13-deprecated",
            "https://docs.python.org/3.13/whatsnew/3.13.html#new-deprecations",
        )
    ]
    assert ctypes_array_rule.remediation.documentation_url == (
        "https://docs.python.org/3.13/whatsnew/3.13.html#new-deprecations"
    )
    ctypes_manifest = next(
        manifest
        for manifest in REGISTRY.coverage
        if manifest.source.id == "python-3.13-deprecated"
    )
    ctypes_entry = next(
        entry for entry in ctypes_manifest.entries if entry.source_key == "ctypes-array"
    )
    assert ctypes_entry.disposition is CoverageDisposition.IMPLEMENTED
    assert ctypes_entry.rules == ("CPY0051",)
    assert "CPY0048" in REGISTRY.retired_ids
    assert REGISTRY.find_rule("CPY0048") is None
    assert "CPY0081" in REGISTRY.retired_ids
    assert REGISTRY.find_rule("CPY0081") is None

    deprecations_manifest = next(
        manifest
        for manifest in REGISTRY.coverage
        if manifest.source.id == "python-deprecations"
    )
    assert deprecations_manifest.source.url == (
        "https://docs.python.org/3.14/deprecations/index.html"
    )
    assert {
        "future-calendar-january-february",
        "future-codecs-open",
        "future-datetime-naive-utc-methods",
        "future-logging-warn",
        "future-shutil-rmtree-onerror",
        "future-threading-activecount",
        "future-threading-condition-notifyall",
        "future-threading-currentthread",
        "future-threading-event-isset",
        "future-threading-thread-daemon-methods",
        "future-threading-thread-name-methods",
        "future-typing-text",
    } <= set(deprecations_manifest.source_keys)
    assert "pending-3.15-locale-getdefaultlocale" not in (
        deprecations_manifest.source_keys
    )
    assert "pending-3.15-glob-glob0-glob1" not in (deprecations_manifest.source_keys)

    tarfile_rule = REGISTRY.find_rule("CPY0063")
    child_watcher_rule = REGISTRY.find_rule("CPY0043")
    assert tarfile_rule is not None
    assert child_watcher_rule is not None
    assert tarfile_rule.subject == "tarfile.TarFile.tarfile"
    qualified_names = {
        getattr(matcher, "qualified_name", None)
        for matcher in child_watcher_rule.matchers
    }
    assert qualified_names >= {
        "asyncio.AbstractEventLoopPolicy.get_child_watcher",
        "asyncio.AbstractEventLoopPolicy.set_child_watcher",
    }

    pathlib_classes = {
        "Path",
        "PosixPath",
        "PurePath",
        "PurePosixPath",
        "PureWindowsPath",
        "WindowsPath",
    }
    relation_rule = REGISTRY.find_rule("CPY0047")
    reserved_rule = REGISTRY.find_rule("CPY0055")
    constructor_rule = REGISTRY.find_rule("CPY0133")
    dynamic_module_rule = REGISTRY.find_rule("CPY0108")
    assert relation_rule is not None
    assert reserved_rule is not None
    assert constructor_rule is not None
    assert dynamic_module_rule is not None
    relation_names = {
        getattr(matcher, "qualified_name", None) for matcher in relation_rule.matchers
    }
    assert relation_names >= {
        f"pathlib.{class_name}.{method}"
        for class_name in pathlib_classes
        for method in ("is_relative_to", "relative_to")
    }
    assert {
        getattr(matcher, "qualified_name", None) for matcher in reserved_rule.matchers
    } >= {f"pathlib.{class_name}.is_reserved" for class_name in pathlib_classes}
    assert {
        getattr(matcher, "qualified_name", None)
        for matcher in constructor_rule.matchers
    } >= {f"pathlib.{class_name}" for class_name in pathlib_classes}
    assert (
        sum(
            getattr(matcher, "module", None) == "nturl2path"
            for matcher in dynamic_module_rule.matchers
        )
        == _NTURL2PATH_MATCHER_COUNT
    )


def test_importlib_load_module_source_entry_is_partial() -> None:
    """Exact public loader names keep the generic source entry actionable."""
    rule = REGISTRY.find_rule("CPY0137")
    assert rule is not None
    assert [(str(event.python), event.kind.value) for event in rule.events] == [
        ("3.15", "removed")
    ]

    deprecations_manifest = next(
        manifest
        for manifest in REGISTRY.coverage
        if manifest.source.id == "python-deprecations"
    )
    entry = next(
        entry
        for entry in deprecations_manifest.entries
        if entry.source_key == "pending-3.15-importlib-load-module"
    )
    assert entry.disposition is CoverageDisposition.PARTIAL
    assert entry.rules == ("CPY0137",)


def test_reviewed_public_stdlib_alias_matcher_sets_are_pinned() -> None:
    """Exact aliases and stdlib subclasses cannot silently disappear."""
    unittest_aliases = {
        "failUnless",
        "failIf",
        "failUnlessEqual",
        "failIfEqual",
        "failUnlessAlmostEqual",
        "failIfAlmostEqual",
        "failUnlessRaises",
        "assertEquals",
        "assertNotEquals",
        "assertAlmostEquals",
        "assertNotAlmostEquals",
        "assertRegexpMatches",
        "assertNotRegexpMatches",
        "assertRaisesRegexp",
        "assertDictContainsSubset",
        "assert_",
    }
    expected_by_rule = {
        "CPY0035": {
            "unittest.TestProgram.usageExit",
            "unittest.main.usageExit",
        },
        "CPY0036": {
            f"turtle.{class_name}.settiltangle"
            for class_name in ("RawTurtle", "RawPen", "Turtle", "Pen")
        },
        "CPY0043": {
            f"asyncio.{class_name}"
            for class_name in (
                "AbstractChildWatcher",
                "SafeChildWatcher",
                "FastChildWatcher",
                "PidfdChildWatcher",
                "MultiLoopChildWatcher",
                "ThreadedChildWatcher",
            )
        }
        | {"asyncio.get_child_watcher", "asyncio.set_child_watcher"}
        | {
            f"asyncio.{class_name}.{method}"
            for class_name in (
                "AbstractEventLoopPolicy",
                "DefaultEventLoopPolicy",
                "WindowsSelectorEventLoopPolicy",
                "WindowsProactorEventLoopPolicy",
            )
            for method in ("get_child_watcher", "set_child_watcher")
        },
        "CPY0071": {
            f"pathlib.{class_name}.link_to"
            for class_name in ("Path", "PosixPath", "WindowsPath")
        },
        "CPY0072": {
            "configparser.SafeConfigParser",
            "configparser.ConfigParser.readfp",
            "configparser.RawConfigParser.readfp",
            "configparser.ParsingError.filename",
            "configparser.MissingSectionHeaderError.filename",
            "configparser.ParsingError",
        },
        "CPY0073": {
            f"unittest.{class_name}.{method}"
            for class_name in (
                "TestCase",
                "FunctionTestCase",
                "IsolatedAsyncioTestCase",
            )
            for method in unittest_aliases
        }
        | {
            "unittest.TestLoader.loadTestsFromModule",
            "unittest._TextTestResult",
        },
        "CPY0074": {
            "importlib.abc.Finder",
            "importlib.abc.Finder.find_module",
            "importlib.abc.MetaPathFinder.find_module",
            "importlib.abc.PathEntryFinder.find_loader",
            "importlib.abc.PathEntryFinder.find_module",
            "importlib.machinery.BuiltinImporter.find_module",
            "importlib.machinery.FileFinder.find_loader",
            "importlib.machinery.FileFinder.find_module",
            "importlib.machinery.FrozenImporter.find_module",
            "importlib.machinery.PathFinder.find_module",
            "importlib.machinery.WindowsRegistryFinder.find_module",
        },
        "CPY0082": {
            "ftplib.FTP_TLS",
            "http.client.HTTPSConnection",
            "imaplib.IMAP4_SSL",
            "poplib.POP3_SSL",
            "smtplib.LMTP.starttls",
            "smtplib.SMTP.starttls",
            "smtplib.SMTP_SSL",
            "smtplib.SMTP_SSL.starttls",
        },
        "CPY0110": {
            f"pathlib.{class_name}.as_uri"
            for class_name in ("PurePath", "PurePosixPath", "PureWindowsPath")
        },
        "CPY0113": {
            f"tkinter.{class_name}.{method}"
            for class_name in (
                "Variable",
                "StringVar",
                "IntVar",
                "DoubleVar",
                "BooleanVar",
            )
            for method in ("trace_variable", "trace_vdelete", "trace_vinfo")
        },
        "CPY0119": {
            "ssl.SSLContext.set_npn_protocols",
            "ssl.SSLObject.selected_npn_protocol",
            "ssl.SSLSocket.selected_npn_protocol",
        },
        "CPY0125": {
            "threading.currentThread",
            "threading.activeCount",
            "threading.Condition.notifyAll",
            "threading.Event.isSet",
        }
        | {
            f"threading.{class_name}.{method}"
            for class_name in ("Thread", "Timer")
            for method in ("getName", "setName", "isDaemon", "setDaemon")
        },
        "CPY0129": {
            "enum.EnumMeta.__getattr__",
            "enum.EnumType.__getattr__",
        },
        "CPY0137": {
            f"importlib.abc.{class_name}.load_module"
            for class_name in _IMPORTLIB_ABC_LOADERS
        }
        | {
            f"importlib.machinery.{class_name}.load_module"
            for class_name in _IMPORTLIB_MACHINERY_LOADERS
        }
        | {
            f"importlib.util.{class_name}.load_module"
            for class_name in _IMPORTLIB_UTIL_LOADERS
        },
    }

    for rule_id, expected in expected_by_rule.items():
        rule = REGISTRY.find_rule(rule_id)
        assert rule is not None
        actual = {
            qualified_name
            for matcher in rule.matchers
            if (qualified_name := getattr(matcher, "qualified_name", None)) is not None
        }
        assert actual == expected


def test_reviewed_public_stdlib_aliases_are_executable(tmp_path: Path) -> None:
    """Every pinned alias family produces a high-confidence exact match."""
    unittest_aliases = (
        "failUnless",
        "failIf",
        "failUnlessEqual",
        "failIfEqual",
        "failUnlessAlmostEqual",
        "failIfAlmostEqual",
        "failUnlessRaises",
        "assertEquals",
        "assertNotEquals",
        "assertAlmostEquals",
        "assertNotAlmostEquals",
        "assertRegexpMatches",
        "assertNotRegexpMatches",
        "assertRaisesRegexp",
        "assertDictContainsSubset",
        "assert_",
    )
    lines = [
        "from asyncio import DefaultEventLoopPolicy",
        "from asyncio import WindowsProactorEventLoopPolicy",
        "from asyncio import WindowsSelectorEventLoopPolicy",
        "from configparser import MissingSectionHeaderError",
        "from enum import EnumType",
        f"from importlib.abc import {', '.join(_IMPORTLIB_ABC_LOADERS)}",
        "from importlib.machinery import " + ", ".join(_IMPORTLIB_MACHINERY_LOADERS),
        f"from importlib.util import {', '.join(_IMPORTLIB_UTIL_LOADERS)}",
        "from pathlib import PosixPath, PurePosixPath, PureWindowsPath, WindowsPath",
        "from smtplib import LMTP, SMTP_SSL",
        "from ssl import SSLObject",
        "from threading import Timer",
        "from tkinter import BooleanVar, DoubleVar, IntVar, StringVar",
        "from turtle import Pen, RawPen, Turtle",
        "from unittest import FunctionTestCase, IsolatedAsyncioTestCase, main",
        "from third_party import Loader as ThirdPartyLoader",
        "from third_party import WindowsProactorEventLoopPolicy as ThirdPartyPolicy",
        "",
        "aliases = [",
        "    main.usageExit,",
        "    RawPen.settiltangle,",
        "    Turtle.settiltangle,",
        "    Pen.settiltangle,",
        "    DefaultEventLoopPolicy.get_child_watcher,",
        "    DefaultEventLoopPolicy.set_child_watcher,",
        "    WindowsSelectorEventLoopPolicy.get_child_watcher,",
        "    WindowsSelectorEventLoopPolicy.set_child_watcher,",
        "    WindowsProactorEventLoopPolicy.get_child_watcher,",
        "    WindowsProactorEventLoopPolicy.set_child_watcher,",
        "    ThirdPartyPolicy.get_child_watcher,",
        "    ThirdPartyPolicy.set_child_watcher,",
        "    PosixPath.link_to,",
        "    WindowsPath.link_to,",
        "    MissingSectionHeaderError.filename,",
        "    BuiltinImporter.find_module,",
        "    FrozenImporter.find_module,",
        "    ThirdPartyLoader.load_module,",
        "    PurePosixPath.as_uri,",
        "    PureWindowsPath.as_uri,",
        "    SSLObject.selected_npn_protocol,",
    ]
    lines.extend(
        f"    {class_name}.load_module,"
        for class_name in (
            *_IMPORTLIB_ABC_LOADERS,
            *_IMPORTLIB_MACHINERY_LOADERS,
            *_IMPORTLIB_UTIL_LOADERS,
        )
    )
    lines.extend(
        f"    {class_name}.{method},"
        for class_name in ("StringVar", "IntVar", "DoubleVar", "BooleanVar")
        for method in ("trace_variable", "trace_vdelete", "trace_vinfo")
    )
    lines.extend(
        f"    {class_name}.{method},"
        for class_name in ("FunctionTestCase", "IsolatedAsyncioTestCase")
        for method in unittest_aliases
    )
    lines.extend(
        [
            "    Timer.getName,",
            "    Timer.setName,",
            "    Timer.isDaemon,",
            "    Timer.setDaemon,",
            "    EnumType.__getattr__,",
            "]",
            'LMTP.starttls(keyfile="client.key")',
            "LMTP.starttls(None, None)",
            'SMTP_SSL.starttls(certfile="client.pem")',
            "SMTP_SSL.starttls(None, None)",
        ]
    )
    source = tmp_path / "source.py"
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
    windows_policy_lines = {
        line_number
        for line_number, line in enumerate(lines, start=1)
        if "WindowsSelectorEventLoopPolicy." in line
        or "WindowsProactorEventLoopPolicy." in line
    }
    lookalike_lines = {
        line_number
        for line_number, line in enumerate(lines, start=1)
        if "ThirdPartyPolicy." in line or "ThirdPartyLoader." in line
    }

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.16",
            paths=(Path("source.py"),),
        )
    )
    findings_by_rule: dict[str, int] = {}
    rules_by_line: dict[int, set[str]] = {}
    for finding in report.findings:
        assert finding.match_confidence.value == "high"
        assert dict(finding.match_evidence)["resolution"] == "exact-import"
        findings_by_rule[finding.rule_id] = findings_by_rule.get(finding.rule_id, 0) + 1
        rules_by_line.setdefault(finding.location.region.start.line, set()).add(
            finding.rule_id
        )

    for line_number in windows_policy_lines:
        assert rules_by_line[line_number] == {"CPY0042", "CPY0043"}
    assert lookalike_lines.isdisjoint(rules_by_line)

    assert findings_by_rule == {
        "CPY0035": 1,
        "CPY0036": 3,
        "CPY0042": 6,
        "CPY0043": 6,
        "CPY0071": 2,
        "CPY0072": 1,
        "CPY0073": 2 * len(unittest_aliases),
        "CPY0074": 2,
        "CPY0082": 4,
        "CPY0110": 2,
        "CPY0113": 12,
        "CPY0119": 1,
        "CPY0125": 4,
        "CPY0129": 1,
        "CPY0137": (
            len(_IMPORTLIB_ABC_LOADERS)
            + len(_IMPORTLIB_MACHINERY_LOADERS)
            + len(_IMPORTLIB_UTIL_LOADERS)
        ),
    }


def test_removed_source_censuses_contain_only_audited_section_entries() -> None:
    """Catch-all labels from other source sections cannot inflate coverage."""
    keys_by_source = {
        manifest.source.id: set(manifest.source_keys) for manifest in REGISTRY.coverage
    }

    assert keys_by_source["python-3.12-removed"].isdisjoint(
        {
            "shlex-split-none",
            "pathlib-path-link-to",
            "ssl-sslsession-manual-construction",
            "fractions-fraction-normalize",
            "removed-command-line-only-options",
            "random-randrange-noninteger-coercion",
            "os-bytes-like-path-arguments",
            "importlib-metadata-legacy-interfaces",
            "sys-getdxp-special-build",
            "distutils-installation-provisioning",
            "cpython-c-api-removals",
        }
    )
    assert keys_by_source["cpython-84131"] == {"pathlib-path-link-to"}
    assert keys_by_source["cpython-94101"] == {"ssl-sslsession-manual-construction"}
    assert keys_by_source["cpython-94352"] == {"shlex-split-none"}
    assert keys_by_source["cpython-97670"] == {"sys-getdxp-special-build"}
    assert keys_by_source["cpython-101773"] == {"fractions-fraction-normalize"}

    assert keys_by_source["python-3.13-removed"].isdisjoint(
        {
            "cpython-c-api-removals",
            "importlib-resources-resource-alias",
            "platform-specific-build-removals",
            "private-asyncio-set-task-name",
            "removed-command-line-behavior",
        }
    )
    assert keys_by_source["python-3.14-removed"].isdisjoint(
        {
            "cpython-c-api-removals",
            "platform-and-build-specific-removals",
            "runtime-warning-and-introspection-removals",
        }
    )


def test_ast_and_pty_warning_boundaries_are_visible_before_removal(
    tmp_path: Path,
) -> None:
    """Python 3.12 warning events produce findings before the 3.14 removals."""
    source = tmp_path / "source.py"
    source.write_text(
        "from ast import Num\n"
        "from pty import master_open\n\n"
        "values = (Num, master_open)\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
        )
    )
    findings = {finding.rule_id: finding for finding in report.findings}

    assert set(findings) == {"CPY0040", "CPY0064"}
    assert {finding.impact.value for finding in findings.values()} == {"deprecated"}
    assert {str(finding.action_version) for finding in findings.values()} == {"3.12"}


def test_nturl2path_literal_dynamic_import_is_medium_confidence(
    tmp_path: Path,
) -> None:
    """The reviewed module spelling participates in literal import matching."""
    source = tmp_path / "source.py"
    source.write_text(
        'from importlib import import_module\n\nmodule = import_module("nturl2path")\n',
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.16",
            minimum_confidence="medium",
            paths=(Path("source.py"),),
        )
    )

    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "CPY0108"
    assert report.findings[0].match_confidence.value == "medium"


def test_locale_getdefaultlocale_has_no_python_315_breaking_finding(
    tmp_path: Path,
) -> None:
    """The explicitly undeprecated API must not retain its retired M5 rule."""
    source = tmp_path / "source.py"
    source.write_text(
        "from locale import getdefaultlocale\n\nvalue = getdefaultlocale()\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.16",
            paths=(Path("source.py"),),
        )
    )

    assert report.findings == ()


def test_hiding_unscheduled_removals_keeps_concrete_non_removal_changes(
    tmp_path: Path,
) -> None:
    """Released and scheduled signature/behavior breaks remain visible."""
    source = tmp_path / "source.py"
    source.write_text(
        "from argparse import BooleanOptionalAction\n"
        "from threading import RLock\n\n"
        'BooleanOptionalAction(["--flag"], "flag", type=str)\n'
        "RLock(debug=True)\n"
        "value = ~True\n",
        encoding="utf-8",
    )

    for rule_id in ("CPY0045", "CPY0057", "CPY0061"):
        rule = REGISTRY.find_rule(rule_id)
        assert rule is not None
        assert rule.removal_unscheduled

    report = scan(
        ScanRequest(
            root=tmp_path,
            baseline_python="3.11",
            horizon_python="3.16",
            paths=(Path("source.py"),),
            show_unscheduled=False,
        )
    )

    assert {finding.rule_id for finding in report.findings} >= {
        "CPY0045",
        "CPY0057",
        "CPY0061",
    }


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_fixture_manifests_are_executable(rule_id: str) -> None:
    """Every declared positive and negative case agrees with a real scan."""
    rule_root = FIXTURE_ROOT / rule_id
    manifest = _mapping(
        json.loads((rule_root / "expected.json").read_text(encoding="utf-8"))
    )
    assert set(manifest) == {"cases", "policy", "rule_id", "schema_version"}
    assert manifest["schema_version"] == 1
    assert manifest["rule_id"] == rule_id
    policy = _mapping(manifest["policy"])
    assert set(policy) == {"baseline_python", "horizon_python"}
    baseline = _string(policy["baseline_python"])
    horizon = _string(policy["horizon_python"])

    has_positive = False
    has_negative = False
    case_names: set[str] = set()
    for raw_case in _sequence(manifest["cases"]):
        case = _mapping(raw_case)
        assert set(case) == {
            "expected_findings",
            "expected_inference_codes",
            "name",
            "paths",
            "root",
        }
        name = _string(case["name"])
        assert name not in case_names
        case_names.add(name)
        case_root = rule_root / _string(case["root"])
        paths = _string_list(case["paths"])
        assert case_root.is_dir()
        assert all((case_root / path).is_file() for path in paths)

        expected_findings: list[dict[str, object]] = []
        for raw_finding in _sequence(case["expected_findings"]):
            finding = _mapping(raw_finding)
            assert set(finding) == {
                "action_version",
                "confidence",
                "impact",
                "reachable_versions",
                "resolution",
                "rule_id",
                "usage_contexts",
            }
            expected = {
                "action_version": _string(finding["action_version"]),
                "confidence": _string(finding["confidence"]),
                "impact": _string(finding["impact"]),
                "reachable_versions": _string_list(finding["reachable_versions"]),
                "resolution": _string(finding["resolution"]),
                "rule_id": _string(finding["rule_id"]),
                "usage_contexts": _string_list(finding["usage_contexts"]),
            }
            assert expected["rule_id"] == rule_id
            expected_findings.append(expected)

        report = scan(
            ScanRequest(
                root=case_root,
                baseline_python=baseline,
                horizon_python=horizon,
                paths=tuple(Path(path) for path in paths),
            )
        )
        assert _finding_records(report) == expected_findings
        assert [item.code for item in report.inferences] == _string_list(
            case["expected_inference_codes"]
        )
        has_positive |= bool(expected_findings)
        has_negative |= not expected_findings

    assert has_positive
    assert has_negative
