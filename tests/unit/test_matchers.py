"""Acceptance fixtures for the indexed M2 matcher framework."""

from pathlib import Path
from typing import cast

import pytest
import yaml

from pyahead.analysis import ScanRequest, scan
from pyahead.analysis.discovery import discover_python_files, project_module_paths
from pyahead.analysis.engine import _parse_file
from pyahead.analysis.matchers import build_matcher_index
from pyahead.model import (
    AnalysisInference,
    BuiltinPattern,
    ExitCode,
    MatchConfidence,
    Policy,
    ScanReport,
    StaticMatch,
)
from pyahead.registry import load_registry

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures/matchers"
RULE_ID = "CPY9001"

MATCHERS: dict[str, dict[str, object]] = {
    "module_import": {"kind": "module-import", "module": "targetpkg"},
    "qualified_reference": {
        "kind": "qualified-reference",
        "qualified_name": "targetpkg.old_attr",
    },
    "qualified_call": {
        "kind": "qualified-call",
        "qualified_name": "targetpkg.old_call",
    },
    "call_shape": {
        "forbidden_keywords": ["modern"],
        "kind": "call-shape",
        "literal_arguments": [
            {"position": 0, "equals": "payload"},
            {"keyword": "mode", "equals": "legacy"},
        ],
        "max_positional_args": 1,
        "min_positional_args": 1,
        "qualified_name": "targetpkg.old_call",
        "required_keywords": ["mode"],
    },
    "literal_dynamic_import": {
        "kind": "literal-dynamic-import",
        "module": "targetpkg",
    },
}
NAMESPACE_PACKAGE_MATCHERS = {
    **MATCHERS,
    "qualified_reference": {
        **MATCHERS["qualified_reference"],
        "qualified_name": "targetpkg.old.old_attr",
    },
    "qualified_call": {
        **MATCHERS["qualified_call"],
        "qualified_name": "targetpkg.old.old_call",
    },
    "call_shape": {
        **MATCHERS["call_shape"],
        "qualified_name": "targetpkg.old.old_call",
    },
}


def _case_matcher(matcher_name: str, case: str) -> dict[str, object]:
    """Use a nested qualified target for implicit namespace-package probes."""
    if case == "namespace_package":
        return NAMESPACE_PACKAGE_MATCHERS[matcher_name]
    return MATCHERS[matcher_name]


def _write_registry(
    root: Path,
    matchers: dict[str, object] | list[dict[str, object]],
    *,
    subject_kind: str = "function",
    subject_name: str = "targetpkg.old_call",
) -> Path:
    registry = root / "registry"
    rule_directory = registry / "cpython"
    rule_directory.mkdir(parents=True)
    matcher_list = matchers if isinstance(matchers, list) else [matchers]
    rule = {
        "schema_version": 1,
        "id": RULE_ID,
        "title": "Matcher acceptance rule",
        "summary": "A synthetic sourced rule used to exercise matcher semantics.",
        "scope": {
            "ecosystem": "python",
            "runtime": "cpython",
            "contexts": ["runtime"],
        },
        "subject": {"kind": subject_kind, "name": subject_name},
        "timeline": [
            {
                "event": "deprecated",
                "python": "3.11",
                "certainty": "released",
                "source": "test-source",
            },
            {
                "event": "removed",
                "python": "3.13",
                "certainty": "released",
                "source": "test-source",
            },
        ],
        "impact": {
            "on_deprecation": "deprecated",
            "on_removal": "breaking",
        },
        "matchers": matcher_list,
        "remediation": {"summary": "Use the supported replacement."},
        "sources": [
            {
                "id": "test-source",
                "title": "Matcher test source",
                "url": "https://example.com/matcher-test",
            }
        ],
        "tags": ["matcher-test"],
    }
    (registry / "index.yaml").write_text(
        (
            "schema_version: 1\n"
            "release: test\n"
            "retired_ids: []\n"
            "rules:\n"
            f"  - cpython/{RULE_ID}.yaml\n"
        ),
        encoding="utf-8",
    )
    (rule_directory / f"{RULE_ID}.yaml").write_text(
        yaml.safe_dump(rule, sort_keys=False),
        encoding="utf-8",
    )
    return registry


def _scan_case(
    tmp_path: Path,
    matcher_name: str,
    case: str,
) -> ScanReport:
    matcher = _case_matcher(matcher_name, case)
    subject_kind = "module" if "module" in matcher else "function"
    subject_name = cast(
        "str",
        matcher.get("module", matcher.get("qualified_name", "targetpkg.old_call")),
    )
    registry = _write_registry(
        tmp_path,
        matcher,
        subject_kind=subject_kind,
        subject_name=subject_name,
    )
    root = FIXTURE_ROOT / matcher_name / case
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
            registry_source=registry,
        )
    )


def _raw_case(
    tmp_path: Path,
    matcher_name: str,
    case: str,
) -> tuple[tuple[StaticMatch, ...], tuple[AnalysisInference, ...]]:
    matcher = _case_matcher(matcher_name, case)
    subject_kind = "module" if "module" in matcher else "function"
    subject_name = cast(
        "str",
        matcher.get("module", matcher.get("qualified_name", "targetpkg.old_call")),
    )
    registry = load_registry(
        _write_registry(
            tmp_path,
            matcher,
            subject_kind=subject_kind,
            subject_name=subject_name,
        )
    )
    root = FIXTURE_ROOT / matcher_name / case
    root_discovery = discover_python_files(root, ())
    selected = discover_python_files(root, (Path("source.py"),))
    matches, inferences, diagnostic = _parse_file(
        selected.files[0],
        build_matcher_index(registry),
        project_module_paths(root_discovery.files, root_discovery.issues),
        Policy.parse("3.11", "3.13").target_versions,
    )
    assert diagnostic is None
    return matches, inferences


@pytest.mark.parametrize("matcher_name", sorted(MATCHERS))
@pytest.mark.parametrize("case", ["positive", "alias"])
def test_each_named_matcher_has_positive_and_alias_fixtures(
    tmp_path: Path,
    matcher_name: str,
    case: str,
) -> None:
    """Every name-based matcher resolves direct and aliased uses."""
    report = _scan_case(tmp_path, matcher_name, case)
    matches, _inferences = _raw_case(tmp_path / "raw", matcher_name, case)

    expected_confidence = (
        MatchConfidence.MEDIUM
        if matcher_name == "literal_dynamic_import"
        else MatchConfidence.HIGH
    )
    assert len(matches) == 1
    assert matches[0].rule_id == RULE_ID
    assert matches[0].matcher_kind == MATCHERS[matcher_name]["kind"]
    assert matches[0].confidence is expected_confidence
    if expected_confidence is MatchConfidence.MEDIUM:
        assert report.findings == ()
        assert report.gate_failed is False
        assert report.exit_code is ExitCode.SUCCESS
    else:
        assert len(report.findings) == 1
        assert report.findings[0].match_confidence is MatchConfidence.HIGH


@pytest.mark.parametrize("matcher_name", sorted(MATCHERS))
@pytest.mark.parametrize("case", ["shadowing", "negative"])
def test_each_named_matcher_has_shadowing_and_negative_fixtures(
    tmp_path: Path,
    matcher_name: str,
    case: str,
) -> None:
    """Lexical shadowing and similar syntax never fabricate exact matches."""
    report = _scan_case(tmp_path, matcher_name, case)

    assert report.findings == ()


@pytest.mark.parametrize("matcher_name", sorted(MATCHERS))
def test_each_named_matcher_has_an_ambiguous_name_fixture(
    tmp_path: Path,
    matcher_name: str,
) -> None:
    """Ambiguous origins are suppressed or explicitly reduced in confidence."""
    report = _scan_case(tmp_path, matcher_name, "ambiguous")
    matches, inferences = _raw_case(tmp_path / "raw", matcher_name, "ambiguous")

    assert report.findings == ()
    assert report.gate_failed is False
    if matcher_name == "module_import":
        assert matches == ()
        assert [inference.code for inference in report.inferences] == ["PYA2001"]
        assert [inference.code for inference in inferences] == ["PYA2001"]
    else:
        assert len(matches) == 1
        assert matches[0].confidence is MatchConfidence.MEDIUM
        assert dict(matches[0].evidence)["resolution"] == "ambiguous-import"


@pytest.mark.parametrize("matcher_name", sorted(MATCHERS))
def test_each_named_matcher_exposes_implicit_namespace_package_ambiguity(
    tmp_path: Path,
    matcher_name: str,
) -> None:
    """A no-init package parent is visible and never produces exact evidence."""
    report = _scan_case(tmp_path, matcher_name, "namespace_package")
    matches, inferences = _raw_case(
        tmp_path / "raw",
        matcher_name,
        "namespace_package",
    )

    assert report.findings == ()
    assert report.gate_failed is False
    assert not any(match.confidence is MatchConfidence.HIGH for match in matches)
    assert [inference.code for inference in report.inferences] == ["PYA2001"]
    assert [inference.code for inference in inferences] == ["PYA2001"]
    assert dict(report.inferences[0].evidence)["candidate_paths"] == (
        "targetpkg/old.py",
    )
    assert dict(inferences[0].evidence)["candidate_paths"] == ("targetpkg/old.py",)


def test_matcher_index_uses_kind_specific_lookup_keys(tmp_path: Path) -> None:
    """Registry matchers compile into terminal/module/hook indexes once."""
    all_matchers = [
        *MATCHERS.values(),
        {"kind": "builtin-pattern", "pattern": "bool-bitwise-inversion"},
    ]
    registry_path = _write_registry(
        tmp_path,
        all_matchers,
        subject_kind="syntax",
        subject_name="matcher-index-test",
    )

    index = build_matcher_index(load_registry(registry_path))

    assert set(index.module_imports) == {"targetpkg"}
    assert set(index.qualified_references) == {"old_attr"}
    assert set(index.qualified_calls) == {"old_call"}
    assert set(index.call_shapes) == {"old_call"}
    assert set(index.literal_dynamic_imports) == {"targetpkg"}
    assert set(index.builtin_patterns) == {BuiltinPattern.BOOL_BITWISE_INVERSION}


def test_builtin_pattern_positive_and_negative_fixtures(tmp_path: Path) -> None:
    """The whitelisted syntax matcher requires the exact built-in literal shape."""
    registry = _write_registry(
        tmp_path,
        {"kind": "builtin-pattern", "pattern": "bool-bitwise-inversion"},
        subject_kind="syntax",
        subject_name="bool-bitwise-inversion",
    )
    reports = {
        case: scan(
            ScanRequest(
                root=FIXTURE_ROOT / "builtin_pattern" / case,
                baseline_python="3.11",
                horizon_python="3.13",
                registry_source=registry,
            )
        )
        for case in ("negative", "positive")
    }

    assert reports["negative"].findings == ()
    assert len(reports["positive"].findings) == 1
    assert reports["positive"].findings[0].match_kind == "builtin-pattern"


@pytest.mark.parametrize("case", ["alias", "shadowing", "ambiguous"])
def test_builtin_pattern_binding_lookalikes_do_not_match(
    tmp_path: Path,
    case: str,
) -> None:
    """Syntax patterns require literals; alias and value ambiguity are irrelevant."""
    registry = _write_registry(
        tmp_path,
        {"kind": "builtin-pattern", "pattern": "bool-bitwise-inversion"},
        subject_kind="syntax",
        subject_name="bool-bitwise-inversion",
    )

    report = scan(
        ScanRequest(
            root=FIXTURE_ROOT / "builtin_pattern" / case,
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    assert report.findings == ()


def test_qualified_reference_context_and_write_filter(tmp_path: Path) -> None:
    """Reference contexts select annotations and exclude attribute writes."""
    registry = _write_registry(
        tmp_path,
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.OldType",
            "contexts": ["annotation"],
        },
        subject_name="targetpkg.OldType",
    )
    (tmp_path / "project").mkdir()
    (tmp_path / "project/source.py").write_text(
        "import targetpkg\nvalue: targetpkg.OldType\ntargetpkg.OldType = object\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=tmp_path / "project",
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    assert len(report.findings) == 1
    assert dict(report.findings[0].match_evidence)["reference_context"] == (
        "annotation"
    )


@pytest.mark.parametrize(
    ("context", "source"),
    [
        (
            "decorator",
            (
                "import targetpkg\n@targetpkg.old_attr\n"
                "def decorated() -> None:\n    pass\n"
            ),
        ),
        (
            "base-class",
            "import targetpkg\nclass Child(targetpkg.old_attr):\n    pass\n",
        ),
    ],
)
def test_qualified_reference_special_contexts(
    tmp_path: Path,
    context: str,
    source: str,
) -> None:
    """Decorator and base-class contexts are classified from parent metadata."""
    registry = _write_registry(
        tmp_path,
        {
            "kind": "qualified-reference",
            "qualified_name": "targetpkg.old_attr",
            "contexts": [context],
        },
        subject_name="targetpkg.old_attr",
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.py").write_text(source, encoding="utf-8")

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    assert len(report.findings) == 1
    assert dict(report.findings[0].match_evidence)["reference_context"] == context


def test_qualified_project_module_ambiguity_is_visible(tmp_path: Path) -> None:
    """A local leading module prevents an exact qualified-name classification."""
    registry = _write_registry(
        tmp_path,
        MATCHERS["qualified_reference"],
        subject_name="targetpkg.old_attr",
    )
    project = tmp_path / "project"
    project.mkdir()
    (project / "targetpkg.py").write_text("old_attr = object()\n", encoding="utf-8")
    (project / "source.py").write_text(
        "import targetpkg\nvalue = targetpkg.old_attr\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
            registry_source=registry,
        )
    )

    assert report.findings == ()
    assert len(report.inferences) == 1
    assert dict(report.inferences[0].evidence)["qualified_name"] == (
        "targetpkg.old_attr"
    )


@pytest.mark.parametrize(
    ("matcher_name", "source", "subject_kind", "subject_name"),
    [
        ("module_import", "import targetpkg\n", "module", "targetpkg"),
        (
            "qualified_reference",
            "import targetpkg\nvalue = targetpkg.old_attr\n",
            "function",
            "targetpkg.old_attr",
        ),
        (
            "qualified_call",
            "import targetpkg\ntargetpkg.old_call()\n",
            "function",
            "targetpkg.old_call",
        ),
        (
            "call_shape",
            'import targetpkg\ntargetpkg.old_call("payload", mode="legacy")\n',
            "function",
            "targetpkg.old_call",
        ),
    ],
)
def test_internal_file_symlink_is_a_project_module_candidate(
    tmp_path: Path,
    matcher_name: str,
    source: str,
    subject_kind: str,
    subject_name: str,
) -> None:
    """Logical symlink aliases prevent exact external-origin classification."""
    registry = _write_registry(
        tmp_path,
        MATCHERS[matcher_name],
        subject_kind=subject_kind,
        subject_name=subject_name,
    )
    project = tmp_path / "project"
    implementation = project / "internal/implementation.py"
    implementation.parent.mkdir(parents=True)
    implementation.write_text(
        "old_attr = object()\ndef old_call(*args: object, **kwargs: object) -> None:\n"
        "    pass\n",
        encoding="utf-8",
    )
    try:
        (project / "targetpkg.py").symlink_to(implementation)
    except OSError:
        pytest.skip("the platform does not permit file symlinks")
    (project / "source.py").write_text(source, encoding="utf-8")

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
            registry_source=registry,
        )
    )

    assert report.findings == ()
    assert len(report.inferences) == 1
    assert dict(report.inferences[0].evidence)["candidate_paths"] == ("targetpkg.py",)


@pytest.mark.parametrize(
    "matcher_case",
    [
        ("module_import", "import targetpkg\n", "module", "targetpkg"),
        (
            "qualified_reference",
            "import targetpkg\nvalue = targetpkg.old_attr\n",
            "function",
            "targetpkg.old_attr",
        ),
        (
            "qualified_call",
            "import targetpkg\ntargetpkg.old_call()\n",
            "function",
            "targetpkg.old_call",
        ),
        (
            "call_shape",
            'import targetpkg\ntargetpkg.old_call("payload", mode="legacy")\n',
            "function",
            "targetpkg.old_call",
        ),
    ],
)
@pytest.mark.parametrize("alias_kind", ["file", "directory"])
@pytest.mark.parametrize("target_location", ["internal", "outside"])
def test_untraversed_symlink_aliases_prevent_exact_origin_classification(
    tmp_path: Path,
    matcher_case: tuple[str, str, str, str],
    alias_kind: str,
    target_location: str,
) -> None:
    """Every exact-origin matcher accounts for logical file and directory aliases."""
    matcher_name, source, subject_kind, subject_name = matcher_case
    registry = _write_registry(
        tmp_path,
        MATCHERS[matcher_name],
        subject_kind=subject_kind,
        subject_name=subject_name,
    )
    project = tmp_path / "project"
    project.mkdir()
    target_root = (
        tmp_path / "outside_impl"
        if target_location == "outside"
        else project / "internal_impl"
    )
    target_root.mkdir()
    implementation = (
        target_root / "implementation.py"
        if alias_kind == "file"
        else target_root / "package"
    )
    if alias_kind == "file":
        implementation.write_text(
            "old_attr = object()\n"
            "def old_call(*args: object, **kwargs: object) -> None:\n"
            "    pass\n",
            encoding="utf-8",
        )
        alias = project / "targetpkg.py"
    else:
        implementation.mkdir()
        (implementation / "__init__.py").write_text(
            "old_attr = object()\n"
            "def old_call(*args: object, **kwargs: object) -> None:\n"
            "    pass\n",
            encoding="utf-8",
        )
        alias = project / "targetpkg"
    try:
        alias.symlink_to(implementation, target_is_directory=alias_kind == "directory")
    except OSError:
        pytest.skip("the platform does not permit symlinks")
    (project / "source.py").write_text(source, encoding="utf-8")

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
            registry_source=registry,
        )
    )

    expected_alias = "targetpkg.py" if alias_kind == "file" else "targetpkg"
    assert report.findings == ()
    assert report.diagnostics == ()
    assert len(report.inferences) == 1
    assert dict(report.inferences[0].evidence)["candidate_paths"] == (expected_alias,)


def test_shape_negative_local_call_does_not_emit_resolution_inference(
    tmp_path: Path,
) -> None:
    """Origin ambiguity is irrelevant when authored call predicates do not match."""
    registry = _write_registry(tmp_path, MATCHERS["call_shape"])
    project = tmp_path / "project"
    project.mkdir()
    (project / "targetpkg.py").write_text(
        "def old_call() -> None:\n    pass\n",
        encoding="utf-8",
    )
    (project / "source.py").write_text(
        "import targetpkg\ntargetpkg.old_call()\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            paths=(Path("source.py"),),
            registry_source=registry,
        )
    )

    assert report.findings == ()
    assert report.inferences == ()


def test_malformed_call_shape_literal_marks_scan_incomplete(tmp_path: Path) -> None:
    """Literal evaluation failures stay inside the per-file parse boundary."""
    registry = _write_registry(tmp_path, MATCHERS["call_shape"])
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.py").write_text(
        'import targetpkg\ntargetpkg.old_call("\\xzz", mode="legacy")\n',
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    assert report.findings == ()
    assert report.counts.files_analyzed == 0
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["PYA1003"]
    assert report.exit_code is ExitCode.INCOMPLETE


def test_dynamic_import_supports_builtin_and_keyword_name(tmp_path: Path) -> None:
    """Only the two whitelisted dynamic import functions inspect literal names."""
    registry = _write_registry(
        tmp_path,
        MATCHERS["literal_dynamic_import"],
        subject_kind="module",
        subject_name="targetpkg",
    )
    (tmp_path / "project").mkdir()
    (tmp_path / "project/source.py").write_text(
        '__import__(name="targetpkg")\n',
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=tmp_path / "project",
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )
    root_discovery = discover_python_files(tmp_path / "project", ())
    matches, _inferences, diagnostic = _parse_file(
        root_discovery.files[0],
        build_matcher_index(load_registry(registry)),
        project_module_paths(root_discovery.files, root_discovery.issues),
        Policy.parse("3.11", "3.13").target_versions,
    )

    assert diagnostic is None
    assert len(matches) == 1
    assert matches[0].confidence is MatchConfidence.MEDIUM
    evidence = dict(matches[0].evidence)
    assert evidence["dynamic_function"] == "builtins.__import__"
    assert evidence["imported_module"] == "targetpkg"
    assert report.findings == ()
    assert report.exit_code is ExitCode.SUCCESS


@pytest.mark.parametrize(
    ("case", "expected_matches"),
    [
        ("explicit_level_zero", 2),
        ("relative_level", 0),
        ("unknown_level", 0),
    ],
)
def test_builtin_dynamic_import_level_fixtures(
    tmp_path: Path,
    case: str,
    expected_matches: int,
) -> None:
    """Only an absent or explicit zero built-in import level is absolute."""
    matches, inferences = _raw_case(
        tmp_path,
        "literal_dynamic_import",
        case,
    )
    report = _scan_case(tmp_path / "scan", "literal_dynamic_import", case)

    assert len(matches) == expected_matches
    assert all(match.confidence is MatchConfidence.MEDIUM for match in matches)
    assert inferences == ()
    assert report.findings == ()
    assert report.gate_failed is False


@pytest.mark.parametrize(
    ("case", "expected_matches", "expected_resolution"),
    [
        ("builtin_positive", 1, "exact-import"),
        ("builtin_alias", 1, "exact-import"),
        ("builtin_ambiguous", 1, "ambiguous-import"),
        ("builtin_shadowing", 0, None),
        ("builtin_negative", 0, None),
    ],
)
def test_imported_builtin_dynamic_import_fixtures(
    tmp_path: Path,
    case: str,
    expected_matches: int,
    expected_resolution: str | None,
) -> None:
    """Imported built-in aliases retain exact, ambiguous, and negative semantics."""
    matches, inferences = _raw_case(tmp_path, "literal_dynamic_import", case)
    report = _scan_case(tmp_path / "scan", "literal_dynamic_import", case)

    assert len(matches) == expected_matches
    assert inferences == ()
    assert report.findings == ()
    if expected_resolution is not None:
        assert dict(matches[0].evidence)["resolution"] == expected_resolution
        assert matches[0].confidence is MatchConfidence.MEDIUM


def test_dynamic_import_local_target_is_inference_only(tmp_path: Path) -> None:
    """A project module competing for the literal target prevents classification."""
    matches, inferences = _raw_case(
        tmp_path,
        "literal_dynamic_import",
        "local_target",
    )
    report = _scan_case(
        tmp_path / "scan",
        "literal_dynamic_import",
        "local_target",
    )

    assert matches == ()
    assert len(inferences) == 1
    assert dict(inferences[0].evidence)["candidate_paths"] == ("targetpkg.py",)
    assert dict(inferences[0].evidence)["imported_module"] == "targetpkg"
    assert report.findings == ()
    assert len(report.inferences) == 1


def test_call_matchers_deduplicate_to_the_most_specific_shape(tmp_path: Path) -> None:
    """Overlapping reference, call, and shape evidence produces one finding."""
    registry = _write_registry(
        tmp_path,
        [
            MATCHERS["qualified_reference"],
            MATCHERS["qualified_call"],
            MATCHERS["call_shape"],
        ],
    )
    root = FIXTURE_ROOT / "call_shape/positive"

    report = scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    assert len(report.findings) == 1
    assert report.findings[0].match_kind == "call-shape"


def test_type_exact_literal_matchers_select_only_their_scalar_kind(
    tmp_path: Path,
) -> None:
    """Boolean, integer, and float matcher identities also differ at scan time."""
    matchers = [
        {
            "kind": "call-shape",
            "qualified_name": "targetpkg.old_call",
            "literal_arguments": [{"position": 0, "equals": value}],
        }
        for value in (True, 1, 1.0)
    ]
    registry = _write_registry(tmp_path, matchers)
    project = tmp_path / "project"
    project.mkdir()
    (project / "source.py").write_text(
        "import targetpkg\n"
        "targetpkg.old_call(True)\n"
        "targetpkg.old_call(1)\n"
        "targetpkg.old_call(1.0)\n",
        encoding="utf-8",
    )

    report = scan(
        ScanRequest(
            root=project,
            baseline_python="3.11",
            horizon_python="3.13",
            registry_source=registry,
        )
    )

    expected_lines = [2, 3, 4]
    assert len(report.findings) == len(expected_lines)
    assert [
        finding.location.region.start.line for finding in report.findings
    ] == expected_lines
