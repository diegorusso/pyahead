"""Strict artifact, merge, and report tests for M7 observed evidence."""

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

import pyahead.evidence as evidence_module
from pyahead.analysis import ScanRequest, scan
from pyahead.evidence import (
    MAX_EVIDENCE_ARTIFACTS,
    MAX_EVIDENCE_BYTES,
    evidence_json_schema,
    merge_evidence,
    parse_evidence_document,
    render_evidence_document,
    resolve_source_commit,
)
from pyahead.model import (
    ConfigurationError,
    EvidenceFreshness,
    EvidenceRelationshipKind,
    ScanReport,
)
from pyahead.reporting import render_json, render_text

ROOT = Path(__file__).parents[2]
CURRENT_COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40
EXPECTED_OBSERVATIONS = 2
EXPECTED_LINKED_OCCURRENCES = 5
EXPECTED_TOTAL_OCCURRENCES = 6
LARGE_EVIDENCE_SET = 512
LARGE_EVIDENCE_ARTIFACTS = 4
EXPECTED_MAX_EVIDENCE_ARTIFACTS = 64


def _warning(
    *,
    path: str = "legacy.py",
    line: int = 1,
    message: str = "'cgi' is deprecated",
    occurrences: int = 1,
) -> dict[str, object]:
    return {
        "category": "builtins.DeprecationWarning",
        "kind": "deprecation-warning",
        "location": {"line": line, "path": path},
        "message": message,
        "occurrences": occurrences,
        "phase": "runtest",
        "test_node": "tests/test_legacy.py::test_legacy",
    }


def _document(
    *,
    commit: str = CURRENT_COMMIT,
    implementation: str = "cpython",
    python_version: str = "3.11.9",
    warnings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "environment": {
            "implementation": implementation,
            "platform": "linux",
            "python_version": python_version,
        },
        "provider": {"name": "pytest-warnings", "version": "0.1.0a2"},
        "run": {
            "exit_code": 0,
            "framework": "pytest",
            "framework_version": "9.1.1",
            "tests_collected": 3,
            "warnings_complete": True,
            "warnings_dropped": 0,
        },
        "schema_version": 1,
        "source": {"commit": commit},
        "warnings": warnings if warnings is not None else [_warning()],
    }


def _write_artifact(path: Path, document: dict[str, object]) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _static_report(root: Path) -> ScanReport:
    (root / "legacy.py").write_text("import cgi\n", encoding="utf-8")
    return scan(
        ScanRequest(
            root=root,
            baseline_python="3.11",
            horizon_python="3.13",
        )
    )


def test_checked_in_evidence_schema_is_current_closed_and_runtime_compatible() -> None:
    """The published schema and strict runtime parser accept the same artifact."""
    checked_in = json.loads(
        (ROOT / "docs/schema/evidence-v1.json").read_text(encoding="utf-8")
    )
    generated = evidence_json_schema()
    validator = Draft202012Validator(generated)

    validator.check_schema(generated)
    assert checked_in == generated
    validator.validate(_document())
    parsed = parse_evidence_document(_document())

    assert parsed.provider == "pytest-warnings"
    assert parsed.source_commit == CURRENT_COMMIT
    assert parsed.warnings[0].location is not None
    assert parsed.warnings[0].location.path.as_posix() == "legacy.py"


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("location", "must be an object"),
        ("test_node", "must be a non-empty string"),
    ],
)
def test_optional_warning_fields_reject_null_but_accept_omission(
    field: str,
    message: str,
) -> None:
    """Schema and runtime agree that optional fields are non-null when present."""
    document = _document()
    warning = cast("dict[str, object]", cast("list[object]", document["warnings"])[0])
    warning[field] = None
    validator = Draft202012Validator(evidence_json_schema())

    with pytest.raises(ValidationError):
        validator.validate(document)
    with pytest.raises(ConfigurationError, match=message):
        parse_evidence_document(document)

    del warning[field]
    validator.validate(document)
    parsed = parse_evidence_document(document)
    assert getattr(parsed.warnings[0], field) is None


def test_schema_and_runtime_reject_complete_evidence_with_dropped_warnings() -> None:
    """Both contracts reject completeness when retained records were dropped."""
    document = _document()
    run = cast("dict[str, object]", document["run"])
    run["warnings_complete"] = True
    run["warnings_dropped"] = 1

    with pytest.raises(ValidationError):
        Draft202012Validator(evidence_json_schema()).validate(document)
    with pytest.raises(ConfigurationError, match="warnings_complete may be true"):
        parse_evidence_document(document)


def test_schema_and_runtime_allow_unproven_capture_without_dropped_records() -> None:
    """False completeness can describe capture that was never proven complete."""
    document = _document()
    run = cast("dict[str, object]", document["run"])
    run["warnings_complete"] = False
    run["warnings_dropped"] = 0

    Draft202012Validator(evidence_json_schema()).validate(document)
    parsed = parse_evidence_document(document)

    assert parsed.warnings_complete is False
    assert parsed.warnings_dropped == 0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(extra=True), "unknown or missing keys"),
        (
            lambda value: cast("dict[str, object]", value["source"]).update(
                commit="abc"
            ),
            "full 40- or 64-character",
        ),
        (
            lambda value: cast(
                "dict[str, object]",
                cast("list[object]", value["warnings"])[0],
            )["location"].update(path="../outside.py"),  # type: ignore[union-attr]
            "repository-relative POSIX",
        ),
        (
            lambda value: cast(
                "dict[str, object]",
                cast("list[object]", value["warnings"])[0],
            ).update(message="\ud800"),
            "valid Unicode",
        ),
    ],
)
def test_evidence_schema_and_runtime_reject_invalid_artifacts(
    mutation: Callable[[dict[str, object]], None],
    message: str,
) -> None:
    """Representative identity, path, and closed-world errors fail ingestion."""
    document = deepcopy(_document())
    mutation(document)

    with pytest.raises(ValidationError):
        Draft202012Validator(evidence_json_schema()).validate(document)
    with pytest.raises(ConfigurationError, match=message):
        parse_evidence_document(document)


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
@pytest.mark.parametrize(
    "path",
    [
        ("environment", "implementation"),
        ("environment", "platform"),
        ("environment", "python_version"),
        ("provider", "version"),
        ("run", "framework_version"),
        ("source", "commit"),
        ("warnings", 0, "category"),
        ("warnings", 0, "message"),
        ("warnings", 0, "test_node"),
        ("warnings", 0, "location", "path"),
    ],
)
def test_schema_and_runtime_reject_final_line_terminators(
    path: tuple[str | int, ...],
    ending: str,
) -> None:
    """JSON Schema and ingestion reject final LF/CRLF in every string family."""
    document = deepcopy(_document())
    selected: object = document
    for part in path[:-1]:
        selected = selected[part]  # type: ignore[index]
    final = path[-1]
    selected[final] += ending  # type: ignore[index,operator]

    with pytest.raises(ValidationError):
        Draft202012Validator(evidence_json_schema()).validate(document)
    with pytest.raises(ConfigurationError, match="line-break"):
        parse_evidence_document(document)


def test_current_duplicate_static_and_observed_evidence_links_without_recounting(
    tmp_path: Path,
) -> None:
    """A unique same-line warning corroborates one finding and stays one record."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    matching = _warning(occurrences=2)
    duplicate = _warning(occurrences=3)
    unmatched = _warning(line=99, message="unmatched deprecation")
    _write_artifact(
        artifact,
        _document(warnings=[matching, duplicate, unmatched]),
    )

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    document = cast("dict[str, object]", json.loads(render_json(merged)))
    findings = cast("list[dict[str, object]]", document["findings"])
    evidence = cast("dict[str, object]", document["evidence"])
    observations = cast("list[dict[str, object]]", evidence["observations"])
    summary = cast("dict[str, int]", document["summary"])

    assert len(merged.findings) == len(report.findings) == 1
    assert len(merged.observed_warnings) == EXPECTED_OBSERVATIONS
    assert merged.observed_warnings[0].occurrences == EXPECTED_LINKED_OCCURRENCES
    assert len(merged.observed_warnings[0].linked_fingerprints) == 1
    assert merged.observed_warnings[0].relationships[0].kind is (
        EvidenceRelationshipKind.CORROBORATES
    )
    assert len(merged.unmatched_observations) == 1
    assert summary["breaking"] == 1
    assert summary["observed"] == EXPECTED_OBSERVATIONS
    assert summary["observed_unmatched"] == 1
    finding_evidence = cast("dict[str, object]", findings[0]["evidence"])
    assert cast("dict[str, object]", finding_evidence["inferred"])["kind"] == (
        "static-match"
    )
    assert len(cast("list[str]", finding_evidence["observed"])) == 1
    assert (
        sum(cast("int", item["occurrences"]) for item in observations)
        == EXPECTED_TOTAL_OCCURRENCES
    )

    text = render_text(merged)
    assert "Inferred evidence:" in text
    assert "Observed evidence:" in text
    assert "Unmatched observed warnings:" in text
    assert "1 finding (1 breaking)" in text
    assert "2 observed warnings (1 linked, 1 unmatched, 0 stale)" in text


def test_artifact_console_fields_escape_terminal_controls(tmp_path: Path) -> None:
    """Artifact paths and text cannot inject controls into terminal output."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings-\u2028line.json"
    warning = _warning(
        path="observed/\x1b[2J.py",
        message="clear\x1b[2J split\u2028line",
    )
    warning["category"] = "builtins.\x1b[31mDeprecationWarning"
    document = _document(warnings=[warning])
    cast("dict[str, object]", document["provider"])["version"] = "v1\x1b[2J"
    _write_artifact(artifact, document)

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    text = render_text(merged)

    assert "\x1b" not in text
    assert "\u2028" not in text
    assert "\\u001b" in text
    assert "\\u2028" in text


def test_unrelated_same_line_warning_is_explicitly_location_only(
    tmp_path: Path,
) -> None:
    """Co-location without subject correlation never becomes corroboration."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    _write_artifact(
        artifact,
        _document(warnings=[_warning(message="another API is deprecated")]),
    )

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    observation = merged.observed_warnings[0]

    assert observation.linked_fingerprints == ()
    assert observation.relationships[0].kind is EvidenceRelationshipKind.LOCATION_ONLY
    assert observation.relationships[0].reasons == ("subject-not-correlated",)
    assert merged.unmatched_observations == (observation,)
    assert "CPY0001=location-only (subject-not-correlated)" in render_text(merged)


@pytest.mark.parametrize(
    ("implementation", "python_version", "reason"),
    [
        ("pypy", "3.11.9", "non-cpython-environment"),
        ("cpython", "3.10.14", "observed-python-outside-policy"),
    ],
)
def test_environment_conflicts_remain_visible_and_unlinked(
    tmp_path: Path,
    implementation: str,
    python_version: str,
    reason: str,
) -> None:
    """Non-CPython and out-of-policy observations cannot corroborate CPython."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    _write_artifact(
        artifact,
        _document(
            implementation=implementation,
            python_version=python_version,
        ),
    )

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    relationship = merged.observed_warnings[0].relationships[0]

    assert relationship.kind is EvidenceRelationshipKind.CONFLICTS
    assert relationship.reasons == (reason,)
    assert merged.observed_warnings[0].linked_fingerprints == ()
    assert f"CPY0001=conflicts ({reason})" in render_text(merged)


def test_warning_conflicting_with_removal_state_is_visible_and_unlinked(
    tmp_path: Path,
) -> None:
    """A warning on a version where the subject is removed contradicts inference."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    _write_artifact(artifact, _document(python_version="3.13.7"))

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    relationship = merged.observed_warnings[0].relationships[0]

    assert relationship.kind is EvidenceRelationshipKind.CONFLICTS
    assert relationship.reasons == (
        "deprecation-warning-conflicts-with-breaking-state",
    )
    assert merged.observed_warnings[0].linked_fingerprints == ()
    assert "deprecation-warning-conflicts-with-breaking-state" in render_text(merged)


def test_different_commit_evidence_is_visible_stale_and_never_linked(
    tmp_path: Path,
) -> None:
    """Same-location evidence from another commit cannot corroborate current code."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    _write_artifact(artifact, _document(commit=OTHER_COMMIT))

    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    document = cast("dict[str, object]", json.loads(render_json(merged)))
    evidence = cast("dict[str, object]", document["evidence"])
    observations = cast("list[dict[str, object]]", evidence["observations"])

    assert merged.evidence_artifacts[0].freshness is EvidenceFreshness.STALE
    assert merged.observed_warnings[0].freshness is EvidenceFreshness.STALE
    assert merged.observed_warnings[0].linked_fingerprints == ()
    assert observations[0]["freshness"] == "stale"
    assert observations[0]["source_commit"] == OTHER_COMMIT
    assert "stale for bbbbbbbbbbbb (scan aaaaaaaaaaaa)" in render_text(merged)


def test_evidence_paths_and_duplicate_artifacts_fail_closed(tmp_path: Path) -> None:
    """Ingestion is root bounded and coalesces identical artifact content."""
    report = _static_report(tmp_path)
    artifact = tmp_path / "warnings.json"
    clone = tmp_path / "warnings-copy.json"
    _write_artifact(artifact, _document())
    _write_artifact(clone, _document())
    outside = tmp_path.parent / "outside-evidence.json"
    _write_artifact(outside, _document())

    with pytest.raises(ConfigurationError, match="beneath the project root"):
        merge_evidence(
            report,
            (outside,),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )
    merged = merge_evidence(
        report,
        (artifact, clone),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    assert len(merged.evidence_artifacts) == 1
    assert len(merged.observed_warnings) == 1


def test_evidence_symlink_is_rejected(tmp_path: Path) -> None:
    """A stable in-root evidence alias is never followed."""
    report = _static_report(tmp_path)
    target = tmp_path / "target.json"
    _write_artifact(target, _document())
    selected = tmp_path / "warnings.json"
    try:
        selected.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ConfigurationError, match="not a regular file"):
        merge_evidence(
            report,
            (selected,),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )


def _raw_evidence(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()


def _document_with_serialized_size(target: int) -> dict[str, object]:
    message = "x" * 16_384
    warning_pool = [
        {
            **_warning(line=index + 1, message=message),
            "test_node": f"t{index}",
        }
        for index in range(1_100)
    ]
    low = 0
    high = len(warning_pool)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = _document(warnings=warning_pool[:middle])
        if len(_raw_evidence(candidate)) <= target:
            low = middle
        else:
            high = middle - 1
    document = _document(warnings=deepcopy(warning_pool[:low]))
    remaining = target - len(_raw_evidence(document))
    warnings = cast("list[dict[str, object]]", document["warnings"])
    for warning in warnings:
        if remaining == 0:
            break
        node = cast("str", warning["test_node"])
        added = min(remaining, 4_096 - len(node))
        warning["test_node"] = node + ("n" * added)
        remaining -= added
    assert remaining == 0
    assert len(_raw_evidence(document)) == target
    return document


def test_producer_and_ingester_share_exact_artifact_byte_boundary(
    tmp_path: Path,
) -> None:
    """The serializer caps output and the descriptor reader enforces the same cap."""
    report = _static_report(tmp_path)
    at_limit = _document_with_serialized_size(MAX_EVIDENCE_BYTES)
    rendered_at_limit = render_evidence_document(at_limit)
    artifact = tmp_path / "warnings.json"
    artifact.write_bytes(rendered_at_limit.encode())

    assert len(rendered_at_limit.encode()) == MAX_EVIDENCE_BYTES
    merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )
    assert merged.evidence_artifacts[0].warnings_complete is True
    assert merged.evidence_artifacts[0].warnings_dropped == 0

    above_limit = deepcopy(at_limit)
    warnings = cast("list[dict[str, object]]", above_limit["warnings"])
    node = cast("str", warnings[-1]["test_node"])
    warnings[-1]["test_node"] = node + "x"
    raw_above_limit = _raw_evidence(above_limit)
    assert len(raw_above_limit) == MAX_EVIDENCE_BYTES + 1
    artifact.write_bytes(raw_above_limit)
    with pytest.raises(ConfigurationError, match="evidence exceeds"):
        merge_evidence(
            report,
            (artifact,),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )

    capped = render_evidence_document(above_limit)
    capped_document = cast("dict[str, object]", json.loads(capped))
    capped_run = cast("dict[str, object]", capped_document["run"])
    artifact.write_bytes(capped.encode())
    capped_merged = merge_evidence(
        report,
        (artifact,),
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )

    assert len(capped.encode()) <= MAX_EVIDENCE_BYTES
    assert capped_run["warnings_complete"] is False
    assert cast("int", capped_run["warnings_dropped"]) > 0
    assert capped_merged.evidence_artifacts[0].warnings_complete is False
    assert capped_merged.evidence_artifacts[0].warnings_dropped > 0


def test_oversized_serialization_never_materializes_the_complete_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The size probe streams an oversized candidate before rendering a prefix."""
    warnings = [_warning(line=index + 1, message="x" * 16_384) for index in range(20)]
    document = _document(warnings=warnings)
    parsed_warning_count = len(warnings)
    original_render = evidence_module._render_parsed_document  # noqa: SLF001

    def guarded_render(document: evidence_module.EvidenceDocument) -> str:
        assert len(document.warnings) < parsed_warning_count
        return original_render(document)

    monkeypatch.setattr(evidence_module, "MAX_EVIDENCE_BYTES", 64 * 1024)
    monkeypatch.setattr(evidence_module, "_render_parsed_document", guarded_render)

    rendered = render_evidence_document(document)
    parsed = parse_evidence_document(cast("dict[str, object]", json.loads(rendered)))

    assert len(rendered.encode()) <= 64 * 1024
    assert parsed.warnings_complete is False
    assert parsed.warnings_dropped > 0


def test_large_disjoint_multi_artifact_merge_uses_near_linear_indexes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Location and rendering lookups scale with records plus actual matches."""
    report = _static_report(tmp_path)
    prototype = report.findings[0]
    findings = tuple(
        replace(
            prototype,
            fingerprint=f"{index:064x}",
            location=replace(
                prototype.location,
                path=PurePosixPath(f"pkg/module_{index:04d}.py"),
            ),
        )
        for index in range(LARGE_EVIDENCE_SET)
    )
    report = replace(report, findings=findings)
    artifact_paths: list[Path] = []
    batch_size = LARGE_EVIDENCE_SET // LARGE_EVIDENCE_ARTIFACTS
    for artifact_index in range(LARGE_EVIDENCE_ARTIFACTS):
        start = artifact_index * batch_size
        artifact = tmp_path / f"warnings-{artifact_index}.json"
        artifact_paths.append(artifact)
        _write_artifact(
            artifact,
            _document(
                warnings=[
                    _warning(
                        path=f"pkg/module_{index:04d}.py",
                        message="'cgi' is deprecated",
                    )
                    for index in range(start, start + batch_size)
                ]
            ),
        )

    subject_checks = 0
    original = cast(
        "Callable[[object, object], bool]",
        evidence_module.__dict__["_subject_correlates"],
    )

    def counted_subject_check(warning: object, finding: object) -> bool:
        nonlocal subject_checks
        subject_checks += 1
        return original(warning, finding)

    monkeypatch.setattr(
        evidence_module,
        "_subject_correlates",
        counted_subject_check,
    )
    merged = merge_evidence(
        report,
        artifact_paths,
        root=tmp_path,
        source_commit=CURRENT_COMMIT,
    )

    observation_index = merged.observations_by_fingerprint
    assert merged.observations_by_fingerprint is observation_index
    assert subject_checks == LARGE_EVIDENCE_SET
    assert len(merged.evidence_artifacts) == LARGE_EVIDENCE_ARTIFACTS
    assert len(merged.observed_warnings) == LARGE_EVIDENCE_SET
    assert len(observation_index) == LARGE_EVIDENCE_SET
    assert sum(map(len, observation_index.values())) == LARGE_EVIDENCE_SET
    assert all(len(merged.observations_for(finding)) == 1 for finding in findings)
    assert render_json(merged) == render_json(merged)
    assert render_text(merged) == render_text(merged)


def test_repeated_evidence_inputs_have_aggregate_resource_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeatable input cannot bypass artifact, byte, or warning-record bounds."""
    report = _static_report(tmp_path)
    with pytest.raises(ConfigurationError, match="at most 64 artifacts"):
        merge_evidence(
            report,
            tuple(Path(f"missing-{index}.json") for index in range(65)),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )
    assert MAX_EVIDENCE_ARTIFACTS == EXPECTED_MAX_EVIDENCE_ARTIFACTS

    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write_artifact(first, _document(warnings=[_warning(message="first cgi")]))
    _write_artifact(second, _document(warnings=[_warning(message="second cgi")]))
    total_bytes = first.stat().st_size + second.stat().st_size
    monkeypatch.setattr(
        evidence_module,
        "MAX_TOTAL_EVIDENCE_BYTES",
        total_bytes - 1,
    )
    with pytest.raises(ConfigurationError, match="aggregate byte limit"):
        merge_evidence(
            report,
            (first, second),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )

    monkeypatch.setattr(evidence_module, "MAX_TOTAL_EVIDENCE_BYTES", total_bytes)
    monkeypatch.setattr(evidence_module, "MAX_TOTAL_EVIDENCE_WARNINGS", 1)
    with pytest.raises(ConfigurationError, match="warning-record limit"):
        merge_evidence(
            report,
            (first, second),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )


@pytest.mark.parametrize(
    ("limit_name", "message"),
    [
        ("MAX_EVIDENCE_CANDIDATE_CHECKS", "candidate checks"),
        ("MAX_EVIDENCE_RELATIONSHIPS", "relationship output"),
    ],
)
def test_overlapping_findings_have_explicit_relationship_expansion_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    message: str,
) -> None:
    """Pathological overlap fails before comparison or output growth is unbounded."""
    report = _static_report(tmp_path)
    first = report.findings[0]
    report = replace(
        report,
        findings=(first, replace(first, fingerprint="f" * 64)),
    )
    artifact = tmp_path / "warnings.json"
    _write_artifact(
        artifact,
        _document(warnings=[_warning(message="unrelated deprecation")]),
    )
    monkeypatch.setattr(evidence_module, limit_name, 1)

    with pytest.raises(ConfigurationError, match=message):
        merge_evidence(
            report,
            (artifact,),
            root=tmp_path,
            source_commit=CURRENT_COMMIT,
        )


def test_source_commit_resolution_is_explicit_and_ci_aware() -> None:
    """Commit selection has stable precedence and never needs a Git process."""
    assert resolve_source_commit(CURRENT_COMMIT.upper(), {}) == CURRENT_COMMIT
    assert (
        resolve_source_commit(
            None,
            {"GITHUB_SHA": OTHER_COMMIT, "CI_COMMIT_SHA": CURRENT_COMMIT},
        )
        == OTHER_COMMIT
    )
    with pytest.raises(ConfigurationError, match="provide --source-commit"):
        resolve_source_commit(None, {})
