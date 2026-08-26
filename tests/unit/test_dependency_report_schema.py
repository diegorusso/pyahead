"""Strict public schema tests for M8 dependency reports."""

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import cast

import pytest
from jsonschema import Draft202012Validator, ValidationError

from pyahead.dependencies import (
    ArtifactAvailability,
    DependencyAssessment,
    DependencyCompatibilityStatus,
    DependencyProjectKind,
    DependencyReport,
    EnvironmentTarget,
    EvaluatedRequirement,
    MetadataArtifact,
    MetadataIssue,
    MetadataKind,
    RequiresPythonStatus,
    ResolutionStatus,
    ResolvedPackage,
    ResolverResult,
    TargetDependencyResult,
    TransitiveRequirementEvidence,
    dependency_report_document,
)

ROOT = Path(__file__).parents[2]
SCHEMA_PATH = ROOT / "docs/schema/dependency-report-v1.json"
ARTIFACT_ID = "a" * 64
RESOLVED_PACKAGE_DOCUMENT: dict[str, object] = {
    "metadata_used": [ARTIFACT_ID],
    "name": "demo",
    "version": "1.0",
}
RESOLUTION_SHAPES: dict[str, tuple[bool, bool, str | None, bool]] = {
    "not-requested": (False, True, None, False),
    "succeeded": (True, True, "0.12.6", True),
    "artifact-unavailable": (True, True, "0.12.6", False),
    "resolution-failed": (True, True, "0.12.6", False),
    "timed-out": (True, False, None, False),
    "unverified": (True, False, "0.12.6", True),
}


def _target() -> EnvironmentTarget:
    return EnvironmentTarget(
        name="cp312-linux",
        python_full_version="3.12.4",
        implementation_name="cpython",
        implementation_version="3.12.4",
        os_name="posix",
        sys_platform="linux",
        platform_machine="x86_64",
        platform_python_implementation="CPython",
        platform_system="Linux",
        platform_release="",
        platform_version="",
        compatible_tags=("py3-none-any",),
        resolver_platform="x86_64-manylinux_2_17",
    )


def _metadata(*, incomplete: bool) -> MetadataArtifact:
    return MetadataArtifact(
        artifact_id=ARTIFACT_ID,
        path=PurePosixPath("wheelhouse/demo-1.0-py3-none-any.whl"),
        kind=MetadataKind.WHEEL,
        name="demo",
        canonical_name="demo",
        version="1.0",
        metadata_version="2.4",
        requires_python=">=3.12",
        requires_dist=(("other==2.0",) if incomplete else ()),
        provides_extra=("speed",),
        dynamic=(),
        wheel_tags=("py3-none-any",),
        metadata_path="demo-1.0.dist-info/METADATA",
        sha256=ARTIFACT_ID,
    )


def _report(*, incomplete: bool) -> DependencyReport:
    resolution = ResolverResult(
        status=(
            ResolutionStatus.UNVERIFIED if incomplete else ResolutionStatus.SUCCEEDED
        ),
        complete=not incomplete,
        resolver="uv",
        resolver_version="0.12.6",
        packages=(
            ResolvedPackage(
                name="demo",
                version="1.0",
                metadata_used=(ARTIFACT_ID,),
            ),
        ),
        reason=(
            "exact artifact provenance was not established"
            if incomplete
            else "resolution completed"
        ),
    )
    declared = EvaluatedRequirement(
        requirement="demo[speed]==1.0",
        applies=True,
        matching_extras=("base",),
        matching_metadata=(() if incomplete else (ARTIFACT_ID,)),
        resolved_versions=(() if incomplete else ("demo==1.0",)),
        verified=not incomplete,
        reason=("evidence is incomplete" if incomplete else "requirement verified"),
    )
    transitive = TransitiveRequirementEvidence(
        requirement="other==2.0",
        required_by=("demo==1.0",),
        locked_versions=("other==2.0",),
        matching_metadata=(),
        resolved_versions=(() if incomplete else ("other==2.0",)),
        verified=not incomplete,
        reason=("evidence is incomplete" if incomplete else "requirement verified"),
    )
    assessment = DependencyAssessment(
        package="demo",
        version="1.0",
        status=(
            DependencyCompatibilityStatus.UNVERIFIED
            if incomplete
            else DependencyCompatibilityStatus.COMPATIBLE
        ),
        requires_python_status=(
            RequiresPythonStatus.UNVERIFIED
            if incomplete
            else RequiresPythonStatus.COMPATIBLE
        ),
        artifact_availability=ArtifactAvailability.AVAILABLE,
        source_build_possible=False,
        metadata_used=(ARTIFACT_ID,),
        applicable_requirements=(("other==2.0",) if incomplete else ()),
        reason=(
            "evidence is incomplete" if incomplete else "compatible wheel supplied"
        ),
    )
    return DependencyReport(
        schema_version=1,
        project_kind=DependencyProjectKind.APPLICATION,
        resolve=True,
        network=False,
        timeout_seconds=30.0,
        resolver="uv",
        index_url=None,
        requirements=(
            ("demo[speed]==1.0", "other==2.0") if incomplete else ("demo[speed]==1.0",)
        ),
        extras=("speed",),
        metadata=(_metadata(incomplete=incomplete),),
        metadata_issues=(),
        targets=(
            TargetDependencyResult(
                target=_target(),
                declared_requirements=(declared,),
                transitive_requirements=((transitive,) if incomplete else ()),
                assessments=(assessment,),
                resolution=resolution,
            ),
        ),
    )


def _schema() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )


def _nested_object(
    document: dict[str, object], path: tuple[str | int, ...]
) -> dict[str, object]:
    value: object = document
    for component in path:
        if isinstance(component, int):
            value = cast("list[object]", value)[component]
        else:
            value = cast("dict[str, object]", value)[component]
    return cast("dict[str, object]", value)


def _resolution_document(status: str) -> dict[str, object]:
    resolve, complete, resolver_version, has_packages = RESOLUTION_SHAPES[status]
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
    controls = _nested_object(document, ("controls",))
    resolution = _nested_object(document, ("targets", 0, "resolution"))
    controls["resolve"] = resolve
    resolution.update(
        {
            "complete": complete,
            "packages": ([deepcopy(RESOLVED_PACKAGE_DOCUMENT)] if has_packages else []),
            "resolver_version": resolver_version,
            "status": status,
        }
    )
    if not has_packages:
        declared = _nested_object(
            document,
            ("targets", 0, "declared_requirements", 0),
        )
        declared["resolved_versions"] = []
    if status == "resolution-failed":
        target = _nested_object(document, ("targets", 0))
        declared_rows = cast(
            "list[dict[str, object]]",
            target["declared_requirements"],
        )
        conflicting = deepcopy(declared_rows[0])
        conflicting.update(
            {
                "matching_metadata": [],
                "requirement": "demo==2.0",
                "resolved_versions": [],
                "verified": True,
            }
        )
        declared_rows.append(conflicting)
        document["requirements"] = ["demo[speed]==1.0", "demo==2.0"]
    return document


def _incomplete_document() -> dict[str, object]:
    return cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=True))),
    )


def _metadata_issue_document() -> dict[str, object]:
    report = replace(
        _report(incomplete=True),
        metadata_issues=(
            MetadataIssue(
                path=PurePosixPath("wheelhouse/broken.whl"),
                message="metadata is malformed",
            ),
        ),
        targets=(
            replace(
                _report(incomplete=True).targets[0],
                resolution=ResolverResult(
                    status=ResolutionStatus.UNVERIFIED,
                    complete=False,
                    resolver="uv",
                    resolver_version=None,
                    packages=(),
                    reason="configured metadata evidence is incomplete",
                ),
            ),
        ),
    )
    return cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(report)),
    )


def _assessment_document(
    status: str,
    requires_python_status: str,
    artifact_availability: str,
) -> dict[str, object]:
    document = _resolution_document("not-requested")
    assessment = _nested_object(document, ("targets", 0, "assessments", 0))
    assessment.update(
        {
            "artifact_availability": artifact_availability,
            "requires_python_status": requires_python_status,
            "source_build_possible": artifact_availability == "source-build-possible",
            "status": status,
        }
    )
    return document


def _inactive_marker_resolution_document() -> dict[str, object]:
    document = _resolution_document("succeeded")
    inactive_requirement = 'demo[speed]==1.0; python_version < "3"'
    document["requirements"] = [inactive_requirement]
    target = _nested_object(document, ("targets", 0))
    _nested_object(target, ("resolution",))["packages"] = []
    target["assessments"] = []
    target["transitive_requirements"] = []
    declared = cast("list[dict[str, object]]", target["declared_requirements"])[0]
    declared.update(
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [],
            "requirement": inactive_requirement,
            "resolved_versions": [],
        }
    )
    return document


def _assert_every_object_is_closed(schema: object) -> None:
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            properties = cast("dict[str, object]", schema["properties"])
            required = cast("list[str]", schema["required"])
            assert schema["additionalProperties"] is False
            assert set(required) == set(properties)
        for value in schema.values():
            _assert_every_object_is_closed(value)
    elif isinstance(schema, list):
        for value in schema:
            _assert_every_object_is_closed(value)


def test_dependency_report_schema_accepts_complete_and_incomplete_documents() -> None:
    """The published schema accepts both representative public outcomes."""
    schema = _schema()
    validator = Draft202012Validator(schema)

    validator.check_schema(schema)
    validator.validate(dependency_report_document(_report(incomplete=False)))
    validator.validate(dependency_report_document(_report(incomplete=True)))
    _assert_every_object_is_closed(schema)


@pytest.mark.parametrize(
    ("path", "expected_maximum"),
    [
        (("properties", "extras"), 256),
        (("properties", "metadata"), 256),
        (("properties", "metadata_issues"), 256),
        (("properties", "requirements"), 10_000),
        (("properties", "targets"), 64),
        (("$defs", "assessment", "properties", "applicable_requirements"), 10_000),
        (("$defs", "assessment", "properties", "metadata_used"), 256),
        (("$defs", "declared_requirement", "properties", "matching_extras"), 256),
        (("$defs", "declared_requirement", "properties", "matching_metadata"), 256),
        (("$defs", "declared_requirement", "properties", "resolved_versions"), 1),
        (("$defs", "metadata", "properties", "dynamic"), 10_000),
        (("$defs", "metadata", "properties", "provides_extra"), 256),
        (("$defs", "metadata", "properties", "requires_dist"), 10_000),
        (("$defs", "metadata", "properties", "wheel_tags"), 4096),
        (("$defs", "resolution", "properties", "packages"), 10_000),
        (("$defs", "resolved_package", "properties", "metadata_used"), 256),
        (("$defs", "target", "properties", "compatible_tags"), 4096),
        (("$defs", "target_result", "properties", "assessments"), 256),
        (
            ("$defs", "target_result", "properties", "declared_requirements"),
            10_000,
        ),
        (
            ("$defs", "target_result", "properties", "transitive_requirements"),
            100_000,
        ),
        (
            ("$defs", "transitive_requirement", "properties", "locked_versions"),
            10_000,
        ),
        (
            ("$defs", "transitive_requirement", "properties", "matching_metadata"),
            256,
        ),
        (
            ("$defs", "transitive_requirement", "properties", "required_by"),
            256,
        ),
        (
            ("$defs", "transitive_requirement", "properties", "resolved_versions"),
            1,
        ),
    ],
)
def test_dependency_report_schema_records_runtime_collection_limits(
    path: tuple[str | int, ...],
    expected_maximum: int,
) -> None:
    """The public schema cannot admit collections the emitter rejects."""
    assert _nested_object(_schema(), path)["maxItems"] == expected_maximum


@pytest.mark.parametrize(
    "path",
    [
        ("metadata", 0, "name"),
        ("metadata", 0, "version"),
        ("targets", 0, "declared_requirements", 0, "requirement"),
        ("targets", 0, "resolution", "packages", 0, "name"),
        ("targets", 0, "resolution", "packages", 0, "version"),
        ("targets", 0, "resolution", "reason"),
        ("targets", 0, "target", "name"),
    ],
)
def test_dependency_report_schema_rejects_empty_evidence_strings(
    path: tuple[str | int, ...],
) -> None:
    """Exact identities and evidence explanations are always nonempty."""
    document = _resolution_document("succeeded")
    _nested_object(document, path[:-1])[cast("str", path[-1])] = ""

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("controls",),
        ("metadata", 0),
        ("metadata_issues", 0),
        ("targets", 0),
        ("targets", 0, "assessments", 0),
        ("targets", 0, "declared_requirements", 0),
        ("targets", 0, "resolution"),
        ("targets", 0, "resolution", "packages", 0),
        ("targets", 0, "target"),
        ("targets", 0, "transitive_requirements", 0),
    ],
)
def test_dependency_report_schema_rejects_extra_keys_at_every_object_level(
    path: tuple[str | int, ...],
) -> None:
    """An additive shape change requires a deliberate schema-version decision."""
    document = (
        _metadata_issue_document()
        if path[:1] == ("metadata_issues",)
        else _incomplete_document()
    )
    _nested_object(document, path)["unexpected"] = True

    with pytest.raises(ValidationError, match="Additional properties"):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        ((), "schema_version"),
        (("controls",), "network"),
        (("metadata", 0), "artifact_id"),
        (("metadata_issues", 0), "message"),
        (("targets", 0), "resolution"),
        (("targets", 0, "assessments", 0), "status"),
        (("targets", 0, "declared_requirements", 0), "verified"),
        (("targets", 0, "resolution"), "status"),
        (("targets", 0, "resolution", "packages", 0), "metadata_used"),
        (("targets", 0, "target"), "python_full_version"),
        (("targets", 0, "transitive_requirements", 0), "required_by"),
    ],
)
def test_dependency_report_schema_rejects_missing_required_fields(
    path: tuple[str | int, ...],
    field: str,
) -> None:
    """Removing a current report field is schema drift, not a silent change."""
    document = (
        _metadata_issue_document()
        if path[:1] == ("metadata_issues",)
        else _incomplete_document()
    )
    del _nested_object(document, path)[field]

    with pytest.raises(ValidationError, match="is a required property"):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    ("network", "index_url"),
    [
        (False, None),
        (True, "https://packages.example/simple"),
    ],
)
def test_dependency_report_schema_accepts_valid_network_controls(
    network: object,
    index_url: str | None,
) -> None:
    """Published controls preserve the effective network/index boundary."""
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
    controls = _nested_object(document, ("controls",))
    controls.update({"index_url": index_url, "network": network})

    Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("network-without-index", None),
        ("offline-with-index", "https://packages.example/simple"),
        ("resolver", "other"),
    ],
)
def test_dependency_report_schema_rejects_contradictory_network_controls(
    field: str,
    invalid_value: str | None,
) -> None:
    """Schema v1 cannot advertise ambient indexes or another resolver."""
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
    controls = _nested_object(document, ("controls",))
    if field == "network-without-index":
        controls.update({"index_url": invalid_value, "network": True})
    elif field == "offline-with-index":
        controls.update({"index_url": invalid_value, "network": False})
    else:
        controls["resolver"] = invalid_value

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_bounds_resolver_timeout() -> None:
    """The published deadline remains portable to Windows millisecond waits."""
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
    controls = _nested_object(document, ("controls",))
    controls["timeout_seconds"] = 86_400
    Draft202012Validator(_schema()).validate(document)

    controls["timeout_seconds"] = 86_400.1
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize("status", RESOLUTION_SHAPES)
def test_dependency_report_schema_accepts_each_resolution_status_shape(
    status: str,
) -> None:
    """Every public resolution status accepts its exact model-valid row."""
    Draft202012Validator(_schema()).validate(_resolution_document(status))


def test_dependency_report_schema_accepts_an_injected_resolver_adapter_name() -> None:
    """Result provenance names the actual adapter while controls remain uv-based."""
    document = _resolution_document("succeeded")
    _nested_object(document, ("targets", 0, "resolution"))["resolver"] = (
        "custom-adapter"
    )

    Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    ("status", "path", "invalid_value"),
    [
        ("not-requested", ("targets", 0, "resolution", "complete"), False),
        (
            "not-requested",
            ("targets", 0, "resolution", "resolver_version"),
            "0.12.6",
        ),
        (
            "not-requested",
            ("targets", 0, "resolution", "packages"),
            [RESOLVED_PACKAGE_DOCUMENT],
        ),
        ("not-requested", ("controls", "resolve"), True),
        ("succeeded", ("targets", 0, "resolution", "complete"), False),
        ("succeeded", ("targets", 0, "resolution", "resolver_version"), None),
        (
            "succeeded",
            ("targets", 0, "resolution", "packages", 0, "metadata_used"),
            [],
        ),
        (
            "succeeded",
            ("targets", 0, "resolution", "packages", 0, "metadata_used"),
            [ARTIFACT_ID, "b" * 64],
        ),
        ("succeeded", ("controls", "resolve"), False),
        (
            "artifact-unavailable",
            ("targets", 0, "resolution", "complete"),
            False,
        ),
        (
            "artifact-unavailable",
            ("targets", 0, "resolution", "resolver_version"),
            None,
        ),
        (
            "artifact-unavailable",
            ("targets", 0, "resolution", "packages"),
            [RESOLVED_PACKAGE_DOCUMENT],
        ),
        ("artifact-unavailable", ("controls", "resolve"), False),
        (
            "resolution-failed",
            ("targets", 0, "resolution", "complete"),
            False,
        ),
        (
            "resolution-failed",
            ("targets", 0, "resolution", "resolver_version"),
            None,
        ),
        (
            "resolution-failed",
            ("targets", 0, "resolution", "packages"),
            [RESOLVED_PACKAGE_DOCUMENT],
        ),
        ("resolution-failed", ("controls", "resolve"), False),
        ("timed-out", ("targets", 0, "resolution", "complete"), True),
        (
            "timed-out",
            ("targets", 0, "resolution", "packages"),
            [RESOLVED_PACKAGE_DOCUMENT],
        ),
        ("timed-out", ("controls", "resolve"), False),
        ("unverified", ("targets", 0, "resolution", "complete"), True),
        ("unverified", ("targets", 0, "resolution", "resolver_version"), None),
        ("unverified", ("controls", "resolve"), False),
    ],
)
def test_dependency_report_schema_rejects_resolution_status_contradictions(
    status: str,
    path: tuple[str | int, ...],
    invalid_value: object,
) -> None:
    """Status rows cannot contradict completeness, evidence, or request state."""
    document = _resolution_document(status)
    parent = _nested_object(document, path[:-1])
    parent[cast("str", path[-1])] = deepcopy(invalid_value)

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_impossible_complete_evidence() -> None:
    """Complete resolver states cannot retain evidence the emitter marks incomplete."""
    documents: list[dict[str, object]] = []

    unverified_assessment = _resolution_document("succeeded")
    _nested_object(
        unverified_assessment,
        ("targets", 0, "assessments", 0),
    )["status"] = "unverified"
    documents.append(unverified_assessment)

    missing_assessment = _resolution_document("succeeded")
    _nested_object(missing_assessment, ("targets", 0))["assessments"] = []
    documents.append(missing_assessment)

    inactive_success = _resolution_document("succeeded")
    inactive_declared = _nested_object(
        inactive_success,
        ("targets", 0, "declared_requirements", 0),
    )
    inactive_declared.update(
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": True,
        }
    )
    documents.append(inactive_success)

    for status in ("artifact-unavailable", "resolution-failed"):
        unverified_negative = _resolution_document(status)
        _nested_object(
            unverified_negative,
            ("targets", 0, "declared_requirements", 0),
        )["verified"] = False
        documents.append(unverified_negative)

    one_root_conflict = _resolution_document("resolution-failed")
    target = _nested_object(one_root_conflict, ("targets", 0))
    declared = cast("list[object]", target["declared_requirements"])
    del declared[1:]
    one_root_conflict["requirements"] = ["demo[speed]==1.0"]
    documents.append(one_root_conflict)

    inactive_unavailability = _resolution_document("artifact-unavailable")
    inactive_declared = _nested_object(
        inactive_unavailability,
        ("targets", 0, "declared_requirements", 0),
    )
    inactive_declared.update(
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": True,
        }
    )
    documents.append(inactive_unavailability)

    validator = Draft202012Validator(_schema())
    for document in documents:
        with pytest.raises(ValidationError):
            validator.validate(document)


def test_dependency_report_schema_accepts_unverified_extra_after_success() -> None:
    """A base-version solve does not prove that its selected wheel provides an extra."""
    document = _resolution_document("succeeded")
    declared = _nested_object(
        document,
        ("targets", 0, "declared_requirements", 0),
    )
    declared.update(
        {
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": False,
        }
    )

    Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_accepts_empty_success_for_inactive_markers() -> None:
    """A target with no active requirement has a complete empty resolver graph."""
    Draft202012Validator(_schema()).validate(_inactive_marker_resolution_document())


def test_dependency_report_schema_rejects_resolver_without_a_configured_root() -> None:
    """Resolver execution always requires at least one configured requirement."""
    document = _inactive_marker_resolution_document()
    document["requirements"] = []

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_omitted_inactive_declared_row() -> None:
    """Every configured root retains one marker-evaluation row per target."""
    document = _inactive_marker_resolution_document()
    _nested_object(document, ("targets", 0))["declared_requirements"] = []

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_accepts_metadata_only_without_requirements() -> None:
    """Resolver-disabled direct inspection may omit configured requirements."""
    document = _resolution_document("not-requested")
    document["requirements"] = []
    _nested_object(document, ("targets", 0))["declared_requirements"] = []

    Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_empty_success_with_active_root() -> None:
    """A successful empty graph cannot silently omit an active requirement."""
    document = _resolution_document("succeeded")
    resolution = _nested_object(document, ("targets", 0, "resolution"))
    resolution["packages"] = []

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize(
    "updates",
    [
        {"applies": True, "matching_extras": []},
        {"applies": True, "matching_extras": ["base", "base"]},
        {
            "applies": False,
            "matching_extras": ["base"],
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": True,
        },
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [ARTIFACT_ID],
            "resolved_versions": [],
            "verified": True,
        },
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": False,
        },
    ],
)
def test_dependency_report_schema_rejects_marker_evidence_contradictions(
    updates: dict[str, object],
) -> None:
    """Declared marker contexts agree with applies and inactive evidence state."""
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
    declared = _nested_object(document, ("targets", 0, "declared_requirements", 0))
    declared.update(updates)

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize("status", ["not-requested", "succeeded"])
def test_dependency_report_schema_requires_local_metadata_evidence(
    status: str,
) -> None:
    """Offline or resolver-disabled reports retain every configured input result."""
    validator = Draft202012Validator(_schema())
    document = _resolution_document(status)
    validator.validate(document)
    document["metadata"] = []
    document["metadata_issues"] = []

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_online_success_without_provenance() -> None:
    """An online selection still requires inspected exact-distribution metadata."""
    document = _resolution_document("succeeded")
    controls = _nested_object(document, ("controls",))
    controls.update(
        {
            "index_url": "https://packages.example/simple",
            "network": True,
        }
    )
    document["metadata"] = []
    document["metadata_issues"] = []

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_success_after_metadata_issue() -> None:
    """A configured artifact failure prevents the resolver child from running."""
    validator = Draft202012Validator(_schema())
    document = _resolution_document("succeeded")
    validator.validate(document)
    document["metadata_issues"] = deepcopy(
        _metadata_issue_document()["metadata_issues"]
    )

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_library_unavailability_claims() -> None:
    """Finite library samples cannot prove artifact unavailability."""
    validator = Draft202012Validator(_schema())
    assessment_claim = _assessment_document(
        "artifact-unavailable",
        "compatible",
        "unavailable",
    )
    validator.validate(assessment_claim)
    assessment_claim["project_kind"] = "library"

    resolution_claim = _resolution_document("artifact-unavailable")
    validator.validate(resolution_claim)
    resolution_claim["project_kind"] = "library"

    for document in (assessment_claim, resolution_claim):
        with pytest.raises(ValidationError):
            validator.validate(document)


def test_dependency_report_schema_rejects_online_unavailability_claim() -> None:
    """An online index failure cannot prove that an artifact does not exist."""
    validator = Draft202012Validator(_schema())
    document = _resolution_document("artifact-unavailable")
    validator.validate(document)
    controls = _nested_object(document, ("controls",))
    controls["network"] = True
    controls["index_url"] = "https://packages.example/simple"

    with pytest.raises(ValidationError):
        validator.validate(document)


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("wheel", "dynamic", ["requires-python"]),
        ("wheel", "wheel_tags", []),
        ("sdist", "wheel_tags", ["py3-none-any"]),
        ("core-metadata", "wheel_tags", ["py3-none-any"]),
    ],
)
def test_dependency_report_schema_rejects_artifact_shape_contradictions(
    kind: str,
    field: str,
    value: object,
) -> None:
    """Artifact kind determines whether wheel tags and dynamic fields can exist."""
    validator = Draft202012Validator(_schema())
    document = _resolution_document("succeeded")
    validator.validate(document)
    metadata = _nested_object(document, ("metadata", 0))
    metadata["kind"] = kind
    metadata[field] = value

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_unproved_declared_verification() -> None:
    """An active verified root names direct metadata or a resolved version."""
    validator = Draft202012Validator(_schema())
    document = _resolution_document("not-requested")
    validator.validate(document)
    declared = _nested_object(document, ("targets", 0, "declared_requirements", 0))
    declared["matching_metadata"] = []
    declared["resolved_versions"] = []

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_unproved_transitive_verification() -> None:
    """An unverified resolver cannot substitute an evidence-free true row."""
    validator = Draft202012Validator(_schema())
    document = _incomplete_document()
    validator.validate(document)
    transitive = _nested_object(document, ("targets", 0, "transitive_requirements", 0))
    transitive.update(
        {
            "locked_versions": [],
            "matching_metadata": [],
            "resolved_versions": [],
            "verified": True,
        }
    )

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_transitive_without_parent() -> None:
    """Every transitive row names at least one exact requiring package."""
    validator = Draft202012Validator(_schema())
    document = _incomplete_document()
    validator.validate(document)
    transitive = _nested_object(document, ("targets", 0, "transitive_requirements", 0))
    transitive["required_by"] = []

    with pytest.raises(ValidationError):
        validator.validate(document)


def _successful_transitive_document(project_kind: str) -> dict[str, object]:
    document = _incomplete_document()
    document["metadata_issues"] = []
    document["project_kind"] = project_kind
    resolution = _nested_object(document, ("targets", 0, "resolution"))
    resolution.update(
        {
            "complete": True,
            "packages": [deepcopy(RESOLVED_PACKAGE_DOCUMENT)],
            "resolver_version": "0.12.6",
            "status": "succeeded",
        }
    )
    assessment = _nested_object(document, ("targets", 0, "assessments", 0))
    assessment.update(
        {
            "requires_python_status": "compatible",
            "status": "compatible",
        }
    )
    declared = _nested_object(document, ("targets", 0, "declared_requirements", 0))
    declared.update(
        {
            "matching_metadata": [ARTIFACT_ID],
            "resolved_versions": ["demo==1.0"],
            "verified": True,
        }
    )
    transitive = _nested_object(document, ("targets", 0, "transitive_requirements", 0))
    transitive.update(
        {
            "locked_versions": ["other==2.0"],
            "matching_metadata": [ARTIFACT_ID],
            "resolved_versions": ["other==2.0"],
            "verified": True,
        }
    )
    return document


def test_dependency_report_schema_requires_library_resolver_evidence() -> None:
    """A verified library transitive row comes from a complete selected version."""
    validator = Draft202012Validator(_schema())
    document = _successful_transitive_document("library")
    validator.validate(document)
    transitive = _nested_object(document, ("targets", 0, "transitive_requirements", 0))
    transitive["resolved_versions"] = []

    with pytest.raises(ValidationError):
        validator.validate(document)


def test_dependency_report_schema_rejects_success_without_selected_transitive() -> None:
    """Successful verification requires the resolver's selected exact version."""
    document = _successful_transitive_document("application")
    _nested_object(document, ("targets", 0, "transitive_requirements", 0))[
        "resolved_versions"
    ] = []

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_accepts_unverified_missing_extra_row() -> None:
    """A successful solve may retain an explicitly unverified dependency extra."""
    document = _successful_transitive_document("application")
    transitive = _nested_object(document, ("targets", 0, "transitive_requirements", 0))
    transitive["resolved_versions"] = []
    transitive["verified"] = False

    Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_false_solver_conflict_row() -> None:
    """A complete solver contradiction verifies every active transitive row."""
    document = _incomplete_document()
    resolution = _nested_object(document, ("targets", 0, "resolution"))
    resolution.update(
        {
            "complete": True,
            "packages": [],
            "resolver_version": "0.12.6",
            "status": "resolution-failed",
        }
    )

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_rejects_noncanonical_collection_shapes() -> None:
    """Emitter-required collections remain nonempty where needed and unique."""
    documents: list[dict[str, object]] = []
    validator = Draft202012Validator(_schema())

    def duplicate_collection(
        document: dict[str, object],
        path: tuple[str | int, ...],
        field: str,
        *,
        seed: object | None = None,
    ) -> None:
        values = cast("list[object]", _nested_object(document, path)[field])
        if not values:
            assert seed is not None
            values.append(seed)
        validator.validate(document)
        values.append(deepcopy(values[0]))
        documents.append(document)

    no_targets = _resolution_document("succeeded")
    no_targets["targets"] = []
    documents.append(no_targets)

    no_tags = _resolution_document("succeeded")
    _nested_object(no_tags, ("targets", 0, "target"))["compatible_tags"] = []
    documents.append(no_tags)

    duplicate_tags = _resolution_document("succeeded")
    _nested_object(duplicate_tags, ("targets", 0, "target"))["compatible_tags"] = [
        "py3-none-any",
        "py3-none-any",
    ]
    documents.append(duplicate_tags)

    duplicate_packages = _resolution_document("succeeded")
    packages = cast(
        "list[object]",
        _nested_object(duplicate_packages, ("targets", 0, "resolution"))["packages"],
    )
    packages.append(deepcopy(packages[0]))
    documents.append(duplicate_packages)

    for field in ("extras", "metadata", "requirements"):
        duplicate_top_level = _resolution_document("succeeded")
        values = cast("list[object]", duplicate_top_level[field])
        values.append(deepcopy(values[0]))
        documents.append(duplicate_top_level)

    duplicate_assessments = _resolution_document("succeeded")
    assessments = cast(
        "list[object]",
        _nested_object(duplicate_assessments, ("targets", 0))["assessments"],
    )
    assessments.append(deepcopy(assessments[0]))
    documents.append(duplicate_assessments)

    duplicate_dynamic = _resolution_document("succeeded")
    dynamic_metadata = _nested_object(duplicate_dynamic, ("metadata", 0))
    dynamic_metadata["kind"] = "sdist"
    dynamic_metadata["wheel_tags"] = []
    duplicate_collection(
        duplicate_dynamic,
        ("metadata", 0),
        "dynamic",
        seed="requires-python",
    )
    duplicate_collection(
        _resolution_document("succeeded"),
        ("metadata", 0),
        "provides_extra",
    )
    duplicate_collection(
        _resolution_document("succeeded"),
        ("metadata", 0),
        "wheel_tags",
    )
    duplicate_collection(
        _incomplete_document(),
        ("targets", 0, "assessments", 0),
        "applicable_requirements",
    )
    duplicate_collection(
        _resolution_document("succeeded"),
        ("targets", 0),
        "declared_requirements",
    )
    duplicate_collection(
        _resolution_document("succeeded"),
        ("targets", 0, "declared_requirements", 0),
        "matching_metadata",
    )
    duplicate_collection(
        _resolution_document("succeeded"),
        ("targets", 0, "declared_requirements", 0),
        "resolved_versions",
    )
    duplicate_collection(
        _metadata_issue_document(),
        (),
        "metadata_issues",
    )
    duplicate_collection(
        _incomplete_document(),
        ("targets", 0),
        "transitive_requirements",
    )
    for field, seed in (
        ("locked_versions", None),
        ("matching_metadata", ARTIFACT_ID),
        ("required_by", None),
        ("resolved_versions", "other==2.0"),
    ):
        duplicate_collection(
            _incomplete_document(),
            ("targets", 0, "transitive_requirements", 0),
            field,
            seed=seed,
        )

    for document in documents:
        with pytest.raises(ValidationError):
            validator.validate(document)


@pytest.mark.parametrize(
    ("status", "requires_python_status", "artifact_availability"),
    [
        ("compatible", "compatible", "available"),
        ("compatible", "unspecified", "available"),
        ("declared-incompatible", "incompatible", "available"),
        ("artifact-unavailable", "compatible", "unavailable"),
        ("artifact-unavailable", "unspecified", "source-build-possible"),
        ("unverified", "incompatible", "available"),
    ],
)
def test_dependency_report_schema_accepts_valid_assessment_status_combinations(
    status: str,
    requires_python_status: str,
    artifact_availability: str,
) -> None:
    """Assessment conditionals permit every model-valid outcome class."""
    Draft202012Validator(_schema()).validate(
        _assessment_document(
            status,
            requires_python_status,
            artifact_availability,
        )
    )


@pytest.mark.parametrize(
    ("status", "requires_python_status", "artifact_availability"),
    [
        ("compatible", "incompatible", "available"),
        ("compatible", "compatible", "unavailable"),
        ("compatible", "unspecified", "unverified"),
        ("declared-incompatible", "compatible", "available"),
        ("declared-incompatible", "unspecified", "available"),
        ("declared-incompatible", "unverified", "available"),
        ("artifact-unavailable", "compatible", "available"),
        ("artifact-unavailable", "compatible", "unverified"),
        ("artifact-unavailable", "incompatible", "unavailable"),
        ("artifact-unavailable", "unverified", "source-build-possible"),
    ],
)
def test_dependency_report_schema_rejects_assessment_status_contradictions(
    status: str,
    requires_python_status: str,
    artifact_availability: str,
) -> None:
    """Compatibility categories cannot contradict their supporting evidence."""
    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(
            _assessment_document(
                status,
                requires_python_status,
                artifact_availability,
            )
        )


@pytest.mark.parametrize(
    ("status", "requires_python_status", "availability", "invalid_source_build"),
    [
        ("artifact-unavailable", "compatible", "source-build-possible", False),
        ("artifact-unavailable", "compatible", "unavailable", True),
        ("unverified", "unverified", "unverified", True),
    ],
)
def test_dependency_report_schema_rejects_source_build_contradictions(
    status: str,
    requires_python_status: str,
    availability: str,
    invalid_source_build: object,
) -> None:
    """The source-build flag agrees with the artifact availability category."""
    document = _assessment_document(status, requires_python_status, availability)
    assessment = _nested_object(document, ("targets", 0, "assessments", 0))
    assessment["source_build_possible"] = invalid_source_build

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


@pytest.mark.parametrize("metadata_used", [[], [ARTIFACT_ID, ARTIFACT_ID]])
def test_dependency_report_schema_requires_unique_assessment_provenance(
    metadata_used: list[str],
) -> None:
    """Every assessment names at least one distinct inspected metadata record."""
    document = _assessment_document("compatible", "compatible", "available")
    assessment = _nested_object(document, ("targets", 0, "assessments", 0))
    assessment["metadata_used"] = metadata_used

    with pytest.raises(ValidationError):
        Draft202012Validator(_schema()).validate(document)


def test_dependency_report_schema_accepts_available_wheel_with_source_fallback() -> (
    None
):
    """An available wheel may coexist with a supplied source distribution."""
    document = _assessment_document("compatible", "compatible", "available")
    assessment = _nested_object(document, ("targets", 0, "assessments", 0))
    assessment["source_build_possible"] = True

    Draft202012Validator(_schema()).validate(document)
