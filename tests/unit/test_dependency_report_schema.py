"""Strict public schema tests for M8 dependency reports."""

import json
from copy import deepcopy
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
        metadata_issues=(
            (
                MetadataIssue(
                    path=PurePosixPath("wheelhouse/broken.whl"),
                    message="metadata is malformed",
                ),
            )
            if incomplete
            else ()
        ),
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
    return document


def _assessment_document(
    status: str,
    requires_python_status: str,
    artifact_availability: str,
) -> dict[str, object]:
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=False))),
    )
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
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=True))),
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
    document = cast(
        "dict[str, object]",
        deepcopy(dependency_report_document(_report(incomplete=True))),
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


def test_dependency_report_schema_accepts_empty_success_for_inactive_markers() -> None:
    """A target with no active requirement has a complete empty resolver graph."""
    document = _resolution_document("succeeded")
    target = _nested_object(document, ("targets", 0))
    resolution = _nested_object(target, ("resolution",))
    resolution["packages"] = []
    target["assessments"] = []
    target["transitive_requirements"] = []
    declared = cast("list[dict[str, object]]", target["declared_requirements"])[0]
    declared.update(
        {
            "applies": False,
            "matching_extras": [],
            "matching_metadata": [],
            "resolved_versions": [],
        }
    )

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


def test_dependency_report_schema_rejects_noncanonical_collection_shapes() -> None:
    """Emitter-required collections remain nonempty where needed and unique."""
    documents: list[dict[str, object]] = []

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

    validator = Draft202012Validator(_schema())
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
