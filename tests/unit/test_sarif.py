"""Golden-field and schema tests for SARIF 2.1.0 output."""

import json
from pathlib import Path
from typing import cast

from jsonschema import validate

from pyahead.analysis import ScanRequest, scan
from pyahead.model import ExitCode, ScanReport
from pyahead.reporting import render_sarif

_OFFICIAL_SARIF_SCHEMA = json.loads(
    (Path(__file__).parents[1] / "fixtures/schemas/sarif-schema-2.1.0.json").read_text(
        encoding="utf-8"
    )
)
_SARIF_SUBSET_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["$schema", "version", "runs"],
    "properties": {
        "$schema": {"type": "string", "format": "uri"},
        "version": {"const": "2.1.0"},
        "runs": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": [
                                    "name",
                                    "version",
                                    "semanticVersion",
                                    "rules",
                                ],
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": [
                                "ruleId",
                                "ruleIndex",
                                "level",
                                "locations",
                                "partialFingerprints",
                                "properties",
                            ],
                        },
                    },
                },
            },
        },
    },
}


def _scan(root: Path, source: str, **options: object) -> ScanReport:
    path = root / "legacy file.py"
    path.write_text(source, encoding="utf-8")
    values: dict[str, object] = {
        "root": root,
        "baseline_python": "3.11",
        "horizon_python": "3.13",
    }
    values.update(options)
    return scan(ScanRequest(**values))  # type: ignore[arg-type]


def test_sarif_validates_and_uses_stable_ci_identity_fields(
    tmp_path: Path,
) -> None:
    """Rule IDs, relative URIs, exact regions, and fingerprints are preserved."""
    report = _scan(tmp_path, "\nimport cgi\n")
    rendered = render_sarif(report)
    document = cast("dict[str, object]", json.loads(rendered))

    validate(document, _OFFICIAL_SARIF_SCHEMA)
    validate(document, _SARIF_SUBSET_SCHEMA)
    runs = cast("list[dict[str, object]]", document["runs"])
    run = runs[0]
    tool = cast("dict[str, object]", run["tool"])
    driver = cast("dict[str, object]", tool["driver"])
    rules = cast("list[dict[str, object]]", driver["rules"])
    results = cast("list[dict[str, object]]", run["results"])
    result = results[0]
    locations = cast("list[dict[str, object]]", result["locations"])
    physical = cast(
        "dict[str, object]",
        cast("dict[str, object]", locations[0]["physicalLocation"]),
    )
    artifact = cast("dict[str, object]", physical["artifactLocation"])

    assert document["version"] == "2.1.0"
    assert run["columnKind"] == "unicodeCodePoints"
    assert driver["name"] == "pyahead"
    assert driver["semanticVersion"] == "0.1.0-alpha.2"
    assert [rule["id"] for rule in rules] == ["CPY0001"]
    assert result["ruleId"] == "CPY0001"
    assert result["level"] == "error"
    assert result["partialFingerprints"] == {
        "pyahead/v1": report.findings[0].fingerprint
    }
    assert artifact == {
        "uri": "legacy%20file.py",
        "uriBaseId": "%SRCROOT%",
    }
    assert physical["region"] == {
        "endColumn": 11,
        "endLine": 2,
        "startColumn": 1,
        "startLine": 2,
    }
    assert str(tmp_path) not in rendered
    assert render_sarif(report) == rendered


def test_sarif_non_bmp_region_uses_declared_unicode_code_points(
    tmp_path: Path,
) -> None:
    """Columns after a non-BMP character agree with the run's declared unit."""
    report = _scan(tmp_path, 'label = "😀"; import cgi\n')
    document = cast("dict[str, object]", json.loads(render_sarif(report)))
    runs = cast("list[dict[str, object]]", document["runs"])
    run = runs[0]
    results = cast("list[dict[str, object]]", run["results"])
    locations = cast("list[dict[str, object]]", results[0]["locations"])
    physical = cast(
        "dict[str, object]",
        cast("dict[str, object]", locations[0]["physicalLocation"]),
    )

    assert run["columnKind"] == "unicodeCodePoints"
    assert physical["region"] == {
        "endColumn": 24,
        "endLine": 1,
        "startColumn": 14,
        "startLine": 1,
    }


def test_sarif_suppression_and_baseline_state_are_structured(
    tmp_path: Path,
) -> None:
    """Opted-in suppressed results use SARIF's in-source suppression model."""
    report = _scan(
        tmp_path,
        "import cgi  # pyahead: ignore[CPY0001] -- tracked\n",
        show_suppressed=True,
    )
    document = cast("dict[str, object]", json.loads(render_sarif(report)))
    runs = cast("list[dict[str, object]]", document["runs"])
    results = cast("list[dict[str, object]]", runs[0]["results"])

    assert results[0]["baselineState"] == "new"
    assert results[0]["suppressions"] == [
        {"justification": "tracked", "kind": "inSource"}
    ]


def test_clean_sarif_has_empty_rule_and_result_arrays(tmp_path: Path) -> None:
    """A complete clean scan is still an independently valid SARIF run."""
    report = _scan(tmp_path, "import pathlib\n")
    document = cast("dict[str, object]", json.loads(render_sarif(report)))
    runs = cast("list[dict[str, object]]", document["runs"])
    tool = cast("dict[str, object]", runs[0]["tool"])
    driver = cast("dict[str, object]", tool["driver"])

    assert driver["rules"] == []
    assert runs[0]["results"] == []


def test_allowed_incomplete_sarif_retains_diagnostic_and_completion_counts(
    tmp_path: Path,
) -> None:
    """An allowed incomplete scan remains explicit in valid empty SARIF."""
    report = _scan(tmp_path, "if:\n", allow_incomplete=True)
    document = cast("dict[str, object]", json.loads(render_sarif(report)))

    assert report.exit_code is ExitCode.SUCCESS
    validate(document, _OFFICIAL_SARIF_SCHEMA)
    runs = cast("list[dict[str, object]]", document["runs"])
    run = runs[0]
    invocations = cast("list[dict[str, object]]", run["invocations"])
    invocation = invocations[0]
    notifications = cast(
        "list[dict[str, object]]",
        invocation["toolExecutionNotifications"],
    )
    notification = notifications[0]
    locations = cast("list[dict[str, object]]", notification["locations"])
    physical = cast("dict[str, object]", locations[0]["physicalLocation"])
    artifact = cast("dict[str, object]", physical["artifactLocation"])

    assert run["results"] == []
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"] == {
        "filesAnalyzed": 0,
        "filesDiscovered": 1,
        "filesIncomplete": 1,
        "scanComplete": False,
    }
    assert notification["descriptor"] == {"id": "PYA1003", "index": 0}
    assert notification["properties"] == {
        "category": "parse",
        "code": "PYA1003",
        "fatal": False,
        "incomplete": True,
    }
    assert artifact == {"uri": "legacy%20file.py", "uriBaseId": "%SRCROOT%"}
    assert str(tmp_path) not in json.dumps(document)


def test_sarif_retains_unknown_suppression_when_all_findings_are_hidden(
    tmp_path: Path,
) -> None:
    """Suppression typos remain visible when the known ID hides every result."""
    report = _scan(
        tmp_path,
        "import cgi  # pyahead: ignore[CPY0001, UNKNOWN]\n",
    )
    document = cast("dict[str, object]", json.loads(render_sarif(report)))

    assert len(report.findings) == 1
    assert report.visible_findings == ()
    validate(document, _OFFICIAL_SARIF_SCHEMA)
    runs = cast("list[dict[str, object]]", document["runs"])
    run = runs[0]
    tool = cast("dict[str, object]", run["tool"])
    driver = cast("dict[str, object]", tool["driver"])
    descriptors = cast("list[dict[str, object]]", driver["notifications"])
    invocations = cast("list[dict[str, object]]", run["invocations"])
    invocation = invocations[0]
    notifications = cast(
        "list[dict[str, object]]",
        invocation["toolExecutionNotifications"],
    )
    notification = notifications[0]
    locations = cast("list[dict[str, object]]", notification["locations"])
    physical = cast("dict[str, object]", locations[0]["physicalLocation"])

    assert run["results"] == []
    assert driver["rules"] == []
    assert [item["id"] for item in descriptors] == ["PYA3001"]
    assert invocation["properties"] == {
        "filesAnalyzed": 1,
        "filesDiscovered": 1,
        "filesIncomplete": 0,
        "scanComplete": True,
    }
    assert notification["descriptor"] == {"id": "PYA3001", "index": 0}
    assert physical["artifactLocation"] == {
        "uri": "legacy%20file.py",
        "uriBaseId": "%SRCROOT%",
    }


def test_sarif_retains_module_resolution_inference_provenance(
    tmp_path: Path,
) -> None:
    """A false-positive guard remains visible in a schema-valid SARIF run."""
    (tmp_path / "cgi.py").write_text("", encoding="utf-8")
    report = _scan(tmp_path, "import cgi\n")
    document = cast("dict[str, object]", json.loads(render_sarif(report)))

    validate(document, _OFFICIAL_SARIF_SCHEMA)
    runs = cast("list[dict[str, object]]", document["runs"])
    run = runs[0]
    invocations = cast("list[dict[str, object]]", run["invocations"])
    notifications = cast(
        "list[dict[str, object]]",
        invocations[0]["toolExecutionNotifications"],
    )
    notification = notifications[0]
    properties = cast("dict[str, object]", notification["properties"])
    evidence = cast("dict[str, object]", properties["evidence"])
    locations = cast("list[dict[str, object]]", notification["locations"])
    physical = cast("dict[str, object]", locations[0]["physicalLocation"])

    assert report.findings == ()
    assert [item.code for item in report.inferences] == ["PYA2001"]
    assert notification["descriptor"] == {"id": "PYA2001", "index": 0}
    assert notification["level"] == "note"
    assert properties["code"] == "PYA2001"
    assert properties["kind"] == "module-resolution"
    assert evidence["candidate_paths"] == ["cgi.py"]
    assert evidence["resolution"] == "competing-project-module"
    assert physical["artifactLocation"] == {
        "uri": "legacy%20file.py",
        "uriBaseId": "%SRCROOT%",
    }


def test_sarif_retains_version_guard_inference_provenance(tmp_path: Path) -> None:
    """Unsupported patch guards remain visible in schema-valid SARIF."""
    report = _scan(
        tmp_path,
        "import sys\nif sys.version_info >= (3, 13, 1):\n    import cgi\n",
    )
    document = cast("dict[str, object]", json.loads(render_sarif(report)))

    validate(document, _OFFICIAL_SARIF_SCHEMA)
    runs = cast("list[dict[str, object]]", document["runs"])
    invocations = cast("list[dict[str, object]]", runs[0]["invocations"])
    notifications = cast(
        "list[dict[str, object]]",
        invocations[0]["toolExecutionNotifications"],
    )
    notification = notifications[0]
    properties = cast("dict[str, object]", notification["properties"])

    assert [item.code for item in report.inferences] == ["PYA2002"]
    assert notification["descriptor"] == {"id": "PYA2002", "index": 0}
    assert notification["level"] == "note"
    assert properties == {
        "code": "PYA2002",
        "evidence": {
            "guard_granularity": "patch",
            "reachability": "both-branches",
        },
        "kind": "version-guard",
    }
