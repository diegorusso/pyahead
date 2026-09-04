"""Hermetic unit tests for the PyPI top-1000 acquisition and verification tool."""

# ruff: noqa: SLF001

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from packaging.tags import cpython_tags

from scripts import pypi_corpus

if TYPE_CHECKING:
    from pathlib import Path

_CORPUS_SIZE = 1000
_SHA256_HEX_LENGTH = 64
_RANKING_URL = "https://example.test/top-pypi-packages.json"


def _fake_environment(count: int = _CORPUS_SIZE) -> tuple[bytes, dict[str, bytes]]:
    """Build a synthetic ranking payload plus every response it will trigger."""
    rows = [{"project": f"demo-package-{index}"} for index in range(count)]
    ranking = json.dumps({"rows": rows}).encode()
    responses: dict[str, bytes] = {}
    for row in rows:
        name = row["project"]
        version = "1.0.0"
        filename = f"{name}-{version}-py3-none-any.whl"
        artifact = f"artifact-contents-for-{name}".encode()
        metadata = {
            "info": {"requires_python": ">=3.9", "version": version},
            "urls": [
                {
                    "filename": filename,
                    "packagetype": "bdist_wheel",
                    "requires_python": ">=3.9",
                    "url": f"https://files.example.test/{filename}",
                    "yanked": False,
                },
            ],
        }
        responses[pypi_corpus._project_metadata_url(name)] = json.dumps(
            metadata
        ).encode()
        responses[f"https://files.example.test/{filename}"] = artifact
    return ranking, responses


def _fake_http_get(ranking: bytes, responses: dict[str, bytes]) -> pypi_corpus.HttpGet:
    """Serve canned bytes for the ranking URL and every derived request, no network."""

    def http_get(url: str, timeout: float) -> bytes:
        assert timeout > 0
        if url == _RANKING_URL:
            return ranking
        try:
            return responses[url]
        except KeyError:
            message = f"unexpected request for {url}"
            raise AssertionError(message) from None

    return http_get


def _fixed_clock() -> datetime:
    return datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


def _acquire_into(tmp_path: Path, *, count: int = _CORPUS_SIZE) -> tuple[Path, Path]:
    """Run `_acquire` against a synthetic environment and return its outputs."""
    ranking, responses = _fake_environment(count)
    manifest_path = tmp_path / "manifest.json"
    wheelhouse = tmp_path / "wheelhouse"
    pypi_corpus._acquire(
        source_url=_RANKING_URL,
        manifest_path=manifest_path,
        wheelhouse=wheelhouse,
        timeout=5.0,
        hooks=pypi_corpus.AcquireHooks(
            http_get=_fake_http_get(ranking, responses),
            clock=_fixed_clock,
            progress=lambda _message: None,
        ),
    )
    return manifest_path, wheelhouse


def _valid_document(count: int = _CORPUS_SIZE) -> dict[str, Any]:
    """Build a manifest document that passes `_load_manifest` unmodified."""
    packages = [
        {
            "filename": f"pkg{index}-1.0.0-py3-none-any.whl",
            "is_wheel": True,
            "name": f"pkg{index}",
            "rank": index + 1,
            "requires_python": ">=3.9",
            "sha256": hashlib.sha256(f"pkg{index}".encode()).hexdigest(),
            "version": "1.0.0",
        }
        for index in range(count)
    ]
    return {
        "packages": packages,
        "retrieved_on": "2026-09-03T12:00:00+00:00",
        "schema_version": 1,
        "source_url": _RANKING_URL,
        "upstream_payload_sha256": "a" * _SHA256_HEX_LENGTH,
    }


def _write_manifest(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


# --- acquire end-to-end -----------------------------------------------------


def test_acquire_writes_a_manifest_with_exactly_1000_verified_entries(
    tmp_path: Path,
) -> None:
    """The acquired manifest is schema-valid and every artifact hash matches."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)

    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["source_url"] == _RANKING_URL
    assert document["retrieved_on"] == "2026-09-03T12:00:00+00:00"
    assert len(document["upstream_payload_sha256"]) == _SHA256_HEX_LENGTH
    assert len(document["packages"]) == _CORPUS_SIZE

    first = document["packages"][0]
    assert first["rank"] == 1
    assert first["name"] == "demo-package-0"
    assert first["is_wheel"] is True
    artifact_path = wheelhouse / first["filename"]
    assert artifact_path.is_file()
    assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == first["sha256"]


def test_acquire_output_round_trips_through_verify(tmp_path: Path) -> None:
    """A freshly acquired wheelhouse always passes its own offline verification."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    problems = pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse)
    assert problems == []


def test_acquire_rejects_a_ranking_snapshot_with_too_few_projects(
    tmp_path: Path,
) -> None:
    """Acquisition fails closed rather than writing a manifest short of 1000 entries."""
    ranking, responses = _fake_environment(count=5)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="at least 1000"):
        pypi_corpus._acquire(
            source_url=_RANKING_URL,
            manifest_path=tmp_path / "manifest.json",
            wheelhouse=tmp_path / "wheelhouse",
            timeout=5.0,
            hooks=pypi_corpus.AcquireHooks(
                http_get=_fake_http_get(ranking, responses),
                clock=_fixed_clock,
                progress=lambda _message: None,
            ),
        )


def test_acquire_rejects_a_non_https_source_url(tmp_path: Path) -> None:
    """The ranking snapshot URL itself must be a credential-free HTTPS URL."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._acquire(
            source_url="http://example.test/top-pypi-packages.json",
            manifest_path=tmp_path / "manifest.json",
            wheelhouse=tmp_path / "wheelhouse",
            timeout=5.0,
            hooks=pypi_corpus.AcquireHooks(
                http_get=_fake_http_get(b"{}", {}),
                clock=_fixed_clock,
                progress=lambda _message: None,
            ),
        )


# --- ranking parsing ----------------------------------------------------


def test_parse_ranking_rejects_duplicate_normalized_projects() -> None:
    """Two spellings of the same normalized project name cannot both rank."""
    payload = json.dumps(
        {"rows": [{"project": "Foo-Bar"}, {"project": "foo_bar"}] * 500}
    ).encode()
    with pytest.raises(pypi_corpus.PypiCorpusError, match="duplicate project"):
        pypi_corpus._parse_ranking(payload)


def test_parse_ranking_rejects_invalid_json() -> None:
    """A corrupted ranking payload is refused instead of parsed partially."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="not valid JSON"):
        pypi_corpus._parse_ranking(b"not json")


def test_parse_ranking_rejects_a_non_object_document() -> None:
    """The ranking payload must be a JSON object, not a bare array or scalar."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="JSON object"):
        pypi_corpus._parse_ranking(b"[]")


def test_parse_ranking_rejects_a_missing_rows_array() -> None:
    """A ranking document without a `rows` array cannot be parsed."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="rows array"):
        pypi_corpus._parse_ranking(json.dumps({}).encode())


def test_parse_ranking_rejects_a_row_without_a_project_string() -> None:
    """Every row must carry a `project` string; other shapes are refused."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="unexpected shape"):
        pypi_corpus._parse_ranking(json.dumps({"rows": [{"downloads": 1}]}).encode())


def test_parse_ranking_rejects_an_empty_project_name() -> None:
    """An empty `project` string cannot stand in for a package name."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="empty project name"):
        pypi_corpus._parse_ranking(json.dumps({"rows": [{"project": ""}]}).encode())


# --- release file selection ----------------------------------------------


def test_select_release_file_prefers_a_wheel_over_an_sdist() -> None:
    """A wheel is chosen over a co-published sdist for the same release."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.example.test/demo-1.0.0.tar.gz",
            },
            {
                "filename": "demo-1.0.0-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/demo-1.0.0-py3-none-any.whl",
            },
        ],
    }
    selected = pypi_corpus._select_release_file(document, name="demo")
    assert selected["is_wheel"] is True
    assert selected["filename"] == "demo-1.0.0-py3-none-any.whl"


def test_select_release_file_falls_back_to_sdist() -> None:
    """A release with only an sdist is still acquirable."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.example.test/demo-1.0.0.tar.gz",
            },
        ],
    }
    selected = pypi_corpus._select_release_file(document, name="demo")
    assert selected["is_wheel"] is False
    assert selected["filename"] == "demo-1.0.0.tar.gz"


def test_select_release_file_skips_a_platform_incompatible_wheel() -> None:
    """A platform-incompatible wheel is skipped for a universal one."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0-cp311-cp311-totallymadeupplatform.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/demo-1.0.0-cp311-cp311-x.whl",
            },
            {
                "filename": "demo-1.0.0-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/demo-1.0.0-py3-none-any.whl",
            },
        ],
    }
    selected = pypi_corpus._select_release_file(document, name="demo")
    assert selected["filename"] == "demo-1.0.0-py3-none-any.whl"


def test_select_release_file_falls_back_to_sdist_when_every_wheel_is_incompatible() -> (
    None
):
    """An all-incompatible-wheel release falls back to the sdist."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0-cp311-cp311-totallymadeupplatform.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/demo-1.0.0-cp311-cp311-x.whl",
            },
            {
                "filename": "demo-1.0.0.tar.gz",
                "packagetype": "sdist",
                "url": "https://files.example.test/demo-1.0.0.tar.gz",
            },
        ],
    }
    selected = pypi_corpus._select_release_file(document, name="demo")
    assert selected["is_wheel"] is False
    assert selected["filename"] == "demo-1.0.0.tar.gz"


def test_wheel_supports_minor_matches_an_exact_cpython_tag() -> None:
    """A `cp313`-tagged wheel installs under 3.13 but not under 3.11."""
    platform = next(iter(cpython_tags(python_version=(3, 13)))).platform
    filename = f"demo-1.0.0-cp313-cp313-{platform}.whl"
    assert pypi_corpus.wheel_supports_minor(filename, 13) is True
    assert pypi_corpus.wheel_supports_minor(filename, 11) is False


def test_wheel_supports_minor_rejects_a_cpython_tag_paired_with_any_platform() -> None:
    """No real wheel pairs a CPython-specific ABI tag with the generic "any" platform.

    `sys_tags()` advertises "any" only for its own generic `pyN-none-any`
    tags; feeding it through to `cpython_tags()` too would otherwise
    fabricate a combination - `cp313-cp313-any` - that no build backend ever
    produces, silently widening what counts as installable.
    """
    filename = "demo-1.0.0-cp313-cp313-any.whl"
    assert pypi_corpus.wheel_supports_minor(filename, 13) is False


def test_wheel_supports_minor_accepts_a_universal_wheel_everywhere() -> None:
    """A `py3-none-any` wheel installs under every supported minor."""
    filename = "demo-1.0.0-py3-none-any.whl"
    assert pypi_corpus.wheel_supports_minor(filename, 11) is True
    assert pypi_corpus.wheel_supports_minor(filename, 15) is True


def test_wheel_supports_minor_accepts_an_unparseable_filename() -> None:
    """A filename that is not a wheel at all is not this check's job to reject."""
    assert pypi_corpus.wheel_supports_minor("not-a-wheel-filename", 13) is True


def test_select_release_file_ignores_yanked_files() -> None:
    """A yanked-only release has no acquirable artifact."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/demo-1.0.0-py3-none-any.whl",
                "yanked": True,
            },
        ],
    }
    with pytest.raises(pypi_corpus.PypiCorpusError, match="no wheel or sdist"):
        pypi_corpus._select_release_file(document, name="demo")


def test_select_release_file_rejects_only_unsupported_package_types() -> None:
    """A release published only as an unsupported package type is refused."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0.egg",
                "packagetype": "bdist_egg",
                "url": "https://files.example.test/demo-1.0.0.egg",
            },
        ],
    }
    with pytest.raises(pypi_corpus.PypiCorpusError, match="no wheel or sdist"):
        pypi_corpus._select_release_file(document, name="demo")


def test_select_release_file_rejects_a_non_https_file_url() -> None:
    """A file whose download URL is not HTTPS is never acquired."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "demo-1.0.0-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "url": "http://files.example.test/demo-1.0.0-py3-none-any.whl",
            },
        ],
    }
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._select_release_file(document, name="demo")


def test_select_release_file_rejects_an_unsafe_filename() -> None:
    """A path-traversal filename from upstream metadata is never trusted."""
    document = {
        "info": {"version": "1.0.0"},
        "urls": [
            {
                "filename": "../../etc/passwd",
                "packagetype": "bdist_wheel",
                "url": "https://files.example.test/evil",
            },
        ],
    }
    with pytest.raises(pypi_corpus.PypiCorpusError, match="plain filename"):
        pypi_corpus._select_release_file(document, name="demo")


def test_select_release_file_rejects_a_missing_current_version() -> None:
    """Metadata without a resolvable current version cannot be acquired."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="no current version"):
        pypi_corpus._select_release_file({"info": {}}, name="demo")


# --- manifest schema rejection --------------------------------------------


def test_load_manifest_accepts_a_valid_document(tmp_path: Path) -> None:
    """A well-formed 1000-entry manifest loads and sorts entries by rank."""
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, _valid_document())
    document, entries = pypi_corpus._load_manifest(manifest_path)
    assert document["schema_version"] == 1
    assert len(entries) == _CORPUS_SIZE
    assert entries[0].rank == 1


def test_load_manifest_public_wrapper_matches_the_internal_loader(
    tmp_path: Path,
) -> None:
    """The public `load_manifest` is a thin, behavior-preserving wrapper."""
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, _valid_document())
    document, entries = pypi_corpus.load_manifest(manifest_path)
    assert document["schema_version"] == 1
    assert len(entries) == _CORPUS_SIZE


def test_load_manifest_rejects_wrong_schema_version(tmp_path: Path) -> None:
    """Only schema version 1 manifests are trusted."""
    document = _valid_document()
    document["schema_version"] = 2
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="schema version 1"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_a_wrong_package_count(tmp_path: Path) -> None:
    """The runner refuses a manifest that silently shrank below 1000 packages."""
    document = _valid_document()
    document["packages"].pop()
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="exactly 1000"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_an_undocumented_field(tmp_path: Path) -> None:
    """An entry with an extra field outside the documented schema is refused."""
    document = _valid_document()
    document["packages"][0]["extra"] = "unexpected"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="documented fields"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_a_missing_field(tmp_path: Path) -> None:
    """An entry missing a documented field is refused, not defaulted."""
    document = _valid_document()
    del document["packages"][0]["is_wheel"]
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="documented fields"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_duplicate_ranks(tmp_path: Path) -> None:
    """Two entries cannot claim the same rank."""
    document = _valid_document()
    document["packages"][1]["rank"] = document["packages"][0]["rank"]
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="duplicate rank"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_duplicate_normalized_names(tmp_path: Path) -> None:
    """Case- or separator-only variants of the same project name collide."""
    document = _valid_document()
    document["packages"][1]["name"] = document["packages"][0]["name"].upper()
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="duplicate normalized"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_duplicate_filenames(tmp_path: Path) -> None:
    """Two entries cannot point at the same wheelhouse filename."""
    document = _valid_document()
    document["packages"][1]["filename"] = document["packages"][0]["filename"]
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="duplicate filename"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_an_unsafe_filename(tmp_path: Path) -> None:
    """A manifest cannot reference a wheelhouse artifact outside its directory."""
    document = _valid_document()
    document["packages"][0]["filename"] = "../escape.whl"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="plain filename"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_an_invalid_sha256(tmp_path: Path) -> None:
    """A malformed sha256 field is refused before it can pass verification."""
    document = _valid_document()
    document["packages"][0]["sha256"] = "not-a-hex-digest"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="invalid sha256"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_a_non_string_requires_python(tmp_path: Path) -> None:
    """`requires_python` must be a string when present."""
    document = _valid_document()
    document["packages"][0]["requires_python"] = 123
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="invalid requires_python"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_accepts_a_null_requires_python(tmp_path: Path) -> None:
    """A package that declared no `requires_python` constraint loads as `None`."""
    document = _valid_document()
    document["packages"][0]["requires_python"] = None
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    _, entries = pypi_corpus._load_manifest(manifest_path)
    assert entries[0].requires_python is None


def test_load_manifest_rejects_a_non_boolean_is_wheel(tmp_path: Path) -> None:
    """`is_wheel` must be a real boolean, not a truthy string."""
    document = _valid_document()
    document["packages"][0]["is_wheel"] = "true"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="invalid is_wheel"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_a_non_https_source_url(tmp_path: Path) -> None:
    """A manifest cannot claim provenance from a non-HTTPS source."""
    document = _valid_document()
    document["source_url"] = "http://example.test/ranking.json"
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, document)
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_malformed_json(tmp_path: Path) -> None:
    """A manifest that is not valid JSON fails closed with a clear error."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("not json", encoding="utf-8")
    with pytest.raises(pypi_corpus.PypiCorpusError, match="unable to load"):
        pypi_corpus._load_manifest(manifest_path)


def test_load_manifest_rejects_a_missing_file(tmp_path: Path) -> None:
    """A missing manifest path is reported as a corpus error, not an OSError."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="unable to load"):
        pypi_corpus._load_manifest(tmp_path / "missing.json")


# --- verify: hash mismatch detection --------------------------------------


def test_verify_detects_a_hash_mismatch(tmp_path: Path) -> None:
    """A tampered or corrupted artifact is caught by the offline re-hash."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered = wheelhouse / document["packages"][0]["filename"]
    tampered.write_bytes(b"corrupted contents")

    problems = pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse)
    assert len(problems) == 1
    assert "sha256 mismatch" in problems[0]


def test_verify_detects_a_missing_artifact(tmp_path: Path) -> None:
    """A deleted wheelhouse artifact is reported, not silently skipped."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    (wheelhouse / document["packages"][0]["filename"]).unlink()

    problems = pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse)
    assert len(problems) == 1
    assert "missing artifact" in problems[0]


def test_verify_passes_for_an_untampered_wheelhouse(tmp_path: Path) -> None:
    """An untouched, freshly acquired wheelhouse reports zero problems."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    assert pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse) == []


def test_verify_rejects_an_unmanifested_wheelhouse_file(tmp_path: Path) -> None:
    """A stray file the manifest never named must fail verification.

    The runner installs with `--find-links` against the whole wheelhouse
    directory, so an unverified extra file could otherwise be silently
    resolved as a dependency and executed during install.
    """
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    (wheelhouse / "unmanifested-1.0-py3-none-any.whl").write_bytes(b"not verified")

    problems = pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse)
    assert len(problems) == 1
    assert "unmanifested-1.0-py3-none-any.whl" in problems[0]


def test_verify_ignores_hidden_temp_files_in_the_wheelhouse(tmp_path: Path) -> None:
    """A dotfile left by an interrupted atomic write is not a verification failure."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    (wheelhouse / ".partial-download.tmp").write_bytes(b"leftover")

    assert pypi_corpus._verify(manifest_path=manifest_path, wheelhouse=wheelhouse) == []


# --- atomic writes -----------------------------------------------------


def test_write_atomic_text_replaces_content_and_leaves_no_temp_file(
    tmp_path: Path,
) -> None:
    """A second atomic text write fully replaces the first with no leftovers."""
    destination = tmp_path / "manifest.json"
    pypi_corpus._write_atomic_text(destination, "first")
    pypi_corpus._write_atomic_text(destination, "second")
    assert destination.read_text(encoding="utf-8") == "second"
    assert list(tmp_path.iterdir()) == [destination]


def test_write_atomic_bytes_replaces_content_and_leaves_no_temp_file(
    tmp_path: Path,
) -> None:
    """A second atomic binary write fully replaces the first with no leftovers."""
    destination = tmp_path / "artifact.whl"
    pypi_corpus._write_atomic_bytes(destination, b"first")
    pypi_corpus._write_atomic_bytes(destination, b"second")
    assert destination.read_bytes() == b"second"
    assert list(tmp_path.iterdir()) == [destination]


# --- HTTPS URL validation ------------------------------------------------


def test_https_url_rejects_a_non_https_scheme() -> None:
    """A non-HTTPS scheme such as `ftp://` is refused outright."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._https_url("ftp://example.test/file", field="url")


def test_https_url_rejects_embedded_credentials() -> None:
    """A URL carrying an embedded username or password is refused."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._https_url("https://user:pass@example.test/file", field="url")


def test_https_url_rejects_an_empty_netloc() -> None:
    """A scheme-only URL with no host is refused."""
    with pytest.raises(pypi_corpus.PypiCorpusError, match="HTTPS"):
        pypi_corpus._https_url("https:///file", field="url")


def test_https_url_accepts_a_plain_https_url() -> None:
    """A credential-free HTTPS URL passes through unchanged."""
    url = "https://example.test/file.whl"
    assert pypi_corpus._https_url(url, field="url") == url


# --- CLI ------------------------------------------------------------------


def test_main_acquire_writes_manifest_and_wheelhouse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `acquire` CLI subcommand wires the real `_http_get` hook by default."""
    ranking, responses = _fake_environment()
    monkeypatch.setattr(pypi_corpus, "_http_get", _fake_http_get(ranking, responses))
    manifest_path = tmp_path / "manifest.json"
    wheelhouse = tmp_path / "wheelhouse"

    result = pypi_corpus.main(
        [
            "acquire",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
            "--source-url",
            _RANKING_URL,
        ]
    )

    assert result == 0
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(document["packages"]) == _CORPUS_SIZE


def test_main_verify_succeeds_for_a_clean_wheelhouse(tmp_path: Path) -> None:
    """The `verify` CLI subcommand returns 0 for a matching manifest and wheelhouse."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)

    result = pypi_corpus.main(
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
        ]
    )

    assert result == 0


def test_main_verify_fails_and_reports_a_tampered_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The `verify` CLI subcommand exits 1 and prints every mismatch to stderr."""
    manifest_path, wheelhouse = _acquire_into(tmp_path)
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    (wheelhouse / document["packages"][0]["filename"]).write_bytes(b"corrupted")

    result = pypi_corpus.main(
        [
            "verify",
            "--manifest",
            str(manifest_path),
            "--wheelhouse",
            str(wheelhouse),
        ]
    )

    assert result == 1
    stderr = capsys.readouterr().err
    assert "sha256 mismatch" in stderr
    assert "failed verification" in stderr


def test_main_requires_a_command() -> None:
    """Invoking the CLI without `acquire` or `verify` fails argument parsing."""
    with pytest.raises(SystemExit):
        pypi_corpus.main([])
