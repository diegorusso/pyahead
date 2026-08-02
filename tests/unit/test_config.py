"""Tests for strict M4 project configuration and policy inference."""

from dataclasses import replace
from pathlib import Path

import pytest

from pyahead.config import (
    ConfigurationOverrides,
    infer_baseline,
    load_project_configuration,
    resolve_configuration,
    resolve_project_root,
)
from pyahead.model import (
    ConfigurationError,
    FailOn,
    MatchConfidence,
    PerFileIgnore,
    PythonRelease,
    Registry,
    ReleaseStatus,
)
from pyahead.registry import load_registry
from pyahead.versions import PythonMinor

_OVERRIDE_MAX_FILE_SIZE = 200
_CONFIG_MAX_FILE_SIZE = 512


@pytest.fixture
def planned_only_registry() -> Registry:
    """Return a registry whose release metadata has no inferable horizon."""
    return replace(
        load_registry(),
        releases=(
            PythonRelease(
                python=PythonMinor.parse("3.16"),
                status=ReleaseStatus.PLANNED,
                released_on=None,
                expected_final_on="2027-10-01",
                source="https://peps.python.org/",
            ),
        ),
    )


def _write_project(root: Path, pyahead: str = "") -> None:
    (root / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "demo"\n'
            'version = "0"\n'
            'requires-python = ">=3.11"\n'
            f"{pyahead}"
        ),
        encoding="utf-8",
    )


def test_every_cli_value_replaces_config_and_per_file_ignores_merge(
    tmp_path: Path,
) -> None:
    """Scalar/list/negative CLI values all have explicit replacement semantics."""
    (tmp_path / "configured-src").mkdir()
    (tmp_path / "override-src").mkdir()
    _write_project(
        tmp_path,
        (
            "\n[tool.pyahead]\n"
            'baseline-python = "3.11"\n'
            'horizon-python = "3.14"\n'
            'include = ["configured/**/*.py"]\n'
            'exclude = ["configured/generated/**"]\n'
            'source-roots = ["configured-src"]\n'
            "respect-gitignore = true\n"
            'minimum-confidence = "high"\n'
            'fail-on = "breaking"\n'
            "show-unscheduled = true\n"
            "max-file-size-bytes = 100\n"
            "\n[tool.pyahead.per-file-ignores]\n"
            '"tests/**" = ["CPY0001"]\n'
        ),
    )
    project = load_project_configuration(tmp_path, None)

    resolved = resolve_configuration(
        tmp_path,
        load_registry(),
        project,
        ConfigurationOverrides(
            baseline_python="3.12",
            horizon_python="3.13",
            include=("override/**/*.py",),
            exclude=("override/generated/**",),
            source_roots=("override-src",),
            respect_gitignore=False,
            minimum_confidence="medium",
            fail_on="any",
            show_unscheduled=False,
            max_file_size_bytes=_OVERRIDE_MAX_FILE_SIZE,
            per_file_ignores=(
                PerFileIgnore(
                    pattern="tests/**",
                    rule_ids=("CPY0001", "CPY9999"),
                ),
                PerFileIgnore(pattern="vendor/**", rule_ids=("CPY0001",)),
            ),
            fail_new_only=True,
            show_suppressed=True,
            allow_incomplete=True,
        ),
    )

    assert str(resolved.policy.baseline_python) == "3.12"
    assert str(resolved.policy.horizon_python) == "3.13"
    assert resolved.policy_provenance.baseline_python == "command-line"
    assert resolved.policy_provenance.horizon_python == "command-line"
    assert resolved.scan.include == ("override/**/*.py",)
    assert resolved.scan.exclude == ("override/generated/**",)
    assert resolved.scan.source_roots == ("override-src",)
    assert resolved.scan.source_roots_provenance == "command-line"
    assert resolved.source_roots_inferred is False
    assert resolved.scan.respect_gitignore is False
    assert resolved.scan.minimum_confidence is MatchConfidence.MEDIUM
    assert resolved.scan.fail_on is FailOn.ANY
    assert resolved.scan.show_unscheduled is False
    assert resolved.scan.max_file_size_bytes == _OVERRIDE_MAX_FILE_SIZE
    assert resolved.scan.per_file_ignores == (
        PerFileIgnore(
            pattern="tests/**",
            rule_ids=("CPY0001", "CPY9999"),
        ),
        PerFileIgnore(pattern="vendor/**", rule_ids=("CPY0001",)),
    )
    assert resolved.scan.fail_new_only is True
    assert resolved.scan.show_suppressed is True
    assert resolved.scan.allow_incomplete is True


def test_config_values_apply_when_cli_values_are_absent(tmp_path: Path) -> None:
    """The complete strict table is useful without command-line duplication."""
    (tmp_path / "src").mkdir()
    _write_project(
        tmp_path,
        (
            "\n[tool.pyahead]\n"
            'baseline-python = "3.11"\n'
            'horizon-python = "3.13"\n'
            'include = ["src/**/*.py"]\n'
            'exclude = ["src/generated/**"]\n'
            'source-roots = ["src"]\n'
            "respect-gitignore = false\n"
            'minimum-confidence = "medium"\n'
            'fail-on = "deprecated"\n'
            "show-unscheduled = false\n"
            "max-file-size-bytes = 512\n"
        ),
    )

    resolved = resolve_configuration(
        tmp_path,
        load_registry(),
        load_project_configuration(tmp_path, None),
        ConfigurationOverrides(),
    )

    assert resolved.scan.include == ("src/**/*.py",)
    assert resolved.scan.exclude == ("src/generated/**",)
    assert resolved.scan.source_roots == ("src",)
    assert resolved.scan.source_roots_provenance.endswith("tool.pyahead.source-roots")
    assert resolved.source_roots_inferred is False
    assert resolved.scan.respect_gitignore is False
    assert resolved.scan.minimum_confidence is MatchConfidence.MEDIUM
    assert resolved.scan.fail_on is FailOn.DEPRECATED
    assert resolved.scan.show_unscheduled is False
    assert resolved.scan.max_file_size_bytes == _CONFIG_MAX_FILE_SIZE
    assert resolved.policy_provenance.baseline_python.endswith(
        "tool.pyahead.baseline-python"
    )


def test_requires_python_and_default_horizon_are_inferred_with_provenance(
    tmp_path: Path,
) -> None:
    """Patch-specific lower bounds retain their declaration and minor baseline."""
    (tmp_path / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "demo"\n'
            'version = "0"\n'
            'requires-python = ">=3.11.2, !=3.12.*"\n'
        ),
        encoding="utf-8",
    )

    resolved = resolve_configuration(
        tmp_path,
        load_registry(),
        load_project_configuration(tmp_path, None),
        ConfigurationOverrides(),
    )

    assert str(resolved.policy.baseline_python) == "3.11"
    assert str(resolved.policy.horizon_python) == "3.15"
    assert (
        resolved.policy_provenance.baseline_python
        == "pyproject.toml:project.requires-python"
    )
    assert resolved.policy_provenance.horizon_python == "registry:newest-active-release"
    assert resolved.policy_provenance.requires_python == ">=3.11.2, !=3.12.*"
    assert resolved.scan.source_roots == (".", "src")
    assert (
        resolved.scan.source_roots_provenance
        == "inferred:conventional-root-and-src-layout"
    )
    assert resolved.source_roots_inferred is True


def test_default_horizon_rejects_only_planned_release_metadata(
    tmp_path: Path,
    planned_only_registry: Registry,
) -> None:
    """Planned releases are never selected automatically as the policy horizon."""
    _write_project(tmp_path)

    with pytest.raises(
        ConfigurationError,
        match="no stable or prerelease release metadata",
    ):
        resolve_configuration(
            tmp_path,
            planned_only_registry,
            load_project_configuration(tmp_path, None),
            ConfigurationOverrides(),
        )


@pytest.mark.parametrize("declaration", [">=4", "not a specifier"])
def test_invalid_or_unsupported_requires_python_fails(
    declaration: str,
) -> None:
    """Inference never guesses when the declaration cannot select the window."""
    supported = tuple(PythonMinor.parse(value) for value in ("3.11", "3.12", "3.13"))

    with pytest.raises(ConfigurationError):
        infer_baseline(declaration, supported)


def test_inference_considers_unlisted_minors_inside_registry_window() -> None:
    """Release/event endpoints define a contiguous supported minor window."""
    project_versions = tuple(
        PythonMinor(major=3, minor=minor) for minor in range(11, 16)
    )

    assert infer_baseline("==3.12.*", project_versions) == PythonMinor.parse("3.12")
    resolved = infer_baseline("!=3.11.*", project_versions)
    assert resolved == PythonMinor.parse("3.12")


def test_missing_authoritative_baseline_fails(tmp_path: Path) -> None:
    """Advisory metadata is not silently adopted in non-interactive scans."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0"\n',
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="baseline Python is required"):
        resolve_configuration(
            tmp_path,
            load_registry(),
            load_project_configuration(tmp_path, None),
            ConfigurationOverrides(),
        )


@pytest.mark.parametrize(
    ("baseline", "horizon"),
    [("3.10", "3.13"), ("3.11", "3.16")],
)
def test_explicit_policy_must_stay_in_registry_window(
    tmp_path: Path,
    baseline: str,
    horizon: str,
) -> None:
    """Explicit precedence never implies unsupported registry coverage."""
    _write_project(tmp_path)

    with pytest.raises(ConfigurationError, match=r"3\.11 through 3\.15"):
        resolve_configuration(
            tmp_path,
            load_registry(),
            load_project_configuration(tmp_path, None),
            ConfigurationOverrides(
                baseline_python=baseline,
                horizon_python=horizon,
            ),
        )


@pytest.mark.parametrize(
    "table",
    [
        "[tool.pyahead]\nunknown-option = true\n",
        '[tool]\npyahead = "invalid"\n',
        '[tool.pyahead]\ninclude = "src/**"\n',
        '[tool.pyahead]\nrespect-gitignore = "yes"\n',
        '[tool.pyahead]\nminimum-confidence = "low"\n',
        '[tool.pyahead]\nfail-on = "severe"\n',
        "[tool.pyahead]\nmax-file-size-bytes = 0\n",
        '[tool.pyahead]\nsource-roots = ["../outside"]\n',
        ('[tool.pyahead.per-file-ignores]\n"tests/**" = "CPY0001"\n'),
    ],
)
def test_strict_config_rejects_unknown_keys_and_wrong_types(
    tmp_path: Path,
    table: str,
) -> None:
    """Every supported key is type checked and misspellings are fatal."""
    (tmp_path / "pyproject.toml").write_text(table, encoding="utf-8")

    with pytest.raises(ConfigurationError):
        load_project_configuration(tmp_path, None)


def test_custom_config_must_stay_in_root_and_be_valid_toml(
    tmp_path: Path,
) -> None:
    """Configuration cannot escape the selected project or partially parse."""
    outside = tmp_path.parent / "outside-pyahead.toml"
    outside.write_text("[tool.pyahead]\n", encoding="utf-8")
    invalid = tmp_path / "invalid.toml"
    invalid.write_text("[tool.pyahead\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="beneath"):
        load_project_configuration(tmp_path, outside)
    with pytest.raises(ConfigurationError, match="valid TOML"):
        load_project_configuration(tmp_path, invalid)


def test_source_roots_are_authoritative_existing_directories(
    tmp_path: Path,
) -> None:
    """A configured source root cannot be missing, a file, or an escape."""
    _write_project(tmp_path)
    project = load_project_configuration(tmp_path, None)

    with pytest.raises(ConfigurationError, match="source root"):
        resolve_configuration(
            tmp_path,
            load_registry(),
            project,
            ConfigurationOverrides(source_roots=("missing",)),
        )
    source_file = tmp_path / "source.py"
    source_file.write_text("", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="directory"):
        resolve_configuration(
            tmp_path,
            load_registry(),
            project,
            ConfigurationOverrides(source_roots=("source.py",)),
        )


def test_explicit_empty_source_roots_remain_authoritative(tmp_path: Path) -> None:
    """An empty configured list never falls back to conventional inference."""
    _write_project(
        tmp_path,
        "\n[tool.pyahead]\nsource-roots = []\n",
    )

    resolved = resolve_configuration(
        tmp_path,
        load_registry(),
        load_project_configuration(tmp_path, None),
        ConfigurationOverrides(),
    )

    assert resolved.scan.source_roots == ()
    assert resolved.scan.source_roots_provenance.endswith("tool.pyahead.source-roots")
    assert resolved.source_roots_inferred is False


def test_project_root_precedence_prefers_pyproject_then_real_git_control(
    tmp_path: Path,
) -> None:
    """Nearest project metadata wins; an empty lookalike .git is ignored."""
    git_root = tmp_path / "git-root"
    project = git_root / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)
    (git_root / ".git").mkdir()
    (git_root / ".git/HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    _write_project(project)

    assert resolve_project_root(nested) == project
    assert resolve_project_root(nested, git_root) == git_root

    (project / "pyproject.toml").unlink()
    assert resolve_project_root(nested) == git_root


def test_explicit_root_must_exist_and_be_a_directory(tmp_path: Path) -> None:
    """Root errors remain concise configuration failures."""
    source = tmp_path / "source.py"
    source.write_text("", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        resolve_project_root(tmp_path, tmp_path / "missing")
    with pytest.raises(ConfigurationError):
        resolve_project_root(tmp_path, source)
