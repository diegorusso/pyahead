"""Real pytest-plugin execution tests for M7 and M8.5b warning evidence."""

# ruff: noqa: SLF001 -- bounded-state assertions intentionally exercise internals.

import contextlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import xdist.plugin as xdist_plugin

import pyahead.pytest_plugin as plugin_module
from pyahead.evidence import parse_evidence_document, render_evidence_document

pytest_plugins = ("pytester",)

CURRENT_COMMIT = "a" * 40
_SUBPROCESS_TIMEOUT_SECONDS = 20.0
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Terminate a test subprocess and every child it may have started."""
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if system_root is None:
            process.kill()
            process.wait(timeout=5)
            pytest.fail("SystemRoot is required for process-tree cleanup on Windows")
        taskkill = Path(system_root) / "System32" / "taskkill.exe"
        if not taskkill.is_file():
            process.kill()
            process.wait(timeout=5)
            pytest.fail(f"process-tree cleanup executable is missing: {taskkill}")
        subprocess.run(  # noqa: S603 -- fixed native tree-termination executable.
            [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _run_pytest_process_tree_safe(
    pytester: pytest.Pytester,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    """Run real pytest with bounded, cross-platform process-tree cleanup."""
    command = [
        sys.executable,
        "-m",
        "pytest",
        f"--basetemp={pytester.path / 'runpytest-tree'}",
        *arguments,
    ]
    environment = os.environ.copy()
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    if os.name == "nt":
        process = subprocess.Popen(  # noqa: S603 -- fixed interpreter/test args.
            command,
            cwd=pytester.path,
            creationflags=_WINDOWS_CREATE_NEW_PROCESS_GROUP,
            encoding="utf-8",
            env=environment,
            errors="replace",
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
    else:
        process = subprocess.Popen(  # noqa: S603 -- fixed interpreter/test args.
            command,
            cwd=pytester.path,
            encoding="utf-8",
            env=environment,
            errors="replace",
            start_new_session=True,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )
    try:
        stdout, stderr = process.communicate(timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        stdout, stderr = process.communicate()
        pytest.fail(
            "pytest subprocess exceeded "
            f"{_SUBPROCESS_TIMEOUT_SECONDS:g}s\nstdout:\n{stdout}\nstderr:\n{stderr}",
            pytrace=False,
        )
    finally:
        if process.poll() is None:
            _terminate_process_tree(process)
    assert process.returncode is not None
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _seed_complete_artifact(path: Path) -> None:
    document: dict[str, object] = {
        "environment": {
            "implementation": "cpython",
            "platform": "linux",
            "python_version": "3.11.9",
        },
        "provider": {"name": "pytest-warnings", "version": "0.1.0a2"},
        "run": {
            "exit_code": 0,
            "framework": "pytest",
            "framework_version": pytest.__version__,
            "tests_collected": 1,
            "warnings_complete": True,
            "warnings_dropped": 0,
        },
        "schema_version": 1,
        "source": {"commit": CURRENT_COMMIT},
        "warnings": [],
    }
    path.write_text(render_evidence_document(document), encoding="utf-8")


def _read_artifact(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(path.read_text(encoding="utf-8")))


def test_explicit_pytest_plugin_collects_only_deprecation_warnings(
    pytester: pytest.Pytester,
) -> None:
    """User pytest execution writes normalized evidence, including on failure."""
    pytester.makepyfile(
        test_warnings="""
        import warnings

        def test_warning_collection():
            warnings.warn("deprecated API", DeprecationWarning, stacklevel=1)
            warnings.warn("pending API", PendingDeprecationWarning, stacklevel=1)
            warnings.warn("ordinary warning", UserWarning, stacklevel=1)
            assert False
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "default::DeprecationWarning",
        "-W",
        "default::PendingDeprecationWarning",
    )

    result.assert_outcomes(failed=1)
    document = _read_artifact(artifact)
    run = cast("dict[str, object]", document["run"])
    captured = cast("list[dict[str, object]]", document["warnings"])
    assert document["schema_version"] == 1
    assert document["source"] == {"commit": CURRENT_COMMIT}
    assert run["framework"] == "pytest"
    assert run["tests_collected"] == 1
    assert run["exit_code"] == 1
    assert run["warnings_complete"] is True
    assert run["warnings_dropped"] == 0
    assert [warning["kind"] for warning in captured] == [
        "deprecation-warning",
        "pending-deprecation-warning",
    ]
    assert all(
        cast("dict[str, object]", warning["location"])["path"]
        == Path("test_warnings.py").as_posix()
        for warning in captured
    )
    assert "ordinary warning" not in artifact.read_text(encoding="utf-8")


def test_pytest_plugin_finalizes_after_session_warning_and_status_hooks(
    pytester: pytest.Pytester,
) -> None:
    """Session-finish warnings and final process status reach the artifact."""
    pytester.makepyfile("def test_ok():\n    assert True\n")
    pytester.makeconftest(
        """
        import warnings
        import pytest

        @pytest.hookimpl(tryfirst=True)
        def pytest_sessionfinish(session):
            warnings.warn("session-final deprecation", DeprecationWarning)
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "default::DeprecationWarning",
    )

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    document = _read_artifact(artifact)
    run = cast("dict[str, object]", document["run"])
    captured = cast("list[dict[str, object]]", document["warnings"])
    assert run["exit_code"] == int(result.ret)
    assert any(
        warning["message"] == "session-final deprecation"
        and cast("dict[str, object]", warning["location"])["path"] == "conftest.py"
        for warning in captured
    )


def test_disabled_warning_capture_fails_and_tombstones(
    pytester: pytest.Pytester,
) -> None:
    """A real warning cannot be represented when built-in capture is disabled."""
    pytester.makeconftest(
        """
        import warnings

        warnings.simplefilter("always", DeprecationWarning)
        warnings.warn("configuration deprecation", DeprecationWarning)
        """
    )
    pytester.makepyfile(
        test_warning="""
        import warnings

        def test_warning():
            warnings.warn("must not be claimed", DeprecationWarning)
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "pyahead.pytest_plugin",
        "-p",
        "no:warnings",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert "requires pytest's warnings capture plugin" in result.stderr
    assert "configuration deprecation" in result.stderr
    assert artifact.read_bytes() == b""
    assert list(pytester.path.glob(f".{artifact.name}.*.tmp")) == []


def test_same_name_plugin_cannot_impersonate_warning_capture(
    pytester: pytest.Pytester,
) -> None:
    """A foreign plugin registered as warnings is not built-in capture."""
    pytester.makepyfile(
        warning_impostor="""
        class Impostor:
            pass

        def pytest_addoption(pluginmanager):
            builtin = pluginmanager.get_plugin("warnings")
            assert builtin is not None
            pluginmanager.unregister(builtin)
            pluginmanager.register(Impostor(), "warnings")
        """,
        test_ok="def test_ok():\n    assert True\n",
    )
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "warning_impostor",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert "requires pytest's warnings capture plugin" in result.stderr
    assert artifact.read_bytes() == b""


def test_disable_warnings_preserves_complete_capture(
    pytester: pytest.Pytester,
) -> None:
    """Terminal-summary suppression does not disable warning observation."""
    pytester.makepyfile(
        test_warning="""
        import warnings

        def test_warning():
            warnings.warn("captured deprecation", DeprecationWarning)
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "--disable-warnings",
        "-W",
        "default::DeprecationWarning",
    )

    result.assert_outcomes(passed=1)
    document = _read_artifact(artifact)
    run = cast("dict[str, object]", document["run"])
    captured = cast("list[dict[str, object]]", document["warnings"])
    assert run["warnings_complete"] is True
    assert [warning["message"] for warning in captured] == ["captured deprecation"]
    assert "warnings summary" not in result.stdout.str()


def test_user_warning_filters_remain_policy(pytester: pytest.Pytester) -> None:
    """Evidence observes pytest's filtered stream without overriding policy."""
    pytester.makepyfile(
        test_warning="""
        import warnings

        def test_warning():
            warnings.warn("ignored deprecation", DeprecationWarning)
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "ignore::DeprecationWarning",
    )

    result.assert_outcomes(passed=1)
    document = _read_artifact(artifact)
    run = cast("dict[str, object]", document["run"])
    assert document["warnings"] == []
    assert run["warnings_complete"] is True
    assert run["warnings_dropped"] == 0


@pytest.mark.parametrize(
    "limits_and_expected",
    [
        (1, plugin_module._MAX_COLLECTED_WARNING_TEXT_BYTES, 1, 1),
        (plugin_module._MAX_COLLECTED_WARNING_RECORDS, 0, 0, 2),
    ],
)
def test_real_collection_reports_record_and_byte_truncation(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
    limits_and_expected: tuple[int, int, int, int],
) -> None:
    """Configured collector bounds fail closed in a real pytest session."""
    record_limit, text_byte_limit, retained, dropped = limits_and_expected
    monkeypatch.setattr(plugin_module, "_MAX_COLLECTED_WARNING_RECORDS", record_limit)
    monkeypatch.setattr(
        plugin_module,
        "_MAX_COLLECTED_WARNING_TEXT_BYTES",
        text_byte_limit,
    )
    pytester.makepyfile(
        test_warnings="""
        import warnings

        def test_warnings():
            warnings.warn("first deprecation", DeprecationWarning)
            warnings.warn("second deprecation", DeprecationWarning)
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "-W",
        "default::DeprecationWarning",
    )

    result.assert_outcomes(passed=1)
    parsed = parse_evidence_document(_read_artifact(artifact))
    assert len(parsed.warnings) == retained
    assert parsed.warnings_complete is False
    assert parsed.warnings_dropped == dropped


@pytest.mark.parametrize(
    "xdist_arguments",
    [("-n", "2"), ("--tx", "popen", "--dist", "load")],
)
def test_active_xdist_execution_is_refused(
    pytester: pytest.Pytester,
    xdist_arguments: tuple[str, ...],
) -> None:
    """A warning-bearing xdist run cannot create partial evidence."""
    pytester.makepyfile(
        test_warning="""
        import warnings

        def test_warning():
            warnings.warn("distributed deprecation", DeprecationWarning)
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "xdist.plugin",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        *xdist_arguments,
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert "does not support pytest-xdist execution" in result.stderr
    assert artifact.read_bytes() == b""


@pytest.mark.parametrize("looponfail_option", ["-f", "--looponfail"])
def test_xdist_looponfail_is_refused_before_tests(
    pytester: pytest.Pytester,
    looponfail_option: str,
) -> None:
    """Loop-on-fail cannot replace the parent with an unaggregated session."""
    pytester.makepyfile(
        test_warning="""
        from pathlib import Path

        def test_warning():
            Path("test-executed").write_text("yes", encoding="utf-8")
            assert False
        """
    )
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "xdist.looponfail",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        looponfail_option,
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert "does not support pytest-xdist execution" in result.stderr
    assert artifact.read_bytes() == b""
    assert not (pytester.path / "test-executed").exists()


@pytest.mark.parametrize(
    "xdist_arguments",
    [("-n", "0"), ("-n", "2", "--collect-only")],
)
def test_inactive_xdist_configuration_preserves_evidence(
    pytester: pytest.Pytester,
    xdist_arguments: tuple[str, ...],
) -> None:
    """Zero workers and collection-only mode do not execute distributed tests."""
    pytester.makepyfile("def test_ok():\n    assert True\n")
    artifact = pytester.path / "pyahead-warnings.json"

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "xdist.plugin",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        *xdist_arguments,
    )

    assert result.returncode == pytest.ExitCode.OK
    parsed = parse_evidence_document(_read_artifact(artifact))
    assert parsed.warnings_complete is True


def test_same_name_xdist_impostors_do_not_trigger_refusal(
    pytester: pytest.Pytester,
) -> None:
    """Names and xdist-shaped options are not provider identity proof."""
    pytester.makepyfile(
        xdist_impostors="""
        class Impostor:
            pass

        def pytest_addoption(parser, pluginmanager):
            parser.addoption("--fake-tx", action="append", dest="tx", default=[])
            parser.addoption("--fake-dist", dest="dist", default="no")
            parser.addoption("--fake-loop", action="store_true", dest="looponfail")
            pluginmanager.register(Impostor(), "xdist")
            pluginmanager.register(Impostor(), "xdist.looponfail")
        """,
        test_ok="def test_ok():\n    assert True\n",
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "xdist_impostors",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
        "--fake-tx=popen",
        "--fake-dist=load",
        "--fake-loop",
    )

    assert result.returncode == pytest.ExitCode.OK
    assert parse_evidence_document(_read_artifact(artifact)).warnings_complete is True


def test_foreign_workerinput_does_not_trigger_refusal(
    pytester: pytest.Pytester,
) -> None:
    """A foreign worker-like Config attribute is not an xdist worker."""
    pytester.makepyfile(
        foreign_worker="""
        def pytest_addoption(pluginmanager):
            config = pluginmanager.get_plugin("pytestconfig")
            config.workerinput = {"workerid": "gw0", "workercount": 1}
        """,
        test_ok="def test_ok():\n    assert True\n",
    )
    artifact = pytester.path / "pyahead-warnings.json"

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "foreign_worker",
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.returncode == pytest.ExitCode.OK
    assert parse_evidence_document(_read_artifact(artifact)).warnings_complete is True


def test_real_xdist_worker_mapping_is_detected() -> None:
    """A documented worker mapping plus exact provider identifies a worker."""
    manager = SimpleNamespace(get_plugins=lambda: frozenset({xdist_plugin}))
    config = cast(
        "pytest.Config",
        SimpleNamespace(
            option=SimpleNamespace(
                collectonly=False,
                dist="no",
                looponfail=False,
                numprocesses=None,
                tx=(),
            ),
            pluginmanager=manager,
            workerinput={"workerid": "gw0", "workercount": 2},
        ),
    )

    assert plugin_module._xdist_execution_active(config) is True


def test_stable_warning_plugin_removal_fails_closed(
    pytester: pytest.Pytester,
) -> None:
    """Capture removed after configure cannot produce a complete artifact."""
    pytester.makeconftest(
        """
        def pytest_sessionstart(session):
            manager = session.config.pluginmanager
            builtin = manager.get_plugin("warnings")
            assert builtin is not None
            manager.unregister(builtin)
        """
    )
    pytester.makepyfile("def test_ok():\n    assert True\n")
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = _run_pytest_process_tree_safe(
        pytester,
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert "requires pytest's warnings capture plugin" in result.stderr
    assert artifact.read_bytes() == b""


def test_evidence_output_must_remain_beneath_pytest_root(
    pytester: pytest.Pytester,
) -> None:
    """The plugin rejects a lexical output escape without creating a file."""
    pytester.makepyfile("def test_ok():\n    assert True\n")
    outside = pytester.path.parent / f"{pytester.path.name}-outside.json"

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        "--pyahead-evidence=../" + outside.name,
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(
        ["*--pyahead-evidence must remain beneath the pytest root*"]
    )
    assert not outside.exists()


def test_evidence_output_atomically_replaces_existing_file(
    pytester: pytest.Pytester,
) -> None:
    """A successful session replaces, rather than appends to, its artifact."""
    pytester.makepyfile("def test_ok():\n    assert True\n")
    artifact = pytester.path / "pyahead-warnings.json"
    _seed_complete_artifact(artifact)

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-evidence={artifact.name}",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    result.assert_outcomes(passed=1)
    document = _read_artifact(artifact)
    run = cast("dict[str, object]", document["run"])
    assert run["exit_code"] == 0
    assert run["warnings_complete"] is True
    assert list(pytester.path.glob(f".{artifact.name}.*.tmp")) == []


def test_pytest_plugin_requires_output_when_commit_is_explicit(
    pytester: pytest.Pytester,
) -> None:
    """A commit option alone is a configuration error rather than a no-op."""
    pytester.makepyfile("def test_ok():\n    assert True\n")

    result = pytester.runpytest_inprocess(
        "-p",
        "pyahead.pytest_plugin",
        f"--pyahead-source-commit={CURRENT_COMMIT}",
    )

    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(
        ["*--pyahead-source-commit requires --pyahead-evidence*"]
    )
