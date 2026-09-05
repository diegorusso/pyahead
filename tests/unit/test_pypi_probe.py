"""Hermetic unit tests for the stdlib-only interpreter probe payload."""

# ruff: noqa: SLF001

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

if sys.platform != "linux":  # pragma: no cover - CI platform guard
    pytest.skip(
        "the PyPI validation harness targets Linux: its isolation depends on "
        "bwrap, and RLIMIT_AS is not dependably enforceable elsewhere",
        allow_module_level=True,
    )

from scripts import pypi_probe

_SCRIPT = Path(pypi_probe.__file__).resolve()


def _write(tmp_path: Path, name: str, source: str) -> None:
    (tmp_path / name).write_text(source, encoding="utf-8")


def _run_batch(
    tmp_path: Path,
    probes: list[dict[str, Any]],
    *,
    wall_clock_seconds: float = 10.0,
    max_processes: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Run the real payload as a subprocess and index its results by id."""
    batch = json.dumps({"schema_version": 1, "probes": probes}).encode()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(tmp_path)
    argv = [
        sys.executable,
        str(_SCRIPT),
        "--wall-clock-seconds",
        str(wall_clock_seconds),
    ]
    if max_processes is not None:
        argv.extend(["--max-processes", str(max_processes)])
    completed = subprocess.run(  # noqa: S603 - fixed argv, test-controlled input.
        argv,
        input=batch,
        capture_output=True,
        env=environment,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    document = json.loads(completed.stdout)
    assert document["schema_version"] == 1
    return {result["id"]: result for result in document["results"]}


def _subject(owner_module: str, attribute_path: list[str]) -> dict[str, Any]:
    return {"owner_module": owner_module, "attribute_path": attribute_path}


# --- subject probe -----------------------------------------------------


def test_subject_probe_reports_present_with_a_signature(tmp_path: Path) -> None:
    """A live, introspectable subject reports present with its signature."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "os.path",
                "attribute_path": ["join"],
            }
        ],
    )
    assert results["s"]["status"] == "present"
    assert results["s"]["signature"] is not None
    assert results["s"]["error"] is None


def test_subject_probe_reports_absent_for_a_missing_attribute(tmp_path: Path) -> None:
    """A subject whose owner module exists but lacks the attribute is absent."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "os",
                "attribute_path": ["definitely_missing_attr_xyz"],
            }
        ],
    )
    assert results["s"]["status"] == "absent"
    assert results["s"]["signature"] is None


def test_subject_probe_reports_absent_for_a_missing_owner_module(
    tmp_path: Path,
) -> None:
    """A subject whose owner module no longer exists is absent, not an error."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "definitely_missing_module_xyz",
                "attribute_path": [],
            }
        ],
    )
    assert results["s"]["status"] == "absent"


def test_subject_probe_reports_absent_for_a_missing_parent_of_a_nested_owner(
    tmp_path: Path,
) -> None:
    """A nested owner module is absent when its whole parent package is gone.

    Importing `missing_parent.child` fails on the *parent* first, so
    `ModuleNotFoundError.name` is `"missing_parent"`, not the full dotted
    owner module - that must still count as the owner (and therefore `S`)
    being gone, not as an unrelated transitive-import failure.
    """
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "definitely_missing_parent_xyz.child",
                "attribute_path": [],
            }
        ],
    )
    assert results["s"]["status"] == "absent"


def test_subject_probe_reports_import_error_for_a_missing_transitive_import(
    tmp_path: Path,
) -> None:
    """A `ModuleNotFoundError` naming a *different* module is not the subject's absence.

    The owner module genuinely exists here; it just fails to import because
    something *it* imports is missing. Reporting that as `absent` would
    tell C1/C2 the subject itself is gone, when its own presence was never
    actually disproven.
    """
    _write(
        tmp_path,
        "owner_with_missing_dep.py",
        "import definitely_missing_transitive_dep_xyz\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "owner_with_missing_dep",
                "attribute_path": [],
            }
        ],
    )
    assert results["s"]["status"] == "import-error"


def test_subject_probe_captures_a_deprecation_warning(tmp_path: Path) -> None:
    """A `DeprecationWarning` raised on module-`__getattr__` access is captured."""
    _write(
        tmp_path,
        "dep_mod.py",
        "import warnings\n"
        "\n"
        "def __getattr__(name):\n"
        "    if name == 'old_api':\n"
        "        warnings.warn('old_api is deprecated', DeprecationWarning)\n"
        "        return object()\n"
        "    raise AttributeError(name)\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "dep_mod",
                "attribute_path": ["old_api"],
            }
        ],
    )
    assert results["s"]["status"] == "present"
    assert "deprecated" in results["s"]["deprecation_warning"]


def test_subject_probe_reports_import_error_for_a_broken_owner_module(
    tmp_path: Path,
) -> None:
    """A module that raises something other than `ModuleNotFoundError` is an error."""
    _write(tmp_path, "broken_module.py", "raise RuntimeError('boom')\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "broken_module",
                "attribute_path": [],
            }
        ],
    )
    assert results["s"]["status"] == "import-error"
    assert "boom" in results["s"]["error"]


# --- binding probe (C1) -------------------------------------------------


def test_binding_probe_confirms_an_identity_match(tmp_path: Path) -> None:
    """A genuine `import os` binds `os.path.join` to the real subject."""
    _write(tmp_path, "binder_ok.py", "import os\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "binder_ok",
                "enclosing_scope": None,
                "head": "os",
                "attribute_path": ["path", "join"],
                "subject": _subject("os.path", ["join"]),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "resolved"
    assert result["identity_match"] is True
    assert result["subject_status"] == "present"


def test_binding_probe_refutes_a_vendored_shadow(tmp_path: Path) -> None:
    """A same-named local shadow never binds to the real stdlib subject."""
    _write(
        tmp_path,
        "binder_shadow.py",
        "class os:\n"
        "    class path:\n"
        "        @staticmethod\n"
        "        def join(*parts):\n"
        "            return 'shadow'\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "binder_shadow",
                "enclosing_scope": None,
                "head": "os",
                "attribute_path": ["path", "join"],
                "subject": _subject("os.path", ["join"]),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "resolved"
    assert result["identity_match"] is False


def test_binding_probe_reports_not_visible_for_a_function_local_import(
    tmp_path: Path,
) -> None:
    """A name imported only inside a function body never reaches module globals."""
    _write(
        tmp_path,
        "local_import.py",
        "def use():\n    import os\n    return os.path.join('a', 'b')\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "local_import",
                "enclosing_scope": None,
                "head": "os",
                "attribute_path": [],
                "subject": _subject("os", []),
            }
        ],
    )
    assert results["b"]["status"] == "binding-not-visible"
    assert results["b"]["identity_match"] is None


def test_binding_probe_refutes_when_the_subject_is_confirmed_absent(
    tmp_path: Path,
) -> None:
    """A live, resolved binding cannot be a subject confirmed not to exist here.

    This is what lets the version-gated-fallback cross-check work: at the
    interpreter where `S` was removed, a fallback branch that binds `head`
    to something else must refute cleanly rather than come back
    inconclusive, or the cross-check could never catch it.
    """
    _write(tmp_path, "binder_present.py", "import sys\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "binder_present",
                "enclosing_scope": None,
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", ["definitely_missing_attr_xyz"]),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "resolved"
    assert result["identity_match"] is False
    assert result["subject_status"] == "absent"


def test_binding_probe_reports_an_unresolvable_subject_as_unresolved_identity(
    tmp_path: Path,
) -> None:
    """A binding that resolves fine cannot be compared against a subject that errored.

    Unlike a subject confirmed absent, an `import-error` while resolving
    the subject means its existence here is unknown, not disproven - so
    identity truly cannot be determined.
    """
    _write(tmp_path, "binder_present.py", "import sys\n")
    _write(tmp_path, "broken_owner.py", "raise RuntimeError('boom')\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "binder_present",
                "enclosing_scope": None,
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("broken_owner", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "resolved"
    assert result["identity_match"] is None
    assert result["subject_status"] == "import-error"


def test_binding_probe_reports_import_error_for_a_broken_module(
    tmp_path: Path,
) -> None:
    """A scanned module that fails to import is reported, not silently skipped."""
    _write(tmp_path, "broken_module.py", "raise RuntimeError('boom')\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "broken_module",
                "enclosing_scope": None,
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "import-error"
    assert result["identity_match"] is None
    assert "boom" in result["error"]


def test_binding_probe_falls_back_to_an_enclosing_scopes_globals(
    tmp_path: Path,
) -> None:
    """A name visible only via the enclosing scope's `__globals__` still resolves."""
    _write(
        tmp_path,
        "scoped_binder.py",
        "import os\n\n\nclass Widget:\n    def method(self):\n        return os.path\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "scoped_binder",
                "enclosing_scope": ["Widget", "method"],
                "head": "os",
                "attribute_path": ["path", "join"],
                "subject": _subject("os.path", ["join"]),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "resolved"
    assert result["identity_match"] is True


def test_binding_probe_reports_not_visible_when_a_local_import_shadows_a_global(
    tmp_path: Path,
) -> None:
    """A function-local import wins over a same-named module global.

    By Python's own scoping rules, `import sys` inside `use()` makes `sys`
    local to the whole function body, shadowing the unrelated module-level
    `sys` for every reference inside it - including the one on the finding's
    line. Comparing the module global here would compare the wrong object
    entirely; the probe must recognize the shadow instead of guessing.
    """
    _write(
        tmp_path,
        "shadowed_global.py",
        "sys = 'not the real sys module'\n\n\n"
        "def use():\n"
        "    import sys\n"
        "    return sys.path\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "shadowed_global",
                "enclosing_scope": ["use"],
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "binding-not-visible"
    assert result["identity_match"] is None


def test_binding_probe_reports_not_visible_for_a_nested_function_local_shadow(
    tmp_path: Path,
) -> None:
    """A local import inside a function nested in another function still shadows.

    `inner` is never an attribute of `outer` - Python only creates that
    function object once `outer` actually runs - so resolving this
    enclosing scope must fall back to walking `outer`'s own code object for
    a same-named nested code object instead of reporting no local names at
    all and misreading the module-level `sys` as the finding's real binding.
    """
    _write(
        tmp_path,
        "nested_shadow.py",
        "sys = 'not the real sys module'\n\n\n"
        "def outer():\n"
        "    def inner():\n"
        "        import sys\n"
        "        return sys.path\n"
        "    return inner\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "nested_shadow",
                "enclosing_scope": ["outer", "inner"],
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "binding-not-visible"
    assert result["identity_match"] is None


def test_binding_probe_reports_not_visible_for_a_closure_captured_shadow(
    tmp_path: Path,
) -> None:
    """A local import captured by a nested closure still shadows the module global.

    `sys` is imported in `outer`, not `inner`, but `inner` closes over it -
    the compiler promotes it out of `outer`'s `co_varnames` into
    `co_cellvars` (and into `inner`'s own `co_freevars`), so a scope walk
    that only looks at `co_varnames` would miss it entirely and misread the
    module-level `sys` as the finding's real binding.
    """
    _write(
        tmp_path,
        "closure_shadow.py",
        "sys = 'not the real sys module'\n\n\n"
        "def outer():\n"
        "    import sys\n"
        "    def inner():\n"
        "        return sys.path\n"
        "    return inner\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "closure_shadow",
                "enclosing_scope": ["outer", "inner"],
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "binding-not-visible"
    assert result["identity_match"] is None


def test_binding_probe_declines_to_adjudicate_an_ambiguous_nested_name(
    tmp_path: Path,
) -> None:
    """Two same-named nested functions cannot be told apart and must not be guessed.

    Both conditional branches define a `def inner(): ...`, so `outer`'s code
    object holds two separate nested code objects named "inner" - the
    finding's `enclosing_scope` is only the dotted name path `outer.inner`,
    with no line number to say which one it means. Only the second `inner`
    actually shadows `sys` locally; picking the first at random would
    misreport `sys` as the module global instead of declining to adjudicate.
    """
    _write(
        tmp_path,
        "ambiguous_nested.py",
        "import sys as sys\n\n\n"
        "def outer(flag):\n"
        "    if flag:\n"
        "        def inner():\n"
        "            return 1\n"
        "        return inner\n"
        "    def inner():\n"
        "        import sys\n"
        "        return sys.path\n"
        "    return inner\n",
    )
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "b",
                "kind": "binding",
                "module": "ambiguous_nested",
                "enclosing_scope": ["outer", "inner"],
                "head": "sys",
                "attribute_path": [],
                "subject": _subject("sys", []),
            }
        ],
    )
    result = results["b"]
    assert result["status"] == "binding-not-visible"
    assert result["identity_match"] is None


# --- call-shape probe ----------------------------------------------------


def test_call_shape_probe_accepts_a_matching_shape(tmp_path: Path) -> None:
    """A call shape that binds against the real signature is accepted."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "c",
                "kind": "call-shape",
                "subject": _subject("os.path", ["join"]),
                "positional_count": 2,
                "keyword_names": [],
            }
        ],
    )
    assert results["c"]["status"] == "accepted"


def test_call_shape_probe_rejects_an_unsupported_keyword(tmp_path: Path) -> None:
    """A keyword the subject's signature does not accept is rejected."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "c",
                "kind": "call-shape",
                "subject": _subject("os.path", ["join"]),
                "positional_count": 0,
                "keyword_names": ["definitely_bogus_kwarg_xyz"],
            }
        ],
    )
    assert results["c"]["status"] == "rejected"


def test_call_shape_probe_reports_no_signature_for_an_uninspectable_builtin(
    tmp_path: Path,
) -> None:
    """A builtin `inspect.signature` cannot introspect is reported distinctly."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "c",
                "kind": "call-shape",
                "subject": _subject("builtins", ["iter"]),
                "positional_count": 1,
                "keyword_names": [],
            }
        ],
    )
    assert results["c"]["status"] == "no-signature"


def test_call_shape_probe_reports_absent_for_a_missing_subject(
    tmp_path: Path,
) -> None:
    """A call-shape probe against a removed subject cannot bind at all."""
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "c",
                "kind": "call-shape",
                "subject": _subject("definitely_missing_module_xyz2", []),
                "positional_count": 0,
                "keyword_names": [],
            }
        ],
    )
    assert results["c"]["status"] == "absent"


# --- isolation: timeouts and crashing packages ---------------------------


def test_a_hanging_import_is_reported_as_a_probe_timeout(tmp_path: Path) -> None:
    """A package that never returns is killed and reported, not left hanging."""
    _write(tmp_path, "slow_module.py", "import time\ntime.sleep(5)\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "slow_module",
                "attribute_path": [],
            }
        ],
        wall_clock_seconds=1.0,
    )
    assert results["m"]["status"] == "probe-timeout"


def test_a_descendant_that_outlives_its_parent_does_not_hang_the_batch(
    tmp_path: Path,
) -> None:
    """A grandchild inheriting the probe's stdout pipe cannot hold the batch hostage.

    The immediate probe child exits well within its own wall-clock budget,
    but a descendant it spawned along the way keeps that pipe's write end
    open for much longer. Without killing the whole process group (not just
    the immediate child), the reader thread here blocks on that pipe until
    the descendant exits on its own - several seconds after the probe's own
    budget, and well past what this test allows.
    """
    _write(
        tmp_path,
        "orphaning_module.py",
        "import subprocess\nimport sys\n\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\n",
    )
    started = time.monotonic()
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "orphaning_module",
                "attribute_path": [],
            }
        ],
        wall_clock_seconds=1.5,
        # RLIMIT_NPROC is a per-user, not per-tree, ceiling: the default
        # test budget is tuned for a probe that never forks, and is too
        # tight to spawn this test's own descendant on a host that already
        # has other processes running under the same user.
        max_processes=512,
    )
    elapsed = time.monotonic() - started
    grandchild_sleep_seconds = 5.0
    assert results["m"]["status"] == "probe-timeout"
    # Well under the grandchild's own sleep: proof this returned by killing
    # the group, not by waiting the grandchild out.
    assert elapsed < grandchild_sleep_seconds - 0.2


def test_a_descendant_outliving_a_fast_exit_still_times_out(tmp_path: Path) -> None:
    """A descendant that survives its fast-exiting parent cannot smuggle a stale result.

    The immediate probe process resolves its subject and exits almost
    instantly, well inside its own wall-clock budget - `process.wait` never
    raises `TimeoutExpired`, so `_kill_group` is never invoked from there. A
    descendant it spawned along the way still holds the inherited stdout
    pipe open for several seconds past that budget: draining it as two
    independent, sequential grace windows (rather than one shared deadline)
    could let both reader threads finish "successfully" well past the
    declared budget, handing back a result that is really several seconds
    stale as if it were on time.
    """
    _write(
        tmp_path,
        "orphaning_module.py",
        "import subprocess\nimport sys\n\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'])\n",
    )
    started = time.monotonic()
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "orphaning_module",
                "attribute_path": [],
            }
        ],
        wall_clock_seconds=0.2,
        max_processes=512,
    )
    elapsed = time.monotonic() - started
    descendant_sleep_seconds = 3.0
    assert results["m"]["status"] == "probe-timeout"
    assert elapsed < descendant_sleep_seconds - 0.5


def test_a_short_descendant_hold_past_budget_still_times_out(tmp_path: Path) -> None:
    """A pipe held only briefly past budget must still miss its declared deadline.

    The post-kill join grace exists to let cleanup finish *after* a
    timeout has already been detected and the group killed - it must not
    become a blanket extension of the declared wall-clock budget for a
    process that exits on time. A descendant that holds the inherited
    stdout pipe for less than the grace window, but well past the probe's
    own tiny budget, must still be reported as a timeout rather than read
    back as a normal, on-time result carrying a stale value.
    """
    _write(
        tmp_path,
        "orphaning_module.py",
        "import subprocess\nimport sys\n\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(1)'])\n",
    )
    started = time.monotonic()
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "orphaning_module",
                "attribute_path": [],
            }
        ],
        wall_clock_seconds=0.2,
        max_processes=512,
    )
    elapsed = time.monotonic() - started
    assert results["m"]["status"] == "probe-timeout"
    assert elapsed < 1.0


def test_an_os_exit_escape_is_contained_to_its_own_child(tmp_path: Path) -> None:
    """`os._exit` inside the scanned package only kills its isolated child."""
    _write(tmp_path, "exit_module.py", "import os\nos._exit(7)\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "exit_module",
                "attribute_path": [],
            }
        ],
    )
    assert results["m"]["status"] == "probe-crashed"


def test_a_sys_exit_escape_is_contained_to_its_own_child(tmp_path: Path) -> None:
    """`sys.exit` inside the scanned package only kills its isolated child."""
    _write(tmp_path, "sysexit_module.py", "import sys\nsys.exit(3)\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "m",
                "kind": "subject",
                "owner_module": "sysexit_module",
                "attribute_path": [],
            }
        ],
    )
    assert results["m"]["status"] == "probe-crashed"


def test_a_batch_of_two_survives_one_crashing_probe(tmp_path: Path) -> None:
    """One crashing probe never prevents the rest of the batch from completing."""
    _write(tmp_path, "exit_module.py", "import os\nos._exit(7)\n")
    results = _run_batch(
        tmp_path,
        [
            {
                "id": "crash",
                "kind": "subject",
                "owner_module": "exit_module",
                "attribute_path": [],
            },
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "os.path",
                "attribute_path": ["join"],
            },
        ],
    )
    assert results["crash"]["status"] == "probe-crashed"
    assert results["s"]["status"] == "present"


def test_single_probe_mode_rejects_a_malformed_request() -> None:
    """`--single-probe` fails closed on a request that is not valid JSON."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, test-controlled input.
        [sys.executable, str(_SCRIPT), "--single-probe"],
        input=b"not json",
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 1
    assert completed.stdout == b""


# --- request schema validation (in-process, no subprocess needed) --------


def test_parse_batch_rejects_invalid_json() -> None:
    """A batch payload that is not valid JSON fails closed."""
    with pytest.raises(pypi_probe.PypiProbeError, match="not valid JSON"):
        pypi_probe._parse_batch(b"not json")


def test_parse_batch_rejects_the_wrong_schema_version() -> None:
    """Only schema version 1 probe batches are trusted."""
    payload = json.dumps({"schema_version": 2, "probes": []}).encode()
    with pytest.raises(pypi_probe.PypiProbeError, match="schema version 1"):
        pypi_probe._parse_batch(payload)


def test_parse_batch_rejects_an_empty_probes_array() -> None:
    """A batch must carry at least one probe."""
    payload = json.dumps({"schema_version": 1, "probes": []}).encode()
    with pytest.raises(pypi_probe.PypiProbeError, match="non-empty probes"):
        pypi_probe._parse_batch(payload)


def test_parse_batch_rejects_duplicate_probe_ids() -> None:
    """Two probes cannot share the same correlation id."""
    probe = {
        "id": "dup",
        "kind": "subject",
        "owner_module": "os",
        "attribute_path": [],
    }
    payload = json.dumps({"schema_version": 1, "probes": [probe, probe]}).encode()
    with pytest.raises(pypi_probe.PypiProbeError, match="duplicate probe id"):
        pypi_probe._parse_batch(payload)


def test_parse_probe_rejects_an_unknown_kind() -> None:
    """A probe with a kind outside the closed set is refused."""
    with pytest.raises(pypi_probe.PypiProbeError, match="unknown kind"):
        pypi_probe._parse_probe({"id": "x", "kind": "unsupported"})


def test_parse_probe_rejects_a_non_object() -> None:
    """A probe entry that is not a JSON object is refused."""
    with pytest.raises(pypi_probe.PypiProbeError, match="must be an object"):
        pypi_probe._parse_probe("not-an-object")


def test_parse_probe_rejects_an_empty_id() -> None:
    """An empty probe id is refused rather than silently correlated as ''."""
    with pytest.raises(pypi_probe.PypiProbeError, match="non-empty string"):
        pypi_probe._parse_probe({"id": "", "kind": "subject"})


def test_parse_subject_probe_rejects_unexpected_fields() -> None:
    """A subject probe with an extra or missing field is refused."""
    with pytest.raises(pypi_probe.PypiProbeError, match="unexpected fields"):
        pypi_probe._parse_probe(
            {
                "id": "s",
                "kind": "subject",
                "owner_module": "os",
                "attribute_path": [],
                "extra": True,
            }
        )


def test_parse_call_shape_probe_rejects_a_negative_positional_count() -> None:
    """A negative `positional_count` can never describe a real call."""
    with pytest.raises(pypi_probe.PypiProbeError, match="invalid positional_count"):
        pypi_probe._parse_probe(
            {
                "id": "c",
                "kind": "call-shape",
                "subject": {"owner_module": "os", "attribute_path": []},
                "positional_count": -1,
                "keyword_names": [],
            }
        )


def test_parse_call_shape_probe_rejects_a_boolean_positional_count() -> None:
    """A boolean is an `int` subtype in Python but never a valid argument count."""
    with pytest.raises(pypi_probe.PypiProbeError, match="invalid positional_count"):
        pypi_probe._parse_probe(
            {
                "id": "c",
                "kind": "call-shape",
                "subject": {"owner_module": "os", "attribute_path": []},
                "positional_count": True,
                "keyword_names": [],
            }
        )


def test_subject_descriptor_rejects_a_wrong_shape() -> None:
    """A subject descriptor must contain exactly the two documented fields."""
    with pytest.raises(
        pypi_probe.PypiProbeError, match="owner_module and attribute_path"
    ):
        pypi_probe._subject_descriptor({"owner_module": "os"}, field="subject")


def test_string_list_rejects_a_non_list() -> None:
    """A field documented as a string list refuses a bare string."""
    with pytest.raises(pypi_probe.PypiProbeError, match="list of strings"):
        pypi_probe._string_list("not-a-list", field="attribute_path")


# --- orchestrator failure mapping (a fake child, real subprocess) --------

# `_run_isolated` drains its child's pipes through real, live file objects on
# background threads, so a `subprocess.run`-shaped mock cannot stand in for
# it credibly. Each scenario below instead swaps `_child_argv` for a small
# real `python -c ...` child that misbehaves in the one specific way under
# test, keeping the real `Popen`/thread/pipe machinery on the hook.


def _probe() -> dict[str, Any]:
    return {
        "id": "p",
        "kind": "subject",
        "owner_module": "does.not.matter",
        "attribute_path": [],
    }


def _limits(*, wall_clock_seconds: float = 5.0) -> pypi_probe.ResourceLimits:
    return pypi_probe.ResourceLimits(
        wall_clock_seconds=wall_clock_seconds,
        cpu_seconds=5,
        address_space_bytes=1024 * 1024 * 1024,
        max_processes=16,
        max_file_size_bytes=1024 * 1024,
    )


def _fake_child(monkeypatch: pytest.MonkeyPatch, code: str) -> None:
    monkeypatch.setattr(
        pypi_probe, "_child_argv", lambda _limits: [sys.executable, "-c", code]
    )


def test_run_isolated_reports_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A child that outlives its wall-clock budget is reported as a timeout."""
    _fake_child(monkeypatch, "import time\ntime.sleep(30)\n")
    result = pypi_probe._run_isolated(_probe(), limits=_limits(wall_clock_seconds=0.3))
    assert result["status"] == "probe-timeout"


def test_run_isolated_accounts_a_blocked_stdin_write_against_the_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Time spent blocked delivering the payload still counts against the budget.

    The child here does not read stdin at all for longer than the declared
    budget, so the parent's stdin write blocks on the full pipe for that
    whole stretch. The deadline must already be exhausted by the time that
    write unblocks - not reset to a fresh full budget for whatever happens
    next - or a child could win back its entire wall-clock allowance just by
    making the parent wait to deliver its own input.
    """
    _fake_child(
        monkeypatch,
        "import sys, time\n"
        "time.sleep(1.0)\n"
        "sys.stdin.buffer.read()\n"
        'print(\'{"id": "p", "kind": "subject", "status": "present", '
        '"deprecation_warning": null, "signature": null, "error": null}\')\n',
    )
    probe = {
        "id": "p",
        "kind": "subject",
        "owner_module": "x" * 300_000,
        "attribute_path": [],
    }
    result = pypi_probe._run_isolated(probe, limits=_limits(wall_clock_seconds=0.2))
    assert result["status"] == "probe-timeout"


def test_run_isolated_reports_a_nonzero_exit_as_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nonzero child exit code surfaces its stderr tail as the crash reason."""
    _fake_child(
        monkeypatch,
        "import sys\nsys.stderr.write('traceback tail')\nsys.exit(1)\n",
    )
    result = pypi_probe._run_isolated(_probe(), limits=_limits())
    assert result["status"] == "probe-crashed"
    assert "traceback tail" in result["error"]


def test_run_isolated_reports_oversized_output_as_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that floods stdout past the cap is killed, not buffered in full.

    The cap must be enforced while reading, not only after a `communicate()`
    call has already buffered everything: this child would never terminate
    on its own, so a post-hoc size check would never even run.
    """
    _fake_child(
        monkeypatch,
        "import sys\n"
        "chunk = b'x' * 65536\n"
        "while True:\n"
        "    sys.stdout.buffer.write(chunk)\n"
        "    sys.stdout.buffer.flush()\n",
    )
    result = pypi_probe._run_isolated(_probe(), limits=_limits())
    assert result["status"] == "probe-crashed"
    assert "output limit" in result["error"]


def test_run_isolated_reports_invalid_json_as_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that prints non-JSON to stdout is treated as crashed."""
    _fake_child(monkeypatch, "print('not json')\n")
    result = pypi_probe._run_isolated(_probe(), limits=_limits())
    assert result["status"] == "probe-crashed"


def test_run_isolated_reports_a_mismatched_result_as_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child result that answers a different probe id is never trusted."""
    payload = json.dumps({"id": "other", "kind": "subject", "status": "present"})
    _fake_child(monkeypatch, f"print({payload!r})\n")
    result = pypi_probe._run_isolated(_probe(), limits=_limits())
    assert result["status"] == "probe-crashed"


def test_run_isolated_reports_an_impossible_binding_result_as_crashed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged binding result with an impossible field combination is never trusted.

    `_run_binding_probe` can never pair `identity_match=True` with a
    non-null `error`, or an out-of-vocabulary `subject_status` - only code
    executing inside the very process under test (the target package's own
    top-level code) could produce that, so it must be rejected the same way
    as a truncated or mismatched record, not accepted with those fields
    silently trusted.
    """
    probe = {
        "id": "p",
        "kind": "binding",
        "module": "does.not.matter",
        "enclosing_scope": None,
        "head": "does_not_matter",
        "attribute_path": [],
        "subject": {"owner_module": "does.not.matter", "attribute_path": []},
    }
    payload = json.dumps(
        {
            "id": "p",
            "kind": "binding",
            "status": "resolved",
            "identity_match": True,
            "subject_status": "forged",
            "error": "AttributeError: nope",
        }
    )
    _fake_child(monkeypatch, f"print({payload!r})\n")
    result = pypi_probe._run_isolated(probe, limits=_limits())
    assert result["status"] == "probe-crashed"


# --- CLI --------------------------------------------------------------


def _stdin_with(payload: bytes) -> object:
    return types.SimpleNamespace(buffer=io.BytesIO(payload))


def test_main_batch_mode_rejects_malformed_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The batch-mode CLI path fails closed and reports why on stderr."""
    monkeypatch.setattr(sys, "stdin", _stdin_with(b"not json"))
    result = pypi_probe.main([])
    assert result == 1
    assert "not valid JSON" in capsys.readouterr().err
