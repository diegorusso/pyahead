"""Stdlib-only interpreter probe payload for the PyPI validation harness.

This module runs *inside* the interpreter and virtual environment used to
scan one PyPI package, so it must never import ``pyahead`` and must remain
parseable under CPython 3.11 regardless of which interpreter actually
executes it. It reads one JSON probe batch on stdin and writes one JSON
result batch on stdout; every individual probe is executed in a fresh child
process of this same interpreter so that a crashing, hanging, or
``sys.exit``-calling target package can never abort the batch.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import os
import signal
import subprocess
import sys
import threading
import time
import types
import warnings
from dataclasses import dataclass
from pathlib import Path
from types import CodeType, ModuleType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import IO

_resource: ModuleType | None
try:
    import resource as _resource
except ImportError:  # pragma: no cover - POSIX-only guard; this harness targets Linux.
    _resource = None

_SCHEMA_VERSION = 1
_SINGLE_PROBE_FLAG = "--single-probe"
_MAX_CHILD_OUTPUT_BYTES = 4 * 1024 * 1024
_STDERR_TAIL_BYTES = 4000
_POST_KILL_JOIN_GRACE_SECONDS = 2.0

_DEFAULT_WALL_CLOCK_SECONDS = 20.0
_DEFAULT_CPU_SECONDS = 10
_DEFAULT_ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024
_DEFAULT_MAX_PROCESSES = 16
_DEFAULT_MAX_FILE_SIZE_BYTES = 64 * 1024 * 1024

_PROBE_KINDS = frozenset({"subject", "binding", "call-shape"})

# Mirrors `_PROBE_RESULT_STATUSES_BY_KIND` in pypi_validate.py; duplicated
# rather than imported since this module must stay stdlib-only and never
# import pyahead (or anything that transitively does).
_KNOWN_PROBE_FAILURE_STATUSES = frozenset({"probe-timeout", "probe-crashed"})
_RESULT_STATUSES_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset({"present", "absent", "import-error"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "binding": frozenset({"resolved", "import-error", "binding-not-visible"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "call-shape": frozenset(
        {"accepted", "rejected", "absent", "no-signature", "import-error"}
    )
    | _KNOWN_PROBE_FAILURE_STATUSES,
}

# Every field a real (non-failure-status) result of this kind always carries,
# regardless of its specific status - `_run_subject_probe`/`_run_binding_probe`/
# `_run_call_shape_probe` all return this exact key set unconditionally. A
# failure-status result (`probe-timeout`/`probe-crashed`) instead always has
# exactly `{id, kind, status, error}`, from `_failure_result`. Enforcing an
# *exact* key set - not just that `status` is in the closed vocabulary - is
# what makes this a closed schema: a truncated or padded-with-extra-keys
# result from the isolated child (forged or merely buggy) is rejected rather
# than silently accepted with missing or spurious fields.
_RESULT_FIELDS_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset(
        {"id", "kind", "status", "deprecation_warning", "signature", "error"}
    ),
    "binding": frozenset(
        {"id", "kind", "status", "identity_match", "subject_status", "error"}
    ),
    "call-shape": frozenset({"id", "kind", "status", "error"}),
}
_FAILURE_RESULT_FIELDS = frozenset({"id", "kind", "status", "error"})

_UNSET: Any = object()
_SENTINEL: Any = object()


class PypiProbeError(RuntimeError):
    """Raised when a probe batch or single-probe request is malformed."""


@dataclass(frozen=True)
class ResourceLimits:
    """Per-probe wall-clock and OS resource ceilings."""

    wall_clock_seconds: float
    cpu_seconds: int
    address_space_bytes: int
    max_processes: int
    max_file_size_bytes: int


@dataclass(frozen=True)
class SubjectResolution:
    """The outcome of resolving one subject descriptor to a live object."""

    status: str
    value: Any
    error: str | None
    deprecation_warning: str | None


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"


def _string_list(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        message = f"{field} must be a list of strings"
        raise PypiProbeError(message)
    return tuple(value)


def _nonempty_str(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        message = f"{field} must be a non-empty string"
        raise PypiProbeError(message)
    return value


def _subject_descriptor(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"owner_module", "attribute_path"}:
        message = f"{field} must contain exactly owner_module and attribute_path"
        raise PypiProbeError(message)
    return {
        "owner_module": _nonempty_str(
            value["owner_module"], field=f"{field}.owner_module"
        ),
        "attribute_path": _string_list(
            value["attribute_path"], field=f"{field}.attribute_path"
        ),
    }


def _parse_subject_probe(item: dict[str, Any], *, probe_id: str) -> dict[str, Any]:
    if set(item) != {"id", "kind", "owner_module", "attribute_path"}:
        message = f"subject probe {probe_id} has unexpected fields"
        raise PypiProbeError(message)
    return {
        "id": probe_id,
        "kind": "subject",
        "owner_module": _nonempty_str(item["owner_module"], field="owner_module"),
        "attribute_path": _string_list(item["attribute_path"], field="attribute_path"),
    }


def _parse_binding_probe(item: dict[str, Any], *, probe_id: str) -> dict[str, Any]:
    allowed = {
        "id",
        "kind",
        "module",
        "enclosing_scope",
        "head",
        "attribute_path",
        "subject",
    }
    if set(item) != allowed:
        message = f"binding probe {probe_id} has unexpected fields"
        raise PypiProbeError(message)
    enclosing_scope = item["enclosing_scope"]
    if enclosing_scope is not None:
        enclosing_scope = _string_list(enclosing_scope, field="enclosing_scope")
    return {
        "id": probe_id,
        "kind": "binding",
        "module": _nonempty_str(item["module"], field="module"),
        "enclosing_scope": enclosing_scope,
        "head": _nonempty_str(item["head"], field="head"),
        "attribute_path": _string_list(item["attribute_path"], field="attribute_path"),
        "subject": _subject_descriptor(item["subject"], field="subject"),
    }


def _parse_call_shape_probe(item: dict[str, Any], *, probe_id: str) -> dict[str, Any]:
    if set(item) != {"id", "kind", "subject", "positional_count", "keyword_names"}:
        message = f"call-shape probe {probe_id} has unexpected fields"
        raise PypiProbeError(message)
    positional_count = item["positional_count"]
    if (
        not isinstance(positional_count, int)
        or isinstance(positional_count, bool)
        or positional_count < 0
    ):
        message = f"call-shape probe {probe_id} has an invalid positional_count"
        raise PypiProbeError(message)
    return {
        "id": probe_id,
        "kind": "call-shape",
        "subject": _subject_descriptor(item["subject"], field="subject"),
        "positional_count": positional_count,
        "keyword_names": _string_list(item["keyword_names"], field="keyword_names"),
    }


_PARSERS = {
    "subject": _parse_subject_probe,
    "binding": _parse_binding_probe,
    "call-shape": _parse_call_shape_probe,
}


def _parse_probe(item: object) -> dict[str, Any]:
    if not isinstance(item, dict):
        message = "probe must be an object"
        raise PypiProbeError(message)
    probe_id = item.get("id")
    if not isinstance(probe_id, str) or not probe_id:
        message = "probe id must be a non-empty string"
        raise PypiProbeError(message)
    kind = item.get("kind")
    if kind not in _PROBE_KINDS:
        message = f"probe {probe_id} has unknown kind {kind!r}"
        raise PypiProbeError(message)
    return _PARSERS[kind](item, probe_id=probe_id)


def _parse_batch(payload: bytes) -> tuple[dict[str, Any], ...]:
    try:
        document: Any = json.loads(payload)
    except json.JSONDecodeError as error:
        message = "probe batch is not valid JSON"
        raise PypiProbeError(message) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != _SCHEMA_VERSION
    ):
        message = "probe batch must use schema version 1"
        raise PypiProbeError(message)
    probes = document.get("probes")
    if not isinstance(probes, list) or not probes:
        message = "probe batch must contain a non-empty probes array"
        raise PypiProbeError(message)
    parsed: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in probes:
        probe = _parse_probe(item)
        if probe["id"] in seen_ids:
            message = f"probe batch has duplicate probe id {probe['id']!r}"
            raise PypiProbeError(message)
        seen_ids.add(probe["id"])
        parsed.append(probe)
    return tuple(parsed)


def _deprecation_text(caught: list[warnings.WarningMessage]) -> str | None:
    messages = [
        str(warning.message)
        for warning in caught
        if issubclass(warning.category, (DeprecationWarning, PendingDeprecationWarning))
    ]
    return "; ".join(messages) if messages else None


def _resolve_subject(descriptor: dict[str, Any]) -> SubjectResolution:
    """Import a subject's owner module and walk its attribute path to `S`."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        owner_module = descriptor["owner_module"]
        try:
            value: Any = importlib.import_module(owner_module)
        except ModuleNotFoundError as error:
            # `error.name` is whichever module import actually failed, not
            # necessarily `owner_module` itself: importing a present module
            # can transitively fail on a different missing module further
            # down its own import chain. A failure naming `owner_module`
            # exactly, or naming one of its dotted-path parents (importing
            # `pkg.sub.mod` first imports `pkg`, then `pkg.sub`, so a missing
            # parent surfaces as `error.name == "pkg"` even though the whole
            # `pkg.sub.mod` chain - including the requested owner - is
            # equally gone), is real evidence that `S` is gone. Anything else
            # leaves its presence unknown, not disproven.
            if error.name is not None and (
                owner_module == error.name or owner_module.startswith(f"{error.name}.")
            ):
                return SubjectResolution("absent", None, None, None)
            return SubjectResolution("import-error", None, _error_text(error), None)
        except Exception as error:  # noqa: BLE001 - reported as a structured status.
            return SubjectResolution("import-error", None, _error_text(error), None)
        qualified = owner_module
        for attribute in descriptor["attribute_path"]:
            qualified = f"{qualified}.{attribute}"
            try:
                value = getattr(value, attribute)
            except AttributeError:
                submodule = _import_submodule(value, qualified)
                if submodule.status != "present":
                    return SubjectResolution(
                        submodule.status,
                        None,
                        submodule.error,
                        _deprecation_text(caught),
                    )
                value = submodule.value
        return SubjectResolution("present", value, None, _deprecation_text(caught))


def _import_submodule(
    parent: Any,  # noqa: ANN401 - the walked owner's current value, of unknown type.
    qualified: str,
) -> SubjectResolution:
    """Resolve `from A import B` the way Python does when `B` is a submodule.

    A package only carries a submodule as an attribute once that submodule has
    been imported, so a bare-interpreter `getattr(lib2to3, "refactor")`
    fails even though `from lib2to3 import refactor` succeeds: the `from`
    form falls back to importing `A.B` itself (`importlib._bootstrap
    ._handle_fromlist`). Mirror exactly that fallback, and only when the
    parent is a module: a missing attribute on a class or instance is
    genuinely absent. A `ModuleNotFoundError` naming the submodule is real
    evidence it does not exist; any other failure leaves it unknown.
    """
    if not isinstance(parent, ModuleType):
        return SubjectResolution("absent", None, None, None)
    try:
        submodule = importlib.import_module(qualified)
    except ModuleNotFoundError as error:
        if error.name == qualified:
            return SubjectResolution("absent", None, None, None)
        return SubjectResolution("import-error", None, _error_text(error), None)
    except Exception as error:  # noqa: BLE001 - reported as a structured status.
        return SubjectResolution("import-error", None, _error_text(error), None)
    return SubjectResolution("present", submodule, None, None)


def _signature_text(value: Any) -> str | None:  # noqa: ANN401 - any resolved subject.
    try:
        return str(inspect.signature(value))
    except (TypeError, ValueError):
        return None


def _run_subject_probe(probe: dict[str, Any]) -> dict[str, Any]:
    resolution = _resolve_subject(probe)
    signature = (
        _signature_text(resolution.value) if resolution.status == "present" else None
    )
    return {
        "id": probe["id"],
        "kind": "subject",
        "status": resolution.status,
        "deprecation_warning": resolution.deprecation_warning,
        "signature": signature,
        "error": resolution.error,
    }


class _AmbiguousScopeError(Exception):
    """Two or more nested code objects in the same scope share a name."""


def _nested_code(code: CodeType | None, *, name: str) -> CodeType | None:
    """Find a same-named nested code object among `code`'s own constants.

    A nested `def` is never an attribute of its enclosing function - Python
    only creates the live function object when that statement executes -
    so once `getattr` stops resolving, this is the only way to keep
    descending without calling anything.

    Two conditional `def inner(): ...` blocks at the same nesting level
    compile to two separate same-named code objects among the constants,
    and the finding's `enclosing_scope` is only a dotted name path with no
    line number to tell them apart. Picking either one risks reading the
    wrong branch's locals, so an ambiguous match raises rather than
    guessing.
    """
    if code is None:
        return None
    matches = [
        const
        for const in code.co_consts
        if isinstance(const, CodeType) and const.co_name == name
    ]
    if len(matches) > 1:
        raise _AmbiguousScopeError
    return matches[0] if matches else None


def _resolve_scope(
    module: object, enclosing_scope: tuple[str, ...] | None
) -> tuple[dict[str, Any] | None, frozenset[str]] | None:
    """Return the enclosing scope's `__globals__` and every name it binds locally.

    Returns `None`, rather than a tuple, when a nested name is ambiguous
    (see `_nested_code`): the caller must then decline to adjudicate instead
    of resolving against a scope that might not be the right one.

    `__globals__` is always the *defining module's* global namespace, never
    a snapshot of the callable's stack frame, so it can never see a name the
    callable only binds locally (a function-local import, a local
    reassignment) - even when that local binding is exactly what the finding
    is about. `co_varnames` lists every name a code object binds locally,
    computed at compile time with no need to call anything, which is what
    lets `_run_binding_probe` recognize a locally shadowed name instead of
    misreading a same-named module global as the finding's real binding.

    `enclosing_scope` may walk through a level with no live attribute at all
    - a function nested inside another function, reachable only via
    `co_consts` (see `_nested_code`), not `getattr`. Every level's
    `co_varnames` is accumulated, not just the innermost's: a name bound
    locally anywhere between the module and the finding's site shadows a
    same-named module global by Python's own scoping rules, whether it was
    bound in the innermost function or one enclosing it. `co_cellvars` and
    `co_freevars` are accumulated too: a name an inner function closes over
    is promoted out of its defining scope's `co_varnames` into that scope's
    `co_cellvars` (and into the closing-over scope's own `co_freevars`), so
    `co_varnames` alone misses exactly the locally-bound names a closure
    actually captures - the same shadowing rule applies to them. `__globals__`
    is only refreshed while `getattr` still resolves live objects, since a
    nested function's globals are always its enclosing function's regardless
    of whether that enclosing function is itself reachable by attribute.
    """
    if not enclosing_scope:
        return None, frozenset()
    target: Any = module
    scope_globals: dict[str, Any] | None = None
    code: CodeType | None = None
    local_names: set[str] = set()
    try:
        for attribute in enclosing_scope:
            target, code, level_globals = _descend_scope(target, code, attribute)
            if level_globals is not None:
                scope_globals = level_globals
            if target is None and code is None:
                return None, frozenset()
            if code is not None:
                local_names.update(code.co_varnames)
                local_names.update(code.co_cellvars)
                local_names.update(code.co_freevars)
    except _AmbiguousScopeError:
        return None
    return scope_globals, frozenset(local_names)


def _descend_scope(
    target: Any,  # noqa: ANN401 - the walked scope's current value, of unknown type.
    code: CodeType | None,
    attribute: str,
) -> tuple[Any, CodeType | None, dict[str, Any] | None]:
    """Take one step of an `enclosing_scope` walk; raises `_AmbiguousScopeError`.

    Returns the new `target` (`None` once no live attribute resolves), the
    code object to keep walking `co_consts` from, and this level's
    `__globals__` when `target` is still a live, reachable object.
    """
    if target is None:
        return None, _nested_code(code, name=attribute), None
    try:
        target = getattr(target, attribute)
    except AttributeError:
        return None, _nested_code(code, name=attribute), None
    scope_globals = getattr(target, "__globals__", None)
    return (
        target,
        getattr(target, "__code__", None),
        scope_globals if isinstance(scope_globals, dict) else None,
    )


def _binding_not_visible(probe: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": probe["id"],
        "kind": "binding",
        "status": "binding-not-visible",
        "identity_match": None,
        "subject_status": None,
        "error": None,
    }


def _find_base(
    head: str, *, module_globals: dict[str, Any], scope_globals: dict[str, Any] | None
) -> Any:  # noqa: ANN401 - the resolved head's value, of unknown type.
    candidates = [module_globals]
    if scope_globals is not None and scope_globals is not module_globals:
        candidates.append(scope_globals)
    for candidate in candidates:
        if head in candidate:
            return candidate[head]
    return _UNSET


def _same_object(
    resolved: Any,  # noqa: ANN401 - the site's resolved value, of unknown type.
    subject: Any,  # noqa: ANN401 - the independently resolved subject.
) -> bool:
    """Identity, extended to bound methods that are re-created on every access.

    `datetime.datetime.utcnow is datetime.datetime.utcnow` is `False` under
    CPython: a classmethod (or any method bound to a class) yields a fresh
    bound-method object per attribute access, so plain `is` refutes every
    genuine reference to such a subject. Two bound methods denote the same
    binding exactly when they are bound to the same object and wrap the same
    underlying function - which is what `__eq__` on both the Python and the
    builtin bound-method types compares. Everything else keeps strict `is`.
    """
    if resolved is subject:
        return True
    if isinstance(resolved, types.MethodType) and isinstance(subject, types.MethodType):
        return (
            resolved.__self__ is subject.__self__
            and resolved.__func__ is subject.__func__
        )
    if isinstance(resolved, types.BuiltinMethodType) and isinstance(
        subject, types.BuiltinMethodType
    ):
        # `builtin_function_or_method.__eq__` already compares `__self__` by
        # identity and the underlying C method.
        return resolved == subject
    return False


def _walk_failed_at_subject_slot(
    attribute_path: list[str],
    *,
    subject_descriptor: dict[str, Any],
    reached: Any,  # noqa: ANN401 - the last object the walk resolved before failing.
    failed_at: int | None,
    subject: SubjectResolution,
) -> bool:
    """Whether the failed attribute walk stopped at exactly `S`'s own slot.

    At an interpreter where `S` has already been removed, a genuine
    `unittest.makeSuite` reference walks the real `unittest` module and
    fails on `makeSuite` - the very attribute `S` itself is missing. That
    is not a binding to a *different* object (the refutation the
    cross-check exists for); it is the site naming `S`'s slot while `S` is
    absent, which C1 cannot compare and must report as inconclusive. The
    walk must have failed on its final step, on the same attribute name as
    `S`'s own final attribute, from the identical parent object `S` hangs
    off - anything else (a shadowing class missing the attribute, an
    earlier step failing) stays a refutation.
    """
    subject_path = subject_descriptor["attribute_path"]
    if (
        subject.status != "absent"
        or not subject_path
        or failed_at != len(attribute_path) - 1
        or attribute_path[-1] != subject_path[-1]
    ):
        return False
    parent = _resolve_subject(
        {
            "owner_module": subject_descriptor["owner_module"],
            "attribute_path": list(subject_path[:-1]),
        }
    )
    return parent.status == "present" and reached is parent.value


def _walk_candidates(
    probe: dict[str, Any],
    *,
    module_globals: dict[str, Any],
    scope_globals: dict[str, Any] | None,
    local_names: frozenset[str],
    subject: SubjectResolution,
) -> tuple[Any, str | None, bool] | None:
    """Walk the recorded name from the head the site actually bound.

    The finding records the *canonical* dotted name (`datetime.datetime.utcnow`),
    not the site's spelling: after `from datetime import datetime` the module
    global `datetime` is the class, and walking `.datetime.utcnow` from it
    fails on the first step even though `datetime.utcnow()` at the site is
    exactly `S`. Which prefix the site bound to a name is not recoverable
    from static evidence (an alias hides it entirely), so every prefix that
    keeps the recorded spelling is tried in order - `head` with the full
    path, then each `attribute_path[k]` with the rest.

    The recorded head is the only candidate whose outcome can refute: a
    later prefix is a guess at the site's spelling, and a module global that
    merely shares a later component's name (`import datetime as dt` beside a
    wrapper `def utcnow()`, `import typing as t` beside a project `class
    Text`) is no evidence the site bound anything else. So a later prefix
    decides only when its walk completes on `S` itself (`_same_object`) or
    stops on `S`'s own slot (inconclusive); a later prefix the enclosing
    callable binds locally is skipped like a shadowed head. A later prefix
    whose walk ends anywhere else - on some *other* live object, or on an
    `AttributeError` away from `S`'s slot - ends the guessing: it is as
    plausible a spelling as every prefix after it, so a prefix after it
    that reaches `S` (a saved `utcnow = datetime.utcnow` beside a `datetime`
    global rebound to a replacement class, whether or not the replacement
    has an `utcnow`) would confirm through a binding the site may never
    have used. Otherwise the recorded head's own outcome stands: a
    refutation if it was visible, not-visible if it was not.

    Returns `(resolved, walk_error, slot_consistent)`, or `None` when no
    candidate decided and the recorded head was not visible.
    """
    attribute_path = list(probe["attribute_path"])
    candidates = [(probe["head"], attribute_path)] + [
        (attribute_path[k], attribute_path[k + 1 :]) for k in range(len(attribute_path))
    ]
    head_outcome: tuple[Any, str | None, bool] | None = None
    for index, (head, path) in enumerate(candidates):
        is_recorded_head = index == 0
        if not is_recorded_head and head in local_names:
            continue
        base = _find_base(
            head, module_globals=module_globals, scope_globals=scope_globals
        )
        if base is _UNSET:
            continue
        resolved: Any = base
        walk_error: str | None = None
        failed_at: int | None = None
        for step, attribute in enumerate(path):
            try:
                resolved = getattr(resolved, attribute)
            except AttributeError as error:
                walk_error = _error_text(error)
                failed_at = step
                break
        if walk_error is None:
            if is_recorded_head or (
                subject.status == "present" and _same_object(resolved, subject.value)
            ):
                return resolved, None, False
            # This prefix reached a live object that is not `S`, and the site
            # may have spelled exactly this prefix: no prefix after it can
            # confirm, so the recorded head's own outcome stands.
            break
        if _walk_failed_at_subject_slot(
            path,
            subject_descriptor=probe["subject"],
            reached=resolved,
            failed_at=failed_at,
            subject=subject,
        ):
            return resolved, walk_error, True
        if is_recorded_head:
            head_outcome = (resolved, walk_error, False)
            continue
        # This prefix is bound but its walk broke away from `S`'s slot: a
        # site that spelled it raises rather than reaching `S`, and it is as
        # plausible a spelling as every prefix after it, so none of them can
        # confirm either. The recorded head's own outcome stands.
        break
    return head_outcome


def _run_binding_probe(probe: dict[str, Any]) -> dict[str, Any]:
    try:
        module = importlib.import_module(probe["module"])
    except Exception as error:  # noqa: BLE001 - reported as a structured status.
        return {
            "id": probe["id"],
            "kind": "binding",
            "status": "import-error",
            "identity_match": None,
            "subject_status": None,
            "error": _error_text(error),
        }

    scope = _resolve_scope(module, probe["enclosing_scope"])
    if scope is None:
        return _binding_not_visible(probe)
    scope_globals, local_names = scope
    if probe["head"] in local_names:
        # A name the enclosing callable binds locally shadows any
        # same-named module global for the whole callable body, by Python's
        # own scoping rules - comparing the module global here would blame
        # or clear the subject based on the wrong object entirely.
        return _binding_not_visible(probe)

    subject_resolution = _resolve_subject(probe["subject"])
    walk = _walk_candidates(
        probe,
        module_globals=vars(module),
        scope_globals=scope_globals,
        local_names=local_names,
        subject=subject_resolution,
    )
    if walk is None:
        return _binding_not_visible(probe)
    resolved, walk_error, slot_consistent = walk
    if walk_error is not None:
        identity_match: bool | None = None if slot_consistent else False
    elif subject_resolution.status == "present":
        identity_match = _same_object(resolved, subject_resolution.value)
    elif subject_resolution.status == "absent":
        # S is confirmed gone at this interpreter (not merely errored while
        # resolving), so a `head` binding that resolved to a live object
        # cannot be it - a genuine refutation, not an inconclusive one. This
        # is what lets a version-gated fallback's cross-check catch the
        # exact interpreter where the old branch's subject was removed.
        identity_match = False
    else:
        identity_match = None
    return {
        "id": probe["id"],
        "kind": "binding",
        "status": "resolved",
        "identity_match": identity_match,
        "subject_status": subject_resolution.status,
        "error": walk_error,
    }


def _run_call_shape_probe(probe: dict[str, Any]) -> dict[str, Any]:
    resolution = _resolve_subject(probe["subject"])
    if resolution.status != "present":
        return {
            "id": probe["id"],
            "kind": "call-shape",
            "status": resolution.status,
            "error": resolution.error,
        }
    try:
        signature = inspect.signature(resolution.value)
    except (TypeError, ValueError):
        return {
            "id": probe["id"],
            "kind": "call-shape",
            "status": "no-signature",
            "error": None,
        }
    arguments = [_SENTINEL] * probe["positional_count"]
    keywords = dict.fromkeys(probe["keyword_names"], _SENTINEL)
    try:
        signature.bind_partial(*arguments, **keywords)
    except TypeError as error:
        return {
            "id": probe["id"],
            "kind": "call-shape",
            "status": "rejected",
            "error": _error_text(error),
        }
    return {
        "id": probe["id"],
        "kind": "call-shape",
        "status": "accepted",
        "error": None,
    }


_RUNNERS = {
    "subject": _run_subject_probe,
    "binding": _run_binding_probe,
    "call-shape": _run_call_shape_probe,
}


def _run_probe(probe: dict[str, Any]) -> dict[str, Any]:
    return _RUNNERS[probe["kind"]](probe)


def _apply_resource_limits(limits: ResourceLimits) -> None:
    if _resource is None:  # pragma: no cover - POSIX-only guard.
        return
    _resource.setrlimit(_resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    _resource.setrlimit(
        _resource.RLIMIT_AS, (limits.address_space_bytes, limits.address_space_bytes)
    )
    _resource.setrlimit(
        _resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes)
    )
    _resource.setrlimit(
        _resource.RLIMIT_FSIZE, (limits.max_file_size_bytes, limits.max_file_size_bytes)
    )


def _probe_environment() -> dict[str, str]:
    """Scrub the child's environment without blocking its own `sys.path`.

    Unlike `-I` isolated mode, this keeps `PYTHONPATH` intact: the child must
    see exactly the same importable locations as this process (the target
    package's own interpreter and venv), which is also what makes the
    provisioning venv's site-packages reachable in production.
    """
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _child_argv(limits: ResourceLimits) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).resolve()),
        _SINGLE_PROBE_FLAG,
        "--cpu-seconds",
        str(limits.cpu_seconds),
        "--address-space-bytes",
        str(limits.address_space_bytes),
        "--max-processes",
        str(limits.max_processes),
        "--max-file-size-bytes",
        str(limits.max_file_size_bytes),
    ]


def _failure_result(
    probe: dict[str, Any], *, status: str, error: str
) -> dict[str, Any]:
    return {"id": probe["id"], "kind": probe["kind"], "status": status, "error": error}


def _tail(text: str, *, limit: int = _STDERR_TAIL_BYTES) -> str:
    return text[-limit:]


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the probe child's whole process group, not just the child itself.

    `Popen(start_new_session=True)` makes the child its own process-group
    leader, so any descendant it forks (a target package spawning a helper
    process during import, for example) inherits that same group unless it
    explicitly detaches. Killing only `process.pid` leaves such a descendant
    running - and, because it also inherits the stdout/stderr pipe fds,
    still holding the write end open, which blocks this process's reader
    threads on a read that will never see EOF. `os.killpg` reaches the
    group; a bare `process.kill()` is the fallback for the (POSIX-only)
    absence of `os.killpg` or a group that is already gone.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        process.kill()


def _drain_capped(
    stream: IO[bytes], *, max_bytes: int, kill: Callable[[], None]
) -> tuple[bytes, bool]:
    """Read a pipe incrementally, killing the writer once `max_bytes` is exceeded.

    `RLIMIT_FSIZE` bounds file writes, not pipe writes: a target package can
    write far more than any per-process memory ceiling by writing
    incrementally and blocking on a full pipe rather than holding it all at
    once. Reading (and discarding) as the bytes arrive, instead of after
    `communicate()` has buffered everything, keeps a flooding child from
    growing this process's own memory without bound.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return b"".join(chunks), False
        total += len(chunk)
        if total > max_bytes:
            kill()
            return b"".join(chunks), True
        chunks.append(chunk)


def _subject_fields_well_typed(result: dict[str, Any]) -> bool:
    return isinstance(result["deprecation_warning"], (str, type(None))) and isinstance(
        result["signature"], (str, type(None))
    )


_SUBJECT_STATUS_VALUES = frozenset({"present", "absent", "import-error"})
_RESOLVED_IDENTITY_MATCH_BY_SUBJECT_STATUS: dict[str, tuple[bool | None, ...]] = {
    "present": (True, False),
    "absent": (False,),
    "import-error": (None,),
}


def _binding_fields_well_typed(result: dict[str, Any]) -> bool:
    """Enforce the exact `(subject_status, error, identity_match)` triples possible.

    `_run_binding_probe` only ever produces one of a handful of combinations
    for a `resolved` result - checking each field's own type in isolation
    would still accept an impossible combination (e.g. a non-null `error`
    paired with `identity_match=True`) from a forged or corrupted record.
    """
    identity_match = result["identity_match"]
    subject_status = result["subject_status"]
    if not isinstance(identity_match, (bool, type(None))) or not isinstance(
        subject_status, (str, type(None))
    ):
        return False
    if result["status"] != "resolved":
        return True
    if subject_status not in _SUBJECT_STATUS_VALUES:
        return False
    expected: tuple[bool | None, ...]
    if result["error"] is not None:
        # A failed attribute walk is a refutation, except when it stopped at
        # `S`'s own slot while `S` is absent (`_walk_failed_at_subject_slot`),
        # which is inconclusive.
        expected = (False, None) if subject_status == "absent" else (False,)
    else:
        expected = _RESOLVED_IDENTITY_MATCH_BY_SUBJECT_STATUS[subject_status]
    return identity_match in expected


_EXTRA_FIELD_CHECKS: dict[str, Callable[[dict[str, Any]], bool]] = {
    "subject": _subject_fields_well_typed,
    "binding": _binding_fields_well_typed,
    "call-shape": lambda _result: True,
}


def _is_well_formed_result(result: dict[str, Any], probe: dict[str, Any]) -> bool:
    """Enforce the exact closed schema for one kind, not just its status vocabulary.

    `result` executes inside the process that produced it, so a forged or
    merely truncated record - one with the right `id`/`kind`/`status` but a
    missing or extra field, or a field of the wrong type - must never reach
    adjudication with those other fields silently defaulting to `None`.
    """
    kind = probe["kind"]
    status = result.get("status")
    if status not in _RESULT_STATUSES_BY_KIND[kind]:
        return False
    if status in _KNOWN_PROBE_FAILURE_STATUSES:
        return set(result) == _FAILURE_RESULT_FIELDS and isinstance(
            result["error"], str
        )
    if set(result) != _RESULT_FIELDS_BY_KIND[kind]:
        return False
    if not isinstance(result["error"], (str, type(None))):
        return False
    return _EXTRA_FIELD_CHECKS[kind](result)


def _wait_within_deadline(process: subprocess.Popen[bytes], deadline: float) -> bool:
    """Return whether `process` missed `deadline`; kill its group if it did.

    `process.wait(timeout=0)` polls rather than enforcing a deadline: a
    process that happens to have already exited by the exact instant this
    runs would be silently accepted as on-time, no matter how far past its
    budget the caller already ran to get here (process startup, a slow
    stdin write, ...). An already-exhausted remaining budget is therefore
    treated as an immediate miss, without calling `wait` at all.
    """
    remaining = deadline - time.monotonic()
    if remaining > 0.0:
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            pass
        else:
            return False
    _kill_group(process)
    process.wait()
    return True


def _run_isolated(probe: dict[str, Any], *, limits: ResourceLimits) -> dict[str, Any]:
    """Run one probe in a fresh child process so it cannot abort the batch."""
    payload = json.dumps({"schema_version": _SCHEMA_VERSION, "probe": probe}).encode()
    process = subprocess.Popen(  # noqa: S603 - fixed argv, isolated interpreter.
        _child_argv(limits),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_probe_environment(),
        # A new session makes this child its own process-group leader, so a
        # descendant it spawns (rather than merely a fresh Python-level
        # `_run_probe` call) can be reached as a group by `_kill_group`
        # instead of surviving `process.kill()` untouched.
        start_new_session=True,
    )
    # The declared wall-clock budget starts here, at process creation - not
    # after the stdin payload is written below. A payload large enough to
    # fill the pipe buffer (or a child slow to start reading, e.g. under
    # `bwrap`) would otherwise let `stdin_pipe.write` block for an
    # unbounded, unaccounted-for stretch before the budget's own clock even
    # starts ticking.
    deadline = time.monotonic() + limits.wall_clock_seconds
    # Bind to locals: passing PIPE for all three above guarantees these are
    # not None, but that narrowing does not survive into a lambda closing
    # over `process.stdin`/`.stdout`/`.stderr` re-read later - binding each
    # as the closure's own default argument value captures the already
    # narrowed type instead.
    stdin_pipe, stdout_pipe, stderr_pipe = process.stdin, process.stdout, process.stderr
    assert stdin_pipe is not None  # noqa: S101
    assert stdout_pipe is not None  # noqa: S101
    assert stderr_pipe is not None  # noqa: S101

    stdout_result: list[tuple[bytes, bool]] = []
    stderr_result: list[tuple[bytes, bool]] = []
    kill_group = lambda: _kill_group(process)  # noqa: E731 - captures `process` once.
    stdout_thread = threading.Thread(
        target=lambda stream=stdout_pipe: stdout_result.append(
            _drain_capped(stream, max_bytes=_MAX_CHILD_OUTPUT_BYTES, kill=kill_group)
        ),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=lambda stream=stderr_pipe: stderr_result.append(
            _drain_capped(stream, max_bytes=_MAX_CHILD_OUTPUT_BYTES, kill=kill_group)
        ),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        stdin_pipe.write(payload)
        stdin_pipe.close()
    except (BrokenPipeError, OSError):
        pass
    # One absolute deadline for the whole probe - process startup, stdin
    # delivery, process exit, and pipe drainage together - rather than a
    # fresh grace window per join call. A descendant that outlives the
    # killed process group but releases the pipes just under a fresh grace
    # period would otherwise let a probe run far longer than its declared
    # wall-clock budget and still be accepted as a normal, on-time result.
    # The extra `_POST_KILL_JOIN_GRACE_SECONDS` is only added once the
    # primary process is confirmed to have already missed its own budget and
    # been killed - it is cleanup slack for that case, not a blanket
    # extension of the declared wall-clock budget, or a descendant that
    # quietly holds a pipe open past the budget while the primary process
    # exits on time would still read as an on-time result.
    timed_out = _wait_within_deadline(process, deadline)
    if timed_out:
        deadline = time.monotonic() + _POST_KILL_JOIN_GRACE_SECONDS

    # The immediate child exiting (or being killed) does not guarantee EOF
    # on these pipes: a descendant it forked before dying may have inherited
    # either fd and still be holding the write end open. Bound the join so
    # such an orphan - whether or not it stayed in the killed process group -
    # can never hold this probe, and the batch behind it, past the shared
    # deadline above.
    stdout_thread.join(timeout=max(0.0, deadline - time.monotonic()))
    stderr_thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        _kill_group(process)
        timed_out = True

    if timed_out:
        return _failure_result(
            probe,
            status="probe-timeout",
            error="probe exceeded its wall-clock budget",
        )
    stdout_bytes, stdout_truncated = stdout_result[0]
    stderr_bytes, _ = stderr_result[0]
    if stdout_truncated:
        return _failure_result(
            probe,
            status="probe-crashed",
            error="probe result exceeded the output limit",
        )
    if process.returncode != 0:
        return _failure_result(
            probe,
            status="probe-crashed",
            error=_tail(stderr_bytes.decode("utf-8", errors="replace")),
        )
    try:
        result: Any = json.loads(stdout_bytes)
    except json.JSONDecodeError:
        return _failure_result(
            probe, status="probe-crashed", error="probe result was not valid JSON"
        )
    if (
        not isinstance(result, dict)
        or result.get("id") != probe["id"]
        or result.get("kind") != probe["kind"]
        or not _is_well_formed_result(result, probe)
    ):
        return _failure_result(
            probe, status="probe-crashed", error="probe result had an unexpected shape"
        )
    return result


def _limits_from_arguments(arguments: argparse.Namespace) -> ResourceLimits:
    return ResourceLimits(
        wall_clock_seconds=arguments.wall_clock_seconds,
        cpu_seconds=arguments.cpu_seconds,
        address_space_bytes=arguments.address_space_bytes,
        max_processes=arguments.max_processes,
        max_file_size_bytes=arguments.max_file_size_bytes,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pypi-probe",
        description="run a JSON PyPI-validation probe batch under this interpreter",
    )
    parser.add_argument(_SINGLE_PROBE_FLAG, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--wall-clock-seconds", type=float, default=_DEFAULT_WALL_CLOCK_SECONDS
    )
    parser.add_argument("--cpu-seconds", type=int, default=_DEFAULT_CPU_SECONDS)
    parser.add_argument(
        "--address-space-bytes", type=int, default=_DEFAULT_ADDRESS_SPACE_BYTES
    )
    parser.add_argument("--max-processes", type=int, default=_DEFAULT_MAX_PROCESSES)
    parser.add_argument(
        "--max-file-size-bytes", type=int, default=_DEFAULT_MAX_FILE_SIZE_BYTES
    )
    return parser


def _run_single_probe_mode(limits: ResourceLimits) -> int:
    _apply_resource_limits(limits)
    payload = sys.stdin.buffer.read()
    try:
        document: Any = json.loads(payload)
        if not isinstance(document, dict) or document.get("schema_version") != (
            _SCHEMA_VERSION
        ):
            message = "single-probe request must use schema version 1"
            raise PypiProbeError(message)  # noqa: TRY301
        probe = _parse_probe(document.get("probe"))
    except (PypiProbeError, json.JSONDecodeError) as error:
        sys.stderr.write(str(error))
        return 1
    try:
        result = _run_probe(probe)
    except Exception as error:  # noqa: BLE001 - last-resort guard so the batch keeps going.
        result = {
            "id": probe["id"],
            "kind": probe["kind"],
            "status": "import-error",
            "error": _error_text(error),
        }
    sys.stdout.write(json.dumps(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run a probe batch from stdin, or (internally) one isolated probe."""
    arguments = _parser().parse_args(argv)
    limits = _limits_from_arguments(arguments)
    if arguments.single_probe:
        return _run_single_probe_mode(limits)
    try:
        probes = _parse_batch(sys.stdin.buffer.read())
    except PypiProbeError as error:
        sys.stderr.write(f"pypi probe batch failed: {error}\n")
        return 1
    results = [_run_isolated(probe, limits=limits) for probe in probes]
    sys.stdout.write(
        json.dumps({"schema_version": _SCHEMA_VERSION, "results": results})
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
