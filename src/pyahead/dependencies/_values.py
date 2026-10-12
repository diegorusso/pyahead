"""Strict scalar and collection readers for dependency configuration."""

from __future__ import annotations

import math

from packaging.version import InvalidVersion, Version

from pyahead.dependencies._model import (
    _MAX_TIMEOUT_SECONDS,
    _PYTHON_MAJOR,
    _VERSION_COMPONENTS,
    _error,
    _string,
)


def _table(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        _error(label, "must be a TOML table")
    return value


def _runtime_version(value: object, label: str, *, python: bool) -> Version:
    """Parse a concrete interpreter version without impossible PEP 440 forms."""
    raw = _string(value, label)
    try:
        parsed = Version(raw)
    except InvalidVersion as error:
        _error(label, f"contains an invalid version: {error}")
    if (
        len(parsed.release) != _VERSION_COMPONENTS
        or parsed.epoch != 0
        or parsed.local is not None
        or parsed.post is not None
        or parsed.dev is not None
        or (python and parsed.release[0] != _PYTHON_MAJOR)
    ):
        qualifier = "Python " if python else ""
        _error(
            label,
            f"must be a concrete {qualifier}runtime version with three release "
            "components and no epoch, local, post, or dev segment",
        )
    return parsed


def _string_list(
    value: object,
    label: str,
    *,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _error(label, "must be an array")
    if max_items is not None and len(value) > max_items:
        _error(label, "contains too many items")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(result) != len(set(result)):
        _error(label, "must not contain duplicates")
    return result


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        _error(label, "must be a boolean")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        _error(label, "must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0 or result > _MAX_TIMEOUT_SECONDS:
        _error(
            label,
            f"must be a finite positive number no greater than {_MAX_TIMEOUT_SECONDS}",
        )
    return result
