"""Tests for strict policy version values."""

import pytest

from pyahead.model import ConfigurationError, Policy
from pyahead.versions import InvalidPythonMinorError, PythonMinor, target_set


def test_python_minor_is_canonical_and_orderable() -> None:
    """Canonical minor values compare numerically, not lexically."""
    assert str(PythonMinor.parse("3.9")) == "3.9"
    assert PythonMinor.parse("3.10") > PythonMinor.parse("3.9")


@pytest.mark.parametrize(
    "value",
    ["", "2.7", "3", "3.011", "3.13.1", "3.14rc1", " 3.13"],
)
def test_python_minor_rejects_non_minor_forms(value: str) -> None:
    """Policy input is never rounded or loosely normalized."""
    with pytest.raises(InvalidPythonMinorError):
        PythonMinor.parse(value)


def test_python_minor_rejects_oversized_minor_without_raw_conversion_error() -> None:
    """Untrusted digit runs fail through the stable validation exception."""
    with pytest.raises(InvalidPythonMinorError):
        PythonMinor.parse("3." + ("9" * 5_000))


def test_python_minor_constructor_enforces_supported_major() -> None:
    """Direct construction cannot bypass the Python 3 invariant."""
    with pytest.raises(InvalidPythonMinorError):
        PythonMinor(major=4, minor=0)


def test_policy_requires_a_non_decreasing_range() -> None:
    """A horizon before the baseline is invalid configuration."""
    with pytest.raises(ConfigurationError):
        Policy.parse("3.13", "3.12")


def test_target_set_is_inclusive_and_minor_order_independent() -> None:
    """Policy generation produces every target as an inspectable frozenset."""
    policy = Policy.parse("3.11", "3.15")

    assert policy.target_versions == target_set(
        PythonMinor.parse("3.11"),
        PythonMinor.parse("3.15"),
    )
    assert tuple(map(str, sorted(policy.target_versions))) == (
        "3.11",
        "3.12",
        "3.13",
        "3.14",
        "3.15",
    )


def test_target_set_rejects_a_reverse_range() -> None:
    """Direct generation cannot silently return an empty invalid policy."""
    with pytest.raises(ValueError, match="must not precede"):
        target_set(PythonMinor.parse("3.13"), PythonMinor.parse("3.12"))
