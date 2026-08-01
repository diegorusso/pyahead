"""Python minor-version values used by policy and registry models."""

import re
from dataclasses import dataclass
from typing import Self

_PYTHON_MINOR_PATTERN = re.compile(r"3\.(0|[1-9][0-9]*)\Z")
_SUPPORTED_MAJOR = 3


class InvalidPythonMinorError(ValueError):
    """Raised when a policy value is not a supported Python minor string."""

    def __init__(self, value: object) -> None:
        """Describe the invalid value without attempting to normalize it."""
        super().__init__(f"expected a Python minor such as '3.13', got {value!r}")


@dataclass(frozen=True, order=True)
class PythonMinor:
    """A canonical Python 3 minor version."""

    major: int
    minor: int

    def __post_init__(self) -> None:
        """Reject values outside the initial Python 3 minor model."""
        if self.major != _SUPPORTED_MAJOR or self.minor < 0:
            value = f"{self.major}.{self.minor}"
            raise InvalidPythonMinorError(value)

    @classmethod
    def parse(cls, value: str) -> Self:
        """Parse a strict ``MAJOR.MINOR`` policy value."""
        match = _PYTHON_MINOR_PATTERN.fullmatch(value)
        if match is None:
            raise InvalidPythonMinorError(value)
        return cls(major=_SUPPORTED_MAJOR, minor=int(match.group(1)))

    def __str__(self) -> str:
        """Render the canonical minor version."""
        return f"{self.major}.{self.minor}"
