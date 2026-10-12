"""Offline environment provisioning and static scan for the PyPI validation harness.

This runner installs and imports arbitrary third-party code from the pinned
wheelhouse built by `pypi_corpus.py`, which crosses PyAhead's own "never
execute target code" boundary. It never touches the network: interpreters and
packages must already be installed locally, and installation always uses
`--no-index --find-links` against the verified wheelhouse.
"""

from scripts.pypi_validate._adjudication import (
    BindingTarget,
    SubjectDescriptor,
    TimelinePlan,
)
from scripts.pypi_validate._cli import (
    main,
)
from scripts.pypi_validate._isolation import (
    Isolation,
)
from scripts.pypi_validate._model import (
    CLOSED_VERDICTS,
    InstalledInterpreter,
    PypiValidateError,
    ResourceLimits,
    RunOptions,
)
from scripts.pypi_validate._provision import (
    BindingVenv,
)
from scripts.pypi_validate._scan import (
    ScanOutcome,
)

__all__ = [
    "CLOSED_VERDICTS",
    "BindingTarget",
    "BindingVenv",
    "InstalledInterpreter",
    "Isolation",
    "PypiValidateError",
    "ResourceLimits",
    "RunOptions",
    "ScanOutcome",
    "SubjectDescriptor",
    "TimelinePlan",
    "main",
]
