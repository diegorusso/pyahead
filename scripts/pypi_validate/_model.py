"""Shared constants, records and errors of the validation harness."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


_PROBE_SCRIPT = _REPO_ROOT / "scripts" / "pypi_probe.py"


_SUPPORTED_MAJOR = 3


_MAX_REPORT_BYTES = 64 * 1024 * 1024


_STDERR_TAIL_BYTES = 4000


_VENV_TIMEOUT_SECONDS = 60.0


_ACCEPTED_SCAN_EXITS = frozenset({0, 3})


_QUALIFIED_MATCH_KINDS = frozenset(
    {"call-shape", "qualified-reference", "qualified-call"}
)


# "import-timeout" is not produced by pypi_probe.py itself (its own
# per-probe budget failure is "probe-timeout"): it is synthesized here when
# the *whole batch subprocess* - one `pypi-probe` invocation covering many
# probes - exceeds its own wall-clock timeout before any individual probe
# gets a chance to report anything, so it is deliberately absent from
# pypi_probe.py's mirrored `_RESULT_STATUSES_BY_KIND`.
_KNOWN_PROBE_FAILURE_STATUSES = frozenset(
    {"probe-timeout", "probe-crashed", "import-timeout"}
)


_PROBE_RESULT_STATUSES_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset({"present", "absent", "import-error"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "binding": frozenset({"resolved", "import-error", "binding-not-visible"})
    | _KNOWN_PROBE_FAILURE_STATUSES,
    "call-shape": frozenset(
        {"accepted", "rejected", "absent", "no-signature", "import-error"}
    )
    | _KNOWN_PROBE_FAILURE_STATUSES,
}


# The exact key set a real (non-failure-status) result of this kind carries;
# mirrors pypi_probe.py's own `_RESULT_FIELDS_BY_KIND`. A failure-status
# result instead always has exactly `{id, kind, status, error}`. Matching the
# key set exactly - not just accepting a closed `status` vocabulary - is what
# makes this a closed schema: a batch process writing a truncated or
# padded-with-extra-keys record is rejected outright.
_PROBE_RESULT_FIELDS_BY_KIND: dict[str, frozenset[str]] = {
    "subject": frozenset(
        {"id", "kind", "status", "deprecation_warning", "signature", "error"}
    ),
    "binding": frozenset(
        {"id", "kind", "status", "identity_match", "subject_status", "error"}
    ),
    "call-shape": frozenset({"id", "kind", "status", "error"}),
}


_FAILURE_RESULT_FIELDS = frozenset({"id", "kind", "status", "error"})


CLOSED_VERDICTS = frozenset(
    {"confirmed", "refuted-binding", "refuted-timeline", "not-adjudicable"}
)


class PypiValidateError(RuntimeError):
    """Raised when a PyPI validation run would be incomplete or untrustworthy."""


@dataclass(frozen=True)
class InstalledInterpreter:
    """One locally installed CPython interpreter available to `uv`."""

    minor: int
    version: str
    path: Path


@dataclass(frozen=True)
class ResourceLimits:
    """Wall-clock-adjacent OS resource ceilings applied to installer children."""

    cpu_seconds: int
    address_space_bytes: int
    max_processes: int
    max_file_size_bytes: int


_INSTALL_LIMITS = ResourceLimits(
    cpu_seconds=180,
    address_space_bytes=3 * 1024 * 1024 * 1024,
    # RLIMIT_NPROC counts every thread already running under the real UID
    # system-wide, not just this subtree, so it needs generous headroom for
    # whatever else shares the host rather than a tight per-package budget.
    max_processes=2048,
    max_file_size_bytes=512 * 1024 * 1024,
)


@dataclass(frozen=True)
class RunOptions:
    """Immutable configuration threaded through one `run` invocation."""

    wheelhouse: Path
    work_dir: Path
    timeout: float
    horizon_minor: int
    baseline_minor: int
    bwrap: str | None
    uv: str
    manifest_sha256: str
    python_install_dir: Path | None


def _tail(text: str) -> str:
    return text[-_STDERR_TAIL_BYTES:]
