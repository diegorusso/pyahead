"""Running uv in isolation and interpreting what it reports."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
)

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    canonicalize_name,
)
from packaging.version import InvalidVersion, Version

from pyahead.model import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Sequence
from pyahead.dependencies._archives import _read_artifact
from pyahead.dependencies._artifacts import _validate_metadata_artifacts
from pyahead.dependencies._config import (
    _resolved_dependency_root,
    _validate_dependency_configuration,
    _validate_target_fields,
)
from pyahead.dependencies._model import (
    _MAX_RESOLVER_RESULT_BYTES,
    _MIN_UNSATISFIABLE_LINES,
    _REVIEWED_UV_ARTIFACT_AVAILABILITY_VERSIONS,
    _SUPPORTED_UV_UNSATISFIABLE_SERIES,
    _UV_ARTIFACT_AVAILABILITY_TERMS,
    _UV_MISSING_PACKAGE_PROOF,
    _UV_MISSING_VERSION_PROOF,
    _UV_NO_SOLUTION_HEADER,
    _UV_NO_USABLE_WHEELS_HINT,
    _UV_NO_USABLE_WHEELS_PROOF,
    _UV_NON_SOLVER_TERMS,
    _UV_PLAIN_CAUSE_PREFIX,
    _UV_PLAIN_NO_SOLUTION_HEADER,
    _UV_RESOLUTION_FAILURE_EXIT,
    _UV_TREE_CAUSE_PREFIX,
    _UV_WRONG_ABI_HINT,
    _UV_WRONG_ABI_PROOF,
    ResolutionStatus,
    ResolverResult,
    _error,
    _fail_metadata,
    _failure_requirement_identities,
    _metadata_artifact_snapshots,
    _MetadataError,
    _ResolverOutputLimitError,
    _UvResolverResult,
    _with_marker_evaluation_budget,
)
from pyahead.dependencies._process import _run_bounded_process
from pyahead.dependencies._resolution import (
    _active_resolver_requirements,
    _conflicting_requirement_names,
    _offline_artifact_unavailability,
    _resolved_packages,
    _resolver_requirement_groups,
    _resolver_unverified,
    _resolver_version,
    _safe_process_text,
    _target_snapshot,
)
from pyahead.dependencies._targets import _canonical_resolver_target

if TYPE_CHECKING:
    from pyahead.dependencies._model import (
        DependencyConfiguration,
        EnvironmentTarget,
        MetadataArtifact,
        _CanonicalResolverTarget,
        _ClosedArtifactUnavailability,
    )
    from pyahead.dependencies._process import ProcessRunner


@dataclass(frozen=True)
class _ResolverWorkspace:
    executable: str
    directory: Path
    requirements: Path
    output: Path
    wheelhouse: Path


@dataclass(frozen=True)
class _ResolverInterpretationContext:
    version: str
    workspace: _ResolverWorkspace
    artifacts: Sequence[MetadataArtifact]
    requirements: Sequence[str]
    target: EnvironmentTarget
    closed_artifact_unavailability: tuple[_ClosedArtifactUnavailability, ...]


def _resolver_environment(workspace: Path) -> dict[str, str]:
    home = workspace / "home"
    temporary = workspace / "tmp"
    cache = workspace / "cache"
    for path in (home, temporary, cache):
        path.mkdir()
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "TMPDIR": str(temporary),
        "UV_CACHE_DIR": str(cache),
        "UV_NO_CONFIG": "1",
        "UV_NO_PROGRESS": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(home / ".config"),
    }
    if os.name == "nt":
        environment["USERPROFILE"] = str(home)
        if "SYSTEMROOT" in os.environ:
            environment["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return environment


def _resolver_command(
    workspace: _ResolverWorkspace,
    configuration: DependencyConfiguration,
    target: _CanonicalResolverTarget,
    *,
    has_artifacts: bool,
) -> list[str]:
    command = [
        workspace.executable,
        "pip",
        "compile",
        str(workspace.requirements),
        "--output-file",
        str(workspace.output),
        "--format",
        "pylock.toml",
        "--no-header",
        "--no-annotate",
        "--only-binary",
        ":all:",
        "--keyring-provider",
        "disabled",
        "--no-sources",
        "--no-python-downloads",
        "--no-progress",
        "--color",
        "never",
        "--python-version",
        target.python_full_version,
        "--python-platform",
        target.resolver_platform,
        "--no-cache",
    ]
    if configuration.network:
        if configuration.index_url is None:
            _error("dependency resolver", "online resolution has no configured index")
        command.extend(["--default-index", configuration.index_url])
        if has_artifacts:
            command.extend(["--find-links", str(workspace.wheelhouse)])
    else:
        command.extend(
            [
                "--offline",
                "--no-index",
                "--find-links",
                str(workspace.wheelhouse),
            ]
        )
    return command


def _stage_resolver_artifacts(
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
    wheelhouse: Path,
) -> str | None:
    try:
        for artifact in artifacts:
            relative, raw = _read_artifact(Path(artifact.path), root)
            if relative != artifact.path or hashlib.sha256(raw).hexdigest() != (
                artifact.sha256
            ):
                return "metadata artifact changed after direct inspection"
            (wheelhouse / artifact.path.name).write_bytes(raw)
    except (ConfigurationError, OSError):
        return "unable to revalidate a metadata artifact for isolated resolution"
    return None


def _uv_reports_unsatisfiable(diagnostic: str, version: str) -> bool:
    parsed_version = re.fullmatch(r"(?P<version>[0-9]+(?:\.[0-9]+)+)(?: .*)?", version)
    if parsed_version is None:
        return False
    series = Version(parsed_version.group("version")).release[:2]
    if series not in _SUPPORTED_UV_UNSATISFIABLE_SERIES:
        return False
    lines = _stable_uv_diagnostic(diagnostic).splitlines()

    if len(lines) < _MIN_UNSATISFIABLE_LINES or lines[0] != _UV_NO_SOLUTION_HEADER:
        return False
    explanation = " ".join(lines[1:])
    normalized = explanation.casefold()
    return (
        explanation.startswith(_UV_TREE_CAUSE_PREFIX + "Because ")
        and explanation.endswith("requirements are unsatisfiable.")
        and not any(term in normalized for term in _UV_NON_SOLVER_TERMS)
    )


def _same_exact_requirement(left: str, right: str) -> bool:
    try:
        left_requirement = Requirement(left)
        right_requirement = Requirement(right)
    except InvalidRequirement:
        return False
    left_specifiers = tuple(left_requirement.specifier)
    right_specifiers = tuple(right_requirement.specifier)
    if (
        len(left_specifiers) != 1
        or len(right_specifiers) != 1
        or left_specifiers[0].operator not in {"==", "==="}
        or right_specifiers[0].operator not in {"==", "==="}
        or left_specifiers[0].version.endswith(".*")
        or right_specifiers[0].version.endswith(".*")
        or canonicalize_name(left_requirement.name)
        != canonicalize_name(right_requirement.name)
        or left_requirement.extras != right_requirement.extras
    ):
        return False
    if left_specifiers[0].operator == right_specifiers[0].operator == "===":
        return left_specifiers[0].version == right_specifiers[0].version
    if left_specifiers[0].operator != right_specifiers[0].operator:
        return False
    try:
        return Version(left_specifiers[0].version) == Version(
            right_specifiers[0].version
        )
    except InvalidVersion:
        return False


def _closed_requirement_matches(
    value: str,
    closed: Sequence[_ClosedArtifactUnavailability],
) -> _ClosedArtifactUnavailability | None:
    return next(
        (
            item
            for item in closed
            if any(
                _same_exact_requirement(value, requirement)
                for requirement in item.requirements
            )
        ),
        None,
    )


def _reviewed_uv_artifact_diagnostic(
    diagnostic: str,
    version: str,
    closed: Sequence[_ClosedArtifactUnavailability],
) -> tuple[str, str | None] | None:
    """Return one bounded proof and optional hint from a reviewed uv release."""
    parsed_version = re.fullmatch(r"(?P<version>[0-9]+(?:\.[0-9]+)+)(?: .*)?", version)
    if (
        parsed_version is None
        or parsed_version.group("version")
        not in _REVIEWED_UV_ARTIFACT_AVAILABILITY_VERSIONS
        or not closed
    ):
        return None
    lines = _stable_uv_diagnostic(diagnostic).splitlines()
    if len(lines) < _MIN_UNSATISFIABLE_LINES or lines[0] != _UV_NO_SOLUTION_HEADER:
        return None
    hint = lines[-1] if lines[-1].startswith("hint: ") else None
    proof_lines = lines[1:-1] if hint is not None else lines[1:]
    if not proof_lines or any(line.startswith("hint: ") for line in proof_lines):
        return None
    proof = " ".join(proof_lines)
    if any(term in proof.casefold() for term in _UV_NON_SOLVER_TERMS):
        return None
    return proof, hint


def _closed_artifact_proof(
    proof: str,
    closed: Sequence[_ClosedArtifactUnavailability],
) -> tuple[str, _ClosedArtifactUnavailability] | None:
    """Bind one exact reviewed proof to an independently absent exact pin."""
    match = _UV_MISSING_PACKAGE_PROOF.fullmatch(proof)
    if match is not None:
        selected = _closed_requirement_matches(match.group("requirement"), closed)
        if selected is not None and canonicalize_name(match.group("name")) == (
            selected.canonical_name
        ):
            return "missing-package", selected
        return None

    for kind, pattern in (
        ("missing-version", _UV_MISSING_VERSION_PROOF),
        ("wrong-abi", _UV_WRONG_ABI_PROOF),
        ("no-usable-wheels", _UV_NO_USABLE_WHEELS_PROOF),
    ):
        match = pattern.fullmatch(proof)
        if match is None or not _same_exact_requirement(
            match.group("proof"), match.group("requirement")
        ):
            continue
        selected = _closed_requirement_matches(match.group("requirement"), closed)
        if selected is not None:
            return kind, selected
    return None


def _reviewed_artifact_hint_matches(
    kind: str,
    hint: str | None,
    selected: _ClosedArtifactUnavailability,
) -> bool:
    if hint is None:
        return True
    if kind == "wrong-abi":
        hint_match = _UV_WRONG_ABI_HINT.fullmatch(hint)
    elif kind == "no-usable-wheels":
        hint_match = _UV_NO_USABLE_WHEELS_HINT.fullmatch(hint)
    else:
        return False
    if (
        hint_match is None
        or canonicalize_name(hint_match.group("name")) != selected.canonical_name
    ):
        return False
    if kind != "wrong-abi":
        return True
    try:
        return Version(hint_match.group("version")) == Version(selected.version)
    except InvalidVersion:
        return False


def _uv_reports_artifact_unavailable(
    diagnostic: str,
    version: str,
    closed: Sequence[_ClosedArtifactUnavailability],
) -> _ClosedArtifactUnavailability | None:
    """Recognize reviewed uv closure grammar and nothing broader."""
    retained = _reviewed_uv_artifact_diagnostic(diagnostic, version, closed)
    if retained is None:
        return None
    proof, hint = retained
    matched = _closed_artifact_proof(proof, closed)
    if matched is None or not _reviewed_artifact_hint_matches(
        matched[0], hint, matched[1]
    ):
        return None
    return matched[1]


def _stable_uv_diagnostic(diagnostic: str) -> str:
    """Remove uv's host-Python fallback warning from retained evidence."""
    lines = [line.strip() for line in diagnostic.splitlines() if line.strip()]
    if lines and re.fullmatch(
        r"warning: The requested Python version .+ is not available; .+ will be "
        r"used to build dependencies instead\.",
        lines[0],
    ):
        lines.pop(0)
    if (
        len(lines) >= _MIN_UNSATISFIABLE_LINES
        and lines[0] == _UV_PLAIN_NO_SOLUTION_HEADER
        and lines[1].startswith(_UV_PLAIN_CAUSE_PREFIX)
    ):
        lines[0] = _UV_NO_SOLUTION_HEADER
        lines[1] = _UV_TREE_CAUSE_PREFIX + lines[1].removeprefix(_UV_PLAIN_CAUSE_PREFIX)
    return "\n".join(lines)


def _uv_reports_constraint_conflict(
    diagnostic: str,
    version: str,
    requirements: Sequence[str],
) -> tuple[str, ...]:
    """Accept reviewed solver grammar only with an independent contradiction."""
    if not _uv_reports_unsatisfiable(diagnostic, version):
        return ()
    normalized = diagnostic.casefold()
    if any(term in normalized for term in _UV_ARTIFACT_AVAILABILITY_TERMS):
        return ()
    groups = _resolver_requirement_groups(requirements)
    matched: list[str] = []
    for name in _conflicting_requirement_names(requirements):
        constraints = tuple(str(requirement).casefold() for requirement in groups[name])
        if constraints and all(
            re.search(
                rf"(?<![A-Za-z0-9._-]){re.escape(constraint)}"
                r"(?![A-Za-z0-9._+!<>=~*-])",
                normalized,
            )
            is not None
            for constraint in constraints
        ):
            matched.append(name)
    return tuple(matched)


def _read_resolver_result(path: Path) -> str:
    """Read one regular resolver result with identity and byte limits."""
    descriptor = -1
    try:
        expected_status = path.lstat()
        if not stat.S_ISREG(expected_status.st_mode):
            _fail_metadata("resolver output is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or not os.path.samestat(
            expected_status, status
        ):
            _fail_metadata("resolver output changed while being read")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(_MAX_RESOLVER_RESULT_BYTES + 1)
    except _MetadataError:
        raise
    except (OSError, RuntimeError, ValueError):
        _fail_metadata("unable to read resolver output")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > _MAX_RESOLVER_RESULT_BYTES:
        _fail_metadata("resolver output exceeds the size limit")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail_metadata("resolver output is not valid UTF-8")


def _interpret_resolver_process(
    process: subprocess.CompletedProcess[str],
    *,
    context: _ResolverInterpretationContext,
) -> ResolverResult:
    if process.returncode != 0:
        stderr_has_evidence = bool(process.stderr.strip())
        diagnostic = process.stderr
        stable_diagnostic = _stable_uv_diagnostic(diagnostic)
        detail = _safe_process_text(
            stable_diagnostic,
            context.workspace.directory,
        )
        reviewed_failure = bool(
            process.returncode == _UV_RESOLUTION_FAILURE_EXIT
            and process.stdout == ""
            and stderr_has_evidence
        )
        artifact_unavailable = (
            _uv_reports_artifact_unavailable(
                diagnostic,
                context.version,
                context.closed_artifact_unavailability,
            )
            if reviewed_failure and context.closed_artifact_unavailability
            else None
        )
        failed_names = (
            _uv_reports_constraint_conflict(
                diagnostic,
                context.version,
                context.requirements,
            )
            if reviewed_failure
            else ()
        )
        complete = artifact_unavailable is not None or bool(failed_names)
        reason = (
            "completed offline resolution found no usable wheel in the closed "
            "artifact set for: " + artifact_unavailable.description
            if artifact_unavailable is not None
            else detail or f"resolver exited with status {process.returncode}"
        )
        verified_failure_names = (
            (artifact_unavailable.canonical_name,)
            if artifact_unavailable is not None
            else failed_names
        )
        return _UvResolverResult(
            status=(
                ResolutionStatus.ARTIFACT_UNAVAILABLE
                if artifact_unavailable is not None
                else ResolutionStatus.RESOLUTION_FAILED
                if failed_names
                else ResolutionStatus.UNVERIFIED
            ),
            complete=complete,
            resolver="uv",
            resolver_version=context.version,
            packages=(),
            reason=reason,
            verified_failure_names=verified_failure_names,
            verified_failure_requirements=_failure_requirement_identities(
                context.requirements,
                frozenset(verified_failure_names),
            ),
            verified_artifact_snapshots=_metadata_artifact_snapshots(context.artifacts),
            verified_target_snapshot=_target_snapshot(context.target),
        )
    try:
        output = _read_resolver_result(context.workspace.output)
        packages, provenance_complete = _resolved_packages(
            output,
            context.artifacts,
            wheelhouse=context.workspace.wheelhouse,
        )
    except (
        OSError,
        RuntimeError,
        UnicodeError,
        ValueError,
        _MetadataError,
        InvalidVersion,
    ) as error:
        return _resolver_unverified(
            str(error) or "unable to parse resolver output", context.version
        )
    if not provenance_complete:
        return _resolver_unverified(
            "resolver selected package metadata whose exact artifact provenance "
            "was not established",
            context.version,
            packages,
        )
    return ResolverResult(
        status=ResolutionStatus.SUCCEEDED,
        complete=True,
        resolver="uv",
        resolver_version=context.version,
        packages=packages,
        reason="resolution completed",
    )


def _prepare_resolver_workspace(
    workspace: _ResolverWorkspace,
    target: EnvironmentTarget,
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
) -> tuple[_CanonicalResolverTarget | None, str | None]:
    resolver_target, target_issue = _canonical_resolver_target(target)
    if resolver_target is None:
        return None, target_issue or "resolver target is unverified"
    filenames = tuple(artifact.path.name for artifact in artifacts)
    portable_filenames = tuple(
        unicodedata.normalize("NFC", filename).casefold() for filename in filenames
    )
    if len(portable_filenames) != len(set(portable_filenames)):
        return None, ("artifact filenames are not portably unique in the resolver set")
    workspace.wheelhouse.mkdir()
    staging_error = _stage_resolver_artifacts(
        artifacts,
        root=root,
        wheelhouse=workspace.wheelhouse,
    )
    return (
        (None, staging_error) if staging_error is not None else (resolver_target, None)
    )


def _resolve_in_workspace(  # noqa: PLR0913 - the resolver's full input.
    workspace: _ResolverWorkspace,
    configuration: DependencyConfiguration,
    target: EnvironmentTarget,
    artifacts: Sequence[MetadataArtifact],
    *,
    root: Path,
    run_process: ProcessRunner,
) -> ResolverResult:
    resolver_target, preparation_issue = _prepare_resolver_workspace(
        workspace,
        target,
        artifacts,
        root=root,
    )
    if resolver_target is None:
        return _resolver_unverified(
            preparation_issue or "resolver preparation is unverified"
        )
    active_requirements = _active_resolver_requirements(
        configuration.requirements,
        target,
        configuration.extras,
    )
    workspace.requirements.write_text(
        "\n".join(active_requirements) + "\n",
        encoding="utf-8",
    )
    environment = _resolver_environment(workspace.directory)
    version: str | None = None
    try:
        version_process = run_process(
            [workspace.executable, "--version"],
            cwd=workspace.directory,
            env=environment,
            timeout=configuration.timeout_seconds,
        )
        version = (
            _resolver_version(version_process.stdout, "uv")
            if version_process.returncode == 0 and not version_process.stderr
            else None
        )
        if version is None:
            return _resolver_unverified(
                "unable to identify the exact uv resolver version"
            )
        closed_artifact_unavailability = (
            _offline_artifact_unavailability(
                active_requirements,
                artifacts,
                target,
                configuration.project_kind,
            )
            if not configuration.network
            else ()
        )
        command = _resolver_command(
            workspace,
            configuration,
            resolver_target,
            has_artifacts=bool(artifacts),
        )
        process = run_process(
            command,
            cwd=workspace.directory,
            env=environment,
            timeout=configuration.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ResolverResult(
            status=ResolutionStatus.TIMED_OUT,
            complete=False,
            resolver="uv",
            resolver_version=version,
            packages=(),
            reason=(
                "resolver exceeded the explicit timeout; compatibility "
                "remains unverified"
            ),
        )
    except (
        OSError,
        UnicodeError,
        _MetadataError,
        _ResolverOutputLimitError,
    ) as error:
        reason = (
            "isolated resolver output exceeded the size limit"
            if isinstance(error, _ResolverOutputLimitError)
            else "unable to execute or decode isolated resolver output"
        )
        return _resolver_unverified(reason, version)
    return _interpret_resolver_process(
        process,
        context=_ResolverInterpretationContext(
            version=version,
            workspace=workspace,
            artifacts=artifacts,
            requirements=active_requirements,
            target=target,
            closed_artifact_unavailability=closed_artifact_unavailability,
        ),
    )


def _trusted_resolver_executable(
    resolver: str,
    *,
    root: Path,
) -> tuple[Path | None, str | None]:
    executable = shutil.which(resolver)
    if executable is None:
        return None, "uv executable is unavailable"
    try:
        resolved = Path(executable).resolve(strict=True)
        status = resolved.stat()
    except (OSError, RuntimeError):
        return None, "unable to validate the uv executable"
    if not stat.S_ISREG(status.st_mode):
        return None, "uv executable is not a regular file"
    try:
        resolved.relative_to(root)
    except ValueError:
        return resolved, None
    return None, "refusing to execute a resolver from inside the scanned root"


class UvResolverAdapter:
    """Run uv in a temporary, configuration-free, build-disabled boundary."""

    name = "uv"

    def __init__(self, *, run_process: ProcessRunner | None = None) -> None:
        """Use the bounded, contained process runner unless given another.

        ``run_process`` receives the command with ``cwd``, ``env`` and
        ``timeout`` keywords and returns its completed process; tests use it
        to stand in for uv.
        """
        self._run_process = _run_bounded_process if run_process is None else run_process

    @_with_marker_evaluation_budget
    def resolve(
        self,
        configuration: DependencyConfiguration,
        target: EnvironmentTarget,
        artifacts: Sequence[MetadataArtifact],
        *,
        root: Path,
    ) -> ResolverResult:
        """Resolve one target with explicit network and timeout controls."""
        configuration = _validate_dependency_configuration(configuration)
        _validate_metadata_artifacts(artifacts)
        resolved_root = _resolved_dependency_root(root)
        if target not in configuration.targets:
            _error("dependency resolver target", "is not declared in configuration")
        if not configuration.resolve:
            return ResolverResult(
                status=ResolutionStatus.NOT_REQUESTED,
                complete=True,
                resolver=self.name,
                resolver_version=None,
                packages=(),
                reason="resolver was not requested",
            )
        _validate_target_fields(target, label="dependency resolver target")
        _resolver_target, target_issue = _canonical_resolver_target(target)
        if _resolver_target is None:
            return _resolver_unverified(target_issue or "resolver target is unverified")
        resolved_executable, executable_issue = _trusted_resolver_executable(
            configuration.resolver,
            root=resolved_root,
        )
        if resolved_executable is None:
            return _resolver_unverified(
                executable_issue or "unable to validate the uv executable"
            )
        with tempfile.TemporaryDirectory(prefix="pyahead-resolver-") as temporary:
            directory = Path(temporary)
            return _resolve_in_workspace(
                _ResolverWorkspace(
                    executable=str(resolved_executable),
                    directory=directory,
                    requirements=directory / "requirements.in",
                    output=directory / "pylock.toml",
                    wheelhouse=directory / "artifacts",
                ),
                configuration,
                target,
                artifacts,
                root=resolved_root,
                run_process=self._run_process,
            )
