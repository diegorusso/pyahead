"""Install one built distribution in isolation and exercise the public CLI."""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

_MAX_ERROR_DETAIL = 2_000


class InstallSmokeError(RuntimeError):
    """Raised when an installed distribution does not satisfy the smoke contract."""


def _project_version(repository: Path) -> str:
    metadata = repository / "src" / "pyahead" / "__init__.py"
    tree = ast.parse(metadata.read_text(encoding="utf-8"), filename=str(metadata))
    for statement in tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        ):
            continue
        if isinstance(statement.value, ast.Constant) and isinstance(
            statement.value.value, str
        ):
            return statement.value.value
    message = "unable to read the project version"
    raise InstallSmokeError(message)


def _select_artifact(dist_dir: Path, kind: str, version: str) -> Path:
    pattern = (
        f"pyahead-{version}-*.whl" if kind == "wheel" else f"pyahead-{version}.tar.gz"
    )
    matches = sorted(path for path in dist_dir.glob(pattern) if path.is_file())
    if len(matches) != 1:
        message = (
            f"expected exactly one {kind} for pyahead {version} in {dist_dir.name}; "
            f"found {len(matches)}"
        )
        raise InstallSmokeError(message)
    return matches[0].resolve()


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _venv_launcher(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "pyahead.exe"
    return environment / "bin" / "pyahead"


def _clean_environment(*, offline: bool) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV"):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if offline:
        environment["UV_OFFLINE"] = "1"
        environment["PIP_NO_INDEX"] = "1"
    return environment


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 - argv is constructed without a shell.
        command,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        if len(detail) > _MAX_ERROR_DETAIL:
            detail = f"{detail[:_MAX_ERROR_DETAIL]}..."
        message = f"{Path(command[0]).name} failed with exit code {result.returncode}"
        if detail:
            message = f"{message}: {detail}"
        raise InstallSmokeError(message)
    return result


def _install(
    artifact: Path,
    environment_dir: Path,
    *,
    environment: dict[str, str],
    timeout: float,
    offline: bool,
) -> None:
    cwd = environment_dir.parent
    uv = shutil.which("uv")
    if uv is not None:
        venv_command = [uv, "venv", "--python", sys.executable]
        venv_command.append(str(environment_dir))
        _run(
            venv_command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        if offline:
            _inherit_locked_dependencies(environment_dir)
        command = [
            uv,
            "pip",
            "install",
            "--python",
            str(_venv_python(environment_dir)),
        ]
        if offline:
            command.extend(("--offline", "--no-deps"))
        command.append(str(artifact))
        _run(
            command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        return

    venv_command = [sys.executable, "-m", "venv"]
    venv_command.append(str(environment_dir))
    _run(
        venv_command,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    if offline:
        _inherit_locked_dependencies(environment_dir)
    command = [str(_venv_python(environment_dir)), "-m", "pip", "install"]
    if offline:
        command.extend(("--no-index", "--no-deps"))
    command.append(str(artifact))
    _run(
        command,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )


def _inherit_locked_dependencies(environment_dir: Path) -> None:
    """Expose the caller's locked site packages without reusing its PyAhead."""
    parent_site = Path(sysconfig.get_path("purelib")).resolve()
    python = _venv_python(environment_dir)
    result = subprocess.run(  # noqa: S603 - fixed child interpreter argv.
        [
            str(python),
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        message = "unable to locate isolated site packages"
        raise InstallSmokeError(message)
    child_site = Path(result.stdout.strip())
    child_site.mkdir(parents=True, exist_ok=True)
    (child_site / "pyahead-smoke-locked-dependencies.pth").write_text(
        f"{parent_site}\n",
        encoding="utf-8",
    )


def _validate_installed_origin(environment_dir: Path, *, timeout: float) -> None:
    result = subprocess.run(  # noqa: S603 - fixed child interpreter argv.
        [
            str(_venv_python(environment_dir)),
            "-c",
            "import pathlib,pyahead; print(pathlib.Path(pyahead.__file__).resolve())",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        message = "unable to import the installed candidate"
        raise InstallSmokeError(message)
    try:
        Path(result.stdout.strip()).relative_to(environment_dir.resolve())
    except ValueError as error:
        message = "smoke environment imported PyAhead outside the candidate install"
        raise InstallSmokeError(message) from error


def _write_sample_project(project: Path) -> None:
    project.mkdir()
    (project / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "pyahead-install-smoke"\n'
            'version = "0"\n'
            'requires-python = ">=3.11"\n'
        ),
        encoding="utf-8",
    )
    (project / "legacy.py").write_text("import cgi\n", encoding="utf-8")


def _validate_scan(document: object) -> None:
    if not isinstance(document, dict):
        message = "installed sample scan did not return a JSON object"
        raise InstallSmokeError(message)
    scan = document.get("scan")
    findings = document.get("findings")
    if not isinstance(scan, dict) or scan.get("files_analyzed") != 1:
        message = "installed sample scan did not analyze exactly one file"
        raise InstallSmokeError(message)
    if not isinstance(findings, list) or len(findings) != 1:
        message = "installed sample scan did not return exactly one finding"
        raise InstallSmokeError(message)
    finding = findings[0]
    if not isinstance(finding, dict):
        message = "installed sample finding is not an object"
        raise InstallSmokeError(message)
    match = finding.get("match")
    location = finding.get("location")
    if (
        finding.get("rule_id") != "CPY0001"
        or not isinstance(match, dict)
        or match.get("confidence") != "high"
        or not isinstance(location, dict)
        or location.get("path") != "legacy.py"
    ):
        message = "installed sample scan did not preserve bundled registry behavior"
        raise InstallSmokeError(message)


def _smoke(
    artifact: Path,
    *,
    version: str,
    timeout: float,
    offline: bool,
) -> None:
    environment = _clean_environment(offline=offline)
    with tempfile.TemporaryDirectory(prefix="pyahead-install-smoke-") as temporary:
        root = Path(temporary)
        environment_dir = root / "environment"
        project = root / "project"
        _install(
            artifact,
            environment_dir,
            environment=environment,
            timeout=timeout,
            offline=offline,
        )
        _validate_installed_origin(environment_dir, timeout=timeout)
        launcher = _venv_launcher(environment_dir)
        if not launcher.is_file():
            message = "installed distribution did not create the pyahead launcher"
            raise InstallSmokeError(message)

        version_result = _run(
            [str(launcher), "--version"],
            cwd=root,
            environment=environment,
            timeout=timeout,
        )
        if version_result.stdout.strip() != f"pyahead {version}":
            message = "installed launcher reported an unexpected version"
            raise InstallSmokeError(message)
        _run(
            [str(launcher), "registry", "validate"],
            cwd=root,
            environment=environment,
            timeout=timeout,
        )
        _run(
            [str(launcher), "registry", "coverage"],
            cwd=root,
            environment=environment,
            timeout=timeout,
        )

        _write_sample_project(project)
        scan_result = _run(
            [
                str(launcher),
                "check",
                ".",
                "--baseline-python",
                "3.11",
                "--horizon-python",
                "3.13",
                "--fail-on",
                "never",
                "--format",
                "json",
            ],
            cwd=project,
            environment=environment,
            timeout=timeout,
        )
        try:
            document: Any = json.loads(scan_result.stdout)
        except json.JSONDecodeError as error:
            message = "installed sample scan returned invalid JSON"
            raise InstallSmokeError(message) from error
        _validate_scan(document)


def _positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        message = "timeout must be a number"
        raise argparse.ArgumentTypeError(message) from error
    if parsed <= 0:
        message = "timeout must be greater than zero"
        raise argparse.ArgumentTypeError(message)
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="install and scan with one built PyAhead distribution"
    )
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--kind", choices=("wheel", "sdist"), required=True)
    parser.add_argument("--timeout", type=_positive_timeout, default=300.0)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="forbid dependency downloads and use only installer caches",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run an isolated install smoke test."""
    arguments = _parser().parse_args(argv)
    repository = Path(__file__).resolve().parents[1]
    try:
        version = _project_version(repository)
        artifact = _select_artifact(
            arguments.dist_dir.resolve(),
            arguments.kind,
            version,
        )
        _smoke(
            artifact,
            version=version,
            timeout=arguments.timeout,
            offline=arguments.offline,
        )
    except (InstallSmokeError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(f"install smoke failed: {error}\n")
        return 1
    sys.stdout.write(f"{arguments.kind} install smoke passed for pyahead {version}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
