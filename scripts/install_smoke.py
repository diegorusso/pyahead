"""Install one built distribution in isolation and exercise the public CLI."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from pyahead._human_text import (
    SafeArgumentParser,
    _is_unsafe_terminal_codepoint,
    escape_terminal_text,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAX_ERROR_DETAIL = 2_000
_MAX_REDACTION_SCAN = 8_192
_MAX_CREDENTIAL_LITERAL_PREFIX = 2
_PUBLIC_INDEX = "https://pypi.org/simple"
_REDACTED = "[REDACTED]"
_CREDENTIAL_CONTROL_SENTINEL = "\0"
_INHERITED_ENVIRONMENT = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*:(?:\\*/){2})([^/\\\s?#]+)@")
_CREDENTIAL_NAME = re.compile(
    r"(?<![a-z0-9_-])"
    r"(?P<name>authorization|proxy-authorization|"
    r"[a-z0-9_-]*(?:password|passwd|token|"
    r"secret(?:[_-]?(?:access[_-]?key|key))?|auth|"
    r"access[_-]?key|api[_-]?key|client[_-]?secret|credential))"
    r"(?![a-z0-9_-])",
    flags=re.IGNORECASE,
)
_SECRET_QUERY = re.compile(
    r"(?i)([?&](?:access_token|api[_-]?key|apikey|auth|credential|key|password|"
    r"secret|token)=)[^&#\s\"'\\]*"
)
_TOKEN = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{8,}|gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"pypi-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16})\b"
)
_CANONICAL_URL_USERINFO = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://(?P<secret>[^/\\\s?#@]+)@"
)
_CANONICAL_UNTERMINATED_URL = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://(?P<secret>[^/\\\s?#@]+)\Z"
)
_CANONICAL_SECRET_QUERY = re.compile(
    r"(?i)[?&](?:access_token|api[_-]?key|apikey|auth|credential|key|password|"
    r"secret|token)=(?P<secret>[^&#\s\"'\\]*)"
)
_CANONICAL_FIELD_AFTER_DELIMITER = re.compile(
    r"\s*[\"']?[a-z_][a-z0-9_-]*[\"']?\s*[:=]",
    flags=re.IGNORECASE,
)
_TYPING_CONSUMER = """\
from pathlib import Path
from typing import assert_type

from pyahead.analysis import ScanReport, ScanRequest, scan
from pyahead.registry import Registry, load_registry

request = ScanRequest(root=Path("."))
assert_type(scan(request), ScanReport)
assert_type(load_registry(), Registry)
"""


class InstallSmokeError(RuntimeError):
    """Raised when an installed distribution does not satisfy the smoke contract."""


class _SanitizedInstallSmokeError(InstallSmokeError):
    """Raised only for child-process details sanitized by ``_run``."""


@dataclass(frozen=True)
class _InstallerPolicy:
    offline: bool
    cache: Path | None


@dataclass(frozen=True)
class _CredentialMatchView:
    """Canonical match text plus exact source spans for safe projection."""

    text: str
    starts: tuple[int, ...]
    ends: tuple[int, ...]


def _project_version(repository: Path) -> str:
    metadata = repository / "src" / "pyahead" / "__init__.py"
    try:
        tree = ast.parse(metadata.read_text(encoding="utf-8"), filename=str(metadata))
    except (OSError, SyntaxError, UnicodeError):
        tree = None
    if tree is None:
        message = "unable to read the project version"
        raise InstallSmokeError(message) from None
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


def _clean_environment(
    *,
    root: Path,
    policy: _InstallerPolicy,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Create the complete, isolated environment used by every smoke child."""
    ambient = os.environ if source is None else source
    environment = {
        name: ambient[name] for name in _INHERITED_ENVIRONMENT if ambient.get(name)
    }
    directories = {
        "APPDATA": root / "appdata",
        "HOME": root / "home",
        "LOCALAPPDATA": root / "local-appdata",
        "TEMP": root / "tmp",
        "TMP": root / "tmp",
        "TMPDIR": root / "tmp",
        "USERPROFILE": root / "home",
        "XDG_CACHE_HOME": root / "cache",
        "XDG_CONFIG_HOME": root / "config",
        "XDG_DATA_HOME": root / "data",
    }
    for directory in set(directories.values()):
        directory.mkdir(parents=True, exist_ok=True)
    environment.update({name: str(path) for name, path in directories.items()})
    environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_KEYRING_PROVIDER": "disabled",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "UV_KEYRING_PROVIDER": "disabled",
            "UV_NO_CONFIG": "1",
            "UV_NO_PROGRESS": "1",
            "UV_PYTHON_DOWNLOADS": "never",
        }
    )
    if policy.offline:
        environment["UV_OFFLINE"] = "1"
        environment["PIP_NO_INDEX"] = "1"
    if policy.cache is None:
        environment["UV_NO_CACHE"] = "1"
    return environment


def _credential_match_view(text: str) -> _CredentialMatchView:
    """Decode JSON syntax and omit controls only in credential match text."""
    rendered: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    while cursor < len(text):
        character = text[cursor]
        if _is_unsafe_terminal_codepoint(ord(character)):
            cursor += 1
            continue
        if character != "\\":
            rendered.append(character)
            starts.append(cursor)
            cursor += 1
            ends.append(cursor)
            continue
        run_end = cursor
        while run_end < len(text) and text[run_end] == "\\":
            run_end += 1
        decoded: str | None = None
        decoded_end = run_end
        if run_end < len(text):
            escaped = text[run_end]
            if escaped in "\\/\"'":
                decoded = escaped
                decoded_end += 1
            elif (
                escaped == "u"
                and run_end + 5 <= len(text)
                and all(
                    digit in "0123456789abcdefABCDEF"
                    for digit in text[run_end + 1 : run_end + 5]
                )
            ):
                decoded = chr(int(text[run_end + 1 : run_end + 5], 16))
                decoded_end = run_end + 5
        if decoded is None:
            rendered.append("\\")
            starts.append(cursor)
            ends.append(run_end)
            cursor = run_end
            continue
        if _is_unsafe_terminal_codepoint(ord(decoded)):
            cursor = decoded_end
            continue
        rendered.append(decoded)
        starts.append(cursor)
        ends.append(decoded_end)
        cursor = decoded_end
    return _CredentialMatchView("".join(rendered), tuple(starts), tuple(ends))


def _canonical_assignment_value_span(
    text: str,
    name_end: int,
) -> tuple[int, int] | None:
    """Locate one named credential value in canonical match text."""
    cursor = name_end
    if cursor < len(text) and text[cursor] in "\"'":
        cursor += 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or text[cursor] not in "=:,":
        return None
    cursor += 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    value_start = cursor
    return value_start, _canonical_credential_value_end(text, value_start)


def _canonical_credential_value_end(
    text: str,
    value_start: int,
    *,
    authorization: bool = False,
) -> int:
    """Find a fail-closed structural value end in canonical match text."""
    if authorization and value_start < len(text) and text[value_start] not in "\"'":
        match = re.match(
            rf"(?i)(?:basic|bearer|token)[ \t{_CREDENTIAL_CONTROL_SENTINEL}]+"
            rf"[^ \t,;}}\]{_CREDENTIAL_CONTROL_SENTINEL}]+",
            text[value_start:],
        )
        if match is not None:
            candidate = value_start + match.end()
            if candidate == len(text) or text[candidate] in (
                " ",
                "\t",
                "\r",
                "\n",
                _CREDENTIAL_CONTROL_SENTINEL,
            ):
                return candidate
    value_end = value_start
    while value_end < len(text):
        if text[value_end] == "]" and text[value_start : value_end + 1].endswith(
            _REDACTED
        ):
            value_end += 1
            continue
        if text[value_end] in "}]":
            break
        if text[value_end] in ",;" and _CANONICAL_FIELD_AFTER_DELIMITER.match(
            text, value_end + 1
        ):
            break
        value_end += 1
    return value_end


def _project_credential_span(
    view: _CredentialMatchView,
    start: int,
    end: int,
) -> tuple[int, int] | None:
    """Project one non-empty canonical span back onto its original text."""
    if start >= end or start < 0 or end > len(view.starts):
        return None
    return view.starts[start], view.ends[end - 1]


def _structural_pattern_spans(
    view: _CredentialMatchView,
) -> list[tuple[int, int]]:
    """Project canonical URL, query, and literal-token matches to source."""
    spans: list[tuple[int, int]] = []
    for pattern in (_CANONICAL_URL_USERINFO, _CANONICAL_SECRET_QUERY):
        for match in pattern.finditer(view.text):
            if match.group("secret") == _REDACTED:
                continue
            projected = _project_credential_span(
                view,
                match.start("secret"),
                match.end("secret"),
            )
            if projected is not None:
                spans.append(projected)
    for match in _TOKEN.finditer(view.text):
        projected = _project_credential_span(view, match.start(), match.end())
        if projected is not None:
            spans.append(projected)
    return spans


def _structural_named_spans(view: _CredentialMatchView) -> list[tuple[int, int]]:
    """Project canonical named-credential matches onto source spans."""
    spans: list[tuple[int, int]] = []
    for match in _CREDENTIAL_NAME.finditer(view.text):
        if match.start() > 0 and view.text[match.start() - 1] in "?&":
            continue
        assignment = _credential_assignment(view.text, match.start(), match.end())
        if assignment is None:
            continue
        _key_start, _separator, value_start = assignment
        credential_name = match.group("name").casefold()
        value_end = _canonical_credential_value_end(
            view.text,
            value_start,
            authorization=credential_name.endswith(("auth", "authorization")),
        )
        normalized_value = view.text[value_start:value_end].strip(" \t\"'")
        if normalized_value == _REDACTED or re.fullmatch(
            rf"(?i)(?:basic|bearer|token)\s+{re.escape(_REDACTED)}",
            normalized_value,
        ):
            continue
        projected = _project_credential_span(view, value_start, value_end)
        if projected is not None:
            spans.append(projected)
    return spans


def _apply_credential_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace possibly overlapping source spans with one stable marker each."""
    if not spans:
        return text
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    parts: list[str] = []
    cursor = 0
    for start, end in merged:
        parts.extend((text[cursor:start], _REDACTED))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _redact_structural_credentials(text: str) -> str:
    """Redact serialized or control-split credentials without rewriting syntax."""
    view = _credential_match_view(text)
    if view.text == text:
        return text
    spans = _structural_pattern_spans(view)
    spans.extend(_structural_named_spans(view))
    return _apply_credential_spans(text, spans)


def _redact_unterminated_url_userinfo(text: str) -> str:
    """Fail closed when a bounded diagnostic cuts off a possible URL authority."""
    view = _credential_match_view(text)
    match = _CANONICAL_UNTERMINATED_URL.search(view.text)
    if match is None or match.group("secret") == _REDACTED:
        return text
    projected = _project_credential_span(
        view, match.start("secret"), match.end("secret")
    )
    if projected is None:
        return text
    start, end = projected
    return f"{text[:start]}{_REDACTED}{text[end:]}"


def _redact_credentials(text: str) -> str:
    """Remove common credential forms before retaining diagnostic text."""
    redacted = _URL_USERINFO.sub(rf"\1{_REDACTED}@", text)
    redacted = _SECRET_QUERY.sub(rf"\1{_REDACTED}", redacted)
    redacted = _redact_named_credentials(redacted)
    redacted = _TOKEN.sub(_REDACTED, redacted)
    return _redact_structural_credentials(redacted)


def _redact_named_credentials(text: str) -> str:
    """Redact assignment and mapping values without parsing untrusted syntax."""
    parts: list[str] = []
    cursor = 0
    while match := _CREDENTIAL_NAME.search(text, cursor):
        assignment = _credential_assignment(text, match.start(), match.end())
        if assignment is None:
            parts.append(text[cursor : match.end()])
            cursor = match.end()
            continue
        key_start, separator, value_start = assignment
        redacted_end = _existing_query_redaction_end(
            text,
            key_start=key_start,
            separator=separator,
            value_start=value_start,
        )
        if redacted_end is not None:
            parts.append(text[cursor:redacted_end])
            cursor = redacted_end
            continue
        parts.append(text[cursor:key_start])
        name = match.group("name")
        parts.append(f"{name}{separator}{_REDACTED}")
        untrusted_marker = text.startswith(_REDACTED, value_start)
        cursor = _credential_value_end(
            text,
            value_start + len(_REDACTED) if untrusted_marker else value_start,
            include_whitespace=(
                name.casefold().endswith(("auth", "authorization")) or untrusted_marker
            ),
        )
    parts.append(text[cursor:])
    return "".join(parts)


def _existing_query_redaction_end(
    text: str,
    *,
    key_start: int,
    separator: str,
    value_start: int,
) -> int | None:
    """Keep a complete marker only in a demonstrable URL-query assignment."""
    if separator != "=" or key_start == 0 or text[key_start - 1] not in "?&":
        return None
    marker_end = value_start + len(_REDACTED)
    if text[value_start:marker_end] != _REDACTED:
        return None
    if marker_end == len(text) or text[marker_end] in " \t,;}]&#\\\"'\r\n":
        return marker_end
    return None


def _credential_assignment(
    text: str,
    name_start: int,
    name_end: int,
) -> tuple[int, str, int] | None:
    """Locate a credential key's syntax without scanning at every backslash."""
    key_start = name_start
    after_key = name_end
    closing_slashes = 0
    while after_key < len(text) and text[after_key] == "\\":
        closing_slashes += 1
        after_key += 1
    if after_key < len(text) and text[after_key] in "\"'":
        quoted_key_start = _quoted_credential_key_start(
            text,
            name_start=name_start,
            quote=text[after_key],
            closing_slashes=closing_slashes,
        )
        if quoted_key_start is None:
            return None
        key_start = quoted_key_start
        after_key += 1

    while after_key < len(text) and (
        text[after_key].isspace() or text[after_key] == _CREDENTIAL_CONTROL_SENTINEL
    ):
        after_key += 1
    if after_key >= len(text) or text[after_key] not in "=:,":
        return None
    separator = text[after_key]
    value_start = after_key + 1
    while value_start < len(text) and (
        text[value_start].isspace() or text[value_start] == _CREDENTIAL_CONTROL_SENTINEL
    ):
        value_start += 1
    return key_start, separator, value_start


def _quoted_credential_key_start(
    text: str,
    *,
    name_start: int,
    quote: str,
    closing_slashes: int,
) -> int | None:
    """Validate a quoted key and return the start of its optional prefix."""
    open_quote = name_start - 1
    if open_quote < 0 or text[open_quote] != quote:
        return None
    opening_start = open_quote
    while opening_start > 0 and text[opening_start - 1] == "\\":
        opening_start -= 1
    if open_quote - opening_start != closing_slashes:
        return None
    prefix_start = opening_start
    while (
        prefix_start > 0
        and opening_start - prefix_start < _MAX_CREDENTIAL_LITERAL_PREFIX
        and text[prefix_start - 1] in "bBrRuU"
    ):
        prefix_start -= 1
    if prefix_start > 0 and _is_credential_name_character(text[prefix_start - 1]):
        return None
    return prefix_start


def _is_credential_name_character(character: str) -> bool:
    """Return whether a character can be part of a recognized credential key."""
    return character.isascii() and (character.isalnum() or character in "_-")


def _credential_value_end(text: str, start: int, *, include_whitespace: bool) -> int:
    """Return the end of one credential value, including diagnostic wrappers."""
    cursor = start
    prefix_end = cursor
    while (
        prefix_end < len(text)
        and prefix_end - cursor < _MAX_CREDENTIAL_LITERAL_PREFIX
        and text[prefix_end] in "bBrRuU"
    ):
        prefix_end += 1

    wrapper_start = prefix_end
    while wrapper_start < len(text) and text[wrapper_start] == "\\":
        wrapper_start += 1
    if wrapper_start < len(text) and text[wrapper_start] in "\"'":
        quoted_end = _quoted_credential_end(
            text,
            content_start=wrapper_start + 1,
            quote=text[wrapper_start],
            wrapper_backslashes=wrapper_start - prefix_end,
        )
        if quoted_end is not None:
            return quoted_end
        cursor = start
        while cursor < len(text) and text[cursor] not in "\r\n":
            cursor += 1
        return cursor

    boundaries = ",;}]\r\n" if include_whitespace else " \t,;}]\r\n"
    cursor = start
    while cursor < len(text) and text[cursor] not in boundaries:
        cursor += 1
    return cursor


def _quoted_credential_end(
    text: str,
    *,
    content_start: int,
    quote: str,
    wrapper_backslashes: int,
) -> int | None:
    """Find a matching diagnostic quote while skipping encoded inner quotes.

    Each diagnostic-serialization layer doubles content backslashes and adds one
    before a delimiter.  A closing delimiter therefore has ``wrapper_backslashes``
    plus an even number of encoded content-backslash groups before its quote.
    """
    cursor = content_start
    encoded_group = wrapper_backslashes + 1
    closing_period = 2 * encoded_group
    while cursor < len(text):
        if text[cursor] == "\\":
            run_start = cursor
            while cursor < len(text) and text[cursor] == "\\":
                cursor += 1
            if cursor < len(text) and text[cursor] == quote:
                run_length = cursor - run_start
                if (
                    run_length >= wrapper_backslashes
                    and (run_length - wrapper_backslashes) % closing_period == 0
                ):
                    return cursor + 1
                cursor += 1
            continue
        if text[cursor] == quote and wrapper_backslashes == 0:
            return cursor + 1
        cursor += 1
    return None


def _error_detail(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        truncated = len(value) > _MAX_REDACTION_SCAN
        text = value[:_MAX_REDACTION_SCAN].decode("utf-8", errors="replace")
    else:
        truncated = len(value) > _MAX_REDACTION_SCAN
        text = value[:_MAX_REDACTION_SCAN]
    if truncated:
        text = _redact_unterminated_url_userinfo(text)
    return _bounded_terminal_detail(_redact_credentials(text))


def _bounded_terminal_detail(value: str) -> str:
    """Make already-redacted diagnostic text safe without redacting it twice."""
    detail = escape_terminal_text(value[:_MAX_REDACTION_SCAN])
    if len(detail) > _MAX_ERROR_DETAIL:
        return f"{detail[:_MAX_ERROR_DETAIL]}..."
    return detail


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    executable = Path(command[0]).name
    failure_message: str | None = None
    try:
        result = subprocess.run(  # noqa: S603 - argv is constructed without a shell.
            command,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        detail = _error_detail(error.stderr or error.stdout)
        message = f"{executable} timed out after {timeout:g} seconds"
        if detail:
            message = f"{message}: {detail}"
        failure_message = message
    except OSError as error:
        detail = _error_detail(str(error))
        message = f"unable to run {executable}"
        if detail:
            message = f"{message}: {detail}"
        failure_message = message
    if failure_message is not None:
        raise _SanitizedInstallSmokeError(failure_message)
    if result.returncode != 0:
        returncode = result.returncode
        detail = _error_detail(result.stderr or result.stdout)
        del result
        message = f"{executable} failed with exit code {returncode}"
        if detail:
            message = f"{message}: {detail}"
        raise _SanitizedInstallSmokeError(message)
    return result


def _uv_prefix(
    uv: str,
    *,
    policy: _InstallerPolicy,
) -> list[str]:
    command = [
        uv,
        "--no-config",
        "--no-progress",
        "--no-python-downloads",
        "--color",
        "never",
    ]
    if policy.cache is None:
        command.append("--no-cache")
    else:
        command.extend(("--cache-dir", str(policy.cache)))
    if policy.offline:
        command.append("--offline")
    return command


def _install(
    artifact: Path,
    environment_dir: Path,
    *,
    environment: dict[str, str],
    timeout: float,
    policy: _InstallerPolicy,
) -> None:
    cwd = environment_dir.parent
    uv = shutil.which("uv", path=environment.get("PATH", ""))
    if uv is not None:
        uv = str(Path(uv).resolve())
        venv_command = [
            *_uv_prefix(
                uv,
                policy=policy,
            ),
            "venv",
            "--no-project",
            "--python",
            sys.executable,
            str(environment_dir),
        ]
        _run(
            venv_command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        command = [
            *_uv_prefix(
                uv,
                policy=policy,
            ),
            "pip",
            "install",
            "--python",
            str(_venv_python(environment_dir)),
            "--keyring-provider",
            "disabled",
            "--no-sources",
            "--default-index",
            _PUBLIC_INDEX,
        ]
        command.append(str(artifact))
        _run(
            command,
            cwd=cwd,
            environment=environment,
            timeout=timeout,
        )
        return

    if policy.cache is not None:
        message = "installer cache requires uv"
        raise InstallSmokeError(message)
    venv_command = [sys.executable, "-I", "-m", "venv", str(environment_dir)]
    _run(
        venv_command,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )
    command = [
        str(_venv_python(environment_dir)),
        "-I",
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "--keyring-provider",
        "disabled",
        "--no-color",
        "install",
        "--no-cache-dir",
    ]
    command.extend(("--index-url", _PUBLIC_INDEX))
    command.append(str(artifact))
    _run(
        command,
        cwd=cwd,
        environment=environment,
        timeout=timeout,
    )


def _validate_installed_origin(
    environment_dir: Path,
    *,
    environment: dict[str, str],
    timeout: float,
) -> None:
    result = _run(
        [
            str(_venv_python(environment_dir)),
            "-I",
            "-c",
            "import pathlib,pyahead; print(pathlib.Path(pyahead.__file__).resolve())",
        ],
        cwd=environment_dir.parent,
        environment=environment,
        timeout=timeout,
    )
    if not Path(result.stdout.strip()).is_relative_to(environment_dir.resolve()):
        message = "smoke environment imported PyAhead outside the candidate install"
        raise InstallSmokeError(message)


def _validate_installed_contract_artifacts(
    environment_dir: Path,
    *,
    environment: dict[str, str],
    timeout: float,
) -> None:
    """Require the installed typing marker and public report schema resource."""
    result = _run(
        [
            str(_venv_python(environment_dir)),
            "-I",
            "-c",
            (
                "import importlib.resources as r,json;"
                "root=r.files('pyahead');"
                "schema=r.files('pyahead.data.schema').joinpath('report-v1.json');"
                "print(json.dumps({'py_typed':root.joinpath('py.typed').is_file(),"
                "'schema':schema.is_file()}))"
            ),
        ],
        cwd=environment_dir.parent,
        environment=environment,
        timeout=timeout,
    )
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError:
        document = None
    if document != {"py_typed": True, "schema": True}:
        message = "installed distribution omitted typing or report-schema data"
        raise InstallSmokeError(message)


def _validate_installed_typing(
    root: Path,
    environment_dir: Path,
    *,
    environment: dict[str, str],
    timeout: float,
) -> None:
    """Type-check the narrow public API against the installed wheel."""
    consumer = root / "typing-consumer.py"
    consumer.write_text(_TYPING_CONSUMER, encoding="utf-8")
    _run(
        [
            sys.executable,
            "-I",
            "-m",
            "mypy",
            "--strict",
            "--no-incremental",
            "--python-executable",
            str(_venv_python(environment_dir)),
            str(consumer),
        ],
        cwd=root,
        environment=environment,
        timeout=timeout,
    )


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


def _decode_scan(stdout: str) -> object:
    """Decode child JSON without retaining attacker-controlled decoder context."""
    invalid_json = False
    try:
        document: object = json.loads(stdout)
    except json.JSONDecodeError:
        invalid_json = True
        document = None
    if invalid_json:
        message = "installed sample scan returned invalid JSON"
        raise InstallSmokeError(message)
    return document


def _smoke(
    artifact: Path,
    *,
    version: str,
    timeout: float,
    policy: _InstallerPolicy,
) -> None:
    with tempfile.TemporaryDirectory(prefix="pyahead-install-smoke-") as temporary:
        root = Path(temporary)
        environment = _clean_environment(root=root, policy=policy)
        environment_dir = root / "environment"
        project = root / "project"
        _install(
            artifact,
            environment_dir,
            environment=environment,
            timeout=timeout,
            policy=policy,
        )
        _validate_installed_origin(
            environment_dir,
            environment=environment,
            timeout=timeout,
        )
        _validate_installed_contract_artifacts(
            environment_dir,
            environment=environment,
            timeout=timeout,
        )
        if artifact.suffix == ".whl":
            _validate_installed_typing(
                root,
                environment_dir,
                environment=environment,
                timeout=timeout,
            )
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
        # Expand Windows temporary-directory aliases to match the inferred root.
        scan_result = _run(
            [
                str(launcher),
                "check",
                str(project.resolve()),
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
        _validate_scan(_decode_scan(scan_result.stdout))


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


class _InstallSmokeArgumentParser(SafeArgumentParser):
    """Redact install-smoke credentials before the shared terminal boundary."""

    def error(self, message: str) -> NoReturn:
        """Report a redacted, control-safe argparse error."""
        super().error(_error_detail(message))


def _parser() -> argparse.ArgumentParser:
    parser = _InstallSmokeArgumentParser(
        prog="pyahead-install-smoke",
        description="install and scan with one built PyAhead distribution",
    )
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--kind", choices=("wheel", "sdist"), required=True)
    parser.add_argument("--timeout", type=_positive_timeout, default=300.0)
    parser.add_argument(
        "--installer-cache",
        type=Path,
        help=(
            "operator-authorized uv cache; optional for online preparation and "
            "required with --offline"
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help=(
            "forbid network and configuration; install only from the local "
            "candidate and --installer-cache"
        ),
    )
    return parser


def _validated_installer_policy(
    value: Path | None,
    *,
    offline: bool,
) -> _InstallerPolicy:
    if value is not None:
        installer_cache = value.resolve()
        if not installer_cache.is_dir():
            message = "--installer-cache must name an existing directory"
            raise InstallSmokeError(message)
        return _InstallerPolicy(offline=offline, cache=installer_cache)
    if offline:
        message = "--offline requires --installer-cache"
        raise InstallSmokeError(message)
    return _InstallerPolicy(offline=False, cache=None)


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
        policy = _validated_installer_policy(
            arguments.installer_cache,
            offline=arguments.offline,
        )
        _smoke(
            artifact,
            version=version,
            timeout=arguments.timeout,
            policy=policy,
        )
    except _SanitizedInstallSmokeError as error:
        sys.stderr.write(
            f"install smoke failed: {_bounded_terminal_detail(str(error))}\n"
        )
        return 1
    except (InstallSmokeError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write(f"install smoke failed: {_error_detail(str(error))}\n")
        return 1
    sys.stdout.write(
        f"{arguments.kind} install smoke passed for pyahead {_error_detail(version)}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
