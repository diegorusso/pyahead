"""Release-install smoke isolation and credential-safety tests."""

# ruff: noqa: FBT001, SLF001

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from pyahead._human_text import escape_terminal_text
from scripts import install_smoke

_PUBLIC_INDEX = "https://pypi.org/simple"
_INSTALL_COMMAND_COUNT = 2
_DEFAULT_TIMEOUT = 300.0
_MULTI_FIELD_REDACTIONS = 2


def _write_project_metadata(repository: Path, contents: bytes) -> Path:
    metadata = repository / "src" / "pyahead" / "__init__.py"
    metadata.parent.mkdir(parents=True)
    metadata.write_bytes(contents)
    return metadata


@pytest.mark.parametrize(
    "contents",
    [
        b'__version__ = "\xff"\n',
        (
            b'__version__ = "0.1.0a2"\n'
            b"github_pat_SyntheticMetadata123 " + bytes((0x1B,)) + b" FORGED\n"
        ),
    ],
    ids=("invalid-utf8", "credential-bearing-syntax"),
)
def test_project_version_rejects_malformed_metadata_without_retaining_source(
    tmp_path: Path,
    contents: bytes,
) -> None:
    """Decode and parse failures expose only the fixed metadata diagnostic."""
    _write_project_metadata(tmp_path, contents)

    with pytest.raises(
        install_smoke.InstallSmokeError,
        match=r"^unable to read the project version$",
    ) as captured:
        install_smoke._project_version(tmp_path)

    assert str(captured.value) == "unable to read the project version"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_install_smoke_parser_redacts_credential_bearing_invalid_argument(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Caller credentials cannot survive an argparse choice diagnostic."""
    credential = "ghp_SyntheticParserSecret123"

    with pytest.raises(SystemExit, match="2"):
        install_smoke._parser().parse_args(["--kind", credential])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert credential not in captured.err
    assert "[REDACTED]" in captured.err


def test_child_environment_is_an_explicit_allowlist(tmp_path: Path) -> None:
    """Installer, Python, proxy, and credential settings cannot cross the boundary."""
    forbidden = {
        "ALL_PROXY",
        "AWS_SECRET_ACCESS_KEY",
        "CONDA_PREFIX",
        "CURL_CA_BUNDLE",
        "FUTURE_CREDENTIAL",
        "GH_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NETRC",
        "PIP_CACHE_DIR",
        "PIP_CERT",
        "PIP_CLIENT_CERT",
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_PROXY",
        "PIP_TRUSTED_HOST",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "TWINE_PASSWORD",
        "UV_CACHE_DIR",
        "UV_CONFIG_FILE",
        "UV_CREDENTIALS_DIR",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_INSECURE_HOST",
        "UV_PROJECT_ENVIRONMENT",
        "UV_PYTHON",
        "VIRTUAL_ENV",
    }
    source = {
        "PATH": os.defpath,
        "LANG": "en_GB.UTF-8",
        "PIP_CONFIG_FILE": "synthetic-secret-sentinel",
        "PIP_KEYRING_PROVIDER": "synthetic-secret-sentinel",
        "SYSTEMROOT": "platform-root",
        "UV_KEYRING_PROVIDER": "synthetic-secret-sentinel",
        **dict.fromkeys(forbidden, "synthetic-secret-sentinel"),
    }

    environment = install_smoke._clean_environment(
        root=tmp_path / "run",
        policy=install_smoke._InstallerPolicy(offline=False, cache=None),
        source=source,
    )

    expected = {
        "APPDATA",
        "HOME",
        "LANG",
        "LOCALAPPDATA",
        "PATH",
        "PIP_CONFIG_FILE",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_KEYRING_PROVIDER",
        "PIP_NO_CACHE_DIR",
        "PIP_NO_INPUT",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONUTF8",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "UV_KEYRING_PROVIDER",
        "UV_NO_CACHE",
        "UV_NO_CONFIG",
        "UV_NO_PROGRESS",
        "UV_PYTHON_DOWNLOADS",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    }
    assert set(environment) == expected
    assert all(value != "synthetic-secret-sentinel" for value in environment.values())
    assert not forbidden.intersection(environment)
    assert environment["PIP_CONFIG_FILE"] == os.devnull
    for name in (
        "APPDATA",
        "HOME",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
    ):
        Path(environment[name]).relative_to(tmp_path / "run")

    offline = install_smoke._clean_environment(
        root=tmp_path / "offline",
        policy=install_smoke._InstallerPolicy(
            offline=True,
            cache=tmp_path / "installer-cache",
        ),
        source=source,
    )
    assert set(offline) == (expected - {"UV_NO_CACHE"}) | {
        "PIP_NO_INDEX",
        "UV_OFFLINE",
    }
    online_cache = install_smoke._clean_environment(
        root=tmp_path / "online-cache",
        policy=install_smoke._InstallerPolicy(
            offline=False,
            cache=tmp_path / "installer-cache",
        ),
        source=source,
    )
    assert set(online_cache) == expected - {"UV_NO_CACHE"}


@pytest.mark.parametrize(
    ("offline", "use_cache"),
    [(False, False), (False, True), (True, True)],
)
def test_uv_installer_commands_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline: bool,
    use_cache: bool,
) -> None:
    """The uv installer gets explicit config, index, cache, and network policy."""
    uv = tmp_path / "tools" / "uv"
    uv.parent.mkdir()
    uv.touch()
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    environment = {"PATH": str(uv.parent)}
    installer_cache = tmp_path / "installer-cache" if use_cache else None
    policy = install_smoke._InstallerPolicy(
        offline=offline,
        cache=installer_cache,
    )

    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        environments.append(cast("dict[str, str]", options["environment"]))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(
        install_smoke.shutil, "which", lambda *_args, **_kwargs: str(uv)
    )
    monkeypatch.setattr(install_smoke, "_run", fake_run)

    install_smoke._install(
        tmp_path / "candidate.whl",
        tmp_path / "environment",
        environment=environment,
        timeout=1.0,
        policy=policy,
    )

    assert len(commands) == _INSTALL_COMMAND_COUNT
    assert environments == [environment, environment]
    for command in commands:
        assert command[0] == str(uv.resolve())
        assert "--no-config" in command
        assert "--no-python-downloads" in command
        assert ("--offline" in command) is offline
        assert ("--no-cache" in command) is not use_cache
        assert ("--cache-dir" in command) is use_cache
        if installer_cache is not None:
            assert command[command.index("--cache-dir") + 1] == str(installer_cache)
    assert "--no-project" in commands[0]
    install = commands[1]
    assert install[install.index("--keyring-provider") + 1] == "disabled"
    assert "--no-sources" in install
    assert install[install.index("--default-index") + 1] == _PUBLIC_INDEX
    if offline:
        assert "--no-index" not in install
        assert "--no-deps" not in install
        assert "--no-build-isolation" not in install
    else:
        assert "--no-index" not in install


def test_pip_fallback_commands_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pip fallback ignores ambient config and receives explicit source policy."""
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    environment = {"PATH": os.defpath}

    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        environments.append(cast("dict[str, str]", options["environment"]))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(install_smoke.shutil, "which", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(install_smoke, "_run", fake_run)

    install_smoke._install(
        tmp_path / "candidate.tar.gz",
        tmp_path / "environment",
        environment=environment,
        timeout=1.0,
        policy=install_smoke._InstallerPolicy(offline=False, cache=None),
    )

    assert commands[0][1:4] == ["-I", "-m", "venv"]
    assert environments == [environment, environment]
    install = commands[1]
    assert install[1:5] == ["-I", "-m", "pip", "--isolated"]
    assert "--disable-pip-version-check" in install
    assert "--no-input" in install
    assert "--no-cache-dir" in install
    assert install[install.index("--keyring-provider") + 1] == "disabled"
    assert install[install.index("--index-url") + 1] == _PUBLIC_INDEX


@pytest.mark.parametrize("offline", [False, True])
def test_pip_fallback_with_installer_cache_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline: bool,
) -> None:
    """An explicit uv cache is never misinterpreted as a pip cache."""
    monkeypatch.setattr(install_smoke.shutil, "which", lambda *_args, **_kwargs: None)

    with pytest.raises(install_smoke.InstallSmokeError, match="requires uv"):
        install_smoke._install(
            tmp_path / "candidate.whl",
            tmp_path / "environment",
            environment={"PATH": os.defpath},
            timeout=1.0,
            policy=install_smoke._InstallerPolicy(
                offline=offline,
                cache=tmp_path / "cache",
            ),
        )


def test_origin_child_receives_the_same_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed-origin validation cannot bypass process isolation."""
    environment_dir = tmp_path / "environment"
    installed = environment_dir / "site" / "pyahead" / "__init__.py"
    installed.parent.mkdir(parents=True)
    installed.touch()
    environment = {"PATH": os.defpath, "HOME": str(tmp_path / "home")}
    observed: list[dict[str, str]] = []

    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        observed.append(cast("dict[str, str]", options["environment"]))
        return subprocess.CompletedProcess(
            command, 0, stdout=f"{installed}\n", stderr=""
        )

    monkeypatch.setattr(install_smoke, "_run", fake_run)

    install_smoke._validate_installed_origin(
        environment_dir,
        environment=environment,
        timeout=1.0,
    )

    assert observed == [environment]


@pytest.mark.parametrize(
    ("payload", "secrets"),
    [
        (
            "https://smoke-user:smoke-pass@example.invalid/simple",
            ("smoke-user", "smoke-pass"),
        ),
        (
            "https://smoke%40user:smoke%2Fpass@example.invalid/simple",
            ("smoke%40user", "smoke%2Fpass"),
        ),
        (
            r"https:\/\/escaped-user:escaped-pass@example.invalid/simple",
            ("escaped-user", "escaped-pass"),
        ),
        (
            "https://split-user:split-pass-left\nsplit-pass-right@example.invalid/simple",
            ("split-user", "split-pass-left", "split-pass-right"),
        ),
        (
            "https://at-user:pa@ss@example.invalid/simple",
            ("at-user", "pa@ss"),
        ),
        ("Authorization: Bearer synthetic-bearer-value", ("synthetic-bearer-value",)),
        (
            "Authorization:\x1b Bearer synthetic-control-bearer",
            ("synthetic-control-bearer",),
        ),
        (
            "https://example.invalid/?token=split-query-left\nsplit-query-right&safe=keep",
            ("split-query-left", "split-query-right"),
        ),
        ("token=synthetic-assignment-value", ("synthetic-assignment-value",)),
        ("AWS_SECRET_ACCESS_KEY=synthetic-aws-value", ("synthetic-aws-value",)),
        ("GH_TOKEN=synthetic-gh-value", ("synthetic-gh-value",)),
        ("SECRET=synthetic-plain-secret", ("synthetic-plain-secret",)),
        ("MY_SECRET=synthetic-custom-secret", ("synthetic-custom-secret",)),
        ("API_SECRET=synthetic-api-secret", ("synthetic-api-secret",)),
        ("SECRET_KEY=synthetic-key-secret", ("synthetic-key-secret",)),
        ("AUTH=Bearer synthetic-auth-secret", ("synthetic-auth-secret",)),
        ("PASSWORD=prefix&synthetic-ampersand safe", ("synthetic-ampersand",)),
        ("SECRET=prefix#synthetic-fragment safe", ("synthetic-fragment",)),
        (r"TOKEN=prefix\synthetic-backslash safe", ("synthetic-backslash",)),
        ('TOKEN=prefix"synthetic-double safe', ("synthetic-double",)),
        ("TOKEN=prefix'synthetic-single safe", ("synthetic-single",)),
        (
            "TOKEN=[REDACTED]&synthetic-marker-ampersand safe",
            ("synthetic-marker-ampersand",),
        ),
        (
            "PASSWORD=[REDACTED] synthetic-marker-space",
            ("synthetic-marker-space",),
        ),
        (
            "SECRET=[REDACTED]#synthetic-marker-fragment",
            ("synthetic-marker-fragment",),
        ),
        (
            r"TOKEN=[REDACTED]\synthetic-marker-backslash",
            ("synthetic-marker-backslash",),
        ),
        ("PIP_PASSWORD=synthetic-pip-value", ("synthetic-pip-value",)),
        ("TWINE_PASSWORD=synthetic-twine-value", ("synthetic-twine-value",)),
        (
            '{"Authorization": "Bearer synthetic-json-auth"}',
            ("synthetic-json-auth",),
        ),
        (
            "{'proxy-authorization': 'Basic synthetic-repr-auth'}",
            ("synthetic-repr-auth",),
        ),
        (
            '{"AWS_SECRET_ACCESS_KEY":"synthetic-json-secret"}',
            ("synthetic-json-secret",),
        ),
        (
            "{'token': 'synthetic-repr-secret'}",
            ("synthetic-repr-secret",),
        ),
        (
            r"{\"Authorization\": \"Bearer synthetic-escaped-auth\"}",
            ("synthetic-escaped-auth",),
        ),
        (
            r"{\"token\": \"synthetic-escaped-secret\"}",
            ("synthetic-escaped-secret",),
        ),
        (
            "{'Authorization': b'Bearer synthetic-bytes-auth'}",
            ("synthetic-bytes-auth",),
        ),
        (
            '{b"token": b"synthetic-bytes-key-secret"}',
            ("synthetic-bytes-key-secret",),
        ),
        (
            "{br'token': rb'synthetic-raw-bytes-secret'}",
            ("synthetic-raw-bytes-secret",),
        ),
        (
            "{u'token': r'synthetic-prefixed-secret'}",
            ("synthetic-prefixed-secret",),
        ),
        (
            'headers=[("Authorization", "Bearer synthetic-tuple-secret")]',
            ("synthetic-tuple-secret",),
        ),
        (
            r"{\"token\": \"synthetic-before-\\\"quoted\\\"-after\"}",
            ("synthetic-before", "quoted", "after"),
        ),
        (
            'token="synthetic-unterminated secret suffix',
            ("synthetic-unterminated", "secret", "suffix"),
        ),
        ("github_pat_SyntheticOnly123", ("github_pat_SyntheticOnly123",)),
        ("pypi-SyntheticOnly123", ("pypi-SyntheticOnly123",)),
    ],
)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_child_failure_redacts_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: str,
    secrets: tuple[str, ...],
    stream: str,
) -> None:
    """Synthetic credentials never survive retained child diagnostics."""
    result = subprocess.CompletedProcess(
        args=["installer"],
        returncode=1,
        stdout=payload if stream == "stdout" else "",
        stderr=payload if stream == "stderr" else "",
    )
    monkeypatch.setattr(
        install_smoke.subprocess, "run", lambda *_args, **_kwargs: result
    )

    with pytest.raises(install_smoke.InstallSmokeError) as captured:
        install_smoke._run(
            ["installer", "install"],
            cwd=tmp_path,
            environment={},
            timeout=1.0,
        )

    rendered = str(captured.value)
    assert "[REDACTED]" in rendered
    assert all(secret not in rendered for secret in secrets)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_child_failure_traceback_does_not_retain_raw_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The raised error's ``_run`` frame cannot retain raw child diagnostics."""
    secret = "synthetic-traceback-secret"  # noqa: S105 - synthetic fixture.
    result = subprocess.CompletedProcess(
        args=["installer"],
        returncode=1,
        stdout="",
        stderr=f"TOKEN={secret}",
    )
    monkeypatch.setattr(
        install_smoke.subprocess, "run", lambda *_args, **_kwargs: result
    )

    with pytest.raises(install_smoke.InstallSmokeError) as captured:
        install_smoke._run(
            ["installer"],
            cwd=tmp_path,
            environment={},
            timeout=1.0,
        )

    traceback = captured.value.__traceback__
    run_frames = []
    while traceback is not None:
        if traceback.tb_frame.f_code.co_name == "_run":
            run_frames.append(traceback.tb_frame.f_locals)
        traceback = traceback.tb_next
    assert run_frames
    assert all(secret not in repr(frame) for frame in run_frames)


def test_redaction_handles_multiple_fields_without_changing_safe_text() -> None:
    """Nested diagnostics redact every credential and preserve ordinary fields."""
    payload = (
        r"prefix {\"token\": \"synthetic-first\", "
        r"\"password\": b\"synthetic-second\", "
        r"\"safe\": \"ordinary-value\"} suffix"
    )

    redacted = install_smoke._redact_credentials(payload)

    assert redacted.count("[REDACTED]") == _MULTI_FIELD_REDACTIONS
    assert "synthetic-first" not in redacted
    assert "synthetic-second" not in redacted
    assert "prefix" in redacted
    assert r"\"safe\": \"ordinary-value\"" in redacted
    assert "suffix" in redacted
    assert install_smoke._redact_credentials('monkey="banana"') == 'monkey="banana"'
    safe_url = "https://example.invalid?email=user@example.org#contact"
    assert install_smoke._redact_credentials(safe_url) == safe_url
    query = "before https://host/x?token=query-secret&safe=keep after"
    assert install_smoke._redact_credentials(query) == (
        "before https://host/x?token=[REDACTED]&safe=keep after"
    )
    assert install_smoke._redact_credentials(
        install_smoke._redact_credentials(query)
    ) == install_smoke._redact_credentials(query)


def test_error_detail_redacts_structural_credentials_before_control_escaping() -> None:
    """Install stderr preserves safe fields but never a split or escaped secret."""
    payload = (
        r"{\"Authorization\":\"Bearer escaped-detail-secret\","
        r"\"safe\":\"keep-json\"}"
        " Authorization:\x1b Bearer control-detail-secret "
        r"https:\/\/detail-user:detail-pass@example.invalid/path "
        "https://example.invalid/?token=query-left\nquery-right&safe=keep-query"
    )

    detail = install_smoke._error_detail(payload)

    for secret in (
        "escaped-detail-secret",
        "control-detail-secret",
        "detail-user",
        "detail-pass",
        "query-left",
        "query-right",
    ):
        assert secret not in detail
    assert "keep-json" in detail
    assert "keep-query" in detail
    assert "\x1b" not in detail
    assert "\\u000a" not in detail


@pytest.mark.parametrize(
    "control",
    ["\x1b", r"\u001b"],
    ids=("raw", "json-escaped"),
)
@pytest.mark.parametrize(
    ("credential_name", "value"),
    [
        ("token", "synthetic-name-secret"),
        ("Authorization", "Bearer synthetic-authorization-secret"),
        ("proxy-authorization", "Basic synthetic-proxy-secret"),
        ("password", "synthetic-password-secret"),
        ("passwd", "synthetic-passwd-secret"),
        ("secret_access_key", "synthetic-secret-access-key"),
        ("secret-key", "synthetic-secret-key"),
        ("auth", "synthetic-auth-secret"),
        ("access_key", "synthetic-access-key"),
        ("api-key", "synthetic-api-key"),
        ("client_secret", "synthetic-client-secret"),
        ("credential", "synthetic-credential-secret"),
        ("AWS_SECRET_ACCESS_KEY", "synthetic-access-key-secret"),
        ("GH_TOKEN", "synthetic-gh-secret"),
        ("PIP_PASSWORD", "synthetic-pip-secret"),
    ],
)
def test_error_detail_redacts_every_control_split_in_credential_names(
    control: str,
    credential_name: str,
    value: str,
) -> None:
    """Raw and serialized controls cannot split a recognized credential name."""
    secret = value.rsplit(maxsplit=1)[-1]
    for position in range(1, len(credential_name) + 1):
        split_name = (
            f"{credential_name[:position]}{control}{credential_name[position:]}"
        )

        detail = install_smoke._error_detail(f"{split_name}={value}")

        assert secret not in detail
        assert "[REDACTED]" in detail


@pytest.mark.parametrize(
    "control",
    ["\x1b", r"\u001b"],
    ids=("raw", "json-escaped"),
)
@pytest.mark.parametrize(
    ("prefix", "body"),
    [
        ("github_pat_", "SyntheticGithubToken123"),
        ("ghp_", "SyntheticGhToken123"),
        ("pypi-", "SyntheticPypiToken123"),
        ("sk-", "SyntheticApiToken123"),
        ("AKIA", "0123456789ABCDEF"),
    ],
)
def test_error_detail_redacts_every_control_split_in_literal_token_prefixes(
    control: str,
    prefix: str,
    body: str,
) -> None:
    """Raw and serialized controls cannot split a recognized token prefix."""
    for position in range(1, len(prefix) + 1):
        token = f"{prefix[:position]}{control}{prefix[position:]}{body}"

        detail = install_smoke._error_detail(token)

        assert body not in detail
        assert detail == "[REDACTED]"


@pytest.mark.parametrize(
    "control",
    ["\x1b", r"\u001b"],
    ids=("raw", "json-escaped"),
)
@pytest.mark.parametrize(
    ("syntax", "tail", "secrets"),
    [
        (
            "https://",
            "synthetic-user:synthetic-password@example.invalid",
            ("synthetic-user", "synthetic-password"),
        ),
        (
            "?token=",
            "synthetic-query-secret&safe=keep",
            ("synthetic-query-secret",),
        ),
    ],
)
def test_error_detail_redacts_every_control_split_in_credential_syntax(
    control: str,
    syntax: str,
    tail: str,
    secrets: tuple[str, ...],
) -> None:
    """Unsafe controls cannot split URL or query credential delimiters."""
    for position in range(1, len(syntax) + 1):
        split_syntax = f"{syntax[:position]}{control}{syntax[position:]}"

        detail = install_smoke._error_detail(f"{split_syntax}{tail}")

        assert not any(secret in detail for secret in secrets)
        assert "[REDACTED]" in detail


def test_error_detail_fails_closed_at_bounded_redaction_cutoff() -> None:
    """A long URL authority cannot hide its delimiter beyond the scan ceiling."""
    detail = install_smoke._error_detail(
        "prefix https://bounded-user:bounded-pass"
        + ("x" * install_smoke._MAX_REDACTION_SCAN)
        + "@example.invalid"
    )

    assert len(detail) <= install_smoke._MAX_ERROR_DETAIL + len("...")
    assert "bounded-user" not in detail
    assert "bounded-pass" not in detail
    assert "[REDACTED]" in detail


def test_raw_redaction_marker_cannot_hide_a_later_secret() -> None:
    """Only query-pass provenance can make an existing marker trustworthy."""
    payload = "TOKEN=[REDACTED] synthetic-marker-secret"

    assert install_smoke._redact_credentials(payload) == "TOKEN=[REDACTED]"


@pytest.mark.parametrize("serialization_depth", range(4))
def test_redaction_handles_trailing_backslashes_and_later_fields(
    serialization_depth: int,
) -> None:
    """A trailing backslash cannot make a later credential escape redaction."""
    payload = json.dumps({"token": "synthetic-first\\", "password": "synthetic-second"})
    for _ in range(serialization_depth):
        payload = json.dumps(payload)

    redacted = install_smoke._redact_credentials(payload)

    assert redacted.count("[REDACTED]") == _MULTI_FIELD_REDACTIONS
    assert "synthetic-first" not in redacted
    assert "synthetic-second" not in redacted


def test_redaction_handles_large_noncredential_backslash_runs() -> None:
    """Scanning unrelated escaped text performs one linear credential-name search."""
    payload = "\\" * 100_000

    assert install_smoke._redact_credentials(payload) == payload


@pytest.mark.parametrize(
    ("payload", "safe_fragment"),
    [
        (
            '{"url":"https://host/x?token=query-secret","safe":"keep"}',
            ',"safe":"keep"}',
        ),
        (
            "{'url':'https://host/x?token=query-secret','safe':'keep'}",
            ",'safe':'keep'}",
        ),
        (
            r"{\"url\":\"https://host/x?token=query-secret\",\"safe\":\"keep\"}",
            r"\",\"safe\":\"keep\"}",
        ),
    ],
)
def test_query_redaction_preserves_structured_diagnostic_fields(
    payload: str,
    safe_fragment: str,
) -> None:
    """Query redaction stops at raw and escaped diagnostic string wrappers."""
    redacted = install_smoke._redact_credentials(payload)

    assert "query-secret" not in redacted
    assert "?token=[REDACTED]" in redacted
    assert safe_fragment in redacted


@pytest.mark.parametrize(
    "payload",
    [
        r"Authorization: Bearer prefix\synthetic-backslash, safe=keep",
        "Authorization: Bearer prefix&synthetic-ampersand, safe=keep",
        "Authorization: Bearer prefix#synthetic-fragment, safe=keep",
        'Authorization: Bearer prefix"synthetic-double, safe=keep',
        "Authorization: Bearer prefix'synthetic-single, safe=keep",
    ],
)
def test_authorization_redaction_keeps_later_structured_diagnostics(
    payload: str,
) -> None:
    """Credential punctuation cannot leak a suffix or erase a later field."""
    redacted = install_smoke._redact_credentials(payload)

    assert redacted == "Authorization:[REDACTED], safe=keep"


@pytest.mark.parametrize("failure", ["timeout", "os-error"])
def test_process_exceptions_are_bounded_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """Redaction happens before bounding for exceptional subprocess exits."""
    userinfo = "boundary-user:boundary-password"
    payload = f"{'x' * 1_990} https://{userinfo}@example.invalid/simple"

    def fail(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(["installer"], 1.0, stderr=payload.encode())
        message = f"token=synthetic-os-error {payload}"
        raise OSError(message)

    monkeypatch.setattr(install_smoke.subprocess, "run", fail)

    with pytest.raises(install_smoke.InstallSmokeError) as captured:
        install_smoke._run(
            ["installer"],
            cwd=tmp_path,
            environment={},
            timeout=1.0,
        )

    rendered = str(captured.value)
    assert userinfo not in rendered
    assert "synthetic-os-error" not in rendered
    assert len(rendered) <= install_smoke._MAX_ERROR_DETAIL + 100
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_bounded_terminal_detail_retains_edge_controls_visibly() -> None:
    """Leading and trailing controls remain explicit diagnostic evidence."""
    hostile = "\n\t\u2028detail\r\x1b\u2029"

    rendered = install_smoke._bounded_terminal_detail(hostile)

    assert rendered == escape_terminal_text(hostile)
    assert "detail" in rendered
    assert not any(
        control in rendered for control in hostile if not control.isprintable()
    )


def test_main_redacts_outer_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Errors outside child execution pass through the same redaction boundary."""
    userinfo = "outer-user:outer-password"
    token = "github_pat_SyntheticOuter123"  # noqa: S105 - synthetic fixture.

    def fail(_repository: Path) -> str:
        message = f"https://{userinfo}@example.invalid token={token}"
        raise OSError(message)

    monkeypatch.setattr(install_smoke, "_project_version", fail)

    assert install_smoke.main(["--kind", "wheel"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "[REDACTED]" in captured.err
    assert userinfo not in captured.err
    assert token not in captured.err


def test_main_does_not_resanitize_child_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Out-of-band child provenance preserves safe text after one redaction pass."""
    result = subprocess.CompletedProcess(
        args=["installer"],
        returncode=1,
        stdout="",
        stderr="TOKEN=synthetic-child-secret safe=keep",
    )
    artifact = tmp_path / "candidate.whl"
    artifact.touch()
    monkeypatch.setattr(
        install_smoke.subprocess, "run", lambda *_args, **_kwargs: result
    )
    monkeypatch.setattr(install_smoke, "_project_version", lambda _root: "0.1.0a2")
    monkeypatch.setattr(
        install_smoke,
        "_select_artifact",
        lambda _dist, _kind, _version: artifact,
    )

    def fail_smoke(
        _artifact: Path,
        *,
        version: str,
        timeout: float,
        policy: install_smoke._InstallerPolicy,
    ) -> None:
        assert version == "0.1.0a2"
        assert timeout == _DEFAULT_TIMEOUT
        assert policy == install_smoke._InstallerPolicy(offline=False, cache=None)
        install_smoke._run(
            ["installer"],
            cwd=tmp_path,
            environment={},
            timeout=1.0,
        )

    monkeypatch.setattr(install_smoke, "_smoke", fail_smoke)

    assert install_smoke.main(["--kind", "wheel"]) == 1
    captured = capsys.readouterr()
    assert "synthetic-child-secret" not in captured.err
    assert "TOKEN=[REDACTED] safe=keep" in captured.err


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--kind", "wheel", "--offline"], "requires --installer-cache"),
        (
            ["--kind", "wheel", "--installer-cache", "missing"],
            "must name an existing directory",
        ),
        (
            ["--kind", "wheel", "--offline", "--installer-cache", "missing"],
            "must name an existing directory",
        ),
    ],
)
def test_cli_rejects_unproven_installer_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    message: str,
) -> None:
    """Offline mode cannot silently adopt ambient or nonexistent cache state."""
    artifact = tmp_path / "candidate.whl"
    artifact.touch()
    monkeypatch.setattr(install_smoke, "_project_version", lambda _root: "0.1.0a2")
    monkeypatch.setattr(
        install_smoke,
        "_select_artifact",
        lambda _dist, _kind, _version: artifact,
    )

    assert install_smoke.main(arguments) == 1
    captured = capsys.readouterr()
    assert message in captured.err


@pytest.mark.parametrize("offline", [False, True])
def test_cli_passes_explicit_cache_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    offline: bool,
) -> None:
    """An existing cache reaches online preparation and offline consumption."""
    artifact = tmp_path / "candidate.whl"
    artifact.touch()
    installer_cache = tmp_path / "installer-cache"
    installer_cache.mkdir()
    observed: list[install_smoke._InstallerPolicy] = []

    def fake_smoke(
        _artifact: Path,
        *,
        version: str,
        timeout: float,
        policy: install_smoke._InstallerPolicy,
    ) -> None:
        assert version == "0.1.0a2"
        assert timeout == _DEFAULT_TIMEOUT
        observed.append(policy)

    monkeypatch.setattr(install_smoke, "_project_version", lambda _root: "0.1.0a2")
    monkeypatch.setattr(
        install_smoke,
        "_select_artifact",
        lambda _dist, _kind, _version: artifact,
    )
    monkeypatch.setattr(install_smoke, "_smoke", fake_smoke)
    arguments = [
        "--kind",
        "wheel",
        "--installer-cache",
        str(installer_cache),
    ]
    if offline:
        arguments.append("--offline")

    assert install_smoke.main(arguments) == 0
    assert observed == [
        install_smoke._InstallerPolicy(
            offline=offline,
            cache=installer_cache.resolve(),
        )
    ]
    assert capsys.readouterr().out == "wheel install smoke passed for pyahead 0.1.0a2\n"


def test_success_output_escapes_a_hostile_project_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A successful smoke keeps project metadata inside the terminal boundary."""
    hostile_version = "0.1\nFORGED\x1b\u2028"
    artifact = tmp_path / "candidate.whl"
    artifact.touch()
    monkeypatch.setattr(
        install_smoke,
        "_project_version",
        lambda _root: hostile_version,
    )
    monkeypatch.setattr(
        install_smoke,
        "_select_artifact",
        lambda _dist, _kind, _version: artifact,
    )
    monkeypatch.setattr(install_smoke, "_smoke", lambda *_args, **_kwargs: None)

    assert install_smoke.main(["--kind", "wheel"]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == (
        "wheel install smoke passed for pyahead "
        f"{escape_terminal_text(hostile_version)}\n"
    )
    assert "\nFORGED" not in captured.out


def test_success_output_redacts_a_credential_shaped_project_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Successful output redacts credentials even in valid version metadata."""
    credential = "ghp_SyntheticVersionSecret123"
    version = f"0.1+{credential}"
    artifact = tmp_path / "candidate.whl"
    artifact.touch()
    monkeypatch.setattr(install_smoke, "_project_version", lambda _root: version)
    monkeypatch.setattr(
        install_smoke,
        "_select_artifact",
        lambda _dist, _kind, _version: artifact,
    )
    monkeypatch.setattr(install_smoke, "_smoke", lambda *_args, **_kwargs: None)

    assert install_smoke.main(["--kind", "wheel"]) == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "wheel install smoke passed for pyahead 0.1+[REDACTED]\n"
    assert credential not in captured.out


def test_invalid_scan_does_not_retain_child_output() -> None:
    """A decoder failure does not retain credential-bearing child output."""
    userinfo = "scan-user:scan-password"

    with pytest.raises(install_smoke.InstallSmokeError) as captured:
        install_smoke._decode_scan(
            f"not-json https://{userinfo}@example.invalid/simple"
        )

    rendered = str(captured.value)
    assert userinfo not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_undecodable_child_output_is_bounded_text(tmp_path: Path) -> None:
    """Invalid child bytes become safe diagnostic text instead of a traceback."""
    code = "import sys; sys.stderr.buffer.write(bytes((0x81,))); raise SystemExit(2)"

    with pytest.raises(install_smoke.InstallSmokeError) as captured:
        install_smoke._run(
            [sys.executable, "-I", "-c", code],
            cwd=tmp_path,
            environment={"PATH": os.defpath},
            timeout=5.0,
        )

    assert "\ufffd" in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize(
    ("offline", "use_cache"),
    [(False, False), (False, True), (True, True)],
)
def test_smoke_orchestration_preserves_artifact_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    offline: bool,
    use_cache: bool,
) -> None:
    """All release modes retain the native launcher and one child boundary."""
    suffix = ".whl" if kind == "wheel" else ".tar.gz"
    artifact = tmp_path / f"candidate{suffix}"
    artifact.touch()
    observed_policies: list[install_smoke._InstallerPolicy] = []
    environments: list[dict[str, str]] = []
    policy = install_smoke._InstallerPolicy(
        offline=offline,
        cache=tmp_path / "installer-cache" if use_cache else None,
    )

    def fake_install(
        _artifact: Path,
        environment_dir: Path,
        *,
        environment: dict[str, str],
        timeout: float,
        policy: install_smoke._InstallerPolicy,
    ) -> None:
        assert timeout == 1.0
        observed_policies.append(policy)
        environments.append(environment)
        launcher = install_smoke._venv_launcher(environment_dir)
        launcher.parent.mkdir(parents=True)
        launcher.touch()

    def fake_origin(
        _environment_dir: Path,
        *,
        environment: dict[str, str],
        timeout: float,
    ) -> None:
        assert timeout == 1.0
        environments.append(environment)

    def fake_run(
        command: list[str],
        **options: object,
    ) -> subprocess.CompletedProcess[str]:
        environments.append(cast("dict[str, str]", options["environment"]))
        if command[-1] == "--version":
            output = "pyahead 0.1.0a2\n"
        elif "check" in command:
            output = json.dumps({"scan": {}, "findings": []})
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(install_smoke, "_install", fake_install)
    monkeypatch.setattr(install_smoke, "_validate_installed_origin", fake_origin)
    monkeypatch.setattr(install_smoke, "_run", fake_run)
    monkeypatch.setattr(install_smoke, "_validate_scan", lambda _document: None)

    install_smoke._smoke(
        artifact,
        version="0.1.0a2",
        timeout=1.0,
        policy=policy,
    )

    assert observed_policies == [policy]
    assert all(environment is environments[0] for environment in environments)
    assert ("UV_OFFLINE" in environments[0]) is offline
    assert ("UV_NO_CACHE" in environments[0]) is not use_cache


def test_native_environment_executable_paths(tmp_path: Path) -> None:
    """Hosted OS jobs exercise the platform's real venv and launcher convention."""
    if os.name == "nt":
        assert install_smoke._venv_python(tmp_path) == tmp_path / "Scripts/python.exe"
        assert (
            install_smoke._venv_launcher(tmp_path) == tmp_path / "Scripts/pyahead.exe"
        )
    else:
        assert install_smoke._venv_python(tmp_path) == tmp_path / "bin/python"
        assert install_smoke._venv_launcher(tmp_path) == tmp_path / "bin/pyahead"
