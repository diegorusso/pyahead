"""Explicit pytest plugin that writes normalized PyAhead warning evidence."""

from __future__ import annotations

import os
import platform
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

import pytest

from pyahead import __version__
from pyahead.evidence import (
    MAX_EVIDENCE_WARNINGS,
    JsonValue,
    render_evidence_document,
    resolve_source_commit,
)
from pyahead.model import ConfigurationError
from pyahead.output import OutputError, write_text_atomic

if TYPE_CHECKING:
    import warnings
    from collections.abc import Generator

_MAX_MESSAGE_LENGTH = 16_384
_MAX_TEXT_LENGTH = 4_096
_MAX_COLLECTED_WARNING_RECORDS = 10_000
_MAX_COLLECTED_WARNING_TEXT_BYTES = 8 * 1024 * 1024
_PLUGIN_NAME = "pyahead-pytest-warning-collector"


@dataclass(frozen=True, order=True)
class _CapturedWarning:
    """Hashable normalized warning data used for occurrence aggregation."""

    kind: str
    category: str
    message: str
    phase: str
    path: PurePosixPath | None
    line: int
    test_node: str | None


def _one_line(value: object, *, limit: int, empty: str) -> str:
    text = " ".join(str(value).splitlines()) or empty
    text = text.replace("\x00", "\\0")
    text = text.encode("utf-8", errors="backslashreplace").decode()
    if len(text) <= limit:
        return text
    marker = "… [truncated]"
    return text[: limit - len(marker)] + marker


def _warning_kind(category: type[Warning]) -> str | None:
    try:
        if issubclass(category, PendingDeprecationWarning):
            return "pending-deprecation-warning"
        if issubclass(category, DeprecationWarning):
            return "deprecation-warning"
    except TypeError:
        return None
    return None


def _category_name(category: type[Warning]) -> str:
    module = category.__module__
    name = category.__qualname__
    return _one_line(
        f"{module}.{name}",
        limit=512,
        empty="builtins.Warning",
    )


def _warning_path(filename: str, root: Path) -> PurePosixPath | None:
    if not filename or (filename.startswith("<") and filename.endswith(">")):
        return None
    candidate = Path(filename)
    selected = candidate if candidate.is_absolute() else root / candidate
    try:
        relative = selected.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    text = relative.as_posix()
    if not text or text == ".":
        return None
    return PurePosixPath(text)


def _output_path(value: str, root: Path) -> Path:
    selected = Path(value)
    if selected == Path("-"):
        message = "--pyahead-evidence must name a file, not stdout"
        raise ConfigurationError(message)
    if not selected.is_absolute():
        selected = root / selected
    try:
        logical = Path(os.path.abspath(selected))  # noqa: PTH100
        logical.relative_to(root)
        logical.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        message = "--pyahead-evidence must remain beneath the pytest root"
        raise ConfigurationError(message) from error
    return logical


class _WarningCollector:
    """Collect only deprecation warnings captured by pytest itself."""

    def __init__(
        self,
        root: Path,
        output: Path,
        source_commit: str,
        *,
        warning_record_limit: int = _MAX_COLLECTED_WARNING_RECORDS,
        warning_text_byte_limit: int = _MAX_COLLECTED_WARNING_TEXT_BYTES,
    ) -> None:
        self._root = root
        self._output = output
        self._source_commit = source_commit
        self._warnings: Counter[_CapturedWarning] = Counter()
        self._warning_record_limit = min(
            warning_record_limit,
            MAX_EVIDENCE_WARNINGS,
        )
        self._warning_text_byte_limit = warning_text_byte_limit
        self._retained_warning_text_bytes = 0
        self._warnings_dropped = 0

    @staticmethod
    def _warning_text_bytes(warning: _CapturedWarning) -> int:
        """Measure normalized variable-size text retained by one record."""
        values = (
            warning.kind,
            warning.category,
            warning.message,
            warning.phase,
            warning.path.as_posix() if warning.path is not None else "",
            warning.test_node or "",
        )
        return sum(len(value.encode("utf-8")) for value in values)

    def pytest_warning_recorded(
        self,
        warning_message: warnings.WarningMessage,
        when: Literal["config", "collect", "runtest"],
        nodeid: str,
        location: tuple[str, int, str] | None,
    ) -> None:
        """Normalize one warning already captured by pytest's warning plugin."""
        del location
        kind = _warning_kind(warning_message.category)
        if kind is None:
            return
        path = _warning_path(warning_message.filename, self._root)
        if path is not None and warning_message.lineno > 0:
            line = warning_message.lineno
        else:
            path = None
            line = 0
        test_node = (
            _one_line(nodeid, limit=_MAX_TEXT_LENGTH, empty="<unknown test>")
            if nodeid
            else None
        )
        warning = _CapturedWarning(
            kind=kind,
            category=_category_name(warning_message.category),
            message=_one_line(
                warning_message.message,
                limit=_MAX_MESSAGE_LENGTH,
                empty="<empty warning message>",
            ),
            phase=when,
            path=path,
            line=line,
            test_node=test_node,
        )
        if warning in self._warnings:
            self._warnings[warning] += 1
            return

        warning_text_bytes = self._warning_text_bytes(warning)
        if (
            len(self._warnings) >= self._warning_record_limit
            or self._retained_warning_text_bytes + warning_text_bytes
            > self._warning_text_byte_limit
        ):
            self._warnings_dropped += 1
            return

        self._warnings[warning] = 1
        self._retained_warning_text_bytes += warning_text_bytes

    def _document(
        self, session: pytest.Session, exitstatus: int
    ) -> dict[str, JsonValue]:
        warning_documents: list[JsonValue] = []
        ordered_warnings = sorted(
            self._warnings,
            key=lambda item: (
                item.phase,
                item.path.as_posix() if item.path is not None else "",
                item.line,
                item.category,
                item.message,
                item.test_node or "",
            ),
        )
        for warning in ordered_warnings:
            document: dict[str, JsonValue] = {
                "category": warning.category,
                "kind": warning.kind,
                "message": warning.message,
                "occurrences": self._warnings[warning],
                "phase": warning.phase,
            }
            if warning.path is not None:
                document["location"] = {
                    "line": warning.line,
                    "path": warning.path.as_posix(),
                }
            if warning.test_node is not None:
                document["test_node"] = warning.test_node
            warning_documents.append(document)
        return {
            "environment": {
                "implementation": sys.implementation.name,
                "platform": sys.platform,
                "python_version": platform.python_version(),
            },
            "provider": {"name": "pytest-warnings", "version": __version__},
            "run": {
                "exit_code": int(exitstatus),
                "framework": "pytest",
                "framework_version": pytest.__version__,
                "tests_collected": session.testscollected,
                "warnings_complete": self._warnings_dropped == 0,
                "warnings_dropped": self._warnings_dropped,
            },
            "schema_version": 1,
            "source": {"commit": self._source_commit},
            "warnings": warning_documents,
        }

    @pytest.hookimpl(wrapper=True, tryfirst=True)
    def pytest_sessionfinish(
        self,
        session: pytest.Session,
        exitstatus: int,
    ) -> Generator[None, object, None]:
        """Write after pytest's warning and terminal wrappers have finalized."""
        del exitstatus
        yield
        try:
            rendered = render_evidence_document(
                self._document(session, int(session.exitstatus))
            )
            write_text_atomic(self._output, rendered, root=self._root)
        except (ConfigurationError, OutputError) as error:
            message = f"pyahead could not write warning evidence: {error}"
            raise pytest.UsageError(message) from error


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register explicit, opt-in warning-evidence collection options."""
    group = parser.getgroup("pyahead")
    group.addoption(
        "--pyahead-evidence",
        dest="pyahead_evidence",
        metavar="PATH",
        help="write versioned pytest warning evidence beneath the pytest root",
    )
    group.addoption(
        "--pyahead-source-commit",
        dest="pyahead_source_commit",
        metavar="SHA",
        help="full source commit (or use PYAHEAD_COMMIT/GITHUB_SHA/CI_COMMIT_SHA)",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Activate the collector only when an artifact destination is explicit."""
    output_value = config.getoption("pyahead_evidence")
    commit_value = config.getoption("pyahead_source_commit")
    if output_value is None:
        if commit_value is not None:
            message = "--pyahead-source-commit requires --pyahead-evidence"
            raise pytest.UsageError(message)
        return
    try:
        root = Path(str(config.rootpath)).resolve(strict=True)
        output = _output_path(str(output_value), root)
        source_commit = resolve_source_commit(commit_value)
    except (ConfigurationError, OSError, RuntimeError) as error:
        raise pytest.UsageError(str(error)) from error
    collector = _WarningCollector(root, output, source_commit)
    config.pluginmanager.register(collector, _PLUGIN_NAME)


__all__ = ["pytest_addoption", "pytest_configure"]
