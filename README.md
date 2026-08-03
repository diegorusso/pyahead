# PyAhead

PyAhead is intended to become a repository-level Python compatibility
forecaster. Given a project's oldest supported Python version, it will show an
evidence-backed timeline of known compatibility concerns in later Python
releases. The complete product and technical contract is in
[`docs/design.md`](docs/design.md).

## Status

The repository is at milestone M5: CPython registry curation. It can scan
Python source with the bundled, source-linked CPython rules and render
deterministic grouped text, JSON, or SARIF 2.1.0 with one multi-state finding
per matched construct:

```console
pyahead check . --baseline-python 3.11 --horizon-python 3.13
```

Strict `[tool.pyahead]` configuration can supply the policy and discovery
settings. When the baseline is omitted, PyAhead can infer the lowest supported
registry minor from `[project].requires-python` and records that provenance in
the report. Includes, excludes, hierarchical `.gitignore` rules, source roots,
bounded file size, and the no-directory-symlink policy are deterministic. An
explicit empty `source-roots` list is authoritative and disables project-module
shadow inference; it does not fall back to conventional root and `src` layouts.

CI can write a report atomically and adopt existing findings as a baseline:

```console
pyahead check --format sarif --output pyahead.sarif
pyahead baseline create --output .pyahead-baseline.json
pyahead check --baseline-file .pyahead-baseline.json --fail-new-only
```

Relative report-output, baseline-input, and baseline-creation paths are resolved
beneath the selected project root, including when the command starts in a
nested directory. Output paths that escape through `..` or a symlink are
rejected.

Inline `# pyahead: ignore[CPY0001] -- reason` comments and configured per-file
ignores are rule-specific. Unknown rule IDs remain visible diagnostics rather
than silently suppressing findings.

Exit code 1 means an unsuppressed finding met the configured `fail-on` gate; 2
means invalid input, 3 means analysis was incomplete, and 4 means an internal
failure. A clean exit is not proof of compatibility.

M1 indexes conventional repository-root and `src/` runtime modules before
classifying imports. Competing project modules are shown as analysis inferences
instead of high-confidence standard-library findings. Source reads are limited
to regular files no larger than 2 MiB; skipped entries make the scan incomplete.

Common import-derived `sys.version_info` comparisons, three-valued Boolean
guards, nested `if`/`elif` branches, `typing.TYPE_CHECKING`, and `.pyi` typing
contexts narrow findings conservatively. Unknown conditions enter both
branches, and patch-level guards remain unknown with a visible analysis
inference rather than being rounded to a minor version.

The strict registry supports release metadata, indexed module imports,
qualified references and calls, call shapes, literal dynamic imports, and a
fixed whitelist of built-in syntax patterns. Registry data can be validated,
listed, and explained without scanning a repository:

```console
pyahead registry validate
pyahead registry coverage
pyahead registry list
pyahead explain CPY0001
```

The M5 snapshot classifies selected entries from PEP 594, the Python 3.12,
3.13, and 3.14 removal notes, and the centralized deprecation index. Coverage
manifests distinguish implemented rules from partial receiver-type patterns,
runtime-only evidence, C API roadmap work, duplicates, and entries outside the
Python-source alpha. `registry coverage` reports these classifications and
fails validation when a rule reference is missing or a curated rule has no
implemented or partial source entry.

M5 does not execute target code, access the network while scanning, infer
general receiver types, analyse C extensions, or provide a hosted service.
Version helpers, user-defined constants, and general control flow outside the
documented lexical guard grammar remain unknown. Those capabilities belong to
later milestones in the design.

Milestone M1.5 adds repository development automation without changing those
product capabilities. Maintainers can use the resumable, independently verified
milestone controller described in [`docs/autopilot.md`](docs/autopilot.md) for
M2 onward.

## Development

PyAhead requires Python 3.11 or newer. The development environment and lockfile
are managed with [uv](https://docs.astral.sh/uv/):

```console
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv build
uv run pyahead --version
```

See [`docs/contributing.md`](docs/contributing.md) before proposing a change.
Installing a built distribution does not require uv; packaging uses Hatchling
through the standard Python build interface.

To inspect the next automated development range without starting Codex or
changing Git:

```console
python scripts/autopilot.py doctor
python scripts/autopilot.py plan --from M2 --through M6
python scripts/autopilot.py run --from M2 --through M6 --dry-run
```

## License

PyAhead is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
