# PyAhead

PyAhead is intended to become a repository-level Python compatibility
forecaster. Given a project's oldest supported Python version, it will show an
evidence-backed timeline of known compatibility concerns in later Python
releases. The complete product and technical contract is in
[`docs/design.md`](docs/design.md).

## Status

The repository is at milestone M3: version timelines and lexical reachability.
It can scan Python source with the bundled `cgi` rule and render deterministic,
grouped text or JSON with authoritative sources and one multi-state finding per
matched construct:

```console
pyahead check . --baseline-python 3.11 --horizon-python 3.13
```

Exit code 1 means a breaking finding met the current fixed gate; 2 means invalid
input, 3 means analysis was incomplete, and 4 means an internal failure. A clean
exit is not proof of compatibility.

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
pyahead registry list
pyahead explain CPY0001
```

M3 does not yet respect project configuration or `.gitignore`, emit SARIF,
manage baselines or suppressions, execute target code, access the network while
scanning, or provide a hosted service. Version helpers, user-defined constants,
and general control flow outside the documented lexical guard grammar remain
unknown. Those capabilities belong to later milestones in the design.

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
