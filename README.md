# PyAhead

PyAhead is intended to become a repository-level Python compatibility
forecaster. Given a project's oldest supported Python version, it will show an
evidence-backed timeline of known compatibility concerns in later Python
releases. The complete product and technical contract is in
[`docs/design.md`](docs/design.md).

## Status

The repository is at milestone M1: the end-to-end static-analysis slice. It can
scan Python source for exact imports of the bundled `cgi` module rule and render
deterministic text or JSON with authoritative timeline sources:

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

M1 deliberately has one registry rule and one matcher kind. It does not yet
match qualified references or calls, evaluate version guards, respect project
configuration or `.gitignore`, emit SARIF, manage baselines or suppressions,
execute target code, access the network while scanning, or provide a hosted
service. Those capabilities belong to later milestones in the design.

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
