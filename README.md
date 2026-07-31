# PyAhead

PyAhead is intended to become a repository-level Python compatibility
forecaster. Given a project's oldest supported Python version, it will show an
evidence-backed timeline of known compatibility concerns in later Python
releases. The complete product and technical contract is in
[`docs/design.md`](docs/design.md).

## Status

The repository is at milestone M0: repository bootstrap. The package currently
provides only a version command:

```console
pyahead --version
```

PyAhead does not yet analyse repositories, load a compatibility registry,
prove compatibility, execute test suites, or provide a hosted service. Those
capabilities belong to later milestones in the design.

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

## License

PyAhead is licensed under the Apache License 2.0. See [`LICENSE`](LICENSE).
