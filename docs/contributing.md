# Contributing

Read [`design.md`](design.md) before making changes. Each contribution should
implement or review one named milestone and should not include work assigned to
later milestones.

Registry changes must also follow the strict schema, source, timeline, matcher,
and fixture conventions in [`registry-authoring.md`](registry-authoring.md).

Set up the locked development environment and run the complete verification
suite:

```console
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv build
uv run pyahead --version
```

Note: repository-wide coverage is configured with `fail_under=90`, so running a
single test file directly (for example `uv run pytest tests/test_cli.py`) can fail
coverage even if the file itself passes. Use `uv run pytest <file> --no-cov` for
isolated test runs.

Before opening a pull request, also run `git diff --check` and inspect the diff
for generated files, credentials, absolute paths, and unrelated changes. In the
pull request, name the milestone, list the acceptance criteria demonstrated,
and record the exact verification results.
