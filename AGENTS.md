# Codex working agreement

`docs/design.md` is the implementation contract. Read it completely with
`README.md`, `pyproject.toml`, and current repository instructions before work.

- Implement only the requested milestone. Never add later-milestone analyser,
  registry, browser-site, or other features opportunistically.
- Preserve public contracts and unrelated work. Record a justified design
  difference in `docs/design.md` in the same change.
- Keep Python in `src/pyahead`, require Python 3.11+, and add only dependencies
  used by the current milestone.
- One passing milestone gets one intentional commit; never combine milestones.

Treat `docs/design.md`, `AGENTS.md`, and `.github/workflows` as protected: change
them only when the requested milestone explicitly requires it. The `tool.ruff`,
`tool.mypy`, `tool.pytest.ini_options`, `tool.coverage.run`, and
`tool.coverage.report` tables in `pyproject.toml` are quality policy; never
weaken a threshold to make a change pass.

Stop at Gate C before M7-M8; Gate C needs recorded corpus-precision evidence and
accountable human approval, and no agent may approve its own precision evidence.
There is no hosted service and no M9; refuse M10 until `docs/c-api-design.md`
exists.

The `gh-pages` branch holds the `0.3` browser site and shares no history with
`main`. Never merge between them and never add site code to `main`: the site
installs `pyahead` from PyPI like any other user.

```console
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src scripts
uv run pytest
uv build
uv run pyahead --version
git diff --check
```

Run milestone-specific checks too. Inspect the final diff for generated files,
secrets, absolute paths, weakened policy, unsafe subprocess/Git behaviour, and
unrelated changes.
