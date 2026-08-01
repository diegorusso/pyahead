# Codex working agreement

`docs/design.md` is the implementation contract. Read it completely, together
with the current `README.md`, `pyproject.toml`, and repository instructions,
before editing.

- Implement only the requested design milestone. Do not add later-milestone
  features opportunistically.
- Commit each completed milestone after its acceptance checks pass; do not
  combine work from different milestones in one commit.
- Preserve unrelated work and the invariants in `docs/design.md`. If code must
  differ from the design, update the design in the same change with a rationale.
- Keep the package in `src/pyahead`, require Python 3.11 or newer, and add only
  dependencies used by the current milestone.
- Do not add analyser, registry, Django, or hosted-service code before its
  milestone.

Run the complete repository verification suite from the repository root:

```console
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv build
uv run pyahead --version
```

Also run milestone-specific checks, `git diff --check`, and inspect the final
diff for generated files, secrets, absolute paths, and unrelated changes.
