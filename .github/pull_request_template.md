## Summary

<!-- Explain the user-visible or repository-level outcome. -->

## Design milestone

<!-- Name one milestone from docs/design.md and its acceptance criteria. -->

## Verification

<!-- List the exact commands run and their results. -->

- [ ] `uv sync`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run mypy src`
- [ ] `uv run pytest`
- [ ] `uv build`
- [ ] `uv run pyahead --version`
- [ ] `git diff --check`

## Scope review

- [ ] Tests cover the implemented behaviour.
- [ ] No later-milestone or unrelated work is included.
- [ ] The diff contains no secrets, local absolute paths, or unintended
      generated files.
