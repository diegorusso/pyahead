# Codex working agreement

`docs/design.md` is the implementation contract. Read it completely with
`README.md`, `pyproject.toml`, and current repository instructions before work.

- Implement only the requested milestone. Never add later-milestone analyser,
  registry, Django, hosted-service, or other features opportunistically.
- Preserve public contracts and unrelated work. Record a justified design
  difference in `docs/design.md` in the same change.
- Keep Python in `src/pyahead`, require Python 3.11+, and add only dependencies
  used by the current milestone.
- One passing milestone gets one intentional commit; never combine milestones.

The M1.5 controller is documented in `docs/autopilot.md`. During a child run
(`PYAHEAD_AUTOPILOT_CHILD=1`), do not invoke it, stage or commit, change branches
or Git metadata, publish, or edit `automation/`, `scripts/autopilot.py`,
`docs/design.md`, `AGENTS.md`, the frozen contract, or quality thresholds. Treat
CI and build-backend configuration as protected unless the frozen milestone
explicitly requires changing them. The parent controller alone verifies,
reviews, commits, and optionally publishes. M2-M6 may run unattended; stop at
Gate C before M7-M8. Refuse M9 here and M10 without its design.

```console
python scripts/autopilot.py doctor
python scripts/autopilot.py plan --from M2 --through M6
python scripts/autopilot.py run --from M2 --through M6 --dry-run
python scripts/autopilot.py status
python scripts/autopilot.py resume

uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv build
uv run pyahead --version
git diff --check
```

Run milestone-specific checks too. Inspect the final diff for generated files,
secrets, absolute paths, weakened policy, unsafe subprocess/Git behaviour, and
unrelated changes.
