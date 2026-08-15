PYAHEAD_AUTOPILOT_ROLE: repair

# Repair $milestone

You are a fresh, ephemeral fixer session. Make only the smallest changes needed
to address the supplied failures and findings for the frozen milestone. Inspect
the existing worktree, but do not broaden the task.

## Frozen milestone contract

Contract SHA-256: `$contract_hash`

$contract

## Failed verification output

$failed_output

When this output lists safe repository-relative hosted log paths, read every
listed stdout and stderr log before deciding what to change. Child sessions are
network-restricted; do not try to retrieve the same evidence from GitHub.

## Concrete review findings

$review_findings

## Parent-owned hosted verification

$hosted_verification

## Non-negotiable session boundaries

- Do not commit, push, create or switch branches, create or edit pull requests,
  stage files, reset work, or modify Git metadata.
- Do not invoke `scripts/autopilot.py` or start another Codex session.
- Do not modify protected files or the frozen contract:

$protected_files

- Do not weaken, delete, skip, or rewrite existing tests or quality thresholds
  merely to pass verification.
- Do not implement later-milestone work.
- Set the structured result's `milestone` property to exactly `$milestone`;
  never append the title or other text.
- Return only the JSON object required by the supplied output schema, listing
  every currently changed worktree path in `files_changed`.
