# PyAhead milestone autopilot

The milestone autopilot turns the repeated implement, verify, review, and repair
conversation into one resumable repository command. It processes one frozen
`docs/design.md` milestone at a time. “Autonomous” means that an operator does
not have to issue each follow-up prompt; it does not bypass milestone scope,
independent evidence, security boundaries, external product gates, or human
merge review.

It is development infrastructure. It does not implement or ship any PyAhead
analyser, registry, Django, or hosted-service feature.

## Architecture and trust boundaries

`scripts/autopilot.py` is a Python 3.11+ standard-library controller. Its policy
is in `automation/milestones.toml`, its role prompts are in
`automation/prompts/`, and its closed-world JSON Schemas are in
`automation/schemas/`.

The roles have deliberately different authority:

| Component | Authority | Trusted output |
| --- | --- | --- |
| Parent controller | State, verification, branch, commits, pushes, draft PR | Git and independently executed command results |
| Implementer | Fresh ephemeral `workspace-write` Codex session | Candidate worktree edits; JSON is validated but claims are not evidence |
| Reviewer | Fresh ephemeral `read-only` Codex session | Structured verdict and concrete findings |
| Fixer | Fresh ephemeral `workspace-write` Codex session | Candidate edits addressing only supplied failures/findings |

Every child runs with `--ask-for-approval never`, the least-capable required
sandbox, `--ephemeral`, an explicit output schema, and
`PYAHEAD_AUTOPILOT_CHILD=1`. The marker makes recursive autopilot invocation
fail. No child owns staging, commits, branch changes, pushes, or pull requests.
Implementation context is never reused for review or repair.

The controller independently checks the current branch, HEAD, semantic index,
complete worktree path/hash set, protected files, selected quality-policy
tables, the frozen contract, and a deterministic digest of stable Git control
metadata. The semantic index digest covers staged objects, modes, paths, merge
stages, and index flags while deliberately ignoring the physical index stat
cache that read-only Git commands may refresh. It also pins the ignored Gate C
approval record so a child or verification process cannot manufacture external
approval. A mismatch stops with all work preserved. The controller does not
reset, checkout, force-push, or silently revert suspicious changes.

## Prerequisites

- Python 3.11 or newer;
- the locked `uv` development environment;
- Git with `main` exactly matching `origin/main` at the start of a new run;
- an authenticated Codex CLI exposing the capabilities checked by `doctor`;
- for publication, an authenticated writable `origin` and the GitHub CLI
  (`gh`) authenticated for the repository.

From a clean repository root, inspect the installed interfaces without starting
a Codex service session:

```console
python scripts/autopilot.py doctor
```

For a run that will publish, make the stronger preflight:

```console
python scripts/autopilot.py doctor --push --draft-pr
```

The stronger form also checks `gh auth status` and read access to the configured
Git remote. Publication can still fail later if write permission or network
state changes; that failure is recoverable.

## First unattended M2-M6 run

After M1.5 has been merged, update local `main` so it is clean and exactly equal
to `origin/main`. Inspect the immutable plan and a no-mutation expansion first:

```console
python scripts/autopilot.py plan --from M2 --through M6
python scripts/autopilot.py run --from M2 --through M6 --push --draft-pr --dry-run
```

The dry run prints the branch, every role stage and argv, all rendered prompts,
verification commands and deadlines, intended commits, publication actions,
Gate C boundary, and protected inputs. It does not create `.autopilot/`, a
branch, a Codex session, a commit, a push, or a pull request.

Start the real range only after reviewing that output:

```console
python scripts/autopilot.py run --from M2 --through M6 --push --draft-pr
```

For local commits with no remote mutation, omit `--push --draft-pr`.

## Per-milestone cycle

For each milestone, the controller:

1. extracts exactly one configured milestone subsection from
   `docs/design.md`, stores it under the run directory, and records its SHA-256;
2. renders and stores a fresh implementation prompt containing that contract,
   repository rules, previous status, checks, and protected boundaries;
3. validates the implementer's strict JSON and requires `files_changed` to equal
   the complete live Git path set;
4. runs the configured full-repository and milestone-specific commands itself;
5. gives a separate read-only reviewer the frozen contract, complete live diff,
   tests, and parent-owned evidence;
6. if verification fails or review returns `changes_requested`, gives a fresh
   fixer only the contract, redacted failed output, concrete findings, and
   protected paths;
7. repeats verification and independent review, with at most three fixer
   cycles;
8. creates one commit only when every check passed and review returned `pass`;
9. optionally pushes that commit as a recoverable checkpoint and creates or
   updates one draft PR;
10. advances to the next contract.

Agent-reported commands are retained as claims but never count as verification.
A malformed or missing implementation/fixer result enters the bounded repair
path. A malformed reviewer result fails safely because it cannot supply a valid
independent decision.

## Command reference

Global options must precede the subcommand. Use `--config PATH` only for a
repository-owned alternate policy.

```console
python scripts/autopilot.py doctor [--push [--draft-pr]]
python scripts/autopilot.py plan --from M2 --through M6
python scripts/autopilot.py run --from M2 --through M6 [--push [--draft-pr]]
python scripts/autopilot.py run --from M2 --through M6 --dry-run
python scripts/autopilot.py status [--json]
python scripts/autopilot.py resume
python scripts/autopilot.py gate status C
python scripts/autopilot.py gate approve C --evidence PATH --approved-by NAME
```

`run --timeout-seconds SECONDS` applies a positive per-process override for a
specific run and is persisted for `resume`. Every command and subcommand has
`--help` output.

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| 0 | Requested work completed, or the requested range ended successfully at Gate C |
| 2 | Invalid input, configuration, schema, or required CLI capability |
| 3 | Agent or external gate blocker |
| 4 | Verification, review protocol, or execution failure |
| 5 | Clean operator interruption |
| 6 | Unsafe state, concurrent run, recursion, or repository divergence |
| 7 | Publication failed; local commits and state were preserved |

## Branches, commits, and draft pull requests

The default M2-M6 branch is:

```text
codex/m2-m6-autopilot
```

One branch serves the selected range. Each accepted milestone receives one
commit such as `Implement M2: Registry and matcher framework`, with
`PyAhead-Autopilot-Run` and `PyAhead-Milestone` trailers. The trailers permit
safe adoption of a commit if the process died after Git committed but before
the next state write.

With `--push`, the controller pushes after every accepted milestone without
force. With `--draft-pr`, after the first push it creates or reuses exactly one
open draft PR targeting `main`, then updates the body with completed milestones,
verification status, current state, and stop reason. It refuses to reuse a
non-draft PR and never merges.

If a push or PR operation fails, exit 7 leaves the local commit and
`publication_pending` state intact. Fix authentication or connectivity and run:

```console
python scripts/autopilot.py resume
```

The controller verifies remote continuity and retries publication only; it does
not re-run implementation, verification, or review already accepted in state.

## State, lock, prompts, results, and logs

Ignored runtime data is stored as:

```text
.autopilot/
├── state.json
├── lock
├── gates.json
└── runs/<run-id>/
    ├── contract/
    ├── prompts/
    ├── results/
    └── logs/
```

State writes use a same-directory temporary file, flush and fsync it, and then
atomically replace `state.json`. State records the run ID, branch, base and
expected commits, milestone/index/phase, repair count, accepted worktree,
completed commits, prompt hashes, contract hashes, protected hashes, Git
metadata digest, Gate C record hash, timeout override, and publication progress.
The Gate C hash may change only through the explicit `gate approve C` operator
command while no milestone phase is active.

Every subprocess has a deadline. Standard output and standard error are stored
in separate complete log files. The runner never records or prints the child
environment, and it redacts common authorization headers, GitHub/OpenAI token
forms, and credential-bearing URLs. Redaction is not a general secret scanner:
do not put secrets in source, prompts, command output, or repository-owned
configuration, and inspect logs before sharing them.

The exclusive lock prevents concurrent controllers. Normal Ctrl-C handling
removes the lock and leaves the last safe state. A hard kill can leave a stale
lock; confirm that its recorded PID is not running and that no controller uses
the repository before removing only `.autopilot/lock`. Never remove state or
worktree changes merely to make `resume` proceed.

## Interrupting and resuming

Press Ctrl-C once. Then inspect:

```console
python scripts/autopilot.py status
git status --short --branch
git diff
```

The state machine resumes from every durable material phase. It does not repeat
a completed verification command recorded in the current evidence set, create a
duplicate milestone commit, or repush a recorded checkpoint. A resumable run
accepts only the exact content recorded in state. Unexpected worktree changes,
branch movement, rewritten history, remote divergence, protected changes, or
Git metadata changes stop safely for operator inspection.

## Failure and stop conditions

Expected stops include:

- dirty worktree or non-empty index before a normal run;
- local `main` not exactly matching `origin/main`;
- unknown or reverse milestone range;
- child-reported `blocked` or `failed` result;
- malformed structured review output;
- verification timeout, signal, failure, or tracked mutation;
- review-requested changes that still fail after three repair cycles;
- protected governance, harness, contract, CI, quality-policy, semantic index,
  history, branch, or stable Git-metadata modification;
- branch/history/remote divergence while paused;
- Gate C awaiting external evidence;
- M9 or M10 policy refusal;
- recoverable publication failure.

Complete evidence stays in the run directory. The controller never weakens,
deletes, skips, or rewrites tests or thresholds to turn a failure into a pass.

## Gate C and M7-M8

After committing and optionally pushing M6, the state becomes
`awaiting_gate_C`. This is mandatory even if M7 or M8 was included in the
original range. External usefulness evidence must be collected and judged by an
accountable human or group; Codex cannot create the approval.

Keep the non-empty evidence document inside the repository and, for a paused
run, ensure it was already part of the recorded clean worktree. Record the
decision locally:

```console
python scripts/autopilot.py gate approve C \
  --evidence docs/evidence/gate-c.md \
  --approved-by "release council"
python scripts/autopilot.py gate status C
```

If the paused range includes M7-M8, run `resume`. If the M2-M6 range ended at
M6, first review and merge it, update clean local `main` to `origin/main`, retain
or re-record the evidence-backed approval, and start:

```console
python scripts/autopilot.py run --from M7 --through M8 --push --draft-pr
```

## Why M9 and M10 are excluded

M9 is a hosted GitHub service. `docs/design.md` requires a separate private
service repository, so this controller refuses M9 in `diegorusso/pyahead` before
any mutation. It does not scaffold Django here.

M10 is a C API investigation whose dedicated contract does not yet exist. The
controller refuses it until `docs/c-api-design.md` exists; existence makes the
range eligible for planning, not automatically approved or implemented.

## Security implications

Unattended Codex can intentionally edit any unprotected worktree path inside a
workspace-write session. Review prompts are not a security boundary by
themselves; sandboxing, parent verification, strict result parsing, protected
hashes, Git metadata hashing, branch/index/history checks, and human merge review
provide layered controls. The runner never selects `danger-full-access`,
deprecated full-auto modes, unrestricted shell invocation, or force push.

Subprocesses are always argv arrays with `shell=False` semantics. Deadlines,
signals, and separated logs are explicit. Inherited Git repository and config
selectors are removed so commands cannot be redirected outside the checkout.
Publication is optional, remote
continuity is checked before every push, and the PR remains draft. Operators
should still use a repository clone and credentials scoped only to the intended
repository, inspect generated code and logs, and rotate any credential that
appears in output.

## Inspecting work before merge

Before making the draft PR ready for review or merging it manually:

1. read the frozen contract and structured results under the run directory;
2. inspect every milestone commit and the complete cumulative diff;
3. read parent verification log pairs and confirm the commands match
   `automation/milestones.toml`;
4. scrutinize changes to dependency, build, test, lint, type, coverage, CI, and
   security configuration;
5. check for accidental later-milestone product work, generated runtime files,
   secrets, absolute machine paths, unsafe subprocesses, and destructive Git;
6. run the full repository suite again in the final branch state;
7. retain external Gate C evidence as external evidence, not as a fabricated
   Codex acceptance claim.

The autopilot never performs the merge.
