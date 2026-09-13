# Investigate the binding-not-visible adjudication gap

## Overview

The PyPI top-1000 sweep adjudicated only 35.6% of findings. The dominant reason
is `binding-not-visible`: 835 of 957 not-adjudicable findings. Decide what that
reason actually means, then either raise coverage or state honestly why it
cannot be raised.

This is an investigation, not a feature. The deliverable is a decision backed by
evidence, plus whatever narrow change that decision justifies. Do not broaden it
into a redesign of the oracle.

The surviving aggregate already localises the gap. Start from these numbers
rather than rediscovering them:

| Matcher kind | confirmed | not-adjudicable | refuted-binding |
| --- | ---: | ---: | ---: |
| `qualified-reference` | 293 | **852** | 0 |
| `module-import` | 215 | 103 | 8 |
| `call-shape` | 9 | 2 | 0 |

| Rule | confirmed | not-adjudicable |
| --- | ---: | ---: |
| `CPY0104` `typing.AnyStr` | 36 | **509** |
| `CPY0126` `typing.Text` | 2 | **211** |
| `CPY0096` `typing.Hashable` | 3 | 59 |

Three typing-alias rules account for 779 of the gap, and almost all of it is
`qualified-reference`. These names are used overwhelmingly inside annotations,
which a module-scope binding probe cannot observe, and which
`from __future__ import annotations` never evaluates at all.

## The question to answer

For a finding whose only use is inside an annotation, two readings are open and
the evidence does not yet separate them:

- **Oracle limitation.** The finding is correct and the C1 binding probe simply
  asks the wrong question of an annotation. Coverage is understating PyAhead.
- **Finding quality.** A deprecated alias referenced only in an annotation that
  is never evaluated does not raise on any interpreter, so reporting it at
  high confidence may overstate the risk. Coverage is telling us something real.

These are not mutually exclusive and the split may differ per rule. The plan
must produce a per-rule answer with counted evidence, not a single verdict.

Note that a never-evaluated annotation is still a genuine future break: when the
alias is removed, `typing.get_type_hints` and any runtime introspection over
that annotation start failing. "Never raises today" is not "safe". Any proposal
to downgrade confidence must address that, not ignore it.

## Context

- Harness: `scripts/pypi_corpus.py`, `pypi_probe.py`, `pypi_validate.py`,
  `pypi_report.py`, specified in [`pypi-validation.md`](../pypi-validation.md).
- The adjudication vocabulary, including `binding-not-visible`, is closed and
  defined there. Do not add a verdict or reason without changing that document
  in the same commit.
- Prior evidence: [`pypi-top-1000.md`](../evidence/pypi-top-1000.md) records the
  completed sweep, 98.48% agreement over 528 adjudicated findings.
- The engine already distinguishes annotation contexts:
  `_annotation_is_deferred` in `src/pyahead/analysis/engine.py` treats a PEP 526
  function-local annotation as never evaluated, and deliberately treats every
  other annotation as a runtime use. Read that docstring before proposing a
  change; its reasoning is the starting point, not an obstacle.
- `usage_contexts` on a finding already carries `runtime` versus `typing`.
  Whether that distinction is already sufficient to answer this question from
  static data alone is the first thing to check.

## Data problem, read this first

**The sweep's per-finding data no longer exists.** The ralphex worktree was
removed after the run, taking `work/pypi-validate/shards/` (999 shards), the
999-artifact wheelhouse, the manifest, and the bound worksheet with it.

What survived, outside the repository and not backed up:

- `/var/tmp/pyahead-sweep/agg-provisional/report.json` and `worksheet.csv`
- `/var/tmp/pyahead-sweep/pypi-report-task5.json` and
  `pypi-disagreements-task5.csv`

These are aggregates. They carry per-rule and per-matcher-kind counts but not
per-finding records, so they cannot answer which construct produced a
`binding-not-visible`. `/var/tmp` is not a durable location.

Re-acquisition will not reproduce the original corpus exactly: the manifest
resolves each project's *current* release, and versions have moved since
11 September. Treat any re-run as a new sample, not a reproduction, and record
its own manifest digest.

## Safety

`pypi_validate.py run` installs and imports arbitrary third-party code. Every
constraint in [`pypi-validation.md`](../pypi-validation.md) applies unchanged:
`--execute-third-party-code` is required, `bwrap` must be present, and any shard
recording `isolation_mode: rlimit-only` halts the plan.

Nothing under `work/` or `/var/tmp/pyahead-sweep/` is ever committed.

## Development Approach

- One task at a time, each ending with the repository gate green:
  `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy src scripts`, `uv run pytest`.
- The full suite takes about 20 minutes on this host. Budget for it.
- Protected as always: `docs/design.md`, `AGENTS.md`, `.github/workflows/**`,
  and the quality-policy tables in `pyproject.toml`.
- Prefer a smaller, targeted sample over another full sweep. A 1000-package run
  is not needed to characterise a gap that three rules dominate.

## Implementation Steps

### Task 1: Preserve the surviving evidence

- [x] copy `/var/tmp/pyahead-sweep/agg-provisional/` and the two `*-task5.*`
      files to a durable location outside the repository, and record the
      destination and each file's SHA-256
- [x] record, from the preserved report, the exact `by_rule` and
      `by_match_kind` breakdowns and the `not_adjudicable_reasons` counts, so
      the baseline survives independently of the files
- [x] confirm nothing was copied into the repository working tree

Task 1 completed on 13 September 2026. See the
[preserved baseline record](../evidence/binding-not-visible-baseline.md) for the
durable destination, all four SHA-256 digests, exact extracts from both surviving
reports, repository-containment verification, and validation results. The
provisional report has 1,482 findings / 796 scanned packages, whereas the
published sweep records 1,485 / 797; the discrepancy is retained explicitly.
Full gate: 1,970 passed, 11 skipped, 91.62% coverage; lint and types passed.

### Task 2: Answer it from static data first

- [x] for the three dominant rules, determine from the registry and the matchers
      alone how their subjects are typically referenced, and whether
      `usage_contexts` already separates annotation-only uses from runtime uses
- [x] write a throwaway script that scans a small set of locally available
      packages and counts, for each finding of those rules, whether every use
      site is an annotation; record the counts
- [x] state explicitly whether this static evidence already answers the question
      for any rule. **If it does, say so and skip the re-run for that rule** —
      a sweep is not required to confirm something the source already shows

Task 2 completed on 13 September 2026. See the
[static investigation](../evidence/binding-not-visible-static.md) for registry
and matcher analysis, the reproducible counter, source hashes, and per-rule
results. Four local packages / 215 files produced 31 findings: 21 annotation
sites and 10 other sites, with seven never-evaluated local annotations. The
sample does not settle the lost sweep's per-rule attribution, so all three
rules remain open for Task 3; Text annotations and Sized were not sampled.
Full gate: 1,986 passed, 11 skipped, 91.62% coverage; lint and types passed.

### Task 3: Targeted re-run, only if Task 2 leaves it open

- [x] acquire a bounded corpus sufficient to sample the open rules rather than
      the full 1000, and record its manifest digest and entry count
- [x] run the harness over it and confirm every shard records
      `isolation_mode: bwrap`
- [x] extract, for each `binding-not-visible` finding, the construct that
      produced it: the use-site context, whether the module used
      `from __future__ import annotations`, and whether the name was imported at
      module scope
- [x] classify each into oracle limitation versus annotation-only use, and
      report the split per rule with counts

Task 3 completed on 13 September 2026. See the
[targeted runtime sample](../evidence/binding-not-visible-targeted.md) for the
15-entry manifest and digest, durable artifacts, execution method, source join,
and per-rule counts. All 15 packages scanned under bubblewrap: 83 findings,
58 confirmed, 24 binding-not-visible, and one module-not-importable. The binding
gaps comprise 23 Text annotation sites with imports under `if False` and one
non-annotation Pygments reference under a main guard; no gaps were observed for
AnyStr or Hashable/Sized. This selected sample does not reconstruct the lost
sweep or decide finding quality. Full gate: 2,006 passed, 11 skipped, 91.62%
coverage; lint and types passed. Task 4's decision remains pending.

### Task 4: Decide, and record the decision

- [x] for each of the three rules, state which reading the evidence supports and
      why, with counts
- [x] if the oracle is the limitation, specify the narrowest probe change that
      would adjudicate these findings, and say what it would cost in coverage
      and in execution risk. Do not implement it in this task
- [x] if finding quality is implicated, specify what should change: confidence,
      `usage_contexts` handling, or the rule itself. Address the future-break
      argument in the Overview explicitly, since "never raises today" does not
      make a removal safe
- [x] record the decision in `docs/evidence/binding-not-visible.md`, leaving the
      decision, reviewer, and date unfilled as `gate-d.md` and
      `pypi-top-1000.md` do. An agent may prepare this evidence but cannot
      approve it

Task 4 completed on 13 September 2026. See the
[decision evidence](../evidence/binding-not-visible.md) for counted per-rule
conclusions, the stored-versus-local annotation distinction, and probe options
with their coverage and execution costs. The prepared recommendation is no
implementation change: the sample explains 23 Text gaps but demonstrates no
valid additional C1 confirmations; the original AnyStr and Hashable/Sized gaps
remain unattributed. Human decision, reviewer, and date remain unfilled.
Twenty new characterization cases support the mechanisms without changing
product behavior. Full gate: 2,026 passed, 11 skipped, 91.62% coverage; lint,
formatting, types, build, and installation smokes passed. Benchmark regression
passed; stricter design timing targets remain unmet. Task 5 remains pending.

### Task 5: Implement only what Task 4 justified

- [x] make the single narrowest change the decision supports, with regression
      coverage; if the decision was "no change", implement nothing and say so
      (no implementation change, as Task 4 recommends)
- [x] every new fixture must fail without its fix and pass with it; record that
      check per fixture (not applicable: no fix or new fixtures; Task 4's
      characterization cases remain evidence of existing behavior)
- [x] if the closed reason vocabulary or the adjudication semantics changed,
      update `docs/pypi-validation.md` in the same commit (not applicable:
      vocabulary and semantics are unchanged)
- [x] full gate green, with exact counts and coverage recorded

Task 5 completed on 13 September 2026 using the explicit no-change branch.
No implementation or tests were changed, and no fail-without-fix fixture check
is claimed. See the [completion record](../evidence/binding-not-visible.md#task-5-completion)
for validation against `c2f7ecf8b8c9c35447c6ffd40806d761611c656e`:
**2,026 passed, 11 skipped, 91.62% coverage**, exit 0 in **1,168.75 seconds**;
lint, formatting, strict types, build, offline installation smokes, CLI and
registry checks passed. Benchmark regression passed; stricter design timing
targets remain unmet. The evidence's human decision, reviewer and date remain
unfilled, and the operator-owned post-completion actions below remain pending.

## Post-Completion (operator, not automatable)

1. **Review and sign the evidence.** As with Gate C and the top-1000 record,
   precision and confidence judgements are human-owned.
2. **Decide whether a fresh full sweep is warranted** once any change lands. The
   35.6% coverage figure in `docs/evidence/pypi-top-1000.md` describes the
   September run and is not retroactively corrected by this work.
3. **Decide where sweep artifacts live in future.** This investigation exists in
   its present shape because 999 shards were deleted with a worktree; a durable
   location outside `.ralphex/worktrees/` would have preserved them.
