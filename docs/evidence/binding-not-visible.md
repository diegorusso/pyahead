# Binding-not-visible investigation: evidence and decision for review

## Decision

- Evidence: binding-not-visible investigation, Task 4
- Decision date: _not yet decided_
- Accountable reviewer: _pending_
- Decision: **not approved; awaiting review**

This record prepares a recommendation for human review, as
[Gate D](gate-d.md) and the [top-1000 record](pypi-top-1000.md) do. An agent
may assemble and test this evidence but cannot approve its precision or
confidence judgement. The preparation date below is not a decision date.

## Recommendation

**No implementation change is justified by this investigation's sample.**
Retain the three rules, their confidence and usage-context handling, and the
current C1/C2 adjudication contract. Task 5's supported outcome is the plan's
explicit no-change branch. The probe options below are evaluated alternatives,
not an instruction to implement them in Task 5.

The sample establishes a concrete observability limit for Text: 23 annotation
sites whose imports never execute during ordinary module import. It does not
establish 23 incorrect deprecation findings. AnyStr and Hashable/Sized have no
binding gaps in this sample, so their original gaps remain unattributed.
Annotation syntax alone does not explain the lost sweep. Honest coverage
therefore remains preferable to a confirmation based on an invented binding.

## Evidence identity and denominators

Prepared on 13 September 2026 against source revision
the investigation branch, plus the characterization tests
described below. PyAhead is `0.2.0`; the registry revision is
`3a2bf7aafb4480a41996e2bba8b4f2061d7a94f2727c083af094ba910865385e`.
This task does not acquire a corpus or run third-party package probes.

- [Preserved baseline](binding-not-visible-baseline.md): the provisional
  aggregate contains 1,482 findings / 796 scanned packages, 517 confirmed,
  eight refuted-binding, and 957 not-adjudicable. The published final sweep
  instead records 1,485 / 797, 520 confirmed and 528 adjudicated. The
  discrepancy is retained; the missing per-finding records are not recovered.
- [Static sample](binding-not-visible-static.md): four local packages,
  215 files, 31 findings for these rules, 21 annotation and ten other sites.
  Seven annotations are never-stored locals. This source-only sample has no
  C1/C2 verdicts and overlaps the targeted sample; the counts must not be added.
- [Targeted sample](binding-not-visible-targeted.md): 15 manifest entries,
  all scanned; 83 findings, 58 confirmed, 24 binding-not-visible and one
  module-not-importable. All 15 shards record bubblewrap for installation, and
  all eight shards with findings record bubblewrap for adjudication; seven
  zero-finding shards have null probe isolation.
  Coverage is 58/83 = 69.8795%; agreement is 58/58 among adjudicated findings
  only. This is a selected new sample, not a reproduction or a precision
  estimate for the original corpus.

The targeted artifact location and full provenance are in the linked record.
Task 4 rehashed these retained files and reconciled their source-joined rows:

| Artifact | SHA-256 |
| --- | --- |
| `manifest.json` (15 entries) | `b0114d2d118f421585c066aeab685b43f7744b5b00e5073cd27aadbb92c307c0` |
| `report.json` | `208de95826d75950782770c1e0b6e11aa9bc8e919fad803afbb5b3aa950f55f8` |
| `source-counts.json` | `1634e338f927bc9b7d6344c2be37663dd474c29ac0eca477093ded4fe5b28fdd` |

The baseline's 779 not-adjudicable findings for these rules (509 + 211 + 59)
are not 779 known binding-not-visible findings. Its 835 binding-not-visible
reasons are a separate marginal total; there is no surviving joint
rule/reason/site distribution. The original 35.6% coverage and 98.48%
agreement over 528 adjudicated findings remain historical figures with the
limitations recorded in the top-1000 document, including its mixed oracle
revisions. No count here retroactively corrects them. Recall is unmeasured.

## Per-rule assessment

All three checked-in rules apply to runtime and typing and report deprecation
impact within the sampled window. None has an in-window removal event. This
is an assessment of the pinned registry, not a new upstream schedule review.

| Rule | Provisional baseline: confirmed / not-adjudicable | Task 2: annotation / other | Task 3: annotation / other | Task 3: confirmed / binding gap |
| --- | ---: | ---: | ---: | ---: |
| CPY0104 AnyStr | 36 / 509 | 20 / 7 | 25 / 11 | 36 / 0 |
| CPY0126 Text | 2 / 211 | 0 / 1 | 25 / 1 | 3 / 23 |
| CPY0096 Hashable and Sized | 3 / 59 | 1 / 2 | 1 / 4 | 5 / 0 |

### CPY0104: AnyStr

The evidence supports neither a sampled binding-probe failure nor a confidence
downgrade. All 36 targeted findings are confirmed: 25 annotations, including
seven never-stored locals, plus eight base-class uses and three reads. C1 can
see the module binding even for a local annotation that never evaluates it.
Task 2's 27 sites similarly contained 20 annotations and seven base-class
uses; its annotation syntax was not evidence of unobservability.

The original 509 not-adjudicable findings cannot be assigned to either reading
from these counts. Keep the rule and current contexts/confidence. Its registry
summary describes eventual full removal outside the supported window; that
possibility reinforces retaining potentially introspected annotations, but
this sample does not test that removal or score deprecation onset.

### CPY0126: Text

The evidence supports an oracle coverage boundary combined with annotation-only
source use, not a demonstrated false positive. The targeted sample has 26
sites: 25 ruamel-yaml annotations and one typing-extensions re-export read.
Two annotations and the read are confirmed. The other 23 are in five
all-annotation file/subject groups with future annotations and module-scoped
`from typing import Text` statements inside `if False`.

Of those 23 gaps, 11 are parameters and six returns: **17 stored annotations**
retain runtime and typing contexts. The other **six function-local annotations**
are never stored and already have typing-only context. The two confirmed
annotations occur in a module with an unconditional Text import and the same
future-annotation mode. There is no sampled spelling/alias mismatch to fix.

Runtime-risk interpretation needs this distinction: the six locals cannot break
through ordinary annotation introspection, while the 17 signatures can require
runtime name resolution. A guarded missing Text name can already defeat default
hint evaluation before any removal. No actual ruamel-yaml hint evaluation or
introspection usage was measured, so these are supported mechanisms, not 17
observed failures or 17 proven future regressions.

Keep confidence and both rule contexts. High confidence describes identifying
the deprecated alias, not the probability that application execution raises.
The six locals are still relevant typing deprecation uses. The registry has no
planned Text removal, so do not invent a removal date or present these findings
as current upgrade blockers. This sample does not justify changing that rule,
suppressing annotation findings, or assigning the lost 211 cases this pattern.

### CPY0096: Hashable and Sized

The evidence supports retaining the existing rule; it does not isolate the
original gap. All five targeted findings are confirmed: four Hashable and one
Sized, comprising one return annotation and four ordinary reads. Task 2 had
one Hashable annotation and two reads, with no Sized findings. The baseline's
59 not-adjudicable cases cannot be attributed to Hashable alone because the
rule has two matchers. No finding-quality defect or observed probe gap is
established for either subject. Keep confidence, contexts, and the existing
unscheduled-removal treatment.

## Future break, confidence, and usage contexts

The engine's
[`_annotation_is_deferred`](../../src/pyahead/analysis/engine.py)
deliberately treats only function-local variable annotations as never
evaluated or stored. Parameter, return, class and module annotations retain
runtime because deferral allows later introspection. `usage_contexts` also
reflects stubs and typing guards; it is not an annotation-only indicator.
For these matchers, existing `match.evidence.reference_context` supplies the
annotation-site distinction without a new public field.

The Overview's future-break argument holds for stored annotations that later
resolve a removed alias: successful import or ordinary function calls today
do not prove that `typing.get_type_hints` will succeed after removal. It does
not apply in the same way to the never-stored locals, nor does an already
missing global establish a new failure caused by removal. Explicit namespaces,
rebinding, or retained alias objects can also alter what introspection resolves.
Whether a package exercises any such path remains unmeasured.

Accordingly, do not lower match confidence merely because no runtime warning
fires. Do not relabel all future annotations typing-only, broaden local
deferral, or change a typing-alias rule to runtime-only. Those changes would
hide applicable typing debt or potentially introspected uses. The evidence
implicates overinterpretation of findings as guaranteed executed failures; it
does not demonstrate a defect in the existing separation of match confidence,
impact, registry certainty, and usage contexts in
[the design](../design.md#3-product-vocabulary-and-invariants).

## Narrow probe options and their costs

C1 requires a live site binding to the claimed subject; C2 then tests that
subject's timeline under the existing
[protocol](../pypi-validation.md#the-oracle-c1c2-per-finding-adjudication).
For these deprecation-only rules, C2 checks presence, not deprecation onset,
warning emission, or package introspection. A new observation must not be
silently relabelled as the existing `confirmed` verdict.

| Option | What it could establish | Supported coverage gain and execution cost |
| --- | --- | --- |
| Carry the exact source spelling into the binding request, preserving scope/shadowing checks | Live global aliases that the canonical-name probe cannot spell, without evaluating annotations | Zero of the 24 observed gaps: none has that cause. Controlled aliased-import tests establish the mechanism, but no corpus gain is measured. Source joining adds scan work; the intended runtime operation remains the existing bounded identity lookup. |
| Evaluate only the identified stored annotation with its original namespace inside the existing bubblewrap probe | Whether that annotation resolves in that environment; any future C1 integration would also need evidence for the exact matched reference inside a composite hint | At most 17 Text gap sites even have stored annotations to examine; zero extra confirmations are demonstrated. The guarded name remains absent, so evaluation alone does not supply a binding. Evaluation may call arbitrary annotation expressions or hooks, increasing code execution and timeout risk beyond import/lookup. |
| Supply missing imports or force guarded/function/script bodies to execute | Behavior in a modified namespace or under an additional execution path | No valid coverage gain for the unchanged C1 question. It changes the state being judged and may execute arbitrary package logic. Reject this option for this investigation. |

For the 23 observed Text gaps, **there is no probe-only change that can produce
a genuine live-binding confirmation while preserving the current C1 question**.
Six have no stored annotation; the other 17 have no live Text global. The
narrowest way to explain them is the existing source-context join, retained as
separate evidence. It accounts for all 23 without increasing the adjudicated
numerator or adding runtime execution. Static import intent alone cannot prove
runtime identity through rebinding or conditional imports.

The remaining binding gap, CPY0088, is outside these three rules: Pygments has
one FancyURLopener base-class reference and import under a main guard. C1's
ordinary import never executes that block. It likewise supplies no case for
an annotation evaluator or a spelling fix; running the script would expand
execution substantially. Retain this gap and the separate CPY0042
module-not-importable finding so all 83 findings reconcile.

The supported recommendation therefore leaves coverage at 58/83 for this
sample, with no added package-execution risk or probe cost. No recovered
percentage for the old sweep can be projected. A future semantic expansion
would need its own justified scope, regression evidence, and a same-change
update of `docs/pypi-validation.md` if it changes adjudication meaning or the
closed vocabulary. No such expansion is proposed here.

## Controlled checks and validation

Task 4 adds 20 characterization cases, with no product fix:

- Eight C1 cases in
  [test_pypi_probe.py](../../tests/unit/test_pypi_probe.py) cover both
  false-guarded signatures and false-guarded local annotations for AnyStr,
  Text, Hashable, and Sized. All remain binding-not-visible.
- Twelve cases in
  [test_annotation_introspection.py](../../tests/unit/test_annotation_introspection.py)
  cover three mechanisms for all four names: synthetic alias removal breaks
  deferred hint resolution while calls still work; a guarded missing global
  fails hint resolution before removal and an explicitly supplied namespace
  does not establish an original live binding; local annotations are never
  stored in function hints.

These execute only small test-owned sources. The removal experiment deletes a
slot on a synthetic namespace holding the alias, never on the real `typing`
module. It demonstrates a mechanism on the validation host, not any actual
future interpreter release or a package-specific failure. Characterization
tests pass with the existing implementation; they are not Task 5
fail-without-fix regression fixtures.

Validation ran on Linux aarch64 with Python 3.13.5. Only this evidence record
and the plan completion are edited after the full suite starts.

- `uv sync --frozen --offline`: passed; 28 locked packages checked.
- `uv run --frozen --offline ruff check .` and
  `uv run --frozen --offline ruff format --check .`: passed.
- `uv run --frozen --offline mypy src scripts`: passed; 46 source files.
- `uv run --frozen --offline pytest`: **2,026 passed, 11 skipped**, exit 0,
  in **1,208.74 seconds**; **91.62%** branch-enabled project coverage against
  the unchanged 90% requirement. Existing platform/interpreter skips remain
  skips; they do not demonstrate an additional corpus run.
- `uv run --frozen --offline pytest --no-cov
  tests/unit/test_annotation_introspection.py tests/unit/test_pypi_probe.py
  -k annotation`: 40 passed, 74 deselected, exit 0 in 5.98 seconds. This
  includes the 20 existing annotation controls and 20 new cases.
- Independent source-only reconciliation passed for the three artifact
  hashes, all 15 shard hashes and wheel hashes, and 21 source-file hashes.
  Per-rule verdict totals, annotation counts, all 23 Text guards/contexts,
  five all-annotation groups, isolation modes, document links and unfilled
  approval fields were checked. No shard verdict was changed.
- `uv build --offline`: wheel and sdist built. Both
  `scripts/install_smoke.py --dist-dir dist --kind wheel|sdist --offline
  --installer-cache /home/diegor/.cache/uv` checks passed.
- `uv run --frozen --offline pyahead --version`: `pyahead 0.2.0`.
- Registry validation and coverage passed: 133 valid rules, 133/133 covered,
  377 entries across 13 sources, zero unclassified entries.
- `scripts/benchmark.py --repeat 1`: exit 0, regression `passed=true`, all
  three cases deterministic. `performance_targets_met` remains **false**:
  one-file, 1,000-file and 10,000-file durations were 1.180338, 11.627982
  and 118.905942 seconds. This ran alongside the full suite; it does not
  establish the stricter design timing targets.

Lint/types used `UV_CACHE_DIR=/tmp/pyahead-uv-cache`; full pytest and offline
build/install checks used host access to the existing cache, following the
earlier tasks' environment requirements. The absolute paths here are
intentional cache locators. No third-party corpus code was executed by this
task; test sources and packaging smokes are repository-owned.

Final diff and whitespace review passed. The change includes only this evidence
record, the two characterization test files, and Task 4's plan completion.
There are no analyser, registry, probe, adjudication, protected policy/design/CI,
dependency, generated-artifact, secret, or unrelated changes. At Task 4's
completion, Task 5 remained pending.

## Task 5 completion

Completed on 13 September 2026 against
this investigation, following the explicit no-change
branch supported by the recommendation above. **No implementation change was
made.** No tests or fixtures were added or changed, so a per-fixture
fail-without-fix/pass-with-fix check is not applicable. Task 4's 20
characterization cases continue to test existing behavior; they are not
regressions demonstrating a product fix.

The closed reason vocabulary and C1/C2 adjudication semantics are unchanged;
no update to `docs/pypi-validation.md` is required. The analyser, registry,
confidence and usage-context handling, and probe behavior are unchanged.
No corpus was acquired or probed, and no coverage numerator or historical
sweep figure was revised. Completing this task records the recommendation's
no-change outcome without approving the precision or confidence evidence.

Fresh validation ran on Linux aarch64 with Python 3.13.5. Source and tests
remained unchanged throughout; only this completion record and the plan were
edited after validation finished. The cache and host-access arrangement is
the same as recorded for Task 4 above.

- `uv sync --frozen --offline`: passed; 28 locked packages checked.
- `uv run --frozen --offline ruff check .`: passed.
- `uv run --frozen --offline ruff format --check .`: passed; 472 files
  already formatted.
- `uv run --frozen --offline mypy src scripts`: passed; 46 source files.
- `uv run --frozen --offline pytest`: **2,026 passed, 11 skipped**, exit 0
  in **1,168.75 seconds**; **91.62%** branch-enabled project coverage against
  the unchanged 90% requirement. Existing platform/interpreter skips remain
  skips. The full suite includes the annotation-context, introspection and
  binding-visibility characterization cases.
- `uv build --offline`: wheel and sdist built successfully.
- `uv run --frozen --offline python scripts/install_smoke.py --dist-dir dist
  --kind wheel|sdist --offline --installer-cache <existing host cache>`:
  both offline installation smokes passed.
- `uv run --frozen --offline pyahead --version`: `pyahead 0.2.0`.
- Registry validation and coverage passed: 133 valid rules, 133/133 covered,
  377 entries across 13 sources, zero unclassified entries.
- `uv run --frozen --offline python scripts/benchmark.py --repeat 1
  --output <temporary report>`: exit 0, regression `passed=true`, all three
  cases deterministic. `performance_targets_met` remains **false**:
  one-file, 1,000-file and 10,000-file durations were 1.464282, 15.419078
  and 113.332612 seconds. The benchmark ran alongside the full suite and
  does not establish the stricter design timing targets.
- `git diff --check`: passed. Final diff review confirmed that only this
  evidence record and the plan completion changed, with no generated files,
  secrets, new absolute paths, protected-policy edits or unrelated changes.

The task's diff contains only this evidence record and the plan completion.
The decision date, accountable reviewer and approval fields above remain
unfilled; the operator-owned review, later sweep decision and artifact-policy
decision remain pending.

## Human review still pending

The reviewer owns acceptance of the per-rule interpretation and the no-change
recommendation. The missing original joint distribution, unmeasured actual
introspection, limited C2 question, convenience selection, and six typing-only
Text locals must remain visible when assessing the evidence. The operator
also owns any later full-sweep decision and durable artifact policy described
in the plan. This record approves none of those actions or product gates.
