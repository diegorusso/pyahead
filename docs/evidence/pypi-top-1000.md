# PyPI top-1000 validation evidence and approval

## Decision

- Evidence: PyPI top-1000 — runtime-adjudicated precision of high-confidence
  findings
- Decision date: 13 September 2026
- Accountable reviewer: Diego Russo, repository owner and product decision-maker
- Decision: accepted as the recorded precision measurement

The reviewer confirmed that the sweep's method, denominators and limitations
are the ones they would have required. Accepting this record accepts two stated
qualifications: agreement is measured over the 528 findings that reached a
verdict, not over all 1,485, with adjudication coverage reported at 35.6%; and
the first aggregation's 201 disagreements were overwhelmingly defects in the
runtime oracle rather than in PyAhead, so the headline figure is post-fix. This
acceptance is a precision measurement for a pinned corpus, not a recall claim
and not a general guarantee.

Recorded on the reviewer's instruction, on the strength of this record and the
qualifications stated above, which were put to them in summary before the
decision. The reviewer did not independently re-perform the measurements.

This document prepares the evidence for the validation sweep specified in
`docs/pypi-validation.md`. It does not record an approval. Precision claims
are human-owned, as with Gate C: an agent prepared and verified this evidence
and cannot sign it. The sweep is a different and stronger instrument than the
source-inspection review behind `docs/evidence/gate-c.md`, not a re-run of it,
and that record stays as approved whatever is decided here.

## Evidence identity

- Source reviewed: the branch head. Every commit after the fifth and sixth
  reviews' source fix changed only this document and the plan, so the head's
  source files are those of that fix. The sweep, the post-triage re-run and the
  report digest below were produced by the analyzer and harness as they stood at
  the triage commit. Four later review changes altered source without re-running
  the sweep: the binding probe's later-prefix walk was narrowed; the analyzer's
  deferred-annotation rule was narrowed to PEP 526; the uv managed-install root
  was resolved before the sandbox binds it; and the later-prefix walk was stopped
  at the first bound component that neither reaches `S` nor stops on its slot,
  with the corpus manifest loader made to reject a non-string unresolved reason.
  What each can and cannot change in the figures below is stated under
  Limitations; none was re-measured over the corpus.
- PyAhead version: `0.2.0`
- Registry revision: `2026.07.31 (3a2bf7aafb44)`, 133 rules valid; full
  digest `3a2bf7aafb4480a41996e2bba8b4f2061d7a94f2727c083af094ba910865385e`,
  carried by every finding. No registry file changed during triage.
- Corpus: PyPI top-1000, ranks 1 to 1000 in download-rank order, no filtering,
  retrieved `2026-09-10T22:12:15Z` from
  `https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json`;
  upstream payload SHA-256
  `cff04ba201a688456eef83ed14deae66a93c143ca5bbc10951b298f9bf9e779e`
- Manifest SHA-256:
  `bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b`,
  carried by all 999 shards and by the report
- Report SHA-256, post-triage, the record this document describes:
  `bec273386131aa799adddfc4ccb67e04519432106bb9868082a31ae8e84cbb62`
- Report SHA-256, first aggregation before triage:
  `c7b44e2bfb988ba7faefd2f6a170345fd0ce0581dfd6e6cc71cbcc518bd7766e`
- Policy: `--horizon-python 3.15`, high-confidence findings only; each
  package's scan reference is the lowest installed minor that satisfies its
  own `requires_python`
- Interpreters: CPython 3.11.15, 3.12.13, 3.13.14, 3.14.6 and 3.15.0b2,
  installed by `uv` 0.11.21 for `linux-aarch64-gnu`; every minor a finding
  needed was installed
- Measurement host: Linux aarch64, 4 cores, 7 GB RAM, shared throughout with
  an unrelated CPU-bound process; bubblewrap 0.11.0
- Isolation: `bwrap` on all 998 shards where an install ran, on every probe
  batch, and on every triage refresh; the one `null` is a package for which no
  environment was created. No shard anywhere records the `rlimit-only`
  fallback.

The manifest, wheelhouse, shards, report and worksheet live under `work/`,
are gitignored, and are never committed; this record and the plan document
`docs/plans/20260910-run-pypi-top-1000-validation.md` are the durable
account. Per-package figures below are derived from those artifacts.

## Record

The evidence-record template from `docs/pypi-validation.md`, filled from the
post-triage report:

```text
Corpus: PyPI top-1000, rank 1-1000, retrieved 2026-09-10, source https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json
Manifest SHA-256: bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b
PyAhead version: 0.2.0 (source as at the sixth review's fix; sweep run at the triage commit)
Registry revision: 2026.07.31 (3a2bf7aafb44)
Report SHA-256: bec273386131aa799adddfc4ccb67e04519432106bb9868082a31ae8e84cbb62

packages_total / packages_scanned: 999 / 797
unresolved_at_acquisition: 1 (589 pywin32 312: no-installable-artifact)
findings_total: 1485
verdicts: confirmed=520 refuted-binding=8 refuted-timeline=0 not-adjudicable=957
agreement_rate: 0.984848 (520 / 528)
adjudication_coverage: 0.355556 (528 / 1485)
not_adjudicable_reasons: binding-not-visible: 835, import-error: 82, module-not-importable: 40

Triage: 201 disagreement rows in the first aggregation (148 refuted-binding,
53 refuted-timeline). 191 were defects in the runtime oracle, fixed in the
harness with tests that fail without each fix; 2 were PyAhead false
positives, fixed with regression fixtures in
tests/unit/test_precision_regressions.py; 0 were registry defects, so no
registry correction was needed. Unresolved rows: 8, still counted as
refuted-binding above; each is named with its reason under "Open rows".

Limitations restated: recall is not measured; findings with an action
version above 3.15 are not-adjudicable:no-interpreter and excluded from
adjudicated counts (0 in this run, the horizon being 3.15).

Reviewed by: Diego Russo, 13 September 2026
```

## Corpus and coverage

Acquisition resolved 999 of 1000 ranks: 996 wheels and 3 sdists (psycopg2,
pyspark, thinc, which publish no wheel installable by CPython 3.11 to 3.15 on
linux-aarch64). Rank 589, pywin32 312, publishes Windows-only wheels and no
sdist and is recorded as `unresolved: no-installable-artifact` with its rank
reserved. The offline verify step re-hashed every artifact against the
manifest without error. Thirty-six entries declare no `requires_python`.

The sweep wrote exactly one shard per resolved entry, 999 in all, every one
carrying the manifest digest.

| Shard status | Packages |
| --- | ---: |
| `scanned` | 797 |
| `install-failed` | 155 |
| `skipped` | 42 |
| `scan-failed` | 5 |

The 202 packages that were not scanned fall into eight classes. None is a
harness defect; the plan document names every package with its reason.

| Class | Packages | Cause |
| --- | ---: | --- |
| `install-failed`: a dependency pin or cap excludes the single release the corpus holds | 89 | The wheelhouse holds one current release per project. pydantic 2.13.5 pins pydantic-core 2.46.5 while the corpus holds 2.49.0, which alone accounts for 47. |
| `install-failed`: a dependency wheel is incompatible with the reference interpreter | 37 | The reference is 3.11 by the spec's rule; numpy 2.5.3 ships cp312+ wheels only (36, directly or via pandas or matplotlib) and mypy's ast-serialize ships cp315 only (1). |
| `install-failed`: a dependency is outside the top-1000 | 21 | Unreachable with `--no-index`. |
| `install-failed`: the installer child died under the sandbox's install limits | 6 | CUDA runtime wheels of 288 MB to 776 MB; two reproduced as `SIGXFSZ` against the 512 MiB file-size limit. None ships Python files, so no finding was lost. |
| `install-failed`: sdist build failed | 2 | psycopg2 needs `pg_config`; thinc's build needs a cython below 3.0 and the corpus holds 3.3.0. |
| `skipped`: no Python files | 41 | Type-stub distributions, binary-only wheels and shims. |
| `skipped`: no compatible interpreter | 1 | backports-asyncio-runner requires Python below 3.11. |
| `scan-failed`: scan exceeded 900 s | 5 | scipy, ray, phonenumbers, google-ads, datadog-api-client, the last three being generated-code trees of thousands of modules. |

Of the 797 scanned packages, 186 produced at least one high-confidence
finding and 611 produced none. A package with no findings contributes nothing
to either metric; it is not recorded as confirmed clean. Reference
interpreters over the 797 scanned packages: 3.11.15 for 790, 3.12.13 for 6,
3.15.0b2 for 1. Over all 998 packages for which a reference was chosen, which
adds the 155 `install-failed`, 41 `skipped: no Python files` and 5
`scan-failed` shards: 3.11.15 for 989, 3.12.13 for 8, 3.15.0b2 for 1; the one
remaining shard, `skipped: no compatible interpreter`, chose none.

## Precision

Agreement is `confirmed / (confirmed + refuted-binding + refuted-timeline)`,
precision over findings that reached a terminal verdict. Coverage is
`adjudicated / findings_total`. Both aggregations are recorded because the
oracle changed between them (see Triage).

| Aggregation | Confirmed | Refuted-binding | Refuted-timeline | Not adjudicable | Adjudicated | Agreement | Coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| First, before triage | 361 | 148 | 53 | 925 | 562 | 64.2% | 37.8% |
| After triage | 520 | 8 | 0 | 957 | 528 | 98.5% | 35.6% |

The post-triage rate is reported mechanically: the 8 open rows are still
counted as refutations, as the spec requires until they are resolved. It is
therefore a floor with respect to those rows, since resolving any of them as
confirmed or not-adjudicable can only raise it.

Coverage fell between the two aggregations because the oracle now declines to
adjudicate aliased from-imports, platform-only attributes and attributes only
set at runtime, which it previously refuted; those 40 findings moved to
`not-adjudicable:module-not-importable`. Two findings disappeared because the
PyAhead fixes below stopped reporting them (1487 to 1485); none was
suppressed.

Per matcher kind, after triage:

| Matcher kind | Confirmed | Refuted-binding | Not adjudicable | Total | Agreement | Coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `call-shape` | 9 | 0 | 2 | 11 | 100% | 81.8% |
| `module-import` | 215 | 8 | 103 | 326 | 96.4% | 68.4% |
| `qualified-reference` | 296 | 0 | 852 | 1148 | 100% | 25.8% |

Per rule, after triage; 48 of the registry's 133 rules still carry at least
one high-confidence finding (49 before triage; CPY0043's only finding was the
anyio false positive):

| Rule | Confirmed | Refuted-binding | Not adjudicable | Total |
| --- | ---: | ---: | ---: | ---: |
| `CPY0001` | - | - | 7 | 7 |
| `CPY0005` | 1 | - | - | 1 |
| `CPY0008` | - | 1 | 1 | 2 |
| `CPY0009` | 1 | - | - | 1 |
| `CPY0014` | - | - | 1 | 1 |
| `CPY0015` | 3 | - | - | 3 |
| `CPY0017` | 1 | - | - | 1 |
| `CPY0021` | 1 | - | - | 1 |
| `CPY0022` | 1 | - | - | 1 |
| `CPY0023` | 113 | 2 | 78 | 193 |
| `CPY0024` | - | 1 | 7 | 8 |
| `CPY0025` | 4 | - | - | 4 |
| `CPY0026` | 3 | - | - | 3 |
| `CPY0027` | 94 | 1 | 7 | 102 |
| `CPY0028` | - | - | 1 | 1 |
| `CPY0031` | 16 | - | - | 16 |
| `CPY0039` | 1 | - | - | 1 |
| `CPY0042` | 26 | - | 18 | 44 |
| `CPY0044` | 2 | - | 1 | 3 |
| `CPY0052` | - | - | 1 | 1 |
| `CPY0058` | 1 | - | - | 1 |
| `CPY0062` | 20 | - | 9 | 29 |
| `CPY0064` | 15 | - | - | 15 |
| `CPY0067` | 7 | - | - | 7 |
| `CPY0073` | 1 | - | - | 1 |
| `CPY0088` | - | - | 1 | 1 |
| `CPY0091` | 6 | - | - | 6 |
| `CPY0093` | 61 | - | 7 | 68 |
| `CPY0094` | 5 | - | 1 | 6 |
| `CPY0095` | - | - | 9 | 9 |
| `CPY0096` | 3 | - | 59 | 62 |
| `CPY0098` | 4 | - | - | 4 |
| `CPY0100` | 3 | - | - | 3 |
| `CPY0104` | 36 | - | 509 | 545 |
| `CPY0105` | 18 | - | 4 | 22 |
| `CPY0106` | 32 | - | 1 | 33 |
| `CPY0108` | - | 1 | 1 | 2 |
| `CPY0109` | 5 | - | 1 | 6 |
| `CPY0117` | - | 2 | - | 2 |
| `CPY0118` | - | - | 1 | 1 |
| `CPY0120` | 5 | - | - | 5 |
| `CPY0122` | 9 | - | 9 | 18 |
| `CPY0123` | 11 | - | - | 11 |
| `CPY0124` | 4 | - | 12 | 16 |
| `CPY0125` | 2 | - | - | 2 |
| `CPY0126` | 2 | - | 211 | 213 |
| `CPY0128` | 2 | - | - | 2 |
| `CPY0137` | 1 | - | - | 1 |
| Total | 520 | 8 | 957 | 1485 |

## Triage

Every one of the 201 disagreement rows in the first aggregation was inspected
against its shard's finding, match evidence, binding-probe evidence and the
pinned wheel source, following the procedure in `docs/pypi-validation.md`.
The rows were dominated not by PyAhead false positives but by defects in the
oracle that made correct findings look refuted. Each was fixed narrowly in
`scripts/pypi_probe.py` or `scripts/pypi_validate.py` with a unit test that
fails without the fix, and the spec's Limitations section now states the
rule each fix introduced.

| Row outcome | Rows |
| --- | ---: |
| `refuted-binding` became `confirmed` | 98 |
| `refuted-binding` became `not-adjudicable:module-not-importable` | 40 |
| `refuted-binding` finding no longer reported (PyAhead fix) | 2 |
| `refuted-binding` still `refuted-binding` (open) | 8 |
| `refuted-timeline` became `confirmed` | 53 |

### Oracle defects (191 rows)

1. **Bound-method identity.** A classmethod such as `datetime.datetime.utcnow`
   is a fresh bound-method object on every access, so comparing with `is`
   refuted every genuine `utcnow()` and `utcfromtimestamp()` call. Identity
   now also holds for two bound methods with the same `__self__` and
   underlying function. All 61 CPY0093 rows.
2. **Submodule from-imports.** `from lib2to3 import refactor` was probed as
   `getattr(lib2to3, "refactor")` on a package that had not imported the
   submodule, reporting the subject absent at 3.12 where it exists. The
   subject is now resolved by importing `A.B`, as the `from` statement does.
   All 53 `refuted-timeline` rows (52 in future 1.0.0, 1 in cython). No
   registry timeline was wrong: lib2to3 is present at 3.12 and gone at 3.13,
   distutils present at 3.11 and gone at 3.12, exactly as CPY0027 and CPY0023
   state.
3. **A walk failing on the subject's own slot.** At the cross-check
   interpreter where the subject is already removed, `unittest.makeSuite`
   walks the real `unittest` module and fails on `makeSuite` itself; that was
   reported as a binding to a different object. It is now inconclusive at that
   interpreter and the reference verdict stands. 37 rows: CPY0031 16, CPY0064
   10, CPY0025 4, CPY0067 3, CPY0026 2, CPY0039 1, CPY0137 1.
4. **Refuting against an unobservable subject.** A live binding with the
   subject absent was always a refutation, so aliased `from A import B as C`,
   the Windows-only `asyncio.WindowsSelectorEventLoopPolicy` on Linux, and
   `sys.last_type` in a fresh interpreter were all refuted. Absence now
   refutes only at an interpreter where the registry itself expects the
   subject gone; elsewhere the finding is not adjudicable. 40 rows: CPY0023
   16, CPY0095 9, CPY0001 6, CPY0027 6, CPY0042 3.
5. **The from-import-bound prefix.** After `from datetime import datetime`,
   the probe walked the canonical name `datetime.datetime.utcnow` from the
   wrong head. It now tries each later component as the site's head. Exposed
   by the first refresh, where 31 CPY0093 rows stayed refuted; they are
   within the 61 counted under item 1. The first, fifth and sixth reviews
   narrowed the rule after the sweep (Limitations): a later component may
   only confirm or be inconclusive, and the first bound component that does
   neither settles the guessing.

### PyAhead false positives (2 rows), fixed with regression fixtures

- **CPY0024, distlib 0.4.3, `wheel.py:109`**: `if sys.version_info[0] < 3:
  import imp`. The major-only index was outside the guard grammar, so a
  Python-2-only branch was reported as breaking at 3.12.
  `src/pyahead/analysis/reachability.py` now decides
  `sys.version_info[0] <op> <int>`; other index forms and non-integer literals
  stay unknown. Fixtures: `test_major_version_index_guard_hides_a_python2_only_import`
  and its two guard tests in `tests/unit/test_precision_regressions.py`, plus
  eight cases in `tests/unit/test_reachability.py`.
- **CPY0043, anyio 4.15.1, `_backends/_asyncio.py:1266`**: a local-variable
  annotation naming `asyncio.AbstractChildWatcher` inside a function body.
  PEP 526 leaves such an annotation unevaluated and unstored, so the
  reference cannot raise on any interpreter. The oracle did not observe
  that: it refuted the row at 3.14 with defect 3's shape, the walk from the
  real `asyncio` module failing on `AbstractChildWatcher` itself, and the
  fixed oracle is inconclusive there and confirms the binding from the 3.11
  reference (both oracle versions were re-run on the pinned wheel under
  3.11 and 3.14 during review). The false-positive classification therefore
  rests on PEP 526 alone. `src/pyahead/analysis/engine.py` now marks the
  annotation of a local variable inside a function body typing-only
  (evidence `annotation_evaluation: deferred`), so a runtime-only rule no
  longer applies. Parameter, return, class-body and module-level annotations
  are unchanged, including under `from __future__ import annotations`, which
  this module uses: PEP 563 only stringifies them, and runtime introspection
  such as `typing.get_type_hints` still evaluates them, so deferral alone is
  no evidence that a reference never runs. As first landed the rule also
  deferred every annotation under PEP 563; the second review narrowed it to
  PEP 526, and rescanning the pinned anyio wheel with the narrowed rule
  reproduces the refreshed shard's 32 findings with identical fingerprints.
  Fixtures: `test_local_variable_annotation_is_never_evaluated`,
  `test_future_annotations_do_not_defer_evaluated_annotations`,
  `test_deferred_annotation_keeps_a_typing_context_finding` and the four
  `test_evaluated_annotations_still_report` cases.

Fingerprints are unaffected by either fix, so the confirmed sample stays
comparable across the two aggregations.

### Re-run

All 61 packages holding a refuted row were refreshed with targeted
`--shard <rank-1>/999 --refresh --timeout 900` invocations, one per package;
the 15 packages holding the rows of item 5 were refreshed a second time after
that fix. Every refreshed shard records `bwrap`; no probe timed out or
crashed. Per-package verdict deltas were checked for every refreshed shard: no
package lost a `confirmed` verdict, and the only new not-adjudicable reason is
`module-not-importable`. The re-aggregated report and worksheet passed the
identity check before any further reading.

### Open rows (8)

None was closed by deleting a finding or lowering a rule's confidence. All
eight remain `refuted-binding` in the report.

- **future 1.0.0, CPY0027, `libpasteurize/main.py:44`**: `from lib2to3.main
  import main, warn, StdoutRefactoringTool`. The probe checks the first bound
  name, `main`, which the module rebinds further down with its own `def
  main`; the import itself is genuine and breaks at 3.13 (its neighbour on
  line 45 is confirmed). Oracle limitation: a bound name rebound after the
  import.
- **ddtrace 4.14.0, CPY0023, `ddtrace/sourcecode/setuptools_auto.py:9`**:
  `import distutils.core as distutils_core` right after `import setuptools`,
  whose shim binds the name to the vendored `setuptools._distutils.core`.
  Whether the line breaks depends on the installed setuptools, not on
  CPython. Open: environment-dependent binding the static claim cannot see.
- **gevent 26.8.0, CPY0024, `gevent/_compat.py:103`**: `try: import _imp as
  imp` / `except ImportError: import imp`. The fallback never runs on 3.x.
  Import-fallback reachability, outside the alpha guard grammar
  (`docs/design.md` §11.4).
- **future 1.0.0, CPY0023, `future/backports/test/support.py:36`**: `try:
  import sysconfig` / `except ImportError: from distutils import sysconfig`.
  Dead fallback on 3.x; same shape.
- **hypothesis 6.168.0, CPY0117, `hypothesis/strategies/_internal/regex.py:29`**
  and **`:30`**: `except ImportError` fallbacks to `sre_constants` and
  `sre_parse` after the `re._constants` and `re._parser` imports succeed on
  3.11+. Dead fallbacks; same shape.
- **future 1.0.0, CPY0108, `future/backports/urllib/request.py:1590`**: `if
  os.name == 'nt': from nturl2path import url2pathname, pathname2url`. Right
  on Windows, unobservable on this Linux host. Open: platform-conditional
  import.
- **passlib 1.7.4, CPY0008, `passlib/utils/__init__.py:854`**: `from crypt
  import crypt as _crypt`. The alias coincides with a real attribute of
  `crypt` (the `_crypt` extension it imports), so the aliased-from-import rule
  could not route it to not-adjudicable; the name at the site is a genuine
  reference. Oracle limitation.

Four of the eight share one shape: an import inside a `try`/`except
ImportError` fallback that never executes on 3.x, so the module-level name is
bound by the other branch. PyAhead reports the statement; the oracle judges
the program. The alpha reachability grammar deliberately excludes general
control flow, so whether to extend it is a roadmap decision, not something to
settle in this record.

The worksheet's `classification`, `reviewer`, `notes` and `regression_fixture`
columns are empty: the worksheet was regenerated by the post-triage
aggregation, and the triage record is this document together with the plan's
Task 6 evidence, not the gitignored CSV.

## Harness fixes made during the run

The plan allowed a genuine harness defect that blocked the sweep to be fixed
narrowly, provided it was named. Besides the five oracle fixes above:

- `scripts/pypi_corpus.py`: a release with no installable artifact is recorded
  under a manifest `unresolved` list with reason `no-installable-artifact`
  and its rank reserved, instead of aborting the whole acquisition (pywin32).
  Fourteen unit tests. After the run, the fifth review made the manifest
  loader reject an unresolved `reason` that is not a string with the same
  manifest error as an unknown reason, where a JSON list or object had
  escaped as a `TypeError`; two more unit tests. The pinned manifest's one
  unresolved reason is a string, so it loads identically (Limitations).
- `scripts/pypi_validate.py`: a relative `--work-dir` is resolved before it is
  handed to `bwrap` as a bind source; interpreter launcher symlinks are
  resolved so the probe interpreter exists inside the sandbox; the
  adjudication `isolation_mode` stays unset until a probe batch runs, so a
  package with no findings is not misreported as a fallback. Three unit tests.
  After the run, the third review added a fourth runner fix to the same file
  the uv managed-install root is resolved before the sandbox
  binds it, so the resolved interpreter files the probes exec always lie
  under a bound tree (`test_uv_python_install_dir_resolves_a_symlinked_root`).
  On this host the root resolves to itself, so the sweep already ran with
  that mount (Limitations).
- `docs/pypi-validation.md`: the documented invocations use the module form
  `python -m scripts.<name>`, which the file-path form could not satisfy.

The corpus and runner fixes are operational and change nothing about what is
measured. The oracle fixes change the oracle's judgement, which is why both
aggregations are recorded rather than only the second.

## Verification

On the sixth review's tree the repository gate passed with each
command exiting 0; the seventh, eighth and ninth reviews changed only this
document and the plan, so every later commit on the branch has the same
source files:

| Command | Result |
| --- | --- |
| `uv run ruff check .` | All checks passed! |
| `uv run ruff format --check .` | 465 files already formatted |
| `uv run mypy src scripts` | Success: no issues found in 46 source files |
| `uv run pytest` | 1970 passed, 11 skipped, 0 failed, exit 0, coverage 91.62% against the 90% floor, in 1171.29 s (19 min 31 s) |

The same gate passed on every earlier review tree, with 1955, 1965, 1964,
1965 and 1965 passing and 11 skipped each time, the last in 1162.97 s; the
pass counts differ only by the fixtures each review added or replaced. It passed again on the seventh review's tree
(1970 passed, 11 skipped, exit 0, coverage 91.62%, in 1173.28 s), on the
eighth review's tree (1970 passed, 11 skipped, exit 0, coverage 91.62%, in
1223.73 s) and on the ninth review's tree (1970 passed, 11 skipped, exit 0,
coverage 91.62%, in 1200.85 s), all of whose source files are those of the
sixth review's fix.

Each fixed file was reverted alone to its `main` version and the test modules
that cover it run in full, then the file restored and the modules run again:
`scripts/pypi_probe.py` on the seventh review's tree, whose source files are
those of the sixth review's fix, because the sixth review changed the probe and added a
fixture after the fifth review's check; `scripts/pypi_corpus.py` on the fifth
review's tree, the last to change it; `scripts/pypi_validate.py` at the review that resolved the uv managed-install
root; and the other two at the review that narrowed the deferred-annotation
rule, since neither they nor their test
modules changed afterwards. Every fix-specific test fails without its fix and
passes with it; every other test in those modules, including the guard tests
that assert a fix does not over-reach, passes both ways. The two later-prefix
fixtures added by the first review pass against `main`, which had no
later-prefix walk at all; that review recorded them failing against the
pre-narrowing probe. The rebound-class fixture added by the
fifth review
(`test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_binds_elsewhere`)
and the failed-walk fixture added by the sixth
(`test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_fails_elsewhere`)
pass against `main` for the same reason and are the 2 of 74 that fail
against the fifth review's probe, whose probe and corpus scripts are identical
to the preceding review's; the fifth review's two corpus fixtures fail against
that loader (2 of 109) with the `TypeError` the fix removes.

| Fixed file | Test modules | Failing without the fix | Passing with it |
| --- | --- | ---: | ---: |
| `src/pyahead/analysis/reachability.py` | `test_precision_regressions.py`, `test_reachability.py` | 6 of 69 | 69 |
| `src/pyahead/analysis/engine.py` | `test_precision_regressions.py` | 3 of 20 | 20 |
| `scripts/pypi_corpus.py` | `test_pypi_corpus.py`, `test_pypi_report.py` | 14 of 109 | 109 |
| `scripts/pypi_probe.py` | `test_pypi_probe.py` | 9 of 74 | 74 |
| `scripts/pypi_validate.py` | `test_pypi_validate.py` | 19 of 131 | 131 |

`docs/design.md`, `AGENTS.md`, `.github/workflows/**` and
`docs/evidence/gate-c.md` are unmodified against `main`, and the `tool.ruff`,
`tool.mypy`, `tool.pytest.ini_options` and `tool.coverage.*` tables in
`pyproject.toml` are byte-identical. Nothing under `work/` is tracked, and the
branch diff contains no host path and no credential. The first aggregation was
repeated into a scratch directory and produced a byte-identical report and
worksheet, so the record is reproducible from the shards alone.

## Comparison with Gate C

| | Gate C | This sweep |
| --- | --- | --- |
| Corpus | 100 public repositories at pinned commits | 999 PyPI releases, 797 scanned |
| High-confidence findings | 448 | 1485 |
| Oracle | Source inspection plus controlled probes where runtime-observable | Execution of each finding's subject in an isolated venv on real interpreters |
| Adjudicated | 448 (all) | 528 |
| Precision | 100% | 98.5% |

The corpora, oracles and denominators differ, so the two numbers are not a
before-and-after measurement of the same thing. Whether this record
supersedes or complements Gate C is the reviewer's decision.

## Limitations retained

- This is observed precision for a pinned corpus and policy, not a universal
  product-precision claim, and not a measurement of recall. Per-finding
  adjudication cannot see occurrences PyAhead failed to report.
- Accuracy is measured over adjudicated findings only: 528 of 1485, 35.6%.
  `adjudication_coverage` excludes the 957 findings the oracle could not
  decide: 835 `binding-not-visible`, references the module-scope probe cannot
  observe, which is a designed coverage limit and the largest single class;
  82 `import-error`, modules whose import fails in the package's own
  environment, typically for an optional dependency the corpus does not
  install; and 40 `module-not-importable`, the aliased, platform-only and
  runtime-set subjects the oracle now declines to judge. That last reason is
  also where a removal version the registry dates too late would hide: C2
  runs only for findings C1 confirmed, so a subject already gone at the
  reference interpreter where the rule still expects it present is counted
  here, never probed at C2 and never forced into the worksheet
  (`docs/pypi-validation.md`, Limitations). In this sweep every one of the
  40 had been a `refuted-binding` row in the first aggregation, so each was
  inspected and classified under oracle defect 4 above (28 with
  `identity_match: false`, CPY0023 16, CPY0027 6, CPY0001 6; 12 with the
  walk stopping on the subject's own slot, CPY0095 9, CPY0042 3); a later
  sweep has no such guarantee and must triage this reason from the shard
  evidence. It also excludes, by construction, the 202 packages that were
  never scanned and every medium-confidence finding.
- Every minor from 3.11 to 3.15 was installed, so no finding was
  `not-adjudicable:no-interpreter`. The sweep ran with `--horizon-python
  3.15`, so 3.16-scheduled changes were outside the scanned policy rather
  than unadjudicated, and remain unmeasured here as they were in Gate C.
  3.15.0b2 is a prerelease build; verdicts at 3.15 are against it.
- The oracle changed during the run. Five of its defects were found by this
  sweep and fixed before the second aggregation; each fix is covered by a
  test that fails without it and documented in the spec's Limitations, but
  the oracle itself has not been validated by an independent instrument. The
  first aggregation is recorded so the size of the change is visible.
- The second aggregation is a mixed-oracle measurement. Only the 61 packages
  holding a refuted row (15 of them twice) were re-adjudicated under the
  fixed oracle; the other 736 scanned packages keep the verdicts of the
  first pass. The fixes only ever turned a false refutation into a
  confirmation or a not-adjudicable reason, so no pre-fix `confirmed` verdict
  is in doubt, but the not-adjudicable counts above (in particular the 835
  `binding-not-visible`) are pre-fix figures for those 736 packages, and a
  full re-run under the fixed oracle would move some of them to `confirmed`
  and raise coverage. The 98.5% is therefore a floor with respect to the
  eight open rows, not with respect to a full re-adjudication.
- After the second aggregation, the first review narrowed item 5 once more,
  a later component of the canonical name may only confirm or
  be inconclusive, never refute, and a later component the enclosing
  callable binds locally is skipped. The sweep was not re-run under that
  oracle. The first half can only turn a refutation into a confirmation or
  a not-adjudicable reason, and none of the eight open rows depended on it:
  all are `module-import` findings refuted from the recorded bound name
  with a completed walk. The second half can only affect a `confirmed`
  verdict reached through a later component the callable also binds locally
  while the recorded head was visible but bound elsewhere; such a
  confirmation would have compared the wrong object. Whether any of the 520
  confirmed rows has that shape is not recoverable from the shards, because
  a probe result records the verdict and not the candidate that decided it,
  so that count is unmeasured rather than known to be zero.
- The second review narrowed the analyzer's deferred-annotation rule to the
  annotation of a local variable inside a function body (PEP 526), in
  the second narrowing; as first landed it also deferred every annotation under
  `from __future__ import annotations`. The 61 refreshed packages were
  scanned with the broader rule. The plan's per-package delta check
  recorded that the two PyAhead fixes removed exactly the distlib and anyio
  rows (`findings_total` 1487 to 1485) and suppressed nothing else, the
  anyio row is a PEP 526 local annotation, and rescanning the pinned anyio
  wheel with the narrowed rule reproduces its refreshed shard's 32 findings
  with identical fingerprints; the other 736 packages were scanned before
  either rule existed. No recorded figure depends on the PEP 563 half.
- The third review resolved the uv managed-install root before the sandbox
  binds it, so that the resolved interpreter paths the runner
  records lie under a bound tree even when `uv python dir` reaches its root
  through a symlink. On this host that root is a real directory whose
  resolved path is itself, so the unresolved and resolved bind sources are
  the same string and every probe in the sweep already ran with the mount
  the fixed runner binds; no recorded figure can depend on this change.
- The fifth and sixth reviews narrowed item 5 a third time:
  the later components are tried in order, and the first that is bound
  settles the guessing unless its walk reaches `S` or stops on `S`'s slot -
  whether it completes on some other object or raises earlier, no component
  after it may confirm, and the recorded head's own outcome stands. Before
  this, a saved `utcnow =
  datetime.utcnow` beside a `datetime` global rebound to a replacement class
  confirmed the site's `datetime.utcnow()` through the unrelated saved
  global, whether or not the replacement had an `utcnow` of its own. The
  sweep was not re-run under that oracle. The change can only turn a `confirmed`
  verdict into a refutation or a not-adjudicable reason, and only for a site
  where a later component of the canonical name is bound to some other live
  object while a component after it is bound to `S` itself. Whether any of
  the 520 confirmed rows has that shape is not recoverable from the shards,
  for the same reason as above, so that count is unmeasured rather than
  known to be zero.
- The fifth review also made `scripts/pypi_corpus.py` reject an unresolved
  manifest `reason` that is not a string with the manifest error an unknown
  reason already raised, where a JSON list or object had escaped as a
  `TypeError`. The pinned manifest carries one unresolved entry whose reason
  is the string `no-installable-artifact`, so it loads identically under
  both loaders and no recorded figure can depend on this change.
- The 8 open rows are counted as refutations. Four are import-fallback shapes
  outside the alpha guard grammar, two are oracle limitations, one is
  environment-dependent and one is platform-conditional.
- The deterministic sample of 200 confirmed findings was generated and
  identity-bound but was not manually reviewed in this run. Confirmed
  verdicts rest on the runtime oracle alone.
- Thirty-seven packages were not scanned because the spec's reference rule
  chose 3.11 while their numpy or ast-serialize dependency ships wheels for
  3.12 or 3.15 only. A reference chosen from the dependency closure would have
  scanned them; changing the rule is a spec decision, not something this run
  did.
- Five scans exceeded 900 s on the loaded host and were lost. That is a
  scanner performance observation on large generated-code trees, and those
  packages' findings are unmeasured.
- Windows-only code paths are unobservable on the Linux host, and pywin32 was
  not installable at all.
- The host was shared with an unrelated CPU-bound process throughout, so
  timings in the plan document are indicative only.

## Reviewer checklist

The evidence above is prepared, not approved. To decide, confirm:

1. the corpus policy was fixed before any result was seen, and the 202
   non-scanned packages are explained by the classes above rather than by
   selection;
2. the five oracle fixes are genuine oracle defects, on the strength of their
   failing-without tests and the spec's Limitations, and not a way of making
   findings agree;
3. what to do with the 8 open rows: accept them as oracle and grammar
   limitations, count them as false positives, or send the import-fallback
   shape to the roadmap;
4. whether 98.5% over 528 adjudicated findings at 35.6% coverage is the number
   to publish, given that Gate C's 100% was over 448 findings judged by
   inspection;
5. whether the reference-interpreter rule should change for the 37 packages it
   excluded, and whether the harness should run in CI on a reduced corpus,
   which executes third-party code and is a security decision;
6. whether this record supersedes or complements Gate C.

This evidence remains human-owned: an agent prepared and verified it, but
cannot create the approval.
