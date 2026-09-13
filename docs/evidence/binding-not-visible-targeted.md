# Binding-not-visible: targeted runtime sample

## Scope and identity

Task 3 of [the investigation plan](../plans/20260913-investigate-binding-not-visible.md),
13 September 2026. This is a new, deliberately selected convenience sample,
not a reproduction of the deleted September sweep or an estimate of its joint
per-rule/reason distribution. Task 4 owns the per-rule decision and any proposed
change. This task changes no analyser, registry, oracle, adjudication vocabulary,
protected instruction/design/CI file, or quality-policy table.

PyAhead: `0.2.0`. Registry revision:
`3a2bf7aafb4480a41996e2bba8b4f2061d7a94f2727c083af094ba910865385e`.
Host: Linux aarch64; development Python 3.13.5 and uv 0.11.21.

Durable artifact directory, outside the repository and its worktree:
`/home/diegor/.local/share/pyahead/evidence/20260913-binding-not-visible-targeted/`.
The absolute locator is intentional evidence provenance. The directory is on
NVMe/ext4; this record does not claim a separate backup. It retains the pinned
wheels, PyPI JSON responses, acquisition provenance, manifest, all shards,
aggregate report and worksheet, source-joined finding records, and the one-off
scripts. The harness removes its temporary installed environments after each
package as usual; the wheels retain the exact source bytes for the source join.

Manifest: `manifest.json`, **15 entries**, zero unresolved entries.
SHA-256: `b0114d2d118f421585c066aeab685b43f7744b5b00e5073cd27aadbb92c307c0`.

## Selection and execution method

The seven selected roots were pytest, pydantic, typing-extensions, tornado,
lark, prompt-toolkit, and ruamel-yaml. The first three continue Task 2's useful
controls; the others were selected to widen the typing-alias source constructs.
The initial six-root acquisition lacked Text annotations on source inspection,
so ruamel-yaml was added before running the final manifest. That preliminary
14-entry manifest was superseded before any shard ran. The final manifest and
its sample ranks are independent of the top-1000 download ranks.

The one-off acquisition driver resolves current PyPI releases and active
non-extra dependencies across CPython 3.11–3.15 on this host, using the existing
artifact-selection function. It refuses source distributions, URL requirements,
extra-bearing dependencies, unsatisfied version constraints, and more than 25
entries. Seven roots plus eight dependencies produced the 15-entry manifest.
All downloaded artifacts are wheels. Each artifact's SHA-256 matched its saved
PyPI metadata, and the existing verifier rehashed every manifest entry and
rejected unmanifested wheelhouse files before execution. Dependencies are
manifest members and are scanned themselves, not hidden installer inputs.

The normal manifest loader requires exactly 1,000 entries. A temporary driver
sets only `scripts.pypi_corpus._CORPUS_SIZE` to the pinned sample's length,
bounded to 1–25, before calling the existing verifier, runner, and reporter.
It does not fabricate missing ranks, mark unselected projects unresolved,
change a checked-in harness file, or alter C1/C2 behavior. The plan explicitly
requests a selected bounded sample, so the full-sweep selection policy does
not apply to this task. The same closed manifest fields, rank/name checks,
artifact hashing, installation policy, and result validation still apply.

The driver invokes `pypi_validate.main` once per rank with the existing shard
selector `(rank - 1) % count`, `--execute-third-party-code`, `--timeout 300`,
and `--horizon-python 3.15`. It checks each completed shard before starting
another package. Any install mode other than `bwrap`, or any non-null probe
mode other than `bwrap`, halts it. A null probe mode is allowed only as evidence
that no probe batch ran, not claimed as an isolated probe execution.

Bubblewrap's network/PID namespace preflight passed on the host. The tool
sandbox denied its netlink operation, so the authorized harness ran host-side
with the harness's own unchanged bubblewrap boundaries. Offline installation
and every probe use the explicit environment allowlist, scratch HOME,
resource limits, isolated network/PID namespaces, private temporary directories,
and restricted filesystem mounts described in
[the protocol](../pypi-validation.md#isolation-and-third-party-code-execution-warning).

All five installed interpreters were discovered: 3.11.15, 3.12.13, 3.13.14,
3.14.6, and 3.15.0b2. Their presence is not a claim that each finding ran on all
five: reference selection, needed action-version pairs, artifact compatibility,
and opportunistic extra-interpreter provisioning remain the existing harness's
rules. In particular, the pinned pydantic-core wheel is CPython 3.11-specific;
absence of another compatible wheel can prevent an extra pydantic environment
from installing. A reference-confirmed verdict remains reference-confirmed
under the existing protocol; it does not establish that extra coverage.

The first driver attempt selected rank 2 when intending rank 1, completed
pydantic under `bwrap`, then stopped when its expected rank-1 shard was absent.
The indexing was corrected in the temporary driver. The resumed run retained
that valid pydantic shard under the same final manifest; no failed or
non-isolated result was replaced with a pass.

## Final sample results

All **15 packages scanned**, with scan exit code 0 in every shard. There were
zero skipped, install-failed, or scan-failed packages. All 15 install isolation
fields are `bwrap`; all eight shards that ran probe batches record `bwrap` in
adjudication isolation as well. The other seven have no findings and correctly
record null probe isolation. There are **zero `rlimit-only` records**.

| Package | Version | Findings | Probe isolation |
| --- | --- | ---: | --- |
| pytest | 9.1.1 | 27 | bwrap |
| pydantic | 2.13.5 | 3 | bwrap |
| typing-extensions | 4.16.0 | 1 | bwrap |
| tornado | 6.5.8 | 13 | bwrap |
| lark | 1.3.1 | 11 | bwrap |
| prompt-toolkit | 3.0.53 | 0 | null; no findings |
| ruamel-yaml | 0.19.1 | 25 | bwrap |
| iniconfig | 2.3.0 | 0 | null; no findings |
| packaging | 26.3 | 0 | null; no findings |
| pluggy | 1.6.0 | 0 | null; no findings |
| pygments | 2.21.0 | 1 | bwrap |
| annotated-types | 0.8.0 | 0 | null; no findings |
| pydantic-core | 2.46.5 | 0 | null; no findings |
| typing-inspection | 0.4.4 | 2 | bwrap |
| wcwidth | 0.8.3 | 0 | null; no findings |

All 83 findings are `qualified-reference`: **58 confirmed**, **25
not-adjudicable**, zero binding refutations, and zero timeline refutations.
Agreement is 58/58 = 100% **among adjudicated findings only**; coverage is
58/83 = **69.8795%**. This small, selected sample neither re-estimates nor
retroactively changes the original sweep's precision or coverage. Recall is
not measured. For the three deprecation-only typing rules, C2 checks subject
presence; a confirmation does not validate deprecation onset, warning
emission, or future annotation-introspection behavior.

The 25 not-adjudicable results comprise **24 binding-not-visible** and **one
module-not-importable**. The latter is retained separately: CPY0042 at
`tornado/platform/asyncio.py:408` matched `asyncio.WindowsSelectorEventLoopPolicy`.
Its binding evidence is `status: resolved`, `identity_match: null`,
`subject_status: absent`, consistent with the protocol's platform-specific
subject-observability limitation on Linux. It is not included in the binding
gap classification or converted into a refutation.

### Per-rule counts and handoff

| Rule | Findings | Annotation sites | Other sites | Confirmed | Binding-not-visible |
| --- | ---: | ---: | ---: | ---: | ---: |
| CPY0096 | 5 | 1 | 4 | 5 | 0 |
| CPY0104 | 36 | 25 | 11 | 36 | 0 |
| CPY0126 | 26 | 25 | 1 | 3 | 23 |
| **Three-rule total** | **67** | **51** | **16** | **44** | **23** |

- **CPY0096:** four Hashable sites and one Sized site, all confirmed. The
  pydantic shard contributes three Hashable findings; typing-inspection adds
  one Hashable and one Sized runtime dictionary-key reference. There is one
  return annotation and four ordinary reads. This sample covers both matcher
  subjects but produces no binding gap to attribute; the original rule's
  lost-sweep gap remains unmeasured.
- **CPY0104:** pytest contributes 27 AnyStr findings, lark seven, and tornado
  two, all confirmed. The 25 annotations include seven never-stored local
  annotations; the other 11 sites comprise eight base-class uses and three
  reads. These results directly show that neither annotation syntax nor
  local-annotation deferral alone makes a finding unadjudicable. They do not
  explain the original 509 not-adjudicable findings.
- **CPY0126:** ruamel-yaml contributes 25 Text annotation sites, of which 23
  are unobservable and two confirmed. typing-extensions adds one confirmed
  Text re-export read. The 23 gaps have a source-supported annotation-only
  and missing-runtime-binding explanation detailed below. They establish
  one real pattern, not the prevalence of that pattern in the original 211
  not-adjudicable findings or a justified confidence downgrade.

| Rule | Annotation-only groups with unobservable bindings | Other-use groups: oracle limitation | Unclassified binding gaps |
| --- | ---: | ---: | ---: |
| CPY0096 | 0 | 0 | 0 |
| CPY0104 | 0 | 0 | 0 |
| CPY0126 | 23 | 0 | 0 |
| CPY0088, outside the three target rules | 0 | 1 | 0 |
| **All binding-not-visible findings** | **23** | **1** | **0** |

The columns count **finding sites**, not numbers of groups. The first column
also has an oracle observability limitation; the buckets are a partition of
source constructs, not mutually exclusive philosophical readings or a binary
precision judgement. No gap in this sample demonstrates an otherwise live,
unconditionally imported binding that the probe merely failed to spell.

## Source join and classification method

The one-off counter reads each source member directly from its hash-verified
wheel, never imports it, and joins the shard's complete source region against
LibCST position metadata. For qualified-reference findings, an independent
parent walk must agree with the matcher's `reference_context`. It records
parameter, return, module-variable, class-variable, and function-local
annotations separately; ordinary reads and base expressions stay distinct.

The counter records each file's future-annotations import and SHA-256. LibCST
scope assignments recover the matched spelling's actual import statement,
its bound name, scope, and enclosing `if` guards. “Imported at module scope”
is a lexical fact: an import under module-level `if False` still has global
scope. “Unconditional module import” excludes guarded imports; neither flag
alone proves that a binding survived module execution. Aliases and local
imports are retained, not inferred from the canonical subject's first token.

A group is `(distribution, relative source file, matched qualified name)`.
“All annotation” requires every detected use in that group to be an annotation,
including confirmed findings when the group also contains an unadjudicable site.
This is a coarse file/subject grouping, not a proof that distinct scopes share
a binding, or that quoted/indirect/dynamic uses do not exist.

Every `binding-not-visible` row receives one of two **investigation buckets**:

- An all-annotation group: annotation-only source use with an unobservable C1
  binding. Oracle observability and annotation-only use can both apply.
- A group with a non-annotation use: an oracle coverage limitation for which an
  annotation-only explanation of the group's uses is insufficient.

These buckets add no verdict or reason to the closed adjudication vocabulary.
They do not classify an unobservable finding as a false positive or prove the
alias will never be evaluated. Stored/deferred annotations may still be
accessed through runtime introspection. Truly never-stored function-local
annotations are counted separately, and typing-context applicability remains
part of the registry contract. Task 4 must weigh these facts before any
confidence, usage-context, rule, or probe proposal.

## Observed binding-not-visible constructs

The ruamel-yaml 0.19.1 shard contains 23 CPY0126 gaps. Every one is a Text
annotation in a file using `from __future__ import annotations`. In every
case, the matched name's from-import is lexically at module scope but inside
`if False:  # MYPY`; none is an unconditional module import. The source join
and the C1 `binding-not-visible` evidence agree on the visibility gap.

| Wheel-relative file | Text import line | Parameter | Return | Function-local | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| `ruamel/yaml/emitter.py` | 22 | 0 | 0 | 2 | 2 |
| `ruamel/yaml/reader.py` | 29 | 3 | 4 | 1 | 8 |
| `ruamel/yaml/scalarstring.py` | 7 | 6 | 1 | 1 | 8 |
| `ruamel/yaml/scanner.py` | 38 | 1 | 1 | 2 | 4 |
| `ruamel/yaml/serializer.py` | 23 | 1 | 0 | 0 | 1 |
| **Total** | | **11** | **6** | **6** | **23** |

These are five all-annotation file/subject groups. There are no class-variable,
module-variable, or non-annotation sites among these 23 gaps. Six local
annotations carry the engine's `annotation_evaluation: deferred` evidence
and typing-only context; the other 17 retain runtime and typing. No observed
gap needs a module-level alias-spelling explanation or function-local import:
the Text spelling is unaliased, and its import is guarded at global scope.

A useful within-distribution control is `ruamel/yaml/main.py`: its line-38
Text import is unconditional. Its two parameter annotation references on
line 60 are confirmed, despite that module also using future annotations.
Thus future deferral does not, by itself, prevent this probe from confirming
an annotation finding. The other ruamel-yaml modules instead give C1 no
live Text binding to compare.

This sample establishes an annotation-only source/observability explanation
for these 23 sites, not a finding-quality verdict. In particular, 17 sites are
parameter/return annotations; their deferral does not establish that runtime
introspection never accesses them. The six local annotations are never stored,
but remain typing uses under these rules. No annotation evaluation or package
function invocation was added to C1, and no artificial binding was injected
to turn an unobservable finding into a confirmation.

The remaining gap is **CPY0088**, a non-annotation base-class reference to
`urllib.request.FancyURLopener` in
`pygments/lexers/_sourcemod_builtins.py:1100`. Its unaliased from-import on
line 1096 is module-scoped under `if __name__ == '__main__'`. The file has
no future-annotations import. C1 imports the module, so that script-only
binding is not created. This is an import-only oracle limitation independent
of annotations. The script body was not executed to force a confirmation.
This preserves the one out-of-target-rule gap rather than omitting it from
the requested classification of every `binding-not-visible` finding.

## Retained artifacts and reproduction

Paths below are relative to the durable directory given above. These hashes
bind the counted evidence and the exact temporary method independently of
this worktree's lifetime.

| Artifact | SHA-256 |
| --- | --- |
| `acquisition.json` | `9000151a16ca8625067dbbd833448ae3ed8529f196fe0d591c2f4795b20522e1` |
| `report.json` | `208de95826d75950782770c1e0b6e11aa9bc8e919fad803afbb5b3aa950f55f8` |
| `worksheet.csv` | `c00156d06ac9a66a7a238de29fcbaf656afa0a1d693b92eeaaf542db1f5ad82e` |
| `source-counts.json` | `1634e338f927bc9b7d6344c2be37663dd474c29ac0eca477093ded4fe5b28fdd` |
| `method/acquire.py` | `6aeec4f24d57b9f248d9577ea0745385ad260dc8e1096d7217305b2ebb1c30af` |
| `method/run_sample.py` | `9b54c45a6e0074ab6a1c7f07c9b4f78d5cf9b27f9bd24e0ebc828db07063b04c` |
| `method/extract.py` | `10348cd10c9bdb4ec0657d74670e9a54c9b5f66414892bdbe7ea90c7225d8a74` |
| `method/test_extract.py` | `936298fc68201cfdbbf6aeaee3ca04250758fd15f276cdbf5ee7d252af354008` |

`manifest.json` holds each wheel filename, version, and artifact SHA-256.
`acquisition.json` holds the selected roots, active dependency constraints,
and URL and digest of each saved PyPI response; the manifest's
`upstream_payload_sha256` is the digest of this acquisition record, not a
fictional top-1000 ranking payload. Its digest is in the table above.
`source-counts.json` retains all **83** source-joined finding records from
**21** files, their source hashes, and all **15** individual shard hashes.
All 83 `(package, fingerprint)` identities are unique. Each of the 24 gaps
has a source region, construct, future-import flag, import-scope facts,
guards, and investigation bucket. Counts reconcile exactly with the report.

From this checkout, with `sample_dir` set to the durable directory above:

```console
PYTHONPATH=.:src .venv/bin/python "$sample_dir/method/test_extract.py"
PYTHONPATH=.:src .venv/bin/python "$sample_dir/method/extract.py" "$sample_dir" > /tmp/binding-source-counts.json
cmp "$sample_dir/source-counts.json" /tmp/binding-source-counts.json
```

This source-only replay does not install or import package code. The retained
`run_sample.py` verifies the pinned wheelhouse, resumes the existing shards,
aggregates every manifest entry, and verifies worksheet/report identity. A
fresh runtime run requires a separate evidence directory with the exact
manifest/wheels, and the same explicit third-party-code authorization and
working bubblewrap isolation. Reacquiring current releases with `acquire.py`
would produce another sample, not reproduce this one; use a fresh directory.
The one-off scripts are not supported product commands.

## Validation

Validation uses the source revision named above plus the 20 new probe
characterization cases in
[test_pypi_probe.py](../../tests/unit/test_pypi_probe.py). Only this evidence
record and the Task 3 plan completion were edited after the full suite began.
These tests characterize existing C1 behavior for all four typing names under
eager/future annotations, aliased from-imports, local imports, and typing
imports guarded by TYPE_CHECKING. This task implements no fix, so these are
not claimed as fail-before/pass-after regression fixtures for Task 5.

- `uv sync --frozen --offline`: passed; 28 locked packages checked.
- `uv run --frozen --offline ruff check .`: passed.
- `uv run --frozen --offline ruff format --check .`: passed; 469 files checked.
- `uv run --frozen --offline mypy src scripts`: passed; 46 source files.
- `uv run --frozen --offline pytest`: **2,006 passed, 11 skipped**, exit 0,
  in **1,249.48 seconds**; **91.62%** branch-enabled project coverage against
  the unchanged 90% requirement. Platform and existing interpreter-guard
  skips remain skips; the real corpus run is recorded separately above.
- The 20 new probe cases passed with `--no-cov` in 4.10 seconds.
- Five independent one-off counter tests passed: guarded global imports,
  annotation/value references on one line, aliased imports, function-local
  imports, and empty samples/invalid source regions.
- Corpus runner, manifest verification, complete aggregation, and bound
  worksheet identity verification: exit 0. All source joins and count
  reconciliation assertions passed; no raw verdict was reclassified. The
  retained extraction script reproduced byte-identical JSON (`cmp` exit 0).
- `uv build --offline`: wheel and sdist built. Both documented installation
  smokes passed with `--offline --installer-cache /home/diegor/.cache/uv`.
- `uv run --frozen --offline pyahead --version`: `pyahead 0.2.0`.
- Registry validation: 133 valid rules. Coverage: 133/133 rules, 377 entries
  across 13 sources, zero unclassified entries.
- `scripts/benchmark.py --repeat 1`: exit 0, regression `passed=true`, all
  three cases deterministic. `performance_targets_met` is **false**:
  one-file, 1,000-file, and 10,000-file durations were 1.367797, 14.426489,
  and 131.037464 seconds. It ran alongside other validation; these results
  do not demonstrate the stricter design timing targets.

The default uv cache is read-only inside the tool sandbox. Lint/types used
`UV_CACHE_DIR=/tmp/pyahead-uv-cache`; the full suite and offline build/install
checks used host cache access, as in the previous tasks. An initial new-test
assertion used the wrong expected status spelling (`not-visible`); it was
corrected to the existing protocol's `binding-not-visible`, after which all
20 cases passed. Formatting was then applied to that test file only. Neither
issue required a product behavior or quality-policy change.

`git diff --check` and final scope review passed. The change consists only of
this aggregate evidence record, the probe characterization tests, and the
Task 3 plan update. All acquired artifacts and raw source-derived records are
outside the repository; no generated distribution, secret, or unrelated file
is included. Absolute paths in this record are intentional artifact/cache
locators. Final validation logs are retained under the durable directory's
`validation/` subdirectory.
