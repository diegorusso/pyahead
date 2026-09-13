# Binding-not-visible: preserved baseline

## Scope and provenance

Task 1 of [the investigation plan](../plans/20260913-investigate-binding-not-visible.md)
preserved the four surviving artifacts on 13 September 2026. This record
transcribes their aggregate counts; it does not adjudicate findings or approve
precision evidence. The per-finding shards and original manifest remain
unavailable. No corpus was acquired or third-party code executed for preservation.

Source directory: `/var/tmp/pyahead-sweep/`.

Durable destination: `/home/diegor/.local/share/pyahead/evidence/20260913-binding-not-visible-baseline/`.

The destination is on the host's ext4 NVMe filesystem, outside the repository,
its worktrees, and temporary directories. These are local retained copies,
not evidence of a separate off-host backup. The source files remain in place.
Each copy was flushed to disk and its SHA-256 matched both the pre-copy and
post-copy source hash. All four are regular files; the destination is not a
symlink into the worktree. Relative paths below apply to both directories.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `agg-provisional/report.json` | 142851 | `225b4cac3a4affc3c1aeba6bb653b98612fcb739e1160b18c9716f0f105799db` |
| `agg-provisional/worksheet.csv` | 69819 | `5f8073a27878dee91d3580899a15c7d67482684ed2a89f1b0b92f4c370963f17` |
| `pypi-report-task5.json` | 143029 | `c7b44e2bfb988ba7faefd2f6a170345fd0ce0581dfd6e6cc71cbcc518bd7766e` |
| `pypi-disagreements-task5.csv` | 136106 | `63f07980260fca5031783e4c5ecee70c3bdfc1c7c4a5a66c5c787a1cfb954c5b` |

## Surviving snapshots differ from the published sweep

The provisional report contains 1,482 findings from 796 scanned packages:
517 confirmed, 8 refuted-binding, 0 refuted-timeline, and 957 not-adjudicable.
Its agreement is 517/525 and its adjudication coverage is 525/1,482.
The [published sweep record](pypi-top-1000.md#evidence-identity) instead records
1,485 findings from 797 scanned packages, 520 confirmed, and 528 adjudicated.
The provisional snapshot therefore has one fewer scanned package and three
fewer confirmed findings. Its reason counts and the plan's matcher and three
dominant-rule breakdowns agree exactly. The missing package and the cause of
the difference are not established by this preservation task.

The other surviving report, `pypi-report-task5.json`, contains 1,487 findings
from 797 scanned packages, with 361 confirmed, 148 refuted-binding,
53 refuted-timeline, and 925 not-adjudicable. It is a distinct snapshot,
not the final result described in the published record. Both reports carry
the same manifest digest, but the manifest itself has not been recovered.
Neither report is relabelled as the published final aggregation.

The following extracts preserve every key and value in `by_rule`,
`by_match_kind`, and `not_adjudicable_reasons`, including sparse verdict keys.
They also retain the report identity, totals, and stored ratios. Only the
`skipped_packages` list is omitted; it remains in the archived reports.

## agg-provisional/report.json

```json
{
  "adjudication_coverage": 0.354251012145749,
  "agreement_rate": 0.9847619047619047,
  "by_match_kind": {
    "call-shape": {"confirmed": 9, "not-adjudicable": 2},
    "module-import": {"confirmed": 215, "not-adjudicable": 103, "refuted-binding": 8},
    "qualified-reference": {"confirmed": 293, "not-adjudicable": 852}
  },
  "by_rule": {
    "CPY0001": {"not-adjudicable": 7},
    "CPY0005": {"confirmed": 1},
    "CPY0008": {"not-adjudicable": 1, "refuted-binding": 1},
    "CPY0009": {"confirmed": 1},
    "CPY0014": {"not-adjudicable": 1},
    "CPY0015": {"confirmed": 3},
    "CPY0017": {"confirmed": 1},
    "CPY0021": {"confirmed": 1},
    "CPY0022": {"confirmed": 1},
    "CPY0023": {"confirmed": 113, "not-adjudicable": 78, "refuted-binding": 2},
    "CPY0024": {"not-adjudicable": 7, "refuted-binding": 1},
    "CPY0025": {"confirmed": 4},
    "CPY0026": {"confirmed": 3},
    "CPY0027": {"confirmed": 94, "not-adjudicable": 7, "refuted-binding": 1},
    "CPY0028": {"not-adjudicable": 1},
    "CPY0031": {"confirmed": 16},
    "CPY0039": {"confirmed": 1},
    "CPY0042": {"confirmed": 26, "not-adjudicable": 18},
    "CPY0044": {"confirmed": 2, "not-adjudicable": 1},
    "CPY0052": {"not-adjudicable": 1},
    "CPY0058": {"confirmed": 1},
    "CPY0062": {"confirmed": 19, "not-adjudicable": 9},
    "CPY0064": {"confirmed": 15},
    "CPY0067": {"confirmed": 7},
    "CPY0073": {"confirmed": 1},
    "CPY0088": {"not-adjudicable": 1},
    "CPY0091": {"confirmed": 6},
    "CPY0093": {"confirmed": 59, "not-adjudicable": 7},
    "CPY0094": {"confirmed": 5, "not-adjudicable": 1},
    "CPY0095": {"not-adjudicable": 9},
    "CPY0096": {"confirmed": 3, "not-adjudicable": 59},
    "CPY0098": {"confirmed": 4},
    "CPY0100": {"confirmed": 3},
    "CPY0104": {"confirmed": 36, "not-adjudicable": 509},
    "CPY0105": {"confirmed": 18, "not-adjudicable": 4},
    "CPY0106": {"confirmed": 32, "not-adjudicable": 1},
    "CPY0108": {"not-adjudicable": 1, "refuted-binding": 1},
    "CPY0109": {"confirmed": 5, "not-adjudicable": 1},
    "CPY0117": {"refuted-binding": 2},
    "CPY0118": {"not-adjudicable": 1},
    "CPY0120": {"confirmed": 5},
    "CPY0122": {"confirmed": 9, "not-adjudicable": 9},
    "CPY0123": {"confirmed": 11},
    "CPY0124": {"confirmed": 4, "not-adjudicable": 12},
    "CPY0125": {"confirmed": 2},
    "CPY0126": {"confirmed": 2, "not-adjudicable": 211},
    "CPY0128": {"confirmed": 2},
    "CPY0137": {"confirmed": 1}
  },
  "findings_total": 1482,
  "manifest_sha256": "bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b",
  "not_adjudicable_reasons": {"binding-not-visible": 835, "import-error": 82, "module-not-importable": 40},
  "packages_scanned": 796,
  "packages_total": 999,
  "schema_version": 1,
  "verdicts": {"confirmed": 517, "not-adjudicable": 957, "refuted-binding": 8, "refuted-timeline": 0}
}
```

## pypi-report-task5.json

```json
{
  "adjudication_coverage": 0.37794216543375925,
  "agreement_rate": 0.6423487544483986,
  "by_match_kind": {
    "call-shape": {"confirmed": 9, "not-adjudicable": 2},
    "module-import": {"confirmed": 162, "not-adjudicable": 75, "refuted-binding": 37, "refuted-timeline": 53},
    "qualified-reference": {"confirmed": 190, "not-adjudicable": 848, "refuted-binding": 111}
  },
  "by_rule": {
    "CPY0001": {"not-adjudicable": 1, "refuted-binding": 6},
    "CPY0005": {"confirmed": 1},
    "CPY0008": {"not-adjudicable": 1, "refuted-binding": 1},
    "CPY0009": {"confirmed": 1},
    "CPY0014": {"not-adjudicable": 1},
    "CPY0015": {"confirmed": 3},
    "CPY0017": {"confirmed": 1},
    "CPY0021": {"confirmed": 1},
    "CPY0022": {"confirmed": 1},
    "CPY0023": {"confirmed": 112, "not-adjudicable": 62, "refuted-binding": 18, "refuted-timeline": 1},
    "CPY0024": {"not-adjudicable": 7, "refuted-binding": 2},
    "CPY0025": {"refuted-binding": 4},
    "CPY0026": {"confirmed": 1, "refuted-binding": 2},
    "CPY0027": {"confirmed": 42, "not-adjudicable": 1, "refuted-binding": 7, "refuted-timeline": 52},
    "CPY0028": {"not-adjudicable": 1},
    "CPY0031": {"refuted-binding": 16},
    "CPY0039": {"refuted-binding": 1},
    "CPY0042": {"confirmed": 26, "not-adjudicable": 15, "refuted-binding": 3},
    "CPY0043": {"refuted-binding": 1},
    "CPY0044": {"confirmed": 2, "not-adjudicable": 1},
    "CPY0052": {"not-adjudicable": 1},
    "CPY0058": {"confirmed": 1},
    "CPY0062": {"confirmed": 20, "not-adjudicable": 9},
    "CPY0064": {"confirmed": 5, "refuted-binding": 10},
    "CPY0067": {"confirmed": 4, "refuted-binding": 3},
    "CPY0073": {"confirmed": 1},
    "CPY0088": {"not-adjudicable": 1},
    "CPY0091": {"confirmed": 6},
    "CPY0093": {"not-adjudicable": 7, "refuted-binding": 61},
    "CPY0094": {"confirmed": 5, "not-adjudicable": 1},
    "CPY0095": {"refuted-binding": 9},
    "CPY0096": {"confirmed": 3, "not-adjudicable": 59},
    "CPY0098": {"confirmed": 4},
    "CPY0100": {"confirmed": 3},
    "CPY0104": {"confirmed": 28, "not-adjudicable": 517},
    "CPY0105": {"confirmed": 18, "not-adjudicable": 4},
    "CPY0106": {"confirmed": 32, "not-adjudicable": 1},
    "CPY0108": {"not-adjudicable": 1, "refuted-binding": 1},
    "CPY0109": {"confirmed": 5, "not-adjudicable": 1},
    "CPY0117": {"refuted-binding": 2},
    "CPY0118": {"not-adjudicable": 1},
    "CPY0120": {"confirmed": 5},
    "CPY0122": {"confirmed": 9, "not-adjudicable": 9},
    "CPY0123": {"confirmed": 11},
    "CPY0124": {"confirmed": 4, "not-adjudicable": 12},
    "CPY0125": {"confirmed": 2},
    "CPY0126": {"confirmed": 2, "not-adjudicable": 211},
    "CPY0128": {"confirmed": 2},
    "CPY0137": {"refuted-binding": 1}
  },
  "findings_total": 1487,
  "manifest_sha256": "bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b",
  "not_adjudicable_reasons": {"binding-not-visible": 843, "import-error": 82},
  "packages_scanned": 797,
  "packages_total": 999,
  "schema_version": 1,
  "verdicts": {"confirmed": 361, "not-adjudicable": 925, "refuted-binding": 148, "refuted-timeline": 53}
}
```

## Preservation verification

A standalone local verification checks all four source/archive byte and hash
pairs, parses the two JSON extracts above and compares them with the archived
reports, reconciles each per-rule and per-matcher sum with verdict totals,
reconciles reason counts and stored ratios, and checks that no artifact copy
is present in the repository working tree. This is artifact-integrity evidence,
not a reconstruction of lost per-finding data.


## Task 1 validation result

Validation ran on Linux with Python 3.13.5 and uv 0.11.21, against source
revision `1ced030ea4fafb35d4ab25e41f2c76b97f49a1f9` plus this documentation
change. No source, test, registry, dependency, or quality-policy file changed.

- Preservation verification: four standalone standard-library tests passed.
  They check archive completeness and byte/hash identity, exact JSON
  transcription, aggregate consistency, and absence of raw copies in the
  working tree. The local verifier is
  `/tmp/pyahead-binding-not-visible-task1/test_preservation.py`.
- `uv sync --frozen --offline --python /usr/bin/python3.13`: passed using the
  existing host cache. The temporary cache lacked the locked mypy wheel;
  no lockfile or dependency change was needed.
- `uv run --frozen --offline ruff check .`: passed.
- `uv run --frozen --offline ruff format --check .`: 467 files already formatted.
- `uv run --frozen --offline mypy src scripts`: passed, 46 source files.
- `uv run --frozen --offline pytest`: **1,970 passed, 11 skipped**, exit 0,
  in 1,183.00 seconds; **91.62%** branch-enabled project coverage against the
  unchanged 90% requirement. The PyPI end-to-end integration fixture was
  skipped by its existing reference-interpreter guard; this run does not
  establish that fixture's confirmation/refutation path.
- `uv build --offline`: wheel and source distribution built successfully.
- `uv run --frozen --offline pyahead --version`: `pyahead 0.2.0`.
- Wheel and sdist `scripts/install_smoke.py` checks both passed with
  `--offline --installer-cache /home/diegor/.cache/uv`.
- Registry validation passed for 133 rules; registry coverage reported
  133/133 rules covered and zero unclassified entries across 377 source entries.
- `scripts/benchmark.py --repeat 1 --output -`: regression checks passed and
  all three cases were deterministic. `performance_targets_met` remained
  `false`: one-file, 1,000-file, and 10,000-file times were 1.435308,
  12.681799, and 118.638714 seconds respectively. The benchmark ran alongside
  the first test run; these measurements do not demonstrate the stricter
  design timing targets.
- `git diff --check`: passed. Repository changes are limited to this evidence
  record and the Task 1 plan update. Artifact locator paths in this record are
  intentional; no raw reports, worksheets, wheelhouse, or shards were added.

The initial full test run inside the restricted filesystem ended with
10 failed, 1,961 passed, and 10 skipped in 1,163.10 seconds (exit 1; 91.62%
coverage). All ten failures came from the harness's interpreter discovery:
its child environment clears the temporary cache override, then uv cannot
create its lock file in the read-only host cache. The focused runner tests
passed with host cache access (131 passed in 6.51 seconds), followed by the
complete passing rerun above. No tests were weakened, disabled, or changed.

Local logs are under `/tmp/pyahead-binding-not-visible-task1/`: `pytest.log`
retains the failed restricted run, `pypi-validate-host.log` the focused check,
`pytest-host.log` the successful full rerun, `build.log` the build, and
`benchmark.json` the benchmark. These are temporary validation logs; the exact
results above and the preserved baseline counts do not depend on their
continued availability.
