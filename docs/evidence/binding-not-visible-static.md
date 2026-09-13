# Binding-not-visible: static investigation

## Scope

Task 2 of [the investigation plan](../plans/20260913-investigate-binding-not-visible.md),
13 September 2026. This record answers what the existing static evidence can
separate and counts a small local convenience sample. It does not assign C1/C2
verdicts, revise the September sweep, or approve precision evidence. The
[preserved baseline](binding-not-visible-baseline.md) remains the record of the
surviving aggregates and their discrepancy with the published sweep.

Registry revision:
`3a2bf7aafb4480a41996e2bba8b4f2061d7a94f2727c083af094ba910865385e`.
Host: Python 3.13.5, uv 0.11.21, Linux aarch64.

## Registry and matcher findings

| Rule | Exact qualified-reference targets | In-window timeline | Contexts |
| --- | --- | --- | --- |
| CPY0096 | `typing.Hashable`, **`typing.Sized`** | Deprecated from 3.12; no removal event | runtime, typing |
| CPY0104 | `typing.AnyStr` | Deprecated from 3.13; no removal event | runtime, typing |
| CPY0126 | `typing.Text` | Deprecated from 3.11; no removal event | runtime, typing |

These are the checked-in registry's claims, not a fresh review of upstream
schedules. CPY0104's summary describes 3.16 access warnings and full removal in
3.18, outside the supported window. CPY0126's summary says no removal is
currently planned. CPY0096's authored subject is Hashable, but its second
matcher covers Sized; the baseline's CPY0096 count cannot be attributed solely
to Hashable. Findings for all three rules have deprecation impact for this
3.11–3.16 scan.

Each matcher accepts every reference context: none specifies a context filter.
The engine matches import-derived loaded names and attributes, including
`typing.AnyStr`, `import typing as t; t.AnyStr`, and
`from typing import AnyStr as Alias; Alias`. Unambiguous import resolution gives
high confidence. Ordinary import statements alone are not use-site findings
for these rules. The matchers do not count strings or comments as references,
and do not follow indirect re-exports or arbitrary dynamic uses.

The registry and matcher configuration admit annotations, alias assignments,
generic base arguments, and other reads; they cannot establish how frequently
packages use each construct. The local sample below observes AnyStr in
annotations and generic bases, Hashable in an annotation and runtime checks,
and Text in an alias re-export.

Source anchors:
[CPY0096](../../src/pyahead/data/registry/cpython/CPY0096.yaml),
[CPY0104](../../src/pyahead/data/registry/cpython/CPY0104.yaml),
[CPY0126](../../src/pyahead/data/registry/cpython/CPY0126.yaml),
`resolve_qualified_name_sources` and `classify_reference_context` in
[qualified.py](../../src/pyahead/analysis/matchers/qualified.py), and
`_visit_reference` in [engine.py](../../src/pyahead/analysis/engine.py).

## What the existing evidence separates

`usage_contexts` is **not an annotation-only flag**. A normal `.py` file starts
with both runtime and typing. The engine's `_annotation_is_deferred` deliberately
retains runtime for parameter, return, class-body, and module-level annotations,
including with `from __future__ import annotations`: subsequent runtime
introspection can evaluate them. Only an `AnnAssign` annotation in function
scope drops runtime and records `annotation_evaluation: deferred` because that
annotation is never evaluated or stored. Its assignment value is a separate use.
Stubs and `TYPE_CHECKING` branches can also be typing-only, including ordinary
reads that are not annotations.

The existing `match.evidence.reference_context` already distinguishes
`annotation` from `read`, `base-class`, and `decorator` for these matchers.
Findings retain individual source regions; deduplication does not merge
different use sites. Thus one can count annotation sites without new analyser
fields. For an aggregate claim that *every* detected use is an annotation, every
finding in the chosen group must be checked. A single annotation finding does
not establish that the imported name has no other uses.

This is an existing static distinction, not proof that an annotation is never
evaluated. Nor does annotation syntax imply `binding-not-visible`: after
importing the module, C1 looks up module globals and available defining-function
globals. It need not evaluate an annotation to find that imported name, although
the module import itself may evaluate eager annotations. A module-level
`from typing import AnyStr` can make AnyStr visible for both annotated and
ordinary references. `_binding_target` derives a
canonical head from `qualified_names`; `_walk_candidates` also tries later
components conservatively, but cannot reconstruct arbitrary source aliases.
Function-local bindings, typing-only imports, missing globals, and ambiguous
scopes can remain unobservable. See `_binding_target` in
[pypi_validate.py](../../scripts/pypi_validate.py), and `_resolve_scope`,
`_walk_candidates`, and `_run_binding_probe` in
[pypi_probe.py](../../scripts/pypi_probe.py).

Consequently the plan's annotation explanation remains a hypothesis about the
lost sweep, not a consequence of the probe implementation. The baseline's
779 not-adjudicable findings for these rules are not a per-rule breakdown of
the 835 `binding-not-visible` reasons; the aggregates contain no such joint
distribution.

## Local sample and counting method

Four locally installed distributions were selected after a bounded source
inspection for the target names. This is a convenience sample with direct
references, not a random sample, reproduction, or new PyPI harness corpus.
It scans `_pytest`, the implementation package of pytest, rather than pytest's
entry-point package. No packages were acquired or installed for sampling.
No C1/C2 probes ran. Target files were copied only into a temporary directory,
parsed, then removed; no target sources or raw finding records are committed.

| Distribution and selected source | `.py` / `.pyi` files | CPY0096 | CPY0104 | CPY0126 |
| --- | ---: | ---: | ---: | ---: |
| pathspec 1.1.1 — `pathspec/` | 31 | 0 | 0 | 0 |
| pytest 9.1.1 — `_pytest/` | 78 | 0 | 27 | 0 |
| pydantic 2.13.4 — `pydantic/`, including `v1/` | 105 | 3 | 0 | 0 |
| typing_extensions 4.16.0 — `typing_extensions.py` | 1 | 0 | 0 | 1 |
| **Total** | **215** | **3** | **27** | **1** |

All 215 files were discovered and analysed; zero were incomplete. Each package
was scanned separately with baseline 3.11, horizon 3.16, high confidence,
unscheduled deprecations shown, source root `.`, and gitignore disabled.
No source-content prefilter or per-rule filter was applied before scanning;
only the resulting findings were filtered to the three rule IDs.

The throwaway counter uses each finding's complete source region to look up a
name/attribute in a separate LibCST parent walk and asserts agreement with
`reference_context == annotation`. It also records the future import, exact
matched qualified name, usage contexts, and local-annotation deferral evidence.
Counters include zeroes for absent rules. The script and its independent small
tests are reproduced below so their removal from temporary storage does not
remove the method.

A group is `(distribution, relative file, matched qualified name)`. It is an
explicitly coarse file/subject group, not a claim that all references share a
single binding across scopes. “All annotation” means every **detected** use in
that group, not all possible runtime uses, quoted annotations, or indirect
references. Imports and strings are not counted as use sites. A zero-finding
group is not counted as annotation-only.

## Counts

| Rule | Findings | Annotation | Other use sites | Annotation with future import | Never-evaluated local annotation | runtime + typing | typing only |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| CPY0096 | 3 | 1 | 2 reads | 0 | 0 | 3 | 0 |
| CPY0104 | 27 | 20 | 7 base-class references | 20 | 7 | 20 | 7 |
| CPY0126 | 1 | 0 | 1 read | 0 | 0 | 1 | 0 |
| **Total** | **31** | **21** | **10** | **20** | **7** | **24** | **7** |

The future-import and local-annotation columns overlap: all seven local
annotations occur in the future-annotation module. Thirteen AnyStr annotation
sites retain runtime, as do all seven of its base-class sites. No finding was
runtime-only. There were three file/subject groups: two mixed groups (AnyStr,
Hashable), one non-annotation group (Text), and **zero all-annotation groups**.
The matched CPY0096 subject was Hashable for all three findings; Sized had zero.

Concrete source checks, relative to the selected packages:

- `_pytest/capture.py` imports AnyStr at module scope on line 19 and has the
  future import. Its 20 annotation sites include class fields, signatures,
  and seven function-local annotations; seven generic base expressions also
  use AnyStr. Multiple sites on one line are counted separately.
- `pydantic/v1/validators.py` imports Hashable from typing at module scope.
  The return annotation on line 359, `isinstance` argument on line 360, and
  identity comparison on line 716 account for its three sites. It has no
  future-annotations import.
- `typing_extensions.py:618` is the module-level re-export `Text = typing.Text`.
  It is a read, not an annotation.
- pathspec's zero is retained: its internal `_typing.py` imports AnyStr and
  other modules consume that re-export, which these exact import-derived
  matchers do not follow through the project. Zero findings is not evidence
  that the distribution has no AnyStr use.

## Per-rule answer and Task 3 handoff

| Rule | What static evidence answers | What remains open; rerun disposition |
| --- | --- | --- |
| CPY0104 | 20/27 detected sites are annotations, but only 7/27 carry the never-evaluated-local evidence. The same file also has 7 base-class uses. Deferral does not justify treating the remaining 13 annotations as never evaluated. | C1 was not run, so no runtime verdicts were sampled. Attribution of the original 509 not-adjudicable findings remains open; retain this rule for a bounded Task 3 run. |
| CPY0096 | Its sample is mixed: 1/3 annotation, 2/3 runtime expression reads, all Hashable. A blanket annotation-only account is false for this sample. The rule also covers Sized. | No Sized sites and no runtime verdicts were sampled. Attribution of the original 59 not-adjudicable findings remains open; retain both matcher subjects when sampling this rule in Task 3. |
| CPY0126 | Its one site is a runtime re-export. The checked-in rule describes deprecation debt without a removal event, so absence of a raised warning is not by itself a false match. | There are zero Text annotation sites in this sample. It cannot explain the original 211 not-adjudicable findings; retain this rule for Task 3 and select a package with actual Text annotations. |

**No rule's original oracle-limitation versus finding-quality split is settled
by this sample, so no per-rule rerun is skipped.** Static evidence does settle
that `usage_contexts` alone is insufficient and `reference_context` already
supports annotation-site counting for all three rules; do not rerun packages
merely to rediscover those facts. A subsequent sample needs actual
`binding-not-visible` rows to relate syntax to that verdict. These 31 static
findings are neither confirmed nor refuted by this task.

The future-break argument is preserved: an unevaluated-today parameter, return,
class, or module annotation can still be evaluated by runtime introspection
after a removal. A truly never-stored local annotation remains a typing use,
and these rules explicitly cover typing. Match confidence describes resolution
of the deprecated alias; it is separate from impact, removal scheduling, and
whether a warning happens during an import. The static evidence does not
justify lowering confidence, suppressing all annotations, changing a rule, or
changing the oracle. Also, the existing C2 protocol checks presence for
deprecation-only events; it does not score deprecation onset or require a
warning to fire (see [the protocol limitations](../pypi-validation.md#limitations)).
Task 4 owns any eventual proposal and human review.

## Source identity and reproduction

Combined source-manifest SHA-256:
`ccba97eb42b19e1531f1a82213d0d49d4c8bf8723928e5042b2cc853086eca28`.
This is the counter's **local source manifest**, not a `pypi_corpus.py`
acquisition manifest and not the lost sweep's digest.

| Selected source | Source-manifest SHA-256 |
| --- | --- |
| pathspec | `266de14be49e3d428086033e93503e56eb74846cb46e1157ec024b399d926b22` |
| _pytest | `15390dab54a078d5e6e93429e204ca86185628ec5ac0da232303612659c0e3b4` |
| pydantic | `25d79bdb6cb20c9f12841dbcb25a972befa23830f4c68489785b2f383c8cc1ed` |
| typing_extensions.py | `4ad7f51e49e2a97c5904ae932ac3b33c7287124971e44890e44b35d974a460fe` |

Each manifest records distribution name, version, and the sorted relative
source paths with byte lengths and SHA-256 hashes. Hashing uses UTF-8 JSON with
sorted keys and compact separators. The combined digest hashes the four
manifests in the command's order. Reproduction against changed files must be
labelled as another sample even if installed version metadata is unchanged.

The first, second, and fourth inputs came from this worktree's locked `.venv`;
pydantic came from the existing Latch development environment, read as package
source only. The absolute locator below is intentional evidence provenance.
Save the counter appendix as `/tmp/pyahead-binding-not-visible-task2/count_annotations.py`
and run from this checkout:

```console
PYTHONPATH=src .venv/bin/python /tmp/pyahead-binding-not-visible-task2/count_annotations.py \
  pathspec==1.1.1=.venv/lib/python3.13/site-packages/pathspec \
  pytest==9.1.1=.venv/lib/python3.13/site-packages/_pytest \
  pydantic==2.13.4=/work/repos/latch-trader/.venv/lib/python3.13/site-packages/pydantic \
  typing_extensions==4.16.0=.venv/lib/python3.13/site-packages/typing_extensions.py \
  > /tmp/pyahead-binding-not-visible-task2/static-counts.json
```

The script extracted from this document reproduced byte-identical JSON
(`cmp` exit 0), including the same file manifests and all 31 finding records.
Counter SHA-256:
`8b1d7da46f02dfbc94a6d7d7e40618452356fe5dfed6966a2a89b844a6cfd98e`.
JSON SHA-256:
`6cd6cfb672696967cfc3c2d1e7bb30ca62febaf1b1fe17576df811afd581c40e`.

The temporary JSON retains file manifests and per-finding records for local
inspection. Its continued availability is not required to read the counts or
method in this record. These input locations are not durable artifact backups.

## Validation

Validation used the source revision above plus the new characterization tests;
only evidence documentation and the Task 2 plan completion were updated while
the full suite ran or after it ended. No analyser, registry, harness, dependency,
protected design/instruction/CI file, or quality-policy table changed.

- `uv sync --frozen --offline`: passed, 28 locked packages checked.
- `uv run --frozen --offline ruff check .`: passed.
- `uv run --frozen --offline ruff format --check .`: passed.
- `uv run --frozen --offline mypy src scripts`: passed, 46 source files.
- `uv run --frozen --offline pytest`: **1,986 passed, 11 skipped**, exit 0,
  in **1,181.96 seconds**; **91.62%** branch-enabled project coverage against
  the unchanged 90% requirement. The PyPI end-to-end fixture skipped at its
  existing reference-interpreter guard; this run does not demonstrate its
  confirmation/refutation path.
- The 16 new cases in
  [test_typing_alias_contexts.py](../../tests/unit/test_typing_alias_contexts.py)
  also passed separately with `--no-cov` in 10.72 seconds. They characterize
  existing behavior for all four names, direct/aliased imports, ordinary/future
  annotations, local annotations, typing guards, stubs, ordinary reads, base
  classes, and unreported strings. They are not fail-before/pass-after claims
  for a fix: this task implements no behavior change.
- Three standalone counter tests passed. Region/parent-walk agreement held
  for all 31 sampled findings. An extracted-appendix rerun produced identical
  JSON; digest, aggregate reconciliation, appendix parity, and local source-link
  checks passed.
- `uv build --offline`: wheel and sdist built successfully. Both documented
  `scripts/install_smoke.py` checks passed using `--offline --installer-cache
  /home/diegor/.cache/uv`.
- `uv run --frozen --offline pyahead --version`: `pyahead 0.2.0`.
- Registry validation: 133 rules valid. Coverage: 133/133 rules covered,
  377 entries across 13 sources, zero unclassified entries.
- `scripts/benchmark.py --repeat 1 --output -`: exit 0, regression
  `passed=true`, all three cases deterministic. `performance_targets_met`
  remains **false**: one-file, 1,000-file, and 10,000-file durations were
  1.504791, 14.731900, and 114.462511 seconds. This ran alongside other
  validation; it does not demonstrate the stricter design timing targets.
- `git diff --check`: passed; final scope is this evidence record, its
  characterization tests, and the Task 2 plan update. Only intentional
  artifact/source locator paths appear in the evidence; no acquired package,
  raw report, generated artifact, or unrelated work is included.

The first offline build used a temporary uv cache lacking Hatchling and failed
before building. Retrying with the existing host cache passed. The full suite
used host cache access from the outset because the interpreter-discovery tests
clear the temporary cache override, as established in Task 1; no test policy
was changed. Temporary validation logs and counter JSON are under
`/tmp/pyahead-binding-not-visible-task2/`. The counts, method, hashes, and final
validation results are retained here independently of those temporary files.

## Counter appendix

This is a throwaway investigation script, not a new supported product command.

```python
"""One-off source-only count; arguments are NAME==VERSION=SOURCE_PATH."""

import hashlib
import json
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import libcst as cst
from libcst.metadata import MetadataWrapper, ParentNodeProvider, PositionProvider

from pyahead.analysis import ScanRequest, scan

RULES = ("CPY0096", "CPY0104", "CPY0126")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def source_contexts(path):
    wrapper = MetadataWrapper(cst.parse_module(path.read_bytes()))
    parents = wrapper.resolve(ParentNodeProvider)
    positions = wrapper.resolve(PositionProvider)
    result = {}
    for node, region in positions.items():
        if not isinstance(node, (cst.Name, cst.Attribute)):
            continue
        key = (
            region.start.line,
            region.start.column + 1,
            region.end.line,
            region.end.column + 1,
        )
        current = node
        annotation = False
        while current in parents:
            current = parents[current]
            if isinstance(current, cst.Annotation):
                annotation = True
                break
            if isinstance(current, cst.BaseStatement):
                break
        # Names within an Attribute have smaller regions; full regions disambiguate.
        result[key] = annotation
    future = any(
        isinstance(node, cst.ImportFrom)
        and isinstance(node.module, cst.Name)
        and node.module.value == "__future__"
        and not isinstance(node.names, cst.ImportStar)
        and any(
            isinstance(alias.name, cst.Name) and alias.name.value == "annotations"
            for alias in node.names
        )
        for node in positions
    )
    return result, future


def summarize(rows):
    result = {}
    for rule in RULES:
        selected = [row for row in rows if row["rule"] == rule]
        groups = defaultdict(list)
        for row in selected:
            groups[(row["package"], row["path"], row["qualified_name"])].append(
                row["annotation"]
            )
        result[rule] = {
            "findings": len(selected),
            "annotation": sum(row["annotation"] for row in selected),
            "non_annotation": sum(not row["annotation"] for row in selected),
            "contexts": dict(
                sorted(Counter(row["reference_context"] for row in selected).items())
            ),
            "usage_contexts": dict(
                sorted(
                    Counter(",".join(row["usage_contexts"]) for row in selected).items()
                )
            ),
            "annotation_with_future": sum(
                row["annotation"] and row["future_annotations"] for row in selected
            ),
            "never_evaluated_local": sum(
                row["annotation_evaluation"] == "deferred" for row in selected
            ),
            "subjects": dict(
                sorted(Counter(row["qualified_name"] for row in selected).items())
            ),
            "file_subject_groups": len(groups),
            "all_annotation_groups": sum(all(values) for values in groups.values()),
            "mixed_groups": sum(
                any(values) and not all(values) for values in groups.values()
            ),
            "no_annotation_groups": sum(not any(values) for values in groups.values()),
        }
    return result


def main():
    manifests, packages, rows = [], [], []
    for argument in sys.argv[1:]:
        label, source_text = argument.rsplit("=", 1)
        name, version = label.split("==", 1)
        source = Path(source_text).resolve(strict=True)
        paths = (
            [source]
            if source.is_file()
            else sorted(p for p in source.rglob("*") if p.suffix in (".py", ".pyi"))
        )
        assert paths and all(p.is_file() and not p.is_symlink() for p in paths)
        entries = []
        with tempfile.TemporaryDirectory(prefix="pyahead-static-sample-") as temporary:
            root = Path(temporary)
            for path in paths:
                relative = (
                    Path(source.name)
                    if source.is_file()
                    else Path(source.name) / path.relative_to(source)
                )
                raw = path.read_bytes()
                entries.append(
                    {
                        "path": relative.as_posix(),
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            report = scan(
                ScanRequest(
                    root=root,
                    baseline_python="3.11",
                    horizon_python="3.16",
                    source_roots=(".",),
                    respect_gitignore=False,
                    show_unscheduled=True,
                )
            )
            assert report.counts.files_incomplete == 0, report.diagnostics
            assert report.counts.files_analyzed == len(entries), (
                name,
                report.counts,
                len(entries),
            )
            package_rows, context_cache = [], {}
            for finding in report.findings:
                if finding.rule_id not in RULES:
                    continue
                evidence = dict(finding.match_evidence)
                assert finding.match_kind == "qualified-reference"
                assert finding.match_confidence.value == "high"
                path = finding.location.path.as_posix()
                if path not in context_cache:
                    context_cache[path] = source_contexts(root / path)
                contexts, future = context_cache[path]
                region = finding.location.region
                position = (
                    region.start.line,
                    region.start.column,
                    region.end.line,
                    region.end.column,
                )
                annotation = contexts[position]
                assert annotation == (evidence["reference_context"] == "annotation"), (
                    path,
                    position,
                    evidence,
                )
                row = {
                    "package": label,
                    "rule": finding.rule_id,
                    "path": path,
                    "position": position,
                    "scope": finding.enclosing_scope,
                    "qualified_name": evidence["qualified_names"][0],
                    "reference_context": evidence["reference_context"],
                    "annotation": annotation,
                    "future_annotations": future,
                    "annotation_evaluation": evidence.get("annotation_evaluation"),
                    "usage_contexts": [
                        context.value for context in finding.usage_contexts
                    ],
                }
                package_rows.append(row)
            rows.extend(package_rows)
            manifest = {"package": name, "version": version, "files": entries}
            manifests.append(manifest)
            packages.append(
                {
                    "package": label,
                    "source_path": str(source),
                    "source_manifest_sha256": digest(manifest),
                    "files": len(entries),
                    "counts": summarize(package_rows),
                }
            )
            print(
                label,
                len(entries),
                "files;",
                len(package_rows),
                "selected findings",
                file=sys.stderr,
                flush=True,
            )
    result = {
        "schema_version": 1,
        "policy": "3.11-3.16; high; show-unscheduled",
        "registry_revision": report.registry_revision,
        "manifest_sha256": digest(manifests),
        "manifests": manifests,
        "packages": packages,
        "counts": summarize(rows),
        "findings": rows,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
```

## Counter test appendix

Save beside the counter as `test_counter.py`; run with the same interpreter
and `PYTHONPATH=src`. The tests exercise empty samples, all-site grouping, and
independent classification of annotation and value references on one line.

```python
"""Tests for the one-off counter, independent of installed package counts."""

import tempfile
import unittest
from pathlib import Path

from count_annotations import source_contexts, summarize


class CounterTests(unittest.TestCase):
    def row(self, annotation, *, package="a", path="a.py", name="typing.Hashable"):
        return {
            "rule": "CPY0096",
            "package": package,
            "path": path,
            "qualified_name": name,
            "annotation": annotation,
            "reference_context": "annotation" if annotation else "read",
            "usage_contexts": ["runtime", "typing"],
            "future_annotations": False,
            "annotation_evaluation": None,
        }

    def test_empty_rule_is_zero_not_annotation_only(self):
        for result in summarize([]).values():
            self.assertEqual(result["findings"], 0)
            self.assertEqual(result["all_annotation_groups"], 0)

    def test_each_file_subject_group_checks_every_site(self):
        rows = [
            self.row(True),
            self.row(False),
            self.row(True, path="b.py"),
            self.row(True, name="typing.Sized"),
            self.row(False, package="b"),
        ]
        result = summarize(rows)["CPY0096"]
        self.assertEqual(
            (result["findings"], result["annotation"], result["non_annotation"]),
            (5, 3, 2),
        )
        self.assertEqual(
            (
                result["file_subject_groups"],
                result["all_annotation_groups"],
                result["mixed_groups"],
                result["no_annotation_groups"],
            ),
            (4, 2, 1, 1),
        )

    def test_source_walk_distinguishes_same_line_sites_and_strings(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.py"
            path.write_text(
                'from __future__ import annotations\nimport typing\nx: typing.Text = typing.Text\ny: "typing.Text"\n'
            )
            contexts, future = source_contexts(path)
        self.assertTrue(future)
        self.assertTrue(contexts[(3, 4, 3, 15)])
        self.assertFalse(contexts[(3, 18, 3, 29)])
        self.assertNotIn((4, 5, 4, 16), contexts)


if __name__ == "__main__":
    unittest.main()
```
