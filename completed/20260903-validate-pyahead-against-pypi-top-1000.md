# Validate PyAhead against the PyPI top 1000 with per-finding runtime adjudication

## Overview

Build an offline, resumable validation harness that scans the PyPI top-1000 packages with `pyahead check` and adjudicates **every** high-confidence finding against a real CPython interpreter, then reports an agreement rate and an adjudication-coverage breakdown.

The oracle is per-finding runtime adjudication (decided in Q1). Each static finding asserts two things, and each is probed separately under a real interpreter:

- **C1 — binding.** At the finding's site in module `M`, the name PyAhead resolved actually binds at runtime to the CPython subject `S` it claims (`resolved is S`). This catches vendoring, shadowing, rebinding, conditional imports and `TYPE_CHECKING`-only names — the real false-positive sources.
- **C2 — timeline.** `S`'s observable state across interpreters 3.11–3.15 matches the registry's timeline for the rule (present / deprecated / removed / signature changed). This validates the 133 registry rules against the interpreters themselves.

Corpus policy (decided in Q2): attempt all 1000 in rank order. Accuracy is agreement over findings that reached a verdict; adjudication coverage is reported separately with every skip and its reason, and is not gated.

## Context

**Files involved**

- Create: `scripts/pypi_corpus.py` — acquisition and pinned manifest (the only network step)
- Create: `scripts/pypi_probe.py` — probe payload executed *by the target interpreter*; stdlib-only, 3.11-compatible, must never import `pyahead`
- Create: `scripts/pypi_validate.py` — offline runner: provision, scan, probe, adjudicate, write per-package shards
- Create: `scripts/pypi_report.py` — aggregate shards into the accuracy record and an identity-bound disagreement worksheet
- Create: `docs/pypi-validation.md` — protocol, metric definitions, triage procedure, evidence-record template
- Create: `tests/unit/test_pypi_corpus.py`, `tests/unit/test_pypi_probe.py`, `tests/unit/test_pypi_validate.py`, `tests/unit/test_pypi_report.py`
- Create: `tests/integration/test_pypi_validation.py`
- Read-only reference: `src/pyahead/model.py` (`Finding`, `MatchConfidence`), `docs/schema/report-v1.json`, `src/pyahead/data/registry/cpython/*.yaml`
- Possibly modify at triage time: `tests/unit/test_precision_regressions.py`

**Not modified:** anything under `src/pyahead/`. `AGENTS.md` forbids opportunistic later-milestone work, and `docs/design.md` §17.5 reserves target-interpreter probes as a shipped `0.2` evidence provider. This harness is a repo-internal validation tool under `scripts/`; it is explicitly *not* the §17.5 provider and produces no `evidence-v1` artifact.

**Patterns to follow (from `scripts/corpus.py` + `docs/corpus-review.md`)**

- A pinned manifest is local acquisition metadata; the runner verifies identity and never fetches.
- `subprocess.run` with fixed argv, scrubbed environment, explicit timeouts, `check=False`.
- Atomic `mkstemp` + `fsync` + `replace` writes.
- A `CorpusError`-style domain exception; `main()` returns an int; `SafeArgumentParser` and `escape_terminal_text` from `pyahead._human_text` for anything repository-derived.
- Review worksheets are CSV bound to the result's SHA-256, with spreadsheet-formula neutralisation on all package-derived columns.

**Host facts measured this session**

- aarch64, 4 cores, 7 GB RAM, 763 GB free on `/work`.
- `uv` can fetch CPython 3.11.15, 3.12.13, 3.13.14, 3.14.6, 3.15.0b2. **3.16 has no interpreter**, so the scan horizon is 3.15.
- `bwrap` (bubblewrap) and `unshare` are available for probe isolation.
- Calibration: 363 files scanned in ~2–3 min. The full sweep is a multi-day background job — sharding, checkpointing and resume are requirements, not niceties.

**Confirmed report shape driving the probe** (measured, not assumed):

```
match.kind = module-import, evidence = {imported_module, bound_names[], syntax, resolution, source_roots}
match.kind = call-shape,    evidence = {qualified_names[], positional_count, keyword_names[], resolution}
```

**Dependencies:** `uv` (already required), `git` (already required), `bwrap` (optional, degrades to rlimit-only isolation with the fallback recorded in the result).

## Safety

The runner installs and imports arbitrary third-party code. That crosses PyAhead's own "never execute target code, never touch the network" boundary, so:

- the run subcommand requires an explicit `--execute-third-party-code` flag;
- probes run under `bwrap --unshare-net --unshare-pid --die-with-parent` with a read-only bind of the venv, a private `/tmp` and a scratch `HOME`, plus `RLIMIT_AS`/`RLIMIT_CPU`/`RLIMIT_NPROC`/`RLIMIT_FSIZE` and a parent-side wall-clock timeout;
- install (which runs `setup.py`) is the one network-free-but-code-executing step, done from the local wheelhouse with `--no-index`;
- no probe result is ever trusted to be well-formed: all payload output is parsed as JSON with a closed schema.

## Metric definitions

Per high-confidence finding, one verdict:

- `confirmed` — C1 holds under an interpreter where `S` exists, and C2 holds for the rule.
- `refuted-binding` — the name resolves to a different object than `S` → PyAhead false positive.
- `refuted-timeline` — the interpreter contradicts the registry → registry defect.
- `not-adjudicable:<reason>` — closed reason set: `install-failed`, `module-not-importable`, `import-error`, `import-timeout`, `binding-not-visible`, `no-signature`, `probe-timeout`, `probe-crashed`, `no-interpreter`.

```
accuracy              = confirmed / (confirmed + refuted-binding + refuted-timeline)
adjudication_coverage = adjudicated / total high-confidence findings   # reported, not gated
```

Recall is out of scope by construction: per-finding adjudication measures precision, not missed occurrences. `docs/pypi-validation.md` must state this limitation rather than let the number be read as overall accuracy.

## Development Approach

- **Testing approach**: Regular (code first, then tests).
- All tests are hermetic: no network, no PyPI installs, no `uv python install`. Fixtures use synthetic packages and a fake local wheelhouse; probe tests execute the real payload as a subprocess under `sys.executable`.
- `uv run mypy src scripts` covers these files, so everything is fully typed. `scripts/pypi_probe.py` additionally must not import `pyahead` and must parse under 3.11.
- Coverage policy (`source = ["pyahead"]`, `fail_under = 90`) is untouched — do not weaken it.
- Complete each task fully before moving to the next.
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: Pinned corpus manifest and acquisition

**Files:**
- Create: `scripts/pypi_corpus.py`
- Create: `tests/unit/test_pypi_corpus.py`

- [x] `acquire` subcommand (the only network step): read a snapshot of the top-1000 download ranking, resolve each project's current release via the PyPI JSON API, and download one artifact per package (wheel preferred, sdist fallback) into a local wheelhouse directory
- [x] write `schema_version: 1` manifest with `source_url`, `retrieved_on`, upstream-payload SHA-256, and 1000 entries of `{rank, name, version, filename, sha256, requires_python, is_wheel}`; reject duplicate normalised names and any non-HTTPS URL, mirroring `_repository_url` in `scripts/corpus.py`
- [x] `verify` subcommand: offline re-hash of every wheelhouse artifact against the manifest, so the runner can assume a verified corpus
- [x] atomic manifest write; manifest and wheelhouse are local acquisition metadata and are gitignored, not committed (matches `docs/corpus-review.md`)
- [x] write unit tests: manifest schema rejection cases, hash mismatch detection, normalised-name collision, non-HTTPS rejection, atomic write — all against fixture files, no network
- [x] run `uv run pytest` — must pass before Task 2

### Task 2: Interpreter probe payload

**Files:**
- Create: `scripts/pypi_probe.py`
- Create: `tests/unit/test_pypi_probe.py`

- [x] implement a stdlib-only payload reading a JSON probe batch on stdin and writing a JSON result batch on stdout, with a closed result schema and one record per probe
- [x] subject probe (C2): resolve `S` by importing its owner module and walking attributes; report `present`/`absent`, any `DeprecationWarning` captured on import or access, and `inspect.signature` text when introspectable
- [x] binding probe (C1): import module `M` from the scanned distribution, look up the recorded `bound_names`/`qualified_names` head in `M`'s globals (falling back to the `enclosing_scope` object's `__globals__` for function-scope findings), walk the remaining attributes, and compare `resolved is S`; emit `binding-not-visible` when the name exists only in a local scope
- [x] call-shape probe: reconstruct the recorded shape from `positional_count`/`keyword_names` and test it with `inspect.signature(S).bind_partial(...)` using sentinels — **never call the subject**; emit `no-signature` for un-introspectable builtins
- [x] module-import end-to-end probe: under an interpreter where `S` is removed, import `M` and record whether `ModuleNotFoundError` naming `S` is raised — the strongest available confirmation
- [x] guard every probe with per-probe wall-clock and `resource` limits, suppress `sys.exit`/`os._exit` escapes by running each import in a fresh child, and never let a crashing package abort the batch
- [x] write unit tests running the real payload under `sys.executable` against synthetic packages covering: identity match, vendored-shadow refutation, function-local binding, missing subject, signature accept/reject, import raising at module level, and a payload that times out
- [x] run `uv run pytest` — must pass before Task 3

### Task 3: Environment provisioning and static scan

**Files:**
- Create: `scripts/pypi_validate.py`
- Create: `tests/unit/test_pypi_validate.py`

- [x] resolve the interpreter set per package: the lowest available minor satisfying `requires_python` (clamped to ≥3.11) as the scan reference, plus, for each finding, the pair `(action_version - 1, action_version)` intersected with 3.11–3.15
- [x] provision one `uv venv` per `(package, interpreter)` and install offline from the verified wheelhouse with `--no-index --find-links`, capturing failures as `install-failed` with the captured stderr tail rather than aborting
- [x] derive the distribution's own files from `importlib.metadata` RECORD so scanning and probing are restricted to the package, not its dependencies
- [x] scan the reference install with `pyahead check --root <site-packages> --source-root <site-packages> --include <owned top-level globs> --baseline-python <resolved> --horizon-python 3.15 --minimum-confidence high --fail-on never --format json --output -`, accepting exit codes 0 and 3 as `scripts/corpus.py` does
- [x] map each finding's `location.path` to a dotted module name relative to site-packages, and record `no-interpreter` for anything whose action version exceeds 3.15
- [x] write one atomic per-package shard under the work directory; support `--shard i/n`, resume-by-default (skip existing shards unless `--refresh`), `--limit`, per-package timeout and venv teardown after each package
- [x] require `--execute-third-party-code`; apply the bwrap/rlimit isolation from the Safety section and record which isolation mode was used
- [x] write unit tests with a fake wheelhouse of two synthetic distributions: RECORD-derived path selection, path→module mapping (including namespace packages and `__init__.py`), interpreter-set derivation, shard resume and `--refresh`, install-failure capture, missing `--execute-third-party-code`
- [x] run `uv run pytest` — must pass before Task 4

### Task 4: Adjudication and verdicts

**Files:**
- Modify: `scripts/pypi_validate.py`
- Modify: `tests/unit/test_pypi_validate.py`

- [x] build probe batches from the scan's findings, grouped by `(interpreter, module)` so one subprocess adjudicates many findings from one import
- [x] join probe results back to findings by fingerprint and assign exactly one verdict from the closed set, with the deciding evidence retained on every record
- [x] cross-check C2 once per rule per interpreter and cache it: a `refuted-timeline` verdict must name the rule, the interpreter and the observed state
- [x] extend the per-package shard with `verdicts`, per-reason `not-adjudicable` counts, the interpreters actually used, and the isolation mode
- [x] write unit tests over recorded probe fixtures for each verdict and each `not-adjudicable` reason, plus the rule-level timeline cache
- [x] run `uv run pytest` — must pass before Task 5

### Task 5: Accuracy report and disagreement worksheet

**Files:**
- Create: `scripts/pypi_report.py`
- Create: `tests/unit/test_pypi_report.py`

- [x] aggregate all shards into one deterministic JSON record: agreement rate, adjudication coverage, per-reason and per-rule and per-matcher-kind breakdowns, and every skipped package with its reason
- [x] emit an identity-bound CSV worksheet of all `refuted-*` findings plus a deterministic sample of `confirmed` ones, following `scripts/corpus.py`'s `corpus_result_sha256` binding, `--verify-identity` mode, and `_spreadsheet_safe` neutralisation of every package-derived column
- [x] fail closed on an incomplete shard set (missing shard indices, truncated shard, mixed manifest digests) rather than silently reporting a partial denominator
- [x] write unit tests: aggregation arithmetic, identity binding and its verification failure modes, formula neutralisation, incomplete-shard rejection, deterministic ordering
- [x] run `uv run pytest` — must pass before Task 6

### Task 6: Hermetic end-to-end integration test

**Files:**
- Create: `tests/integration/test_pypi_validation.py`

- [x] build a synthetic two-distribution wheelhouse in `tmp_path`: one package whose module genuinely imports a removed stdlib module, and one that vendors a same-named shadow module (a guaranteed `refuted-binding`)
- [x] drive `pypi_corpus.py verify` → `pypi_validate.py` → `pypi_report.py` as real subprocesses against `sys.executable` only, with no network and no `uv python install`
- [x] assert the end-to-end record contains one `confirmed` and one `refuted-binding` verdict, correct coverage arithmetic, and a worksheet that passes `--verify-identity`
- [x] run `uv run pytest` — must pass before Task 7

### Task 7: Verify acceptance criteria

- [x] `uv run ruff check .` and `uv run ruff format --check .`
- [x] `uv run mypy src scripts`
- [x] `uv run pytest` (full suite)
- [x] confirm `git diff --stat` shows no change under `src/pyahead/`, no change to `pyproject.toml` policy tables, and no committed manifest, wheelhouse or venv artifacts
- [x] confirm `scripts/pypi_probe.py` imports no `pyahead` module and parses under `ast.parse(..., feature_version=(3, 11))`

### Task 8: Update documentation

- [x] write `docs/pypi-validation.md`: corpus and acquisition protocol, the C1/C2 oracle, the closed verdict and reason vocabularies, the exact accuracy and coverage formulas, isolation and third-party-code execution warning, shard/resume operation, the triage procedure routing each `refuted-binding` into an inline fixture in `tests/unit/test_precision_regressions.py` and each `refuted-timeline` into a registry correction, and an evidence-record template
- [x] state the two limitations plainly: recall is not measured, and 3.16 rules are unadjudicable because no 3.16 interpreter exists
- [x] add the gitignore entries for the work directory, wheelhouse and manifest
- [x] add a short pointer from `docs/contributing.md` to the new protocol, and note in `docs/design.md` §17.5 that this harness is repo-internal validation and not the shipped probe provider
- [x] run `uv run pytest` and `uv run ruff format --check .` — must pass

## Post-Completion (operator, not automatable)

These require network, hours-to-days of wall clock, and human judgement, so they sit outside the task checkboxes:

1. `uv python install 3.11 3.12 3.13 3.14 3.15`, then `scripts/pypi_corpus.py acquire` to build the pinned manifest and wheelhouse.
2. Run the sharded sweep in the background and let it resume across restarts.
3. `scripts/pypi_report.py` to produce the record and worksheet.
4. Triage every disagreement; land regression fixtures and registry corrections; re-run affected packages only.
5. Record the final agreement rate and adjudication coverage in the evidence document. Per the repo's gate convention, an agent may prepare and verify this evidence but cannot approve it.
