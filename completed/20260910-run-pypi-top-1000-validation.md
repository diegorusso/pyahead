# Run the PyPI top-1000 validation sweep and triage its disagreements

## Overview

Execute the existing validation harness against the PyPI top-1000, adjudicate
every high-confidence finding against real CPython interpreters, triage the
disagreements it finds, and record an accountable evidence document.

**This plan builds nothing.** `scripts/pypi_corpus.py`, `scripts/pypi_probe.py`,
`scripts/pypi_validate.py` and `scripts/pypi_report.py` already exist, total
about 4,200 lines, carry 262 tests, and are specified in
[`pypi-validation.md`](../pypi-validation.md). They have never been run against
a real package. The work here is operating them, then acting on what they
report. Do not re-derive, refactor, or "improve" the harness while running it;
if a genuine harness defect blocks the sweep, fix that defect narrowly and say
so in the task's evidence.

The oracle, the closed verdict vocabulary, the metric definitions, the
shard/resume semantics, the aggregation rules and the triage procedure are all
already defined in `docs/pypi-validation.md`. This plan does not restate them —
read that document first and follow it.

## Context

- Harness entry points: `pypi_corpus.py acquire|verify`, `pypi_validate.py run`,
  `pypi_report.py` (aggregate, and `--verify-identity`).
- Gitignored acquisition and run artifacts, already listed in `.gitignore`:
  `work/pypi-manifest.json`, `work/pypi-wheelhouse/`, `work/pypi-validate/`,
  `work/pypi-report.json`, `work/pypi-disagreements.csv`. Never commit any of
  them, matching `docs/corpus-review.md`.
- Prior evidence for comparison: `docs/evidence/gate-c.md` records 100 pinned
  repositories, 448 high-confidence findings, 100% sampled precision, judged by
  source inspection rather than execution. This sweep is a different and
  stronger instrument, not a re-run of that one.
- Current release: `pyahead 0.2.0`, registry revision `3a2bf7aafb44`, 133 rules.
- Measurement host: 4 cores, 7 GB RAM, ~700 GB free, `bwrap` present.
- Only CPython 3.13 is installed locally; 3.11, 3.12, 3.14 and 3.15 must be
  installed before the sweep or most findings become
  `not-adjudicable:no-interpreter`.

## Safety

`pypi_validate.py run` installs and imports arbitrary third-party code. It is
the one tool in this repository that deliberately crosses the default scan
boundary. Before any sweep task runs:

- `--execute-third-party-code` must be passed explicitly; the run refuses to
  start without it.
- `bwrap` must be present, and the recorded `isolation_mode` must be `bwrap`.
  **If any package records `rlimit-only`, stop and report it.** That fallback
  has no filesystem isolation, and `docs/security-and-privacy.md` requires a
  dedicated account with no credentials on the same filesystem before it is
  acceptable.
- Nothing in `work/` is ever committed, quoted verbatim into a commit message,
  or pasted into an evidence document without the formula-neutralisation the
  worksheet already applies.

## Development Approach

- Work one task at a time. Each task must end with the repository's own gate
  passing: `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy src scripts`, `uv run pytest`.
- The sweep is long. On this host a full 1000-package pass across five
  interpreters is plausibly tens of hours, far beyond one session. Resume is
  the default: an existing shard is skipped unless `--refresh` is passed, so
  bounded invocations converge. Never delete `work/pypi-validate/shards/` to
  "start clean" — that discards completed work and changes nothing about a
  failure.
- Protected as always: `docs/design.md`, `AGENTS.md`, `.github/workflows/**`,
  and the `tool.ruff`, `tool.mypy`, `tool.pytest.ini_options`,
  `tool.coverage.*` tables in `pyproject.toml`. Never weaken a threshold to
  make a triage fix pass.
- Corpus policy is fixed before any result is seen: all 1000 packages in
  download-rank order, no filtering, no exclusion of packages because they look
  likely or unlikely to produce findings.

## Implementation Steps

### Task 1: Preflight

- [x] confirm `bwrap` is on PATH and record its path; confirm free disk is at
      least 100 GB and record the figure
- [x] `uv python install 3.11 3.12 3.13 3.14 3.15`, then record
      `uv python list --only-installed`; any minor that fails to install must be
      named, because its absence converts findings to
      `not-adjudicable:no-interpreter`
- [x] record `uv run pyahead --version` and the registry revision from
      `uv run pyahead registry validate`
- [x] run the repository gate and record each result verbatim
- [x] confirm the harness's own tests pass:
      `uv run pytest tests/unit/test_pypi_corpus.py tests/unit/test_pypi_probe.py
      tests/unit/test_pypi_validate.py tests/unit/test_pypi_report.py
      tests/integration/test_pypi_validation.py`

**Evidence (Task 1, run 2026-09-10 on the measurement host, Linux aarch64,
4 cores, 7 GB RAM):**

- `bwrap` resolves on PATH to `/usr/bin/bwrap`, bubblewrap 0.11.0. Free disk
  on the repository filesystem: 705 GB available of 915 GB (`df -BG`), above
  the 100 GB floor.
- `uv python install 3.11 3.12 3.13 3.14 3.15` (uv 0.11.21) exited 0 with all
  five minors present. `uv python list --only-installed` reports, all
  `linux-aarch64-gnu`: cpython-3.11.15, cpython-3.12.13, cpython-3.13.14 and
  the system cpython-3.13.5, cpython-3.14.6, cpython-3.15.0b2. No minor failed
  to install, so no finding with an action version in 3.11-3.15 will be
  `not-adjudicable:no-interpreter` for want of an interpreter.
- `uv run pyahead --version`: `pyahead 0.2.0`.
  `uv run pyahead registry validate`:
  `Registry 2026.07.31 (3a2bf7aafb44): 133 rules valid.`
- Repository gate, verbatim, each exit 0:
  - `uv run ruff check .`: `All checks passed!`
  - `uv run ruff format --check .`: `464 files already formatted`
  - `uv run mypy src scripts`: `Success: no issues found in 46 source files`
  - `uv run pytest`: `1897 passed, 11 skipped in 1150.93s (0:19:10)`;
    `Required test coverage of 90.0% reached. Total coverage: 91.60%`;
    coverage TOTAL 8773 statements, 586 missed, 2800 branches, 366 partial,
    92%. The 19-minute wall clock was measured with another CPU-bound process
    sharing the host (load average about 3 on 4 cores).
- Harness tests, exact command from this task:
  `261 passed, 1 skipped in 26.37s`, no failures or errors. The process exit
  code was 1 solely because pytest-cov applies the whole-suite 90% coverage
  floor to the subset (`FAIL Required test coverage of 90.0% not reached.
  Total coverage: 0.53%`; the harness lives under `scripts/`, outside the
  measured `pyahead` package). Re-run with `--no-cov -rs`:
  `261 passed, 1 skipped in 20.45s`, exit 0. The one skip is
  `tests/integration/test_pypi_validation.py:181`, "no installed interpreter
  has passed a real stdlib removal; confirmation is unreachable with only one
  interpreter": the hermetic test takes as its reference the interpreter the
  harness would pick for an unconstrained package, which is the lowest
  installed minor, and this preflight installed 3.11, where `imp` (the
  fixture's removed module, gone in 3.12) still imports. This is a consequence
  of the test's single-interpreter design, not a harness defect, and does not
  affect the sweep, which resolves each package's reference from its own
  `requires_python` and cross-checks at every installed minor a finding
  needs. It does mean the end-to-end integration test does not execute on a
  host with 3.11 installed.

### Task 2: Acquire and verify the corpus

- [x] `uv run python scripts/pypi_corpus.py acquire --manifest
      work/pypi-manifest.json --wheelhouse work/pypi-wheelhouse --timeout 30`
      (the only network step)
- [x] record the manifest's `source_url`, `retrieved_on`, upstream-payload
      SHA-256, entry count, and the manifest file's own SHA-256
- [x] record how many entries are wheels versus sdists, and name any package
      the acquisition could not resolve, with its reason
- [x] `uv run python scripts/pypi_corpus.py verify --manifest
      work/pypi-manifest.json --wheelhouse work/pypi-wheelhouse` and record that
      it re-hashed every artifact offline without error
- [x] confirm `git status --porcelain` shows nothing from `work/`

**Evidence (Task 2, run 2026-09-10 on the measurement host):**

- **First `acquire` attempt aborted; one narrow harness fix was needed.** The
  exact command above ran 21:45:13Z to 21:50:43Z, downloaded 588 artifacts
  (2.1 GB), and exited 1 at rank 589 with
  `pypi corpus run failed: PyPI metadata for pywin32 312 has no wheel or sdist`.
  pywin32 312 publishes 21 wheels, all `win32`, `win_amd64` or `win_arm64`
  for cp39 through cp315, and no sdist, so nothing is installable on this
  Linux aarch64 host. The harness treated that as fatal for the whole corpus,
  which contradicts this plan's own expectation that unresolvable packages
  are named with a reason and the spec's "attempt all 1000" policy, and it
  would have recurred for any other Windows-only or x86-only package further
  down the ranking. The fix, confined to `scripts/pypi_corpus.py`: a typed
  `NoInstallableArtifactError` for exactly this case; `acquire` records the
  package under a new manifest `unresolved` list as
  `{rank, name, version, reason}` with the closed reason
  `no-installable-artifact` and continues, keeping the rank reserved rather
  than filling it from rank 1001; every other acquisition error still
  aborts. `load_manifest` validates that list with the same rank and
  normalised-name uniqueness as `packages`, requires `packages` plus
  `unresolved` to account for exactly 1000 ranks, treats a missing
  `unresolved` key as empty, and still returns only resolved entries, so
  `pypi_validate.py` and `pypi_report.py` are unchanged.
  `docs/pypi-validation.md` documents the list and adds an
  `unresolved_at_acquisition` line to the evidence template. Fourteen unit
  tests were added in `tests/unit/test_pypi_corpus.py` (acquisition records
  and skips the download, other errors still abort, the typed error, loader
  acceptance, and ten malformed-list rejections). The harness subset from
  Task 1 now reports `275 passed, 1 skipped in 22.11s` with `--no-cov`, the
  same single skip as before.
- **Second `acquire` run, same command, completed.** 21:58:35Z to 22:12:15Z
  (13 min 40 s), exit 0. The one progress line that was not `resolving` was
  `[589/1000] unresolved pywin32 312: no-installable-artifact`. The
  configured `source_url` answers with a 301 to
  `https://hugovk.dev/top-pypi-packages/top-pypi-packages.json`, which
  urllib follows; the manifest records the configured URL.
- **Manifest** (`work/pypi-manifest.json`, 298,090 bytes, `schema_version` 1):
  - `source_url`:
    `https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json`
  - `retrieved_on`: `2026-09-10T22:12:15.444658+00:00`
  - `upstream_payload_sha256`:
    `cff04ba201a688456eef83ed14deae66a93c143ca5bbc10951b298f9bf9e779e`
  - manifest file SHA-256:
    `bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b`
  - entry count: 999 `packages` plus 1 `unresolved`, ranks 1-1000 covered
    exactly once; 36 package entries carry a null `requires_python`.
- **Artifact kinds:** 996 wheels, 3 sdists (psycopg2, pyspark, thinc: no
  wheel installable by CPython 3.11-3.15 on linux-aarch64).
  **Unresolved:** rank 589, pywin32 312, `no-installable-artifact` (Windows-only
  wheels, no sdist). Nothing else failed to resolve.
- **Offline verify:** `uv run python scripts/pypi_corpus.py verify --manifest
  work/pypi-manifest.json --wheelhouse work/pypi-wheelhouse` exit 0 with no
  problem lines, 185 s, so all 999 artifacts re-hashed to their manifest
  SHA-256 and the wheelhouse holds no unmanifested file (the 588 artifacts from
  the aborted first attempt were overwritten in place by the second run, none
  left over). The wheelhouse is 999 files, 7.7 GB; 697 GB remain free.
- **Git:** `git status --porcelain` lists only the three tracked files changed
  by the fix (`docs/pypi-validation.md`, `scripts/pypi_corpus.py`,
  `tests/unit/test_pypi_corpus.py`); `git status --ignored` shows
  `work/pypi-manifest.json` and `work/pypi-wheelhouse/` as ignored, so nothing
  under `work/` can be committed.
- Repository gate after the fix, verbatim, each exit 0:
  - `uv run ruff check .`: `All checks passed!`
  - `uv run ruff format --check .`: `464 files already formatted`
  - `uv run mypy src scripts`: `Success: no issues found in 46 source files`
  - `uv run pytest`: `1911 passed, 11 skipped in 1152.62s (0:19:12)`;
    `Required test coverage of 90.0% reached. Total coverage: 91.60%`;
    coverage TOTAL unchanged at 8773 statements, 586 missed, 2800 branches,
    366 partial, 92% (the fix lives under `scripts/`, outside the measured
    package). The 14 new tests account for the rise from Task 1's 1897.

### Task 3: Smoke run before committing to the sweep

- [x] run a bounded pass:
      `uv run python scripts/pypi_validate.py run --manifest work/pypi-manifest.json
      --wheelhouse work/pypi-wheelhouse --work-dir work/pypi-validate
      --execute-third-party-code --limit 25 --timeout 300 --horizon-python 3.15`
- [x] record wall-clock time for those 25 packages and extrapolate an estimate
      for 1000; state the estimate explicitly
- [x] open at least one `scanned` shard and one non-`scanned` shard and record
      their `status`, `reason`, finding count, and verdicts
- [x] confirm every shard records `isolation_mode: bwrap`; if any records
      `rlimit-only`, stop and report per Safety
- [x] if the smoke pass produces zero findings across all 25 packages, stop and
      report that rather than proceeding: it more likely indicates a harness or
      scanning defect than a clean top-25

**Evidence (Task 3, run 2026-09-10 22:37Z to 23:27Z on the measurement
host; job logs kept under `/var/tmp`, outside `work/`):**

- **Three harness defects blocked the smoke run; each was fixed narrowly.**
  None changes what the harness measures; all three were invisible to the
  unit tests because those use absolute temporary paths and a single host
  interpreter. In the order met:
  1. *Invocation.* The plan's and spec's exact command,
     `uv run python scripts/pypi_validate.py run ...`, exits 1 at import
     with `ModuleNotFoundError: No module named 'scripts'`: the runner and
     `pypi_report.py` import `scripts.pypi_corpus`, and run as a file path
     `sys.path[0]` is `scripts/`, not the repository root. The harness's own
     integration test drives them as `python -m scripts.pypi_validate` from
     the root. Fix: documentation only. The three commands in
     `docs/pypi-validation.md` now use the module form plus one explanatory
     sentence; every command below is the plan's, with
     `python -m scripts.pypi_validate` in place of the file path. Tasks 5 and
     6 must invoke `python -m scripts.pypi_report` the same way.
  2. *Relative `--work-dir`.* The first real attempt (22:38:05Z, exit 0 after
     2 s) wrote 25 `install-failed` shards, each with reason
     `bwrap: Can't find source path work/pypi-validate/tmp/<rank>/venv`.
     `_run` resolved the manifest and wheelhouse to absolute paths but
     passed the work directory through as given; the per-package venv and
     scratch home derive from it and are handed to `bwrap` as bind sources,
     which bubblewrap resolves against the sandbox's old root, so a relative
     path is never found. Fix: one line in `scripts/pypi_validate.py`
     (`arguments.work_dir.resolve()`), covered by
     `test_run_resolves_a_relative_work_dir_before_processing`, checked to
     fail without the fix and pass with it.
  3. *C2 probes started through launcher links.* The second attempt
     (22:40:37Z to 23:00:45Z, 20 min 8 s, exit 0) scanned 23 packages and
     found 201 findings but reached zero `confirmed` verdicts: 94 were
     `not-adjudicable:probe-crashed` with binding evidence
     `identity_match: true`, meaning C1 passed and C2 never answered.
     Re-running one subject probe by hand through the harness's own
     `_isolate_command` showed the discarded stderr:
     `bwrap: execvp ~/.local/bin/python3.11: No such file or directory`.
     `uv python list --only-installed` reports each interpreter through the
     launcher link that `uv python install` places in `~/.local/bin`, and
     the sandbox binds only `uv python dir` and the base system roots. C1
     was unaffected because it executes the venv's own `bin/python`, which
     lives under the bound venv and resolves under uv's root. The same probe
     with `bwrap` removed answered `present` at once, so the interpreters
     and probe script were fine; only the exec path was. Fix:
     `_installed_interpreters` records `Path(path).resolve()`, covered by
     `test_installed_interpreters_resolve_launcher_symlinks`; all five
     minors now resolve under `~/.local/share/uv/python/`.
- **Isolation record, reported per Safety.** In that second attempt the 15
  scanned packages with no findings carried
  `adjudication.isolation_mode: "rlimit-only"` although no probe batch ran
  for them: it was the field's initial value, not an execution record. The
  shard-level install mode was `bwrap` on all 25 shards and the 8 packages
  whose probes did run recorded `bwrap`, so no third-party code executed
  outside `bwrap` in any attempt. Because that default would have flagged
  every zero-finding package in the full sweep as a fallback, the initial
  value is now `None`, mirroring the shard-level `isolation_mode: null`
  used when no install ran, covered by
  `test_run_records_no_probe_isolation_mode_without_findings` and one
  sentence in `docs/pypi-validation.md`.
- **Recorded smoke pass** (third attempt): the plan's command with
  `--refresh` added so the 25 shards of the defective attempts were
  reprocessed rather than deleted. 23:05:25Z to 23:26:32Z, exit 0.
  - Wall clock 1267 s (21 min 7 s) for 25 packages: 50.7 s per package,
    median 10 s. Slowest: setuptools 349 s, numpy 301 s (scan timeout),
    pygments 159 s, pytest 127 s, anyio 73 s. Load average 2.4 to 3.4 on
    4 cores throughout, from an unrelated CPU-bound process.
  - **Estimate for 1000:** 50.7 s x 999 resolved packages = 14.1 h serial on
    this loaded host. With three shards in parallel as Task 4 suggests,
    plan for roughly 5 to 8 h wall clock. Two caveats pull in opposite
    directions: ranks 1-25 are unusually large packages, so deeper ranks
    should be cheaper; but a package whose scan exceeds `--timeout` costs
    the whole timeout and is lost as `scan-failed` (numpy here), so Task 4
    should consider a larger scan timeout, which raises the worst case.
  - **Status distribution:** 23 `scanned`, 1 `install-failed`, 1
    `scan-failed`, 0 `skipped`. All 25 shards record `isolation_mode: bwrap`
    for the install; adjudication `isolation_mode` is `bwrap` for the 8
    packages where a probe batch ran and `null` for the 15 with no findings.
    No `rlimit-only` anywhere.
  - **Scanned shard, rank 9 setuptools 84.0.0:** `status: scanned`,
    `reason: null`, reference 3.11.15, scan exit 0 in 76.4 s, 113
    high-confidence findings; verdicts confirmed 81, refuted-binding 5,
    not-adjudicable 27 (all `binding-not-visible`); interpreters used 3.11
    to 3.14. A confirmed example: CPY0023 `distutils` module-import in
    `setuptools`, binding resolved with `identity_match: true`, timeline
    observed present at 3.11 and absent at 3.12. The five refuted-binding
    findings are CPY0023 in setuptools' own modules where the name binds at
    runtime to setuptools' vendored `_distutils` rather than the stdlib
    subject (`identity_match: false`, subject absent), Task 6 material.
    A second scanned shard, rank 3 typing-extensions 4.16.0: one finding,
    CPY0126 `typing.Text` qualified-reference, `confirmed`.
  - **Non-scanned shards:** rank 18 pydantic 2.13.5, `status:
    install-failed`, `isolation_mode: bwrap`, reference 3.11.15, reason: the
    offline resolver found no solution because pydantic 2.13.5 pins
    `pydantic-core==2.46.5` while the wheelhouse holds only pydantic-core
    2.49.0, rank 24's current release. That is a property of a
    one-artifact-per-project corpus, not a harness fault, and it contributes
    no findings. Rank 19 numpy 2.5.3, `status: scan-failed`, reason
    `scan exceeded its timeout`, `isolation_mode: bwrap`, reference 3.12.13
    (`requires_python >=3.12`): `pyahead check` over numpy's own files did
    not finish within 300 s on the loaded host.
  - **Findings and verdicts:** 201 high-confidence findings across 8 of the
    23 scanned packages, so the zero-findings stop condition did not apply.
    Verdicts: confirmed 94, refuted-binding 6, not-adjudicable 101
    (`binding-not-visible` 92, `import-error` 9). Agreement over adjudicated
    findings 94/100; adjudication coverage 100/201. By matcher kind:
    module-import 86 confirmed, 5 refuted, 29 not-adjudicable;
    qualified-reference 7 confirmed, 1 refuted, 72 not-adjudicable;
    call-shape 1 confirmed. By rule: CPY0023 (`distutils`) 86 confirmed, 5
    refuted, 28 not-visible; CPY0104 (`typing.AnyStr`) 1 confirmed, 62
    not-visible, 2 import-error; CPY0105 3 confirmed; CPY0094, CPY0109,
    CPY0123, CPY0126 1 confirmed each; CPY0122 3 and CPY0124 4 import-error
    (all in `urllib3.contrib.pyopenssl`, whose import needs pyOpenSSL,
    absent from the venv); CPY0024 and CPY0088 1 not-visible each; CPY0043
    (`asyncio.AbstractChildWatcher` in `anyio._backends._asyncio`) 1
    refuted-binding. The 92 `binding-not-visible` findings are references
    the runtime probe cannot see from module scope, a designed coverage
    limit, not a precision defect.
- **Gate after the fixes, verbatim, each exit 0:**
  - `uv run ruff check .`: `All checks passed!`
  - `uv run ruff format --check .`: `464 files already formatted`
  - `uv run mypy src scripts`: `Success: no issues found in 46 source files`
  - harness subset with `--no-cov -rs`: `278 passed, 1 skipped in 24.46s`,
    the same single skip as Task 1; the three new tests raise Task 2's 275.
  - `uv run pytest`: `1914 passed, 11 skipped in 1166.54s (0:19:26)`;
    `Required test coverage of 90.0% reached. Total coverage: 91.60%`;
    coverage TOTAL 8773 statements, 586 missed, 2800 branches,
    366 partial, 92%, unchanged from Task 2 (the fixes live under
    `scripts/`, outside the measured package); the three new tests account
    for the rise from Task 2's 1911. Wall clock again measured with the
    unrelated CPU-bound process sharing the host.
- `git status --porcelain` lists only `docs/pypi-validation.md`,
  `scripts/pypi_validate.py`, `tests/unit/test_pypi_validate.py` and this
  plan; `work/` remains ignored in full.

### Task 4: Full sweep

- [x] run the remaining packages to completion using shards sized for this host,
      for example `--shard 0/3` through `--shard 2/3` as separate background
      jobs writing into the same `--work-dir`, leaving a core free
- [x] resume as needed rather than restarting; record how many invocations were
      needed and any that were killed by a timeout
- [x] on completion, confirm `work/pypi-validate/shards/` holds exactly one
      shard per manifest entry and record the count
- [x] record the distribution of shard `status` values, and for every
      non-`scanned` shard its `reason`

**Evidence (Task 4, run 2026-09-10 23:50Z to 2026-09-11 03:14Z on the
measurement host; job logs and exit markers kept under `/var/tmp`, outside
`work/`):**

- **Invocations: 2; runners killed by a timeout: 0.** Invocation 1 was the
  sweep proper: three detached runners, each the plan's command in the module
  form Task 3 established, `uv run python -m scripts.pypi_validate run
  --manifest work/pypi-manifest.json --wheelhouse work/pypi-wheelhouse --work-
  dir work/pypi-validate --execute-third-party-code --shard N/3 --timeout 900
  --horizon-python 3.15` for N in 0, 1, 2, started 23:50:35Z to 23:50:51Z,
  leaving the fourth core to the host's unrelated CPU-bound process.
  `--timeout 900` replaces the smoke run's 300, as Task 3 recommended. Resume
  was relied on rather than restart: the 25 smoke-run shards were kept, so the
  runners processed the 974 remaining resolved packages (324, 325 and 325).
  Every runner exited 0 of its own accord: shard 2/3 at 02:53:57Z, 1/3 at
  03:02:57Z, 0/3 at 03:14:10Z. The session that launched them was ended by its
  own two-hour limit while it polled; that is a limit of the driving session,
  not of the harness. The detached runners were unaffected, were observed to
  completion from a fresh session, and no shard was re-run or resumed.
  Invocation 2 was one targeted refresh, `--shard 18/999 --refresh --timeout
  900`, which selects rank 19 only: numpy's smoke-run shard was the only one
  carrying a parameter the sweep did not use (`scan-failed` at the smoke run's
  300 s). It ran 02:58:47Z to 03:07:55Z, after shard 2/3 had freed a core, and
  exited 0; numpy is now `scanned` (reference 3.12.13, scan 544 s, 1 high-
  confidence finding, `not-adjudicable:import-error`).
- **Wall clock:** 3 h 23 min 35 s from the first runner's start to the last
  runner's exit for 974 packages on three runners, load average 4 to 6 on 4
  cores throughout. Per package, from the runner logs' timestamps (974
  packages): mean 35.7 s, median 7 s, p90 71 s, max 910 s; Task 3's 50.7 s
  over ranks 1-25 was, as it predicted, an overestimate for deeper ranks. Scan
  duration as recorded on the 797 scanned shards: mean 33.3 s, median 8.0 s,
  p90 76.8 s, max 884.5 s (google-cloud-compute); 15 scans exceeded 300 s, so
  the smoke run's timeout would have lost 12 more packages than 900 s did.
- **Shard reconciliation:** manifest resolved entries 999; shard files 999; missing 0; unexpected 0; manifest_sha256 on every shard: {'bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b': 999}
- **Status distribution:** scanned 797, install-failed 155, skipped 42, scan-failed 5
- **Isolation:** shard-level isolation_mode {'bwrap': 998, 'None': 1}; adjudication isolation_mode over scanned shards {'None': 611, 'bwrap': 186}
- **Safety, per the plan's rule:** every one of the 998 shards where an
  install ran records `isolation_mode: bwrap`. The single `null` is rank 959
  backports-asyncio-runner 1.2.0 (`requires_python <3.11,>=3.8`), `skipped:
  no-compatible-interpreter`, for which no venv was created and no third-party
  code ran. Adjudication `isolation_mode` is `bwrap` for the 186 scanned
  packages where a probe batch ran and `null` for the 611 with no findings. No
  shard anywhere records `rlimit-only`; no third-party code executed outside
  `bwrap` at any point.
- **Every non-scanned shard (202), grouped by status and reason (rank name version: detail):**
  - install-failed, dependency version not the single artifact the corpus holds (89):
    - [35] 60 fastapi 0.141.1; 83 pydantic-settings 2.15.0; 98 openai 3.13.0; 122 mcp 2.2.0; 151 google-genai 2.22.0; 158 langchain 1.4.0; 208 anthropic 1.5.0; 236 langchain-core 1.6.2; 293 pydantic-ai-slim 2.42.0; 301 langsmith 0.12.4; 327 pydantic-graph 2.42.0; 348 weaviate-client 4.23.1; 401 pydantic-extra-types 2.11.1; 471 mcp-types 2.2.0; 496 openapi-pydantic 0.5.1; 660 mistralai 2.10.0; 698 openapi-spec-validator 0.9.0; 703 openai-agents 0.22.2; 704 pyiceberg 0.12.0; 708 realtime 2.31.0; 749 agent-client-protocol 0.12.1; 770 storage3 2.31.0; 771 postgrest 2.31.0; 813 supabase-auth 2.31.0; 840 langfuse 4.15.2; 866 weasel 1.0.0; 867 wandb 0.30.0; 875 groq 1.7.0; 903 genai-prices 0.1.6; 910 llama-cloud 2.16.0; 911 openapi-schema-validator 0.9.0; 918 langchain-anthropic 1.7.2; 926 sqlmodel 0.0.42; 992 ollama 0.6.2; 994 aws-sam-translator 1.113.0: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic==2.13.5 is available and <pkg> depends on pydantic==2.13.5 (corpus holds pydantic-core 2.49.0)
    - [4] 432 langchain-openai 1.6.2; 510 langgraph-prebuilt 1.1.0; 525 langgraph-checkpoint 4.2.0; 581 langchain-text-splitters 1.1.2: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic==2.13.5 is available and langchain-core==1.6.2 depends on pydantic==2.13.5, we can conclude that langchain-core==1.6.2 cannot be used. And because only langchain-core==1.6.2 is available and <pkg> depends on langchain-core==1.6.2 (corpus holds pydantic-core 2.49.0)
    - [2] 339 dbt-adapters 1.24.5; 384 dbt-core 1.12.4: Because only agate==1.14.2 is available and dbt-common==1.39.0 depends on agate>=1.7.0,<1.10, we can conclude that dbt-common==1.39.0 cannot be used. And because only dbt-common==1.39.0 is available and <pkg> depends on dbt-common==1.39.0
    - [2] 623 omegaconf 2.3.1; 946 hydra-core 1.3.6: Because only antlr4-python3-runtime==4.13.2 is available and <pkg> depends on antlr4-python3-runtime==4.9.* (corpus holds antlr4-python3-runtime 4.13.2)
    - [2] 622 mlflow-skinny 3.16.0; 868 mlflow-tracing 3.16.0: Because only databricks-sdk==0.137.0 is available and databricks-sdk==0.137.0 depends on one of 10 ranges (protobuf>=4.25.8,<5.26.dev0 ... protobuf>6.31.0,<7.0) we can conclude that databricks-sdk==0.137.0 depends on one of 10 ranges (protobuf>=4.25.8,<5.26.dev0 ... protobuf>6.31.0,<7.0) And because only protobuf==7.36.1 is available, we can conclude that databricks-sdk==0.137.0 depends on protobuf>=4.25.8,<5.0. And because opentelemetry-proto==1.44.0 depends on protobuf==7.36.1 and only opentelemetry-proto==1.44.0 is available, we can conclude that databricks-sdk==0.137.0 and opentelemetry-proto==1.44.0 are incompatible. And because <pkg> depends on databricks-sdk==0.137.0 and opentelemetry-proto==1.44.0
    - [2] 390 fastmcp-slim 4.0.3; 467 fastapi-cloud-cli 0.26.0: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic[email]==2.13.5 is available and <pkg> depends on pydantic[email]==2.13.5 (corpus holds pydantic-core 2.49.0)
    - 974 django-cors-headers 4.9.0: Because django==6.1.1 requires Python >=3.12 and only django==6.1.1 is available, we can conclude that django==6.1.1 cannot be used. And because <pkg> depends on django==6.1.1 (corpus holds django 6.1.1)
    - 415 dbt-common 1.39.0: Because only agate==1.14.2 is available and <pkg> depends on agate>=1.7.0,<1.10 (corpus holds agate 1.14.2)
    - 503 pylint 4.0.8: Because only astroid==4.3.1 is available and <pkg> depends on astroid>=4.0.2,<=4.1.dev0 (corpus holds astroid 4.3.1)
    - 26 aiobotocore 3.9.1: Because only botocore==1.43.92 is available and <pkg> depends on botocore>=1.43.66,<1.43.76 (corpus holds botocore 1.43.92)
    - 59 s3fs 2026.7.0: Because only botocore==1.43.92 is available and aiobotocore==3.9.1 depends on botocore>=1.43.66,<1.43.76, we can conclude that aiobotocore==3.9.1 cannot be used. And because only aiobotocore==3.9.1 is available and <pkg> depends on aiobotocore==3.9.1
    - 426 snowflake-snowpark-python 1.55.0: Because only cloudpickle==3.1.2 is available and <pkg> depends on one of 3 ranges (cloudpickle>=1.6.0,<2.1.0 ... cloudpickle>2.2.0,<=3.1.1) (corpus holds cloudpickle 3.1.2)
    - 811 djangorestframework 3.18.1: Because only django==6.1.1 is available and django==6.1.1 requires Python >=3.12, we can conclude that django==6.1.1 cannot be used. And because <pkg> depends on django==6.1.1 (corpus holds django 6.1.1)
    - 249 awscli 1.46.1: Because only docutils==0.23 is available and <pkg> depends on docutils>=0.18.1,<=0.19 (corpus holds docutils 0.23)
    - 442 sphinx 9.1.0: Because only docutils==0.23 is available and <pkg> depends on docutils>=0.21,<0.23 (corpus holds docutils 0.23)
    - 601 swebench 5.0.2: Because only ghapi==2.1.3 is available and <pkg> depends on ghapi<2 (corpus holds ghapi 2.1.3)
    - 286 google-cloud-aiplatform 2.1.0: Because only google-api-core[grpc]==2.36.0 is available and google-api-core==2.36.0 depends on protobuf==7.36.1, we can conclude that google-api-core[grpc]==2.36.0 depends on protobuf==7.36.1. And because only protobuf==7.36.1 is available, we can conclude that google-api-core[grpc]==2.36.0 depends on protobuf==7.36.1. And because <pkg> depends on google-api-core[grpc]==2.36.0 and one of 7 ranges (protobuf>=3.20.2,<4.21.0 ... protobuf>4.21.5,<7.0.0)
    - 690 delta-spark 4.4.0: Because only importlib-metadata==9.0.1 is available and <pkg> depends on importlib-metadata>=1.0.0,<=8.7.1 (corpus holds importlib-metadata 9.0.1)
    - 830 instructor 1.17.0: Because only jiter==0.16.0 is available and <pkg> depends on jiter>=0.6.1,<0.15 (corpus holds jiter 0.16.0)
    - 450 langgraph 1.2.11: Because only langchain-core==1.6.2 is available and langchain-core==1.6.2 depends on pydantic==2.13.5, we can conclude that langchain-core==1.6.2 depends on pydantic==2.13.5. And because only pydantic==2.13.5 is available, we can conclude that langchain-core==1.6.2 depends on pydantic==2.13.5. (1) Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because we know from (1) that langchain-core==1.6.2 depends on pydantic==2.13.5, we can conclude that langchain-core==1.6.2 cannot be used. And because <pkg> depends on langchain-core==1.6.2 (corpus holds pydantic-core 2.49.0)
    - 780 llama-index-indices-managed-llama-cloud 0.12.0: Because only llama-cloud==2.16.0 is available and <pkg> depends on llama-cloud>=1.6.0,<2 (corpus holds llama-cloud 2.16.0)
    - 464 dataclasses-json 0.6.7: Because only marshmallow==4.3.1 is available and <pkg> depends on marshmallow>=3.18.0,<4.0.0 (corpus holds marshmallow 4.3.1)
    - 678 strands-agents 1.55.1: Because only mcp==2.2.0 is available and <pkg> depends on mcp>=1.23.0,<2.2 (corpus holds mcp 2.2.0)
    - 224 sympy 1.14.0: Because only mpmath==1.4.1 is available and <pkg> depends on mpmath>=1.1.0,<1.4 (corpus holds mpmath 1.4.1)
    - 460 cfn-lint 1.56.3: Because only mpmath==1.4.1 is available and sympy==1.14.0 depends on mpmath>=1.1.0,<1.4, we can conclude that sympy==1.14.0 cannot be used. And because only sympy==1.14.0 is available and <pkg> depends on sympy==1.14.0
    - 48 litellm 1.100.1: Because only openai==3.13.0 is available and <pkg> depends on openai>=2.20.0,<3.0.0 (corpus holds openai 3.13.0)
    - 472 poetry-plugin-export 1.10.0: Because only poetry==2.4.3 is available and poetry==2.4.3 depends on poetry-core==2.4.0, we can conclude that poetry==2.4.3 depends on poetry-core==2.4.0. And because there is no version of poetry-core==2.4.0 and <pkg> depends on poetry==2.4.3 (corpus holds poetry-core 2.4.1)
    - 277 databricks-sdk 0.137.0: Because only protobuf==7.36.1 is available and <pkg> depends on one of 10 ranges (protobuf>=4.25.8,<5.26.dev0 ... protobuf>6.31.0,<7.0) (corpus holds protobuf 7.36.1)
    - 391 modal 1.5.5: Because only protobuf==7.36.1 is available and <pkg> depends on one of 2 ranges (protobuf>=3.19,<4.24.0 ... protobuf>4.24.0,<7.0) (corpus holds protobuf 7.36.1)
    - 263 ydb 3.31.5: Because only protobuf==7.36.1 is available and <pkg> depends on protobuf>=3.13.0,<7.0.0 (corpus holds protobuf 7.36.1)
    - 893 databricks-labs-blueprint 0.12.0: Because only protobuf==7.36.1 is available and databricks-sdk==0.137.0 depends on one of 10 ranges (protobuf>=4.25.8,<5.26.dev0 ... protobuf>6.31.0,<7.0) we can conclude that databricks-sdk==0.137.0 cannot be used. And because only databricks-sdk==0.137.0 is available and <pkg> depends on databricks-sdk==0.137.0
    - 790 cohere 7.1.1: Because only pydantic==2.13.5 is available and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 depends on pydantic-core==2.46.5. And because there is no version of pydantic-core==2.46.5 and <pkg> depends on pydantic==2.13.5 (corpus holds pydantic-core 2.49.0)
    - 308 playwright 1.62.0: Because only pyee==14.0.0 is available and <pkg> depends on pyee>=13,<14 (corpus holds pyee 14.0.0)
    - 829 spacy 3.8.16: Because only thinc==9.1.1 is available and <pkg> depends on thinc>=8.3.12,<8.4.0 (corpus holds thinc 9.1.1)
    - 518 langgraph-sdk 0.4.4: Because only websockets==17.1 is available and <pkg> depends on websockets>=14,<17 (corpus holds websockets 17.1)
    - 661 aioboto3 15.5.0: Because there is no version of aiobotocore[boto3]==2.25.1 and <pkg> depends on aiobotocore[boto3]==2.25.1 (corpus holds aiobotocore 3.9.1)
    - 536 browser-use 0.13.10: Because there is no version of anthropic==0.76.0 and <pkg> depends on anthropic==0.76.0 (corpus holds anthropic 1.5.0)
    - 358 torch 2.14.0: Because there is no version of cuda-toolkit[cublas]==13.0.3 and <pkg> depends on cuda-toolkit[cublas]==13.0.3 (corpus holds cuda-toolkit 13.4.1)
    - 740 torchvision 0.29.0: Because there is no version of cuda-toolkit[cublas]==13.0.3 and torch==2.14.0 depends on cuda-toolkit[cublas]==13.0.3, we can conclude that torch==2.14.0 cannot be used. And because <pkg> depends on torch==2.14.0 (corpus holds cuda-toolkit 13.4.1)
    - 744 sentence-transformers 6.0.1: Because there is no version of cuda-toolkit[cublas]==13.0.3 and torch==2.14.0 depends on cuda-toolkit[cublas]==13.0.3, we can conclude that torch==2.14.0 cannot be used. And because only torch==2.14.0 is available and <pkg> depends on torch==2.14.0 (corpus holds cuda-toolkit 13.4.1)
    - 430 llama-cloud-services 0.6.94: Because there is no version of llama-cloud==0.1.46 and <pkg> depends on llama-cloud==0.1.46 (corpus holds llama-cloud 2.16.0)
    - 428 llama-parse 0.6.94: Because there is no version of llama-cloud==0.1.46 and llama-cloud-services==0.6.94 depends on llama-cloud==0.1.46, we can conclude that llama-cloud-services==0.6.94 cannot be used. And because only llama-cloud-services==0.6.94 is available and <pkg> depends on llama-cloud-services==0.6.94 (corpus holds llama-cloud 2.16.0)
    - 772 semgrep 1.177.0: Because there is no version of mcp==1.29.0 and <pkg> depends on mcp==1.29.0 (corpus holds mcp 2.2.0)
    - 433 poetry 2.4.3: Because there is no version of poetry-core==2.4.0 and <pkg> depends on poetry-core==2.4.0 (corpus holds poetry-core 2.4.1)
    - 18 pydantic 2.13.5: Because there is no version of pydantic-core==2.46.5 and <pkg> depends on pydantic-core==2.46.5 (corpus holds pydantic-core 2.49.0)
    - 756 claude-agent-sdk 0.2.152: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic==2.13.5 is available and mcp==2.2.0 depends on pydantic==2.13.5, we can conclude that mcp==2.2.0 cannot be used. And because only mcp==2.2.0 is available and <pkg> depends on mcp==2.2.0 (corpus holds pydantic-core 2.49.0)
    - 752 supabase 2.31.0: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic==2.13.5 is available, we can conclude that pydantic==2.13.5 cannot be used. And because realtime==2.31.0 depends on pydantic==2.13.5 and <pkg> depends on realtime==2.31.0 (corpus holds pydantic-core 2.49.0)
    - 359 fastmcp 4.0.3: Because there is no version of pydantic-core==2.46.5 and pydantic==2.13.5 depends on pydantic-core==2.46.5, we can conclude that pydantic==2.13.5 cannot be used. And because only pydantic[email]==2.13.5 is available, we can conclude that pydantic[email]==2.13.5 cannot be used. And because fastmcp-slim==4.0.3 depends on pydantic[email]==2.13.5 and <pkg> depends on fastmcp-slim[client]==4.0.3 (corpus holds pydantic-core 2.49.0)
  - skipped, no-python-files (41):
    - 252 librt 0.15.0; 254 types-requests 2.33.0.20260906; 344 ruamel-yaml-clib 0.2.15; 351 types-toml 0.10.8.20260518; 381 types-certifi 2021.10.8.3; 395 types-pyyaml 6.0.12.20260906; 425 mmh3 5.3.0; 437 types-protobuf 7.35.1.20260906; 534 botocore-stubs 1.43.67; 557 types-python-dateutil 2.9.0.20260807; 561 types-s3transfer 0.16.0; 603 boto3-stubs 1.43.92; 614 nvidia-nccl-cu13 2.31.2; 619 types-awscrt 0.36.2; 626 nvidia-nccl-cu12 2.31.2; 632 cuda-toolkit 13.4.1; 644 nvidia-cuda-nvrtc 13.4.59; 651 nvidia-cusparselt-cu13 0.9.1; 652 pyodbc 5.3.0; 654 nvidia-nvjitlink 13.4.52; 656 nvidia-cuda-runtime 13.4.49; 657 nvidia-cusparse 12.8.6.49; 665 nvidia-cufft 12.4.0.34; 670 nvidia-cuda-cupti 13.4.58; 673 nvidia-curand 10.4.4.49; 674 pyroaring 1.1.0; 680 nvidia-cufile 1.19.0.109; 683 nvidia-nvtx 13.4.49; 730 types-pytz 2026.3.1.20260727; 753 ujson 6.0.0; 789 types-setuptools 84.0.0.20260812; 822 py-spy 0.4.2; 883 types-urllib3 1.26.25.14; 965 nvidia-cuda-nvrtc-cu12 12.9.86; 971 nvidia-cusparse-cu12 12.5.10.65; 975 types-paramiko 5.0.0.20260724; 976 typer-slim 0.24.0; 980 nvidia-nvjitlink-cu12 12.9.86; 982 nvidia-cufft-cu12 11.4.1.4; 983 nvidia-cuda-runtime-cu12 12.9.79; 991 bs4 0.0.2
  - install-failed, dependency wheel incompatible with the reference interpreter (37):
    - [18] 39 pandas 3.0.5; 162 scikit-learn 1.9.1; 198 contourpy 1.3.3; 407 shapely 2.1.2; 543 pandas-stubs 3.0.5.260730; 555 opencv-python 5.0.0.93; 566 opencv-python-headless 5.0.0.93; 618 db-dtypes 1.7.1; 630 h5py 3.16.0; 635 statsmodels 0.15.0; 694 ml-dtypes 0.6.0; 705 seaborn 0.13.2; 714 patsy 1.0.3; 825 scikit-image 0.26.0; 872 accelerate 1.15.0; 891 blis 1.3.3; 932 opencv-contrib-python 5.0.0.93; 972 skops 0.14.0: Because only numpy==2.5.3 is available and numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`), we can conclude that numpy==2.5.3 cannot be used. And because <pkg> depends on numpy==2.5.3 [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - [13] 166 matplotlib 3.11.1; 225 transformers 5.17.0; 257 datasets 5.0.1; 357 awswrangler 3.17.1; 378 onnxruntime 1.30.0; 411 numba 0.67.0; 781 pandas-gbq 0.35.2; 794 streamlit 1.63.0; 834 yfinance 1.7.0; 852 great-expectations 1.23.0; 860 pydeck 0.9.3; 863 lightgbm 4.7.0; 882 tensorboard 2.21.0: Because numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`) and only numpy==2.5.3 is available, we can conclude that numpy==2.5.3 cannot be used. And because <pkg> depends on numpy==2.5.3 [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - 191 mypy 2.3.1: Because ast-serialize==0.11.1 has no wheels with a matching Python implementation tag (e.g., `cp311`) and only ast-serialize==0.11.1 is available, we can conclude that ast-serialize==0.11.1 cannot be used. And because <pkg> depends on ast-serialize==0.11.1 [wheel tags cp315, reference CPython 3.11] (corpus holds ast-serialize 0.11.1)
    - 737 soundfile 0.14.0: Because numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`) and only numpy==2.5.3 is available, we can conclude that all versions of numpy cannot be used. And because <pkg> depends on numpy [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - 400 databricks-sql-connector 4.5.0: Because numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`) and only numpy==2.5.3 is available, we can conclude that numpy==2.5.3 cannot be used. And because pandas==3.0.5 depends on numpy==2.5.3, we can conclude that pandas==3.0.5 cannot be used. And because only pandas==3.0.5 is available and <pkg> depends on pandas==3.0.5 [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - 853 databricks-sqlalchemy 2.0.10: Because numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`) and only numpy==2.5.3 is available, we can conclude that numpy==2.5.3 cannot be used. And because pandas==3.0.5 depends on numpy==2.5.3, we can conclude that pandas==3.0.5 cannot be used. And because only pandas==3.0.5 is available and databricks-sql-connector==4.5.0 depends on pandas==3.0.5, we can conclude that databricks-sql-connector==4.5.0 cannot be used. And because only databricks-sql-connector==4.5.0 is available and <pkg> depends on databricks-sql-connector==4.5.0 [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - 639 mlflow 3.16.0: Because only matplotlib==3.11.1 is available and matplotlib==3.11.1 depends on numpy==2.5.3, we can conclude that matplotlib==3.11.1 depends on numpy==2.5.3. (1) Because only numpy==2.5.3 is available and numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`), we can conclude that numpy==2.5.3 cannot be used. And because we know from (1) that matplotlib==3.11.1 depends on numpy==2.5.3, we can conclude that matplotlib==3.11.1 depends on numpy>=3. And because <pkg> depends on matplotlib==3.11.1 and numpy==2.5.3 [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
    - 628 imageio 2.37.4: Because only numpy==2.5.3 is available and numpy==2.5.3 has no wheels with a matching Python implementation tag (e.g., `cp311`), we can conclude that all versions of numpy cannot be used. And because <pkg> depends on numpy [wheel tags cp312, reference CPython 3.11] (corpus holds numpy 2.5.3)
  - install-failed, dependency absent from the corpus (21):
    - [2] 86 ghapi 2.1.3; 739 fastspec 0.2.4: Because fasttransport was not found in the provided package locations and <pkg> depends on fasttransport>=0.0.2 (fasttransport not in corpus)
    - 615 apache-airflow-providers-common-sql 2.1.1: Because apache-airflow was not found in the provided package locations and <pkg> depends on apache-airflow>=2.11.0 (apache-airflow not in corpus)
    - 127 sglang 0.5.19: Because apache-tvm-ffi was not found in the provided package locations and <pkg> depends on apache-tvm-ffi==0.1.11 (apache-tvm-ffi not in corpus)
    - 922 deltalake 1.6.3: Because arro3-core was not found in the provided package locations and <pkg> depends on arro3-core>=0.5.0 (arro3-core not in corpus)
    - 735 langchain-google-vertexai 3.2.4: Because bottleneck was not found in the provided package locations and <pkg> depends on bottleneck>=1.4.0,<2.0.0 (bottleneck not in corpus)
    - 414 deepdiff 9.1.0: Because cachebox was not found in the provided package locations and <pkg> depends on cachebox>=5.2,<6 (cachebox not in corpus)
    - 803 pinotdb 9.1.2: Because ciso8601 was not found in the provided package locations and <pkg> depends on ciso8601>=2.1.3,<3.0.0 (ciso8601 not in corpus)
    - 798 crewai 1.15.21: Because crewai-cli was not found in the provided package locations and <pkg> depends on crewai-cli==1.15.21 (crewai-cli not in corpus)
    - 765 crewai-tools 1.15.21: Because crewai-cli was not found in the provided package locations and crewai==1.15.21 depends on crewai-cli==1.15.21, we can conclude that crewai==1.15.21 cannot be used. And because <pkg> depends on crewai==1.15.21 (crewai-cli not in corpus)
    - 847 feedparser 6.0.14: Because feedparser-sgmllib was not found in the provided package locations and <pkg> depends on feedparser-sgmllib>=2,<3 (feedparser-sgmllib not in corpus)
    - 760 griffe 2.3.0: Because griffecli was not found in the provided package locations and <pkg> depends on griffecli==2.3.0 (griffecli not in corpus)
    - 808 amazon-ion 0.14.6: Because jsonconversion was not found in the provided package locations and <pkg> depends on jsonconversion>=1.2.1 (jsonconversion not in corpus)
    - 613 langchain-community 0.4.2: Because langchain-classic was not found in the provided package locations and <pkg> depends on langchain-classic>=1.0.7,<2.0.0 (langchain-classic not in corpus)
    - 801 llama-index-llms-openai 0.8.1: Because llama-index-core was not found in the provided package locations and <pkg> depends on llama-index-core>=0.14.5,<0.15 (llama-index-core not in corpus)
    - 653 nvidia-nvshmem-cu13 3.7.2: Because nvidia-cuda-cccl was not found in the provided package locations and <pkg> depends on nvidia-cuda-cccl (nvidia-cuda-cccl not in corpus)
    - 560 opensearch-py 3.2.0: Because opensearch-protobufs was not found in the provided package locations and <pkg> depends on opensearch-protobufs==1.2.0 (opensearch-protobufs not in corpus)
    - 768 lmnr 0.7.62: Because opentelemetry-semantic-conventions-ai was not found in the provided package locations and <pkg> depends on opentelemetry-semantic-conventions-ai==0.4.13 (opentelemetry-semantic-conventions-ai not in corpus)
    - 783 universal-pathlib 0.3.10: Because pathlib-abc was not found in the provided package locations and <pkg> depends on pathlib-abc>=0.5.1,<0.6.0 (pathlib-abc not in corpus)
    - 809 tox 4.61.4: Because pyproject-api was not found in the provided package locations and <pkg> depends on pyproject-api>=1.10 (pyproject-api not in corpus)
    - 956 ua-parser 1.0.2: Because ua-parser-builtins was not found in the provided package locations and <pkg> depends on ua-parser-builtins (ua-parser-builtins not in corpus)
  - install-failed, installer child died silently under the sandbox's install rlimits (6), uv stderr ending after `Resolved N packages` with no diagnostic (see the reading below):
    - 637 nvidia-cublas 13.7.0.27: reproduced as `SIGXFSZ` (`RLIMIT_FSIZE` 512 MiB)
    - 643 nvidia-cudnn-cu13 9.26.0.51: installs cleanly under the same rlimits outside `bwrap`; in-sandbox cause not confirmed
    - 666 nvidia-cusolver 12.3.2.15: reproduced as `SIGXFSZ` (`RLIMIT_FSIZE` 512 MiB)
    - 952 nvidia-cublas-cu12 12.9.2.10: not individually reproduced
    - 964 nvidia-cudnn-cu12 9.26.0.51: not individually reproduced
    - 995 nvidia-cusolver-cu12 11.7.5.82: not individually reproduced
  - scan-failed, scan exceeded its timeout (5):
    - [4] 541 ray 2.58.0; 655 phonenumbers 9.0.39; 757 google-ads 32.0.0; 930 datadog-api-client 2.60.0: reference 3.11
    - 106 scipy 1.18.1: reference 3.12
  - install-failed, sdist build failed (2):
    - 459 psycopg2 2.9.13: psycopg2: pg_config not found
    - 855 thinc 9.1.1: thinc is one of the corpus's three sdists; its build requirement `cython>=0.25,<3.0` cannot be met offline because the corpus holds cython 3.3.0
  - skipped, no-compatible-interpreter (1):
    - 959 backports-asyncio-runner 1.2.0
- **Reading the non-scanned classes.** None is a harness defect and nothing in
  the harness was changed for them; each is recorded for the evidence
  document:
  - *dependency version not the single artifact the corpus holds* (89): the
    property Task 3 met with pydantic. The wheelhouse holds exactly one
    current release per project, so a package that pins or caps a dependency
    below that release cannot resolve offline. pydantic 2.13.5's pin on
    pydantic-core 2.46.5, while rank 24 holds 2.49.0, accounts for 47 of the
    89 (pydantic itself and every dependent that reaches it); the rest are
    ordinary upper bounds (`docutils<0.23`, `protobuf<7.0`, `agate<1.10`, ...)
    or pins on a release the corpus does not hold.
  - *dependency wheel incompatible with the reference interpreter* (37): the
    spec fixes the scan reference as the lowest installed minor satisfying the
    package's own `requires_python`, which is 3.11 for all 37, while numpy
    2.5.3 (36 of them, directly or through pandas or matplotlib) ships cp312+
    wheels only and mypy's ast-serialize 0.11.1 ships cp315 only. This is a
    designed limit of the reference rule, not an install fault; a reference
    chosen from the dependency closure would have scanned these packages under
    3.12 and is a decision for the evidence document, not for this run.
  - *dependency absent from the corpus* (21): a runtime dependency outside the
    top-1000 (for nvidia-nvshmem-cu13, one published under another
    distribution name), unreachable with `--no-index`.
  - *installer child died silently* (6): all six are CUDA runtime wheels of
    288 MB to 776 MB whose uv stderr stops after `Resolved N packages`; the
    harness records the stderr tail but not the exit status. Reproduced
    outside `bwrap` under the harness's own `_INSTALL_LIMITS` via
    `preexec_fn=_apply_resource_limits`, with `TMPDIR` on the disk-backed
    filesystem: nvidia-cusolver 12.3.2.15 dies with signal 25 (`SIGXFSZ`, the
    512 MiB `RLIMIT_FSIZE`) after 10 s and installs cleanly without the
    limits; nvidia-cublas 13.7.0.27, whose `libcublasLt.so.13` member alone is
    646 MB, exits 153 (`SIGXFSZ`) under `ulimit -f 524288` alone. nvidia-
    cudnn-cu13 9.26.0.51 installed cleanly under the same rlimits outside
    `bwrap`, so its in-sandbox death is consistent with the same limit or with
    the sandbox's private tmpfs `/tmp`, where `--no-cache` stages the 974 MB
    unpacked wheel, but was not confirmed. The three `-cu12` twins (ranks 952,
    964, 995) were not reproduced individually. All six ship no Python files
    (their installed siblings such as nvidia-cusparse are `skipped: no-python-
    files`), so no finding was lost.
  - *scan exceeded its timeout* (5): `pyahead check` over the distribution's
    own files did not finish in 900 s on the loaded host for scipy, ray,
    phonenumbers, google-ads and datadog-api-client, the last three being
    generated-code trees of thousands of modules. Each cost its runner the
    full 900 s. A performance observation about the scanner for the evidence
    document, not a harness fault.
  - *skipped: no-python-files* (41): type-stub distributions (`types-*`,
    `*-stubs`), binary-only wheels (CUDA libraries, mmh3, pyodbc, ujson,
    pyroaring, py-spy) and shims (bs4, typer-slim): nothing to scan.
  - *sdist build failed* (2) and *no-compatible-interpreter* (1): psycopg2
    needs `pg_config`, absent on the host; thinc's build backend needs a
    cython the corpus does not hold; backports-asyncio-runner requires Python
    below 3.11.
- **Raw shard totals, before Task 5's aggregation:** 1487 high-confidence
  findings on 186 of the 797 scanned packages; verdicts confirmed 361,
  refuted-binding 148, refuted-timeline 53, not-adjudicable 925 (binding-not-
  visible 843, import-error 82). The 53 refuted-timeline verdicts come from
  two shards, rank 482 future 1.0.0 (52) and rank 288 cython 3.3.0 (1). Task 5
  aggregates and Task 6 triages; nothing was acted on here.
- **Gate.** No tracked source file changed in this task (the tree is
  code-identical to e6480bd). Each exit 0: `uv run ruff check .`: `All checks
  passed!`; `uv run ruff format --check .`: `464 files already formatted`; `uv
  run mypy src scripts`: `Success: no issues found in 46 source files`. `uv
  run pytest`, started 03:08Z while the last runner and the numpy refresh were
  still executing (load average 4 to 5): `1 failed, 1913 passed, 11 skipped in
  1275.01s (0:21:15)`, exit 1; `Required test coverage of 90.0% reached. Total
  coverage: 91.58%`; coverage TOTAL 8773 statements, 587 missed, 2800
  branches, 365 partial, 92%. The one failure is
  `tests/unit/test_dependencies.py::test_interruption_before_containment_cleans_the_suspended_process`,
  which raises a real `SIGINT` inside a fake `Popen` and expects
  `KeyboardInterrupt`; under load the signal landed where
  `_start_contained_process` reports `unable to contain isolated resolver
  process` instead. Re-run in isolation three times with `--no-cov` it passed
  3 of 3 (0.45 s, 0.28 s, 0.99 s). It is a load sensitivity of that test, not
  a regression from this task, which changed no code; Task 7 re-runs the gate
  on a quiet host. The single-statement coverage difference from Task 3 (586
  to 587 missed) is that failed test's uncovered branch.
- `git status --porcelain` lists only this plan; `work/` (manifest,
  wheelhouse, `pypi-validate/`) remains ignored in full.

### Task 5: Aggregate and bind the worksheet

- [x] `uv run python scripts/pypi_report.py --manifest work/pypi-manifest.json
      --shards work/pypi-validate/shards --output work/pypi-report.json
      --worksheet work/pypi-disagreements.csv --sample-size 200`
- [x] `uv run python scripts/pypi_report.py --verify-identity --output
      work/pypi-report.json --worksheet work/pypi-disagreements.csv`, and do not
      begin triage until this passes
- [x] record `agreement_rate`, `adjudication_coverage`, every verdict count,
      `not_adjudicable_reasons` with counts, and the per-rule and
      per-matcher-kind breakdowns
- [x] record the report's SHA-256 and the number of `refuted-binding` and
      `refuted-timeline` rows in the worksheet

**Evidence (Task 5, run 2026-09-11 03:31Z on the measurement host; the
aggregation is a pure read of the 999 shards and touched no sandbox):**

- **Invocation.** Both commands in the module form Task 3 established, `uv
  run python -m scripts.pypi_report --manifest work/pypi-manifest.json
  --shards work/pypi-validate/shards --output work/pypi-report.json
  --worksheet work/pypi-disagreements.csv --sample-size 200`, exit 0 in 0.5
  s wall (`143,029` bytes of report, `136,106` bytes of worksheet), then `uv run
  python -m scripts.pypi_report --verify-identity --output
  work/pypi-report.json --worksheet work/pypi-disagreements.csv`, exit 0.
  Aggregation raised nothing: every shard carried the manifest digest and
  every finding a recognised verdict and reason, so the denominator is
  complete, not partial. Both artifacts are matched by `.gitignore` lines
  17-18; `git status` stayed clean and `git ls-files work` is empty.
- **Identity binding verified; triage may begin.** The worksheet's first
  row is `report-identity` carrying the digest below, every one of the
  401 `finding` rows repeats it, and it equals `sha256sum` of the report
  file. A second aggregation into a scratch directory outside `work/`
  produced a byte-identical report and worksheet (same two SHA-256s, `cmp`
  silent), so the record and the confirmed sample are reproducible from
  the shards alone; the scratch copies were deleted.
- **Report SHA-256: `c7b44e2bfb988ba7faefd2f6a170345fd0ce0581dfd6e6cc71cbcc518bd7766e`.**
  `manifest_sha256` in the record is `bafc2107da4e6e774f5d5a7c8385e6da0ef7fc04ce553b326c127e761529872b`, the same
  digest every shard carries (Task 4). `schema_version` 1.
- **Packages:** `packages_total` 999, `packages_scanned` 797,
  `skipped_packages` 202 (install-failed 155, skipped 42, scan-failed 5), reconciling
  exactly with Task 4's status distribution; each carries the reason Task 4
  already lists, so they are not repeated here.
- **Findings and verdicts:** `findings_total` 1487; `confirmed` 361,
  `refuted-binding` 148, `refuted-timeline` 53, `not-adjudicable` 925;
  adjudicated (the agreement denominator) 562.
- **`agreement_rate` 0.642349** (361 / 562); **`adjudication_coverage`
  0.377942** (562 / 1487). Per the spec the first is precision over
  terminal verdicts only and the second is reported, not gated; neither
  says anything about recall.
- **`not_adjudicable_reasons`:** `binding-not-visible` 843, `import-error` 82. The other
  7 closed reasons (`install-failed`, `module-not-importable`, `import-timeout`, `no-signature`, `probe-timeout`, `probe-crashed`, `no-interpreter`)
  are 0: in particular no finding needed an interpreter outside the
  installed 3.11-3.15 set, and none lost adjudication to a probe timeout or
  crash. `binding-not-visible` alone is 56.7% of all findings and
  91.1% of the non-adjudicable ones; it is the coverage ceiling, not a
  precision signal.
- **Per matcher kind** (`by_match_kind`; agreement over adjudicated,
  coverage over the kind's findings):

  | kind | confirmed | refuted-binding | refuted-timeline | not-adjudicable | total | agreement | coverage |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | `call-shape` | 9 | 0 | 0 | 2 | 11 | 1.000 | 0.818 |
  | `module-import` | 162 | 37 | 53 | 75 | 327 | 0.643 | 0.771 |
  | `qualified-reference` | 190 | 111 | 0 | 848 | 1149 | 0.631 | 0.262 |

- **Per rule** (`by_rule`; 49 of the registry's 133 rules produced at least
  one high-confidence finding; columns as above, `-` for 0):

  | rule | confirmed | refuted-binding | refuted-timeline | not-adjudicable | total |
  |---|---:|---:|---:|---:|---:|
  | CPY0001 | - | 6 | - | 1 | 7 |
  | CPY0005 | 1 | - | - | - | 1 |
  | CPY0008 | - | 1 | - | 1 | 2 |
  | CPY0009 | 1 | - | - | - | 1 |
  | CPY0014 | - | - | - | 1 | 1 |
  | CPY0015 | 3 | - | - | - | 3 |
  | CPY0017 | 1 | - | - | - | 1 |
  | CPY0021 | 1 | - | - | - | 1 |
  | CPY0022 | 1 | - | - | - | 1 |
  | CPY0023 | 112 | 18 | 1 | 62 | 193 |
  | CPY0024 | - | 2 | - | 7 | 9 |
  | CPY0025 | - | 4 | - | - | 4 |
  | CPY0026 | 1 | 2 | - | - | 3 |
  | CPY0027 | 42 | 7 | 52 | 1 | 102 |
  | CPY0028 | - | - | - | 1 | 1 |
  | CPY0031 | - | 16 | - | - | 16 |
  | CPY0039 | - | 1 | - | - | 1 |
  | CPY0042 | 26 | 3 | - | 15 | 44 |
  | CPY0043 | - | 1 | - | - | 1 |
  | CPY0044 | 2 | - | - | 1 | 3 |
  | CPY0052 | - | - | - | 1 | 1 |
  | CPY0058 | 1 | - | - | - | 1 |
  | CPY0062 | 20 | - | - | 9 | 29 |
  | CPY0064 | 5 | 10 | - | - | 15 |
  | CPY0067 | 4 | 3 | - | - | 7 |
  | CPY0073 | 1 | - | - | - | 1 |
  | CPY0088 | - | - | - | 1 | 1 |
  | CPY0091 | 6 | - | - | - | 6 |
  | CPY0093 | - | 61 | - | 7 | 68 |
  | CPY0094 | 5 | - | - | 1 | 6 |
  | CPY0095 | - | 9 | - | - | 9 |
  | CPY0096 | 3 | - | - | 59 | 62 |
  | CPY0098 | 4 | - | - | - | 4 |
  | CPY0100 | 3 | - | - | - | 3 |
  | CPY0104 | 28 | - | - | 517 | 545 |
  | CPY0105 | 18 | - | - | 4 | 22 |
  | CPY0106 | 32 | - | - | 1 | 33 |
  | CPY0108 | - | 1 | - | 1 | 2 |
  | CPY0109 | 5 | - | - | 1 | 6 |
  | CPY0117 | - | 2 | - | - | 2 |
  | CPY0118 | - | - | - | 1 | 1 |
  | CPY0120 | 5 | - | - | - | 5 |
  | CPY0122 | 9 | - | - | 9 | 18 |
  | CPY0123 | 11 | - | - | - | 11 |
  | CPY0124 | 4 | - | - | 12 | 16 |
  | CPY0125 | 2 | - | - | - | 2 |
  | CPY0126 | 2 | - | - | 211 | 213 |
  | CPY0128 | 2 | - | - | - | 2 |
  | CPY0137 | - | 1 | - | - | 1 |

- **Worksheet:** 1 `report-identity` row plus 401 `finding` rows: **`refuted-binding`
  148** (61 distinct packages, 18 rules), **`refuted-timeline` 53**
  (2 packages, 2 rules), and the deterministic `confirmed` sample of 200 of
  361 (62 packages, 27 rules), each with its `sample_rank` digest. The
  `classification`, `reviewer`, `notes` and `regression_fixture` columns are
  empty on every row, as they must be before triage. Package-derived
  columns are formula-neutralised by the harness, so the worksheet may be
  opened in a spreadsheet as the spec intends.
- **Shape of the disagreements, read from the worksheet for Task 6 to
  triage under the spec's procedure (rule, registry subject, rows by
  package; nothing here is a triage conclusion):**
  - `refuted-binding`:
    - CPY0093 `datetime.datetime.utcnow` (61): adal 1.2.7; amqp 5.3.1 x2; aws-requests-auth 0.4.3; azure-batch 15.1.0; celery 5.6.3 x3; cloudpathlib 0.25.0 x4; curl-cffi 0.16.3; datadog 0.53.0 x4; elasticsearch 9.5.1 x2; firebase-admin 7.5.0 x2; flask-login 0.6.3; future 1.0.0 x4; gcsfs 2026.8.0; google-cloud-core 2.7.0; google-cloud-firestore 2.30.0; google-cloud-monitoring 2.31.0; google-cloud-storage 3.14.1; graphene 3.4.3; hvac 2.4.0; jira 3.10.5; kafka-python 3.0.11; kubernetes 36.0.3 x2; ldap3 2.9.1 x5; moto 5.2.3 x2; nbclient 0.11.0; oauth2client 4.1.3; oauthlib 3.3.1; opencensus 0.11.4 x4; passlib 1.7.4 x4; peewee 4.5.1; pendulum 3.2.0; tornado 6.5.8 x2; trino 0.339.0; userpath 1.9.2
    - CPY0023 `distutils` (18): babel 2.18.0; cython 3.3.0 x2; ddtrace 4.14.0; future 1.0.0; humanfriendly 10.0; pbr 7.0.3; pip 26.2.1 x2; pipenv 2026.8.0 x2; pybind11 3.1.0 x2; setuptools 84.0.0 x5
    - CPY0031 `unittest.makeSuite` (16): google-pasta 0.2.0 x16
    - CPY0064 `ast.Num` (10): astor 0.8.1; executing 2.2.1; fastcore 2.2.23 x3; fire 0.7.1; google-pasta 0.2.0 x4
    - CPY0095 `sys.last_type` (9): ipython 9.17.1 x6; trio 0.34.0 x3
    - CPY0027 `lib2to3` (7): future 1.0.0 x7
    - CPY0001 `cgi` (6): distlib 0.4.3; lxml 6.1.3; msal 1.38.0; nltk 3.10.3; pip 26.2.1; pipenv 2026.8.0
    - CPY0025 `pkgutil.ImpImporter` (4): pip 26.2.1 x2; pipenv 2026.8.0 x2
    - CPY0042 `asyncio.get_event_loop_policy` (3): jupyter-core 5.9.1 x2; tornado 6.5.8
    - CPY0067 `ssl.match_hostname` (3): future 1.0.0; httplib2 0.32.0; pysocks 1.7.1
    - CPY0024 `imp` (2): distlib 0.4.3; gevent 26.8.0
    - CPY0026 `ssl.wrap_socket` (2): ldap3 2.9.1 x2
    - CPY0117 `sre_compile` (2): hypothesis 6.168.0 x2
    - CPY0008 `crypt` (1): passlib 1.7.4
    - CPY0039 `pkgutil.find_loader` (1): tornado 6.5.8
    - CPY0043 `asyncio.AbstractChildWatcher` (1): anyio 4.15.1
    - CPY0108 `nturl2path` (1): future 1.0.0
    - CPY0137 `importlib.abc.Loader.load_module` (1): pymupdf 1.28.2
  - `refuted-timeline`:
    - CPY0027 `lib2to3` (52): future 1.0.0 x52
    - CPY0023 `distutils` (1): cython 3.3.0
- **Harness:** no code was changed; this task built nothing and so adds no
  tests. Gate: `ruff check`, `ruff format --check` and `mypy src scripts`
  clean; full `pytest` 1914 passed, 11 skipped, 0 failed, exit 0, in 19 min
  16 s (coverage 91.60 %, threshold 90 %), run detached with its log under
  `/var/tmp` while the host's unrelated process kept a core busy. The
  SIGINT-timing test that failed once in Task 4's run passed here.

### Task 6: Triage the disagreements

- [x] for every `refuted-binding` row, follow the triage procedure in
      `docs/pypi-validation.md`: inspect the shard's finding and binding-probe
      evidence, land an inline fixture in
      `tests/unit/test_precision_regressions.py` reproducing the shape, and fix
      the matcher or rule that produced it
- [x] for every `refuted-timeline` row, treat it as a registry defect: correct
      the rule's timeline against an authoritative CPython source, cite that
      source, and add fixture coverage
- [x] re-run only the affected packages with
      `pypi_validate.py run --refresh --limit` or a targeted `--shard`, and
      record that each previously refuted finding now resolves as expected
- [x] any row left unresolved must be named with the reason it is still open;
      never close a row by deleting the finding or lowering a rule's confidence
      without evidence that the lower confidence is correct
- [x] re-aggregate after the fixes and record the new `agreement_rate` beside
      the original

**Evidence (Task 6, triaged 2026-09-11 on the measurement host; targeted
refresh of the 61 affected packages ran 04:13Z–05:15Z, three lanes of
`uv run python -m scripts.pypi_validate run ... --shard <rank-1>/999 --refresh
--timeout 900 --horizon-python 3.15`, one invocation per package, every
refreshed shard `bwrap`, no `rlimit-only` fallback):**

- **What the 201 rows actually were.** Every one of the 148 `refuted-binding`
  and 53 `refuted-timeline` rows was inspected against its shard's finding,
  match evidence, binding-probe evidence and the pinned wheel source. The
  disagreements were dominated not by PyAhead false positives but by five
  defects in the oracle itself, each of which made a *correct* finding look
  refuted. Per the Overview's rule for harness defects, each was fixed
  narrowly, with a unit test that fails without the fix, and is named here:
  1. **Bound-method identity** (`scripts/pypi_probe.py`, `_same_object`). All
     61 CPY0093 rows were genuine `datetime.utcnow()` /
     `utcfromtimestamp()` calls; `datetime.datetime.utcnow is
     datetime.datetime.utcnow` is `False` under CPython because a classmethod
     is a fresh bound-method object on every access, so plain `is` refuted
     every reference to such a subject. Identity now also holds for two bound
     methods with the same `__self__` and the same underlying function.
  2. **Submodule from-imports** (`_resolve_subject`, `_import_submodule`).
     All 53 `refuted-timeline` rows (52 `from lib2to3 import <submodule>` in
     future 1.0.0, 1 `from distutils import sysconfig` in cython) were the
     bare-interpreter C2 probe doing `getattr(lib2to3, "refactor")` on a
     package that had not imported that submodule, and reporting `S` absent at
     3.12 where it exists. `S` is now resolved the way the `from` statement
     itself resolves it, by importing `A.B`. No registry timeline was wrong:
     lib2to3 is present at 3.12 and gone at 3.13, distutils present at 3.11
     and gone at 3.12, exactly as CPY0027 and CPY0023 state, so no
     `src/pyahead/data/registry/cpython/*.yaml` entry changed.
  3. **Walk failing on `S`'s own slot** (`_walk_failed_at_subject_slot`). At
     the cross-check interpreter where `S` is already removed, a genuine
     `unittest.makeSuite(...)` walks the real `unittest` module and fails on
     `makeSuite` itself; the probe reported that as `identity_match=False`, i.e.
     as a binding to a different object. It is now inconclusive at that
     interpreter (the reference verdict stands and C2 decides), which is what
     the closed result schema on both sides now admits as the one new
     `(absent, walk error, None)` triple. This was CPY0031 x16, CPY0064 x10,
     CPY0025 x4, CPY0067 x3, CPY0026 x2, CPY0039, CPY0137.
  4. **Refuting against an unobservable subject** (`scripts/pypi_validate.py`,
     `_binding_verdict`, `expected_presence`). A live binding with `S` absent
     was always a refutation, so an aliased `from A import B as C` (which the
     spec's own Limitations say must be `not-adjudicable`), a Windows-only
     `asyncio.WindowsSelectorEventLoopPolicy` on Linux, and `sys.last_type`
     (unset in a fresh interpreter) were all refuted. Absence now refutes only
     at an interpreter where the registry itself expects `S` gone, which
     keeps the version-gated-fallback cross-check intact; elsewhere it is
     `not-adjudicable:module-not-importable`. CPY0095 x9, CPY0042 x3, and the
     aliased rows under CPY0023, CPY0027, CPY0001, CPY0008 fall here.
  5. **The from-import-bound prefix** (`scripts/pypi_probe.py`,
     `_walk_candidates`). After `from datetime import datetime`, the probe
     walked the canonical `datetime.datetime.utcnow` from the wrong head and
     failed on the first step. Each later component is now tried as the
     site's head. Exposed by the first refresh, where 31 CPY0093 rows stayed
     refuted; they are within the 61 counted under item 1. The post-run
     review narrowed this so a later component may only confirm or be
     inconclusive, never refute (`docs/evidence/pypi-top-1000.md`,
     Limitations); the fifth and sixth reviews then made the first bound
     later component that neither reaches `S` nor stops on its slot settle
     the guessing, so a component after it cannot confirm through an
     unrelated global.
  `docs/pypi-validation.md` Limitations now state rules 3, 4 and 5 and the
  bound-method/submodule resolution.
- **Genuine PyAhead false positives, fixed with fixtures in
  `tests/unit/test_precision_regressions.py`:**
  - **CPY0024 distlib `wheel.py:109`** — `if sys.version_info[0] < 3: import
    imp`. The `sys.version_info[0]` major-only index was outside the guard
    grammar, so a Python-2-only branch was reported as breaking at 3.12.
    `src/pyahead/analysis/reachability.py` now decides `sys.version_info[0]
    <op> <int>` (new `_VersionInfoShape.MAJOR_INDEX`); other index forms and
    non-integer literals stay unknown. Fixtures:
    `test_major_version_index_guard_hides_a_python2_only_import`,
    `..._keeps_the_python3_branch`, `..._against_a_non_integer_stays_unknown`,
    plus eight cases in `tests/unit/test_reachability.py`. `docs/usage.md`
    mentions the shape.
  - **CPY0043 anyio `_backends/_asyncio.py:1266`** — `child_watcher:
    asyncio.AbstractChildWatcher | None = None` inside a function body. A
    local-variable annotation is never evaluated or stored (PEP 526), so the
    reference cannot raise on any interpreter. The oracle did not see that:
    it refuted the row at 3.14 with defect 3's shape (the walk from the real
    `asyncio` module failing on `AbstractChildWatcher` itself), and the
    fixed oracle is inconclusive there and confirms the binding from the
    3.11 reference, so the false-positive classification rests on PEP 526
    alone. `engine.py` marks the annotation of a local variable inside a
    function body typing-only (`annotation_evaluation: deferred` evidence),
    so a runtime-only rule no longer applies; parameter, return, class-body
    and module-level annotations are unchanged, including under
    `from __future__ import annotations`, because runtime introspection
    still evaluates stringified annotations. As first landed the rule also
    deferred every annotation under PEP 563; the second review narrowed it
    to PEP 526, and rescanning the pinned anyio wheel reproduces the
    refreshed shard's 32 findings exactly. Fixtures:
    `test_local_variable_annotation_is_never_evaluated`,
    `test_future_annotations_do_not_defer_evaluated_annotations`,
    `test_deferred_annotation_keeps_a_typing_context_finding`,
    `test_evaluated_annotations_still_report` (4 cases).
  Fingerprints are unaffected (`_fingerprint` hashes rule, path, scope,
  subject and ordinal only), so the worksheet's confirmed sample stays
  comparable.
- **Re-run of the affected packages.** All 61 packages holding a refuted row were refreshed in three lanes (04:13Z–04:59Z), plus one invocation each for rank 1000 (`--shard 999/1000`, because `(rank-1) % 999` folds rank 1000 onto shard 0 with rank 1) and for kubernetes (rank 317), whose first refresh hit the 900 s scan timeout while sharing the host with the other lanes and the full pytest gate, and scanned in 733 s once the host was idle (3 confirmed). After that pass 31 CPY0093 rows were still refuted and exposed the fifth oracle defect above (the from-import-bound prefix), so the 15 packages holding them were refreshed a second time (05:12Z–05:15Z). Every refreshed shard records `bwrap`; no `rlimit-only` fallback; no probe timed out or crashed. Two findings are no longer reported (distlib CPY0024 and anyio CPY0043, removed by the PyAhead fixes, `findings_total` 1487 → 1485); none was suppressed. Per-package verdict deltas were checked for every refreshed shard: no package lost a `confirmed` verdict, and the only new `not-adjudicable` reason is `module-not-importable` (40), all from rule 4.
- **Row-by-row outcome of the 201 rows** (Task 5 worksheet row → verdict in
  the refreshed shard, by rule):
  - `refuted-binding` → `confirmed` (98): CPY0025 x4, CPY0026 x2, CPY0031 x16, CPY0039 x1, CPY0064 x10, CPY0067 x3, CPY0093 x61, CPY0137 x1
  - `refuted-binding` → `not-adjudicable:module-not-importable` (40): CPY0001 x6, CPY0023 x16, CPY0027 x6, CPY0042 x3, CPY0095 x9
  - `refuted-binding` → `finding-no-longer-reported` (2): CPY0024 x1, CPY0043 x1
  - `refuted-binding` → `refuted-binding` (8): CPY0008 x1, CPY0023 x2, CPY0024 x1, CPY0027 x1, CPY0108 x1, CPY0117 x2
  - `refuted-timeline` → `confirmed` (53): CPY0023 x1, CPY0027 x52
- **Rows left open, each named with its reason** (8; none closed by
  deleting a finding or lowering a confidence):
  - future 1.0.0, CPY0027 `lib2to3`, `libpasteurize/main.py:44` — `from lib2to3.main import main, warn, StdoutRefactoringTool`. The probe checks the first bound name, `main`, which the module rebinds further down with its own `def main`; the import itself is genuine and breaks at 3.13 (its neighbour `from lib2to3 import refactor` on line 45 is confirmed). Oracle limitation: a bound name rebound after the import.
  - ddtrace 4.14.0, CPY0023 `distutils`, `ddtrace/sourcecode/setuptools_auto.py:9` — `import distutils.core as distutils_core`, executed right after `import setuptools`, which installs setuptools' `distutils` shim; the name is bound to the vendored `setuptools._distutils.core`, not the stdlib `distutils.core` the finding names. Whether the line breaks depends on the installed setuptools, not on CPython. Open: environment-dependent binding the static claim cannot see.
  - gevent 26.8.0, CPY0024 `imp`, `gevent/_compat.py:103` — `try: import _imp as imp` / `except ImportError: import imp`. The fallback never runs on 3.x (`_imp` always imports), so the module-level `imp` is `_imp`. Import-fallback reachability, outside the alpha guard grammar (`docs/design.md` §11.4).
  - future 1.0.0, CPY0023 `distutils`, `future/backports/test/support.py:36` — `try: import sysconfig` / `except ImportError: from distutils import sysconfig`. Dead fallback on 3.x (`sysconfig` exists since 3.2); the global is the stdlib `sysconfig`. Same import-fallback shape.
  - hypothesis 6.168.0, CPY0117 `sre_compile`, `hypothesis/strategies/_internal/regex.py:30` — `except ImportError: import sre_parse` after `import re._parser as sre_parse` succeeds on 3.11+. Dead fallback; same shape.
  - future 1.0.0, CPY0108 `nturl2path`, `future/backports/urllib/request.py:1590` — `if os.name == 'nt': from nturl2path import url2pathname, pathname2url`; on this Linux host the `else` branch defines both names locally. The finding is right on Windows and unobservable here. Open: platform-conditional import.
  - passlib 1.7.4, CPY0008 `crypt`, `passlib/utils/__init__.py:854` — `from crypt import crypt as _crypt`. An aliased from-import whose alias `_crypt` coincides with a real attribute of `crypt` (the `_crypt` C extension it imports), so the documented aliased-from-import limitation could not route it to `not-adjudicable`; `_crypt` at the site is `crypt.crypt`, a genuine reference. Oracle limitation.
  - hypothesis 6.168.0, CPY0117 `sre_compile`, `hypothesis/strategies/_internal/regex.py:29` — `except ImportError: import sre_constants as sre` after `import re._constants as sre` succeeds on 3.11+. Dead fallback; same shape.
- **Re-aggregation** (`uv run python -m scripts.pypi_report --manifest
  work/pypi-manifest.json --shards work/pypi-validate/shards --output
  work/pypi-report.json --worksheet work/pypi-disagreements.csv --sample-size
  200`, then `--verify-identity`, both exit 0):
  - **`agreement_rate` 0.984848 (520 / 528), beside the
    original 0.642349 (361 / 562).** `adjudication_coverage` 0.355556
    (528 / 1485), beside the original 0.377942 (562 / 1487).
    Report SHA-256 `bec273386131aa799adddfc4ccb67e04519432106bb9868082a31ae8e84cbb62`; identity binding verified before any
    further reading of the worksheet.
  - Verdicts: confirmed 520, not-adjudicable 957, refuted-binding 8, refuted-timeline 0 (original: confirmed 361, refuted-binding 148,
    refuted-timeline 53, not-adjudicable 925). `not_adjudicable_reasons`:
    binding-not-visible 835, import-error 82, module-not-importable 40 (original: binding-not-visible 843, import-error 82).
    Coverage fell because the oracle now declines to adjudicate the
    aliased, platform-only and runtime-set subjects it previously refuted.
  - Per matcher kind: `call-shape` {'confirmed': 9, 'not-adjudicable': 2}; `module-import` {'confirmed': 215, 'not-adjudicable': 103, 'refuted-binding': 8}; `qualified-reference` {'confirmed': 296, 'not-adjudicable': 852}
  - Per rule, only rows that changed: CPY0001 {'not-adjudicable': 7} (was {'not-adjudicable': 1, 'refuted-binding': 6}); CPY0023 {'confirmed': 113, 'not-adjudicable': 78, 'refuted-binding': 2} (was {'confirmed': 112, 'not-adjudicable': 62, 'refuted-binding': 18, 'refuted-timeline': 1}); CPY0024 {'not-adjudicable': 7, 'refuted-binding': 1} (was {'not-adjudicable': 7, 'refuted-binding': 2}); CPY0025 {'confirmed': 4} (was {'refuted-binding': 4}); CPY0026 {'confirmed': 3} (was {'confirmed': 1, 'refuted-binding': 2}); CPY0027 {'confirmed': 94, 'not-adjudicable': 7, 'refuted-binding': 1} (was {'confirmed': 42, 'not-adjudicable': 1, 'refuted-binding': 7, 'refuted-timeline': 52}); CPY0031 {'confirmed': 16} (was {'refuted-binding': 16}); CPY0039 {'confirmed': 1} (was {'refuted-binding': 1}); CPY0042 {'confirmed': 26, 'not-adjudicable': 18} (was {'confirmed': 26, 'not-adjudicable': 15, 'refuted-binding': 3}); CPY0043 None (was {'refuted-binding': 1}); CPY0064 {'confirmed': 15} (was {'confirmed': 5, 'refuted-binding': 10}); CPY0067 {'confirmed': 7} (was {'confirmed': 4, 'refuted-binding': 3}); CPY0093 {'confirmed': 61, 'not-adjudicable': 7} (was {'not-adjudicable': 7, 'refuted-binding': 61}); CPY0095 {'not-adjudicable': 9} (was {'refuted-binding': 9}); CPY0104 {'confirmed': 36, 'not-adjudicable': 509} (was {'confirmed': 28, 'not-adjudicable': 517}); CPY0137 {'confirmed': 1} (was {'refuted-binding': 1})
  - Packages: `packages_total` 999, `packages_scanned` 797, skipped 202 ({'install-failed': 155, 'scan-failed': 5, 'skipped': 42}); `findings_total` 1485 (original 1487; two
    findings removed by the PyAhead fixes above, none by suppression).
  - The rate is reported mechanically: the 8 open rows are still
    counted as `refuted-binding` in its denominator, as the spec requires
    until they are resolved. Read the number as precision over adjudicated
    findings on this pinned corpus; it says nothing about recall.
- **Interpretation for the operator, not a triage conclusion:** of the 201
  disagreements, 191 were oracle defects, 2 were PyAhead false
  positives now fixed, and 8 remain open, 4 of them the
  same shape — an import inside a `try`/`except ImportError` fallback that
  never executes on 3.x, so the module-level name is bound by the other
  branch. PyAhead reports the statement; the oracle judges the program. The
  alpha reachability grammar (`docs/design.md` §11) deliberately excludes
  general control flow, so this is a roadmap decision, not something to
  paper over here.
- **Gate:** `ruff check`, `ruff format --check`, `mypy src scripts` clean
  after the last change. Full `pytest` run twice: 1953 passed, 11 skipped, 0
  failed, coverage 91.63 % (threshold 90 %) in 39 min 41 s while sharing the
  host with the refresh lanes, after every fix except the fifth probe fix
  (`_walk_candidates`); then again after that fix on the idle host, 1955
  passed, 11 skipped, 0 failed, coverage 91.63 %, exit 0, in 19 min 30 s
  (the two extra tests are the candidate-head probe tests). Both logs are
  under `/var/tmp`, outside the repository.

### Task 7: Verify acceptance

- [x] full repository gate green: `uv run ruff check .`,
      `uv run ruff format --check .`, `uv run mypy src scripts`,
      `uv run pytest` with its exact pass/skip counts and coverage percentage
- [x] `git diff --check` clean, and the diff contains no `work/` artifact, no
      absolute host path, and no credential
- [x] confirm `docs/design.md`, `AGENTS.md`, `.github/workflows/**` and
      `docs/evidence/gate-c.md` are unmodified, and that no quality-policy table
      in `pyproject.toml` changed
- [x] every landed regression fixture fails without its fix and passes with it;
      record that check per fixture

**Evidence (Task 7, verified 2026-09-11 from 05:38Z on the measurement host
against `f9c89a2`, the tree after Task 6; nothing under `work/` was read or
written, and `ps` showed no sweep runner alive before anything was launched):**

- **Full repository gate, each exit 0, run on the committed tree after the
  fixture reverts below had been restored (`git status --short` empty):**
  - `uv run ruff check .` — "All checks passed!"
  - `uv run ruff format --check .` — "464 files already formatted"
  - `uv run mypy src scripts` — "Success: no issues found in 46 source files"
  - `uv run pytest` — 1966 items collected, **1955 passed, 11 skipped, 0
    failed, coverage 91.63 % (`fail_under` 90 %), exit 0**, in 1163.71 s
    (19 min 24 s) of test time; launched 05:40:24Z, exit marker seen by
    05:59:50Z, while the host carried unrelated load (load average about
    2.5 on 4 cores before the run). Same pass and skip counts and the same
    coverage as the Task 6 post-fix gate, as expected for an unchanged tree.
    Log under `/var/tmp`, outside the repository.
- **Diff hygiene.** `git diff --check main...HEAD` exit 0 and the working
  tree is clean. `git diff --name-only main...HEAD` lists 13 files: this
  plan, `docs/pypi-validation.md`, `docs/usage.md`, `scripts/pypi_corpus.py`,
  `scripts/pypi_probe.py`, `scripts/pypi_validate.py`,
  `src/pyahead/analysis/engine.py`, `src/pyahead/analysis/reachability.py`
  and five modules under `tests/unit/`. None is under `work/`, and
  `git ls-files work/` is empty, so no manifest, wheelhouse, shard, report or
  worksheet is tracked. Every added line was grepped for `/home/`, `/root/`,
  `/work/repos`, `/Users/`, the host name and the user name: 0 hits. Grepped
  for `password`, `passwd`, `secret`, `api_key`/`api-key`, `token`, `bearer`,
  the AWS, GitHub, Slack and OpenAI key shapes, `ssh-rsa`/`ssh-ed25519` and
  `BEGIN ... PRIVATE KEY`: 0 hits. The only path-like text is in this plan's
  narrative: relative `work/...` arguments quoted from the documented
  invocations (24 added lines, all in this file) and four mentions of
  `/var/tmp` as the generic location of job logs, which identifies no host.
  No other changed file mentions `work/`, `/tmp` or `/var/tmp`.
- **Protected files.** `git diff --quiet main...HEAD -- <path>` exit 0 for
  `docs/design.md`, `AGENTS.md`, `.github/workflows`,
  `docs/evidence/gate-c.md` and `pyproject.toml`. `pyproject.toml` is not in
  the diff at all, and its `tool.ruff`, `tool.mypy`,
  `tool.pytest.ini_options` and `tool.coverage.*` tables were also compared
  table-by-table against `main`: byte-identical, `fail_under = 90` intact.
- **Regression fixtures, fail-without / pass-with, per fixture.** Method:
  each fixed file was reverted alone to its `main` version
  (`git show main:<file> > <file>`), its fixtures run with
  `uv run pytest <modules> -k <fixture names> --no-cov -q -rA`, the file
  restored (`git checkout HEAD -- <file>`, `git status --short` empty after
  every group), and the fixtures run again; the per-test log is under
  `/var/tmp`. Tests marked *guard* assert that the fix does not over-reach
  (the pre-fix behaviour was already right for them), so they pass both
  ways by design. Every fix-specific test fails on `main` and passes on
  `HEAD`:
  - `src/pyahead/analysis/reachability.py`, CPY0024 distlib, the
    `sys.version_info[0]` major-index guard (Task 6). FAIL → PASS:
    `test_precision_regressions.py::test_major_version_index_guard_hides_a_python2_only_import`;
    `test_reachability.py::test_major_index_guard_compares_the_major_component_only`
    cases `version[0] < 3`, `version[0] >= 3`, `version[0] == 2`,
    `version[0] != 2`, `2 < version[0]`. Guards, PASS → PASS:
    `test_major_version_index_guard_keeps_the_python3_branch` (3 cases),
    `test_major_version_index_against_a_non_integer_stays_unknown`, and the
    `version[0] < (3,)`, `version[1] < 3`, `version[0] < 3.0` unknown cases.
    Without the fix 6 failed, 7 passed; with it 13 passed.
  - `src/pyahead/analysis/engine.py`, CPY0043 anyio, never-evaluated
    annotations (Task 6). FAIL → PASS:
    `test_local_variable_annotation_is_never_evaluated`,
    `test_future_annotations_defer_every_annotation`. Guards:
    `test_evaluated_annotations_still_report` (`parameter`, `class-body`,
    `module-level`). Without 2 failed, 3 passed; with 5 passed. Superseded
    by the second review below, which narrowed the rule to PEP 526 and
    replaced the PEP 563 fixture.
  - `scripts/pypi_corpus.py`, `unresolved` manifest entries for a release
    with no installable artifact (Task 2). FAIL → PASS:
    `test_acquire_records_a_package_without_an_installable_artifact_as_unresolved`,
    `test_select_release_file_reports_no_installable_artifact_as_a_typed_error`,
    `test_load_manifest_accepts_unresolved_entries_alongside_packages`, and
    `test_load_manifest_rejects_a_malformed_unresolved_list` cases
    `unknown-reason`, `rank-shared-with-a-package`,
    `name-shared-with-a-package`, `empty-version`, `undocumented-field`,
    `missing-field`, `not-an-object`. Guards:
    `test_acquire_still_aborts_on_any_other_package_error` and the
    `over-count`, `under-count`, `not-a-list` cases, which `main` rejects
    too. Without 10 failed, 4 passed; with 14 passed.
  - `scripts/pypi_probe.py`, oracle fixes 1, 2, 3 and 5 of Task 6
    (bound-method identity, submodule from-imports, walk failing at `S`'s
    own slot, from-import-bound prefix). FAIL → PASS:
    `test_subject_probe_resolves_a_from_imported_submodule`,
    `test_subject_probe_reports_import_error_for_a_broken_submodule`,
    `test_binding_probe_confirms_a_classmethod_bound_on_every_access`,
    `test_same_object_compares_bound_methods_by_self_and_function`,
    `test_binding_probe_is_inconclusive_when_the_walk_fails_at_the_subjects_slot`,
    `test_binding_fields_allow_an_inconclusive_slot_walk_failure_only`
    case `absent-AttributeError: nope-None-True`,
    `test_binding_probe_walks_from_a_from_imported_prefix`. Guards:
    `test_subject_probe_does_not_import_a_missing_attribute_of_a_class`,
    `test_binding_probe_refutes_a_different_bound_method`,
    `test_binding_probe_still_refutes_a_shadow_missing_the_subjects_attribute`,
    `test_binding_probe_still_refutes_a_walk_failing_before_the_subjects_slot`,
    `test_binding_probe_still_refutes_a_shadow_via_a_later_prefix`, and the
    four other `binding_fields` cases. Without 7 failed, 9 passed; with 16
    passed.
  - `scripts/pypi_validate.py`, the Task 3 smoke-run fixes (interpreter
    launcher symlinks resolved, relative `--work-dir` resolved,
    `probe_isolation_mode` unset until a probe runs) and Task 6 oracle fix 4
    with its schema mirror. FAIL → PASS:
    `test_installed_interpreters_resolve_launcher_symlinks`,
    `test_run_resolves_a_relative_work_dir_before_processing`,
    `test_run_records_no_probe_isolation_mode_without_findings`,
    `test_binding_verdict_refutes_an_absent_subject_only_where_expected`,
    `test_adjudicate_does_not_refute_an_aliased_from_import_at_the_reference`,
    `test_probe_result_binding_fields_mirror_the_slot_walk_failure` case
    `absent-AttributeError: nope-None-True`. Guards:
    `test_adjudicate_still_refutes_a_fallback_at_the_removal_minor`,
    `test_adjudicate_treats_a_slot_walk_failure_as_inconclusive_at_the_cross_check`
    (passes on `main` too, which already did not refute an
    `identity_match: None` cross-check result; the new
    `(absent, walk error, None)` schema triple is what the mirror case above
    proves), and the two other mirror cases. Without 6 failed, 4 passed;
    with 10 passed.
  - No file under `src/pyahead/data/registry/` changed on this branch, so
    there is no timeline fixture to check: the 53 `refuted-timeline` rows
    were oracle fix 2, not a registry defect.

### Task 8: Record the evidence

- [x] write `docs/evidence/pypi-top-1000.md` following the evidence-record
      template in `docs/pypi-validation.md` and the house style of
      `docs/evidence/gate-c.md`
- [x] state the limitations plainly: what `adjudication_coverage` excludes, that
      accuracy is measured over adjudicated findings only, that this is
      precision on a pinned corpus and not recall, and that any minor
      interpreter unavailable at run time bounded what could be adjudicated
- [x] leave the decision, reviewer and date **unfilled**, exactly as
      `docs/evidence/gate-d.md` does. An agent may prepare and verify this
      evidence but cannot approve it; approval is a human act
- [x] update `CHANGELOG.md` under `Unreleased` only if a triage fix changed
      user-visible behaviour; a validation run on its own is not a changelog
      entry

**Evidence (Task 8, written 2026-09-11 on the measurement host against
`2eaea98`; nothing under `work/` was modified, and the report and worksheet
were only read to derive the figures):**

- **`docs/evidence/pypi-top-1000.md` written.** It follows the spec's
  evidence-record template (reproduced verbatim as a filled `text` block)
  and the house style of `gate-c.md` and `gate-d.md`: a Decision block, an
  Evidence identity block (revision, version, registry revision and full
  digest, corpus source and retrieval time, upstream-payload, manifest and
  both report SHA-256s, policy, interpreters, host, isolation), Corpus and
  coverage (the eight non-scanned classes as a table, 186 of 797 scanned
  packages carrying findings, reference-interpreter distribution), Precision
  (both aggregations side by side, per matcher kind, and the full per-rule
  table generated from `work/pypi-report.json` rather than transcribed:
  48 rules, totals 520 / 8 / 957 / 1485), Triage (the row-outcome table,
  the five oracle defects with row counts summing to 191, the two PyAhead
  false positives with their fixtures, the re-run, and all 8 open rows each
  named with its reason), the harness fixes made during the run, Verification
  (Task 7's gate, the per-file fail-without/pass-with table, protected files,
  hygiene, reproducibility), a comparison table with Gate C, Limitations
  retained, and a reviewer checklist. It states that the worksheet's review
  columns are empty and that the triage record is the document plus this
  plan, and that the 200-row confirmed sample was generated and
  identity-bound but not manually reviewed.
- **Limitations stated plainly**, in the Record block and the Limitations
  section: recall is not measured; accuracy is over the 528 adjudicated
  findings only (35.6% coverage) and `adjudication_coverage` excludes the
  957 not-adjudicable findings by reason (835 `binding-not-visible`, 82
  `import-error`, 40 `module-not-importable`), the 202 unscanned packages
  and every medium-confidence finding; it is precision on a pinned corpus;
  every minor 3.11-3.15 was installed so `no-interpreter` was 0, the horizon
  was 3.15 so 3.16 schedules were outside the policy, and 3.15.0b2 is a
  prerelease. Also recorded: the oracle changed during the run, the 8 open
  rows are counted as refutations, the 37 packages lost to the reference
  rule, the 5 scan timeouts, Windows-only paths, and the shared host.
- **Decision, reviewer and date unfilled**, exactly as `gate-d.md`:
  `Decision date: _not yet decided_`, `Accountable reviewer: _pending_`,
  `Decision: **not approved; awaiting review**`, and `Reviewed by:
  _pending_, _not yet decided_` in the Record block. The document says in
  its first and last paragraphs that an agent prepared it and cannot
  approve it.
- **`CHANGELOG.md` updated under `Unreleased`** with a `### Fixed` section
  for the two triage fixes that changed user-visible behaviour: the
  `sys.version_info[0]` major-index guard (findings in Python-2-only
  branches no longer reported) and never-evaluated annotations treated as
  typing-only (runtime-only rules no longer report them). The harness fixes
  under `scripts/` are developer tooling and the sweep itself is not a
  changelog entry, so neither is listed.
- **Gate on the tree with this document and the changelog entry, each exit
  0:** `uv run ruff check .`: `All checks passed!`; `uv run ruff format
  --check .`: `465 files already formatted`; `uv run mypy src scripts`:
  `Success: no issues found in 46 source files`; `uv run pytest`, launched
  detached at 06:07Z with its log under `/var/tmp`:
  `1955 passed, 11 skipped, 0 failed, exit 0, coverage 91.63% against the 90% floor, in 1153.75 s (19 min 13 s)`. `git status --short` before the commit lists only
  `CHANGELOG.md`, `docs/evidence/pypi-top-1000.md` and this plan; `work/`
  remains ignored in full.

## Second review (2026-09-11, after `6178b96`)

The second review pass found two major issues. The source fix is
`9638826ef75028e8cbccd9d9a25653e406ffa677`; the document corrections are in
`2357684084eae32cff6051fb8b8b7b1d222a2c8d`.

- **The anyio rationale was misattributed, and the engine fix was broader
  than the row.** This plan, the evidence record and the fixture docstring
  said the oracle refuted the anyio CPY0043 row "because the site was never
  executed". The binding probe never executes a site. Re-running both
  oracle versions on the pinned wheel, in fresh 3.11 and 3.14 environments
  built from the wheelhouse, shows what happened: `identity_match: true` at
  3.11 under both; at 3.14 the `main` oracle returned `identity_match:
  false` with `AttributeError: module 'asyncio' has no attribute
  'AbstractChildWatcher'` (defect 3's shape), and the fixed oracle returns
  `identity_match: null`, so the fixed oracle confirms the row. The
  false-positive classification rests on PEP 526 alone; the three
  statements now say so. On that basis the engine rule is narrowed to the
  annotation of a local variable inside a function body:
  `from __future__ import annotations` no longer defers every annotation,
  because `typing.get_type_hints` and the libraries built on it
  (dataclasses, pydantic, attrs) still evaluate stringified annotations at
  runtime, so a removed subject in a parameter, return, class-body or
  module-level annotation still breaks and the broader rule had silenced
  it. `_has_future_annotations` and the PEP 563 short-circuit are gone;
  `test_future_annotations_do_not_defer_evaluated_annotations` asserts
  that the four evaluated sites report under PEP 563 and the local one does
  not, and `test_deferred_annotation_keeps_a_typing_context_finding` uses a
  local annotation. Rescanning the pinned anyio wheel with the narrowed
  rule (baseline 3.11, horizon 3.15, high confidence) reproduces the
  refreshed shard's 32 findings with identical fingerprints, so no sweep
  figure changes. `CHANGELOG.md` and `docs/usage.md` are narrowed to match.
- **The evidence record described a tree that was not `HEAD`.** Its
  identity block named `2eaea98` and said the later commits changed only
  the plan, after `6178b96` had changed the probe, the validator, the
  corpus script, the engine docstring and the tests; its gate table and
  per-file fixture table were those of `a4c753c`. The identity block now
  names `9638826` as the revision reviewed, `4a279db` as the source that
  produced the sweep and the report digest, and both post-sweep source
  changes. Limitations states what each can and cannot change in the
  figures, including that a `confirmed` verdict reached through a locally
  bound later prefix is unmeasured rather than known to be zero, because a
  probe result does not record which candidate decided it. The gate and
  the fixture table were re-derived on the final tree, below.
- **Fixture check re-derived at `9638826`, whole modules:** each fixed
  file reverted alone to `main`, its modules run, the file restored from a
  copy and the modules run again; `git status --short` showed no source
  change after every group; per-test log under `/var/tmp`.
  `reachability.py`: 6 failed of 69, then 69 passed. `engine.py`: 3 failed
  of 20 (`test_local_variable_annotation_is_never_evaluated`,
  `test_future_annotations_do_not_defer_evaluated_annotations`,
  `test_deferred_annotation_keeps_a_typing_context_finding`), then 20
  passed. `pypi_corpus.py`: 12 failed of 107 across `test_pypi_corpus.py`
  and `test_pypi_report.py` (the ten Task 2 fixtures plus
  `test_acquire_writes_a_manifest_with_exactly_1000_verified_entries` and
  `test_main_aggregates_a_manifest_with_an_unresolved_rank`), then 107
  passed. `pypi_probe.py`: 8 failed of 71 (the seven Task 6 fixtures plus
  `test_subject_probe_reports_import_error_for_a_submodule_missing_a_dependency`),
  then 71 passed; the two later-prefix narrowing fixtures pass on `main`,
  which had no later-prefix walk at all, and the first review recorded
  them failing against the pre-narrowing probe at `a4c753c`.
  `pypi_validate.py`: 18 failed of 130, then 130 passed. Six fail on
  their assertions (`test_run_resolves_a_relative_work_dir_before_processing`,
  `test_installed_interpreters_resolve_launcher_symlinks`,
  `test_run_records_no_probe_isolation_mode_without_findings`, the
  `absent-AttributeError: nope-None-True` mirror case,
  `test_adjudicate_does_not_refute_an_aliased_from_import_at_the_reference`
  and the first review's
  `test_adjudicate_cross_check_does_not_refute_an_absent_subject_before_removal`)
  and twelve `_binding_verdict` cases, among them
  `test_binding_verdict_refutes_an_absent_subject_only_where_expected`,
  raise `TypeError` because the `main` signature lacks the
  `expected_presence` keyword oracle fix 4 introduced.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached with its log under `/var/tmp`: 1964 passed, 11 skipped, 0 failed, exit 0, coverage 91.62% against the 90% floor, in 1171.67 s (19 min 31 s).

## Third review (2026-09-11, after `2357684`)

The third review pass found two major issues. The source fix is
`b75064416e37ed20bf27c30c4a0c6abd4dad68e6`, which also carries its document
corrections.

- **The bound uv install root was not resolved.** The second review made
  `_installed_interpreters` record each interpreter's resolved path, so a
  bare-interpreter probe execs a file under the managed-install root, but
  `_uv_python_install_dir` still returned that root unresolved and the
  sandbox bound the unresolved path. On a host where `uv python dir`
  reaches its root through a symlink (a relocated `~/.local/share`, or
  `UV_PYTHON_INSTALL_DIR` pointing through a link), every resolved
  interpreter path would lie outside every bound tree and every C2 probe
  would fail at exec inside `bwrap`. The root is now resolved before it is
  bound, and `test_uv_python_install_dir_resolves_a_symlinked_root` pins
  the behaviour with a symlinked root. On this host the root resolves to
  itself, so the recorded sweep ran with the same mount and no figure
  changes.
- **`docs/pypi-validation.md` claimed a coverage C2 does not have.** It
  said a registry timeline that wrongly expects the subject present at the
  reference interpreter is caught by C2's presence check. It is not:
  `_binding_verdict` returns `not-adjudicable:module-not-importable` for
  that shape, `_run_binding_phase` drops the finding before `c1_confirmed`,
  `_adjudicate` schedules C2 only from `c1_confirmed`, and the worksheet
  forces in refutations only. The sentence is corrected; a Limitations
  bullet states what is and is not caught, including that routing the
  shape to C2 would not close the gap because C2 probes only the
  action-1/action pair; and the evidence record carries the same
  limitation with the per-rule split of the 40 such rows this sweep
  inspected by hand, all of which had been `refuted-binding` rows in the
  first aggregation. Forcing those rows into the worksheet was not done,
  because it would invalidate the worksheet already bound to the report
  digest.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached with its log under `/var/tmp`: 1965 passed, 11 skipped, 0
  failed, exit 0, coverage 91.62% against the 90% floor, in 1154.91 s
  (19 min 14 s).

## Fourth review (2026-09-11, after `b750644`)

The fourth review pass found one major issue, corrected in
`7983731f3a5d9c601c3d9bfe5f2581f5605958f0`. That commit changes no source.

- **The evidence record again described a tree that was not `HEAD`.** Its
  identity block named `9638826` as the last source change on the branch
  after `b750644` had changed `scripts/pypi_validate.py` and added a test;
  its harness-fix list named three validator fixes and three tests; its
  gate row was the `9638826` run (1964 passed, 1975 items) and its fixture
  row for the validator said 130 tests, where `HEAD` collects 131 in that
  module and 1976 in all. The identity block and the record template line
  now name `b750644` and all three post-sweep source changes; the fix list
  names the install-root resolve and its test; Limitations states why that
  change cannot alter a figure (on this host the root resolves to itself);
  and the gate table and the validator's fixture row are re-derived on the
  final tree, below. This section also records the third review, which
  the plan had not.
- **Fixture check re-derived at `b750644` for `pypi_validate.py`, whole
  module:** the file reverted alone to `main`, `test_pypi_validate.py`
  run, the file restored from a copy and the module run again; `git
  status --short` clean afterwards; log under `/var/tmp`. 19 failed of
  131, then 131 passed: the eighteen the second review listed plus
  `test_uv_python_install_dir_resolves_a_symlinked_root`. The other four
  fixed files and their test modules are unchanged since the second
  review's check at `9638826`, so their rows stand.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached with its log under `/var/tmp`: 1965 passed, 11 skipped, 0
  failed, exit 0, coverage 91.62% against the 90% floor, in 1162.97 s
  (19 min 22 s).

## Fifth review (2026-09-11, after `7983731`)

The fifth review pass found one major and one minor issue. The source fix is
`7e0110a662cb7935b3ddc55fe14990e66e9f1e10`, which also carries the sixth
review's fix.

- **A later prefix could confirm through an unrelated saved global.**
  `_walk_candidates` tried every later component of the canonical name and
  let any of them confirm on reaching `S`, even after an earlier component
  had walked to a different live object. With `from datetime import
  datetime`, a saved `utcnow = datetime.utcnow`, and `datetime` rebound
  through `globals()` to a replacement class, the recorded head failed on
  `.datetime`, `datetime.utcnow` reached the replacement's method, and the
  bare `utcnow` global reached `S`, so a high-confidence CPY0093 row was
  confirmed (`main` refuted it) through a binding the site never used. The
  walk now stops guessing at the first later component whose walk completes
  on a live object: `S` confirms, anything else leaves the recorded head's
  own outcome standing. Fixtures:
  `test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_binds_elsewhere`
  (fails against `7983731`, passes against `main`, which never walked a
  later prefix) and the guard
  `test_binding_probe_still_confirms_a_from_imported_prefix_beside_a_wrapper`
  (`from datetime import datetime` beside `def utcnow()` still confirms
  through the class; fails against `main`). `docs/pypi-validation.md`
  Limitations and the evidence record's item 5 and Limitations state the
  rule and that it can only turn a `confirmed` verdict into a refutation or
  a not-adjudicable reason, for a shape whose count is unmeasured.
- **A non-string unresolved `reason` escaped manifest validation.**
  `_check_unresolved_entry` tested `item["reason"]` for membership of the
  closed reason set directly, so a JSON list or object raised an uncaught
  `TypeError` from the set lookup instead of `PypiCorpusError`. The value is
  now required to be a string before the membership test. Fixtures:
  `test_load_manifest_rejects_a_malformed_unresolved_list` cases
  `list-reason` and `object-reason`, both failing against `7983731` with the
  `TypeError`. The pinned manifest's one unresolved reason is a string, so
  it loads identically.
- **Fixture check on the fifth review's tree, whole modules:** each fixed
  file reverted alone, first to `7983731` and then to `main`, its modules
  run, the file restored from a copy and the modules run again; `git status
  --short` showed only the four intended modifications afterwards; log under
  `/var/tmp`. `pypi_probe.py`: against `7983731`, 1 failed of 73 (the
  rebound-class fixture); against `main`, 9 failed of 73 (the eight the
  second review listed plus the wrapper guard); restored, 73 passed.
  `pypi_corpus.py`: against `7983731`, 2 failed of 109 (the two reason
  cases); against `main`, 14 failed of 109 across `test_pypi_corpus.py` and
  `test_pypi_report.py` (the twelve the second review listed plus the two
  reason cases); restored, 109 passed.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached with its log under `/var/tmp`: not completed on this tree - the
  run was still in progress when the sixth review's source edit landed
  and was stopped (see the sixth review), so the full pytest gate for
  the commit carrying both reviews' fixes is the one recorded there.

## Sixth review (2026-09-11, on the fifth review's uncommitted tree)

The sixth review pass found one major issue. The source fix is carried by
the same commit as the fifth review's fixes.

- **A later prefix whose walk failed still let a prefix after it confirm.**
  The fifth review's fix ended the guessing only when a later component's
  walk *completed* on a live object other than `S`. A later component whose
  walk raised `AttributeError` away from `S`'s own slot fell through, so
  with `from datetime import datetime`, a saved `utcnow = datetime.utcnow`,
  and `datetime` rebound through `globals()` to a replacement class that
  has no `utcnow` at all, the recorded head failed on `.datetime`,
  `datetime.utcnow` failed on `.utcnow`, and the bare `utcnow` global
  reached `S`: a high-confidence CPY0093 row was confirmed while the site's
  own `datetime.utcnow()` raises (`main` refuted it). A bound later
  component whose walk breaks away from `S`'s slot is as plausible a
  spelling as every component after it, so it now ends the guessing exactly
  as a walk onto a different object does; the recorded head's own outcome
  stands. Fixture:
  `test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_fails_elsewhere`.
  The scenario was run through the probe payload directly from temporary
  copies of the script, without touching the worktree: against `main`
  `identity_match` is `False`; against `7983731` and against the fifth
  review's uncommitted tree it is `True`; against the fixed tree it is
  `False` with the recorded head's `AttributeError` as the error. The
  fifth review's four guards (from-import prefix, shadow-class refutation,
  wrapper beside the class, rebound class with its own `utcnow`) still
  pass. `docs/pypi-validation.md` Limitations, the evidence record's item
  5, its revision note and its Limitations state the widened rule.
- **The fifth review's detached gate was superseded.** Its `uv run pytest`
  (log `/var/tmp/pyahead-review5-pytest-20260911102412.log`) was still
  running when this review's source edit landed, so its result would have
  covered a tree that changed mid-run; it was stopped and the gate below
  was run on the final tree instead. The evidence record's gate table, which
  had carried the fourth review's pytest figures under the fifth review's
  heading, now reports this run.
- **A pre-existing test depended on how pytest was launched.** The first
  full gate on this tree (log
  `/var/tmp/pyahead-gate-sixth-review-20260911T103537.log`) ran 1969
  passed, 1 failed: `tests/unit/test_dependencies.py::`
  `test_interruption_before_containment_cleans_the_suspended_process`,
  untouched by this branch and passing in isolation. That gate had been
  started as a shell background job from a non-interactive `bash`, which
  starts its children with SIGINT ignored; Python then leaves SIGINT
  ignored, and `_replay_deferred_sigint` correctly honours `SIG_IGN`, so the
  test's real `SIGINT` never became the `KeyboardInterrupt` it expects. The
  same test fails the same way on `main` under that launch and passes under
  a foreground launch. The test now installs `signal.default_int_handler`
  for its duration and restores the prior handler, which is the
  precondition its docstring assumes; it passes under both launches, and
  the module's other interruption and containment fixtures still pass. The
  gate below was re-run on the final tree through a launcher that resets
  SIGINT to `SIG_DFL` before starting pytest.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached with its log under `/var/tmp`: 1970 passed, 11 skipped, 0 failed, exit 0, coverage 91.62% against the 90% floor, in 1171.29 s (19 min 31 s).

## Seventh review (2026-09-11, on `7e0110a`)

The seventh review pass found one major issue, in the evidence record rather
than in the source. No source file changed.

- **The per-fixture record described the fifth review's probe, not the
  committed one.** The evidence record's Verification section still carried
  the fifth review's fixture check for `scripts/pypi_probe.py` (9 of 73
  failing against `main`, 73 passing restored) and named only the fifth
  review's rebound-class fixture, although the sixth review changed the
  probe again and added a 74th test to `test_pypi_probe.py`, and the sixth
  review had recorded only a payload run from temporary copies rather than
  the module-level revert check Task 7 requires. Re-derived on this tree,
  in place, with the file restored through `git checkout` afterwards and
  `git status --short` clean; log
  `/var/tmp/pyahead-review7-probe-fixture-20260911T113523.log`.
  `pypi_probe.py` against `main`: 9 failed of 74 (the eight the second
  review listed plus the wrapper guard; both later-prefix fixtures pass, as
  `main` never walked a later prefix); against `7983731`, whose probe and
  corpus scripts are identical to those at `b750644`: 2 failed of 74, the
  fifth review's
  `test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_binds_elsewhere`
  and the sixth review's
  `test_binding_probe_does_not_confirm_via_a_later_prefix_after_one_fails_elsewhere`;
  restored, 74 passed. `pypi_corpus.py` was last changed by the fifth review
  and its two modules still collect 109 tests, so the fifth review's corpus
  check stands. The evidence record's fixture paragraph and table row now
  state these figures, and its Verification heading names `7e0110a` as the
  tree the gate table describes.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached through a launcher that resets SIGINT to `SIG_DFL`, with its log
  under `/var/tmp`: 1970 passed, 11 skipped, 0 failed, exit 0, coverage
  91.62% against the 90% floor, in 1173.28 s (19 min 33 s).

## Eighth review (2026-09-11, on `3e1c11f`)

The eighth review pass found one major issue, in the evidence record rather
than in the source. No source file changed.

- **The evidence record's identity block still described itself as the
  fifth review's source-fix commit.** Its "PyAhead revision reviewed" entry
  read "the commit that carries this revision of the record, the fifth
  review's source fix", named `b750644` as the last source change before
  it, and asked a later revision of the document to pin the hash. The
  seventh review's commit, `3e1c11f`, was that later revision and changed
  only documents, so at the branch head the sentence named the wrong commit
  and the pin was never made; the record's filled template line still gave
  `revision b750644`, which predates the later-prefix stop rule and the
  corpus loader's string check that the same record describes, and the
  Limitations entry for item 5 used the same self-reference. The identity
  block now pins `7e0110a662cb7935b3ddc55fe14990e66e9f1e10` as the revision
  reviewed and the last commit to change a source file, and states that
  every later commit changed only the record and this plan; the template
  line and the Limitations entry name the same hash; the Verification
  paragraph covers the seventh and eighth reviews. The second, fourth and
  fifth review sections above, which also said "the commit that carries
  this section", now name `2357684`, `7983731` and `7e0110a`, checked
  against the first commit in which each section appears.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached through a launcher that resets SIGINT to `SIG_DFL`, with its log
  under `/var/tmp`: 1970 passed, 11 skipped, 0 failed, exit 0, coverage
  91.62% against the 90% floor, in 1223.73 s (20 min 24 s).

## Ninth review (2026-09-11, on `79c4d36`)

The ninth review pass found one major issue, in the evidence record rather
than in the source. No source file changed.

- **The evidence record's reference-interpreter split was scoped to the
  wrong population.** Under "Corpus and coverage", the sentence "Reference
  interpreters by package: 3.11.15 for 989, 3.12.13 for 8, 3.15.0b2 for 1"
  followed "Of the 797 scanned packages, 186 produced at least one
  high-confidence finding and 611 produced none", but 989 + 8 + 1 = 998 is
  the split over every shard that chose a reference, including the 155
  `install-failed`, 41 `skipped: no Python files` and 5 `scan-failed`
  shards, so a reader took 989 3.11-referenced packages out of 797 scanned
  and could not reproduce the figure from the scanned set. Recounted from
  the `interpreter.reference_version` field of the 999 shards, the scanned
  split is 3.11.15 for 790, 3.12.13 for 6, 3.15.0b2 for 1 (the other
  populations: `install-failed` 154 and 1, `skipped: no Python files` 41,
  `scan-failed` 4 and 1). The record now states both splits with their
  populations and names the one shard, `skipped: no compatible
  interpreter`, that chose none.
- **Gate on the final tree, each exit 0:** `uv run ruff check .`: `All
  checks passed!`; `uv run ruff format --check .`: `465 files already
  formatted`; `uv run mypy src scripts`: `Success: no issues found in 46
  source files`; `git diff --check`: clean; `uv run pytest`, launched
  detached through a launcher that resets SIGINT to `SIG_DFL`, with its log
  under `/var/tmp`, started before the two document edits above, which no
  test reads: 1970 passed, 11 skipped, 0 failed, exit 0, coverage 91.62%
  against the 90% floor, in 1200.85 s (20 min 1 s).

## Post-Completion (operator, not automatable)

1. **Review and sign the evidence.** Precision claims are human-owned, as with
   Gate C. Nothing in this plan may record an approval.
2. **Decide what the number means for the roadmap.** A materially different
   agreement rate from Gate C's sampled 100% is a product signal about the
   registry and the matchers, not merely a report.
3. **Decide whether this supersedes or complements Gate C.** The two corpora
   and oracles differ; `docs/evidence/gate-c.md` stays as approved either way.
4. **Consider whether the harness should run in CI on a reduced corpus.** It is
   Linux-only and executes third-party code, so this is a deliberate decision
   with a security dimension, not an obvious extension.
