# PyPI top-1000 validation with per-finding runtime adjudication

This protocol measures PyAhead's precision against the PyPI top-1000 by
adjudicating **every** high-confidence finding against a real CPython
interpreter. It is a repo-internal validation harness under `scripts/`, not
the shipped `0.2` compatibility-probe provider described in
[`design.md`](design.md) §17.5 — see that section for the product feature
this harness must not be confused with.

The harness runs on Linux only. Its isolation depends on `bwrap`, which needs
Linux namespaces, and `RLIMIT_AS` is not dependably enforceable elsewhere —
on macOS setting it makes CPython fail to allocate, so every probe returns
`probe-crashed`. The `tests/unit/test_pypi_probe.py`,
`tests/unit/test_pypi_validate.py`, and
`tests/integration/test_pypi_validation.py` modules skip at import on other
platforms, before `scripts/pypi_validate.py` can import the POSIX-only
`resource` module. Every other command in this repository remains
cross-platform.

## The oracle: C1/C2 per-finding adjudication

A static finding is a claim, not a fact. Each high-confidence finding asserts
two things, and each is probed separately under a real interpreter rather
than trusted from the static match:

- **C1 — binding.** At the finding's site in module `M`, the name PyAhead
  resolved actually binds at runtime to the CPython subject `S` it claims
  (`resolved is S`). This catches vendoring, shadowing, rebinding,
  conditional imports, and `TYPE_CHECKING`-only names — the real
  false-positive sources.
- **C2 — timeline.** `S`'s observable state across interpreters 3.11–3.15
  matches the registry's timeline for the rule: present/absent for a
  `removed` event, accepted/rejected for a `signature_changed` event. This is
  keyed on the finding's own timeline *event type*, not merely on whether the
  rule's overall impact is breaking: a `behavior_changed` or
  `support_dropped` event (for example `ssl.SSLSession` rejecting direct
  construction, or `shlex.split(None)` raising inside the function body) is
  breaking without removing `S` or changing what its call shape accepts, so
  C2 expects `S` to stay present and its call shape to stay accepted for
  those events — asserting otherwise from `impact == "breaking"` alone would
  misread a subject that never left as a registry defect. This validates the
  registry's removal and signature-change claims against the interpreters
  themselves, not just against the static claim. (See
  [Limitations](#limitations) for what C2 does not yet cover.)

C1 runs inside the target distribution's own installed environment, at every
interpreter minor the finding actually needs whose own venv is available (see
below); C2 runs stdlib-only probes against `S` itself under a bare
interpreter, using the probe payload in `scripts/pypi_probe.py` (stdlib-only,
executed *by* the target interpreter, never importing `pyahead`).

## Verdicts

Every high-confidence finding is assigned exactly one verdict from a closed
set:

- `confirmed` — C1 holds under an interpreter where `S` exists, and C2 holds
  for the rule.
- `refuted-binding` — the name resolves to a different object than `S` → a
  PyAhead false positive.
- `refuted-timeline` — the interpreter contradicts the registry timeline → a
  registry defect.
- `not-adjudicable:<reason>` — adjudication could not reach a verdict, for
  one of a closed set of reasons: `install-failed`, `module-not-importable`,
  `import-error`, `import-timeout`, `binding-not-visible`, `no-signature`,
  `probe-timeout`, `probe-crashed`, `no-interpreter`.

## Metric definitions

```
accuracy              = confirmed / (confirmed + refuted-binding + refuted-timeline)
adjudication_coverage = adjudicated / total high-confidence findings   # reported, not gated
```

`accuracy` (labelled `agreement_rate` in the aggregate record) is computed
only over findings that reached a terminal, adjudicated verdict.
`adjudication_coverage` is reported alongside it, broken down by
`not-adjudicable` reason, by rule, and by matcher kind, but does not gate the
accuracy number — a finding that cannot be adjudicated is neither an
agreement nor a disagreement.

### Limitations

- **Recall is out of scope by construction.** Per-finding adjudication
  measures precision — whether findings PyAhead reported are correct — not
  whether PyAhead missed occurrences it should have reported. Do not read
  the accuracy number as an overall correctness score; it says nothing about
  missed findings.
- **3.16 rules are unadjudicable.** No 3.16 interpreter exists on the host
  used for this validation (only 3.11–3.15 are installable via `uv`), so any
  finding whose action version exceeds 3.15 is recorded as
  `not-adjudicable:no-interpreter` rather than skipped silently.
- **Aliased from-imports of a module-level subject are unadjudicable.** For
  `from A import B as C`, the finding's evidence records only the bound name
  `C`, not the original attribute `B`; there is no way to recover `B` from
  static evidence alone. Naming `S` as `A.C` (a nonexistent attribute)
  resolves to "absent" rather than a false identity match, so the finding is
  recorded as `not-adjudicable:module-not-importable` instead of wrongly
  confirmed or refuted - a coverage loss for this narrow evidence gap, not a
  precision defect. Unaliased `from A import B` is unaffected: `B` is both
  the bound name and the real attribute.
- **C1's cross-check at a non-reference interpreter is opportunistic, not
  guaranteed.** C1 is always checked at the reference interpreter — already
  sufficient to confirm or refute many findings (`module-import-end-to-end`,
  or a straightforward identity mismatch), which a host with only one
  interpreter installed must still be able to reach. When a finding's own
  `interpreters_needed` pair includes another minor, the runner additionally
  provisions that minor's own venv and installs the distribution into it
  (`(package, interpreter)`, per the plan), and cross-checks C1 there too:
  this is what catches a `try`/`except ImportError` or
  `sys.version_info`-gated fallback that binds a *different* object once
  actually run under the interpreter where the registry claims `S` breaks —
  a reference-only check can never see that, since the guarded branch simply
  never executes under the reference interpreter. Only a clean refutation at
  that extra minor (the identity genuinely does not match) overrides an
  otherwise-confirmable reference verdict; an inconclusive probe there
  (install failed for that interpreter, the subject import crashed, ...)
  is not treated as a reason to make an otherwise-confirmable finding
  `not-adjudicable` — it simply falls back to the reference-only verdict.
  Provisioning an extra venv per distinct non-reference minor a package's
  findings need adds to the already multi-day sweep's install/disk cost,
  proportional to how many distinct action versions a package's findings
  span; a finding whose extra minor's venv never installed is still
  adjudicated (via the reference alone), it just cannot benefit from this
  additional catch for that one interpreter.
- **Deprecation onset is not scored by C2.** For a `deprecated`-impact
  finding, C2 currently only checks that `S` stays present (it does not
  check whether Python's own deprecation warning actually fires at the
  claimed version): the subject probe already captures any
  `DeprecationWarning`/`PendingDeprecationWarning` raised on import or
  attribute access as `deprecation_warning`, and this is retained in the
  adjudication evidence for manual triage, but it does not currently gate
  the verdict. A registry rule that gets the deprecation *onset* version
  wrong therefore cannot yet be caught by `refuted-timeline`; only a wrong
  removal version or signature change can be. Scoring this automatically is
  future work: not every deprecation warning fires on mere import/attribute
  access (some only fire when the deprecated callable is actually invoked,
  which C2 deliberately never does), so naively gating on
  `deprecation_warning` would trade missed registry defects for spurious
  `refuted-timeline` false positives.

## Isolation and third-party-code execution warning

This harness installs and imports arbitrary third-party code from the PyPI
top-1000. That crosses PyAhead's own "never execute target code, never touch
the network" boundary described in `docs/security-and-privacy.md`, so:

- `pypi_validate.py run` requires an explicit `--execute-third-party-code`
  flag and refuses to run without it;
- probes and installs run under `bwrap --unshare-net --unshare-pid
  --die-with-parent`, with a private `/tmp`, `/run`, and `/proc` (a fresh
  procfs scoped to the sandbox's own PID namespace, not the host's real
  one — see below), a scratch `HOME` (never the operator's real one, even in
  the `rlimit-only` fallback below), a child environment built from an
  explicit allowlist rather than the parent's own, plus
  `RLIMIT_AS`/`RLIMIT_CPU`/`RLIMIT_NPROC`/`RLIMIT_FSIZE` and a parent-side
  wall-clock timeout, when `bwrap` (bubblewrap) is available on the host;
- when `bwrap` is not available, isolation degrades to rlimits, the scrubbed
  environment, and a parent-side timeout only (`rlimit-only`) — there is no
  filesystem, `/proc`, or network isolation at all in this fallback; the
  isolation mode actually used for each install and each probe batch is
  recorded on the shard so this degradation is never silent;
- **the sandbox never binds the operator's home directory or the rest of the
  host filesystem**, under `bwrap`: only a fixed set of base system
  directories (`/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, whichever exist) are
  bound read-only, plus the specific extra paths a command actually needs —
  the wheelhouse and the `uv` binary for installs, the probe script and,
  when the interpreter is `uv`-managed rather than a system package (needed
  for 3.15, which no distribution packages yet), `uv python dir`'s own
  install root. The venv itself is bound read-write only for installs;
  probes see it read-only, so a probe cannot mutate the shared venv for
  probes that run after it. Target code cannot read anything outside these
  paths — no credential files, no dotfiles, nothing else under the
  operator's home directory — regardless of what the invoking user's own
  filesystem permissions would otherwise allow;
- installation (which runs `setup.py` for sdists) is the one network-free
  step that still executes code, and is always done offline from the local
  wheelhouse with `--no-index --find-links`, installing the manifest's exact
  pinned artifact path rather than a `name==version` match that a reused
  wheelhouse could resolve to a different, unverified file;
- no probe result is ever trusted to be well-formed: both `pypi_probe.py`
  (validating what an isolated single-probe child wrote) and
  `pypi_validate.py` (validating a whole batch process's own output) parse
  every result against a closed per-kind schema - not just that `status` is
  in that kind's vocabulary, but that the result carries exactly that kind's
  field set with no fields missing, no extras, and every value correctly
  typed - rejecting the whole batch on any violation (including a wrong
  `schema_version` or a duplicate probe id) rather than trusting the one
  malformed record; and a crashing, hanging, or output-flooding package can
  never abort the batch or grow the parent's memory without bound.

Only run this harness in an environment where installing and importing
arbitrary PyPI packages is an accepted risk, on an account whose filesystem
holds nothing sensitive.

## Corpus and acquisition protocol

Acquisition is the only network step, performed explicitly by an operator
and gitignored rather than committed — the runner never fetches over the
network. Corpus policy is: attempt all 1000 packages in download-rank order;
there is no filtering by "known to contain a rule" or similar, matching the
spirit of the 100-repository corpus protocol in
[`corpus-review.md`](corpus-review.md).

```console
uv python install 3.11 3.12 3.13 3.14 3.15
uv run python scripts/pypi_corpus.py acquire \
  --manifest work/pypi-manifest.json \
  --wheelhouse work/pypi-wheelhouse \
  --timeout 30
```

`acquire` reads a snapshot of the top-1000 download ranking, resolves each
project's current release via the PyPI JSON API, and downloads one artifact
per package (wheel preferred, sdist fallback) into the wheelhouse. It writes
a `schema_version: 1` manifest with `source_url`, `retrieved_on`, the
upstream-payload SHA-256, and 1000 entries of `{rank, name, version,
filename, sha256, requires_python, is_wheel}`. Duplicate normalised names and
any non-HTTPS URL are rejected, mirroring `_repository_url` in
`scripts/corpus.py`. The manifest is written atomically.

Before running the sweep (and any time the wheelhouse may have been touched
out of band), re-verify it offline:

```console
uv run python scripts/pypi_corpus.py verify \
  --manifest work/pypi-manifest.json \
  --wheelhouse work/pypi-wheelhouse
```

`verify` re-hashes every wheelhouse artifact against the manifest without any
network access, so the runner can assume a verified corpus. The manifest and
wheelhouse are local acquisition metadata: they are gitignored, never
committed, matching `docs/corpus-review.md`.

## Shard/resume operation

`pypi_validate.py run` is the offline runner: it provisions interpreters and
one venv per `(package, interpreter)` actually needed (the scan reference,
plus any other minor a finding needs whose interpreter is installed), scans
each package with `pyahead check`, probes every high-confidence finding,
adjudicates it, and writes one atomic per-package shard to
`<work-dir>/shards/<rank>-<normalized-name>.json`.

```console
uv run python scripts/pypi_validate.py run \
  --manifest work/pypi-manifest.json \
  --wheelhouse work/pypi-wheelhouse \
  --work-dir work/pypi-validate \
  --execute-third-party-code \
  --shard 0/8 \
  --timeout 300 \
  --horizon-python 3.15
```

- `--execute-third-party-code` is required (see above); the run refuses to
  start without it.
- `--shard INDEX/COUNT` partitions the manifest by rank across `COUNT`
  parallel invocations (for example, run `--shard 0/8` through `--shard 7/8`
  as separate background jobs, each writing into the same `--work-dir`).
- Resume is the default: an existing shard file is skipped unless
  `--refresh` is passed, so a killed or restarted run picks up where it left
  off without reprocessing completed packages.
- `--limit N` caps the number of packages processed in this invocation,
  useful for a smoke run before committing to the full sweep.
- `--timeout` bounds every install and scan subprocess (seconds, default
  300).
- `--horizon-python` bounds the scan horizon (default `3.15`, the highest
  interpreter `uv` can install at present); findings whose action version
  exceeds it are `not-adjudicable:no-interpreter`.

For each package, the interpreter set is: the lowest available minor
satisfying `requires_python` (clamped to ≥3.11) as the scan reference, plus,
for each finding, the pair `(action_version - 1, action_version)` intersected
with 3.11–3.15. Scanning uses `importlib.metadata` RECORD to restrict
scanning and probing to the distribution's own files, not its dependencies.
A shard's `status` is one of `scanned`, `install-failed`, `scan-failed`, or
`skipped` (with a `reason` such as `no-compatible-interpreter` or
`no-python-files`); a non-`scanned` shard contributes no findings and is
reported under `skipped_packages` rather than silently dropped.

## Aggregation and the disagreement worksheet

Once the sweep has produced a shard for every manifest entry, aggregate:

```console
uv run python scripts/pypi_report.py \
  --manifest work/pypi-manifest.json \
  --shards work/pypi-validate/shards \
  --output work/pypi-report.json \
  --worksheet work/pypi-disagreements.csv \
  --sample-size 200
```

This produces one deterministic JSON record — `agreement_rate`,
`adjudication_coverage`, verdict counts, `not_adjudicable_reasons`, per-rule
and per-matcher-kind breakdowns, and every skipped package with its reason —
plus an identity-bound CSV worksheet of every `refuted-*` finding and a
deterministic sample of `confirmed` ones (sampled by SHA-256 of
`package rank, name, version, fingerprint`, same method as
`scripts/corpus.py`'s worksheet sampling, so reruns over the same findings
select the same sample). Package-derived worksheet columns
(`package_name`, `package_version`, `module`, `path`, `subject`, `match_kind`)
are neutralised
against spreadsheet-formula injection.

Aggregation fails closed: a missing shard index, a shard produced against a
different manifest digest, or a shard missing required fields raises rather
than silently reporting a partial denominator.

The worksheet's first row is a `report-identity` row carrying the exact
SHA-256 of the report JSON it was generated alongside; every `finding` row
repeats that digest. As with the 100-repository corpus, never begin or
resume triage until this binding is verified:

```console
uv run python scripts/pypi_report.py \
  --verify-identity \
  --output work/pypi-report.json \
  --worksheet work/pypi-disagreements.csv
```

Verification fails closed if the schema, identity row, or any finding row's
digest differ from the current report file.

## Triage procedure

For every `refuted-binding` row in the worksheet:

1. Inspect the pinned finding's location, subject, and match evidence in the
   corresponding shard, plus the binding-probe evidence that decided the
   verdict.
2. If PyAhead reported a construct that does not actually resolve to the
   claimed CPython subject, land an inline fixture reproducing the shape in
   `tests/unit/test_precision_regressions.py`, following that file's
   existing pattern of a synthetic project plus an assertion that the rule
   no longer fires (or no longer fires at high confidence).
3. Fix the matcher or registry rule that produced the false positive.
4. Re-run only the affected package(s) with `pypi_validate.py run --refresh
   --limit` (or a targeted `--shard`) to confirm the fixture and the fix
   agree, without re-running the full sweep.

For every `refuted-timeline` row:

1. Identify the rule, interpreter, and observed state named in the
   adjudication evidence.
2. Correct the corresponding `src/pyahead/data/registry/cpython/*.yaml`
   timeline entry to match the interpreter's actual observed behaviour,
   following the source and evidence conventions in
   [`registry-authoring.md`](registry-authoring.md).
3. Re-run only the affected package(s) to confirm the correction resolves
   the disagreement.

Treat `unresolved`-equivalent cases (ambiguous or disputed evidence) the same
way `corpus-review.md` treats `unresolved` corpus rows: do not include them
in the accuracy calculation until resolved.

## Evidence-record template

Record the following in the accountable evidence document once triage is
complete:

```text
Corpus: PyPI top-1000, rank 1-1000, retrieved <date>, source <source_url>
Manifest SHA-256: <manifest sha256>
PyAhead version: <version>
Registry revision: <revision/commit>
Report SHA-256: <report result digest>

packages_total / packages_scanned: <n> / <n>
findings_total: <n>
verdicts: confirmed=<n> refuted-binding=<n> refuted-timeline=<n> not-adjudicable=<n>
agreement_rate: <confirmed / adjudicated>
adjudication_coverage: <adjudicated / findings_total>
not_adjudicable_reasons: <reason: count, ...>

Triage: all refuted-binding rows have a landed regression_fixture path and a
passing negative test; all refuted-timeline rows have a landed registry
correction. Unresolved rows: <n>, reason each is still open.

Limitations restated: recall is not measured; findings with an action
version above 3.15 are not-adjudicable:no-interpreter and excluded from
adjudicated counts.

Reviewed by: <name>, <date>
```

Per the repo's gate convention, an agent may prepare and verify this
evidence but cannot approve it — approval requires a human accountable
product owner or release group, as in `corpus-review.md`'s Gate C.
