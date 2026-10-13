# PyAhead: How It Was Built

This is the delivered part of the product and technical design, moved out of
[`design.md`](design.md) on 13 October 2026 so that the contract there holds
only what still binds. Everything below is word for word as it stood in
`design.md` document version 1.1, under its original section numbers, so
citations elsewhere (evidence records, the changelog) still resolve. It is a
record, not a contract: where it and `design.md` disagree, `design.md` wins.

---

## 1. Executive summary

### 1.1 Why now

As of this document, Python 3.15 is at beta 4, release candidate 1 is expected on 4 August 2026, and the final release is expected on 1 October 2026. That provides a concrete launch story: scan repositories that still support Python 3.11 or later and show their upgrade path through Python 3.15 and beyond. The schedule is contextual, not a hard-coded product assumption; release status belongs in versioned registry data.

---

## 4. Scope and release sequence

### 4.1 `0.1.0a1`: end-to-end vertical slice

The first usable slice supports:

- a packaged CLI;
- explicit baseline and horizon versions;
- registry loading and validation;
- direct, aliased, and from-module imports;
- a small seed rule set, including PEP 594 module removals;
- text and JSON output;
- deterministic exit codes;
- tests from command line through rendered finding.

This release exists to validate architecture, not registry breadth.
Exact qualified-reference and qualified-call matching starts in M2 with the
matcher framework and its required shadowing and ambiguity fixtures.

### 4.2 `0.1.0a2`: useful CPython static analyser

Add:

- call-shape matchers;
- common `sys.version_info` guard analysis;
- `pyproject.toml` configuration and policy inference;
- SARIF output;
- baselines and suppressions;
- coverage manifests for official CPython sources;
- all high-confidence Python-level CPython entries representable by the supported matcher set for the initial version window;
- packaging and cross-platform hardening.

This is the first release to show to maintainers.

### 4.3 `0.2`: evidence providers

Add, behind explicit commands or configuration:

- dependency metadata and resolver evidence;
- pytest warning collection;
- evidence merging and conflict handling for the providers that exist.

`0.2.0` shipped these three. PEP 702 / type-checker evidence and
actual-interpreter compile/import/test probe ingestion were scoped here
originally and are deferred: §17 already records them as design constraints
rather than implied current features, and the first type-checker adapter is
still an open decision in §25. They move to `0.2.x`, whichever release
implements one, and neither blocks Gate D, which asks for one evidence provider
working end to end rather than for every provider this section once listed.

---

## 22. Validation gates

The project advances only when the preceding gate is met.

### Gate A: architecture

- One registry rule flows through CLI, analyser, finding model, text, JSON, and tests.
- An aliased import is detected.
- A call or string that merely mentions a module-rule subject is not detected as an import.
- Output is deterministic.

### Gate B: useful static alpha

- Version guards work for the documented alpha grammar.
- JSON and SARIF validate.
- Baselines and suppressions work.
- Selected CPython source pages have complete coverage manifests.
- Every implemented rule has positive and negative fixtures.
- Wheel and sdist install cleanly.

### Gate C: public-alpha precision

- At least 100 active public repositories scanned.
- At least 95% sampled precision for high-confidence findings.
- False positives have regression tests.
- Incomplete diagnostics and material limitations are retained in the evidence.
- An accountable product owner or release group reviews the evidence and
  explicitly approves proceeding to dynamic-evidence work.

### Gate D: dynamic evidence

- One evidence provider works end to end in CI.
- Evidence is clearly distinguished from static inference.
- Conflicts do not silently overwrite either source.
- Network and execution boundaries are explicit.

---

## 23. Detailed implementation backlog

Each milestone should be a separate branch and pull request once the repository has an initial commit. Codex should not implement later milestones opportunistically.

### M0 — Repository bootstrap

Deliverables:

- `docs/design.md` containing this specification;
- `AGENTS.md` containing concise project commands, invariants, and the instruction to implement one design milestone at a time;
- `README.md` with problem statement, status, and non-claims;
- Apache-2.0 `LICENSE`, subject to owner confirmation;
- `pyproject.toml` with package metadata, dependencies, scripts, Ruff, mypy, and pytest configuration;
- `src/pyahead/__init__.py`, `__main__.py`, and a minimal `--version` command;
- test package and one smoke test;
- `uv.lock`;
- CI for lint, typing, tests, and build;
- contribution and pull-request templates.

Acceptance:

```console
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src scripts
uv run pytest
uv build
uv run pyahead --version
```

All commands pass from a clean clone.

### M1 — Vertical static-analysis slice

Deliverables:

- `PythonMinor`, policy, location, diagnostic, rule, match, finding, and report models;
- registry loader for bundled YAML;
- one PEP 594 rule with direct, alias, and from-import matchers;
- LibCST parsing and exact import detection;
- text and JSON reports;
- exit codes 0–4;
- end-to-end fixtures and golden output.

Acceptance:

- direct, aliased, and from imports produce one high-confidence finding each;
- a local `cgi.py` candidate prevents a high-confidence stdlib classification and its competing path is exposed as inference evidence;
- a call or string that mentions `cgi` without importing it is not reported;
- files above 2 MiB and non-regular source entries produce bounded incomplete-analysis diagnostics without being parsed;
- line insertion does not change the fingerprint;
- invalid YAML exits 2;
- unparseable included source exits 3;
- JSON output is deterministic.

Qualified-reference and qualified-call shadowing remains an M2 acceptance
criterion. M1 cannot demonstrate call-binding shadowing without implementing the
M2 matcher framework, so its negative criterion is limited to the import syntax
that its matcher can emit.

### M2 — Registry and matcher framework

Deliverables:

- strict registry schema and generated JSON Schema;
- unique/stable ID validation;
- source and timeline validation;
- matcher index;
- `module-import`, `qualified-reference`, `qualified-call`, `call-shape`, and `literal-dynamic-import` matchers;
- whitelisted `builtin-pattern` dispatch;
- `registry validate`, `registry list`, and `explain` commands;
- registry authoring guide and fixture convention.

Acceptance:

- every matcher has alias, shadowing, ambiguous-name, positive, and negative tests;
- arbitrary callable paths in registry YAML are rejected;
- missing sources and invalid timelines are rejected;
- a rule can expose Ruff/pyupgrade automation metadata without invoking either tool;
- `pyahead explain CPY0001` works without scanning.

### M3 — Version timeline and reachability

Deliverables:

- event-to-state derivation;
- target set generation;
- release metadata loader;
- version-guard evaluator and lexical propagation;
- runtime-versus-typing usage-context propagation, including `TYPE_CHECKING` and `.pyi` files;
- grouped timeline console output;
- tests for every operator and Boolean combination.

Acceptance:

- a PEP 594 import guarded to `<3.13` is debt on 3.11–3.12 but not a blocker on 3.13+;
- unknown conditions enter both branches;
- nested and `elif` guards produce correct target sets;
- a runtime-only rule in a `TYPE_CHECKING` branch or `.pyi` file is not emitted as a runtime blocker;
- patch guards are diagnosed as unsupported/unknown rather than rounded;
- one finding represents its entire timeline.

### M4 — Project configuration and CI reports

Deliverables:

- strict `[tool.pyahead]` parsing;
- `requires-python` baseline inference with provenance;
- deterministic discovery, include/exclude, gitignore, and symlink policy;
- SARIF 2.1.0 output;
- baseline create/read;
- inline and per-file suppressions;
- gate semantics and `--fail-new-only`;
- atomic output-file writes.

Acceptance:

- CLI/config precedence has exhaustive tests;
- unknown config keys fail;
- SARIF validates and uses stable `ruleId`, relative paths, regions, and fingerprints;
- baseline line shifts do not create new findings;
- suppressions with unknown rule IDs produce diagnostics;
- machine output is never contaminated by progress messages.

### M5 — CPython registry curation

Deliverables:

- release records for the supported window;
- PEP 594 rules;
- rules for all selected, statically representable Python-level entries from released and pending-removal sources;
- coverage manifests for every selected authoritative source;
- fixtures for every implemented rule;
- documented partial and out-of-scope entries.

Acceptance:

- coverage command reports no unclassified source entries;
- every implemented entry maps to at least one rule and fixture;
- every rule has a negative fixture;
- all future schedule claims link to an authoritative source;
- a manual review finds no invented replacements or removal dates.

### M6 — Public-alpha hardening

Deliverables:

- complete user documentation;
- install smoke tests for wheel and sdist;
- supported-host CI matrix;
- changelog and release process;
- performance benchmark command or script;
- 100-repository corpus runner that stores only repository URL, commit, metrics, and findings required for review;
- false-positive review worksheet;
- security and privacy documentation.

Acceptance:

- Gate B passes;
- package installs and scans on Linux, macOS, and Windows;
- performance budgets are measured and regressions tracked;
- high-confidence precision sample is ready for Gate C review;
- README states limitations prominently.

### M7 — First dynamic evidence provider

Recommended first choice: pytest warnings, because it is immediately useful and executes only in the user's own CI.

Deliverables:

- versioned evidence JSON schema;
- pytest warning collector;
- `--evidence` ingestion;
- static/dynamic evidence merger;
- console and JSON distinction between inferred and observed evidence;
- CI example.

Acceptance:

- warning collection occurs in user CI;
- duplicate static and dynamic evidence is linked, not double counted;
- unmatched warnings remain visible;
- evidence from a different commit is rejected or visibly marked stale.

### M8 — Dependency compatibility

Deliverables:

- environment target model;
- application/library configuration;
- direct metadata inspection;
- isolated resolver adapter;
- `Requires-Python`, resolution failure, and artifact availability distinctions;
- explicit network and timeout controls.

Acceptance:

- no build backend executes during metadata inspection;
- offline mode is deterministic;
- a resolver timeout is incomplete evidence, not a compatibility failure;
- environment markers are evaluated against the declared target;
- results name the exact package versions and metadata used.

### M8.5 — 0.2 release hardening

This maintenance milestone implements the release-blocking findings from the
post-M8 architecture and maintainability review. It is deliberately split into
seven ordered, independently reviewed submilestones. Each submilestone receives
one intentional commit only after its targeted tests, the complete repository
suite, build and install checks, and a fresh read-only review pass. M8.5 does
not add another evidence provider or begin `0.3` browser-site work.

#### M8.5a — Rooted and bounded repository input

Deliverables:

- one private low-level rooted reader, extracted from the proven M8 dependency
  input implementation, for source, pytest evidence, configuration, baseline,
  and dependency inputs;
- POSIX reads anchored to a pinned root directory descriptor, with every
  ancestor opened relative to its predecessor, symlinks and non-regular leaves
  rejected, root/ancestor/leaf identities checked before and after reading,
  in-place mutation detection, and byte limits applied while reading;
- equivalent native Windows containment using pinned directory/file handles,
  reparse-point and alternate-data-stream rejection, and native swap tests;
- explicit documented byte limits for `pyproject.toml` and baseline documents,
  plus finite baseline finding-count and variable-text limits; and
- one selected `pyproject.toml` byte snapshot parsed once per scan and reused
  for both configuration and `Requires-Python` inference.

Acceptance:

- ancestor swaps, leaf replacement, in-place mutation, stable symlinks, and
  outside-root paths fail closed for every migrated reader;
- native Windows tests cover ancestor and reparse swaps without replacing the
  implementation with POSIX mocks;
- an input at each byte limit succeeds and limit plus one fails;
- oversized default and explicit configuration and oversized or over-count
  baselines fail concisely with no partial JSON or SARIF document; and
- dependency input retains all existing containment, mutation, size, relative
  path, deterministic-output, and exit-status behavior.

#### M8.5b — Pytest evidence completeness

Deliverables:

- `--pyahead-evidence` raises a clear `pytest.UsageError` when pytest warning
  capture is disabled or unavailable;
- ordinary `--disable-warnings` behavior and user warning-filter policy remain
  intact while complete capture is active;
- active pytest-xdist controller or worker execution is refused until a
  deliberate aggregation protocol exists; and
- `warnings_complete` is derived from proven capture and retention state, not
  merely from a zero dropped-record count. Pytest, conftests, plugins, and tests
  share one trusted process; the evidence artifact is not an anti-tamper
  attestation against repository-owner code running in that process.

Acceptance:

- integration tests cover `-p no:warnings` with a real warning,
  `--disable-warnings`, successful and failing sessions, record and byte
  truncation, warning-bearing xdist execution, and root-bounded atomic output;
- ordinary successful and failing non-xdist sessions still produce artifacts;
  and
- no incomplete warning observation is reported as complete.

#### M8.5c — Dependency compatibility semantics

Deliverables:

- `artifact_availability` describes only the supplied artifact sample: a
  wrong-target wheel may be `unavailable` and an sdist may be
  `source-build-possible` without proving repository-wide compatibility;
- partial direct application and library samples remain compatibility
  `unverified` unless inventory closure is independently established;
- complete `artifact-unavailable` is limited to a closed offline application
  wheelhouse proven by completed resolution over exact application pins; and
- schemas, documentation, golden data, and tests use the same status contract.

Acceptance:

- the scenario matrix covers direct wrong-target wheels, direct sdist-only
  samples, library samples, closed exact-pin inventories, a successful
  resolution selecting another artifact, missing package and version in a
  closed inventory, online index failure, timeout, and genuine constraint
  contradiction;
- exact final `Requires-Python` exclusions remain `declared-incompatible`;
- `resolution-failed` still requires reviewed resolver grammar plus an
  independently demonstrated active constraint contradiction;
- a complete negative result verifies only its corroborated root group, while
  unrelated incomplete roots or transitives retain exit-status precedence;
- the closed JSON Schema validates structure and status shapes, and the trusted
  model-to-document boundary separately recomputes cross-row root identity and
  PEP 440 contradiction semantics before machine output is emitted;
- timeouts, unsupported resolver evidence, unknown diagnostic grammar, and
  incomplete evidence remain incomplete and take exit-status precedence; and
- a real offline unsatisfiable-constraint regression runs against an explicitly
  controlled, reviewed `uv` series in CI.

#### M8.5d — Release smoke isolation

Deliverables:

- a documented explicit child-installer environment policy for
  `scripts/install_smoke.py`;
- ambient pip/uv indexes, extra indexes, configuration, caches, Python
  environments, and credential-bearing settings are removed; only deliberate
  platform execution variables and documented proxy policy are retained;
- online smoke uses its intended public source, while offline smoke installs
  only from allowed local artifacts and caches; and
- URL user-info and other credential-bearing material is redacted from child
  output, exceptions, and retained diagnostics.

Acceptance:

- sentinel pip/uv index, extra-index, and configuration values never reach the
  child installer;
- synthetic credential-bearing failures are redacted without inspecting real
  credentials; and
- online and offline wheel and sdist smoke retains Linux, macOS, and Windows
  launcher/path behavior.

#### M8.5e — Safe human output

Deliverables:

- one explicit terminal/log text-sanitization boundary applied to all untrusted
  human-readable source, evidence, diagnostic, inference, match, remediation,
  source, registry, quiet-mode, baseline, and dependency values;
- embedded newlines, terminal escapes, carriage returns, and dangerous Unicode
  control/separator categories are escaped while normal printable Unicode and
  renderer-owned structural newlines are preserved; and
- JSON and SARIF bytes remain unchanged unless their documented data contract
  itself requires a change.

Acceptance:

- negative fixtures cover filenames, registry text, and diagnostic data with
  newline, escape, carriage-return, and Unicode control/separator characters;
- no untrusted control data reaches human terminal or log output; and
- all machine-format golden and determinism tests remain byte stable.

#### M8.5f — Public machine and typing contracts

Deliverables:

- strict `docs/schema/report-v1.json` coverage for ordinary and empty reports,
  incomplete diagnostics, suppressions/baselines, analysis inferences, and
  optional M7 evidence enrichment;
- one deterministic source of truth with checked-in schema parity and
  representative/golden document validation;
- a packaged `py.typed` marker and documented narrow alpha import surface for
  the already named scan request/result and registry types, without exposing
  LibCST, parser, resolver, process, or automation internals;
- documented 0.x compatibility expectations and an installed-wheel consumer
  mypy test proving supported return types are not `Any`; and
- package Documentation metadata points to the user-facing usage guide.

Acceptance:

- required properties and `additionalProperties: false` close every report
  schema object except the two specifically documented extensibility points,
  `evidenceMap` and `configuration.per_file_ignores`, whose key spaces are owned
  by matchers and by the scanned project rather than by the schema;
- generated and checked-in schemas are identical and every representative and
  golden report validates;
- wheel and sdist contain the intended schema/typing artifacts, and a clean
  installed-wheel consumer passes strict mypy; and
- compatibility exports such as `render_evidence_schema`,
  `project_module_names`, and existing accessors remain until a separate public
  API decision proves removal safe.

#### M8.5g — Small behavior-preserving cleanup

Deliverables:

- quiet rendering computes the final result line directly while preserving its
  exact bytes;
- identical evidence artifacts retain the lexicographically smallest
  repository-relative representative independent of argument order;
- canonical strict mypy checks cover `src` and `scripts`, without lowering or
  repurposing the 90% product coverage threshold or inventing an unmeasured
  script threshold;
- contributor setup uses `uv sync --frozen`; and
- this design's repository map, actual runtime dependencies, provider-specific
  evidence architecture, and separate `DependencyReport` boundary describe the
  implementation that exists.

Acceptance:

- quiet output is byte-identical and does not render discarded detail;
- evidence representative selection passes argument-permutation tests;
- the complete strict `mypy src scripts` check passes before CI is changed;
- benchmark regression JSON reports `passed=true`, while unmet design targets
  remain separately visible; and
- no impact-order change, speculative optimization, large-module split, broad
  test reorganization, unused compatibility-symbol removal, generic provider or
  dependency-injection framework, parallel scan, browser-site code, or M10
  work is included.

### M10 — C API roadmap

Use CPython expertise as a differentiator only after the Python-source product is proven.

Investigate:

- C symbol removals and deprecations;
- limited API versus non-limited API distinctions;
- Stable ABI implications;
- `pythoncapi-compat` guidance;
- compile-database integration;
- Clang-based matching;
- Cython-generated source exclusions.

This milestone requires its own design document before implementation.

---

## 26. Codex implementation protocol

### 26.5 Historical initial prompt

Use this prompt against <https://github.com/diegorusso/pyahead>:

```text
Implement milestone M0 (Repository bootstrap) from docs/design.md in the
diegorusso/pyahead repository.

Treat docs/design.md as the implementation contract. First inspect the current
repository and restate the M0 acceptance criteria. Then implement only M0.

Requirements:
- Use a Python src layout and Python >=3.11.
- Use uv for the development lockfile and Hatchling (or another justified,
  standards-compatible backend) for packaging.
- Configure Ruff, strict mypy, pytest, coverage, and GitHub Actions.
- Add a concise AGENTS.md that points Codex to docs/design.md, records the
  verification commands, and forbids opportunistic later-milestone work.
- Add the minimal pyahead --version entry point and smoke test.
- Do not implement the analyser or registry engine yet.
- Keep runtime dependencies aligned with docs/design.md; do not add unused
  dependencies merely as placeholders.
- Run every command listed in M0 acceptance, build both wheel and sdist, install
  the wheel in a clean environment, and report exact results.
- Review the final diff for generated files, secrets, absolute paths, and
  unrelated changes.

If the repository is still empty and docs/design.md is not present, add the
provided design document first. Do not weaken an acceptance criterion to make
the checks pass; explain and fix the underlying problem.
```

### 26.6 Subsequent milestone prompt template

```text
Implement milestone M<N> from docs/design.md in diegorusso/pyahead.

Before editing:
1. Read the complete design and current project instructions.
2. Inspect all code delivered by earlier milestones.
3. Restate M<N>'s deliverables and acceptance criteria.
4. Identify any mismatch between the design and current code.

Implement only the smallest coherent change that satisfies M<N>. Preserve the
public contracts already established. Add unit, integration, fixture, and
golden tests required by the milestone. Run the complete repository test,
lint, format, type-check, and build suite, not only new tests. Inspect the final
diff and update the design in the same change if a justified decision differs.

Finish with:
- files and behaviour changed;
- acceptance criteria demonstrated;
- exact commands and results;
- known limitations that belong to later milestones;
- the recommended next milestone, without implementing it.
```

### 26.7 Review prompt after each milestone

Run a separate review before merging:

```text
Review the current branch against milestone M<N> in docs/design.md. Do not make
changes yet. Look specifically for incorrect compatibility semantics, false
positive risks, nondeterministic output, unsafe repository handling, missing
negative fixtures, schema drift, and acceptance criteria that were asserted but
not demonstrated. Rank findings by severity with file and line references. If
there are no findings, say so and list the verification evidence you inspected.
```

Only ask Codex to fix the concrete review findings after reading the review.
