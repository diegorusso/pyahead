# Changelog

All notable user-visible changes are recorded here. PyAhead follows Semantic
Versioning, including prerelease identifiers while public contracts are still
stabilizing.

## Unreleased

### Changed

- The registry analysis window now opens at Python 3.8 instead of 3.11, so a
  codebase on 3.8, 3.9 or 3.10 can be scanned on its way forward. Release
  metadata gains 3.8 and 3.9 as end-of-life and 3.10 as security-only; the
  registry label is `2026.09.17`.

  This changes inferred policy for projects that never set a baseline: a
  `requires-python = ">=3.8"` project previously inferred 3.11, the lowest the
  registry admitted, and now infers 3.8. Findings whose events fall between 3.8
  and 3.11 become reachable for such projects, and `reachable_versions` widens
  to match. Set `baseline-python` explicitly to keep the old policy.

  Coverage is not uniform across the wider window. The registry was curated
  for changes landing in 3.11 and later and carries only a handful of events
  between 3.8 and 3.10; `docs/usage.md` says so where the window is described.

## 0.2.2 - 2026-09-16

A performance fix with no public contract changes.

### Fixed

- The bundled registry is now read once per process instead of once per scan.
  Reading it costs about 0.6 seconds, which nobody noticed in a one-shot
  `pyahead check` and which was almost the entire cost of a repeated scan: four
  scans in one process went from 0.62 seconds each to 0.62 and then 0.026. This
  matters wherever the analyser is called more than once in a process, and most
  sharply under WebAssembly, where re-parsing the registry dominated everything
  the analyser actually had to do. A registry named explicitly with
  `--registry` is still read every time, because a path names a file that can
  change.

## 0.2.1 - 2026-09-13

Precision fixes found by adjudicating the PyPI top-1000 against real
interpreters. No public contract changes.

### Fixed

- `sys.version_info[0]` compared against an integer, the Python 2/3 split
  such as `if sys.version_info[0] < 3:`, is now evaluated as a version guard,
  so a Python-2-only branch no longer produces findings for Python 3 targets.
- The annotation of a local variable inside a function body, which Python
  never evaluates or stores, is now a typing-only reference, so runtime-only
  rules no longer report it. Parameter, return, class-body and module-level
  annotations are unchanged, including under
  `from __future__ import annotations`, because runtime introspection such
  as `typing.get_type_hints` still evaluates them. Both fixes come from the
  runtime adjudication of the PyPI top-1000 recorded in
  `docs/evidence/pypi-top-1000.md`.

## 0.2.0 - 2026-09-01

First public-alpha release. It carries the evidence providers that
`docs/design.md` §4.3 assigns to `0.2`: opt-in pytest deprecation-warning
evidence and opt-in dependency metadata and resolver evidence. No `0.1.0`
release was published; the `0.1.0a2` candidate is superseded by this version.

### Added

- A closed static-report JSON Schema, packaged schema resource, `py.typed`
  marker, and documented narrow public Python API with installed-wheel strict
  mypy verification.
- Opt-in dependency compatibility reports with declared environment targets,
  separate application and library semantics, direct build-free wheel/sdist
  metadata inspection, target marker evaluation, `Requires-Python` and wheel
  availability distinctions, and an isolated `uv` adapter with explicit
  offline, network, index, and timeout controls. Wheel structure, direct URL,
  coherent-target, and complete transitive-dependency evidence fail closed;
  closed-wheelhouse artifact absence remains distinct from proven constraint
  conflicts and operational index failures. Direct application and library
  samples retain precise artifact availability but remain incomplete
  compatibility evidence until resolution closes the inventory, except that an
  exact, final `Requires-Python` exclusion remains declared incompatible;
  resolver-selected extras require exact `Provides-Extra` provenance. Nested
  dependency extras reach a fixed point, and
  archive member, shared expanded-data, and decoder limits are enforced before
  unbounded object creation, decompression, or LZMA dictionary allocation.
  Dependency evaluation and correlation share a bounded work budget, and public
  metadata records must preserve exact container identity. Target-selected
  metadata now exclusively supplies extras and dependency edges; conflicting
  artifact declarations, ambiguous local-version pins, unreachable resolver
  packages, legacy source-metadata dynamism, malformed markers, impossible
  target versions, resolver output, aggregate metadata, and sdist identity
  boundaries fail closed as invalid input or explicit incomplete evidence, as
  appropriate.
- Versioned pytest deprecation-warning evidence, explicit user-CI collection,
  commit-aware ingestion, subject/timeline-aware static/observed relationships,
  explicit per-artifact and aggregate resource limits, indexed relationship
  processing, bounded collection-time warning retention, incremental artifact
  sizing, and visible unmatched, conflicting, or stale observations in text and
  JSON reports.
- Deterministic repository discovery, Python-version reachability, strict
  configuration, baselines, rule-specific suppressions, JSON, and SARIF 2.1.0.
- A source-linked CPython registry with explicit coverage manifests and
  positive and negative fixtures for implemented rules.
- A Linux, macOS, and Windows CI matrix for Python 3.11 through 3.14, plus an
  advisory Python 3.15 prerelease job.
- Isolated wheel and sdist install-and-scan smoke tests.
- Checked performance budgets and a synthetic benchmark command.
- A privacy-minimal 100-repository corpus runner and deterministic
  high-confidence false-positive review worksheet.
- Complete user, release, security, privacy, and corpus-review documentation.
- The first end-to-end static-analysis slice, including exact module imports,
  deterministic text and JSON findings, bounded discovery, and stable exits.
- Initial package, command-line entry point, locked development environment,
  quality policy, build configuration, and CI.

### Changed

- The package maturity classifier is now Alpha.
- Gate C now uses accountable review of reproducible public-corpus precision
  evidence; continuous-use adoption is measured after public distribution.
- Exact `sys.path` mutation ambiguity and removal-safe `hasattr` short circuits
  no longer produce high-confidence post-removal blockers.
- Corpus scan and read-only Git verification subprocesses have separate,
  configurable finite timeouts.
- Release install smoke tests now use one explicit run-local child environment,
  resolve online only from public PyPI, and exercise wheel and sdist installation
  from an explicit operator-selected uv cache on every supported hosted
  operating system. CI creates a fresh cache, populates it through the online
  public-PyPI smokes, and then reuses it for offline evidence.

### Removed

- The milestone controller and its development automation: `scripts/autopilot.py`,
  `automation/`, `docs/autopilot.md`, and the offline controller test suite. The
  source distribution no longer ships the `automation/` tree. Milestone rules,
  protected paths, quality-policy tables, and the Gate C approval requirement are
  retained as prose in `AGENTS.md` and `docs/design.md`.

### Fixed

- Root-bounded Windows input now reports absent, access-denied, and
  non-directory paths as the corresponding standard `FileNotFoundError`,
  `PermissionError`, and `NotADirectoryError`, instead of a generic NTSTATUS
  `OSError`. Optional configuration, baselines, and evidence are no longer
  misreported as unreadable when they are simply absent.

### Security

- Documented offline scan, no-telemetry, no-target-execution, filesystem, and
  corpus-data boundaries.
- Human-readable reports, CLI diagnostics, registry and dependency presentation,
  and project maintenance logs now escape untrusted terminal controls, embedded
  line breaks, and dangerous Unicode separators while preserving printable
  Unicode and deterministic machine formats.
- Root-bounded Windows output creation and replacement stays anchored to opened
  non-reparse directory handles and fails closed if those APIs are unavailable.
- Corpus review worksheets carry and verify the exact result digest so a
  partially published pair cannot be mistaken for matching Gate C evidence.
- Corpus review worksheets quote repository-derived `path`, `subject`, and
  `match_kind` values so a scanned file name cannot become a live formula in a
  reviewer's spreadsheet, and reject an unescaped one when a reviewed worksheet
  is read back. Reviewer prose columns stay free text.
- Release smoke children no longer inherit ambient installer configuration,
  caches, proxies, Python environments, or credentials, and retained failure
  diagnostics redact common credential forms before truncation.

Release headings, dates, and comparison links are added only after their
immutable tags exist.
