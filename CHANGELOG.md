# Changelog

All notable user-visible changes are recorded here. PyAhead follows Semantic
Versioning, including prerelease identifiers while public contracts are still
stabilizing.

## Unreleased

### Changed

- `--evidence` files are checked against the published
  `docs/schema/evidence-v1.json` itself (with `jsonschema`, now a runtime
  dependency) before they are read, instead of by a parallel hand-written
  parser. Valid evidence is read exactly as before. An invalid file is still
  rejected, with a message naming the field and the rule it breaks, for
  example `evidence document.warnings[0].location.path: has an invalid
  format`; the wording of these messages differs from 0.6.0.

### Fixed

- One Python file whose dedent matched no outer indentation level (for
  example `if x:` / `    a = 1` / `  b = 2`) aborted the whole scan with
  `PYA9000` (exit 4). It is now that file's `PYA1003` parse diagnostic and an
  incomplete scan (exit 3), and every other file is still analysed.
- A `--registry` file containing a control character such as `\x07` was an
  internal error (`PYA9000`, exit 4) when PyYAML ran without libyaml; it is
  now invalid input naming the file (exit 2), like every other malformed
  registry YAML.

## 0.6.0 - 2026-10-11

The repository becomes a GitHub Action that uploads findings to code
scanning, and `pyahead dependencies` reads uv 0.12.18's resolver output. A
minor release because the Action is a new public interface; the registry is
the one 0.5.0 shipped (`2026.10.10`, `fa9db725e612`), so the 10 October
precision record still describes it.

### Added

- The repository is a GitHub Action (`action.yml`):
  `uses: diegorusso/pyahead@v<version>` installs that PyAhead release, scans,
  uploads SARIF to code scanning, and then applies the `fail-on` gate, so
  findings reach code scanning even when they fail the job. Inputs mirror the
  command line; outputs are `exit-code` and `sarif-file`. A self-test workflow
  runs it from source against the golden project.

### Fixed

- `pyahead dependencies` with `uv` 0.12.18: a dependency conflict or a closed
  offline artifact absence was reported as incomplete evidence (exit 3)
  instead of `resolution-failed` or `artifact-unavailable`. Later 0.12
  releases print the solver proof under a plain `error: … / cause: …` header
  rather than `× … / ╰─▶ …`; the proof sentences are unchanged and PyAhead now
  reads both spellings. Closed artifact absence is accepted from `uv` 0.11.21
  and 0.12.18 exactly; any other version stays unverified.

## 0.5.0 - 2026-10-10

Python 3.15.0 was released on 9 October 2026. The registry records it as a
stable release and its "What's New" Deprecated and Removed sections are
censused; 3.16 is now the release in development. Registry label `2026.10.10`.
A minor release: new rules, an analyser change (import-fallback
reachability) and a new default horizon; no public contract changes.
Precision was measured against the PyPI top 1000 and is recorded in
`docs/evidence/pypi-top-1000-2026-10-10.md`: 99.66% agreement, up from
98.49%, with every `except ImportError` refutation of the earlier records
gone.

### Changed

- The inferred default horizon is now Python 3.16, the release in active
  development, as design §8 prescribes; it was 3.15 while 3.15 was the
  prerelease. Projects that set `horizon-python` are unaffected.
- The fifteen rules whose 3.15 removal or signature change was scheduled now
  record it as released.
- `CPY0135` (`types.CodeType.co_lnotab`) gains its removal: deprecated in 3.10
  by PEP 626, removed in 3.15. Findings that were deprecation debt now become
  breaking from 3.15.

### Added

- Seven rules from the Python 3.15 "What's New" (CPY0205–CPY0211): the
  `profile` module (removal in 3.17, outside the window); `webbrowser.MacOSXOSAScript`
  (3.17); `http.cookies` `js_output` (3.19); the `string=` keyword of the
  `hashlib` constructors (3.19); instantiating abstract AST node classes such as
  `ast.AST()` (an error from 3.20); the `__version__`, `version` and `VERSION`
  attributes of twenty-three standard-library modules and `logging.__date__`
  (3.20); and the `package=` keyword of `importlib.resources.files()`,
  deprecated by the 3.12 rename to `anchor` and removed in 3.15. Each was
  checked against a 3.15 interpreter, which warns or refuses exactly where the
  rule reports. Both 3.15 sections are censused — 20 removals and 43
  deprecation entries; `re.match`'s soft deprecation is recorded as not
  applicable because CPython advises code supporting older versions to keep
  using it.
- `cProfile.Profile` is in the known-import table, so `try: from cProfile
  import Profile` / `except ImportError: from profile import Profile` reports
  nothing.
- Import-fallback reachability. When a `try` body is absolute imports,
  optionally followed by assignments that only read what they bound
  (`ATOMIC_GROUP = sre.ATOMIC_GROUP`), and every import is in the new
  known-import table
  (`pyahead.analysis.known_imports`: standard-library modules and attributes
  present on every platform and in every CPython build, with the minor each
  arrived in), an `except ImportError` / `except ModuleNotFoundError` handler
  is unreachable on the targets that have them all. `try: import threading` /
  `except ImportError: import dummy_threading` reports nothing; `try: import
  zoneinfo` keeps its handler on 3.8 alone. Every refuted row of the September
  and 17 September PyPI sweeps that was an `except ImportError` fallback —
  `_imp`/`imp`, `sysconfig`/`distutils`, `re._constants`/`sre_constants`,
  `threading`/`dummy_threading` — now reports nothing, and each is a regression
  test. Narrowed findings carry `reachability_guard=import-fallback`; anything
  outside the exact shape changes nothing (design §11).

## 0.4.0 - 2026-09-21

A caller running a long scan can now follow it file by file. A minor release
because the public scan API grows an optional field; nothing existing changes
behaviour, and the report schema is untouched.

### Added

- `ScanRequest.on_file`, an optional callback `scan()` invokes once per parsed
  file with a `FileProgress` (repository-relative path, one-based index, total
  files being parsed, and whether the file was incomplete), so a caller running
  a long scan can show progress. It receives no findings and cannot alter the
  scan, and a scan without it pays one skipped branch per file. No command-line
  option sets it; a caller that embeds the CLI — the browser page — passes it
  as `pyahead.cli.main(argv, on_file=...)`, which `check` hands to the scan.

## 0.3.1 - 2026-09-21

Every rule now cites the change at the version it happened, so a finding's
documentation link lands where the deprecation was announced and its source
list says where the deprecation and the removal each came from. A patch
release: registry data and documentation only; no detection or contract
changes.

### Changed

- The sources of all 198 rules were re-derived from the fetched CPython pages.
  Each timeline event cites the section of its own version's "What's New"
  that names the subject, or the subject's entry in the module reference of
  the version that made the change, or — for a deprecation older than both —
  the later "What's New" bullet that states the version; scheduled events
  cite the deprecating version's "Pending removal in Python 3.N" section.
  Before this, 68 rules linked the removal's page for a deprecation, 39 linked
  a 3.14 module reference for a change made in 3.6–3.10 (the `ssl` constants
  among them), and 41 linked `3.13.html#removed`, an anchor the 3.13 page no
  longer has. `documentation_url` is now the deprecation event's source and is
  always one of the rule's cited sources; `CPY0001` gains the link it lacked.
  All 90 distinct URLs resolve and every anchor exists. The convention is in
  `docs/registry-authoring.md` and enforced by the test suite. Registry label
  `2026.09.20`.

### Added

- Eleven rules from the "What's New in Python 3.11" sections (CPY0194–CPY0204):
  the `@asyncio.coroutine` decorator; the bytes-returning `gettext` API —
  `lgettext`, `ldgettext`, `lngettext`, `ldngettext`, `bind_textdomain_codeset`,
  and the `codeset` keyword of `translation()` and `install()`; and
  `inspect.getargspec`, `inspect.formatargspec`, `inspect.Signature.from_builtin`
  and `from_function`. All removed in 3.11. `CPY0036` additionally matches the
  module-level `turtle.settiltangle`. Both 3.11 sections are censused — 66 and
  22 entries — which closes the last gap between 3.9 and 3.14; most of the
  Deprecated section is the page re-listing 3.10 deprecations already covered,
  and two of its entries, `locale.getdefaultlocale` and the `importlib.resources`
  legacy functions, were later un-deprecated by CPython and are recorded as such.

## 0.3.0 - 2026-09-19

The registry analysis window opens at Python 3.8, and the Python 3.9 and 3.10
"What's New" sections are curated. A minor release because inferred policy
changes for projects declaring a floor below 3.11; no public contract
changes. Precision on the new rules was measured against the PyPI top 1000
and is recorded in `docs/evidence/pypi-top-1000-2026-09-17.md`.

### Added

- Twenty-eight rules for the Python 3.10 removals, censused from the
  "What's New in Python 3.10 — Removed" section: the `parser` and `formatter`
  modules (CPY0138, CPY0139); the `loop` parameter removed from eighteen
  `asyncio` high-level signatures (CPY0140), one call-shape matcher per
  signature the 3.10 documentation marks, with `asyncio.Future` and
  `asyncio.Task` deliberately unmatched because they kept it; and the
  twenty-five `collections` aliases of `collections.abc` classes
  (CPY0141–CPY0165), deprecated since 3.3, one rule per alias so a finding's
  headline names the alias actually used. `collections.ByteString` (CPY0165)
  does not recommend `collections.abc.ByteString`, which is deprecated in
  3.12 in turn.
- Seventeen rules for the Python 3.9 removals, censused from the "What's New
  in Python 3.9 — Removed" section (CPY0166–CPY0184, with CPY0169 and
  CPY0170 retired): `sys.callstats`, `sys.getcheckinterval` and
  `setcheckinterval`; `wave.openfp`; the old `plistlib` API —
  `readPlist`, `writePlist`, `readPlistFromBytes`, `writePlistToBytes`,
  `Data`, and the `use_builtin_types` keyword of `load` and `loads`;
  `base64.encodestring` and `decodestring`; `fractions.gcd`; the `buffering`
  keyword of `bz2.BZ2File` (keyword form only; a positional third argument is
  not claimed); the `encoding` keyword of `json.loads`; and
  `asyncio.Task.current_task` and `all_tasks`. `aifc.openfp` and
  `sunau.openfp` have no rule of their own: any use of them already reports
  the removal of those modules in 3.13, so their census entry is partial and
  says so. The instance-method removals on that page — `Thread.isAlive`,
  `array.tostring`, `Element.getchildren`, `HTMLParser.unescape` and the
  rest — are recorded as not statically detectable rather than guessed at.
  Rules for `dummy_threading` and `_dummy_thread` were written and then
  retired the same day: the top-1000 sweep refuted every one of their eleven
  adjudicable findings, because those modules only ever existed to be the
  `except ImportError` fallback and every real reference to them is dead code
  on Python 3. Their census entry records that with the packages it was seen
  in.
- Nine rules from the "What's New in Python 3.9 — Deprecated" and "3.10 —
  Deprecated" sections (CPY0185–CPY0193): the `symbol` module, removed in
  3.10 with the old parser; the `binhex` module and the four `binascii` hqx
  functions, removed in 3.11; `ast.Index` and `ast.ExtSlice`, deprecated in
  3.9 and still importable at 3.14 with no removal scheduled; and the
  `random` parameter of `random.shuffle`, removed in 3.11, detected both as a
  keyword and as a second positional argument since `shuffle` never took
  another. Both pages are fully censused — 19 and 36 entries — and most of the
  3.10 page turns out to be already covered by the rules for the 3.11 and
  3.12 removals that followed, which the census now records as duplicates of
  those rules rather than leaving implicit.

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
