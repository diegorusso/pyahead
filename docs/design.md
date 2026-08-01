# PyAhead: Product and Technical Design

- **Status:** Implementation specification
- **Document version:** 1.0
- **Date:** 31 July 2026
- **Repository:** <https://github.com/diegorusso/pyahead>
- **Repository state at design time:** Private, empty, default branch `main`
- **Initial implementation language:** Python

This document is the implementation contract for PyAhead. It is intentionally detailed enough for Codex to implement the project in small, independently verifiable milestones. When an implementation choice conflicts with this document, either update this document in the same change with a written rationale or treat the conflict as a bug.

---

## 1. Executive summary

PyAhead is a repository-level Python compatibility forecaster.

Its core question is:

> Given the oldest Python version this repository supports, what known deprecations, removals, signature changes, behaviour changes, dependency constraints, and observed failures affect it in each subsequent Python version?

The initial command-line experience is:

```console
$ pyahead check . --baseline-python 3.11 --horizon-python 3.16

PyAhead 0.1.0
Policy: Python 3.11 through 3.16
Registry: 2026.07.31 (8e8128d)

Python 3.13 — 1 upgrade blocker
  CPY0001  src/legacy.py:4  import cgi
           Deprecated in 3.11; removed in 3.13.
           Confidence: high (exact imported module)
           Guidance: replace the required cgi functionality; no single drop-in
           replacement exists.

Python 3.16 — 1 planned migration
  CPY0042  src/events.py:19  asyncio.get_event_loop_policy()
           Deprecated; scheduled for removal in 3.16.
           Confidence: high (exact qualified call)
           Guidance: use asyncio.run() or asyncio.Runner with loop_factory.

Result: 1 blocker, 1 planned migration, 0 incomplete files
```

PyAhead is not a modernisation tool and should not duplicate pyupgrade or Ruff. Its product boundary is:

- **PyAhead:** identify what is known to become deprecated or incompatible, in which Python version, why it matters, and where the repository is affected.
- **Ruff/pyupgrade:** perform existing safe source transformations when available.
- **Tests on real interpreters:** establish executed compatibility for the paths covered by the tests.

PyAhead should link to an existing Ruff or pyupgrade fix when one exists. It should not build a general rewriting engine in its first releases.

The product consists of three layers, delivered in this order:

1. An open-source deterministic analyser and CLI.
2. A reviewed, versioned compatibility registry.
3. A hosted GitHub App that continuously rescans repositories and reports only newly introduced or newly known risks.

The first implementation phase covers layers 1 and 2. The hosted service must not be built until the CLI passes the validation gates in section 22.

### 1.1 Why now

As of this document, Python 3.15 is at beta 4, release candidate 1 is expected on 4 August 2026, and the final release is expected on 1 October 2026. That provides a concrete launch story: scan repositories that still support Python 3.11 or later and show their upgrade path through Python 3.15 and beyond. The schedule is contextual, not a hard-coded product assumption; release status belongs in versioned registry data.

### 1.2 Product promise

The public promise should be precise:

> PyAhead shows a repository's evidence-backed compatibility timeline across known Python releases.

It must not promise to predict arbitrary future breakage. A clean report must say:

> No known issues were detected through Python 3.16 using registry revision X. This is not proof of compatibility; run the project test suite on each target interpreter as well.

### 1.3 Initial audience

The initial audience is maintainers of actively developed Python applications and libraries that:

- support more than one Python minor version;
- upgrade Python deliberately rather than immediately;
- want advance notice of work required by the next release;
- use GitHub and CI; and
- value an auditable source for every warning.

Open-source maintainers are the adoption path. Private repositories and organisation-level reporting are the commercial path.

---

## 2. Goals and non-goals

### 2.1 Goals

The first public alpha must:

1. Analyse Python source without importing or executing the target repository.
2. Accept an inclusive baseline-to-horizon range of Python minor versions.
3. Find high-confidence uses of registry-described CPython APIs and constructs.
4. Understand common import aliases and ordinary lexical shadowing.
5. Understand common `sys.version_info` guards well enough not to flag unreachable compatibility branches as blockers.
6. Produce one finding with a version timeline, not duplicate warnings for every affected version.
7. Keep impact, matcher confidence, and registry certainty as separate dimensions.
8. Produce deterministic console, JSON, and SARIF 2.1.0 output.
9. Support configuration in `pyproject.toml`, baselines, and explicit suppressions.
10. Give every finding an authoritative source and stable rule ID.
11. Expose the coverage limits of the registry rather than implying completeness.
12. Run fully offline by default and perform no telemetry.
13. Be installable as a normal Python package and runnable with `pipx` or `uvx`.

### 2.2 Longer-term goals

After the static analyser proves useful, PyAhead should add:

- dependency compatibility checks based on `Requires-Python`, lockfiles, and isolated resolution;
- PEP 702 deprecation evidence from type checkers and installed type metadata;
- normalized runtime-warning evidence from tests;
- test and import probes on actual target interpreters in customer CI;
- C API compatibility rules;
- a hosted GitHub App with check runs, history, triage, and registry-triggered rescans;
- organisation-wide compatibility views.

### 2.3 Non-goals for the first public alpha

The first public alpha does not:

- prove that a repository is compatible with a Python version;
- execute repository code;
- install repository dependencies;
- resolve arbitrary dynamic imports or reflection;
- infer general Python types;
- comprehensively interpret prose release notes with an LLM;
- cover every PyPI package;
- analyse C extensions;
- generate pull requests or automatic fixes;
- replace a test matrix, type checker, Ruff, or pyupgrade;
- expose a plugin API that runs untrusted rule code;
- require a hosted account or network access.

---

## 3. Product vocabulary and invariants

These terms must be used consistently in code, output, and documentation.

| Term | Definition |
| --- | --- |
| **Host Python** | The interpreter running PyAhead. It is independent of the repository's supported versions. |
| **Baseline Python** | The oldest Python minor release the repository claims to support. Inclusive. |
| **Horizon Python** | The newest Python minor release the user wants assessed. Inclusive. |
| **Target set** | Every Python minor version from baseline through horizon, unless an explicit non-contiguous set is supported in a later release. |
| **Registry** | Reviewed facts about Python compatibility changes and how they can be detected. |
| **Rule** | A stable registry record describing one compatibility concern, its timeline, matchers, sources, and remediation. |
| **Change event** | A deprecation, removal, signature change, behaviour change, syntax change, or support drop at a Python version. |
| **Match** | Static evidence that a source construct corresponds to a rule's subject. |
| **Finding** | A repository-specific match combined with its reachable target versions and rule timeline. |
| **Impact** | What happens if the affected code executes: deprecation debt, compatibility risk, or breakage. |
| **Match confidence** | How strongly source analysis identified the affected object. |
| **Registry certainty** | How authoritative and settled the scheduled change is. |
| **Observed evidence** | Evidence produced by an actual interpreter, resolver, warning, import, or test run. This arrives after the static alpha. |

The following invariants are non-negotiable:

1. A rule ID is never reused for a different concern.
2. A finding always identifies the registry revision that produced it.
3. A finding never loses its authoritative source in a formatter.
4. `impact`, `match_confidence`, and `registry_certainty` are never collapsed into one ambiguous “severity” value in the internal model.
5. Static absence of findings is never represented as proof of compatibility.
6. The default scan never executes code, imports the target repository, installs dependencies, or accesses the network.
7. Repository-relative paths are used in all persistent and machine-readable output.
8. The same source, configuration, tool version, and registry revision produce byte-for-byte identical JSON and SARIF.
9. A partially completed scan is not silently treated as a successful clean scan.
10. Inference is always shown with its source and can always be overridden.

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
- PEP 702/type-checker evidence;
- pytest warning collection;
- actual-interpreter compile/import/test probe ingestion;
- evidence merging and conflict handling.

### 4.4 `0.3`: hosted private beta

Add:

- GitHub App installation;
- scans on push and pull request;
- GitHub Check annotations;
- dashboard, history, and triage;
- registry-triggered rescans;
- strict source-retention and isolation controls.

### 4.5 `1.0`

`1.0` requires a stable registry schema, stable JSON output schema, documented compatibility guarantees, proven low false-positive rates, and at least one complete end-to-end dynamic evidence path.

---

## 5. User journeys

### 5.1 First local scan

```console
uvx pyahead check . --baseline-python 3.11 --horizon-python 3.16
```

Expected flow:

1. Locate the repository root.
2. Load explicit CLI policy.
3. Discover eligible Python files.
4. Load and validate the bundled registry.
5. Analyse every file.
6. Merge duplicate matches into findings.
7. Render the compatibility timeline.
8. Exit according to the configured gate.

The command must print the effective policy and registry revision before findings.

### 5.2 Configured repository

```toml
[tool.pyahead]
baseline-python = "3.11"
horizon-python = "3.16"
include = ["src/**/*.py", "tests/**/*.py"]
exclude = ["src/generated/**"]
source-roots = ["src"]
minimum-confidence = "high"
fail-on = "breaking"
show-unscheduled = true
respect-gitignore = true
```

Then:

```console
pyahead check
```

### 5.3 CI scan with SARIF

```console
pyahead check --format sarif --output pyahead.sarif
```

The SARIF file is valid independently of GitHub. Upload availability depends on the repository and GitHub plan. PyAhead must not assume that code scanning is enabled.

### 5.4 Existing repository adopting a baseline

```console
pyahead baseline create --output .pyahead-baseline.json
git add .pyahead-baseline.json
```

Subsequent scans can report all findings while failing CI only for new fingerprints:

```console
pyahead check --baseline-file .pyahead-baseline.json --fail-new-only
```

### 5.5 Explaining a rule

```console
pyahead explain CPY0001
```

This prints the full timeline, matcher types, remediation, sources, registry certainty, and examples without scanning a repository.

### 5.6 Hosted service

1. Install the GitHub App on selected repositories.
2. Confirm or override inferred Python policy.
3. Receive a check run on the default branch and pull requests.
4. See only newly introduced findings on a pull request.
5. Receive a new scan when a registry update adds or changes a relevant rule, even if repository code has not changed.

That final behaviour is a principal reason for the hosted product to exist.

---

## 6. Repository layout

The empty repository should begin as one Python package and one in-tree registry. Do not create the Django service, a JavaScript frontend, or multiple repositories during the CLI milestones.

```text
pyahead/
├── AGENTS.md                       # concise Codex working contract
├── automation/                     # M1.5 development policy (not product code)
│   ├── milestones.toml
│   ├── prompts/
│   └── schemas/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── pull_request_template.md
│   └── workflows/
│       ├── ci.yml
│       └── release.yml              # added only when publishing starts
├── docs/
│   ├── autopilot.md                # milestone-controller operations and safety
│   ├── design.md                    # this document
│   ├── registry-authoring.md
│   └── contributing.md
├── src/
│   └── pyahead/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── diagnostics.py
│       ├── versions.py
│       ├── project.py
│       ├── model.py
│       ├── analysis/
│       │   ├── __init__.py
│       │   ├── engine.py
│       │   ├── discovery.py
│       │   ├── names.py
│       │   ├── reachability.py
│       │   ├── suppressions.py
│       │   └── matchers/
│       │       ├── base.py
│       │       ├── imports.py
│       │       ├── qualified.py
│       │       ├── calls.py
│       │       └── builtins.py
│       ├── registry/
│       │   ├── loader.py
│       │   ├── model.py
│       │   ├── validation.py
│       │   └── coverage.py
│       ├── reporting/
│       │   ├── console.py
│       │   ├── json.py
│       │   └── sarif.py
│       └── data/
│           └── registry/
│               ├── releases.yaml
│               ├── cpython/
│               │   └── *.yaml
│               └── coverage/
│                   └── *.yaml
├── tests/
│   ├── automation/                 # offline fake-service controller tests
│   ├── unit/
│   ├── integration/
│   ├── golden/
│   └── fixtures/
│       └── rules/
├── scripts/
│   └── autopilot.py                # M1.5 parent-owned controller
├── CHANGELOG.md
├── LICENSE
├── README.md
├── pyproject.toml
└── uv.lock
```

### 6.1 Packaging decisions

- Use a `src` layout.
- Require Python 3.11 or newer to run PyAhead initially.
- Target versions are independent of the host version.
- Use `uv` for development environment and lockfile management.
- Use a standards-compatible build backend such as Hatchling. Do not make installation of PyAhead depend on the user having `uv`.
- Expose the console script `pyahead = pyahead.cli:main`.
- Package registry YAML under `pyahead.data` and load it through `importlib.resources`.
- Use semantic versioning for the CLI and an independent content revision for the registry.
- Recommended licence for the open CLI and registry: Apache-2.0. Confirm before the first public release.
- Keep the eventual proprietary hosted service in a separate private repository that consumes the published core package. Do not place service code under the core repository's open-source licence by accident.

### 6.2 Initial dependencies

Runtime dependencies should remain small and purposeful:

| Dependency | Purpose |
| --- | --- |
| `libcst` | Lossless parsing, positions, scopes, and qualified-name metadata. |
| `packaging` | Python versions, specifiers, requirements, and markers. |
| `pydantic` | Strict registry, configuration, and report models. |
| `PyYAML` | Safe loading of human-maintained registry records. |
| `pathspec` | Gitignore-compatible file discovery. |
| `click` | Stable subcommand-based CLI. |
| `rich` | Readable terminal reports; never used by JSON/SARIF paths. |

Development dependencies:

- `pytest` and `pytest-cov`;
- `hypothesis` for version-expression and schema properties where useful;
- `ruff` for lint and formatting;
- `mypy` in strict mode;
- `build` or `uv build` for distribution verification.

Avoid adding a dependency when a small standard-library implementation is clearer.

---

## 7. Core architecture

```mermaid
flowchart TD
    A["CLI or library caller"] --> B["Policy and project discovery"]
    R["Reviewed registry"] --> C["Registry loader and matcher index"]
    B --> D["File discovery"]
    C --> E["Static analysis engine"]
    D --> E
    E --> F["Evidence and finding merger"]
    F --> G["Gate evaluation"]
    G --> H["Console, JSON, or SARIF"]
```

The CLI is a thin adapter. Business logic must be callable as a Python library:

```python
from pathlib import Path

from pyahead.analysis import ScanRequest, scan

report = scan(
    ScanRequest(
        root=Path.cwd(),
        baseline_python="3.11",
        horizon_python="3.16",
    )
)
```

No analyser module should import Click or Rich. Formatters consume immutable report models.

### 7.1 Scan pipeline

1. Resolve repository root and configuration.
2. Establish the effective target set.
3. Load registry and release metadata.
4. Compile a matcher index keyed by matcher kind and leading module or symbol.
5. Discover source files deterministically.
6. Parse each file with LibCST.
7. Resolve positions, scopes, and possible imported qualified names.
8. Calculate per-node target-version reachability for recognized guards.
9. Run applicable matchers.
10. Convert matches into findings using rule timelines.
11. Deduplicate and fingerprint findings.
12. Apply suppressions and baseline status.
13. Record incomplete analysis diagnostics.
14. Sort deterministically.
15. Evaluate the CI gate.
16. Render the selected output.

### 7.2 Public Python API

The alpha public API is deliberately narrow:

```python
def scan(request: ScanRequest) -> ScanReport: ...

def load_registry(source: RegistrySource | None = None) -> Registry: ...
```

Everything else is private until `1.0`. Use leading underscores or document non-stability. Do not expose raw LibCST nodes in the public result model.

### 7.3 Determinism

The core report must exclude:

- wall-clock timestamps;
- absolute paths;
- process IDs;
- unordered dictionaries or sets;
- environment-specific temporary paths;
- terminal-width-dependent text from machine formats.

Sort files by POSIX repository-relative path, findings by earliest relevant version then impact then rule ID then location, and sources in registry order.

---

## 8. Version model

### 8.1 Minor versions

The first release reasons at Python minor-version granularity. A `PythonMinor` value:

- parses only `MAJOR.MINOR`;
- is orderable and hashable;
- rejects prerelease and patch strings in policy configuration;
- currently requires major version 3;
- renders canonically as, for example, `3.13`.

Patch-specific changes may appear in evidence metadata later, but they must not be silently rounded into the minor model.

### 8.2 Target set

For baseline `3.11` and horizon `3.16`, the target set is:

```text
{3.11, 3.12, 3.13, 3.14, 3.15, 3.16}
```

Use a `frozenset[PythonMinor]` internally for reachability. The set is tiny, easy to inspect, and naturally handles Boolean guards and future non-contiguous matrices. Do not begin with complex interval algebra.

### 8.3 Release metadata

`releases.yaml` records facts used for presentation and defaults:

```yaml
schema_version: 1
releases:
  - python: "3.14"
    status: stable
    released_on: "2025-10-07"
  - python: "3.15"
    status: prerelease
    expected_final_on: "2026-10-01"
    source: "https://peps.python.org/pep-0790/"
```

Allowed statuses are `eol`, `security`, `stable`, `prerelease`, and `planned`. Dates are informative registry data and must not drive detection semantics.

### 8.4 Defaults

Policy precedence is:

1. CLI arguments.
2. `[tool.pyahead]` configuration.
3. A lower bound inferred from `[project].requires-python`.
4. Advisory inference from a consistent test matrix or Trove classifiers.
5. Otherwise, a configuration error.

The baseline must never be guessed from the host interpreter.

If the horizon is omitted, use the newest stable or actively developed Python release known by the bundled release registry, whichever is newer. Print that this was inferred and show the registry snapshot. Do not automatically include a merely planned version beyond the active development release.

The horizon must be greater than or equal to the baseline. Every requested version must fall within the registry's declared analysis window. Outside-window requests are configuration errors in the alpha, not silently partial scans. If the inferred default horizon is older than the baseline, require an explicit supported registry update or policy rather than inventing coverage.

### 8.5 Host and target separation

PyAhead may run under Python 3.11 while assessing a 3.11-to-3.16 horizon. Static rules do not require each target interpreter.

A best-effort baseline grammar check may use `ast.parse(..., feature_version=(3, minor))` when the host supports the requested feature version. Its result must be labelled best-effort. Actual grammar and runtime validation belongs to target-interpreter probes.

---

## 9. Compatibility registry

The registry is the heart of the product. A sophisticated analyser with an unreviewed or opaque registry is not useful.

### 9.1 Registry principles

- Human reviewed.
- Version controlled.
- Source linked.
- Schema validated.
- Testable independently of the analyser.
- No LLM-generated rule may be published without review.
- No arbitrary executable code in YAML.
- Every official source item is either implemented or explicitly classified in a coverage manifest.

The registry remains in the monorepo initially so a rule, matcher change, and regression test can land atomically. Split it into its own repository or package only when independent release cadence becomes a demonstrated need.

### 9.2 Rule schema

Example:

```yaml
schema_version: 1
id: CPY0001
title: "The cgi module is removed"
summary: >-
  The cgi standard-library module is deprecated in Python 3.11 and
  removed in Python 3.13.

scope:
  ecosystem: python
  runtime: cpython
  contexts: [runtime]

subject:
  kind: module
  name: cgi

timeline:
  - event: deprecated
    python: "3.11"
    certainty: released
    source: pep-0594
  - event: removed
    python: "3.13"
    certainty: released
    source: whatsnew-3.13

impact:
  on_deprecation: deprecated
  on_removal: breaking

matchers:
  - kind: module-import
    module: cgi
  - kind: literal-dynamic-import
    module: cgi
    confidence: medium

remediation:
  summary: >-
    Replace the specific cgi functionality in use. There is no single
    drop-in replacement for the complete module.
  automation: null

sources:
  - id: pep-0594
    title: "PEP 594 — Removing dead batteries from the standard library"
    url: "https://peps.python.org/pep-0594/"
  - id: whatsnew-3.13
    title: "What's New in Python 3.13"
    url: "https://docs.python.org/3.13/whatsnew/3.13.html"

tags: [stdlib, module-removal, pep-594]
```

Initial rule contexts are `runtime` and `typing`. A rule may apply to both. Future dependency and build-system rules may add an `installation` context through a schema-versioned change; do not overload `runtime` to mean installation.

### 9.3 Stable IDs

- CPython rules use `CPY` plus four decimal digits, for example `CPY0001`.
- IDs do not encode the affected Python version; schedules can change.
- Deleted or merged rule IDs remain reserved.
- A rule split creates new IDs and keeps the old ID as retired metadata.
- Rule aliases may be added for migrated IDs, but formatters always emit the canonical ID.

### 9.4 Change events

Allowed initial events:

| Event | Meaning |
| --- | --- |
| `deprecated` | Supported but discouraged; normally produces debt. |
| `removed` | API or module is unavailable from this version; normally breaking. |
| `signature_changed` | A previously accepted call form is no longer accepted or changes meaning. |
| `behavior_changed` | The same source may execute differently. |
| `syntax_changed` | Grammar or compilation behaviour changes. |
| `support_dropped` | A package or tool declares a Python version unsupported. |

Allowed registry certainty values:

| Certainty | Meaning |
| --- | --- |
| `released` | The change exists in a final Python release. |
| `scheduled` | An authoritative source assigns it to a future version. |
| `provisional` | Announced or present in prerelease development but explicitly subject to change. |

Every event has a Python version. If a rule has a deprecation event but no authoritative removal event, report that removal is unscheduled; absence of a removal event is not itself a fictional event. This keeps certainty attached only to changes that have actually happened or been announced.

If a removal is postponed, update the existing event rather than create a new rule, add the new authoritative source, and add a regression test for the corrected timeline.

### 9.5 Matcher schema

Supported declarative matcher kinds in the alpha:

1. `module-import`
   - `import cgi`
   - `import cgi as legacy_cgi`
   - `from cgi import FieldStorage`
2. `qualified-reference`
   - exact import-derived reference to a symbol;
   - optional contexts such as `read`, `decorator`, `base-class`, or `annotation`.
3. `qualified-call`
   - exact import-derived callable used as `Call.func`.
4. `call-shape`
   - a qualified call plus predicates over positional count, keyword presence, literal values, or omitted arguments.
5. `literal-dynamic-import`
   - `importlib.import_module("cgi")` or `__import__("cgi")` with a literal string;
   - medium confidence by default.
6. `builtin-pattern`
   - a whitelisted built-in analyser for syntax or value shapes that cannot be expressed safely in YAML.

A `builtin-pattern` references a known implementation identifier such as `bool-bitwise-inversion`. Registry data cannot provide a module path or arbitrary callable.

### 9.6 Remediation

Remediation fields may include:

```yaml
remediation:
  summary: "Use inspect.iscoroutinefunction()."
  documentation_url: "https://docs.python.org/..."
  automation:
    tool: ruff
    rule: UP999
```

Never claim an automatic fix unless the referenced tool and rule are verified. Do not estimate time-to-fix.

### 9.7 Sources

Preferred sources, in order:

1. Python documentation for the affected release.
2. Accepted PEPs.
3. CPython documentation's centralized deprecation index.
4. CPython issues or merged changes when the first three are insufficient.
5. Official package documentation for third-party rules later.

Each source has a stable local ID, title, and direct URL. A rule must contain at least one source. Future scheduled events require an authoritative source that names the version.

### 9.8 Coverage manifests

Completeness must be auditable. For every curated source page, add a coverage manifest:

```yaml
schema_version: 1
source:
  id: python-deprecations-3.14
  url: "https://docs.python.org/3/deprecations/index.html"
  checked_on: "2026-07-31"

entries:
  - source_key: "pending-3.16-asyncio-iscoroutinefunction"
    disposition: implemented
    rules: [CPY0042]

  - source_key: "pending-3.15-import-system-cached"
    disposition: not-statically-detectable
    note: "Requires runtime module-state inspection."

  - source_key: "pending-3.15-pyweakref-getobject"
    disposition: c-api-roadmap
    note: "Excluded from the Python-source alpha."
```

Allowed dispositions:

- `implemented`;
- `partial`;
- `not-statically-detectable`;
- `dynamic-evidence-roadmap`;
- `c-api-roadmap`;
- `duplicate`;
- `not-applicable`.

Registry CI fails when a referenced source entry has no disposition or when an `implemented` entry points to a missing rule.

### 9.9 Registry revision

Compute the registry revision as a SHA-256 digest of canonicalized registry and release files. Expose both:

- a human release label such as `2026.07.31`; and
- a short content digest such as `8e8128d`.

Every report includes both. The hosted service uses the full digest in scan identity.

---

## 10. Static analysis engine

### 10.1 File discovery

Default discovery:

- scan `*.py` and `*.pyi` beneath the repository root;
- respect `.gitignore` when present;
- exclude `.git`, `.venv`, `venv`, `build`, `dist`, cache directories, and common generated directories;
- do not follow directory symlinks;
- do not follow a file symlink that resolves outside the repository root;
- skip files above 2 MiB by default and emit an incomplete-analysis diagnostic;
- normalize all report paths to repository-relative POSIX form.

Normal `.py` source begins in both runtime and typing contexts because it is executed by Python and analysed by type checkers. Stub `.pyi` source begins in typing-only context. The engine also recognizes import-derived `typing.TYPE_CHECKING` guards: the true branch is typing-only and the false branch is runtime-only. A registry rule declares the contexts in which it applies, so a runtime-only CPython removal is not incorrectly reported as a runtime blocker for an import that exists only in a stub or `TYPE_CHECKING` branch.

Includes and excludes are evaluated in documented order:

1. built-in exclusions;
2. gitignore rules if enabled;
3. configured includes;
4. configured excludes, which win.

File order is lexical by normalized path.

### 10.2 Parsing

Use LibCST because positions, formatting, imports, scopes, comments, and qualified-name metadata are all valuable to detection and suppression.

For each source file:

1. Read bytes and detect Python source encoding according to Python rules.
2. Parse with LibCST.
3. Wrap with metadata providers:
   - `PositionProvider`;
   - `ParentNodeProvider`;
   - `ScopeProvider`;
   - `QualifiedNameProvider`.
4. Collect syntax, suppression, reachability, and match evidence in one coordinated traversal where practical.

Parse failure produces a diagnostic containing path, location, and parser message. By default, any unexcluded parse failure makes the scan incomplete and produces exit code 3 even if other files were analysed. `--allow-incomplete` may downgrade that to a warning, but output must still state that the scan was incomplete.

### 10.3 Qualified-name resolution

Recognize ordinary aliasing:

```python
import locale as loc
loc.getdefaultlocale()

from locale import getdefaultlocale as get_locale
get_locale()
```

Use import-derived qualified names from LibCST. Confidence rules:

- **high:** exactly one applicable import-derived qualified name matches the registry subject and no competing imported target is possible;
- **medium:** the subject is one of multiple possible import-derived names, or the match is a literal dynamic import;
- **low:** heuristic text or attribute shape without reliable binding.

The alpha emits high-confidence findings by default. Medium findings are available with configuration. Low-confidence matching should not be implemented until there is a specific, validated use case.

Lexical shadowing must not produce a false exact match:

```python
import locale

def f(locale):
    locale.getdefaultlocale()  # not an imported locale reference
```

Star imports are unresolved by default. Do not pretend that an unqualified name from `import *` is exact.

Build a project-module index from discovered source roots before analysing imports. Configured `source-roots` are authoritative. Otherwise, infer only conventional repository-root and `src/` layouts and expose the inference in the report. Explicit relative imports are local. If an absolute import could resolve to a repository module that shadows a standard-library or third-party name, treat it as ambiguous rather than high confidence. Uncertain packaging layouts must reduce confidence, not fabricate an origin.

### 10.4 Match collection

An internal `StaticMatch` contains:

```python
EvidenceValue = str | tuple[str, ...]

@dataclass(frozen=True)
class StaticMatch:
    rule_id: str
    matcher_kind: str
    path: PurePosixPath
    region: SourceRegion
    enclosing_scope: str
    subject: str
    confidence: MatchConfidence
    reachable_versions: frozenset[PythonMinor]
    usage_contexts: frozenset[UsageContext]
    evidence: tuple[tuple[str, EvidenceValue], ...]
```

`evidence` contains only structured, formatter-safe facts such as resolved
qualified names and call keyword names. M1 stores deterministic immutable
key-value pairs and serializes them as a JSON mapping; it must not contain LibCST
objects.

### 10.5 Matcher index

Do not visit every node once per rule. Compile indexes:

- module-import rules by top-level module;
- qualified rules by terminal name and full name;
- call-shape rules by full callable name;
- built-in patterns by visitor hook.

The engine visits each file once and asks only relevant matcher groups to inspect a node.

### 10.6 Deduplication

Multiple matchers may identify the same construct. Deduplicate by rule, file, source region, and canonical subject. Keep the strongest confidence and union non-conflicting evidence.

Do not merge distinct call sites merely because they use the same rule.

---

## 11. Version-guard reachability

Ignoring version guards would create exactly the sort of false positives that destroys trust.

### 11.1 Required alpha patterns

Recognize comparisons involving import-derived `sys.version_info` and aliases:

```python
import sys
if sys.version_info >= (3, 13): ...

from sys import version_info as py_version
if py_version < (3, 13): ...

if sys.version_info[:2] == (3, 12): ...
if not (sys.version_info >= (3, 14)): ...

if sys.version_info >= (3, 13) and feature_enabled: ...
```

Support `<`, `<=`, `>`, `>=`, `==`, `!=`, parentheses, `not`, `and`, and `or`.

Also recognize import-derived `typing.TYPE_CHECKING` and aliases. Its true branch is typing-only and its false branch is runtime-only. Apply the same conservative rule to unknown aliases: uncertain context must not be used to suppress a finding.

### 11.2 Evaluation algorithm

Evaluate a recognized condition independently for every target minor version. The result for each target is `true`, `false`, or `unknown`.

For an `if` statement with active version set `A`:

```text
true branch  = versions in A where condition is true or unknown
false branch = versions in A where condition is false or unknown
```

Unknown enters both branches. This is conservative: it may retain a finding, but it does not hide one.

For Boolean operations, use three-valued logic. For example, `known_false and unknown` is false, while `known_true and unknown` is unknown.

Handle `if`/`elif`/`else` sequentially so an `elif` receives only versions not definitely handled by preceding branches.

### 11.3 Example

```python
import sys

if sys.version_info < (3, 13):
    import cgi
else:
    from replacement import parse_form
```

For a 3.11-to-3.16 target set, the `cgi` import is reachable only on 3.11 and 3.12. Its removal in 3.13 is therefore not an upgrade blocker. It may still be reported as deprecation debt for 3.11–3.12.

### 11.4 Explicit limitations

The alpha treats these as unknown:

- patch-level guards such as `sys.version_info >= (3, 13, 2)`;
- user-defined version constants;
- helper functions that hide version checks;
- string comparisons of `platform.python_version()`;
- Boolean expressions that mix `TYPE_CHECKING` with runtime version or feature predicates beyond a direct `not`;
- conditions dependent on environment variables or package versions;
- general control-flow reachability beyond lexical guards.

Add support only with positive and negative fixtures. Never infer target unreachability from a condition the engine does not understand.

---

## 12. Finding and report model

### 12.1 Finding lifecycle

A source match and rule timeline produce one finding. Its `states` summarize contiguous portions of the reachable target set:

```json
{
  "rule_id": "CPY0001",
  "states": [
    {"from": "3.11", "through": "3.12", "state": "deprecated"},
    {"from": "3.13", "through": "3.16", "state": "breaking"}
  ]
}
```

Initial states:

| State | Meaning |
| --- | --- |
| `deprecated` | The usage remains available but is deprecated. |
| `risk` | A signature, behaviour, or environment change may affect execution. |
| `breaking` | The matched usage is unavailable or invalid in the target version. |
| `informational` | Relevant future or unscheduled information that is not currently gated. |

If the usage is unreachable for a target version, that version does not appear in the finding state.

### 12.2 Internal model

```python
@dataclass(frozen=True)
class Finding:
    fingerprint: str
    rule_id: str
    title: str
    path: PurePosixPath
    region: SourceRegion
    enclosing_scope: str
    subject: str
    match_kind: str
    match_confidence: MatchConfidence
    match_evidence: tuple[tuple[str, EvidenceValue], ...]
    usage_contexts: tuple[UsageContext, ...]
    reachable_versions: tuple[PythonMinor, ...]
    states: tuple[FindingStateRange, ...]
    remediation: Remediation
    sources: tuple[SourceReference, ...]
    suppression: Suppression | None
    baseline_status: BaselineStatus
```

`ScanReport` contains:

- tool and schema versions;
- registry release and digest;
- effective policy and provenance;
- scanned root label, never absolute path;
- file counts;
- findings;
- diagnostics;
- analysis inferences and their provenance;
- summary counts;
- gate configuration and result.

### 12.3 Impact and confidence

Keep these separate in every machine format:

```text
impact: breaking
match_confidence: high
registry_certainty_by_event: {deprecated: released, removed: scheduled}
```

Certainty belongs to the event or derived state range because one rule can contain a released deprecation and a scheduled removal. A formatter may present a summary certainty, but it must retain the per-event values. A future scheduled removal can be high-confidence static evidence and breaking impact while still being scheduled rather than released.

### 12.4 Stable fingerprints

Fingerprint version 1 is:

```text
sha256(
  "pyahead-fingerprint-v1\0" +
  rule_id + "\0" +
  repository_relative_path + "\0" +
  enclosing_scope + "\0" +
  canonical_subject + "\0" +
  occurrence_ordinal_within_scope
)
```

The occurrence ordinal counts matches for the same rule and subject within the enclosing scope, not physical lines. This survives unrelated line insertions better than a line-based hash.

Tests must cover:

- adding blank lines above a finding does not change it;
- renaming the containing function does change it;
- renaming or moving the source file changes it and is a documented baseline limitation;
- adding a preceding same-rule match within the same scope changes later ordinals and is documented as a limitation;
- normalized path separators are stable across platforms.

Use the fingerprint in SARIF `partialFingerprints` and baseline files.

### 12.5 Baseline file

```json
{
  "schema_version": 1,
  "created_by": "pyahead 0.1.0",
  "registry_revision": "...",
  "findings": [
    {
      "fingerprint": "...",
      "rule_id": "CPY0001",
      "path": "src/legacy.py",
      "subject": "cgi"
    }
  ]
}
```

The registry revision is informative; a baseline remains usable after registry changes. A finding with a new fingerprint is new even if its rule ID already exists in the baseline.

### 12.6 Suppressions

Support:

```python
import cgi  # pyahead: ignore[CPY0001] -- migration tracked in issue 42
```

and configuration:

```toml
[tool.pyahead.per-file-ignores]
"tests/fixtures/**" = ["CPY0001", "CPY0002"]
```

Rules:

- an inline suppression applies to findings whose primary region touches that logical statement;
- a rule ID is mandatory;
- a reason after `--` is recommended but not required in the alpha;
- unknown rule IDs are diagnostics;
- suppressed findings remain available in JSON with `suppressed: true` when `--show-suppressed` is used;
- suppressions do not erase incomplete-analysis diagnostics.

Do not reuse `# noqa`; PyAhead's semantics and timelines are distinct.

---

## 13. Configuration and project inference

### 13.1 Configuration schema

```toml
[tool.pyahead]
baseline-python = "3.11"
horizon-python = "3.16"
include = ["src/**/*.py", "tests/**/*.py"]
exclude = ["**/generated/**"]
source-roots = ["src"]
respect-gitignore = true
minimum-confidence = "high"
fail-on = "breaking"
show-unscheduled = true
max-file-size-bytes = 2097152

[tool.pyahead.per-file-ignores]
"tests/fixtures/**" = ["CPY0001"]
```

Unknown keys are configuration errors. This catches spelling mistakes instead of silently ignoring them.

### 13.2 Merge semantics

- Scalars: CLI replaces configuration.
- Lists: CLI replaces rather than appends unless the option explicitly says `--add-*`.
- Per-file ignores: merge by pattern, with CLI-specific ignores added.
- Explicit `--no-*` flags override true configuration values.

Print effective configuration under `--verbose` and expose it in JSON.

### 13.3 Baseline inference

From:

```toml
[project]
requires-python = ">=3.11"
```

infer baseline `3.11` with provenance `project.requires-python`.

For complicated specifiers:

- use `packaging.specifiers.SpecifierSet`;
- find the lowest included Python minor from the registry's supported analysis range;
- reject a specifier with no supported included minor;
- if the lower boundary is patch-specific, report the exact declaration and explain that PyAhead analyses at minor granularity;
- never infer a baseline solely from Trove classifiers when they conflict with `requires-python`.

CI matrices, Tox, Nox, and classifiers are advisory in the alpha. If they agree and no authoritative baseline exists, PyAhead may suggest a value, but non-interactive `check` should fail with a clear instruction rather than silently adopt it.

### 13.4 Repository root

Resolve root in this order:

1. Explicit `--root`.
2. Nearest ancestor containing `pyproject.toml`.
3. Nearest Git worktree root.
4. Current directory.

Configuration discovery stops at the selected root.

---

## 14. CLI contract

### 14.1 Commands

```text
pyahead check [PATHS...]
pyahead explain RULE_ID
pyahead baseline create
pyahead registry validate
pyahead registry list
pyahead registry coverage
pyahead version
```

Use `pyahead --version` as an alias for `pyahead version`.

### 14.2 `check` options

Core options:

```text
--baseline-python VERSION
--horizon-python VERSION
--config PATH
--root PATH
--registry PATH
--format text|json|sarif
--output PATH
--minimum-confidence high|medium
--fail-on never|breaking|risk|deprecated|any
--baseline-file PATH
--fail-new-only
--show-suppressed
--allow-incomplete
--verbose
--quiet
```

`--output -` means standard output. Without `--output`, text goes to stdout and machine formats go to stdout. Diagnostics that would corrupt JSON/SARIF go to stderr.

### 14.3 Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed and no finding met the configured failure gate. |
| `1` | Scan completed and one or more findings met the gate. |
| `2` | Invalid command line, configuration, or registry input. |
| `3` | Analysis was incomplete because one or more eligible files could not be read or parsed. |
| `4` | Unexpected internal error. |

`--allow-incomplete` permits exit 0 or 1 instead of 3, but the report retains prominent incomplete diagnostics.

### 14.4 Gate semantics

Impact ordering for gate purposes:

```text
informational < deprecated < risk < breaking
```

- `never`: findings never cause exit 1.
- `breaking`: fail on breaking findings only; default.
- `risk`: fail on risk or breaking.
- `deprecated`: fail on deprecated, risk, or breaking.
- `any`: fail on every unsuppressed finding, including informational.

`--fail-new-only` evaluates only findings absent from the baseline file. It does not hide existing findings from output.

### 14.5 Text output

Text output is optimized for a human terminal:

- timeline grouped by earliest actionable Python version;
- concise summary at top and bottom;
- one primary location per finding;
- source and full explanation available without network through `pyahead explain`;
- colour only on a TTY and when `NO_COLOR` is not set;
- `--quiet` prints only a one-line summary and errors.

Avoid animation and progress bars in CI.

---

## 15. JSON and SARIF contracts

### 15.1 JSON

Top-level shape:

```json
{
  "schema_version": 1,
  "tool": {"name": "pyahead", "version": "0.1.0"},
  "registry": {"release": "2026.07.31", "revision": "..."},
  "policy": {
    "baseline_python": "3.11",
    "horizon_python": "3.16",
    "versions": ["3.11", "3.12", "3.13", "3.14", "3.15", "3.16"],
    "provenance": {"baseline_python": "pyproject.toml:project.requires-python"}
  },
  "scan": {
    "files_discovered": 42,
    "files_analyzed": 42,
    "files_incomplete": 0
  },
  "summary": {
    "breaking": 1,
    "risk": 0,
    "deprecated": 2,
    "informational": 0,
    "suppressed": 0,
    "new": 1
  },
  "findings": [],
  "diagnostics": [],
  "inferences": [],
  "gate": {"fail_on": "breaking", "new_only": false, "failed": true}
}
```

Publish a JSON Schema under `docs/schema/report-v1.json` before calling the format stable. Additive optional fields are allowed within schema version 1; removals or semantic changes require schema version 2.

### 15.2 SARIF

Emit SARIF 2.1.0 using GitHub's supported subset:

- one run;
- tool driver name and semantic version;
- one rule descriptor per emitted rule;
- repository-relative artifact URIs;
- exact regions;
- `ruleId` equal to the stable PyAhead rule ID;
- `partialFingerprints.pyahead/v1` equal to the finding fingerprint;
- impact mapped to SARIF levels:
  - `breaking` → `error`;
  - `risk` → `warning`;
  - `deprecated` and `informational` → `note`;
- match confidence, per-event registry certainty, usage contexts, version states, and registry revision in result properties;
- help URI pointing to stable hosted rule documentation when available, otherwise the primary authoritative source.

GitHub relies on stable rule IDs, paths, and fingerprints to avoid duplicate code-scanning alerts. Golden tests must validate these fields.

### 15.3 Machine-format errors

If JSON or SARIF was requested and configuration fails before a report can be constructed:

- write no partial machine document to stdout;
- write a concise error to stderr;
- exit 2, 3, or 4 as appropriate.

If an output file was requested, write to a temporary sibling and atomically replace the destination only after successful serialization.

---

## 16. Initial rule coverage

### 16.1 Supported version window

The first useful registry targets repositories with a baseline of Python 3.11 or newer and a horizon through the newest authoritative future version represented by curated data.

The architecture must not hard-code 3.11. Older baselines can be added by registry curation and parser testing.

### 16.2 Seed sources

Start with:

- PEP 594 module removals;
- released “Removed” and “Deprecated” sections for Python 3.12, 3.13, and 3.14;
- the centralized Python deprecation index for scheduled 3.15, 3.16, and later removals;
- relevant accepted PEPs linked by those pages.

### 16.3 Seed rule priorities

Implement in this order:

1. Whole-module removals, because matching is precise and impact is clear.
2. Exact function/class/attribute removals reachable through imports.
3. Changed call forms expressible through call-shape predicates.
4. Simple literal/syntax patterns with a dedicated built-in matcher.
5. Partial patterns only when output clearly describes the limitation.

Do not set an arbitrary rule-count target. The acceptance criterion is that every entry in each selected authoritative source is classified in a coverage manifest, and every `implemented` rule has positive and negative fixtures.

### 16.4 Example fixture matrix

For a module rule:

```text
tests/fixtures/rules/CPY0001/
├── positive/
│   ├── import_direct.py
│   ├── import_alias.py
│   ├── from_import.py
│   └── literal_dynamic_import.py
├── negative/
│   ├── local_module.py
│   ├── shadowed_name.py
│   └── string_only.py
└── expected.json
```

M1 fixtures declare expected confidence, action version, and resolution evidence.
From M3 onward, each fixture also declares reachable versions and usage contexts.
A rule cannot be marked implemented without at least one negative fixture. Fixture
manifests are executable contracts: tests validate their schema and compare every
declared expectation rather than merely using them as lists of paths.

---

## 17. Evidence providers after the static alpha

These components are designed now but implemented only after the static validation gate.

### 17.1 Evidence-provider interface

```python
class EvidenceProvider(Protocol):
    name: str

    def collect(self, request: EvidenceRequest) -> Iterable[Evidence]: ...
```

Evidence is normalized into:

```python
@dataclass(frozen=True)
class Evidence:
    provider: str
    kind: str
    target: EnvironmentTarget
    subject: str | None
    location: SourceLocation | None
    confidence: EvidenceConfidence
    observed: bool
    details: Mapping[str, JsonValue]
```

Providers never mutate static findings. The merger creates a report view that links corroborating or conflicting evidence.

### 17.2 Dependency compatibility

Separate application and library semantics:

- **Application:** its lockfile and deployed platform are authoritative.
- **Library:** a version range, extras, and supported platform matrix matter; one lock is insufficient.

Initial dependency evidence should distinguish:

1. `declared-incompatible`: available distribution metadata excludes a target through `Requires-Python`;
2. `resolution-failed`: dependency constraints cannot be solved for the target;
3. `artifact-unavailable`: no suitable wheel is available for a platform, but source build may remain possible;
4. `unverified`: required metadata or index access was unavailable.

Use `packaging` for metadata semantics and an isolated `uv` resolver adapter initially. Resolver use is opt-in, network-visible, separately timed out, and never part of the default static command.

Do not execute build backends merely to discover metadata in the hosted service.

### 17.3 PEP 702

Do not implement a partial type checker. Integrate an existing checker through an evidence adapter. Mypy supports PEP 702 deprecation diagnostics; other adapters can be added when they have stable machine output.

The provider records:

- checker and version;
- configuration used;
- deprecated symbol and message;
- source location;
- whether overload resolution selected a deprecated overload.

PEP 702 messages may mention a removal version, but PyAhead must not parse free text into an authoritative timeline without review. A message without structured schedule data is an unscheduled deprecation.

### 17.4 Runtime warnings

Provide a pytest plugin or explicit wrapper that captures `DeprecationWarning` and `PendingDeprecationWarning` into normalized JSON. Pytest already controls warnings through `-W`; PyAhead's value is durable normalization and timeline merging.

Dynamic execution occurs in the user's CI, not the hosted scanner. The evidence artifact is uploaded or passed to `pyahead check --evidence`.

### 17.5 Compatibility probes

The target-interpreter probe can:

- compile all source;
- resolve dependencies;
- perform configured import smoke tests;
- run the user's test command;
- capture warnings and failures.

Probe results must state coverage. “Tests passed” is not equivalent to universal compatibility.

---

## 18. Hosted GitHub service design

The hosted service is a later phase, but its constraints influence the core API. Once Gate C passes, create it in a separate private repository and depend on released versions of the open `pyahead` core package. The diagrams and contracts below apply to that repository; do not scaffold the service inside `diegorusso/pyahead`.

### 18.1 Architecture

```mermaid
flowchart TD
    A["GitHub webhooks"] --> B["Django web process"]
    B --> C["PostgreSQL job table"]
    C --> D["Worker"]
    D --> E["Ephemeral static-scan sandbox"]
    R["Published registry snapshot"] --> D
    E --> F["Finding persistence"]
    F --> G["GitHub Checks and dashboard"]
```

Initial stack:

- Django;
- PostgreSQL;
- one web process;
- one worker process;
- a PostgreSQL-backed job table using transactional claiming;
- server-rendered HTML;
- the same published `pyahead` Python package used by the CLI.

Do not add Kubernetes, a separate SPA, Kafka, or multiple services for the private beta.

### 18.2 GitHub App permissions

Request the minimum required permissions:

- Metadata: read;
- Contents: read;
- Pull requests: read;
- Checks: write.

Subscribe initially to:

- installation and installation-repository changes;
- push;
- pull request events needed to scan head commits;
- check-run rerequests.

Only GitHub Apps can create check runs through the Checks API. Check annotations are sent in batches of at most 50 per API request.

### 18.3 Webhook handling

- Verify `X-Hub-Signature-256` against the raw request body with constant-time comparison before parsing.
- Persist the GitHub delivery ID and reject duplicate deliveries idempotently.
- Acknowledge valid webhooks quickly; enqueue work rather than scanning in the request.
- Use a unique scan identity of repository, commit SHA, registry revision, configuration digest, and analyser version.
- Treat deleted branches and superseded pull-request heads as cancellable work.

### 18.4 Source handling

1. Obtain a repository archive using a short-lived installation token.
2. Enforce archive byte, expanded byte, file-count, and path-depth limits.
3. Reject path traversal and unsafe symlinks.
4. Place source in an ephemeral per-job directory.
5. Start the analyser in a separate process with network disabled, resource limits, and a deadline.
6. Do not initialize submodules or fetch Git LFS objects in the beta.
7. Delete the source directory at job completion or failure.

Persist only:

- repository and commit identifiers;
- configuration digest and effective policy;
- rule IDs, fingerprints, repository-relative locations, and structured evidence;
- finding state and triage metadata;
- scan metrics and diagnostics.

Do not persist repository source or full source snippets by default.

### 18.5 Service data model

Core entities:

| Entity | Purpose |
| --- | --- |
| `GitHubInstallation` | Installation identity and account metadata. |
| `Repository` | GitHub repository identity, default branch, policy, and enabled state. |
| `RegistrySnapshot` | Immutable registry release and digest. |
| `Scan` | Commit, analyser version, registry, status, timings, and diagnostics. |
| `FindingIdentity` | Stable repository-scoped fingerprint and rule ID. |
| `FindingOccurrence` | A finding as observed in a particular scan. |
| `TriageDecision` | Open, accepted risk, false positive, or resolved; actor and reason. |
| `WebhookDelivery` | Delivery ID and processing state for idempotency. |
| `ScanJob` | Transactionally claimed background work. |

Triage decisions attach to stable finding identity, not a line number.

### 18.6 Check-run behaviour

The check summary includes:

- effective Python policy;
- new versus existing counts;
- earliest breaking version;
- incomplete-scan status;
- registry revision;
- link to the full dashboard.

Only new findings on changed lines should become pull-request annotations by default. Existing repository debt remains in the summary and dashboard.

Conclusions:

- `success`: complete scan and no gated new findings;
- `failure`: complete scan with gated new breaking findings;
- `neutral`: complete scan with non-gated debt or risk;
- `action_required`: policy missing or scan incomplete in a way the user can fix;
- `timed_out` or `cancelled`: corresponding job outcome.

### 18.7 Registry-triggered rescans

When a new registry snapshot is published:

1. Determine repositories whose configured horizon intersects changed rules.
2. Queue default-branch scans with a registry-update cause.
3. Compare findings to the last successful scan.
4. Notify only on newly relevant findings or materially changed timelines.

This path must be rate limited and resumable.

### 18.8 Product packaging

The open CLI and registry remain free. Hosted scans for public repositories should also be free to create adoption and improve the rule corpus. Charge for active private repositories rather than developer seats; the value is continuous repository monitoring, not per-user editor access.

The initial pricing hypothesis is a low-cost individual plan for a small number of private repositories and a team plan with organisation views and longer history. Do not hard-code price points into the domain model. Model entitlements such as active private repositories, history retention, notification channels, and organisation dashboards. The private beta uses manual allow-listing and no billing integration; add billing only after users demonstrate willingness to pay.

---

## 19. Security, privacy, and trust

### 19.1 CLI

- No telemetry.
- No network access by default.
- Never import target modules.
- Never execute project configuration as Python.
- Load YAML with safe parsing.
- Resolve and validate all filesystem paths beneath the scan root.
- Refuse symlink escapes.
- Bound file size and total files.
- Redact absolute home and temporary paths from diagnostics.
- Document every command that can access the network or execute user code in later releases.

### 19.2 Registry supply chain

- Registry changes require code review and CI.
- Signed releases are desirable before `1.0`.
- A registry update has a content digest.
- The CLI does not auto-download or silently replace registry data in the alpha.
- A future update command verifies integrity and supports pinning.
- Hosted scans always record the exact immutable registry digest.

### 19.3 Hosted service

- Least-privilege GitHub App permissions.
- Short-lived installation tokens.
- Encrypted secrets and database connections.
- Constant-time webhook signature validation.
- Idempotent delivery handling.
- Strict scan isolation, timeouts, and resource limits.
- No test execution on hosted infrastructure in the beta.
- No persistent source storage.
- Tenant-scoped authorization on every repository object.
- Audit records for triage and administrative actions.
- A documented deletion path for installation and repository data.

### 19.4 Trust through explainability

Every visible finding answers:

1. What source construct was matched?
2. How was its name resolved?
3. In which versions is the code reachable?
4. When is the relevant API deprecated or incompatible?
5. Is the schedule released, scheduled, provisional, or unscheduled?
6. What authoritative source supports it?
7. What remediation is known?
8. Can an existing tool apply a verified mechanical fix?

If PyAhead cannot answer these, it should not emit a high-confidence finding.

---

## 20. Testing and quality strategy

### 20.1 Test layers

1. **Model tests**
   - version parsing and ordering;
   - schema validation;
   - timeline state derivation;
   - configuration merge and inference.
2. **Matcher unit tests**
   - direct imports;
   - aliases;
   - shadowing;
   - call-shape predicates;
   - positions and confidence.
3. **Reachability tests**
   - each comparison operator;
   - Boolean truth tables;
   - nested `if`/`elif`/`else`;
   - unknown conditions enter both branches.
4. **Registry contract tests**
   - every YAML file validates;
   - IDs are unique and reserved IDs are not reused;
   - sources exist and event references resolve;
   - timeline ordering is valid;
   - implemented coverage entries map to rules;
   - fixtures exist for implemented rules.
5. **Integration tests**
   - temporary repositories with `pyproject.toml`;
   - complete CLI execution and exit codes;
   - baseline and suppression semantics;
   - incomplete scans.
6. **Golden tests**
   - console without colour;
   - JSON;
   - SARIF;
   - rule explanation.
7. **Packaging tests**
   - build sdist and wheel;
   - install each into a clean environment;
   - run `pyahead --version` and a sample scan;
   - verify registry package data is present.
8. **Corpus tests**
   - scan selected public repositories;
   - record performance and manually assessed precision;
   - never turn third-party repository output into brittle unit snapshots.

### 20.2 CI matrix

Required:

- Linux on every supported host Python;
- Windows and macOS on the oldest and newest stable supported host Python;
- a prerelease Python job while the next Python is in development;
- lint, formatting, and strict type checking;
- registry validation and coverage;
- build/install smoke test.

The prerelease job may begin as non-blocking but becomes required before PyAhead claims host support for that Python.

### 20.3 Coverage targets

- Core version, registry, finding, and reachability modules: 95% branch coverage.
- Project-wide: 90% branch coverage before public beta.
- More important than numeric coverage: every rule has explicit positive and negative fixtures.

Do not exclude difficult error paths merely to meet a percentage.

### 20.4 Precision gate

Before hosted work begins:

- manually inspect a statistically useful sample of high-confidence findings across at least 100 active public repositories;
- achieve at least 95% precision for high-confidence findings;
- classify every false positive and add a regression fixture;
- demonstrate that maintainers understand the timeline without verbal explanation;
- obtain at least ten maintainers willing to run it continuously.

Recall is measured through the registry coverage manifests and curated test repositories. Optimise precision before expanding heuristic recall.

### 20.5 Performance budgets

Initial budgets on a normal four-core development machine:

- CLI startup and one-file scan: under 500 ms after environment startup;
- 1,000 ordinary Python files: under 5 seconds;
- 10,000 ordinary Python files: under 30 seconds;
- peak resident memory for 10,000 files: under 1 GiB;
- output ordering identical across runs and worker counts.

Measure before parallelizing. If needed, parallelize by file with a bounded process pool, but preserve deterministic aggregation. Dependency resolution and test probes have separate budgets.

---

## 21. Observability and diagnostics

### 21.1 CLI diagnostics

Diagnostic categories:

- configuration;
- discovery;
- encoding;
- parse;
- registry;
- inference;
- suppression;
- internal.

Each diagnostic has a stable code, message, optional path and region, and `fatal` or `incomplete` flags. Example:

```text
PYA1003 src/generated.py: unable to parse source: unexpected indent
```

Diagnostic codes are not rule IDs and use the `PYA` prefix.

`--verbose` prints stage timings and inference evidence to stderr. It must not include source contents or sensitive environment variables.

### 21.2 Hosted metrics

Track:

- webhook-to-check latency;
- queue delay and scan duration;
- source file count and bytes;
- findings by rule, impact, and confidence;
- incomplete and timed-out scan rate;
- registry-triggered rescan volume;
- triage outcomes, especially false positives;
- installation and repository retention.

Do not use private source text as metric labels or log payloads.

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

### Gate C: external usefulness

- At least 100 active public repositories scanned.
- At least 95% sampled precision for high-confidence findings.
- False positives have regression tests.
- At least ten maintainers agree to continuous use.

### Gate D: dynamic evidence

- One evidence provider works end to end in CI.
- Evidence is clearly distinguished from static inference.
- Conflicts do not silently overwrite either source.
- Network and execution boundaries are explicit.

### Gate E: hosted private beta

- GitHub permissions and source-retention design reviewed.
- Webhook signature and replay tests pass.
- Static scans run in resource-bounded network-disabled workers.
- Source is deleted after success and failure.
- Check-run annotations are correctly batched.
- Registry updates trigger idempotent rescans.

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
uv sync
uv run ruff check .
uv run ruff format --check .
uv run mypy src
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

### M1.5 — Autonomous milestone orchestrator

This is development infrastructure, not a product-capability milestone. It
automates the implement, independently verify, review, repair, commit, and
optional publication cycle without adding any M2 analyser or registry work.

Deliverables:

- a standard-library orchestrator at `scripts/autopilot.py` with `doctor`,
  `plan`, `run`, `status`, `resume`, and evidence-backed Gate C commands;
- repository-owned milestone policy, prompt templates, and strict result schemas
  under `automation/`;
- one fresh ephemeral Codex context for each implementation, review, and repair
  role, with read-only review and bounded workspace-write implementation/repair;
- independent parent-owned verification and one intentional Git commit per
  passing milestone;
- atomic ignored state, complete separated logs, interruption recovery, and
  publication-only retry;
- protected governance, harness, quality-policy, CI, frozen-contract, external
  gate-record, and Git metadata boundaries;
- deterministic offline tests using fake Codex, Git, and GitHub executables;
- operator and security documentation in `docs/autopilot.md`.

Acceptance:

- `doctor` proves that the installed Codex CLI exposes the required ephemeral,
  sandbox, approval-policy, schema-output, last-message, and working-directory
  controls without invoking the service;
- ranges, exact contract extraction, rendered prompts, closed-world result
  parsing, role isolation, repair limits, Gate C, M9/M10 refusals, and every
  durable resume boundary have deterministic offline tests;
- parent verification is authoritative, a milestone cannot commit before all
  configured commands pass and an independent reviewer returns `pass`, and a
  recovered commit cannot be duplicated;
- protected-file, quality-policy, and Git-metadata changes stop with work
  preserved rather than being reverted or committed;
- `run --dry-run` prints the branch, stages, argv, rendered prompts,
  verification, commit, publication, gate, and protected-file plan while making
  no state, Git, Codex, or remote mutation;
- a failed push preserves local commits and resumes only publication;
- M2–M6 may run unattended, execution stops after M6 in `awaiting_gate_C`, M7–M8
  require recorded external evidence, M9 is refused in this repository, and M10
  is refused until its design exists;
- the full repository quality and build suite passes without a real M2 run.

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

Recommended first choice: pytest warnings, because it is immediately useful and does not require hosted execution.

Deliverables:

- versioned evidence JSON schema;
- pytest warning collector;
- `--evidence` ingestion;
- static/dynamic evidence merger;
- console and JSON distinction between inferred and observed evidence;
- CI example.

Acceptance:

- warning collection occurs in user CI;
- the hosted scanner is not involved;
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

- no build backend executes during hosted metadata inspection;
- offline mode is deterministic;
- a resolver timeout is incomplete evidence, not a compatibility failure;
- environment markers are evaluated against the declared target;
- results name the exact package versions and metadata used.

### M9 — Hosted GitHub private beta

Create a separate private service repository for this milestone. The core `diegorusso/pyahead` repository remains the open CLI and registry.

Deliverables:

- Django project and PostgreSQL schema;
- GitHub App registration documentation;
- signed/idempotent webhook ingestion;
- job claiming and retry policy;
- isolated source acquisition and static scan;
- check-run publisher;
- dashboard and triage;
- registry rescan scheduler;
- deletion and retention controls.

Acceptance:

- Gate E passes;
- a private repository receives a correct check on push and pull request;
- source is absent after scan completion and failure;
- duplicate webhook delivery creates no duplicate scan;
- more than 50 annotations are sent in correct batches;
- a registry-only change can create a new check without a source commit.

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

## 24. Architectural decisions

### ADR-001: Python end to end

**Decision:** Implement the analyser, CLI, registry tooling, and later Django service in Python.

**Reason:** Ecosystem integration, packaging semantics, warning handling, type metadata, and contributor accessibility outweigh hypothetical parser performance. Measure before considering a native component.

### ADR-002: LibCST for primary source analysis

**Decision:** Use LibCST rather than raw text or only `ast`.

**Reason:** Qualified-name, scope, parent, and position metadata plus preserved comments are required for precise matching and suppressions. Use `ast` only for best-effort grammar checks or narrowly justified helpers.

### ADR-003: Registry and code in one repository initially

**Decision:** Keep them together through the alpha.

**Reason:** Atomic matcher/rule/test changes are more valuable than independent release mechanics at this stage.

### ADR-004: Static and offline by default

**Decision:** `pyahead check` neither executes code nor uses the network.

**Reason:** Reproducibility, safety, corporate adoption, and clear evidence boundaries.

### ADR-005: Precision before recall

**Decision:** Emit high confidence by default and avoid low-confidence heuristics in the alpha.

**Reason:** A forecasting tool loses trust quickly through false positives. Coverage manifests expose missing detection honestly.

### ADR-006: No automatic rewrite engine

**Decision:** Link to verified Ruff/pyupgrade fixes but do not implement general source rewrites initially.

**Reason:** Existing tools are mature, and PyAhead's differentiation is the versioned forecast.

### ADR-007: One finding, many version states

**Decision:** A call site produces one finding containing its full timeline.

**Reason:** Users think about a migration item, not six duplicated diagnostics.

### ADR-008: Hosted tests run in customer CI

**Decision:** The hosted beta performs static scans only; dynamic tests and warnings execute in the customer's CI.

**Reason:** Avoid running arbitrary code and naturally use the project's configured environment and secrets.

### ADR-009: Server-rendered hosted UI

**Decision:** Django templates first, no SPA.

**Reason:** The dashboard is workflow and data presentation, not a high-interaction client application.

### ADR-010: Separate certainty dimensions

**Decision:** Match confidence, registry certainty, impact, and observed status remain separate.

**Reason:** “High severity” cannot explain whether a future schedule is provisional or whether a name match is ambiguous.

### ADR-011: Separate hosted-service repository

**Decision:** Keep the Apache-licensed CLI and registry in `diegorusso/pyahead`; create the commercial hosted service in a separate private repository after Gate C.

**Reason:** The service consumes a stable public core while retaining an independent deployment and licensing boundary. It also prevents premature Django scaffolding from distorting the analyser repository.

---

## 25. Open decisions

These do not block M0–M4 unless stated.

1. **Licence confirmation:** Apache-2.0 is recommended; confirm before public release.
2. **Distribution-name availability:** Verify `pyahead` on PyPI before publishing. The import package remains `pyahead` even if the distribution name changes.
3. **Hosted commercial entity and billing:** not required until private-beta demand exists.
4. **Registry update channel:** bundled releases first; signed independent updates later.
5. **First type-checker adapter:** evaluate machine-output stability before choosing mypy or another checker.
6. **First resolver adapter:** `uv` is recommended, but the provider interface must not make it irreplaceable.
7. **Public rule documentation URL:** can initially be generated with a static documentation site.
8. **Application versus library inference:** explicit configuration is preferred until reliable heuristics are validated.

---

## 26. Codex implementation protocol

PyAhead is built one milestone at a time. M1.5 replaces repeated operator
prompting with a repository-owned, resumable controller; it does not relax
milestone boundaries, independent evidence, or external product gates. A single
agent context that implements and approves multiple milestones creates too much
opportunity for unverified assumptions and architectural drift.

### 26.1 Rules for every Codex milestone

Each implementation, review, or repair role must, as applicable:

1. Read `docs/design.md`, `README.md`, `pyproject.toml`, and any repository instruction file before editing.
2. State which milestone and acceptance criteria it is implementing.
3. Inspect the current tree and preserve unrelated work.
4. Write or update tests with implementation.
5. Avoid implementing later milestones unless needed for the current vertical slice.
6. Prefer explicit data models and deterministic behaviour.
7. Run the milestone's full verification commands.
8. Inspect `git diff --check` and the final diff.
9. Update documentation when behaviour or a design decision changes.
10. Stop and explain if an acceptance criterion requires a product decision not covered here.

### 26.2 Default automated cycle

After M1.5 is merged and local `main` exactly matches `origin/main`, the normal
unattended alpha sequence is:

```console
python scripts/autopilot.py doctor --push --draft-pr
python scripts/autopilot.py plan --from M2 --through M6
python scripts/autopilot.py run --from M2 --through M6 --push --draft-pr
```

Omit `--push --draft-pr` for local commits only. `run --dry-run` must expose the
complete planned branch, stages, argv, prompts, verification, commits, gate
boundaries, publication, and protected files without calling Codex, writing
state, changing Git, or touching a remote.

The controller freezes the exact current milestone subsection and its SHA-256
digest. It then performs this cycle:

1. launch a fresh ephemeral workspace-write implementer with only the current
   contract, repository rules, previous status, parent checks, and prohibitions;
2. validate its closed-world structured result and compare its claimed paths to
   the complete Git worktree;
3. independently run every configured verification argv with a deadline and
   separated logs;
4. launch a separate fresh ephemeral read-only reviewer over the contract, live
   diff, tests, and parent-owned evidence;
5. on failed verification or concrete `changes_requested`, launch a fresh
   workspace-write fixer with only the contract, failed output, and findings;
6. repeat independent verification and review, permitting at most three repair
   cycles;
7. let the parent controller create exactly one intentional milestone commit
   only after verification passes and the reviewer returns `pass`;
8. optionally push that commit and create or update one draft pull request,
   never merging it or pushing directly to `main`.

No implementation context is resumed for review or repair. Agent claims about
commands are informational; only controller-run verification is acceptance
evidence.

### 26.3 Ownership and protected boundaries

Only the controller owns branch creation, staging, commits, pushes, and draft
pull requests. Child roles may not invoke the controller recursively or modify
Git metadata. The controller hashes the harness, governance files, frozen
contract, protected CI, selected quality-policy tables, ignored external gate
record, stable Git control metadata, and the semantic index at the relevant
boundaries. The semantic index covers staged objects, modes, paths, merge
stages, and index flags; the volatile physical index stat cache is excluded
because read-only Git commands may refresh it. A mismatch stops with work
preserved; it is never silently reset or reverted.

Runtime state and logs live under ignored `.autopilot/`. State is written
atomically and records the run/branch/base identity, current phase, repair
count, commits, prompt and contract hashes, exact accepted worktree, Git
metadata digest, and publication progress. `resume` accepts only that recorded
identity and work, detects history movement or divergence, recovers a
trailer-authenticated parent commit once, and retries publication without
re-running accepted Codex roles.

### 26.4 Gates and repository boundaries

M2 through M6 may run unattended, but a successful M6 always transitions to
`awaiting_gate_C`. Codex output cannot manufacture external usefulness. Record
an accountable approval only after a non-empty evidence document exists inside
the repository:

```console
python scripts/autopilot.py gate approve C \
  --evidence docs/evidence/gate-c.md \
  --approved-by "release council"
python scripts/autopilot.py gate status C
```

If an existing run selected work after M6, use `resume`; otherwise, after the M6
branch is reviewed, merged, and local `main` again exactly matches
`origin/main`, start the next range with:

```console
python scripts/autopilot.py run --from M7 --through M8 --push --draft-pr
```

M9 is refused because the hosted service belongs in a separate private
repository. M10 is refused until `docs/c-api-design.md` exists. Unknown or
reverse ranges are rejected before state or Git mutation.

### 26.5 Interruption and operator review

Interrupt with Ctrl-C, inspect `python scripts/autopilot.py status`, the live
diff, and `.autopilot/runs/<run-id>/`, then use
`python scripts/autopilot.py resume`. Never discard or reset incomplete work as
part of automated recovery. Before merging, review each milestone commit,
verification logs, structured review, protected-policy changes, and draft-PR
body. “Autonomous” means no repeated prompting; it does not mean bypassing
security boundaries, human merge review, or product gates. Full operational and
security guidance is in `docs/autopilot.md`.

### 26.6 Historical initial prompt (manual fallback)

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
- Do not implement the analyser, registry engine, Django, or hosted service yet.
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

### 26.7 Subsequent milestone prompt template (manual fallback)

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

### 26.8 Review prompt after each milestone (manual fallback)

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

---

## 27. Source references

These sources informed the design and should be rechecked when the relevant feature is implemented:

- [PEP 790 — Python 3.15 Release Schedule](https://peps.python.org/pep-0790/)
- [Python deprecation index](https://docs.python.org/3/deprecations/index.html)
- [PEP 387 — Backwards Compatibility Policy](https://peps.python.org/pep-0387/)
- [PEP 594 — Removing dead batteries from the standard library](https://peps.python.org/pep-0594/)
- [PEP 702 — Marking deprecations using the type system](https://peps.python.org/pep-0702/)
- [Python warnings documentation](https://docs.python.org/3/library/warnings.html)
- [Python `ast` documentation](https://docs.python.org/3/library/ast.html)
- [Python core metadata specification, including `Requires-Python`](https://packaging.python.org/en/latest/specifications/core-metadata/)
- [Python version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/)
- [LibCST metadata providers](https://libcst.readthedocs.io/en/latest/metadata.html)
- [Mypy PEP 702 diagnostics](https://mypy.readthedocs.io/en/latest/error_code_list2.html)
- [Pytest warning capture](https://docs.pytest.org/en/stable/how-to/capture-warnings.html)
- [GitHub Checks API](https://docs.github.com/en/rest/checks/runs)
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [GitHub App permission guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [GitHub webhook signature validation](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)

---

## 28. Definition of success

PyAhead succeeds when a maintainer can point it at a repository that supports Python 3.11, receive a concise and accurate timeline through later Python releases, understand exactly why each item was reported, and take action before an upgrade fails.

The initial technical success is not “many rules” or “an attractive dashboard.” It is:

- auditable registry facts;
- precise repository-specific matching;
- correct version reachability;
- deterministic reports;
- honest limitations;
- a workflow maintainers trust enough to run continuously.

That is the foundation on which dependency analysis, runtime evidence, C API expertise, and the hosted business can be built.
