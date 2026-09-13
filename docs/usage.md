# User guide

PyAhead scans Python source for reviewed compatibility changes and reports when
each matched construct becomes deprecated, risky, or breaking across an
inclusive baseline-to-horizon Python range. It never treats a static clean scan
as proof that a repository works on a target interpreter.

## Installation and supported hosts

The public alpha supports CPython 3.11, 3.12, 3.13, and 3.14 as host
interpreters on Linux, macOS, and Windows. The host is the interpreter running
PyAhead; target versions are the policy being assessed and do not need to be
installed locally.

Use an isolated tool environment after publication:

```console
pipx install pyahead==0.2.1
uvx pyahead==0.2.1 --version
```

For a repository build:

```console
uv build
python -m venv .pyahead-smoke
.pyahead-smoke/bin/python -m pip install dist/pyahead-0.2.1-py3-none-any.whl
.pyahead-smoke/bin/pyahead --version
```

On Windows, the last two paths are `.pyahead-smoke\Scripts\python.exe` and
`.pyahead-smoke\Scripts\pyahead.exe`. Installation can contact a configured
package index for dependencies. Scanning is offline.

## Python API and compatibility

The typed public-alpha library surface is intentionally narrow:

```python
from pathlib import Path

from pyahead.analysis import ScanReport, ScanRequest, scan
from pyahead.registry import Registry, RegistryError, load_registry

request = ScanRequest(root=Path.cwd(), baseline_python="3.11", horizon_python="3.14")
report: ScanReport = scan(request)
registry: Registry = load_registry()
```

PyAhead `0.x` releases may make documented incompatible API changes between
minor releases. Patch releases preserve this import surface and the documented
report schema unless a security or correctness defect requires a clearly
recorded exception. Parser, resolver, process, LibCST, automation, and other
unlisted internals are not public APIs. Existing compatibility exports remain
available until a separate public-API decision documents their removal.

Static JSON reports conform to the closed
[`report-v1.json`](schema/report-v1.json) schema. Matcher and inference
`evidence` maps are the one documented extensibility point: their keys may grow,
while each value remains a string or list of strings. Structural report objects
reject unknown properties. The same schema is bundled as the package resource
`pyahead.data.schema/report-v1.json` for offline consumers.

## Policy and first scan

The baseline is the oldest supported Python minor. The horizon is the newest
minor to assess. Both are inclusive:

```console
pyahead check . --baseline-python 3.11 --horizon-python 3.14
```

Policy precedence is command line, `[tool.pyahead]`, then baseline inference
from `[project].requires-python`. The default horizon is inferred from bundled
release metadata. PyAhead reports provenance and rejects versions outside the
registry analysis window.

A strict project configuration can declare the complete policy:

```toml
[tool.pyahead]
baseline-python = "3.11"
horizon-python = "3.14"
include = ["src/**/*.py", "tests/**/*.py"]
exclude = ["src/generated/**"]
source-roots = ["src"]
respect-gitignore = true
minimum-confidence = "high"
fail-on = "breaking"
show-unscheduled = true
max-file-size-bytes = 2097152

[tool.pyahead.per-file-ignores]
"tests/fixtures/**" = ["CPY0001"]
```

Unknown keys are errors. Command-line lists replace configured lists. Explicit
`source-roots = []` is authoritative and disables project-module shadow
inference; it does not fall back to conventional root and `src` layouts.

## Discovery and safety

By default PyAhead discovers `.py` and `.pyi` files, applies built-in
exclusions, respects hierarchical `.gitignore` rules, then applies configured
includes and excludes. Excludes win. Directory symlinks are not followed and
source-file symlinks are retained only as opaque incomplete module evidence;
their bytes are never parsed. Only regular files within the configured size
limit are parsed. Discovery stops safely at 100,000 selected
source entries. Exceeding that fixed public-alpha bound produces `PYA1006`,
returns an incomplete scan, and analyzes none of the truncated set so an unseen
project module cannot create false high-confidence resolution evidence.

Relative report-output, baseline-input, baseline-creation, and configuration
paths are resolved beneath the selected root. Logical `..` escapes and symlink
escapes are rejected. Source, `.gitignore`, configuration, baseline, pytest
evidence, and dependency inputs are read through pinned root-relative
descriptors or native Windows handles. A selected `pyproject.toml` is capped at
2 MiB and its one parsed byte snapshot supplies both `[tool.pyahead]` and
`project.requires-python` for the scan. Persistent output uses
repository-relative POSIX paths.

## Findings and confidence

One finding represents one source construct and its complete reachable version
timeline. Impact, match confidence, and per-event registry certainty remain
separate. High confidence is the default. Medium-confidence literal dynamic or
ambiguous imported-name evidence is available with:

```console
pyahead check --minimum-confidence medium
```

The analyzer understands import-derived aliases, ordinary lexical shadowing,
common `sys.version_info` comparisons (including the `sys.version_info[0]`
major-only Python 2/3 split), three-valued Boolean guards, nested
`if`/`elif` branches, `typing.TYPE_CHECKING`, `.pyi` typing contexts, and the
exact removal-safe `hasattr(imported_module, "attribute") and ...` short-circuit
shape. Unknown conditions conservatively enter both branches. The annotation
of a local variable inside a function body, which Python never evaluates, is
a typing-only reference, so a runtime-only rule does not report it;
parameter, return, class-body and module-level annotations remain runtime
references, including under `from __future__ import annotations`, because
runtime introspection can still evaluate them.

An exact import-derived `sys.path.insert` or `sys.path.append` plus a matching
nested repository module produces visible `PYA2001` module-resolution evidence.
Prepending lowers the origin to medium confidence. Appending preserves a
standard-library module finding only for target versions where that module
still exists; PyAhead does not pretend the post-removal import remains standard
library code. Path expressions are not executed or evaluated.

Explain registry evidence without scanning:

```console
pyahead registry validate
pyahead registry coverage
pyahead registry list
pyahead explain CPY0001
```

Every rule includes stable sources, timeline certainty, matchers, and
remediation. Coverage output distinguishes implemented detection from partial,
dynamic-only, C-API, duplicate, and out-of-scope source entries.

## Gates, baselines, and suppressions

`--fail-on` accepts `never`, `breaking`, `risk`, `deprecated`, or `any`.
The gate order is informational, deprecated, risk, then breaking. Findings stay
in the report even when they do not meet the gate.

Adopt known findings into a deterministic baseline:

```console
pyahead baseline create --output .pyahead-baseline.json
pyahead check --baseline-file .pyahead-baseline.json --fail-new-only
```

Fingerprints survive unrelated line insertion. File moves, containing-scope
renames, and inserting a preceding same-rule occurrence in the same scope can
change a fingerprint. Baseline documents are capped at 32 MiB and 100,000
findings. Each variable created-by, registry-revision, rule-ID, path, or subject
field is capped at 4,096 characters. Creation and ingestion use the same limits.

Suppress one logical statement with an exact rule ID:

```python
import cgi  # pyahead: ignore[CPY0001] -- migration tracked in issue 42
```

Configured per-file ignores are also rule-specific. Unknown IDs produce
diagnostics, and suppressions never erase incomplete-analysis diagnostics.

## Reports and CI

Text is the default. JSON and SARIF 2.1.0 are deterministic and safe to redirect
or write atomically:

```console
pyahead check --format json --output pyahead.json --fail-on never
pyahead check --format sarif --output pyahead.sarif
```

`--output -` writes to standard output. Errors that occur before a machine
report exists go to standard error and do not emit partial JSON or SARIF.
SARIF uses stable rule IDs, relative paths, exact regions, and PyAhead
fingerprints. Whether GitHub accepts a SARIF upload depends on repository and
plan settings; PyAhead does not assume code scanning is enabled.

Human-readable output escapes embedded line breaks, terminal controls, Unicode
line and paragraph separators, and direction-changing format controls in
repository-, registry-, evidence-, and diagnostic-provided values. Escapes are
shown as visible `\uXXXX` or `\UXXXXXXXX` text; normal printable Unicode and
PyAhead's own report line structure remain unchanged. JSON and SARIF preserve
their machine data rather than applying terminal escaping.

### Pytest warning evidence in user CI

PyAhead's first observed-evidence provider is an explicit pytest plugin. Tests
and imports run only in the repository owner's CI job; `pyahead check` still
does not execute target code, and no hosted scanner participates. Load the
plugin explicitly from an environment containing both PyAhead and pytest (the
plugin does not make pytest a PyAhead runtime dependency), and make pytest show
the warning categories to collect:

```console
pytest -p pyahead.pytest_plugin \
  --pyahead-evidence pyahead-pytest-warnings.json \
  --pyahead-source-commit "$GITHUB_SHA" \
  -W default::DeprecationWarning \
  -W default::PendingDeprecationWarning

pyahead check . \
  --baseline-python 3.11 \
  --horizon-python 3.14 \
  --evidence pyahead-pytest-warnings.json \
  --source-commit "$GITHUB_SHA" \
  --format json \
  --output pyahead.json
```

`--pyahead-source-commit` and `--source-commit` can be omitted when
`PYAHEAD_COMMIT`, `GITHUB_SHA`, or `CI_COMMIT_SHA` supplies the same full
40- or 64-character commit. PyAhead never invokes Git to guess this identity.
Evidence paths must remain beneath the selected project root. The artifact is
strict versioned JSON described by
[`schema/evidence-v1.json`](schema/evidence-v1.json).

A current warning is linked as corroboration only when its message identifies a
static finding's rule or subject, its repository location overlaps that finding,
and its CPython version agrees with the configured policy and finding timeline.
Co-location without subject correlation is labelled `location-only`; an
observed environment or timeline contradiction is labelled `conflicts`. Both
remain in the unmatched warning list rather than being counted as duplicate
evidence. The finding count and gate remain static. Evidence from another commit
remains visible as `stale`, is never linked to current findings, and records both
commit identities. Text and JSON reports distinguish inferred from observed
evidence; SARIF ingestion is deliberately not offered in M7 because its
dynamic-evidence representation is not yet defined.

One minimal GitHub Actions job sequence is:

```yaml
- name: Run tests and collect PyAhead warnings
  run: >-
    pytest -p pyahead.pytest_plugin
    --pyahead-evidence pyahead-pytest-warnings.json
    --pyahead-source-commit "$GITHUB_SHA"
    -W default::DeprecationWarning
    -W default::PendingDeprecationWarning

- name: Merge static and observed evidence
  if: ${{ always() }}
  run: >-
    pyahead check .
    --baseline-python 3.11
    --horizon-python 3.14
    --evidence pyahead-pytest-warnings.json
    --source-commit "$GITHUB_SHA"
    --format json
    --output pyahead.json
```

The plugin finalizes its artifact even when pytest reports test failures. The
artifact records pytest's exit code and collected-test count; it does not claim
that warning-free tests cover every execution path. During collection it retains
at most 10,000 unique warning records and 8 MiB of normalized warning text;
every omitted occurrence is counted without retaining its record. Artifacts are
capped at 16 MiB. If the deterministic warning list cannot fit, the serializer
measures it incrementally, retains the largest fitting prefix, and records
`warnings_complete: false` plus the omitted occurrence count in
`warnings_dropped`; ingestion applies the same byte cap.
The evidence contract also permits `warnings_complete: false` with zero dropped
records when a provider cannot prove that warning capture itself was complete.
PyAhead's pytest plugin fails with a usage error instead of writing an artifact
when pytest warning capture is unavailable or when pytest-xdist is active; xdist
aggregation is not yet supported. `--disable-warnings` only hides pytest's
terminal summary and remains compatible with evidence capture.
User-configured warning filters remain user policy: completeness describes the
filtered warning stream that pytest was configured to capture.
During `pytest_configure`, the plugin atomically empties the single effective,
root-bounded output before it validates capture and xdist policy. Loop-on-fail
bypasses pytest's ordinary configure path, so its refusal performs the same
rooted tombstone immediately before the loop controller can start. Ordinary
successful and test-failing sessions replace that tombstone with a schema-valid
artifact at session finish. Failures before either boundary do not run PyAhead's
rooted invalidation step and cannot create a new artifact.
One scan accepts at most 64 evidence paths, 64 MiB combined, and 100,000
warning records across all selected artifacts. Relationship evaluation is
indexed by repository path and source interval, with explicit aggregate caps
of 1,000,000 candidate checks and 200,000 emitted relationship records.
Inputs exceeding any aggregate cap fail as invalid evidence instead of risking
unbounded memory use or silently dropping observations.

### Dependency compatibility evidence

Dependency analysis is a separate opt-in command. It does not change static
findings or make `pyahead check` network-visible:

```console
pyahead dependencies --format json --output pyahead-dependencies.json
```

JSON output follows the closed, versioned
[`dependency-report-v1.json`](schema/dependency-report-v1.json) schema.
The schema validates the complete document structure, limits, and allowed status
shapes. Cross-row package identity and PEP 440 constraint satisfiability cannot
be expressed by portable JSON Schema, so PyAhead recomputes those invariants at
the trusted model-to-document boundary before emitting JSON. Schema validation
alone must not turn an unowned or modified report into compatibility evidence.

Configuration must explicitly distinguish an application from a library.
Applications use exact `==` pins because the configured lock set and deployment
target are authoritative. Libraries may use ranges and repeat targets to
describe their supported matrix; one library lock is not treated as universal
evidence.

```toml
[tool.pyahead.dependencies]
project-kind = "application"
requirements = ["httpx==0.28.1"]
extras = []
metadata = [
  "wheelhouse/httpx-0.28.1-py3-none-any.whl",
]
resolve = false
network = false
timeout-seconds = 30
resolver = "uv"

[[tool.pyahead.dependencies.targets]]
name = "cpython-3.13-linux-x86_64"
python-full-version = "3.13.7"
implementation-name = "cpython"
implementation-version = "3.13.7"
os-name = "posix"
sys-platform = "linux"
platform-machine = "x86_64"
platform-python-implementation = "CPython"
platform-system = "Linux"
platform-release = ""
platform-version = ""
compatible-tags = [
  "cp313-cp313-manylinux_2_17_x86_64",
  "py3-none-any",
]
resolver-platform = "x86_64-manylinux_2_17"
```

Every marker value comes from the declared target. PyAhead does not fill marker
fields from the host running the command. Each result names the exact package
version, metadata version, repository-relative artifact path, archive metadata
member, SHA-256 digest, `Requires-Python`, evaluated `Requires-Dist` entries, and
metadata artifact IDs used for the conclusion.

Windows targets use the marker values reported by Windows CPython (for example,
`platform-machine = "AMD64"` with
`resolver-platform = "x86_64-pc-windows-msvc"`). Direct metadata and marker
assessment uses those declared values. The current `uv` target interface cannot
represent that Windows `platform_machine` value faithfully, so optional
resolution for such a target is explicitly `unverified` instead of substituting
the Unix-style `x86_64` value.

An active configured requirement is joined to evidence by normalized package
name, requested extras, and version constraint. Missing names, wrong application
pins, out-of-range library versions, and unprovided extras are incomplete
evidence unless a complete resolver result accounts for the requirement using
the exact selected metadata. A resolver-selected base distribution does not
prove an extra that its `Provides-Extra` fields do not declare.
PEP 440 `==1.0` also admits local versions such as `1.0+cpu`. If more than one
supplied version satisfies an application pin, direct evidence is unverified
until exact resolver provenance selects one; an explicit `==1.0+cpu` pin is not
ambiguous with the public version.
Only metadata selected for the declared target can provide an extra or a
transitive edge; a same-version wheel for another platform cannot complete the
evidence. Root `extras` select those marker contexts exclusively. The base
marker context is evaluated only when no root extra is selected.
Unrelated supplied metadata remains listed but is not assessed as if it were a
declared dependency.

Every active `Requires-Dist` entry is also reported with the exact parent
package version, application pins, inspected metadata IDs, and resolver-selected
versions used to cover it. In application mode, the entry must match one
simultaneously consistent exact pin plus inspected metadata, or a complete
resolver result. In library mode, a supplied artifact set is not a universal
solve: active transitive requirements require complete resolver evidence.
Requested dependency extras are propagated through inspected metadata to a
fixed point, so an optional dependency of a transitive extra remains visible.
The configured `extras` list supplies the root project's marker context; it
does not implicitly request the same-named extra from every dependency. Package
extras activate only through an explicit `name[extra]` requirement. With a
complete resolution, PyAhead follows the reachable selected dependency
closure using only each resolver package's exact `metadata_used` artifact IDs;
unselected same-version artifacts cannot contribute dependency edges. A
resolver package outside that root-reachable closure invalidates an otherwise
successful result. An empty package selection is valid when every configured
requirement marker is inactive. Missing selected transitive packages and
uncorroborated conflict claims make the report incomplete; a resolver-backed,
independently corroborated active root conflict is complete failure evidence.

Direct inspection accepts wheels, `.tar.gz`/`.zip` source distributions with a
single top-level, identity-matching `<name>-<version>/PKG-INFO` agreeing with
both the filename and Core Metadata identity, and standalone Core Metadata
files. It reads archive members as data, never extracts them, imports package
code, or invokes a PEP 517 build backend. A matching wheel records
`artifact_availability` as `available`. When no declared target tag matches,
that field is `unavailable`; a supplied sdist instead records
`source-build-possible` without attempting or claiming that the source builds.
Those values describe only the supplied sample. Without a complete resolution,
both application and library assessments remain compatibility `unverified`,
including when the sample contains a matching wheel. A wrong-target wheel or
sdist-only sample therefore retains its precise availability value without
becoming a compatibility failure. Complete `compatible` or
`artifact-unavailable` status requires the resolution evidence described below.
`Requires-Python` exclusion is reported separately as `declared-incompatible`.
An sdist or standalone metadata field declared `Dynamic` is not treated as a
final compatibility declaration. A wheel that retains source-only `Dynamic`
fields is malformed evidence and is reported incomplete.
Core Metadata older than 2.2 cannot declare which source fields are dynamic.
For an sdist or provenance-unknown standalone metadata file, PyAhead therefore
treats its `Requires-Python`, `Requires-Dist`, and `Provides-Extra` fields as
implicitly dynamic. The same legacy fields in an already-built wheel remain
final wheel metadata.

Compressed input size, ZIP central-directory member counts and declared
expanded sizes, physical tar headers and control records, incrementally
decompressed tar bytes, logical tar member counts, retained tar member objects,
and the selected metadata payload are bounded before they can become unbounded
object graphs or decompression work. Archive reads share a 1 GiB expanded-byte
budget across the inspection, counting repeated tar passes. ZIP LZMA, multi-disk,
and ZIP64 containers are reported as incomplete unsupported evidence. One run
accepts at most 256
metadata inputs and 512 MiB of artifact bytes in aggregate; each artifact is
also capped at 128 MiB and each selected Core Metadata payload at 2 MiB.
Configured and wheel-declared compatibility tags accept at most 256 compressed
values and 4,096 expanded tags; compressed Cartesian products are counted
before `packaging` expands them.
Root marker evaluation accepts at most 256 configured extras, and each Core
Metadata artifact may declare at most 256 `Provides-Extra` fields. Each
configured or metadata requirement may request at most 256 extras. Inspected
artifacts may contain at most 100,000 `Requires-Dist` fields in aggregate, and a
run is capped at 1,000,000 dependency-evaluation work units. The shared counter
includes target/extra markers, artifact/constraint and tag correlation, and
repeated fixed-point evaluations while transitive extras propagate.
The dependency TOML document is capped at 2 MiB before parsing.
Configuration and metadata inputs are opened relative to pinned repository
directory descriptors or Windows handles; mutable ancestors, symlinks, and
reparse points cannot redirect a read outside the selected root. In-place input
changes during a read are rejected rather than combining bytes from different
file states.

Wheel availability additionally requires a matching top-level `.dist-info`
directory, `WHEEL` and `RECORD` members, a supported major `Wheel-Version`, a
boolean `Root-Is-Purelib`, and exact agreement between the filename and internal
`Tag` fields. A direct URL in `Requires-Dist` is rejected as incomplete evidence
before resolver discovery; configured dependency metadata cannot introduce an
undeclared `file:`, HTTP, or HTTPS source.

Resolver use must be requested with `resolve = true` or `--resolve`. Offline is
the default. The adapter copies only the configured artifacts into a temporary
wheelhouse, disables indexes, caches, configuration discovery, source builds,
and Python downloads, and records the exact `uv` version and selected package
versions. Online resolution additionally requires both `network = true` and an
explicit credential-free `index-url`; `--network` cannot fall back to an
ambient index. `--no-network` can override and disable configured online use.
An index URL may be predeclared while `network = false`; it remains disabled
unless configuration or the explicit CLI override also enables network use.
Each resolver process has a finite `timeout-seconds` deadline of at most 86,400
seconds, overridable by `--timeout-seconds` within the same bound. Resolver
descendants are contained in a dedicated POSIX process group or Windows Job
Object and terminated during cleanup. On Windows,
the resolver remains suspended until Job assignment succeeds. Stdout and stderr
are retained separately and capped at
4 MiB each. PyAhead reads at most 8 MiB from the result file, rejects a larger
file, and accepts at most 10,000 unique package records. The read limit is not
an operating-system disk quota while `uv` writes its temporary result. A
timeout, undecodable output, output overflow, malformed result, or output pipe
that does not close produces incomplete evidence rather than a compatibility
claim. Retained diagnostics are stripped of control characters and isolated
workspace paths.

The `uv` adapter resolves only canonical CPython targets whose implementation,
platform marker fields, compatible tags, and `resolver-platform` agree. A PyPy
target or non-empty platform release/version marker is explicitly unverified by
the adapter rather than resolved with host defaults. Contradictions among the
declared Python version, implementation, platform markers, compatible tags, and
`resolver-platform` are rejected before either direct assessment or resolution.
Interpreter versions use exactly three release components, Python targets must
have major version 3, and epoch, local, post, and development segments are
rejected; prerelease interpreter versions remain representable.
Successful local resolution parses `uv`'s `pylock.toml` selection and associates
only the exact selected wheel's inspected artifact ID. An online selection
without directly inspected exact-distribution provenance remains unverified; it
is never attributed to a same-name/version local artifact. Online resolution
may contact artifact or redirect hosts selected by the configured index; the
index URL is not a host-level egress allowlist.

An offline application wheelhouse becomes closed compatibility evidence only
after a recognized resolver completes the configured exact-pin resolution
attempt. A missing package, missing pinned version, or lack of a
target-compatible supplied wheel is then complete `artifact-unavailable`
evidence. Without completed resolution, configured metadata inputs may be
partial, so matching and unsuitable direct samples remain unverified. A
configured library artifact sample is not a complete platform inventory, even
for an exact requirement or in metadata-only mode. A library public equality
such as `==1.0` also admits unseen local versions and cannot make a sampled
exclusion definitive; an equality with an explicit local segment names one
version. When complete resolution selects another compatible artifact, the
unsuitable sample does not override that result. Resolver text is not enough by
itself to prove a conflict:
`resolution-failed` requires reviewed unsatisfiable-output grammar from a
recognized exact `uv` version, excludes availability and Python-version
diagnostics, and is accepted only when active exact or simple bounded
constraints independently contradict one another. Uncorroborated transitive
solver text, and missing or unreachable distributions from an online index,
remain `unverified` operational evidence.
The reviewed failure shape is exact: the version probe emits only its canonical
stdout line, while resolution exits 1 with empty stdout and the diagnostic on
stderr. An injected adapter, an unexpected exit code, or output on another stream
cannot establish a compatibility failure.
A complete negative resolver status applies only to the independently
corroborated root group. It does not verify unrelated roots or transitive
requirements; any such incomplete evidence keeps exit code 3 precedence.
Repository CI pins `uv 0.11.21` for the real offline regression. Other versions
remain unverified unless their diagnostic series is in the reviewed allowlist.

The result categories are intentionally not interchangeable:

- `declared-incompatible`: exact metadata `Requires-Python` excludes the target;
- `resolution-failed`: versioned resolver evidence confirms independently
  contradictory active constraints;
- `artifact-unavailable`: a closed application wheelhouse contains no supplied
  package, pinned version, or wheel matching the declared target tags, while a
  source build may or may not remain possible;
- `unverified`: metadata, resolver identity, or resolver execution was
  unavailable; and
- `timed-out`: the deadline expired, producing incomplete evidence rather than
  a compatibility failure.

Dependency exit code 1 means complete incompatible dependency evidence was
found. Exit code 3 means some dependency evidence is incomplete, including a
timeout or unverified metadata, and takes precedence over compatibility
findings. There is no dependency equivalent of `--allow-incomplete`.

Exit codes are stable:

| Code | Meaning |
| ---: | --- |
| 0 | Complete scan; no finding met the selected gate. |
| 1 | Complete scan; at least one finding met the gate. |
| 2 | Invalid command, configuration, path, or registry input. |
| 3 | Analysis was incomplete. |
| 4 | Unexpected internal failure. |

`--allow-incomplete` permits exit 0 or 1, but the report remains visibly
incomplete. Do not use it to claim compatibility.

## Performance

Checked targets and regression ceilings live in
`scripts/performance-budgets.json`. The benchmark generates source in temporary
directories, launches the real CLI, measures wall time, records peak resident
memory where the host exposes it, and exits nonzero when a measurement exceeds
the checked regression ceiling. Even `--repeat 1` compares two independently
generated reports; the extra run checks determinism but does not alter the one
requested timing sample. Its JSON separately records whether the design target
was met, so a passing regression check cannot be mistaken for proof that the
target is already satisfied:

```console
uv run python scripts/benchmark.py --repeat 3 --output benchmark-results.json
```

The initial four-core development-machine targets are under 500 ms for startup
plus one file, under 5 seconds for 1,000 ordinary files, and under 30 seconds
plus 1 GiB peak RSS for 10,000 ordinary files. Linux CI is the authoritative
memory measurement; platforms without standard-library peak-RSS support record
that memory was not measured. The benchmark does not execute target code and
does not include repository acquisition time. The first M6 baseline may exceed
the time targets; those misses remain visible while the regression ceilings
prevent further silent degradation.

## Limitations

The public alpha deliberately does not:

- prove runtime, test, dependency-resolution, packaging, or platform
  compatibility;
- execute or import target code, install target dependencies, or use the
  network during `check`;
- infer general Python types or arbitrary dynamic imports and reflection;
- understand user-defined version helpers, patch-level guards, or general
  interprocedural control flow;
- evaluate arbitrary `sys.path` expressions or prove that a path-mutating
  helper executes;
- analyze C extensions or cover every CPython and third-party compatibility
  change;
- rewrite source, open pull requests, or replace Ruff, pyupgrade, a type
  checker, or a real interpreter test matrix.

Registry coverage is limited to selected reviewed sources and matcher shapes.
Receiver-type-dependent entries are explicitly partial rather than guessed.
Generated, ignored, oversized, unreadable, and unparseable source may be absent;
eligible failures make the scan incomplete. Consult `registry coverage`, the
report diagnostics and inferences, and the exact registry revision before
drawing conclusions.

## Privacy and troubleshooting

`pyahead check` has no telemetry and performs no network operations. Reports
contain repository-relative locations, matched subjects, structured binding
evidence, and rule sources; those can still reveal private project structure.
Treat reports according to the repository's sensitivity.

If a finding is surprising, run `pyahead explain RULE_ID`, inspect its match
evidence and reachability, and reduce the case to a positive or negative
fixture. If a scan is incomplete, resolve every diagnostic rather than relying
on a clean summary. See [security and privacy](security-and-privacy.md) and the
[corpus review protocol](corpus-review.md).
