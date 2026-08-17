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
pipx install pyahead==0.1.0a2
uvx pyahead==0.1.0a2 --version
```

For a repository build:

```console
uv build
python -m venv .pyahead-smoke
.pyahead-smoke/bin/python -m pip install dist/pyahead-0.1.0a2-py3-none-any.whl
.pyahead-smoke/bin/pyahead --version
```

On Windows, the last two paths are `.pyahead-smoke\Scripts\python.exe` and
`.pyahead-smoke\Scripts\pyahead.exe`. Installation can contact a configured
package index for dependencies. Scanning is offline.

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
includes and excludes. Excludes win. Directory symlinks are not followed, file
symlinks may not escape the selected root, and only regular files within the
configured size limit are parsed. Discovery stops safely at 100,000 selected
source entries. Exceeding that fixed public-alpha bound produces `PYA1006`,
returns an incomplete scan, and analyzes none of the truncated set so an unseen
project module cannot create false high-confidence resolution evidence.

Relative report-output, baseline-input, baseline-creation, and configuration
paths are resolved beneath the selected root. Logical `..` escapes and symlink
escapes are rejected. Persistent output uses repository-relative POSIX paths.

## Findings and confidence

One finding represents one source construct and its complete reachable version
timeline. Impact, match confidence, and per-event registry certainty remain
separate. High confidence is the default. Medium-confidence literal dynamic or
ambiguous imported-name evidence is available with:

```console
pyahead check --minimum-confidence medium
```

The analyzer understands import-derived aliases, ordinary lexical shadowing,
common `sys.version_info` comparisons, three-valued Boolean guards, nested
`if`/`elif` branches, `typing.TYPE_CHECKING`, and `.pyi` typing contexts.
Unknown conditions conservatively enter both branches.

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
change a fingerprint.

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
