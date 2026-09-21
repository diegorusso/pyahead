<p align="center">
  <a href="https://www.diegor.it/pyahead/"><img src="https://raw.githubusercontent.com/diegorusso/pyahead/main/.github/readme/mark.svg" width="72" alt=""></a>
</p>

<h1 align="center">PyAhead</h1>

<p align="center">
  <b>A little foresight for your Python code.</b><br>
  Find the CPython deprecations and removals a codebase will hit — and when — before the upgrade does.
</p>

<p align="center">
  <a href="https://pypi.org/project/pyahead/"><img src="https://img.shields.io/pypi/v/pyahead?label=PyPI&color=246449" alt="PyPI version"></a>
  <a href="https://pypi.org/project/pyahead/"><img src="https://img.shields.io/pypi/pyversions/pyahead?color=246449" alt="Supported host Python versions"></a>
  <a href="https://github.com/diegorusso/pyahead/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/diegorusso/pyahead/ci.yml?branch=main&label=CI" alt="CI status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/diegorusso/pyahead?color=246449" alt="Apache-2.0 license"></a>
</p>

<p align="center">
  <a href="https://www.diegor.it/pyahead/"><img src="https://raw.githubusercontent.com/diegorusso/pyahead/main/.github/readme/site.png" width="920" alt="The PyAhead website after scanning paramiko 2.7.2 for Python 3.9 through 3.14: 7 breaking and 1 deprecated finding, the first a base64.decodestring call marked deprecated in 3.1 and removed in 3.9, with the replacement and a link to the Python 3.9 release notes."></a>
  <br>
  <sub><a href="https://www.diegor.it/pyahead/">www.diegor.it/pyahead</a> — paramiko 2.7.2 scanned in the browser for Python 3.9 through 3.14. Nothing leaves your machine.</sub>
</p>

PyAhead scans a repository without importing or executing its code and presents
one timeline per finding: when CPython deprecated the API, when it is or will be
removed, what to use instead, and the "What's New" entry that says so. Every
rule in its registry cites the change at the version it happened.

## Try it without installing anything

[**www.diegor.it/pyahead**](https://www.diegor.it/pyahead/) scans a public
GitHub repository in your browser. PyAhead runs there as WebAssembly: the page
fetches the repository's Python files, analyses them on your machine, and
renders the report. Nothing is uploaded, nothing is stored, and no account is
needed — there is no server to send anything to.

It reads public repositories only, and fetches file by file under a cap, so a
large repository produces a scan that says it is incomplete rather than one
that looks clean. For private code, continuous scanning, or CI, install the
command below.

## Limitations — read before use

PyAhead is a public alpha. A clean scan is **not proof of compatibility**. The
bundled registry covers reviewed, statically representable Python-level entries
from selected CPython sources; it does not cover arbitrary runtime behavior,
dependencies, C extensions, reflection, generated code, or every Python API.
Run the repository's tests on every supported target interpreter as well.

The default static command does not execute target code, install target
dependencies, infer general receiver types, resolve arbitrary dynamic imports,
access the network, or send telemetry. Dependency evidence is a separate opt-in
command with explicit targets, network policy, and deadlines. Version helpers,
user-defined constants, patch-level guards, and general control flow outside
the documented lexical grammar remain unknown.
Skipped, unreadable, oversized, unparseable, or over-limit source entries make
analysis incomplete rather than silently clean. See
[all documented limitations](docs/usage.md#limitations).

## What you get

- **A timeline, not a lint.** Each finding says which Python versions it
  reaches, when the API was deprecated, when it goes away, and what replaces
  it — grouped by the version the change lands in, so the 3.13 work is
  separate from the 3.10 work.
- **Sources you can check.** The registry's 198 rules are curated from
  CPython's own release notes — every "What's New" page from 3.9 to 3.14
  censused entry by entry — and each rule links the section that announced
  the change at the version it happened.
- **Static, offline, deterministic.** LibCST parsing only: no imports, no
  execution, no network, byte-identical reports for identical input.
  Version guards (`sys.version_info`, `TYPE_CHECKING`) narrow what a finding
  reaches.
- **Made for CI.** SARIF and JSON output, a `--fail-on` gate, baselines that
  adopt existing findings without hiding them, and rule-specific inline
  suppressions that stay auditable.
- **Measured precision.** Findings are validated against the PyPI top 1000
  with a real interpreter adjudicating them; the approved record is in
  [`docs/evidence`](docs/evidence).

## Install

```console
pipx install pyahead==0.4.0
# or run without a persistent tool environment
uvx pyahead==0.4.0 --version
```

To build and install a candidate from this repository instead:

```console
uv build
pipx install dist/pyahead-0.4.0-py3-none-any.whl
```

Installing PyAhead may contact the configured package index to obtain PyAhead
and its dependencies. Running `pyahead check` itself is offline.

## Quick start

Scan a repository with an explicit inclusive policy:

```console
pyahead check . --baseline-python 3.9 --horizon-python 3.14
```

For paramiko 2.7.2 that reports eight findings, grouped by the Python version
each change lands in:

```text
PyAhead 0.4.0
Policy: Python 3.9 through 3.14
Registry: 2026.09.20 (15fc94fd4d2b)

Python 3.9 — 2 upgrade blockers
  CPY0178  paramiko/py3compat.py:40:19  base64.encodestring (breaking; high confidence)
    base64.encodestring is removed
    Match evidence: qualified_names=[base64.encodestring]; reference_context=read; resolution=exact-import
    Reachable targets: 3.9, 3.10, 3.11, 3.12, 3.13, 3.14
    Usage contexts: runtime
    States: breaking on 3.9 through 3.14
    Timeline: deprecated in 3.1 (released); removed in 3.9 (released)
    Guidance: Call base64.encodebytes().
    Remediation documentation: https://docs.python.org/3.9/whatsnew/3.9.html#removed
    Source: What's New in Python 3.9 — Removed — https://docs.python.org/3.9/whatsnew/3.9.html#removed

  ...

Python 3.10 — 2 compatibility findings
  CPY0153  paramiko/py3compat.py:162:30  collections.Callable (breaking; high confidence)
    collections.Callable is removed
    Match evidence: qualified_names=[collections.Callable]; reference_context=read; resolution=exact-import
    Reachable targets: 3.9, 3.10, 3.11, 3.12, 3.13, 3.14
    Usage contexts: runtime, typing
    States: deprecated on 3.9; breaking on 3.10 through 3.14
    Timeline: deprecated in 3.3 (released); removed in 3.10 (released)
    Guidance: Import Callable from collections.abc.
    Remediation documentation: https://docs.python.org/3.9/library/collections.html
    Source: Python 3.9 collections documentation — https://docs.python.org/3.9/library/collections.html
    Source: What's New in Python 3.10 — Removed — https://docs.python.org/3.10/whatsnew/3.10.html#removed

  ...

Result: 8 findings (7 breaking, 1 deprecated); 84 files analyzed; 0 files incomplete.
```

Or declare strict configuration in `pyproject.toml`:

```toml
[tool.pyahead]
baseline-python = "3.11"
horizon-python = "3.14"
include = ["src/**/*.py", "tests/**/*.py"]
exclude = ["src/generated/**"]
source-roots = ["src"]
minimum-confidence = "high"
fail-on = "breaking"
respect-gitignore = true
show-unscheduled = true
```

Then run:

```console
pyahead check
```

When the baseline is omitted, PyAhead can infer the lowest supported registry
minor from `[project].requires-python` and records that provenance in the
report. It never infers the baseline from the host interpreter.

Exit code 1 means an unsuppressed finding met the selected `fail-on` gate; 2
means invalid command, configuration, or registry input; 3 means analysis was
incomplete; and 4 means an unexpected internal failure. Exit 0 means only that
the configured static scan completed without a gated finding.

## Status

Version `0.4.0` is the current public-alpha release. It provides deterministic
text, JSON, and SARIF 2.1.0 reports; strict project configuration; baselines and
rule-specific suppressions; version-guard and typing-context reachability; a
source-linked, coverage-audited CPython registry; opt-in pytest warning
evidence; and opt-in dependency metadata and isolated-resolution evidence.

PyAhead supports host Python 3.11 through 3.14 on Linux, macOS, and Windows.
The host interpreter is independent of the baseline and horizon Python versions
being assessed. Python 3.15 prerelease CI is advisory until support is claimed.

The first opt-in dynamic provider collects deprecation warnings with an explicit
pytest plugin in the repository owner's CI, then merges its versioned artifact
with `pyahead check --evidence`. Observed warnings stay separate from static
inference; unmatched and different-commit evidence remains visible. PyAhead
does not run those tests in a hosted scanner.

`pyahead dependencies` separately inspects supplied wheel, source-distribution,
or Core Metadata files without executing build backends. An optional isolated
`uv` adapter has explicit offline/online and timeout controls. Dependency
results distinguish exact declared incompatibility, independently corroborated
constraint failures, closed-wheelhouse target-artifact absence, sample-level
artifact availability, and incomplete evidence. Direct artifact samples remain
compatibility unverified until a complete resolution closes the relevant
inventory, except that an exact, final `Requires-Python` exclusion remains
declared incompatible.

Gate B is exercised by repository tests and clean wheel/sdist installation.
Gate C requires evidence from 100 active public repositories, at least 95%
sampled precision for high-confidence findings, false-positive regressions,
retained limitations, and accountable product-owner approval. Continuous-use
adoption is measured after the alpha is publicly available; it is not a
prerequisite for the M7–M8 dynamic-evidence work.

## CI and review workflows

Write SARIF or deterministic JSON atomically:

```console
pyahead check --format sarif --output pyahead.sarif
pyahead check --format json --output pyahead.json --fail-on never
```

Adopt existing findings without hiding them from reports:

```console
pyahead baseline create --output .pyahead-baseline.json
pyahead check --baseline-file .pyahead-baseline.json --fail-new-only
```

Inline suppressions are rule-specific and stay auditable:

```python
import cgi  # pyahead: ignore[CPY0001] -- migration tracked in issue 42
```

Unknown rule IDs remain visible diagnostics. Report, baseline, and output paths
must remain beneath the selected project root, including through symlinks.

Inspect the bundled registry without scanning a repository:

```console
pyahead registry validate
pyahead registry coverage
pyahead registry list
pyahead explain CPY0001
```

## Documentation

- [User guide](docs/usage.md)
- [Static report JSON Schema](docs/schema/report-v1.json)
- [Registry authoring](docs/registry-authoring.md)
- [Security and privacy](docs/security-and-privacy.md)
- [Performance budgets](docs/usage.md#performance)
- [100-repository corpus and false-positive review](docs/corpus-review.md)
- [PyPI top-1000 precision validation](docs/pypi-validation.md)
- [Release process](docs/releasing.md)
- [Changelog](CHANGELOG.md)
- [Product and technical design](docs/design.md)

## Development

PyAhead requires Python 3.11 or newer. The locked development environment uses
[uv](https://docs.astral.sh/uv/):

```console
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src scripts
uv run pytest
uv build
uv run pyahead --version
uv run python scripts/install_smoke.py --dist-dir dist --kind wheel
uv run python scripts/install_smoke.py --dist-dir dist --kind sdist
uv run python scripts/benchmark.py --repeat 1 --output -
git diff --check
```

Project-wide branch coverage is enforced at 90%. A focused pytest invocation
may therefore fail only because it did not cover the whole package; use
`--no-cov` for isolated iteration, then run the complete suite.

Read [the contribution guide](docs/contributing.md) before proposing a change.

## License

PyAhead is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
