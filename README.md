# PyAhead

PyAhead is an evidence-backed Python compatibility forecaster. It scans a
repository without importing or executing its code, then presents one timeline
for each known CPython deprecation, removal, call change, or behavior change that
matches the source.

## Limitations — read before use

PyAhead is a public alpha. A clean scan is **not proof of compatibility**. The
bundled registry covers reviewed, statically representable Python-level entries
from selected CPython sources; it does not cover arbitrary runtime behavior,
dependencies, C extensions, reflection, generated code, or every Python API.
Run the repository's tests on every supported target interpreter as well.

The alpha does not execute target code, install target dependencies, infer
general receiver types, resolve arbitrary dynamic imports, access the network,
or send telemetry. Version helpers, user-defined constants, patch-level guards,
and general control flow outside the documented lexical grammar remain unknown.
Skipped, unreadable, oversized, unparseable, or over-limit source entries make
analysis incomplete rather than silently clean. See
[all documented limitations](docs/usage.md#limitations).

## Status

Version `0.1.0a2` is the first public-alpha candidate. It provides deterministic
text, JSON, and SARIF 2.1.0 reports; strict project configuration; baselines and
rule-specific suppressions; version-guard and typing-context reachability; and a
source-linked, coverage-audited CPython registry.

PyAhead supports host Python 3.11 through 3.14 on Linux, macOS, and Windows.
The host interpreter is independent of the baseline and horizon Python versions
being assessed. Python 3.15 prerelease CI is advisory until support is claimed.

Gate B is exercised by repository tests and clean wheel/sdist installation.
Gate C remains external work: 100 active public repositories, at least 95%
sampled precision for high-confidence findings, false-positive regressions, and
ten maintainers willing to run PyAhead continuously.

## Install

After the alpha is published, install it in an isolated tool environment:

```console
pipx install pyahead==0.1.0a2
# or run without a persistent tool environment
uvx pyahead==0.1.0a2 --version
```

Before publication, build and install the candidate from this repository:

```console
uv build
pipx install dist/pyahead-0.1.0a2-py3-none-any.whl
```

Installing PyAhead may contact the configured package index to obtain PyAhead
and its dependencies. Running `pyahead check` itself is offline.

## Quick start

Scan a repository with an explicit inclusive policy:

```console
pyahead check . --baseline-python 3.11 --horizon-python 3.14
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
- [Registry authoring](docs/registry-authoring.md)
- [Security and privacy](docs/security-and-privacy.md)
- [Performance budgets](docs/usage.md#performance)
- [100-repository corpus and false-positive review](docs/corpus-review.md)
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
uv run mypy src
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
The separate milestone controller is documented in [docs/autopilot.md](docs/autopilot.md).

## License

PyAhead is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
