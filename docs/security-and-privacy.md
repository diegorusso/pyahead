# Security and privacy

This document describes the public-alpha CLI and repository-review tooling. It
does not grant future hosted or dynamic-evidence components any authority.

## Default scan boundary

`pyahead check` parses selected source as data. It does not import target
modules, execute target configuration, install target dependencies, invoke
build backends, run tests, access the network, or send telemetry. YAML is loaded
with safe parsing and registry entries cannot name arbitrary executable matcher
code.

The scanner rejects root escapes, does not follow directory symlinks, rejects
file-symlink escapes, bounds source file size and selected source entries, and
reports eligible unreadable or unparseable files as incomplete. A source-entry
overflow stops before parsing the truncated set. Machine output uses
repository-relative POSIX paths and excludes timestamps, process IDs,
environment variables, and absolute temporary or home paths.

These controls reduce risk; they do not make an untrusted checkout harmless for
other tools. Do not run its tests, build backend, shell hooks, editor tasks, or
Git configuration as part of a PyAhead static scan.

## Explicit dynamic-evidence boundary

The `pyahead.pytest_plugin` module is an opt-in user-CI component. Loading it
with `pytest -p` means pytest executes the repository's tests with their normal
code, dependency, secret, filesystem, and network authority. This execution is
not performed by `pyahead check` or by a hosted PyAhead scanner. Use the plugin
only in a CI environment already trusted to run that test suite.

The plugin records deprecation-warning category and message, repository-relative
location when available, pytest node ID, phase, occurrence count, concrete
Python environment, pytest version, test count, exit code, collection
completeness, and an explicit source commit. It omits absolute paths and
external locations. Collection retains at most 10,000 unique records and 8 MiB
of normalized warning text; omitted occurrences are counted without retaining
their full records. Evidence files and ingestion are root-bounded and capped at
16 MiB per artifact; incremental size truncation is explicit in the artifact.
Ingestion
also caps one scan at 64 paths, 64 MiB, and 100,000 warning records in total,
then bounds relationship candidate checks and output records. Reports can still
reveal test names, warning messages, and project structure, so protect them like
other CI logs. Do not put secrets in warning messages or parameterized test IDs.

Ingestion is offline and does not execute the artifact. A full commit must come
from an explicit option or a documented CI environment variable; PyAhead does
not invoke Git. Different-commit evidence is retained as visibly stale and is
not linked to current findings. Subject, interpreter, policy, and timeline
checks distinguish corroboration from location-only or conflicting
associations. Observed warnings do not alter static gate counts or silently
override static inference.

## Explicit dependency-evidence boundary

`pyahead dependencies` is opt-in and separate from the default static scan.
Direct metadata inspection opens only root-bounded regular files, limits input
and metadata sizes, preflights ZIP member counts and declared expanded sizes,
preflights physical tar headers and control-record sizes, and then streams tar
members through a bounded decompressor without retaining the member list.
Multi-disk and ZIP64 containers are conservatively retained as incomplete
evidence. It reads a
wheel's `METADATA` or an sdist's `PKG-INFO` without extracting files. It does not
import the package, execute its configuration, or invoke a build backend.
Standalone Core Metadata does not establish artifact availability by itself and
remains unverified for that dimension.

Wheel availability additionally requires a matching top-level `.dist-info`
identity, `WHEEL` and `RECORD`, and agreement between internal and filename
tags. Core Metadata direct URL dependencies are incomplete evidence and stop
resolver execution; they are never passed through to `uv`.

The optional `uv` resolver runs as a subprocess in a fresh temporary directory.
It receives a small environment allowlist, ignores project sources and ambient
configuration and credentials, disables source builds, keyring access, and
Python downloads, and uses an isolated home, temporary area, and cache. Offline
mode is the default and supplies `--offline`, `--no-index`, and a temporary
wheelhouse containing only configured artifacts whose bytes are revalidated
against the directly inspected SHA-256 digest. Online use requires an explicit
switch and an explicit HTTP(S) index URL without embedded credentials, query,
or fragment. Do not place credentials in repository configuration;
authenticated index design is deferred. Every resolver process has a finite
explicit deadline. A timeout, missing resolver, unrecognized resolver failure,
or malformed output is incomplete evidence, never a compatibility failure.
For exact application pins only, the closed offline wheelhouse can prove that a
package, requested version, or target-compatible wheel is unavailable. Library
artifact gaps remain unverified even for exact constraints or metadata-only
inspection because the configured sample is not a complete platform inventory.
Resolver-selected packages prove requested extras only when the exact inspected
metadata declares them. Online index lookup failures also remain unverified. A
solver failure is reported only when a recognized exact `uv` version
corroborates independently contradictory active constraints; generic "no
solution" text is insufficient.

Resolver execution reads third-party wheel metadata as part of solving but
cannot build source distributions. When network use is enabled, it may contact
the configured index plus artifact or redirect hosts referenced by that index;
the index option is not a host-level egress allowlist. Reports record package
names, exact versions, artifact hashes, dependency declarations, target
platform values, resolver version, and bounded failure text; treat them as
repository-sensitive CI data.

## Network-visible commands

The following M6 operations can access a network outside `pyahead check`:

- package installation when an installer resolves PyAhead dependencies;
- `uv sync`, `uv build`, or publication when required artifacts are not cached;
- operator-owned Git acquisition of public corpus repositories;
- explicit release publication to a package index or Git hosting service.

The M8 `pyahead dependencies` resolver can also access its explicitly configured
package index, plus artifact or redirect hosts selected by that index, only when
network use is enabled. The index option is not an egress allowlist. Direct
metadata inspection and offline dependency resolution do not access an index or
follow metadata direct URLs.

`scripts/install_smoke.py --offline` sets supported installer offline controls,
inherits only the caller's already locked runtime dependencies, installs the
candidate itself with dependency resolution disabled, and fails if its isolated
build requirements are absent from local caches. Normal hosted smoke jobs use a
clean environment and resolve every dependency. The corpus runner never clones,
fetches, or updates repositories; acquisition is a separate, visible operator
step.

## Reports and private repositories

Reports contain repository-relative paths and regions, rule IDs, matched
subjects, binding evidence, policy, registry identity, diagnostics, and summary
counts. Even without source snippets, these fields can reveal internal project
structure or technology choices. Store and transmit reports with the same
access policy as the repository unless an owner approves broader disclosure.

Baselines and SARIF also contain finding identities and locations. Suppression
reasons can contain issue references or human-authored text; do not put secrets
in suppression comments.

## Corpus minimization

`scripts/corpus.py` accepts exactly 100 clean local Git checkouts pinned to full
commit IDs. Persistent JSON contains only:

- public repository URL and exact commit;
- aggregate scan, policy, registry, diagnostic-count, duration, and exit
  metrics; and
- high-confidence findings required for manual review: relative locations,
  fingerprints, rule and subject data, structured match evidence, timelines,
  states, contexts, and authoritative sources.

It does not persist checkout paths, source text, snippets, Git configuration,
authors, commit messages, branches, environment values, or scanner stderr. The
generated CSV contains only the corpus-result digest, finding identities, and
blank review fields. The digest binding must be verified before review because
the JSON and CSV are published by two separate atomic replacements. Local
checkouts remain operator-owned and should be deleted according to the review
environment's retention policy.

Checkout verification disables optional Git locks, ambient global/system Git
configuration, filesystem monitors, untracked caches, submodule recursion, and
credential or askpass interaction. It invokes no shell and performs no fetch. Treat acquisition
and any other Git command outside the runner as a separate trust boundary.

Only public repositories whose licenses and hosting terms permit the planned
review should enter the corpus. Do not add private, embargoed, credentialed, or
personal-data-focused repositories. Reviewer names and maintainer-consent
evidence belong in separately access-controlled Gate C records, not corpus JSON.

## Supply chain and releases

Registry data is bundled with the package, content-digested, and never silently
auto-updated. Every finding records the registry revision. A release candidate
must pass locked quality checks, build wheel and sdist, install and scan from
each artifact, and receive exact-commit hosted evidence on supported operating
systems. Published files are immutable; a faulty artifact is yanked and
replaced only by a new version.

GitHub Actions use read-only repository contents by default. Release
publication is not automatic in the M6 workflow and remains an explicit
maintainer action. Do not place package-index tokens in configuration, command
history, logs, reports, or corpus manifests.

## Vulnerability reporting

Use the private GitHub Security Advisory reporting flow described in
[`SECURITY.md`](../SECURITY.md). Include the affected version, platform,
reproduction, impact, and whether untrusted repository content is required.
Do not include live credentials or private source.
