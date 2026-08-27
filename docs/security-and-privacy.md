# Security and privacy

This document describes the public-alpha CLI and repository-review tooling. It
does not grant future hosted or dynamic-evidence components any authority.

## Default scan boundary

`pyahead check` parses selected source as data. It does not import target
modules, execute target configuration, install target dependencies, invoke
build backends, run tests, access the network, or send telemetry. YAML is loaded
with safe parsing and registry entries cannot name arbitrary executable matcher
code.

The scanner rejects root escapes and never reads source through directory or
file symlinks. A discovered file alias remains opaque, incomplete module
evidence rather than a source of bytes. Source file size and selected source
entries are bounded, and eligible unreadable or unparseable files are reported
as incomplete. A source-entry
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

Repository inputs use one private bounded reader. On POSIX it opens the root,
every ancestor, and the regular leaf through pinned directory descriptors; on
Windows it uses native handles and rejects reparse points and alternate data
streams. Symlinks, mutable path bindings, and files changed in place during a
read fail closed. `pyproject.toml` is capped at 2 MiB. Baselines are capped at
32 MiB and 100,000 findings, with each variable text field capped at 4,096
characters. Baseline creation enforces the same limits as baseline ingestion.

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
members through a bounded decompressor without retaining the member list. All
archive reads in one inspection share a 1 GiB expanded-byte budget, including
both tar preflight and metadata passes. ZIP LZMA is rejected before decoder
construction because the standard-library path cannot impose a dictionary-memory
limit; stored, deflated, and BZIP2 members remain supported.
Multi-disk and ZIP64 containers are conservatively retained as incomplete
evidence. One run accepts at most 256 metadata inputs and 512 MiB in aggregate;
each input is capped at 128 MiB and its selected metadata at 2 MiB. It reads a
wheel's `METADATA` or the single identity-matching top-level
`<name>-<version>/PKG-INFO` from an sdist without extracting files. It does not
import the package, execute its configuration, or invoke a build backend.
Compatibility-tag inputs are capped at 256 compressed values and 4,096 expanded
tags, with the Cartesian product checked before filename, configuration, or
wheel-header parsing expands it.
Root marker evaluation accepts at most 256 configured extras, and each metadata
artifact accepts at most 256 `Provides-Extra` fields before transitive-extra
propagation. Each configured or metadata requirement may request at most 256
extras. Across one run, inspected artifacts may contain at most 100,000
`Requires-Dist` fields and the declared target, extra, tag, artifact, and
requirement products may require at most 1,000,000 dependency-evaluation work
units. Statically excessive products fail before target evaluation or resolver
execution, and one shared runtime counter also bounds repeated marker
evaluations, artifact and constraint comparisons, tag matching, and
transitive-extra propagation.
The dependency TOML document is read with a 2 MiB pre-parse cap.
Configuration and metadata reads traverse from a pinned repository root through
directory descriptors on POSIX and reparse-safe relative handles on Windows;
ancestor or leaf binding changes fail closed. POSIX reads also compare
mutation-sensitive file attributes before and after reading, while Windows leaf
handles deny concurrent write sharing, so ordinary in-place changes fail closed.
Terminal-facing Core Metadata fields, including every `Requires-Dist`, reject
control characters and oversized values before they enter a report.
Standalone Core Metadata does not establish artifact availability by itself and
remains unverified for that dimension.
For sdists and provenance-unknown standalone metadata using Core Metadata older
than 2.2, `Requires-Python`, `Requires-Dist`, and `Provides-Extra` are treated as
implicitly dynamic under the legacy metadata rules. Legacy wheel metadata is
already a built-artifact declaration and remains final.

Wheel availability additionally requires a matching top-level `.dist-info`
identity, `WHEEL` and `RECORD`, a supported major `Wheel-Version`, a boolean
`Root-Is-Purelib`, and agreement between internal and filename tags. Core
Metadata direct URL dependencies are incomplete evidence and stop resolver
execution; they are never passed through to `uv`.

The optional `uv` resolver runs as a subprocess in a fresh temporary directory.
The executable must resolve to a regular file outside the scanned repository;
repository content is never accepted as the resolver. Configured artifacts must
also have basenames that remain unique after Unicode NFC normalization and
case-folding before they are flattened into the temporary wheelhouse.
It receives a small environment allowlist, ignores project sources and ambient
configuration and credentials, disables source builds, keyring access, and
Python downloads, and uses an isolated home, temporary area, and cache. Offline
mode is the default and supplies `--offline`, `--no-index`, and a temporary
wheelhouse containing only configured artifacts whose bytes are revalidated
against the directly inspected SHA-256 digest. Online use requires an explicit
switch and an explicit HTTP(S) index URL without embedded credentials, query,
or fragment. Do not place credentials in repository configuration;
authenticated index design is deferred. Every resolver process has a finite
explicit deadline capped at 86,400 seconds. Stdout and stderr are separately
capped at 4 MiB; the reader accepts at most 8 MiB from the resolver result and
10,000 package
records. The result read limit is not an operating-system quota on temporary
disk growth while `uv` is running; use a disk-limited execution environment
when an online index is not fully trusted. PyAhead isolates the resolver tree in
a dedicated POSIX process group or Windows Job Object and terminates descendants
during cleanup. Windows resolver processes remain suspended until Job assignment
has succeeded. A timeout, missing resolver, output
overflow, unclosed output pipe, undecodable output, unrecognized resolver
failure, or malformed output is incomplete evidence, never a compatibility
failure. Stored diagnostics remove control characters and isolated-workspace
paths, as well as host-interpreter fallback warnings that are not target
evidence.
Only when offline resolution is requested for exact application pins can the
closed wheelhouse prove that a package, requested version, or target-compatible
wheel is unavailable. Metadata-only gaps and library artifact gaps remain
unverified because the configured sample may not be a complete platform
inventory. A library `==` pin without an explicit local segment also admits
unseen local versions and cannot make one sampled exclusion definitive.
Resolver-selected packages prove requested extras only when the exact inspected
metadata declares them. Online index lookup failures also remain unverified. A
successful result must contain exactly the package closure reachable from the
active configured roots; SHA-bound but unreachable packages make it incomplete.
An empty closure remains valid when all configured requirement markers are
inactive. A public-version application pin such as `==1.0` remains unverified
when multiple supplied local variants satisfy it without exact resolver
selection. A solver failure is reported only for reviewed unsatisfiable grammar
from a recognized exact `uv` version after availability and Python-version
diagnostics are excluded. It must corroborate independently contradictory exact
or simple bounded active constraints. Uncorroborated transitive solver text and
generic "no solution" text are insufficient.

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
