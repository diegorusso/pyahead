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

## Network-visible commands

The following M6 operations can access a network outside `pyahead check`:

- package installation when an installer resolves PyAhead dependencies;
- `uv sync`, `uv build`, or publication when required artifacts are not cached;
- operator-owned Git acquisition of public corpus repositories;
- explicit release publication to a package index or Git hosting service.

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
generated CSV contains only finding identities and blank review fields. Local
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
