# Changelog

All notable user-visible changes are recorded here. PyAhead follows Semantic
Versioning, including prerelease identifiers while public contracts are still
stabilizing.

## [Unreleased]

No user-visible changes yet.

## [0.1.0a2] - 2026-08-11

### Added

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

### Changed

- The package maturity classifier is now Alpha.

### Security

- Documented offline scan, no-telemetry, no-target-execution, filesystem, and
  corpus-data boundaries.

## [0.1.0a1] - 2026-08-03

### Added

- The first end-to-end static-analysis slice, including exact module imports,
  deterministic text and JSON findings, bounded discovery, and stable exits.

## [0.1.0a0] - 2026-07-31

### Added

- Initial package, command-line entry point, locked development environment,
  quality policy, build configuration, and CI.

[Unreleased]: https://github.com/diegorusso/pyahead/compare/v0.1.0a2...HEAD
[0.1.0a2]: https://github.com/diegorusso/pyahead/compare/v0.1.0a1...v0.1.0a2
[0.1.0a1]: https://github.com/diegorusso/pyahead/compare/v0.1.0a0...v0.1.0a1
[0.1.0a0]: https://github.com/diegorusso/pyahead/releases/tag/v0.1.0a0
