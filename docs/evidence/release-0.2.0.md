# Release 0.2.0 evidence

Evidence assembled for the release review in `docs/releasing.md` §3. Everything
recorded here was executed against the candidate. Nothing was tagged, published,
or released.

## Candidate identity

- Version: `0.2.0`
- Registry revision: `2026.07.31 (3a2bf7aafb44)`, 133 rules valid
- Measurement host: Linux aarch64, CPython 3.13.5
- Evidence assembled: 1 September 2026

The candidate is CI-verified. Run `33528860664` concluded `success` on the
released commit with all 16 jobs green, satisfying `docs/releasing.md` §1, which
requires successful Linux, macOS, Windows, build, and install jobs for the
released commit.

Figures below describe the candidate. Later commits on `main` are the next
`Unreleased` cycle and are deliberately not folded into this record.

## The Windows blocker

Windows CI had been failing on every candidate. Raw NTSTATUS failures in
`src/pyahead/_windows_output.py` never became the standard Python exceptions the
callers catch, so reading `pyproject.toml` through the rooted-input path failed
and the CLI exited 2 where it should have exited 0, 1, or 3.

| Stage | Windows test failures |
| --- | ---: |
| Before any fix | 154 |
| After the NTSTATUS translation | 2 |
| After guarding two descriptor-only tests | 0 |

The NTSTATUS translation maps `OBJECT_NAME_NOT_FOUND`, `OBJECT_PATH_NOT_FOUND`, and
`NO_SUCH_FILE` to `FileNotFoundError`; `ACCESS_DENIED` and `SHARING_VIOLATION` to
`PermissionError`; and `NOT_A_DIRECTORY` to `NotADirectoryError`, keeping
`.status` intact for the existing collision branch. Regression coverage is in
`tests/unit/test_output.py` and `tests/unit/test_rooted_reader.py`. The fix
introduced no new failures.

The two survivors were pre-existing rather than caused by that fix; they were
invisible among 154. Both monkeypatch `supports_rooted_descriptor_reads` to
`True` and intercept `os.open` calls carrying `dir_fd`, but Windows provides
neither `os.supports_dir_fd` for `open`/`stat` nor `O_DIRECTORY`/`O_NOFOLLOW`, so
they asserted against a path the platform cannot take. The fix guards both with
the capability they require. They still run unchanged on Linux and macOS, and
Windows keeps its own fail-closed coverage in
`test_windows_leaf_reparse_swap_fails_closed`.

## M8.5 audit

Every deliverable and acceptance bullet of submilestones a through g was mapped
to its implementing module and covering tests. No FAIL verdict was found.

| Submilestone | Verdict | Gap recorded |
| --- | --- | --- |
| M8.5a | 1 gap | Native Windows tests lacked the missing-input case, the confirmed blocker root cause. Closed by the NTSTATUS translation. |
| M8.5b | Pass | All 7 acceptance bullets pass. |
| M8.5c | Pass | All 4 deliverables and 7 acceptance bullets pass. |
| M8.5d | 1 gap | Doc/code drift between `docs/security-and-privacy.md` and `install_smoke.py` is not test-pinned. |
| M8.5e | 1 gap | Not every dependency sub-field has an individual negative-fixture test. |
| M8.5f | 2 gaps | No test pins the internals excluded from `__all__`; no test pins the `Documentation` URL metadata. |
| M8.5g | 2 gaps | No test checks the contributing docs for `--frozen`; the benchmark `passed=true` happy path is not explicitly asserted. |

All seven findings are missing test coverage rather than defective behaviour. The
M8.5a gap is closed; the remaining six are open and none blocks this release.

## Verification

The `AGENTS.md` block and the `docs/releasing.md` §2 sequence, run on the
candidate under a freshly created installer cache.

| Command | Result |
| --- | --- |
| `uv sync --frozen` | Checked 28 packages |
| `uv run ruff check .` | All checks passed! |
| `uv run ruff format --check .` | 450 files already formatted |
| `uv run mypy src scripts` | Success: no issues found in 42 source files |
| `uv run pytest` | 1633 passed, 10 skipped; branch coverage 91.58%, gate 90% reached |
| `uv run pyahead registry validate` | Registry 2026.07.31 (3a2bf7aafb44): 133 rules valid. |
| `uv run pyahead registry coverage` | Rules covered: 133/133; unclassified source entries: 0 |
| `uv build --clear --offline` | Both artifacts built with no network access |
| `uv run pyahead --version` | pyahead 0.2.0 |
| `git diff --check` | No output |

## Artifacts

Built offline into a clean `dist/`. Digests were produced with the
`docs/releasing.md` §3 command without modifying the distributions.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `pyahead-0.2.0-py3-none-any.whl` | 292,298 | `982704de642c5c649019c2a0b7c4f2ae7b12572fb5e4b91b39b601170e050f49` |
| `pyahead-0.2.0.tar.gz` | 549,098 | `3972f5fb120b6c76d6ece2a37f307fb127b78a047750de762f7f07e457dd633f` |

Installed separately into clean environments, both artifacts report
`pyahead 0.2.0` and the same registry revision `2026.07.31 (3a2bf7aafb44)` with
133 rules valid.

The §3 digest command walks every file in `dist/`, so it also digests the
`.gitignore` that `uv` places there. Only the two distributions above are release
artifacts.

## Install smoke

| Artifact | Network | Result |
| --- | --- | --- |
| wheel | online | wheel install smoke passed for pyahead 0.2.0 |
| wheel | `--offline` | wheel install smoke passed for pyahead 0.2.0 |
| sdist | online | sdist install smoke passed for pyahead 0.2.0 |
| sdist | `--offline` | sdist install smoke passed for pyahead 0.2.0 |

## Benchmark

`uv run python scripts/benchmark.py --repeat 3`.

| Case | Files | Median | Peak RSS | Deterministic | Regression gate | Design target |
| --- | ---: | ---: | ---: | --- | --- | --- |
| one-file | 1 | 1.489 s | 45.4 MB | yes | pass | unmet |
| 1k-files | 1,000 | 17.857 s | 48.5 MB | yes | pass | unmet |
| 10k-files | 10,000 | 154.237 s | 79.2 MB | yes | pass | unmet |

Overall `passed: true` with `performance_targets_met: false`, all three cases
deterministic across 3 repeats. Unmet design targets are reported separately by
design, so they stay visible without failing the regression gate. The absolute
timings are a property of this measurement host, a Raspberry Pi 5 running Linux
aarch64, and should be re-measured on release hardware before being treated as
representative.

## Hosted CI

Run `33528860664` on the released commit concluded `success`, 16 of 16 jobs
green. Its parent was independently green in run `33503563286`, so the Windows
fix and the version bump were each verified in isolation.

| Job | Host | Python |
| --- | --- | --- |
| Quality and Gate B | ubuntu-latest | 3.11 |
| Build wheel and sdist | ubuntu-latest | — |
| Tests | ubuntu-latest | 3.12, 3.13, 3.14 |
| Tests | macos-latest | 3.11, 3.14 |
| Tests | windows-latest | 3.11, 3.14 |
| Install wheel and sdist | ubuntu-latest | 3.11, 3.14 |
| Install wheel and sdist | macos-latest | 3.11, 3.14 |
| Install wheel and sdist | windows-latest | 3.11, 3.14 |
| Prerelease, advisory | ubuntu-latest | 3.15 |

`gh run view --log-failed` returns empty output on this repository. Failure logs
must be fetched through `gh api repos/diegorusso/pyahead/actions/jobs/<id>/logs`;
without that fallback a red run supplies no diagnosis.

## Version decision

The candidate previously carried `0.1.0a2` while `docs/design.md` §4.3 assigns the
delivered M7 and M8 evidence providers to release `0.2`, and §4.2 scopes
`0.1.0a2` to the static analyser alone.

The conflict is resolved in favour of the design: this release is `0.2.0`. No
`0.1.0` was ever published, so no version is skipped in the index. The
`Development Status :: 3 - Alpha` classifier is unchanged; it describes maturity,
which this release does not claim to advance, and a `0.x` version already signals
unstable public contracts.

The bump updated the version source, the README status sentence and install
snippets, the usage-guide snippets, and the two golden reports that embed the
tool version. The `Unreleased` changelog section was cut as `0.2.0`.

## Change range

19 commits since the last published release, M8: 82 files,
16,263 insertions, 17,144 deletions.

- M8.5a–g release hardening: rooted repository input, fail-closed pytest
  evidence, dependency compatibility semantics, release smoke isolation,
  terminal-safe human output, public machine and typing contracts, and
  behaviour-preserving cleanup.
- Removal of the M1.5 milestone controller, its offline test suite, its
  documentation, and its `automation/` policy tree, about 21,100 lines. Milestone
  rules, protected paths, quality-policy tables, and the Gate C approval
  requirement are retained as prose in `AGENTS.md` and `docs/design.md`.
- Corpus worksheet escaping: repository-derived `path`, `subject`, and
  `match_kind` values are quoted so a scanned file name cannot become a live
  formula in the reviewer's spreadsheet, with read-back rejection of unescaped
  values.
- Windows NTSTATUS translation and the descriptor-capability test guards
  described above.
- The version bump to `0.2.0` with its changelog release section.

Protected files were changed within this range. `docs/design.md` was modified by
M8.5a, M8.5b, M8.5c, M8.5f, M8.5g, and the controller removal; `AGENTS.md` and
`.github/workflows/ci.yml` by M8.5g and the controller removal. Each change
belonged to a milestone that required it.

`docs/evidence/gate-c.md` is untouched, unchanged since its approval. Gate C
was neither re-approved nor restated.

## Not done

- No tag created, and no annotated `v0.2.0`.
- No PyPI upload and no GitHub release.
- No pull request opened.
- No history rewrite of any published commit.
- No change to `docs/evidence/gate-c.md`.
- No use of `codex/m8.5-release-hardening`.
- No post-release verification, which requires a published package.

## Remaining maintainer actions

1. Confirm the pre-publication open decisions in `docs/design.md` §25:
   Apache-2.0 licence confirmation, and PyPI availability and ownership of the
   `pyahead` distribution name. Neither is determinable from the repository.
2. Release-review sign-off per `docs/releasing.md` §1 and §3 against this record.
3. Tag an annotated `v0.2.0` on the verified commit, then publish the GitHub
   release and PyPI distribution through an MFA or trusted-publishing identity.
4. Post-release verification per `docs/releasing.md` §5 on a supported host.

The six open pass-with-gap findings are optional follow-ups for the next
`Unreleased` cycle. None blocks this release.
