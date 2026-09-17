# Gate C evidence and approval

## Scope note, 17 September 2026

The measurements in this record were taken with the registry analysis window
opening at Python 3.11. On 17 September 2026 the window opened at 3.8, and the
registry began gaining rules whose events fall in 3.9 and 3.10, starting with
twenty-eight for the 3.10 removals. For a project whose baseline is inferred
below 3.11, those rules produce findings this record did not measure. Nothing
here is retracted: the precision claim holds for the policy it names, and the
newly reachable population is unmeasured rather than measured badly. The plan
for that curation, on the `plans` branch, schedules a fresh run of this
protocol once the 3.9 and 3.10 pages are fully censused.

## Decision

- Gate: C — public-alpha precision
- Decision date: 24 August 2026
- Accountable reviewer: Diego Russo, repository owner and product decision-maker
- Decision: approved to proceed to M7 and M8

The reviewer confirmed that the direct source inspection and controlled
cross-version validation represent the checks they would have performed and
approved the evidence below. This approval does not claim that a clean PyAhead
scan proves repository compatibility.

## Evidence identity

- Registry revision: `3a2bf7aafb4480a41996e2bba8b4f2061d7a94f2727c083af094ba910865385e`
- Corpus-result SHA-256: `e8d8ec3dbe32f556d4768675672566d58d03fa17beb783a3af66c52154974f6d`
- Policy: Python 3.11 through 3.16, high-confidence findings only
- Corpus: 100 distinct active public repositories at pinned commits
- High-confidence findings: 448
- Repositories retaining explicit incomplete diagnostics: 8

The corpus runner verified each credential-free HTTPS origin, exact commit, and
clean checkout before scanning. Its identity-bound worksheet was verified
against the result digest before adjudication. Selection was fixed before
examining PyAhead findings, and the deterministic sample ranked findings by a
SHA-256 of repository URL, commit, and finding fingerprint.

## Precision

| Review | True positives | False positives | Unresolved | Precision |
| --- | ---: | ---: | ---: | ---: |
| Deterministic Gate C sample | 200 | 0 | 0 | 100% |
| Complete high-confidence result | 448 | 0 | 0 | 100% |

Precision is `true_positive / (true_positive + false_positive)`. The observed
sample result exceeds Gate C's 95% requirement.

Every finding was bound to an exact pinned source location, imported subject,
rule timeline, and structured match evidence. Controlled isolated probes used
CPython 3.11.15, 3.12.13, 3.13.5, 3.14.6, and 3.15.0b2 where the claim was
runtime-observable. Documentation-defined deprecations and Python 3.16 schedules
were checked against authoritative registry sources.

## False-positive remediation

The preceding 451-finding audit classified 447 findings as true positives and
four as false positives. The remediation:

- reduced three Fail2Ban `asynchat`/`asyncore` findings from high confidence
  because exact `sys.path` mutations made their import origin ambiguous; and
- corrected the guarded CadQuery `ast.NameConstant` finding to retain only the
  applicable deprecation timeline rather than a post-removal breaking state.

Regression coverage is retained in:

- `tests/unit/test_precision_regressions.py`;
- `tests/fixtures/rules/CPY0003/compatibility/`;
- `tests/fixtures/rules/CPY0004/compatibility/`; and
- `tests/fixtures/rules/CPY0064/guarded/`.

The remediation introduced no new finding. Of the final 448 findings, 447 had
the same repository URL, commit, fingerprint, and complete persisted payload as
their previously adjudicated occurrence. The changed CadQuery occurrence was
reviewed again against pinned source and controlled runtime evidence.

## Limitations retained

- This is observed precision for the pinned corpus and policy, not a universal
  product-precision claim and not a measurement of recall.
- PyAhead did not execute repository code, install repository dependencies, or
  run each repository's test suite.
- Eight repository reports remained explicitly incomplete; they were not
  rewritten as clean scans.
- No runnable Python 3.16 interpreter was available. Python 3.16 schedules are
  authoritative-source-backed rather than runtime-demonstrated.
- Medium-confidence findings were outside the measured population.

## Adoption-stage decision

PyAhead has not yet been distributed to an established maintainer audience.
Requiring ten maintainers to commit to continuous use before M7 or M8 would
make development depend on adoption before prospective users can reasonably
discover or evaluate the public alpha. Continuous-use adoption is therefore a
post-distribution product-success metric, not part of this engineering gate.

Gate C remains human-owned: the corpus runner and Codex may prepare and verify
evidence, but neither can create this approval.
