# Gate D evidence and approval

## Decision

- Gate: D — dynamic evidence
- Decision date: 13 September 2026
- Accountable reviewer: Diego Russo, repository owner and product decision-maker
- Decision: approved to proceed to M9

The reviewer confirmed that the M7 pytest deprecation-warning path is one
evidence provider working end to end in CI, that observed evidence stays
separate from static inference, that a conflict is recorded rather than
resolved, and that both the producing and consuming boundaries are explicit
opt-ins. This approval does not claim that a second provider exists, nor that
observed silence proves compatibility.

Recorded on the reviewer's instruction, on the strength of this record and the
qualifications stated above, which were put to them in summary before the
decision. The reviewer did not independently re-perform the measurements.

`docs/design.md` §4.3 previously scoped five items to `0.2` and `0.2.0` shipped
three; §4.3 has since been reconciled with what shipped, and the two deferred
providers are recorded there as `0.2.x` work. Gate D asks for one provider
working end to end, which is satisfied independently of that deferral.

## Evidence identity

- Released version: `0.2.0`
- Registry revision: `3a2bf7aafb44`
- `docs/schema/evidence-v1.json` SHA-256:
  `93aa41b82e097e008bf7ae06b4d4b85e8e18ee76f6ad0c77b42439ade8dfcbca`
- `docs/schema/report-v1.json` SHA-256:
  `9bcbd827df2fe5c57673877678e2b6f452bcfcf9c2ae3b701425884eafee4140`
- Hosted verification: run `33528860664`, conclusion `success`, 16 of 16 jobs,
  on the released commit

The provider under review is the M7 pytest deprecation-warning path. The M8
dependency path is a separate analysis product with its own report contract and
is not offered as this gate's provider.

## D1 — one evidence provider works end to end in CI

`pyahead.pytest_plugin` writes the versioned `evidence-v1` artifact during a
pytest run in the repository owner's CI. `pyahead check --evidence` then
validates and ingests that artifact. Both halves are exercised as one path:
`tests/integration/test_pytest_plugin.py` launches a real pytest subprocess and
asserts on the artifact it produces, and `tests/integration/test_cli_m7.py`
feeds an artifact through the CLI to a rendered report.

Coverage of the provider is 17 integration tests for the plugin, 3 CLI
ingestion tests, and 20 unit tests in `tests/unit/test_evidence.py`. All run in
the standard suite, which the hosted matrix executes on Linux, macOS and Windows
for Python 3.11 through 3.14; the recorded run above is green on every job.

The artifact contract is closed and published. `evidence-v1.json` requires
`environment`, `provider`, `run`, `schema_version`, `source` and `warnings`.

## D2 — evidence is clearly distinguished from static inference

Observed warnings never enter the static finding population. They are carried in
a separate optional evidence section of `ScanReport`, modelled by
`EvidenceArtifact`, `EvidenceEnvironment`, `EvidenceLocation` and
`EvidenceRelationship` in `src/pyahead/model.py`.

The published report schema keeps the two populations apart in its summary:
`breaking`, `deprecated`, `informational`, `new`, `risk` and `suppressed` count
static inference, while `observed`, `observed_stale` and `observed_unmatched`
count observations. A reader cannot mistake one for the other, and an
observation that matched nothing stays visible in its own count rather than
being dropped.

`EvidenceEnvironment` records the concrete interpreter that produced the
observation, so an observation is always attributable to a real run rather than
presented as a general property of the code.

## D3 — conflicts do not silently overwrite either source

Conflict is a recorded outcome, not a resolution. `EvidenceRelationshipKind` in
`src/pyahead/model.py` has exactly three members — `corroborates`, `conflicts`
and `location-only` — so an observation that contradicts static inference is
retained *as* a conflict and both sides survive in the report.

`EvidenceFreshness` has two members, `current` and `stale`. Evidence produced at
a different commit is retained as visibly stale and is not linked to current
findings, so a stale observation can neither corroborate nor suppress a current
one.

`docs/security-and-privacy.md` states the invariant directly: "Observed warnings
do not alter static gate counts or silently override static inference." Exit
codes and gate counts therefore remain a function of static inference alone,
and adding `--evidence` cannot turn a failing scan into a passing one.

Ingestion fails closed rather than degrading: `tests/unit/test_evidence.py`
covers artifacts with dropped warning records, unproven capture, and optional
fields explicitly set to null.

## D4 — network and execution boundaries are explicit

Both directions of the boundary are opt-in and named.

- Producing evidence requires the explicit `--pyahead-evidence` pytest option
  (`pytest_addoption` in `src/pyahead/pytest_plugin.py`). Without it the plugin
  produces nothing.
- Consuming evidence requires the explicit `--evidence` option on
  `pyahead check`. `--source-commit` is rejected without it, and `--evidence` is
  refused with SARIF output rather than silently ignored.

Execution is confined to the user's own CI. PyAhead does not run the user's
tests; it ingests an artifact those tests produced. Ingestion itself is offline
and does not execute the artifact, and PyAhead does not invoke Git — a full
commit must come from an explicit option or a documented CI environment
variable.

The plugin refuses configurations under which capture cannot be proven complete,
rather than emitting a partial artifact: pytest's warnings plugin must be
active, and pytest-xdist execution is refused. Same-name impostor plugins do not
satisfy either check.

The default static command remains unchanged by this gate: it does not execute
target code, install target dependencies, access the network, or send telemetry.

## Limitations retained

- One provider satisfies this gate; a second is not implemented. There is no
  generic provider protocol, and `src/pyahead/evidence.py` accepts only the
  provider name `pytest-warnings`. Cross-provider merging and cross-provider
  conflict handling are therefore unimplemented and untested.
- `docs/design.md` §4.3 scopes five items to release `0.2`. PEP 702 /
  type-checker evidence (§17.3) and interpreter compile/import/test probe
  ingestion (§17.5) are not implemented, and §17 records them as design
  constraints rather than current features. The reviewer should decide whether
  Gate D is satisfied by one working provider or should wait for §4.3 to be
  reconciled with what `0.2.0` shipped.
- Evidence quality depends on the user's test suite. Warnings are observed only
  where tests execute the affected code; silence is not proof of compatibility.
- The end-to-end path is demonstrated by this repository's own CI and test
  suite. No external project has yet run the plugin and fed the artifact back
  through `pyahead check`.
- Open decision §25.5, the first type-checker adapter, remains unmade and blocks
  the PEP 702 provider.

## Reviewer checklist

The evidence above is prepared, not approved. To decide this gate, confirm:

1. one provider genuinely works end to end, on the strength of D1;
2. the separation in D2 is legible in a real report, not only in the schema;
3. the conflict and staleness semantics in D3 match the intent;
4. the boundaries in D4 are the ones intended for a hosted service to inherit;
5. whether one provider satisfies Gate D, given the §4.3 gap in Limitations.

Gate D remains human-owned: an agent may prepare and verify this evidence, but
cannot create this approval.
