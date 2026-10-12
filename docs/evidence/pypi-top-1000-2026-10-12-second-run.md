# PyPI top-1000 validation, 12 October 2026, second run

The fifth run of the protocol in `docs/pypi-validation.md`, made the same
day as the approved 12 October record
(`docs/evidence/pypi-top-1000-2026-10-12.md`) to measure one harness
change: names the probe could not see are now resolved through the import
the source names (`37ad973`). PyAhead, the corpus, the manifest and the
registry are those of that record, so every difference below is the
harness's.

## Decision

- Prepared by an agent on 12 October 2026. **Approved 12 October 2026 by
  Diego Russo, repository owner and product decision-maker**, on the strength
  of this record and a summary of it. Under the repository's gate convention
  an agent may prepare and verify this evidence but cannot approve it.
- Decision: accept as the current precision record, and stop raising
  coverage here: the remaining import errors need optional dependencies,
  Windows, or test-only modules, which the harness does not install. Adjudication
  coverage rises from 84.03% to 91.74%; every row that moved was
  `binding-not-visible`, none moved to a refutation, and no other row of
  the 1453 changed.

## Record

```text
Corpus: PyPI top-1000, rank 1-1000, retrieved 2026-09-17T16:35:21Z,
        source https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json
Manifest SHA-256: d7fac3498e91ecb1b2f69c0b68b1fe6cb462a444b1903c6230762527689c8ea4
PyAhead commit: 37ad973 (0.7.0's analyser, ca35025, plus harness changes
                only)
Registry revision: fa9db725e612 (205 rules, label 2026.10.10)
Report SHA-256: 730898e6083d25c36d2402fc2f64ba297204fec13976bfad1bfdc38d40aacb88
Worksheet SHA-256: d12b804ce1ac74d76b1f0bb9bccabf3688205fcf97fee7ff4deacccb3aa4562d

packages_total / packages_scanned: 999 / 805
unresolved_at_acquisition: 1 (589 pywin32 312: no-installable-artifact)
findings_total: 1453
verdicts: confirmed=1332 refuted-binding=1 refuted-timeline=0 not-adjudicable=120
agreement_rate: 0.9992 (1332 / 1333)
adjudication_coverage: 0.9174 (1333 / 1453)
not_adjudicable_reasons: import-error: 79, module-not-importable: 27,
                         binding-not-visible: 13, platform-conditional: 1

Triage: 1 refuted-binding row (humanfriendly, CPY0023), the open row the
first 12 October record documents; unchanged.

Limitations restated: recall is not measured; the probe host is Linux only.

Reviewed by: Diego Russo, 2026-10-12
```

## What changed, and what it did

The probe reads a finding's name from the module's globals or the
enclosing callable's, so 131 rows of the first 12 October run were
`binding-not-visible`: an alias the canonical name does not spell
(`import typing as t`, then `t.AnyStr`), a function-local import, an import
under `if TYPE_CHECKING:` that never runs, or a module-import finding that
is itself inside a function. `37ad973` reads the installed source for each
(`scripts/pypi_validate/_site_names.py`, rules in
`docs/pypi-validation.md`). The probe still compares identities at
runtime: the source names the import, the interpreter supplies the object.

Between the first 12 October run and this one, every package kept its
status and its exact set of findings; only these verdicts moved:

| move | rows |
| --- | --- |
| not-adjudicable:binding-not-visible → confirmed | 112 |
| not-adjudicable:binding-not-visible → not-adjudicable:import-error | 4 |
| not-adjudicable:binding-not-visible → not-adjudicable:module-not-importable | 2 |

- The 4 import errors are `ipykernel` and `jupyter-server` sites that bind
  `asyncio.WindowsProactorEventLoopPolicy` and
  `asyncio.WindowsSelectorEventLoopPolicy` locally; those classes do not
  exist on this Linux host, so the import the source names cannot run.
- The 2 `module-not-importable` rows are `zope-interface`'s
  `inspect.getargspec` and `inspect.formatargspec`, absent at the reference
  interpreter.

| | first run | second run |
| --- | --- | --- |
| confirmed | 1220 | 1332 |
| refuted | 1 | 1 |
| not adjudicable | 232 | 120 |
| agreement | 99.92% | 99.92% |
| adjudication coverage | 84.03% | 91.74% |

## Not adjudicable

- `import-error` (79, in 32 packages): every package installed; the module
  holding the finding cannot be imported without something the harness
  does not install. Most need an optional dependency
  (`urllib3.contrib.pyopenssl` and pip's vendored copy of it, 14 rows;
  `grpc._simple_stubs`, 8; `pyspark.mllib` and `pyspark.pandas`, 8;
  Cython's IPython magic; `cattrs.preconf.ujson`; a Django integration);
  others are Windows-only (`click._winconsole` and typer's copy, and the 4
  asyncio rows above) or test helpers and setup scripts shipped in wheels
  (`pyarrow.tests`, `srsly.tests`, `jupyterlab_server.test_utils`). The
  earlier records described this bucket as CPython-tagged wheels that
  cannot be installed under an earlier interpreter; on this run's shards
  that is not what it holds.
- `module-not-importable` (27): subjects absent or unobservable at the
  reference interpreter.
- `binding-not-visible` (13, in `cffi`, `ruamel-yaml`, `python-discovery`,
  `distlib`, `pip`, `setuptools`, `absl-py`, `future`, `flatbuffers`,
  `cython`): names bound more than once in their scope, star imports, and
  imports a version test or early exit decides; the harness leaves these
  to the probe by design.
- `platform-conditional` (1): unchanged from the first run.

## Skipped

152 install-failed after every admitted candidate was tried, and 42 with
no Python files. No package hit the scan timeout.

## Verification

- `pypi_report --verify-identity` passed on the report and worksheet above.
- Every shard of this run has the same status and set of finding
  fingerprints as the first 12 October run; the verdict moves are listed
  above and are all from `binding-not-visible`.
- A targeted rerun of the 34 packages with `binding-not-visible` rows,
  before the commit, gave the same 112 / 4 / 2 moves.
- Registry: 205 rules, revision `fa9db725e612`, unchanged since 0.5.0.
- Gate at `37ad973`: ruff, ruff format, mypy, 2638 tests passing, run with
  uv 0.11.21 (CI's pinned version); CI passed on `37ad973`.
- The harness ran with uv 0.11.21, four shards, a 900 s timeout, in 2.09 h.
