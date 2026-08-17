# 100-repository corpus and false-positive review

Gate C is external evidence, not an automated claim. This protocol prepares a
reproducible high-confidence sample while minimizing retained repository data.

## Select and acquire the corpus

Choose exactly 100 distinct, active public Python repositories before looking
at PyAhead results. Record the activity criterion, selection source, selection
date, inclusion/exclusion rules, and any stratification in the Gate C evidence
document. Do not select repositories because they are known to contain a
particular rule.

Acquire each repository separately and detach it at one full commit. Network
access belongs to this visible operator step; the runner never clones or
fetches:

```console
git clone --filter=blob:none --no-tags https://github.com/example/project checkout/project
git -C checkout/project checkout --detach 0123456789abcdef0123456789abcdef01234567
git -C checkout/project status --short
```

Every checkout must be clean, including ordinary and ignored untracked files.
The runner verifies its credential-free HTTPS `origin` URL and `HEAD` against
the manifest before scanning, so a mislabeled checkout or local ignored source
cannot contaminate exact-commit evidence.

## Manifest

The manifest is local acquisition metadata and is not copied into results:

```json
{
  "schema_version": 1,
  "repositories": [
    {
      "repository_url": "https://github.com/example/project",
      "commit": "0123456789abcdef0123456789abcdef01234567",
      "checkout": "../checkout/project",
      "baseline_python": "3.11",
      "horizon_python": "3.14"
    }
  ]
}
```

The real array must contain exactly 100 unique credential-free HTTPS URLs.
Choose baseline and horizon from maintainer declarations or record the review
rationale; never infer a favorable policy from scan output.

## Run

From an installed or locked PyAhead environment:

```console
uv run python scripts/corpus.py \
  --manifest corpus-manifest.json \
  --output corpus-results.json \
  --worksheet false-positive-review.csv \
  --sample-size 200
```

The process stops before publication if a checkout is dirty, mis-pinned, a scan
fails, output is malformed, or a report exceeds 64 MiB. It uses isolated Python
module lookup so a target checkout cannot replace the installed `pyahead`
module.

The result and worksheet are each replaced atomically, but the two replacements
are not one filesystem transaction: the result is published first. If the
worksheet replacement then fails, a new result can remain beside an old or
missing worksheet. Every generated worksheet therefore carries the exact
SHA-256 of its result in a `corpus-identity` row and in every finding row. Never
begin or resume review until this binding passes:

```console
uv run python scripts/corpus.py \
  --verify-identity \
  --output corpus-results.json \
  --worksheet false-positive-review.csv
```

Verification fails closed if the schema, identity row, finding bindings, or
result digest differ. Rerun the complete corpus scan to regenerate a rejected
pair; do not copy review classifications into a newly generated worksheet until
the new result has been treated as a distinct sample.

Result records contain exactly `repository_url`, `commit`, `metrics`, and
`findings`. Metrics retain policy, registry, scan and summary counts, diagnostic
code counts, exit, and duration. Findings are high-confidence only and retain
the relative location, fingerprint, subject, structured match evidence,
timeline, state, usage contexts, and authoritative sources needed for review.
No source snippets or local checkout paths are stored.

## Review worksheet

The worksheet sample is deterministic: candidates are ranked by SHA-256 of
repository URL, commit, and finding fingerprint, then the first requested rows
are selected. This makes reruns of the same findings select the same sample
without hand-picking favorable results. The first `corpus-identity` row is
metadata and is not a finding to classify; review only `finding` rows. If fewer
findings exist, review all of them. If no high-confidence finding exists, no
precision claim is possible.

[`false-positive-review.csv`](false-positive-review.csv) documents the columns;
Gate C review must use the identity-bound generated worksheet. After verifying
its result binding, inspect the pinned source and rule evidence for every
`finding` row, then set `classification` to exactly one of:

- `true-positive`: the construct resolves to the rule subject and the reported
  reachable timeline applies;
- `false-positive`: name resolution, context, reachability, or matcher semantics
  do not support the finding;
- `unresolved`: evidence is insufficient or reviewers disagree.

Record reviewer identity and a concise reason. A false positive also requires a
`regression_fixture` path and a passing negative test before Gate C. Resolve
every `unresolved` row before calculating precision.

For a completed sample:

```text
precision = true_positive / (true_positive + false_positive)
```

Gate C requires at least 95% precision for sampled high-confidence findings.
Report the sample size, counts, precision, selection method, PyAhead version,
registry revision, and exact corpus-result digest. Independent review is
recommended for borderline receiver, shadowing, and reachability cases.

## Complete Gate C evidence

The accountable evidence document must also show that all false positives have
regression tests and at least ten maintainers agreed to continuous use. Keep
maintainer identities and consent in an appropriately access-controlled record;
the corpus runner deliberately does not collect them. Gate C approval happens
only after those external facts exist and are reviewed.

Delete local checkouts and manifests according to the review retention policy.
Keep only the approved minimal result, completed worksheet, hashes, regression
tests, and Gate C evidence needed for audit.
