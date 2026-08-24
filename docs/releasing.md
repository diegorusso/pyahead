# Release process

Releases are explicit maintainer actions. CI builds and verifies candidates but
does not publish packages. Never replace an existing tag or package-index file.

## 1. Prepare the candidate

1. Confirm the release version follows Semantic Versioning and is not already
   present in Git or the package index.
2. Update `src/pyahead/__init__.py`, package classifiers when needed, and
   `CHANGELOG.md` in the same candidate.
3. Confirm the README limitations, supported hosts, security policy, and
   registry coverage are current.
4. Require a clean, reviewed exact commit. M6 candidates also require successful
   Linux, macOS, Windows, build, and wheel/sdist install jobs for that SHA.

PyPI project-name availability and Apache-2.0 ownership approval remain explicit
maintainer checks before the first publication.

## 2. Verify locally

Use the locked environment and a clean distribution directory:

```console
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv run pyahead registry validate
uv run pyahead registry coverage
uv build --clear
uv run python scripts/install_smoke.py --dist-dir dist --kind wheel
uv run python scripts/install_smoke.py --dist-dir dist --kind sdist
uv run python scripts/benchmark.py --repeat 3 --output benchmark-results.json
git diff --check
```

Inspect wheel and sdist contents for source code, registry data, user
documentation, license, changelog, tests, and release scripts. Reject generated
caches, local paths, credentials, corpus checkouts, corpus results, and benchmark
results.

## 3. Record artifacts

Create SHA-256 digests without modifying the distributions:

```console
python -c "import hashlib,pathlib; [print(hashlib.sha256(p.read_bytes()).hexdigest(), p.name) for p in sorted(pathlib.Path('dist').iterdir()) if p.is_file()]"
```

Retain the exact commit, hosted job URLs, artifact names, sizes, and digests in
the release review. Confirm installed `pyahead --version` equals the tag version
and both artifacts produce the same sample-scan registry revision.

## 4. Tag and publish

After approval, create one annotated `v<version>` tag on the verified commit and
push that tag without rewriting it. Create a GitHub release from the same tag
and attach the verified wheel, sdist, and digest list.

Publish only those exact files through an account with multi-factor
authentication or a narrowly scoped trusted-publishing identity. If a token is
unavoidable, pass it through the publisher's environment mechanism and never
write it to repository files or logs. Publication is operator-controlled; this
repository intentionally provides no automatic release workflow in M6.

## 5. Post-release checks

Install the published version in a new environment on a supported host, run
`pyahead --version`, `registry validate`, `registry coverage`, and the sample
scan from `scripts/install_smoke.py`. Confirm changelog and documentation links
resolve and package-index metadata names the correct Python requirement and
license.

If a release is faulty, do not overwrite files or move its tag. Yank it with a
concise reason, document the issue under `Unreleased`, fix it in a new version,
and repeat the complete process.
