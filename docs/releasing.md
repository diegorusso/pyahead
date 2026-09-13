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

Use the locked environment, a clean distribution directory, and a newly created
installer cache. The commands below use a POSIX shell. In PowerShell, create a
unique empty directory under `[System.IO.Path]::GetTempPath()`, assign it to
`$env:PYAHEAD_INSTALLER_CACHE`, and replace each
`$PYAHEAD_INSTALLER_CACHE` below with that expression.

```console
PYAHEAD_INSTALLER_CACHE=$(mktemp -d /tmp/pyahead-release-uv-cache.XXXXXX)
uv sync --frozen --cache-dir "$PYAHEAD_INSTALLER_CACHE"
uv run ruff check .
uv run ruff format --check .
uv run mypy src scripts
uv run pytest
uv run pyahead registry validate
uv run pyahead registry coverage
uv build --clear --offline --cache-dir "$PYAHEAD_INSTALLER_CACHE"
uv run --frozen --offline --cache-dir "$PYAHEAD_INSTALLER_CACHE" python scripts/install_smoke.py --dist-dir dist --kind wheel --installer-cache "$PYAHEAD_INSTALLER_CACHE"
uv run --frozen --offline --cache-dir "$PYAHEAD_INSTALLER_CACHE" python scripts/install_smoke.py --dist-dir dist --kind sdist --installer-cache "$PYAHEAD_INSTALLER_CACHE"
uv run --frozen --offline --cache-dir "$PYAHEAD_INSTALLER_CACHE" python scripts/install_smoke.py --dist-dir dist --kind wheel --offline --installer-cache "$PYAHEAD_INSTALLER_CACHE"
uv run --frozen --offline --cache-dir "$PYAHEAD_INSTALLER_CACHE" python scripts/install_smoke.py --dist-dir dist --kind sdist --offline --installer-cache "$PYAHEAD_INSTALLER_CACHE"
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

Publish only those exact files. Two routes are supported.

`.github/workflows/release.yml` publishes through PyPI trusted publishing when
an operator pushes a `v*` tag. It builds the distributions once, refuses to
continue if the built version does not match the tag, smoke-tests the wheel and
sdist, records their digests, and publishes those same files. The upload runs in
the `pypi` environment, whose required reviewers are what keep publication an
explicit operator action rather than a consequence of pushing a tag. No API
token is stored in this repository: the workflow requests a short-lived OIDC
credential, and the publish step deliberately passes no password input.

Because that workflow builds in CI, the published artifacts are the ones it
built, not the ones built locally in §2. Record the workflow's digests in the
release evidence when publishing this way.

Uploading by hand remains valid and is preferable when the release evidence
already pins locally built artifacts: publish those exact files through an
account with multi-factor authentication. If a token is unavoidable, pass it
through the publisher's environment mechanism and never write it to repository
files or logs.

Publication stays operator-controlled either way. M6 intentionally shipped no
release workflow; the one above was added when publishing began.

## 5. Post-release checks

Install the published version in a new environment on a supported host, run
`pyahead --version`, `registry validate`, `registry coverage`, and the sample
scan from `scripts/install_smoke.py`. Confirm changelog and documentation links
resolve and package-index metadata names the correct Python requirement and
license.

If a release is faulty, do not overwrite files or move its tag. Yank it with a
concise reason, document the issue under `Unreleased`, fix it in a new version,
and repeat the complete process.
