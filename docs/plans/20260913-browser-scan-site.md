# A browser-only scan site on GitHub Pages

## Overview

Build a static site where someone pastes a public GitHub repository URL and gets
a PyAhead report, with the entire scan running in their own browser. No server,
no CI job, no queue, no abuse surface, no disclosure question: the source is
fetched by the visitor's browser, analysed there by PyAhead compiled to
WebAssembly, and the report is rendered there. Nothing is submitted to us and
nothing is published about anyone's repository.

The site is a separate public repository published through GitHub Pages. This
repository changes only if Task 1 finds that it must.

## What has already been established

These were verified before the plan was written; do not re-derive them.

- **PyAhead's stack runs under Pyodide.** `libcst` ships a WebAssembly build in
  Pyodide, so the Rust parser is available in the browser. `pyahead`, `pathspec`
  and `packaging` are pure-Python wheels that `micropip` installs from PyPI.
  `PyYAML` is already in Pyodide.
- **One version conflict blocks it.** Pyodide 0.28 and 0.29 both ship
  `libcst 1.6.0`; `pyahead` requires `libcst>=1.8,<2`. That floor was set in the
  first M1 commit as a recent-version choice, not for any 1.8 API: everything
  PyAhead touches (`cst.*` node types, `libcst.metadata` providers,
  `ScopeProvider`, `QualifiedName`, `helpers.get_full_name_for_node`) long
  predates 1.8. Whether it actually works on 1.6 is **unproven** and is Task 1.
- **The browser can fetch the source.** `raw.githubusercontent.com` returns
  `access-control-allow-origin: *`, so file contents are fetchable directly and
  are CDN-served rather than API-rate-limited. `api.github.com` also allows all
  origins but is limited to **60 requests per hour per IP** unauthenticated, so
  it may be used for the one recursive tree listing and nothing per-file.
- **The tarball route is closed.** `codeload.github.com` returns
  `access-control-allow-origin: https://render.githubusercontent.com`, so a page
  on `github.io` cannot fetch a repository archive. Per-file fetching is the
  only route.

## Why this is safe in a way the server design was not

PyAhead is a static analyser: it reads source, never imports it, never installs
its dependencies, never runs its tests. Running it in the visitor's browser
means no code of ours touches a stranger's repository, no results are published,
and no Actions minutes are spent. The abuse, disclosure and retention questions
that a submit-a-URL service would raise do not arise here.

The one boundary that still matters is the browser's own: the page must not
execute fetched repository content, and must escape it when rendering. Source
text arrives as data and stays data.

## Task 1 decides whether the rest is possible

If PyAhead does not work on `libcst 1.6`, everything below is blocked, and the
alternatives are worse: waiting for Pyodide to ship a newer libcst, or building
one. Prove it first, on a real browser or a real Pyodide runtime, not by
reasoning about API surfaces.

This host cannot run that test: there is no Node, Deno or browser available, and
`libcst 1.6.0` has no aarch64 wheel so it cannot even be installed natively
here. Task 1 must run somewhere that can, which in practice means a GitHub
Actions runner or a real browser.

## Development Approach

- One task at a time. Tasks touching this repository end with its gate green:
  `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy src scripts`, `uv run pytest`.
- Site code lives in the new repository, not here. Do not scaffold it under
  `docs/` or `scripts/`.
- Pin everything: an exact Pyodide version, an exact `pyahead` version from
  PyPI. A site that floats on "latest" breaks silently when either moves.
- Never weaken PyAhead's scan boundary to make a browser scan succeed. A
  repository that cannot be fully fetched produces an incomplete report, which
  is what PyAhead does everywhere else.

## Implementation Steps

### Task 1: Prove PyAhead runs on Pyodide's libcst

- [ ] in a scratch workflow on a GitHub Actions runner, install `libcst==1.6.0`
      and the published `pyahead`, then run this repository's full test suite
      against it; record the exact pass, fail and skip counts
- [ ] if tests fail, identify for each whether it is a real 1.6 incompatibility
      or an artefact of the pin, and name the libcst API responsible
- [ ] independently, load Pyodide in a headless browser or Node, `micropip`
      install `pyahead`, and scan a small source string end to end; record the
      Pyodide version, the resolved package versions, and the JSON report
- [ ] **decide and record**: lower the `libcst` floor to `>=1.6`, or stop. If
      lowering, that is a change to this repository's `pyproject.toml` and needs
      its own patch release before the site can depend on it
- [ ] if PyAhead does not work on 1.6, stop here and report which API is
      missing; do not attempt to vendor or patch libcst

### Task 2: Create the site repository

- [ ] create the public repository and enable Pages from its default branch
- [ ] add a README stating what the site is, that scanning happens entirely in
      the visitor's browser, and that no repository data reaches any server
- [ ] add the Apache-2.0 licence, matching this project
- [ ] commit a placeholder page and confirm Pages serves it

### Task 3: The Pyodide harness

- [ ] load a pinned Pyodide from a CDN, `micropip` install a pinned `pyahead`,
      and expose one JavaScript function that takes a mapping of path to source
      text and returns the `report-v1` JSON
- [ ] surface load progress: the first load fetches several megabytes of
      WebAssembly, and a page that appears frozen for that long will be
      abandoned
- [ ] cache the Pyodide runtime so a second scan in the same session does not
      re-download it
- [ ] verify the returned JSON validates against the published
      `report-v1.json` schema

### Task 4: Fetching a repository in the browser

- [ ] accept a `https://github.com/owner/repo` URL, optionally with a branch or
      tag, and reject anything else with a clear message
- [ ] resolve the ref and list the tree with one `api.github.com` call; select
      only `.py` files
- [ ] fetch each selected file from `raw.githubusercontent.com` with bounded
      concurrency, a per-file size cap and an overall file-count cap; report
      what was skipped rather than silently truncating
- [ ] handle the 60-per-hour API limit explicitly: detect a rate-limited
      response and tell the visitor what happened and when it resets
- [ ] handle the repository that does not exist, is private, or is empty, each
      with its own message

### Task 5: Rendering the report

- [ ] render the `report-v1` JSON: summary counts, findings grouped by action
      version, each with rule, location, subject and remediation link
- [ ] escape every repository-derived value; add a test that a path or subject
      containing HTML metacharacters renders inert
- [ ] show incompleteness prominently. A report that skipped files is not a
      clean scan, and the page must not let a visitor read it as one
- [ ] offer the raw JSON for download, so a visitor can keep the machine-readable
      result

### Task 6: The site itself

- [ ] a landing page with the URL input, a short explanation, and a worked
      example someone can run without typing a URL
- [ ] an about page covering what PyAhead does and does not detect, linking to
      this repository's `docs/usage.md` limitations and
      `docs/security-and-privacy.md`
- [ ] state the browser requirement plainly: WebAssembly, and a few megabytes of
      download on first use
- [ ] make it usable on a narrow screen, and readable without JavaScript for the
      explanatory pages even though the scan needs it

### Task 7: Verify acceptance

- [ ] scan three real repositories of different sizes in a browser; record the
      wall-clock time, the file counts and whether each completed
- [ ] confirm the browser report matches `pyahead check --format json` run
      locally at the same commit, for at least one repository
- [ ] confirm no network request leaves the browser except to the pinned CDN,
      `api.github.com` and `raw.githubusercontent.com`
- [ ] record the first-load download size and the time to first usable scan

## Post-Completion (operator, not automatable)

1. **Decide the file-count cap.** Every repository above it gets an incomplete
   report. Too low is useless, too high hangs the browser. Set it from Task 7's
   measurements, not from a guess.
2. **Decide how the site tracks PyAhead releases.** The pinned version has to be
   bumped deliberately, and a report rendered by an old pin is a report about an
   old analyser.
3. **Announce it.** A scan that needs no install is the cheapest possible way for
   someone to try PyAhead, and it is worthless unmentioned.
