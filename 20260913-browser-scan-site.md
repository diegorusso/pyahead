# A browser-only scan site on GitHub Pages

## Overview

Build a static site where someone pastes a public GitHub repository URL and gets
a PyAhead report, with the entire scan running in their own browser. No server,
no CI job, no queue, no abuse surface, no disclosure question: the source is
fetched by the visitor's browser, analysed there by PyAhead compiled to
WebAssembly, and the report is rendered there. Nothing is submitted to us and
nothing is published about anyone's repository.

The site is published through GitHub Pages from this repository's `gh-pages`
branch, which shares no history with `main`. Task 1 settled that `main` does not
have to change at all.

## What has already been established

These were verified before the plan was written; do not re-derive them.

- **PyAhead runs under Pyodide, on the published metadata.** Measured, not
  inferred: see Task 1's result below. `micropip.install("pyahead==0.2.1")`
  resolves and scans under Pyodide 314.0.6 with no override.
- **There is no version conflict.** An earlier reading of this had Pyodide
  pinned to `libcst 1.6.0` against a `libcst>=1.8` floor, making a floor change
  a prerequisite. That is true of Pyodide 0.28 and 0.29 only. Pyodide 314.0.6
  runs Python 3.14.2 and ships `libcst 1.8.6`, which the floor already accepts.
  Nothing in this repository has to change for the site to exist.
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

## Task 1 was the gate, and it is green

Task 1 asked whether PyAhead runs under a real Pyodide runtime. It does. The
probe ran on an Actions runner because this host has no JavaScript runtime, in
run `34761069701` on the `pyodide-probe` branch, against published `pyahead`
`0.2.1` from PyPI:

| | Pyodide 314.0.6 | Pyodide 0.29.4 |
| --- | --- | --- |
| Python | 3.14.2 | 3.13.2 |
| install | `micropip.install("pyahead==0.2.1")`, no override | `deps=False` over the bundled wheels |
| libcst | 1.8.6, from Pyodide | 1.6.0, from Pyodide |
| packaging / pathspec | 26.3 / 1.1.1, from PyPI | 26.2 / 1.1.1 |
| PyYAML | 6.0.3 | 6.0.2 |
| scan | exit 0, one finding, `CPY0093` | exit 0, one finding, `CPY0093` |
| time | 1.7s runtime load, 3.4s install and scan | 1.8s / 3.4s |

Those times are Node loading WebAssembly from `node_modules` on a warm runner.
They are not the site's first-load time, which is a CDN download in a browser
and is Task 7's measurement. Do not quote them as if they were.

The left column is the one that matters: real dependency metadata, no
overrides, nothing to change here first. The right column answers the question
the plan was originally written around — PyAhead does work on `libcst 1.6` —
but it is a one-file smoke test, not the suite, and it is moot while the
current Pyodide satisfies the floor as published.

Two constraints the probe exposed, which Task 3 must honour:

- **There is no public Python API.** `pyahead.__all__` is `["__version__"]`. The
  browser harness calls `pyahead.cli.main([...])`, which is the stable contract;
  it must not reach into internal modules.
- **The scan root is enforced.** Paths must stay beneath the scan root, so the
  harness writes the file mapping into a directory in the Pyodide filesystem,
  `chdir`s there, and runs `check .` with `--format json --output` and
  `--fail-on never`, then reads the report back off that filesystem.

The working harness is `.github/probe/pyodide-probe.mjs` on the `pyodide-probe`
branch. Task 3 starts from it and moves it onto `gh-pages`, after which
`pyodide-probe` can be deleted.

## Development Approach

- One task at a time. Tasks touching this repository end with its gate green:
  `uv run ruff check .`, `uv run ruff format --check .`,
  `uv run mypy src scripts`, `uv run pytest`.
- Site code lives on `gh-pages`, never on `main`. Do not scaffold it under
  `docs/` or `scripts/`, and never merge the two branches.
- Pin everything: an exact Pyodide version, an exact `pyahead` version from
  PyPI. A site that floats on "latest" breaks silently when either moves. The
  probe used Pyodide 314.0.6 and `pyahead` 0.2.1; the site starts from those.
- Never weaken PyAhead's scan boundary to make a browser scan succeed. A
  repository that cannot be fully fetched produces an incomplete report, which
  is what PyAhead does everywhere else.

## Implementation Steps

### Task 1: Prove PyAhead runs under Pyodide — done

- [x] load Pyodide in Node on an Actions runner, `micropip` install the
      published `pyahead`, and scan a source string end to end; record the
      Pyodide version, the resolved package versions and the report
- [x] confirm the scan is correct and not merely successful: the fixture's one
      expected finding, `CPY0093`, was verified natively first and the probe
      fails if the browser run reports anything else
- [x] **decided**: no `libcst` floor change and no patch release. Pyodide
      314.0.6 ships `libcst 1.8.6`, which `libcst>=1.8,<2` already accepts, so
      the site can depend on `pyahead` as published
- [x] record, for the case where an older Pyodide is ever needed, that PyAhead
      also runs on `libcst 1.6.0` at smoke level. Not acted on; the floor stays
      where it is while it costs nothing

### Task 2: Publish the site — done

- [x] enable Pages on a branch of this repository: `gh-pages` at the repository
      root, a branch sharing no history with `main`
- [x] add a README stating what the site is, that scanning happens entirely in
      the visitor's browser, and that no repository data reaches any server
- [x] add the Apache-2.0 licence, matching this project
- [x] commit a placeholder page and confirm Pages serves it

**It serves at `https://www.diegor.it/pyahead/`.** The owner's user site
carries the custom domain `www.diegor.it`, and project sites inherit it, so
`diegorusso.github.io/pyahead/` redirects there. Changing the Pages source
through the API does not queue a build; the first one had to be requested
explicitly. HTTPS is enforced, which the site needs anyway: a page
served over HTTP cannot fetch `api.github.com`, because the browser blocks it
as mixed content. `.nojekyll` is committed, since branch-deployed Pages runs
Jekyll by default and would silently drop any path beginning with an underscore.

The publishing source is the `main` branch at the repository root, and stays a
branch rather than a workflow. Decided by the owner on 14 September 2026, and it
matches what the site is: hand-written static files that load Pyodide from a
CDN, with nothing to build.

That leaves one thing to handle by hand. Under branch deploy a red check cannot
stop a deploy, so nothing mechanical prevents publishing a site whose pinned
PyAhead and pinned Pyodide no longer work together. Since the pins only move
when someone edits them, the rule is a process one: run the harness check on
every push, and never merge a pin bump on a red check. Note also that a commit
made by a workflow using `GITHUB_TOKEN` does not trigger a Pages build, so a pin
bump cannot be fully automated under this source anyway.

The site is not at `pyahead.github.io`. That hostname requires a GitHub account
named `pyahead`, and the owner decided on 14 September 2026 not to create one.
A short-lived `diegorusso/pyahead-web` repository was created and removed the
same day, before the branch arrangement was chosen.

### Task 3: The Pyodide harness — done

- [x] load Pyodide 314.0.6, `micropip` install a pinned `pyahead`, and expose
      one function taking a mapping of path to source text and returning the
      `report-v1` JSON (`scan.mjs`)
- [x] surface load progress, as named stages rather than a frozen page
- [x] cache the runtime: the second scan in a session re-downloads nothing,
      measured at 0.9s against 5.9s for the first
- [x] verify the returned JSON validates against the published
      `report-v1.json` schema, fetched at the matching tag

The three pure-Python wheels are vendored into the site rather than installed
from PyPI. Pinning is the obvious reason; the better one is that it keeps PyPI
off the runtime path, which is what makes the host allowlist assertable. libcst
and PyYAML come from Pyodide's own distribution.

### Task 4: Fetching a repository in the browser — done

- [x] accept `https://github.com/owner/repo`, optionally `/tree/<ref>`, and the
      `owner/repo` shorthand; refuse everything else by name
- [x] one `api.github.com` call for the recursive tree, then `.py` blobs only
- [x] fetch from `raw.githubusercontent.com` with bounded concurrency and three
      caps — file count, per-file size and total size — naming what each skips
- [x] handle the 60-per-hour limit explicitly, including when it resets, and
      distinguish it from a 403 that is not a rate limit
- [x] handle the repository that does not exist, is private, is empty, or has
      no Python, each with its own message

The per-file cap is PyAhead's own default rather than a new number: a larger
file would be refused by the analyser anyway. Symlinks and submodules are
excluded and reported — see Task 7, which is where that was found.

### Task 5: Rendering the report — done

- [x] summary counts, findings grouped by action version, each with rule,
      location, subject and remediation link
- [x] repository-derived values cannot become markup, and the check enforces it
      structurally: `mount` is handed a document that throws on any access to
      `innerHTML`, `outerHTML` or `insertAdjacentHTML`, so a future edit that
      introduces a markup path fails whatever it contains
- [x] incompleteness shown as its own banner, above the findings
- [x] the raw JSON offered for download

Documentation links are made only for `https` URLs, so a `javascript:` URL
renders as inert prose.

### Task 6: The site itself — done

- [x] a landing page with the input and a worked example that runs without
      typing a URL: three bundled files, five findings, three Python versions
- [x] an about page covering what PyAhead does and does not detect, linking to
      `docs/usage.md` and `docs/security-and-privacy.md`
- [x] the browser requirement and the first-load cost stated next to the button
- [x] usable on a narrow screen, with the explanatory page readable without
      JavaScript and a `noscript` note on the scan page

### Task 7: Verify acceptance — done

- [x] three real repositories of different sizes, in Chromium:

| | files | wall clock | outcome |
| --- | --- | --- | --- |
| `benjaminp/six` | 4 | 8.8s | complete |
| `pallets/click` | 90 | 49.7s | complete |
| `django/django` | 400 (capped) | 64.5s | reported incomplete |

- [x] the browser report matches the CLI at the same commit: `psf/requests` at
      `v2.32.3`, scanned both ways, identical findings, identical summary
      counts, same registry revision, 36 files each
- [x] no request leaves the browser except to the pinned CDN and the site's own
      origin, collected from real requests rather than asserted
- [x] first load ~7.3MB and 5.9s to a usable scan; 0.9s on the second

Everything above runs on every push, in `.github/workflows/site-check.yml` on
the `gh-pages` branch: 140 assertions across a Node harness check, a fetching
check, a renderer check, a Chromium check of the real page, and the parity
comparison against the installed CLI.

## Post-Completion (operator, not automatable)

1. **The file-count cap is 400, set from measurement.** Django hits it and
   finishes in 64.5s having reported itself incomplete, which is the behaviour
   that matters. Raising it trades a longer wait for fewer truncated scans;
   lowering it does the reverse. Revisit with real usage, not in the abstract.
2. **Decide how the site tracks PyAhead releases.** The pinned version has to be
   bumped deliberately, and a report rendered by an old pin is a report about an
   old analyser. Under branch deploy nothing blocks a bad bump from deploying,
   so the rule is: do not merge a pin change on a red check.
3. **Announce it.** A scan that needs no install is the cheapest possible way for
   someone to try PyAhead, and it is worthless unmentioned.
4. **Decide whether `main` should link to it.** `README.md` does not mention the
   site, so nobody arriving at the repository learns it exists.
