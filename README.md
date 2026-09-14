# PyAhead scan site

A static site that scans a public GitHub repository for upcoming Python
incompatibilities, and runs the whole scan in your browser.

Paste a repository URL. The page fetches that repository's Python files, runs
[PyAhead](https://github.com/diegorusso/pyahead) against them through
WebAssembly, and renders the report. That is the entire flow.

## Nothing is sent anywhere

There is no server here. No repository content, URL or report reaches any
machine operated by this project, because there is no such machine — the site
is static files on GitHub Pages, and the scan happens inside your own browser.
Nothing is stored, nothing is published, and no account is needed.

The page talks to exactly three hosts: a CDN for the Python runtime,
`api.github.com` to list a repository's files, and `raw.githubusercontent.com`
to fetch them. Those requests come from your browser, not from us.

PyAhead is a static analyser. It reads source as data; it never imports the
code it scans, installs its dependencies, or runs its tests.

## What it does not do

- Private repositories. The site is unauthenticated, so it can only read public
  source.
- Large repositories in full. Fetching happens file by file under a cap; a scan
  that hits the cap says so rather than presenting a partial result as a clean
  one.
- Continuous monitoring. This is a one-shot scan. To scan on a schedule, in CI,
  or against private code, install the CLI: `pip install pyahead`.

## Licence

Apache-2.0, matching PyAhead itself. See [LICENSE](LICENSE).
