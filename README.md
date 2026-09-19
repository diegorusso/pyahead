# Plans

Work-package plans for [PyAhead](https://github.com/diegorusso/pyahead),
on a branch of their own because they are scaffolding, not documentation.

A plan is the scope handed to an execution run: an overview, an ordered list of
tasks, and the checkboxes that record what was done. Once the work lands, the
durable account is the code, `docs/design.md`, the evidence records and the
commit messages — so plans do not belong beside documentation someone reads to
use the tool.

This branch shares no history with `main`.

## What is here

| | |
| --- | --- |
| `20260913-browser-scan-site.md` | the `0.3` browser scan site, complete; the site is on `gh-pages` |
| `20260901-pyahead-0-1-0a2-release-readiness.md` | the `0.1.0a2` release, superseded — `0.2.1` shipped, and its open boxes describe a release that has been overtaken |
| `completed/20260903-validate-pyahead-against-pypi-top-1000.md` | designing the PyPI top-1000 validation protocol |
| `completed/20260910-run-pypi-top-1000-validation.md` | running it; the protocol it produced is `docs/pypi-validation.md` on `main` |
| `completed/20260913-investigate-binding-not-visible.md` | the 835 `binding-not-visible` findings |
| `completed/20260917-curate-python-3-9-and-3-10-changes.md` | opening the window at 3.8 and curating the 3.9 and 3.10 changes; released as 0.3.0 |

## Working on one

    git fetch origin plans
    git worktree add ../pyahead-plans plans

A plan being executed belongs on the branch doing the work, so an execution run
can see it, and goes away when that work lands. This branch is where finished
ones are kept.
