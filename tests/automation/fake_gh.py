"""Offline GitHub CLI stand-in for publication tests."""

# This module is an executable fixture and intentionally prints CLI responses.
# ruff: noqa: C901, EM101, PLR0911, PLR0912, PLR0915, S603, T201, TRY003, TRY004

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

EVENTS_ENV = "PYAHEAD_FAKE_GH_EVENTS"
PR_LIST_ENV = "PYAHEAD_FAKE_GH_PR_LIST"
RUN_PLAN_ENV = "PYAHEAD_FAKE_GH_RUN_PLAN"
RUN_STATE_ENV = "PYAHEAD_FAKE_GH_RUN_STATE"
GIT_ENV = "PYAHEAD_FAKE_GIT"
GIT_REMOTE_ENV = "PYAHEAD_FAKE_GIT_REMOTE"
DUPLICATE_DISPATCH_ENV = "PYAHEAD_FAKE_GH_DUPLICATE_DISPATCH"
DELAYED_DUPLICATE_ENV = "PYAHEAD_FAKE_GH_DELAYED_DUPLICATE"
UNRELATED_DISPATCH_ENV = "PYAHEAD_FAKE_GH_UNRELATED_DISPATCH"
RACE_EXACT_REF_ENV = "PYAHEAD_FAKE_GH_RACE_EXACT_REF"
CREATE_REF_RESULT_ENV = "PYAHEAD_FAKE_GH_CREATE_REF_RESULT"
CROWDED_DUPLICATE_ENV = "PYAHEAD_FAKE_GH_CROWDED_DUPLICATE"
REPOSITORY = "github.com/example/pyahead"
WEB_ROOT = "https://github.com/example/pyahead"
API_JOB_LOG_ARGC = 4


def _record(arguments: list[str]) -> None:
    """Append a fake GitHub invocation to the external test log."""
    path_value = os.environ.get(EVENTS_ENV)
    if path_value is None:
        return
    path = Path(path_value)
    events: list[object] = []
    if path.exists():
        loaded = cast("object", json.loads(path.read_text(encoding="utf-8")))
        if not isinstance(loaded, list):
            raise RuntimeError("fake GitHub event log is malformed")
        events = loaded
    events.append(arguments)
    path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")


def _run_state() -> tuple[Path, dict[str, object]]:
    """Load the fake workflow runs created for the current fixture."""
    path = Path(os.environ[RUN_STATE_ENV])
    if not path.exists():
        return path, {"job_logs": {}, "runs": [], "view_count": 0}
    loaded = cast("object", json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(loaded, dict):
        raise RuntimeError("fake GitHub run state is malformed")
    state = cast("dict[str, object]", loaded)
    if (
        not isinstance(state.get("runs"), list)
        or type(state.get("view_count")) is not int
        or not isinstance(state.get("job_logs", {}), dict)
    ):
        raise RuntimeError("fake GitHub run state fields are malformed")
    state.setdefault("job_logs", {})
    return path, state


def _candidate_sha(branch: str) -> str:
    """Resolve the immutable candidate from the fixture's local bare origin."""
    git = os.environ.get(GIT_ENV, "git")
    result = subprocess.run(
        [git, "ls-remote", os.environ[GIT_REMOTE_ENV], f"refs/heads/{branch}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    line = result.stdout.strip()
    if not line or "\t" not in line:
        raise RuntimeError("fake GitHub could not resolve the candidate ref")
    return line.split("\t", maxsplit=1)[0]


def _api_create_ref(argv: list[str]) -> int:
    """Atomically create one final fixture ref, including a controllable race."""
    expected_endpoint = "repos/example/pyahead/git/refs"
    if argv[:6] != [
        "api",
        "--hostname",
        "github.com",
        "--method",
        "POST",
        expected_endpoint,
    ]:
        return 42
    fields: dict[str, str] = {}
    remaining = argv[6:]
    if remaining[:1] != ["--include"]:
        return 42
    remaining = remaining[1:]
    if len(remaining) % 2:
        return 42
    for flag, value in zip(remaining[::2], remaining[1::2], strict=True):
        if flag != "--raw-field":
            return 42
        name, separator, field_value = value.partition("=")
        if not separator or name in fields:
            return 42
        fields[name] = field_value
    if set(fields) != {"ref", "sha"}:
        return 42
    reference = fields["ref"]
    sha = fields["sha"]
    if not reference.startswith("refs/heads/") or not sha:
        return 42
    git = os.environ.get(GIT_ENV, "git")
    remote = os.environ[GIT_REMOTE_ENV]
    race_value = os.environ.get(RACE_EXACT_REF_ENV)
    if race_value:
        sentinel = Path(race_value)
        if sentinel.exists():
            sentinel.unlink()
            subprocess.run(
                [
                    git,
                    "--git-dir",
                    remote,
                    "update-ref",
                    reference,
                    sha,
                    "0" * len(sha),
                ],
                check=True,
            )
    configured_result = os.environ.get(CREATE_REF_RESULT_ENV)
    failures = {
        "alternate-422": (422, "Validation Failed"),
        "400": (400, "Bad Request"),
        "403": (403, "Forbidden"),
    }
    if configured_result in failures:
        status, reason = failures[configured_result]
        print(f"HTTP/2.0 {status} {reason}\nContent-Type: application/json\n")
        print(json.dumps({"message": reason}))
        sys.stderr.write(f"gh: {reason} (HTTP {status})\n")
        return 1
    exists = subprocess.run(
        [git, "--git-dir", remote, "show-ref", "--verify", "--quiet", reference],
        check=False,
    )
    if exists.returncode == 0:
        print("HTTP/2.0 422 Unprocessable Entity\nContent-Type: application/json\n")
        print(json.dumps({"message": "Reference already exists"}))
        sys.stderr.write("gh: Reference already exists (HTTP 422)\n")
        return 1
    if exists.returncode != 1:
        return 42
    created = subprocess.run(
        [
            git,
            "--git-dir",
            remote,
            "update-ref",
            reference,
            sha,
            "0" * len(sha),
        ],
        check=False,
    )
    if created.returncode != 0:
        print("HTTP/2.0 422 Unprocessable Entity\nContent-Type: application/json\n")
        print(json.dumps({"message": "Reference already exists"}))
        sys.stderr.write("gh: Reference already exists (HTTP 422)\n")
        return 1
    print("HTTP/2.0 201 Created\nContent-Type: application/json\n")
    if configured_result == "malformed-success":
        print("{malformed")
    else:
        git_object = {"sha": sha, "type": "commit"}
        if configured_result == "missing-type-success":
            git_object.pop("type")
        elif configured_result == "wrong-type-success":
            git_object["type"] = "tree"
        print(json.dumps({"object": git_object, "ref": reference}))
    return 0


def _workflow_run(argv: list[str]) -> int:
    ref_index = argv.index("--ref")
    branch = argv[ref_index + 1]
    state_path, state = _run_state()
    runs = cast("list[dict[str, object]]", state["runs"])
    field = argv[argv.index("--field") + 1]
    _name, separator, token = field.partition("=")
    if not separator or not token:
        raise RuntimeError("fake GitHub dispatch requires a one-time token")
    candidate = {
        "branch": branch,
        "databaseId": 9001 + len(runs),
        "headSha": _candidate_sha(branch),
        "poll": 0,
        "displayTitle": f"PyAhead autopilot {token}",
        "workflowName": argv[2],
    }
    runs.append(candidate)
    if os.environ.get(DUPLICATE_DISPATCH_ENV) == "1":
        duplicate = dict(candidate)
        duplicate["databaseId"] = cast("int", candidate["databaseId"]) + 1
        runs.append(duplicate)
    if os.environ.get(UNRELATED_DISPATCH_ENV) == "1":
        unrelated = dict(candidate)
        unrelated["databaseId"] = (
            max(cast("int", item["databaseId"]) for item in runs) + 1
        )
        unrelated["displayTitle"] = "PyAhead autopilot unrelated-manual-token"
        runs.append(unrelated)
    crowded = os.environ.get(CROWDED_DUPLICATE_ENV)
    if crowded is not None:
        count = int(crowded)
        for index in range(count):
            unrelated = dict(candidate)
            unrelated["databaseId"] = (
                max(cast("int", item["databaseId"]) for item in runs) + 1
            )
            unrelated["displayTitle"] = f"PyAhead autopilot unrelated-{index}"
            runs.append(unrelated)
        duplicate = dict(candidate)
        duplicate["databaseId"] = (
            max(cast("int", item["databaseId"]) for item in runs) + 1
        )
        runs.append(duplicate)
    state["runs"] = runs
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return 0


def _run_list(argv: list[str]) -> int:
    _path, state = _run_state()
    branch = argv[argv.index("--branch") + 1]
    commit = argv[argv.index("--commit") + 1]
    runs = [
        run
        for run in cast("list[dict[str, object]]", state["runs"])
        if run.get("branch") == branch and run.get("headSha") == commit
    ]
    limit = int(argv[argv.index("--limit") + 1])
    runs = sorted(
        runs,
        key=lambda item: cast("int", item["databaseId"]),
        reverse=True,
    )[:limit]
    print(
        json.dumps(
            [
                {
                    "conclusion": None,
                    "createdAt": "2026-08-03T00:00:00Z",
                    "databaseId": run["databaseId"],
                    "displayTitle": run["displayTitle"],
                    "event": "workflow_dispatch",
                    "headSha": run["headSha"],
                    "status": "queued",
                    "url": f"{WEB_ROOT}/actions/runs/{run['databaseId']}",
                    "workflowName": run["workflowName"],
                }
                for run in runs
            ]
        )
    )
    return 0


def _run_view(argv: list[str]) -> int:
    state_path, state = _run_state()
    run_id = int(argv[2])
    runs = cast("list[dict[str, object]]", state["runs"])
    matching = [run for run in runs if run.get("databaseId") == run_id]
    if len(matching) != 1:
        return 42
    run = matching[0]
    plan_path = Path(os.environ[RUN_PLAN_ENV])
    plan: list[object] = []
    if plan_path.exists():
        loaded = cast("object", json.loads(plan_path.read_text(encoding="utf-8")))
        if not isinstance(loaded, list) or not all(
            isinstance(item, dict) for item in loaded
        ):
            raise RuntimeError("fake GitHub run plan is malformed")
        plan = loaded
    poll = state.get("view_count", 0)
    if type(poll) is not int or poll < 0:
        raise RuntimeError("fake GitHub poll counter is malformed")
    raw = plan[min(poll, len(plan) - 1)] if plan else {}
    result = cast("dict[str, object]", raw)
    status = result.get("status", "completed")
    conclusion = result.get("conclusion", "success" if status == "completed" else None)
    head_sha = result.get("headSha", run["headSha"])
    raw_jobs = result.get(
        "jobs",
        [
            {
                "conclusion": "success" if status == "completed" else None,
                "databaseId": 1,
                "name": "fixture-hosted",
                "status": status,
                "url": f"{WEB_ROOT}/actions/runs/{run_id}/job/1",
            }
        ],
    )
    jobs: object = raw_jobs
    if isinstance(raw_jobs, list):
        normalized: list[object] = []
        job_logs = cast("dict[str, object]", state["job_logs"])
        for index, raw_job in enumerate(raw_jobs):
            if not isinstance(raw_job, dict):
                normalized.append(raw_job)
                continue
            job = cast("dict[str, object]", dict(raw_job))
            raw_url = job.get("url")
            url_job_id = (
                int(raw_url.rstrip("/").rsplit("/", maxsplit=1)[-1])
                if isinstance(raw_url, str)
                and raw_url.rstrip("/").rsplit("/", maxsplit=1)[-1].isdigit()
                else None
            )
            job_id = job.get("databaseId", url_job_id or index + 1)
            job["databaseId"] = job_id
            if "url" not in job:
                job["url"] = f"{WEB_ROOT}/actions/runs/{run_id}/job/{job_id}"
            log = job.pop("log", f"fixture log for job {job_id}\n")
            error_once = job.pop("log_error_once", False)
            run_view_empty = job.pop("log_run_view_empty", False)
            api_error_once = job.pop("log_api_error_once", False)
            api_empty = job.pop("log_api_empty", False)
            key = f"{run_id}:{job_id}"
            existing = job_logs.get(key)
            failed_once = (
                existing.get("failed_once", False)
                if isinstance(existing, dict)
                else False
            )
            api_failed_once = (
                existing.get("api_failed_once", False)
                if isinstance(existing, dict)
                else False
            )
            job_logs[key] = {
                "api_empty": api_empty,
                "api_error_once": api_error_once,
                "api_failed_once": api_failed_once,
                "content": log,
                "error_once": error_once,
                "failed_once": failed_once,
                "run_view_empty": run_view_empty,
            }
            normalized.append(job)
        jobs = normalized
    if (
        status == "completed"
        and os.environ.get(DELAYED_DUPLICATE_ENV) == "1"
        and state.get("delayed_duplicate_added") is not True
    ):
        duplicate = dict(run)
        duplicate["databaseId"] = (
            max(cast("int", item["databaseId"]) for item in runs) + 1
        )
        runs.append(duplicate)
        state["runs"] = runs
        state["delayed_duplicate_added"] = True
    state["view_count"] = poll + 1
    state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "conclusion": conclusion,
                "databaseId": run["databaseId"],
                "displayTitle": run["displayTitle"],
                "event": "workflow_dispatch",
                "headSha": head_sha,
                "jobs": jobs,
                "status": status,
                "url": f"{WEB_ROOT}/actions/runs/{run['databaseId']}",
                "workflowName": run["workflowName"],
            }
        )
    )
    return 0


def _run_job_log(argv: list[str]) -> int:
    """Return one complete hosted-job log with an optional transient failure."""
    if len(argv) != 6 or argv[3] != "--job" or argv[5:] != ["--log"]:  # noqa: PLR2004
        return 42
    run_id = int(argv[2])
    job_id = int(argv[4])
    state_path, state = _run_state()
    job_logs = cast("dict[str, object]", state["job_logs"])
    raw = job_logs.get(f"{run_id}:{job_id}")
    if not isinstance(raw, dict):
        sys.stderr.write("fake GitHub job log is unavailable\n")
        return 1
    record = cast("dict[str, object]", raw)
    if record.get("error_once") is True and record.get("failed_once") is not True:
        record["failed_once"] = True
        job_logs[f"{run_id}:{job_id}"] = record
        state["job_logs"] = job_logs
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        sys.stderr.write("transient fake GitHub job-log failure\n")
        return 1
    content = record.get("content")
    if not isinstance(content, str):
        sys.stderr.write("fake GitHub job log is malformed\n")
        return 1
    if record.get("run_view_empty") is True:
        return 0
    sys.stdout.write(content)
    return 0


def _api_job_log(argv: list[str]) -> int:
    """Return one repository-bound hosted-job log through the API fallback."""
    prefix = "repos/example/pyahead/actions/jobs/"
    if (
        len(argv) != API_JOB_LOG_ARGC
        or argv[:3] != ["api", "--hostname", "github.com"]
        or not argv[3].startswith(prefix)
        or not argv[3].endswith("/logs")
    ):
        return 42
    raw_job_id = argv[3][len(prefix) : -len("/logs")]
    if not raw_job_id.isdigit():
        return 42
    state_path, state = _run_state()
    job_logs = cast("dict[str, object]", state["job_logs"])
    matches = [
        (key, value)
        for key, value in job_logs.items()
        if key.endswith(f":{raw_job_id}")
    ]
    if len(matches) != 1 or not isinstance(matches[0][1], dict):
        sys.stderr.write("fake GitHub API job log is unavailable\n")
        return 1
    key, raw = matches[0]
    record = cast("dict[str, object]", raw)
    if (
        record.get("api_error_once") is True
        and record.get("api_failed_once") is not True
    ):
        record["api_failed_once"] = True
        job_logs[key] = record
        state["job_logs"] = job_logs
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        sys.stderr.write("transient fake GitHub API job-log failure\n")
        return 1
    content = record.get("content")
    if not isinstance(content, str):
        sys.stderr.write("fake GitHub API job log is malformed\n")
        return 1
    if record.get("api_empty") is True:
        return 0
    sys.stdout.write(content)
    return 0


def main(arguments: list[str] | None = None) -> int:
    """Implement the authenticated draft-PR calls used by the orchestrator."""
    argv = list(sys.argv[1:] if arguments is None else arguments)
    _record(argv)
    if "--repo" in argv:
        repository_index = argv.index("--repo")
        if argv[repository_index + 1] != REPOSITORY:
            raise RuntimeError("orchestrator selected the wrong GitHub repository")
        del argv[repository_index : repository_index + 2]
    if argv == ["--version"]:
        print("gh version fixture")
        return 0
    if argv == ["auth", "status", "--hostname", "github.com"]:
        return 0
    if argv == ["api", "--help"]:
        print("--hostname --method --raw-field --include")
        return 0
    if argv == ["workflow", "run", "--help"]:
        print("--ref --field")
        return 0
    if argv == ["run", "list", "--help"]:
        print("--branch --commit --event --json --workflow")
        return 0
    if argv == ["run", "view", "--help"]:
        print("--job --json --log")
        return 0
    if argv == ["repo", "view", REPOSITORY, "--json", "nameWithOwner,url"]:
        print(json.dumps({"nameWithOwner": "example/pyahead", "url": WEB_ROOT}))
        return 0
    if (
        argv[:3] == ["api", "--hostname", "github.com"]
        and len(argv) == API_JOB_LOG_ARGC
        and "/actions/jobs/" in argv[3]
    ):
        return _api_job_log(argv)
    if argv and argv[0] == "api":
        return _api_create_ref(argv)
    if argv[:2] == ["workflow", "run"]:
        return _workflow_run(argv)
    if argv[:2] == ["run", "list"]:
        return _run_list(argv)
    if argv[:2] == ["run", "view"] and "--job" in argv:
        return _run_job_log(argv)
    if argv[:2] == ["run", "view"]:
        return _run_view(argv)
    if argv[:2] == ["pr", "list"]:
        print(os.environ.get(PR_LIST_ENV, "[]"))
        return 0
    if argv[:2] == ["pr", "create"]:
        print(f"{WEB_ROOT}/pull/1")
        return 0
    if argv[:2] == ["pr", "edit"]:
        return 0
    return 41


if __name__ == "__main__":
    raise SystemExit(main())
