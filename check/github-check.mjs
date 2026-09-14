// Checks the fetching layer without touching the network, then once with it.
//
// Every failure mode a visitor can hit is exercised against a stub, because
// they are exactly the paths that never occur during ordinary use and so are
// never noticed when they rot: the rate limit, the private repository, the
// empty one, the tree GitHub refuses to finish listing.

import { parseRepositoryUrl, listPythonFiles, fetchSources, RepositoryError, LIMITS, API_ORIGIN, RAW_ORIGIN } from "../github.mjs";

const failures = [];
function check(description, condition, detail = "") {
  if (condition) console.log(`  ok    ${description}`);
  else {
    console.log(`  FAIL  ${description}${detail ? ` — ${detail}` : ""}`);
    failures.push(description);
  }
}

async function refuses(description, run, kind) {
  try {
    await run();
    check(description, false, "did not throw");
  } catch (error) {
    check(description, error instanceof RepositoryError && error.kind === kind, `${error.name}/${error.kind}: ${error.message}`);
  }
}

function stubResponse({ status = 200, body = {}, headers = {}, text = "" }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
    json: async () => body,
    text: async () => text,
  };
}

function tree(entries, truncated = false) {
  return stubResponse({ body: { truncated, tree: entries } });
}

const blob = (path, size = 100) => ({ type: "blob", path, size });

console.log("parsing");
for (const [input, expected] of [
  ["https://github.com/owner/repo", { owner: "owner", repo: "repo", ref: null }],
  ["https://github.com/owner/repo/", { owner: "owner", repo: "repo", ref: null }],
  ["https://github.com/owner/repo.git", { owner: "owner", repo: "repo", ref: null }],
  ["http://github.com/owner/repo", { owner: "owner", repo: "repo", ref: null }],
  ["github.com/owner/repo", { owner: "owner", repo: "repo", ref: null }],
  ["owner/repo", { owner: "owner", repo: "repo", ref: null }],
  ["  https://github.com/owner/repo  ", { owner: "owner", repo: "repo", ref: null }],
  ["https://github.com/owner/repo/tree/main", { owner: "owner", repo: "repo", ref: "main" }],
  ["https://github.com/owner/repo/tree/release/1.x", { owner: "owner", repo: "repo", ref: "release/1.x" }],
  ["https://github.com/a-b/c.d_e", { owner: "a-b", repo: "c.d_e", ref: null }],
]) {
  const got = parseRepositoryUrl(input);
  check(`parses ${JSON.stringify(input)}`, JSON.stringify(got) === JSON.stringify(expected), JSON.stringify(got));
}

for (const [input, kind] of [
  ["", "empty"],
  ["   ", "empty"],
  ["https://gitlab.com/owner/repo", "host"],
  ["https://example.com/owner/repo", "host"],
  ["https://github.com/owner", "malformed"],
  ["not a url at all", "malformed"],
  ["https://github.com/owner/repo/blob/main/setup.py", "unsupported-path"],
  ["https://github.com/owner/repo/pulls", "unsupported-path"],
  ["https://github.com/owner/repo/tree", "unsupported-path"],
]) {
  await refuses(`refuses ${JSON.stringify(input)}`, () => parseRepositoryUrl(input), kind);
}

console.log("\nlisting");
const target = { owner: "o", repo: "r", ref: null };

{
  const result = await listPythonFiles(target, {
    fetch: async () => tree([blob("a.py"), blob("b.txt"), { type: "tree", path: "pkg" }, blob("pkg/c.py")]),
  });
  check("selects only .py blobs", result.files.map((f) => f.path).join(",") === "a.py,pkg/c.py", JSON.stringify(result.files));
  check("counts the bytes it will fetch", result.bytes === 200, String(result.bytes));
}

{
  let requested = null;
  await listPythonFiles({ owner: "o", repo: "r", ref: "release/1.x" }, {
    fetch: async (url) => { requested = url; return tree([blob("a.py")]); },
  });
  check("uses one api.github.com call", requested.startsWith(`${API_ORIGIN}/repos/o/r/git/trees/`));
  check("escapes the ref", requested.includes("release%2F1.x"), requested);
}

{
  let requested = null;
  await listPythonFiles(target, { fetch: async (url) => { requested = url; return tree([blob("a.py")]); } });
  check("defaults to HEAD when no ref is given", requested.includes("/trees/HEAD?"), requested);
}

{
  const limits = { ...LIMITS, maxFiles: 2 };
  const result = await listPythonFiles(target, {
    fetch: async () => tree([blob("a.py"), blob("b.py"), blob("c.py"), blob("d.py")]),
    limits,
  });
  check("applies the file-count cap", result.files.length === 2, String(result.files.length));
  check("names what the cap skipped", result.skippedOverCap.join(",") === "c.py,d.py", JSON.stringify(result.skippedOverCap));
  check("reports how many there were in total", result.totalPythonFiles === 4, String(result.totalPythonFiles));
}

{
  const result = await listPythonFiles(target, {
    fetch: async () => tree([blob("small.py", 10), blob("huge.py", LIMITS.maxFileBytes + 1)]),
  });
  check("skips a file larger than PyAhead would read", result.skippedTooLarge.join(",") === "huge.py", JSON.stringify(result.skippedTooLarge));
  check("keeps the rest", result.files.map((f) => f.path).join(",") === "small.py");
}

{
  const limits = { ...LIMITS, maxTotalBytes: 150 };
  const result = await listPythonFiles(target, { fetch: async () => tree([blob("a.py", 100), blob("b.py", 100)]), limits });
  check("applies the total-bytes cap", result.files.length === 1 && result.skippedOverCap.join(",") === "b.py", JSON.stringify(result));
}

{
  const result = await listPythonFiles(target, { fetch: async () => tree([blob("a.py")], true) });
  check("surfaces a truncated tree", result.treeTruncated === true);
}

await refuses("reports a missing repository", () => listPythonFiles(target, { fetch: async () => stubResponse({ status: 404 }) }), "not-found");
await refuses("reports an empty repository", () => listPythonFiles(target, { fetch: async () => stubResponse({ status: 409 }) }), "empty-repository");
await refuses("reports a repository with no Python", () => listPythonFiles(target, { fetch: async () => tree([blob("README.md")]) }), "no-python");
await refuses("reports a network failure", () => listPythonFiles(target, { fetch: async () => { throw new TypeError("failed to fetch"); } }), "network");
await refuses("reports an unexpected status", () => listPythonFiles(target, { fetch: async () => stubResponse({ status: 500 }) }), "http");

{
  const reset = Math.floor(Date.now() / 1000) + 1800;
  try {
    await listPythonFiles(target, {
      fetch: async () => stubResponse({ status: 403, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset) } }),
    });
    check("reports the rate limit", false, "did not throw");
  } catch (error) {
    check("reports the rate limit", error.kind === "rate-limited", error.kind);
    check("says when it resets", error.message.includes("resets at"), error.message);
    check("carries the reset time", error.resetAt instanceof Date && Math.abs(error.resetAt.getTime() - reset * 1000) < 1000);
  }
}

{
  // A 403 that is not a rate limit must not be reported as one.
  await refuses("distinguishes a plain 403", () => listPythonFiles(target, {
    fetch: async () => stubResponse({ status: 403, headers: { "x-ratelimit-remaining": "42" } }),
  }), "http");
}

console.log("\nfetching sources");
{
  const urls = [];
  const files = [{ path: "a.py" }, { path: "pkg/b.py" }, { path: "with space.py" }, { path: "gone.py" }];
  const { sources, failed } = await fetchSources({ owner: "o", repo: "r", ref: null }, files, {
    fetch: async (url) => {
      urls.push(url);
      if (url.endsWith("gone.py")) return stubResponse({ status: 404 });
      return stubResponse({ text: `# ${url}` });
    },
  });
  check("fetches every file from the raw CDN", urls.every((url) => url.startsWith(RAW_ORIGIN)));
  check("fetches each selected file once", urls.length === 4, String(urls.length));
  check("escapes each path segment", urls.some((url) => url.endsWith("/with%20space.py")), JSON.stringify(urls));
  check("keeps directory separators unescaped", urls.some((url) => url.endsWith("/pkg/b.py")));
  check("returns the source it got", Object.keys(sources).sort().join(",") === "a.py,pkg/b.py,with space.py", JSON.stringify(Object.keys(sources)));
  check("records what it could not fetch", failed.length === 1 && failed[0].path === "gone.py" && failed[0].status === 404, JSON.stringify(failed));
}

{
  let inFlight = 0;
  let peak = 0;
  const files = Array.from({ length: 30 }, (_, index) => ({ path: `f${index}.py` }));
  await fetchSources({ owner: "o", repo: "r", ref: null }, files, {
    limits: { ...LIMITS, concurrency: 4 },
    fetch: async () => {
      peak = Math.max(peak, ++inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight--;
      return stubResponse({ text: "x = 1" });
    },
  });
  check("bounds concurrency", peak <= 4, `peak ${peak}`);
  check("actually runs in parallel", peak > 1, `peak ${peak}`);
}

{
  let seen = 0;
  await fetchSources({ owner: "o", repo: "r", ref: null }, [{ path: "a.py" }, { path: "b.py" }], {
    fetch: async () => stubResponse({ text: "x = 1" }),
    onProgress: ({ done, total }) => { seen = done; check.total = total; },
  });
  check("reports progress to the last file", seen === 2, String(seen));
}

console.log("\nagainst the real GitHub");
try {
  const listing = await listPythonFiles(parseRepositoryUrl("https://github.com/diegorusso/pyahead"), {});
  check("lists a real repository", listing.files.length > 100, `${listing.files.length} files`);
  check("the tree was not truncated", listing.treeTruncated === false);
  const { sources, failed } = await fetchSources(parseRepositoryUrl("https://github.com/diegorusso/pyahead"), listing.files.slice(0, 3), {});
  check("fetches real source", Object.keys(sources).length === 3 && failed.length === 0, JSON.stringify(failed));
  check("the source looks like Python", Object.values(sources).every((text) => typeof text === "string" && text.length > 0));
} catch (error) {
  if (error.kind === "rate-limited") console.log("  skip  shared runner IP is rate limited by GitHub");
  else { console.log(`  FAIL  live call — ${error.message}`); failures.push("live call"); }
}

console.log(failures.length === 0 ? "\nPASS" : `\nFAIL: ${failures.length} check(s)\n  ${failures.join("\n  ")}`);
process.exit(failures.length === 0 ? 0 : 1);
