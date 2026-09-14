// Fetching a public repository from the browser.
//
// Two hosts, and a hard rule about which does what. `api.github.com` is rate
// limited to 60 requests per hour per IP without a token, so it is used for
// exactly one call: the recursive tree listing. Every file then comes from
// `raw.githubusercontent.com`, which is CDN-served and not rate limited.
//
// Both send `access-control-allow-origin: *`, which is why this works from a
// static page at all. `codeload.github.com` does not, so the archive route is
// closed and per-file fetching is the only one available.

export const API_ORIGIN = "https://api.github.com";
export const RAW_ORIGIN = "https://raw.githubusercontent.com";

export const LIMITS = {
  // Provisional, to be set from real measurements (Task 7). Too low is
  // useless; too high hangs the tab.
  maxFiles: 400,
  // PyAhead's own default file-size limit. Matching it avoids inventing a
  // second threshold: anything larger it would refuse to read anyway.
  maxFileBytes: 2 * 1024 * 1024,
  // Bounds the total download when a repository has many large files.
  maxTotalBytes: 12 * 1024 * 1024,
  concurrency: 8,
};

/** Raised for every condition a visitor can do something about. */
export class RepositoryError extends Error {
  constructor(message, { kind, resetAt } = {}) {
    super(message);
    this.name = "RepositoryError";
    this.kind = kind;
    this.resetAt = resetAt;
  }
}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Accepts `https://github.com/owner/repo`, optionally `/tree/<ref>`, and the
 * bare `owner/repo` shorthand. Everything else is refused by name.
 */
export function parseRepositoryUrl(input) {
  const text = String(input ?? "").trim();
  if (text === "") throw new RepositoryError("Enter a GitHub repository URL.", { kind: "empty" });

  let path;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text) || text.startsWith("github.com/")) {
    let url;
    try {
      url = new URL(text.startsWith("github.com/") ? `https://${text}` : text);
    } catch {
      throw new RepositoryError("That is not a URL. Paste a link like https://github.com/owner/repo", { kind: "malformed" });
    }
    if (url.hostname !== "github.com" && url.hostname !== "www.github.com") {
      throw new RepositoryError(`This scans GitHub repositories, and that link points at ${url.hostname}.`, { kind: "host" });
    }
    path = url.pathname;
  } else {
    path = `/${text}`;
  }

  const parts = path.replace(/^\/+|\/+$/g, "").split("/");
  const [owner, rawRepo, ...rest] = parts;
  if (!owner || !rawRepo) {
    throw new RepositoryError("That link has no repository in it. Use https://github.com/owner/repo", { kind: "malformed" });
  }
  const repo = rawRepo.replace(/\.git$/, "");
  if (!OWNER.test(owner) || !REPO.test(repo)) {
    throw new RepositoryError(`"${owner}/${repo}" is not a valid repository name.`, { kind: "malformed" });
  }

  let ref = null;
  if (rest.length > 0) {
    if (rest[0] !== "tree" || rest.length < 2) {
      throw new RepositoryError(
        "Only a repository, or a branch or tag link, can be scanned — not a single file or directory.",
        { kind: "unsupported-path" },
      );
    }
    // A ref may contain slashes, as in `tree/release/1.x`.
    ref = rest.slice(1).join("/");
  }
  return { owner, repo, ref };
}

function rateLimited(response) {
  return (
    (response.status === 403 || response.status === 429) &&
    response.headers.get("x-ratelimit-remaining") === "0"
  );
}

function rateLimitError(response) {
  const reset = Number(response.headers.get("x-ratelimit-reset"));
  const resetAt = Number.isFinite(reset) && reset > 0 ? new Date(reset * 1000) : null;
  const when = resetAt
    ? ` It resets at ${resetAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`
    : "";
  return new RepositoryError(
    `GitHub's unauthenticated limit of 60 requests an hour is used up for your network.${when} Listing a repository costs one request; the files themselves do not count.`,
    { kind: "rate-limited", resetAt },
  );
}

/** The single `api.github.com` call: list the tree and pick the Python out of it. */
export async function listPythonFiles({ owner, repo, ref }, { fetch: fetchImpl = fetch, limits = LIMITS } = {}) {
  const target = ref ?? "HEAD";
  const url = `${API_ORIGIN}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(target)}?recursive=1`;

  let response;
  try {
    response = await fetchImpl(url, { headers: { accept: "application/vnd.github+json" } });
  } catch (cause) {
    throw new RepositoryError("Could not reach GitHub. Check your connection and try again.", { kind: "network" });
  }

  if (rateLimited(response)) throw rateLimitError(response);
  if (response.status === 404) {
    throw new RepositoryError(
      ref
        ? `No branch or tag called "${ref}" in ${owner}/${repo} — or the repository is private or does not exist.`
        : `${owner}/${repo} does not exist, or it is private. This scans public repositories only.`,
      { kind: "not-found" },
    );
  }
  if (response.status === 409) {
    throw new RepositoryError(`${owner}/${repo} is empty — there is nothing to scan.`, { kind: "empty-repository" });
  }
  if (!response.ok) {
    throw new RepositoryError(`GitHub refused the request (HTTP ${response.status}).`, { kind: "http" });
  }

  const body = await response.json();
  const entries = body.tree ?? [];

  // Two things in a tree hold source this page cannot bring over, and both are
  // invisible if you filter for `.py` first. A symlink's blob contains the
  // target path, not Python, so fetching one would scan a string; and PyAhead
  // itself refuses to traverse directory symlinks, reporting that refusal as
  // incompleteness. A submodule is a different repository entirely.
  const symlinks = entries.filter((entry) => entry.mode === "120000").map((entry) => entry.path);
  const submodules = entries.filter((entry) => entry.type === "commit").map((entry) => entry.path);

  const python = entries
    .filter((entry) => entry.type === "blob" && entry.mode !== "120000" && entry.path.endsWith(".py"))
    .sort((a, b) => a.path.localeCompare(b.path));

  if (python.length === 0) {
    throw new RepositoryError(
      body.truncated
        ? `No Python files in the part of ${owner}/${repo} GitHub would list — the repository is too large to enumerate in one request.`
        : `No Python files in ${owner}/${repo}.`,
      { kind: "no-python" },
    );
  }

  const selected = [];
  const skippedTooLarge = [];
  const skippedOverCap = [];
  let bytes = 0;

  for (const entry of python) {
    if (entry.size > limits.maxFileBytes) {
      skippedTooLarge.push(entry.path);
    } else if (selected.length >= limits.maxFiles || bytes + entry.size > limits.maxTotalBytes) {
      skippedOverCap.push(entry.path);
    } else {
      selected.push({ path: entry.path, size: entry.size });
      bytes += entry.size;
    }
  }

  return {
    files: selected,
    bytes,
    // `truncated` means GitHub would not list the whole tree, so files may be
    // missing that were never offered to us in the first place.
    treeTruncated: Boolean(body.truncated),
    skippedTooLarge,
    skippedOverCap,
    symlinks,
    submodules,
    totalPythonFiles: python.length,
  };
}

/** Fetch the selected files from the CDN, a bounded number at a time. */
export async function fetchSources({ owner, repo, ref }, files, { fetch: fetchImpl = fetch, limits = LIMITS, onProgress = () => {} } = {}) {
  const target = ref ?? "HEAD";
  const sources = {};
  const failed = [];
  let done = 0;

  const queue = [...files];
  async function worker() {
    for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
      const url = `${RAW_ORIGIN}/${owner}/${repo}/${target}/${next.path.split("/").map(encodeURIComponent).join("/")}`;
      try {
        const response = await fetchImpl(url);
        if (response.ok) {
          sources[next.path] = await response.text();
        } else {
          failed.push({ path: next.path, status: response.status });
        }
      } catch {
        failed.push({ path: next.path, status: 0 });
      }
      onProgress({ done: ++done, total: files.length });
    }
  }

  await Promise.all(Array.from({ length: Math.min(limits.concurrency, files.length) }, worker));
  return { sources, failed };
}
