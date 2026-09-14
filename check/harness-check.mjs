// The gate. Under branch-deployed Pages a red check cannot stop a deploy, so
// this is what makes a broken pin visible before anyone merges it.
//
// It exercises the real harness against the real pinned runtime: no stubs, no
// mocked Pyodide. Three things must hold, and each can fail independently.
//
//   1. The pinned PyAhead installs and scans under the pinned Pyodide.
//   2. The report is correct, not merely well-formed: it must carry exactly the
//      finding the fixture is known to produce, and validate against the
//      published report-v1 schema.
//   3. The scan reaches no host the site does not declare.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";

import { loadPyodide } from "pyodide";
import Ajv from "ajv/dist/2020.js";

import { createScanner, isUnsafePath, PYAHEAD_VERSION, PYODIDE_VERSION, PYODIDE_INDEX_URL } from "../scan.mjs";

const SITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SCHEMA_URL = `https://raw.githubusercontent.com/diegorusso/pyahead/v${PYAHEAD_VERSION}/docs/schema/report-v1.json`;

// Everything the scan itself is allowed to reach. The site's own origin stands
// in for the page; jsDelivr is the pinned Pyodide CDN. GitHub's hosts are not
// here because the harness never fetches a repository — that is Task 4's code,
// and it is checked separately.
const ALLOWED_SCAN_HOSTS = new Set(["cdn.jsdelivr.net", "127.0.0.1"]);

const MIME = { ".whl": "application/octet-stream", ".mjs": "text/javascript", ".html": "text/html", ".css": "text/css", ".py": "text/plain", ".json": "application/json" };

function serveSite() {
  const server = createServer(async (req, res) => {
    try {
      const path = normalize(decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname)).replace(/^(\.\.[/\\])+/, "");
      const body = await readFile(join(SITE_ROOT, path));
      const ext = path.slice(path.lastIndexOf("."));
      res.writeHead(200, { "content-type": MIME[ext] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port }));
  });
}

/** Record every fetch the wrapped call makes, so the host allowlist is asserted rather than assumed. */
async function recordingFetches(run) {
  const seen = [];
  const original = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    seen.push(typeof input === "string" ? input : input.url);
    return original(input, init);
  };
  try {
    return { result: await run(), seen };
  } finally {
    globalThis.fetch = original;
  }
}

const failures = [];
function check(description, condition, detail = "") {
  if (condition) {
    console.log(`  ok    ${description}`);
  } else {
    console.log(`  FAIL  ${description}${detail ? ` — ${detail}` : ""}`);
    failures.push(description);
  }
}

async function main() {
  console.log(`Pyodide ${PYODIDE_VERSION}, PyAhead ${PYAHEAD_VERSION}`);

  console.log("\npath safety");
  for (const bad of ["../etc/passwd", "/etc/passwd", "a/../../b", "C:\\x", "", "a\0b"]) {
    check(`rejects ${JSON.stringify(bad)}`, isUnsafePath(bad));
  }
  for (const good of ["a.py", "src/pkg/mod.py", "deep/nested/path/x.py"]) {
    check(`accepts ${JSON.stringify(good)}`, !isUnsafePath(good));
  }

  const { server, port } = await serveSite();
  const vendorBase = `http://127.0.0.1:${port}/vendor/`;

  const stages = [];
  const scanner = createScanner({
    loadPyodide,
    indexURL: PYODIDE_INDEX_URL,
    vendorBase,
    onProgress: ({ stage }) => stages.push(stage),
  });

  const source = await readFile(join(SITE_ROOT, "fixtures", "example.py"), "utf8");

  console.log("\nfirst scan");
  const started = Date.now();
  const { result: first, seen } = await recordingFetches(() =>
    scanner.scan({ "example.py": source }, { baseline: "3.11", horizon: "3.14" }),
  );
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  console.log(`  (${elapsed}s, ${seen.length} requests)`);

  check("exit code is 0 under --fail-on never", first.exit_code === 0, `got ${first.exit_code}`);

  const rules = first.report.findings.map((finding) => finding.rule_id);
  check("reports exactly [CPY0093]", rules.length === 1 && rules[0] === "CPY0093", JSON.stringify(rules));

  const finding = first.report.findings[0];
  check("the finding is the utcnow call site", finding?.subject === "datetime.datetime.utcnow", finding?.subject);
  check("located in the fixture at line 5", finding?.location?.path === "example.py" && finding?.location?.region?.start?.line === 5,
    JSON.stringify(finding?.location));
  check("the scan saw exactly one file", first.report.scan?.files_analyzed === 1, JSON.stringify(first.report.scan));
  check("no diagnostics", (first.report.diagnostics ?? []).length === 0, JSON.stringify(first.report.diagnostics));
  check(`the report names PyAhead ${PYAHEAD_VERSION}`, first.report.tool?.version === PYAHEAD_VERSION, first.report.tool?.version);

  console.log("\nhosts reached");
  const hosts = [...new Set(seen.map((url) => new URL(url).hostname))].sort();
  for (const host of hosts) {
    check(`${host} is declared`, ALLOWED_SCAN_HOSTS.has(host));
  }
  check("something was actually fetched", seen.length > 0);

  console.log("\nprogress reporting");
  for (const stage of ["runtime", "packages", "pyahead", "scanning", "done"]) {
    check(`reported the ${stage} stage`, stages.includes(stage));
  }

  console.log("\nschema");
  const schema = await (await fetch(SCHEMA_URL)).json();
  const validate = new Ajv({ strict: false, allErrors: true }).compile(schema);
  check("the report validates against the published report-v1 schema", validate(first.report),
    JSON.stringify(validate.errors?.slice(0, 2)));

  console.log("\nsecond scan reuses the runtime");
  const { result: second, seen: secondSeen } = await recordingFetches(() =>
    scanner.scan({ "example.py": source }, { baseline: "3.11", horizon: "3.14" }),
  );
  check("no further downloads", secondSeen.length === 0, `${secondSeen.length} requests`);
  check("same findings", JSON.stringify(second.report.findings) === JSON.stringify(first.report.findings));

  console.log("\nrefusals");
  await scanner.scan({ "../escape.py": "x = 1" }, {}).then(
    () => check("refuses a path that escapes the scan root", false),
    (error) => check("refuses a path that escapes the scan root", /outside the scan root/.test(error.message), error.message),
  );
  await scanner.scan({}, {}).then(
    () => check("refuses an empty file set", false),
    (error) => check("refuses an empty file set", /nothing to scan/.test(error.message), error.message),
  );

  server.close();

  console.log(failures.length === 0 ? "\nPASS" : `\nFAIL: ${failures.length} check(s)\n  ${failures.join("\n  ")}`);
  process.exit(failures.length === 0 ? 0 : 1);
}

await main();
