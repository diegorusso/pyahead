// Task 7: does the browser produce the same answer as the command line, and
// what does it cost on real repositories?
//
// The parity half scans one repository at a pinned tag through the real page,
// and compares the result against `pyahead check --format json` run on the same
// tag by the installed CLI. Anything but an exact match is a failure: the whole
// premise of the site is that it is the same analyser.
//
// The sweep half scans three repositories of different sizes and records what
// it cost. The largest is expected to exceed the page's cap, which is the point
// — a truncated scan must announce itself rather than read as a clean one.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import { chromium } from "playwright";

const SITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const LOCAL_REPORT = process.env.LOCAL_REPORT ?? "local.json";
const PARITY_TARGET = "https://github.com/psf/requests/tree/v2.32.3";
const MIME = { ".whl": "application/octet-stream", ".mjs": "text/javascript", ".html": "text/html", ".css": "text/css", ".py": "text/plain" };

const failures = [];
function check(description, condition, detail = "") {
  if (condition) console.log(`  ok    ${description}`);
  else {
    console.log(`  FAIL  ${description}${detail ? ` — ${detail}` : ""}`);
    failures.push(description);
  }
}

function serveSite() {
  const server = createServer(async (req, res) => {
    try {
      let path = normalize(decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname));
      if (path.endsWith("/")) path += "index.html";
      const body = await readFile(join(SITE_ROOT, path));
      res.writeHead(200, { "content-type": MIME[path.slice(path.lastIndexOf("."))] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port })));
}

/** Identity of a finding, independent of anything that legitimately varies. */
const identity = (finding) =>
  `${finding.rule_id}|${finding.location.path}|${finding.location.region?.start?.line ?? 0}|${finding.subject}`;

const { server, port } = await serveSite();
const origin = `http://127.0.0.1:${port}`;
const browser = await chromium.launch();
const page = await browser.newPage();
page.on("pageerror", (error) => { console.log(`  page error: ${error}`); failures.push("page error"); });

/** Drive the real page, and take the report out of the download it offers. */
async function scanThroughTheSite(url, timeout) {
  await page.goto(origin, { waitUntil: "load" });
  await page.fill("#repository", url);
  const started = Date.now();
  await page.click("#submit");
  await page.waitForSelector(".report, #error:visible", { timeout });
  if (await page.locator("#error").isVisible()) {
    throw new Error(`the page refused it: ${await page.textContent("#error")}`);
  }
  const elapsed = (Date.now() - started) / 1000;
  const report = JSON.parse(await page.evaluate(async () => {
    const response = await fetch(document.getElementById("download").href);
    return response.text();
  }));
  return { report, elapsed, incomplete: (await page.locator(".incomplete").count()) > 0 };
}

console.log(`parity: ${PARITY_TARGET}`);
const local = JSON.parse(await readFile(LOCAL_REPORT, "utf8"));
const { report: browserReport, elapsed } = await scanThroughTheSite(PARITY_TARGET, 600000);
console.log(`  browser scanned ${browserReport.scan.files_analyzed} files in ${elapsed.toFixed(1)}s`);
console.log(`  CLI scanned ${local.scan.files_analyzed} files`);

const localFindings = local.findings.map(identity).sort();
const browserFindings = browserReport.findings.map(identity).sort();
check("the same analyser version ran on both sides", local.tool.version === browserReport.tool.version,
  `${local.tool.version} vs ${browserReport.tool.version}`);
check("the same registry revision", local.registry.revision === browserReport.registry.revision);
check("the same number of files analysed", local.scan.files_analyzed === browserReport.scan.files_analyzed,
  `${local.scan.files_analyzed} vs ${browserReport.scan.files_analyzed}`);
check("identical findings", JSON.stringify(localFindings) === JSON.stringify(browserFindings),
  `\n    only in CLI: ${JSON.stringify(localFindings.filter((f) => !browserFindings.includes(f)))}\n    only in browser: ${JSON.stringify(browserFindings.filter((f) => !localFindings.includes(f)))}`);
check("identical summary counts", JSON.stringify(local.summary) === JSON.stringify(browserReport.summary),
  `${JSON.stringify(local.summary)} vs ${JSON.stringify(browserReport.summary)}`);

console.log("\nsize sweep");
const sweep = [
  { name: "small", url: "https://github.com/benjaminp/six", timeout: 300000, expectCapped: false },
  { name: "medium", url: "https://github.com/pallets/click", timeout: 600000, expectCapped: false },
  { name: "large", url: "https://github.com/django/django", timeout: 900000, expectCapped: true },
];

for (const target of sweep) {
  try {
    const result = await scanThroughTheSite(target.url, target.timeout);
    console.log(`  ${target.name.padEnd(6)} ${target.url.replace("https://github.com/", "")}: ` +
      `${result.report.scan.files_analyzed} files, ${result.elapsed.toFixed(1)}s, ` +
      `${result.incomplete ? "reported incomplete" : "complete"}`);
    check(`${target.name}: completed`, result.report.scan.files_analyzed > 0);
    if (target.expectCapped) {
      check(`${target.name}: a capped scan says so`, result.incomplete);
    }
  } catch (error) {
    if (/60 requests an hour/.test(error.message)) {
      console.log(`  skip  ${target.name}: the runner's IP is rate limited by GitHub`);
    } else {
      check(`${target.name}: completed`, false, error.message);
    }
  }
}

await browser.close();
server.close();
console.log(failures.length === 0 ? "\nPASS" : `\nFAIL: ${failures.length} check(s)\n  ${failures.join("\n  ")}`);
process.exit(failures.length === 0 ? 0 : 1);
