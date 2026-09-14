// The site in a real browser.
//
// The module checks cover the harness, the fetching layer and the renderer.
// None of them touch app.mjs, which is where the element ids, the event
// handlers and the dynamic import of the pinned runtime live — the pieces a
// typo breaks silently. This drives the actual page in Chromium instead.
//
// It also produces the measurements Task 7 asks for: first-load bytes and the
// time to a usable scan, and the set of hosts the page really contacts.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import { chromium } from "playwright";

const SITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const ALLOWED_HOSTS = new Set(["127.0.0.1", "cdn.jsdelivr.net"]);
const MIME = { ".whl": "application/octet-stream", ".mjs": "text/javascript", ".html": "text/html", ".css": "text/css", ".py": "text/plain", ".json": "application/json" };

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

const { server, port } = await serveSite();
const origin = `http://127.0.0.1:${port}`;
const browser = await chromium.launch();
const page = await browser.newPage();

const hosts = new Set();
const consoleErrors = [];
let transferred = 0;

page.on("request", (request) => hosts.add(new URL(request.url()).hostname));
page.on("response", (response) => {
  const length = Number(response.headers()["content-length"] ?? 0);
  if (Number.isFinite(length)) transferred += length;
});
page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
page.on("pageerror", (error) => consoleErrors.push(String(error)));

console.log("loading the page");
await page.goto(origin, { waitUntil: "load" });
check("the page has its title", (await page.title()).includes("PyAhead"));
check("the pins are written into the page", /PyAhead 0\.2\.1 · Pyodide 314\.0\.6/.test(await page.textContent("#pins")), await page.textContent("#pins"));

console.log("\nrefusing bad input");
await page.fill("#repository", "https://gitlab.com/owner/repo");
await page.click("#submit");
await page.waitForSelector("#error:visible", { timeout: 10000 });
check("names the wrong host", (await page.textContent("#error")).includes("gitlab.com"), await page.textContent("#error"));
check("no report was rendered", (await page.locator(".report").count()) === 0);

console.log("\nscanning the bundled example");
const started = Date.now();
await page.click("#example");
await page.waitForSelector(".report", { timeout: 300000 });
const elapsed = (Date.now() - started) / 1000;
console.log(`  first usable scan in ${elapsed.toFixed(1)}s, ~${(transferred / 1024 / 1024).toFixed(1)}MB transferred`);

const counts = Object.fromEntries(await page.locator(".count").evaluateAll((nodes) =>
  nodes.map((node) => [node.querySelector(".count-label").textContent, Number(node.querySelector(".count-number").textContent)]),
));
check("counts 2 breaking", counts.breaking === 2, JSON.stringify(counts));
check("counts 3 deprecated", counts.deprecated === 3, JSON.stringify(counts));
check("renders 5 findings", (await page.locator(".finding").count()) === 5, String(await page.locator(".finding").count()));

const headings = await page.locator(".group h3").allTextContents();
check("groups by Python version, earliest first",
  headings.length === 3 && headings[0].startsWith("Python 3.11") && headings[2].startsWith("Python 3.13"), JSON.stringify(headings));
check("names a rule", (await page.textContent(".report")).includes("CPY0026"));
check("names the removed API", (await page.textContent(".report")).includes("ssl.wrap_socket"));
check("links to CPython documentation", (await page.locator(".doc-link").count()) > 0);
check("offers the JSON download", await page.locator("#download").isVisible());
check("the download is named", (await page.getAttribute("#download", "download")).endsWith(".pyahead.json"));
check("a clean example shows no incompleteness banner", (await page.locator(".incomplete").count()) === 0);

console.log("\nsecond scan reuses the cached runtime");
const secondStarted = Date.now();
await page.click("#example");
await page.waitForFunction(() => document.querySelectorAll(".finding").length === 5, null, { timeout: 120000 });
const secondElapsed = (Date.now() - secondStarted) / 1000;
console.log(`  second scan in ${secondElapsed.toFixed(1)}s`);
check("the second scan is much faster", secondElapsed < elapsed / 2, `${secondElapsed.toFixed(1)}s vs ${elapsed.toFixed(1)}s`);

console.log("\nhosts contacted");
for (const host of [...hosts].sort()) check(`${host} is declared`, ALLOWED_HOSTS.has(host));
check("PyPI was never contacted", ![...hosts].some((host) => host.includes("pypi") || host.includes("pythonhosted")));

console.log("\nconsole");
check("no console errors", consoleErrors.length === 0, consoleErrors.slice(0, 3).join(" | "));

console.log("\nnarrow screen");
await page.setViewportSize({ width: 360, height: 720 });
const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
check("the page does not scroll sideways at 360px", overflow <= 1, `${overflow}px of overflow`);

await browser.close();
server.close();

console.log(`\nmeasurements: first scan ${elapsed.toFixed(1)}s, second ${secondElapsed.toFixed(1)}s, ~${(transferred / 1024 / 1024).toFixed(1)}MB`);
console.log(failures.length === 0 ? "PASS" : `FAIL: ${failures.length} check(s)\n  ${failures.join("\n  ")}`);
process.exit(failures.length === 0 ? 0 : 1);
