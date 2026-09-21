// A picture of the page after a scan, for the README.
//
// Serves this checkout, scans one public repository in Chromium, and saves two
// captures: the whole page, and the report clipped to a README-sized hero.
// Run through the "Screenshot" workflow (workflow_dispatch) or locally with
// `node check/screenshot.mjs`, with REPO, BASELINE, HORIZON, CARDS and OUT to
// taste.

import { createServer } from "node:http";
import { mkdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import * as playwright from "playwright";

const SITE_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MIME = { ".whl": "application/octet-stream", ".mjs": "text/javascript", ".html": "text/html", ".css": "text/css", ".py": "text/plain", ".json": "application/json", ".svg": "image/svg+xml" };

const REPO = process.env.REPO ?? "https://github.com/urllib3/urllib3/tree/2.0.0";
const BASELINE = process.env.BASELINE ?? "3.9";
const HORIZON = process.env.HORIZON ?? "3.14";
const OUT = process.env.OUT ?? join(SITE_ROOT, "screenshots");
const WIDTH = Number(process.env.WIDTH ?? 1280);
// The hero ends at the bottom edge of the CARDS-th finding, so no card is cut.
const CARDS = Number(process.env.CARDS ?? 1);

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
const browser = await playwright.chromium.launch();
const page = await browser.newPage({ viewport: { width: WIDTH, height: 900 }, deviceScaleFactor: 2 });
await mkdir(OUT, { recursive: true });

try {
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });
  await page.fill("#repository", REPO);
  await page.selectOption("#baseline", BASELINE);
  await page.selectOption("#horizon", HORIZON);
  await page.click("#submit");
  await page.waitForSelector(".report, #error:visible", { timeout: 300000 });
  if (await page.locator("#error").isVisible()) {
    throw new Error(`the page reported: ${await page.textContent("#error")}`);
  }
  // Let the fonts settle and the busy state clear before the capture.
  await page.waitForSelector("body:not(.busy)", { timeout: 10000 });
  await page.evaluate(() => document.fonts.ready);
  console.log(`scanned ${REPO}: ${await page.textContent(".report-head .meta")}`);

  await page.screenshot({ path: join(OUT, "page.png"), fullPage: true });
  // Bounding boxes are viewport-relative and the page has scrolled to the
  // results; a full-page clip wants document coordinates.
  const { top, bottom } = await page.evaluate((cards) => {
    const region = document.getElementById("report-region").getBoundingClientRect();
    const findings = document.querySelectorAll(".finding");
    const last = findings[Math.min(cards, findings.length) - 1]?.getBoundingClientRect() ?? region;
    return { top: region.top + window.scrollY, bottom: last.bottom + window.scrollY };
  }, CARDS);
  await page.screenshot({
    path: join(OUT, "report.png"),
    fullPage: true,
    clip: { x: 0, y: Math.floor(top), width: WIDTH, height: Math.ceil(bottom - top) + 12 },
  });
  console.log(`saved ${join(OUT, "page.png")} and ${join(OUT, "report.png")}`);
} finally {
  await browser.close();
  server.close();
}
