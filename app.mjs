// Wiring: input to report. Everything below runs in the visitor's browser.

import { createScanner, PYAHEAD_VERSION, PYODIDE_INDEX_URL, PYODIDE_VERSION } from "./scan.mjs";
import { parseRepositoryUrl, listPythonFiles, fetchSources, RepositoryError, LIMITS } from "./github.mjs";
import { buildReportView, mount } from "./render.mjs";

const EXAMPLE_FILES = ["app/storage.py", "app/net.py", "tests/test_storage.py"];

const form = document.getElementById("scan-form");
const input = document.getElementById("repository");
const baseline = document.getElementById("baseline");
const horizon = document.getElementById("horizon");
const submit = document.getElementById("submit");
const exampleButton = document.getElementById("example");
const status = document.getElementById("status");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
const download = document.getElementById("download");

let scanner = null;
let downloadUrl = null;

function say(message) {
  status.textContent = message;
  status.hidden = message === "";
}

function fail(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
  say("");
}

function reset() {
  errorBox.hidden = true;
  results.replaceChildren();
  download.hidden = true;
  if (downloadUrl) {
    URL.revokeObjectURL(downloadUrl);
    downloadUrl = null;
  }
}

function busy(isBusy) {
  submit.disabled = isBusy;
  exampleButton.disabled = isBusy;
  document.body.classList.toggle("busy", isBusy);
}

async function getScanner() {
  if (scanner) return scanner;
  // Imported by URL so the pinned version in scan.mjs stays the only one.
  const { loadPyodide } = await import(`${PYODIDE_INDEX_URL}pyodide.mjs`);
  scanner = createScanner({
    loadPyodide,
    vendorBase: new URL("vendor/", document.baseURI).href,
    onProgress: ({ stage, message }) => {
      say(stage === "runtime" ? `${message} — a few megabytes, once per visit` : message);
    },
  });
  return scanner;
}

function offerDownload(report, name) {
  downloadUrl = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  download.href = downloadUrl;
  download.download = `${name}.pyahead.json`;
  download.hidden = false;
}

async function run(produceFiles, context) {
  reset();
  busy(true);
  const started = performance.now();
  try {
    const { files, listing } = await produceFiles();
    const instance = await getScanner();
    const { report } = await instance.scan(files, { baseline: baseline.value, horizon: horizon.value });
    const elapsedSeconds = ((performance.now() - started) / 1000).toFixed(1);

    say("");
    mount(buildReportView(report, { ...context, ...listing, elapsedSeconds }), document, results);
    offerDownload(report, context.repository?.replace("/", "-") ?? "example");
  } catch (error) {
    fail(error instanceof RepositoryError ? error.message : `Something went wrong: ${error.message}`);
    throw error;
  } finally {
    busy(false);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  let target;
  try {
    target = parseRepositoryUrl(input.value);
  } catch (error) {
    reset();
    fail(error.message);
    return;
  }

  const label = `${target.owner}/${target.repo}`;
  await run(async () => {
    say(`Listing the Python files in ${label}`);
    const listing = await listPythonFiles(target, {});
    say(`Downloading ${listing.files.length} files`);
    const { sources, failed } = await fetchSources(target, listing.files, {
      onProgress: ({ done, total }) => say(`Downloading ${done} of ${total} files`),
    });
    if (Object.keys(sources).length === 0) {
      throw new RepositoryError("Every file failed to download. GitHub may be having trouble.", { kind: "network" });
    }
    return { files: sources, listing: { listing, failed } };
  }, { repository: label, ref: target.ref }).catch(() => {});
});

exampleButton.addEventListener("click", async () => {
  await run(async () => {
    say("Loading the example");
    const entries = await Promise.all(EXAMPLE_FILES.map(async (path) => [path, await (await fetch(`example/${path}`)).text()]));
    return { files: Object.fromEntries(entries), listing: { listing: {}, failed: [] } };
  }, { repository: "the bundled example" }).catch(() => {});
});

// Stated in the page, but the exact pins belong next to the thing they pin.
document.getElementById("pins").textContent =
  `PyAhead ${PYAHEAD_VERSION} · Pyodide ${PYODIDE_VERSION} · at most ${LIMITS.maxFiles} files per scan`;
