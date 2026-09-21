// Wiring: input to report. Everything below runs in the visitor's browser.

import { PYAHEAD_VERSION, PYODIDE_VERSION } from "./scan.mjs";
import { createWorkerScanner } from "./scan-client.mjs";
import { parseRepositoryUrl, listPythonFiles, fetchSources, RepositoryError, LIMITS } from "./github.mjs";
import { buildReportView, mount } from "./render.mjs";
import { pickSamples } from "./samples.mjs";

const EXAMPLE_FILES = ["app/storage.py", "app/net.py", "tests/test_storage.py"];

const form = document.getElementById("scan-form");
const input = document.getElementById("repository");
const baseline = document.getElementById("baseline");
const horizon = document.getElementById("horizon");
const submit = document.getElementById("submit");
const status = document.getElementById("status");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
const download = document.getElementById("download");
// Optional: the page works without it, so the redesign can place it whenever.
const samples = document.getElementById("samples");
const reportRegion = document.getElementById("report-region");
const resultsTitle = document.getElementById("results-title");
const submitLabel = document.getElementById("submit-label");

let scanner = null;
let downloadUrl = null;

function isLaterVersion(version, reference) {
  const [major, minor] = version.split(".").map(Number);
  const [referenceMajor, referenceMinor] = reference.split(".").map(Number);
  return major > referenceMajor || (major === referenceMajor && minor > referenceMinor);
}

function updateHorizon() {
  for (const option of horizon.options) {
    option.disabled = !isLaterVersion(option.value, baseline.value);
  }
  if (!isLaterVersion(horizon.value, baseline.value)) {
    horizon.value = [...horizon.options].find((option) => !option.disabled)?.value ?? "";
  }
}

baseline.addEventListener("change", updateHorizon);
updateHorizon();

function say(message) {
  status.textContent = message;
  status.hidden = message === "";
}

const progress = document.getElementById("progress");
const progressBar = document.getElementById("progress-bar");
const progressDetail = document.getElementById("progress-detail");

// One file at a time, under the status line. The live region above is left
// alone: it announces the stage once, not four hundred file names.
function showProgress(index, total, detail) {
  progressBar.max = total;
  progressBar.value = index;
  progressDetail.textContent = detail;
  progress.hidden = false;
}

function showFile({ path, index, total }) {
  showProgress(index, total, `${index} of ${total} · ${path}`);
}

function hideProgress() {
  progress.hidden = true;
  progressBar.value = 0;
  progressDetail.textContent = "";
}

function fail(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
  say("");
  hideProgress();
}

function reset() {
  errorBox.hidden = true;
  hideProgress();
  results.replaceChildren();
  reportRegion.hidden = true;
  download.hidden = true;
  if (downloadUrl) {
    URL.revokeObjectURL(downloadUrl);
    downloadUrl = null;
  }
}

function busy(isBusy) {
  submit.disabled = isBusy;
  input.disabled = isBusy;
  baseline.disabled = isBusy;
  horizon.disabled = isBusy;
  for (const chip of samples?.querySelectorAll("button") ?? []) chip.disabled = isBusy;
  submitLabel.textContent = isBusy ? "Scanning…" : "Scan repository";
  form.setAttribute("aria-busy", String(isBusy));
  document.body.classList.toggle("busy", isBusy);
}

function getScanner() {
  if (scanner) return scanner;
  // The runtime lives in a worker, so a scan never blocks the page.
  scanner = createWorkerScanner({
    vendorBase: new URL("vendor/", document.baseURI).href,
    onProgress: ({ stage, message, file }) => {
      if (file) {
        showFile(file);
        return;
      }
      if (stage === "done") hideProgress();
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
  const options = { baseline: baseline.value, horizon: horizon.value };
  if (!isLaterVersion(options.horizon, options.baseline)) {
    fail("Choose a look-ahead Python version greater than the oldest Python you support.");
    return;
  }
  busy(true);
  const started = performance.now();
  try {
    const { files, listing } = await produceFiles();
    const instance = getScanner();
    const { report } = await instance.scan(files, options);
    const elapsedSeconds = ((performance.now() - started) / 1000).toFixed(1);

    say("");
    mount(buildReportView(report, { ...context, ...listing, elapsedSeconds }), document, results);
    offerDownload(report, context.repository?.replace("/", "-") ?? "example");
    reportRegion.hidden = false;
    resultsTitle.focus({ preventScroll: true });
    reportRegion.scrollIntoView({ block: "start" });
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
      onProgress: ({ done, total }) => showProgress(done, total, `${done} of ${total} downloaded`),
    });
    if (Object.keys(sources).length === 0) {
      throw new RepositoryError("Every file failed to download. GitHub may be having trouble.", { kind: "network" });
    }
    return { files: sources, listing: { listing, failed } };
  }, { repository: label, ref: target.ref }).catch(() => {});
});

function addChip(label, onClick, attributes = {}) {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.className = "chip";
  chip.textContent = label;
  Object.assign(chip.dataset, attributes);
  chip.addEventListener("click", onClick);
  samples.appendChild(chip);
}

if (samples) {
  // First, and the only one that costs nothing: the bundled files are served
  // from this origin, so it still works when GitHub's 60-an-hour limit is spent.
  addChip("bundled example", () => {
    run(async () => {
      say("Loading the example");
      const entries = await Promise.all(EXAMPLE_FILES.map(async (path) => [path, await (await fetch(`example/${path}`)).text()]));
      return { files: Object.fromEntries(entries), listing: { listing: {}, failed: [] } };
    }, { repository: "the bundled example" }).catch(() => {});
  }, { example: "true" });

  // Then a different three on every visit, so the page does not always
  // demonstrate itself with the same repository.
  for (const url of pickSamples(3)) {
    addChip(url.replace("https://github.com/", ""), () => {
      input.value = url;
      form.requestSubmit();
    }, { repo: url });
  }
}

// Stated in the page, but the exact pins belong next to the thing they pin.
document.getElementById("pins").textContent =
  `PyAhead ${PYAHEAD_VERSION} · Pyodide ${PYODIDE_VERSION} · at most ${LIMITS.maxFiles} files per scan`;
