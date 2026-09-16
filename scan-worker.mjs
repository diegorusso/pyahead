// The scan, off the main thread.
//
// Pyodide executes Python on whatever thread it is loaded on. Loaded on the
// main thread — which is what this site did until now — a scan freezes the
// page for its whole duration: no clicks, no links, no scrolling, while the
// CSS spinner keeps turning on the compositor and makes the page look alive.
// Seconds of that for the bundled example, a minute for a large repository.
//
// So it runs here instead. This worker owns the runtime for the life of the
// page, which also keeps it warm between scans.

import { createScanner, PYODIDE_INDEX_URL } from "./scan.mjs";

let scanner = null;

async function getScanner(vendorBase, post) {
  if (scanner) return scanner;
  const { loadPyodide } = await import(`${PYODIDE_INDEX_URL}pyodide.mjs`);
  scanner = createScanner({
    loadPyodide,
    vendorBase,
    onProgress: (progress) => post({ type: "progress", ...progress }),
  });
  return scanner;
}

self.addEventListener("message", async ({ data }) => {
  const { id, files, options, vendorBase } = data;
  const post = (message) => self.postMessage({ id, ...message });
  try {
    const instance = await getScanner(vendorBase, post);
    post({ type: "result", result: await instance.scan(files, options) });
  } catch (error) {
    // Error objects do not survive structured cloning intact, so send what the
    // page actually shows.
    post({ type: "error", message: error?.message ?? String(error) });
  }
});
