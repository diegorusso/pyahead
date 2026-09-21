// Browser-side handle on the worker.
//
// Same shape as `createScanner` in scan.mjs, so the page does not care which
// thread the work happens on, and the Node checks can keep driving the engine
// directly without a worker in the way.

const WORKER_URL = new URL("./scan-worker.mjs", import.meta.url);

export function createWorkerScanner({ vendorBase, onProgress = () => {} }) {
  let worker = null;
  let nextId = 0;
  const pending = new Map();

  function connect() {
    if (worker) return worker;
    worker = new Worker(WORKER_URL, { type: "module" });
    worker.addEventListener("message", ({ data }) => {
      const handlers = pending.get(data.id);
      if (!handlers) return;
      if (data.type === "progress") {
        handlers.onStage?.(data.stage);
        onProgress(data);
      } else if (data.type === "result") {
        pending.delete(data.id);
        handlers.resolve(data.result);
      } else if (data.type === "error") {
        pending.delete(data.id);
        handlers.reject(new Error(data.message));
      }
    });
    // A worker that dies takes every scan waiting on it with it; failing them
    // is better than leaving the page waiting for a reply that cannot come.
    worker.addEventListener("error", (event) => {
      const reason = new Error(event.message || "the scanner stopped unexpectedly");
      for (const [, handlers] of pending) handlers.reject(reason);
      pending.clear();
      worker.terminate();
      worker = null;
    });
    return worker;
  }

  return {
    scan(files, options) {
      const id = ++nextId;
      // Timing per stage, in the console. Without it a slow scan is just slow,
      // and the interesting question — runtime load, wheel install, or the
      // analysis itself — cannot be answered from the outside.
      const started = performance.now();
      const timings = [];
      // Each event marks a stage beginning, so record when it began rather
      // than attributing a duration to the wrong stage. Per-file events repeat
      // the scanning stage and are not stage changes.
      let lastStage = null;
      const timed = (stage) => {
        if (stage === lastStage) return;
        lastStage = stage;
        timings.push(`${stage}@+${Math.round(performance.now() - started)}ms`);
      };
      return new Promise((resolve, reject) => {
        pending.set(id, {
          onStage: timed,
          resolve: (result) => {
            // The worker already reports a "done" stage; this marks the point
            // the result actually reached the page.
            timed("returned");
            console.log(`[pyahead] scan ${id}: ${timings.join(" · ")} (${Math.round(performance.now() - started)}ms overall)`);
            resolve(result);
          },
          reject,
        });
        connect().postMessage({ id, files, options, vendorBase });
      });
    },
  };
}
