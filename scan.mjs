// The scan harness: PyAhead running in WebAssembly.
//
// One entry point. Give it a mapping of repository-relative path to source
// text; get back the `report-v1` document PyAhead's CLI would have produced for
// the same files on disk. Nothing here talks to the network except to load the
// runtime and the pinned wheels.
//
// The same module runs in a browser and under Node, which is what lets
// check/harness-check.mjs verify the real thing rather than a stand-in.

// Pinned deliberately. A site that floats on "latest" breaks silently when
// either side moves. Pyodide 314.0.6 runs Python 3.14.2 and ships libcst
// 1.8.6, which satisfies PyAhead's `libcst>=1.8,<2` without an override.
export const PYODIDE_VERSION = "314.0.6";
export const PYAHEAD_VERSION = "0.3.0";
export const PYODIDE_INDEX_URL = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

// Installed in order: the two pure-Python dependencies first, so PyAhead's own
// wheel finds them already present and micropip never reaches PyPI. libcst and
// PyYAML come from Pyodide's own distribution.
const WHEELS = [
  "packaging-26.3-py3-none-any.whl",
  "pathspec-1.1.1-py3-none-any.whl",
  `pyahead-${PYAHEAD_VERSION}-py3-none-any.whl`,
];

const SCAN_ROOT = "/scan";

// Runs inside Pyodide. PyAhead exposes no public Python API — `__all__` is
// `["__version__"]` — so the harness drives the CLI, which is the contract the
// project actually keeps stable.
const SCAN_SOURCE = `
import contextlib, io, json, os, pathlib, shutil

_files = json.loads(_files_json)
_opts = json.loads(_options_json)

_root = pathlib.Path(${JSON.stringify(SCAN_ROOT)})
# Step out first. On a second scan the working directory is the tree about to
# be removed, and deleting the directory you are standing in aborts at the
# Emscripten filesystem layer rather than raising something catchable.
os.chdir("/")
if _root.exists():
    shutil.rmtree(_root)
_root.mkdir(parents=True)

for _rel, _text in _files.items():
    _dest = _root / _rel
    # Defence in depth: the caller already rejects escaping paths, but this
    # runs on text fetched from a stranger's repository.
    if not _dest.resolve().is_relative_to(_root):
        raise ValueError(f"path escapes the scan root: {_rel}")
    _dest.parent.mkdir(parents=True, exist_ok=True)
    _dest.write_text(_text)

os.chdir(_root)

from pyahead.cli import main

# The CLI writes its own summary to stdout; the report goes to a file.
with contextlib.redirect_stdout(io.StringIO()) as _captured:
    _code = main([
        "check", ".",
        "--baseline-python", _opts["baseline"],
        "--horizon-python", _opts["horizon"],
        "--format", "json",
        "--output", "report.json",
        "--fail-on", "never",
    ])

json.dumps({
    "exit_code": _code,
    "report": json.loads((_root / "report.json").read_text()),
})
`;

/** Paths that would write outside the scan root, or that no repository should produce. */
export function isUnsafePath(path) {
  if (typeof path !== "string" || path.length === 0) return true;
  if (path.startsWith("/") || path.startsWith("\\")) return true;
  if (/^[A-Za-z]:/.test(path)) return true;
  if (path.includes("\0")) return true;
  return path.split(/[\\/]/).some((segment) => segment === ".." );
}

/**
 * @param {object} config
 * @param {Function} config.loadPyodide  from the CDN in a browser, from the npm package under Node
 * @param {string}   [config.indexURL]   only when Pyodide cannot derive it: in a
 *   browser it comes from the CDN module's own URL, and under Node from the
 *   installed package. Node cannot import a remote module, so never hand it a
 *   CDN URL there.
 * @param {string}   config.vendorBase   URL prefix the pinned wheels are served from
 * @param {Function} [config.onProgress] called with {stage, message}
 */
export function createScanner({ loadPyodide, indexURL, vendorBase, onProgress = () => {} }) {
  if (typeof loadPyodide !== "function") throw new TypeError("loadPyodide is required");
  if (typeof vendorBase !== "string") throw new TypeError("vendorBase is required");

  // Memoised, so a second scan in the same session reuses the runtime rather
  // than downloading several megabytes of WebAssembly again.
  let booting = null;

  function boot() {
    if (booting) return booting;
    booting = (async () => {
      onProgress({ stage: "runtime", message: "Downloading the Python runtime" });
      const pyodide = await loadPyodide(indexURL ? { indexURL } : undefined);

      onProgress({ stage: "packages", message: "Loading the Python parser" });
      await pyodide.loadPackage(["micropip", "libcst", "pyyaml"]);

      onProgress({ stage: "pyahead", message: `Installing PyAhead ${PYAHEAD_VERSION}` });
      const micropip = pyodide.pyimport("micropip");
      for (const wheel of WHEELS) {
        await micropip.install(new URL(wheel, vendorBase).href);
      }
      return pyodide;
    })();
    // A failed boot must not be cached, or every later attempt reports a stale
    // error instead of retrying.
    booting.catch(() => { booting = null; });
    return booting;
  }

  return {
    boot,

    /**
     * @param {Record<string,string>} files  repository-relative path -> source text
     * @param {object} [options]             {baseline, horizon} Python versions
     * @returns {Promise<{exit_code: number, report: object}>}
     */
    async scan(files, options = {}) {
      const unsafe = Object.keys(files).filter(isUnsafePath);
      if (unsafe.length > 0) {
        throw new Error(`refusing to write outside the scan root: ${unsafe[0]}`);
      }
      if (Object.keys(files).length === 0) {
        throw new Error("nothing to scan: no Python files were supplied");
      }

      const pyodide = await boot();
      onProgress({ stage: "scanning", message: `Scanning ${Object.keys(files).length} files` });

      pyodide.globals.set("_files_json", JSON.stringify(files));
      pyodide.globals.set("_options_json", JSON.stringify({
        baseline: options.baseline ?? "3.11",
        horizon: options.horizon ?? "3.14",
      }));
      try {
        const result = JSON.parse(await pyodide.runPythonAsync(SCAN_SOURCE));
        onProgress({ stage: "done", message: "Scan complete" });
        return result;
      } finally {
        pyodide.globals.delete("_files_json");
        pyodide.globals.delete("_options_json");
      }
    },
  };
}
