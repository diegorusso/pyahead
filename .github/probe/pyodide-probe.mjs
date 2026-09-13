// Scratch probe for docs/plans/20260913-browser-scan-site.md Task 1: prove that
// PyAhead runs under a real Pyodide runtime before any site work starts. The
// development host has no JavaScript runtime, so this runs on an Actions runner.
//
// PROBE_MODE=resolved   install `pyahead` with its real dependency metadata.
//                       This is the case the site depends on.
// PROBE_MODE=libcst16   install with `deps=False` against Pyodide's bundled
//                       libcst 1.6.0, to record whether the `libcst>=1.8` floor
//                       could be lowered. Informational only.

import { loadPyodide } from "pyodide";

const PYAHEAD_VERSION = process.env.PYAHEAD_VERSION ?? "0.2.1";
const MODE = process.env.PROBE_MODE ?? "resolved";

// One call site, one rule: `datetime.datetime.utcnow` is CPY0093. Verified
// against the same version of the CLI natively before this probe was written.
const FIXTURE = `import datetime


def stamp() -> str:
    return datetime.datetime.utcnow().isoformat()
`;

const since = (start) => ((performance.now() - start) / 1000).toFixed(1);

const loadStart = performance.now();
const pyodide = await loadPyodide();
console.log(`pyodide ${pyodide.version} loaded in ${since(loadStart)}s`);

await pyodide.loadPackage(["micropip"]);
if (MODE === "libcst16") {
  // The published metadata cannot resolve here, so stage the wasm builds first.
  await pyodide.loadPackage(["libcst", "pyyaml"]);
}

pyodide.globals.set("PYAHEAD_VERSION", PYAHEAD_VERSION);
pyodide.globals.set("FIXTURE", FIXTURE);
pyodide.globals.set("MODE", MODE);

const scanStart = performance.now();
const raw = await pyodide.runPythonAsync(`
import json, os, pathlib, sys
import micropip

if MODE == "libcst16":
    await micropip.install(["pathspec", "packaging"])
    await micropip.install(f"pyahead=={PYAHEAD_VERSION}", deps=False)
else:
    await micropip.install(f"pyahead=={PYAHEAD_VERSION}")

from importlib.metadata import version

versions = {
    name: version(name)
    for name in ("pyahead", "libcst", "packaging", "pathspec", "PyYAML")
}

root = pathlib.Path("/scan")
root.mkdir(exist_ok=True)
(root / "example.py").write_text(FIXTURE)
os.chdir(root)

from pyahead.cli import main

exit_code = main([
    "check", ".",
    "--baseline-python", "3.11",
    "--horizon-python", "3.14",
    "--format", "json",
    "--output", "report.json",
    "--fail-on", "never",
])
report = json.loads((root / "report.json").read_text())
json.dumps({
    "python": sys.version.split()[0],
    "versions": versions,
    "exit_code": exit_code,
    "report": report,
})
`);
console.log(`install and scan in ${since(scanStart)}s`);

const out = JSON.parse(raw);
console.log(`python ${out.python}`);
console.log(`versions ${JSON.stringify(out.versions)}`);
console.log(`exit code ${out.exit_code}`);
console.log(`summary ${JSON.stringify(out.report.summary)}`);
console.log("--- report ---");
console.log(JSON.stringify(out.report, null, 2));
console.log("--- end report ---");

const rules = (out.report.findings ?? []).map((finding) => finding.rule_id);
if (out.exit_code !== 0) {
  console.error(`FAIL: --fail-on never should exit 0, got ${out.exit_code}`);
  process.exit(1);
}
if (rules.length !== 1 || rules[0] !== "CPY0093") {
  console.error(`FAIL: expected exactly [CPY0093], got ${JSON.stringify(rules)}`);
  process.exit(1);
}
console.log(`PASS: ${MODE} — PyAhead scanned under Pyodide and reported CPY0093`);
