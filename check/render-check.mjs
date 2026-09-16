// Checks the renderer, including the claim that matters most: a repository
// cannot inject markup into this page.
//
// The claim is checked structurally, not by pattern-matching for `<script>`.
// `mount` is handed a document whose elements throw if anything assigns to
// `innerHTML`, `outerHTML` or `insertAdjacentHTML`, so the test fails if a
// future edit introduces a markup path at all — whatever it happens to contain.

import { buildReportView, groupByActionVersion, incompletenessNotes, mount } from "../render.mjs";

const failures = [];
function check(description, condition, detail = "") {
  if (condition) console.log(`  ok    ${description}`);
  else {
    console.log(`  FAIL  ${description}${detail ? ` — ${detail}` : ""}`);
    failures.push(description);
  }
}

const HTML_SETTERS = ["innerHTML", "outerHTML", "insertAdjacentHTML"];

function fakeDocument() {
  const created = [];
  function createElement(tag) {
    const element = {
      tag,
      className: "",
      textContent: undefined,
      attributes: {},
      children: [],
      setAttribute(name, value) { this.attributes[name] = value; },
      appendChild(child) { this.children.push(child); },
    };
    for (const name of HTML_SETTERS) {
      Object.defineProperty(element, name, {
        set() { throw new Error(`markup path used: ${name}`); },
        get() { throw new Error(`markup path read: ${name}`); },
      });
    }
    created.push(element);
    return element;
  }
  return { createElement, created };
}

function allText(element) {
  const own = element.textContent === undefined ? [] : [element.textContent];
  return own.concat(element.children.flatMap(allText));
}

const HOSTILE = '</script><img src=x onerror="alert(1)">';

const report = {
  tool: { name: "pyahead", version: "0.2.2" },
  registry: { release: "2026.07.31" },
  scan: { files_analyzed: 3, files_discovered: 3, files_incomplete: 1 },
  summary: { breaking: 1, deprecated: 1, informational: 0, risk: 0, new: 2, suppressed: 0 },
  diagnostics: [{ code: "PYA1003", message: `unable to parse ${HOSTILE}` }],
  findings: [
    {
      rule_id: "CPY0001", subject: HOSTILE, impact: "breaking", action_version: "3.13",
      title: `removed in ${HOSTILE}`, enclosing_scope: HOSTILE,
      location: { path: `${HOSTILE}/mod.py`, region: { start: { line: 12, column: 4 } } },
      remediation: { summary: `use ${HOSTILE}`, documentation_url: "https://docs.python.org/3.13/whatsnew/3.13.html" },
      removal_unscheduled: false,
    },
    {
      rule_id: "CPY0093", subject: "datetime.datetime.utcnow", impact: "deprecated", action_version: "3.12",
      title: "deprecated", location: { path: "a.py", region: { start: { line: 5, column: 12 } } },
      remediation: { summary: "use datetime.now", documentation_url: "javascript:alert(1)" },
      removal_unscheduled: true,
    },
  ],
};

console.log("grouping");
{
  const groups = groupByActionVersion(report.findings);
  check("groups by action version, earliest first", groups.map((g) => g.version).join(",") === "3.12,3.13", JSON.stringify(groups.map((g) => g.version)));
}
{
  const groups = groupByActionVersion([
    { impact: "deprecated", action_version: null, removal_unscheduled: true, location: { path: "a.py" } },
    { impact: "breaking", action_version: "3.14", location: { path: "b.py" } },
    { impact: "breaking", action_version: "3.9", location: { path: "c.py" } },
  ]);
  check("sorts versions numerically, not lexically", groups.map((g) => g.version).join(",") === "3.9,3.14,unscheduled", JSON.stringify(groups.map((g) => g.version)));
}
{
  const groups = groupByActionVersion([
    { impact: "informational", action_version: "3.13", location: { path: "z.py", region: { start: { line: 1 } } } },
    { impact: "breaking", action_version: "3.13", location: { path: "z.py", region: { start: { line: 9 } } } },
  ]);
  check("puts the worst impact first within a version", groups[0].findings[0].impact === "breaking");
}

console.log("\nincompleteness");
{
  const notes = incompletenessNotes(report, { treeTruncated: true, skippedOverCap: ["x.py"], skippedTooLarge: ["y.py", "z.py"] }, [{ path: "q.py" }]);
  check("names a truncated tree", notes.some((note) => note.includes("would not list the whole repository")));
  check("names files skipped by the cap", notes.some((note) => note.includes("1 file beyond")));
  check("pluralises correctly", notes.some((note) => note.includes("2 files larger")));
  check("names files that failed to download", notes.some((note) => note.includes("1 file could not be downloaded")));
  check("names files PyAhead could not analyse", notes.some((note) => note.includes("could not fully analyse 1 file")));
  check("carries diagnostics through", notes.some((note) => note.startsWith("PYA1003")));
}
{
  const notes = incompletenessNotes({ scan: {}, diagnostics: [] }, { symlinks: ["a/ca"], submodules: ["v/dep", "v/other"] }, []);
  check("names an unfollowed symlink", notes.some((note) => note.includes("1 symlink was not followed")), JSON.stringify(notes));
  check("says PyAhead does not follow them either", notes.some((note) => note.includes("does not follow them either")));
  check("names unscanned submodules", notes.some((note) => note.includes("2 submodules are separate repositories")), JSON.stringify(notes));
}
check("a complete scan has no notes", incompletenessNotes({ scan: { files_incomplete: 0 }, diagnostics: [] }, {}, []).length === 0);

console.log("\nmounting");
const document = fakeDocument();
let root;
try {
  root = mount(buildReportView(report, { repository: "owner/repo", ref: "main", listing: { treeTruncated: true }, failed: [], elapsedSeconds: "4.2" }), document);
  check("mounts without touching any markup path", true);
} catch (error) {
  check("mounts without touching any markup path", false, error.message);
}

if (root) {
  const texts = allText(root);
  check("the hostile subject is rendered as text", texts.includes(HOSTILE));
  check("the hostile path is rendered as text", texts.some((value) => value.includes(`${HOSTILE}/mod.py:12`)));
  check("every repository-derived value went through textContent", texts.filter((value) => value.includes(HOSTILE)).length >= 4,
    String(texts.filter((value) => value.includes(HOSTILE)).length));

  const links = document.created.filter((element) => element.tag === "a");
  check("links only to https documentation", links.length === 1 && links[0].attributes.href.startsWith("https://"),
    JSON.stringify(links.map((link) => link.attributes.href)));
  check("drops a javascript: documentation url", !links.some((link) => link.attributes.href.startsWith("javascript:")));
  check("opens documentation safely", links[0]?.attributes.rel === "noopener noreferrer");

  check("shows the incompleteness banner", document.created.some((element) => element.className === "incomplete"));
  check("names the repository", texts.some((value) => value.includes("owner/repo at main")));
  check("reports the analyser version", texts.some((value) => value.includes("PyAhead 0.2.2")));
}

{
  const clean = fakeDocument();
  const empty = mount(buildReportView({ tool: {}, registry: {}, scan: { files_analyzed: 2, files_incomplete: 0 }, summary: {}, diagnostics: [], findings: [] }, {}), clean);
  const texts = allText(empty);
  check("says plainly when there is nothing to report", texts.some((value) => value.includes("No findings")));
  check("a clean scan shows no incompleteness banner", !clean.created.some((element) => element.className === "incomplete"));
}

console.log(failures.length === 0 ? "\nPASS" : `\nFAIL: ${failures.length} check(s)\n  ${failures.join("\n  ")}`);
process.exit(failures.length === 0 ? 0 : 1);
