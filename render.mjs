// Turning a report into a page.
//
// Everything here is built as plain data first and only then turned into DOM
// nodes, through `textContent` alone. That is the whole defence against a
// repository whose file paths or identifiers contain HTML: there is no code
// path that concatenates repository text into markup, so there is nothing to
// escape correctly and nothing to get wrong. `mount` is tested against a
// document that throws if anything touches `innerHTML`.

const IMPACT_ORDER = ["breaking", "deprecated", "risk", "informational"];

const el = (tag, options = {}) => ({ tag, ...options });
const text = (tag, value, options = {}) => ({ tag, text: String(value), ...options });

function pluralise(count, singular, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Everything that makes a scan less than a complete answer, in one list. */
export function incompletenessNotes(report, listing = {}, failed = []) {
  const notes = [];
  if (listing.treeTruncated) {
    notes.push("GitHub would not list the whole repository in one request, so files may be missing that were never offered for scanning.");
  }
  const overCap = listing.skippedOverCap?.length ?? 0;
  if (overCap > 0) {
    notes.push(`${pluralise(overCap, "file")} beyond this page's limit ${overCap === 1 ? "was" : "were"} not fetched.`);
  }
  const tooLarge = listing.skippedTooLarge?.length ?? 0;
  if (tooLarge > 0) {
    notes.push(`${pluralise(tooLarge, "file")} larger than PyAhead reads ${tooLarge === 1 ? "was" : "were"} skipped.`);
  }
  const symlinks = listing.symlinks?.length ?? 0;
  if (symlinks > 0) {
    notes.push(`${pluralise(symlinks, "symlink")} ${symlinks === 1 ? "was" : "were"} not followed, so anything only reachable through ${symlinks === 1 ? "it" : "them"} was not scanned. PyAhead does not follow them either.`);
  }
  const submodules = listing.submodules?.length ?? 0;
  if (submodules > 0) {
    notes.push(`${pluralise(submodules, "submodule")} ${submodules === 1 ? "is a" : "are"} separate ${submodules === 1 ? "repository" : "repositories"} and ${submodules === 1 ? "was" : "were"} not scanned.`);
  }
  if (failed.length > 0) {
    notes.push(`${pluralise(failed.length, "file")} could not be downloaded.`);
  }
  const incomplete = report?.scan?.files_incomplete ?? 0;
  if (incomplete > 0) {
    notes.push(`PyAhead could not fully analyse ${pluralise(incomplete, "file")} — usually a syntax error, or syntax newer than the parser.`);
  }
  for (const diagnostic of report?.diagnostics ?? []) {
    notes.push(`${diagnostic.code}: ${diagnostic.message}`);
  }
  return notes;
}

/** Findings by the Python version the change lands in, earliest first, unscheduled last. */
export function groupByActionVersion(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const key = finding.removal_unscheduled && !finding.action_version ? "unscheduled" : finding.action_version ?? "unscheduled";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  const versions = [...groups.keys()].filter((key) => key !== "unscheduled").sort((a, b) =>
    a.localeCompare(b, undefined, { numeric: true }),
  );
  if (groups.has("unscheduled")) versions.push("unscheduled");
  return versions.map((version) => ({
    version,
    findings: groups.get(version).sort((a, b) =>
      IMPACT_ORDER.indexOf(a.impact) - IMPACT_ORDER.indexOf(b.impact) ||
      a.location.path.localeCompare(b.location.path) ||
      (a.location.region?.start?.line ?? 0) - (b.location.region?.start?.line ?? 0),
    ),
  }));
}

function locationLabel(location) {
  const line = location?.region?.start?.line;
  return line ? `${location.path}:${line}` : location?.path ?? "";
}

const EVENT_LABEL = {
  deprecated: "Deprecated",
  removed: "Removed",
  signature_changed: "Signature changed",
  behavior_changed: "Behaviour changed",
  syntax_changed: "Syntax changed",
  support_dropped: "Support dropped",
};

/** "Deprecated in 3.11 · Removed in 3.13", a scheduled event marked as such. */
export function timelineLabel(timeline) {
  return (timeline ?? [])
    .filter((event) => typeof event?.python === "string" && event.event in EVENT_LABEL)
    .map((event) => `${EVENT_LABEL[event.event]} in ${event.python}${event.certainty === "scheduled" ? " (scheduled)" : ""}`)
    .join(" · ");
}

// Registry-supplied, not repository-supplied, but a link is still only made
// for a scheme a link should have.
const isDocumentationUrl = (url) => typeof url === "string" && url.startsWith("https://");

function findingView(finding) {
  const children = [
    el("div", {
      class: "finding-head",
      children: [
        text("span", finding.rule_id, { class: "rule" }),
        text("span", finding.impact, { class: `badge impact-${finding.impact}` }),
        text("code", finding.subject, { class: "subject" }),
      ],
    }),
    text("p", finding.title ?? "", { class: "finding-title" }),
    text("p", locationLabel(finding.location), { class: "location" }),
  ];

  const timeline = timelineLabel(finding.timeline);
  if (timeline) {
    children.push(text("p", timeline, { class: "timeline" }));
  }
  if (finding.remediation?.summary) {
    children.push(text("p", finding.remediation.summary, { class: "remediation" }));
  }
  const url = finding.remediation?.documentation_url;
  if (isDocumentationUrl(url)) {
    children.push(el("p", { children: [text("a", "What changed and why", { href: url, class: "doc-link" })] }));
  }
  // Every source the rule cites, by title, so the reader sees where the
  // deprecation and the removal were each announced.
  const sources = (finding.sources ?? []).filter((source) => isDocumentationUrl(source?.url) && typeof source?.title === "string");
  if (sources.length > 0) {
    children.push(el("ul", {
      class: "sources",
      children: sources.map((source) => el("li", { children: [text("a", source.title, { href: source.url, class: "source-link" })] })),
    }));
  }
  if (finding.enclosing_scope) {
    children.push(text("p", `in ${finding.enclosing_scope}`, { class: "scope" }));
  }
  return el("li", { class: "finding", children });
}

/**
 * @param {object} report    a report-v1 document
 * @param {object} context   {repository, ref, listing, failed, elapsedSeconds}
 * @returns a virtual node tree; hand it to `mount`
 */
export function buildReportView(report, context = {}) {
  const summary = report.summary ?? {};
  const scan = report.scan ?? {};
  const sections = [];

  sections.push(el("header", {
    class: "report-head",
    children: [
      text("h2", context.repository ? `${context.repository}${context.ref ? ` at ${context.ref}` : ""}` : "Scan report"),
      text("p", [
        `${pluralise(scan.files_analyzed ?? 0, "file")} analysed`,
        context.elapsedSeconds ? `in ${context.elapsedSeconds}s` : null,
        `· PyAhead ${report.tool?.version ?? "?"}`,
        `· registry ${report.registry?.release ?? "?"}`,
      ].filter(Boolean).join(" "), { class: "meta" }),
    ],
  }));

  const counts = IMPACT_ORDER.filter((impact) => (summary[impact] ?? 0) > 0)
    .map((impact) => el("div", {
      class: `count count-${impact}`,
      children: [text("span", summary[impact], { class: "count-number" }), text("span", impact, { class: "count-label" })],
    }));
  sections.push(el("div", { class: "counts", children: counts.length > 0 ? counts : [text("p", "Nothing found.", { class: "count-empty" })] }));

  const notes = incompletenessNotes(report, context.listing, context.failed ?? []);
  if (notes.length > 0) {
    sections.push(el("section", {
      class: "incomplete",
      children: [
        text("h3", "This scan is incomplete"),
        text("p", "Findings below are real, but absence of a finding is not evidence of its absence."),
        el("ul", { children: notes.map((note) => text("li", note)) }),
      ],
    }));
  }

  const groups = groupByActionVersion(report.findings ?? []);
  for (const group of groups) {
    sections.push(el("section", {
      class: "group",
      children: [
        text("h3", group.version === "unscheduled"
          ? `Deprecated, no removal scheduled — ${pluralise(group.findings.length, "finding")}`
          : `Python ${group.version} — ${pluralise(group.findings.length, "finding")}`),
        el("ul", { class: "findings", children: group.findings.map(findingView) }),
      ],
    }));
  }

  if (groups.length === 0) {
    sections.push(text("p", "No findings in the files that were scanned.", { class: "empty" }));
  }

  return el("article", { class: "report", children: sections });
}

/** Realise a virtual node tree as DOM. The only text path is `textContent`. */
export function mount(node, document, parent) {
  const element = document.createElement(node.tag);
  if (node.class) element.className = node.class;
  if (node.href) {
    element.setAttribute("href", node.href);
    element.setAttribute("rel", "noopener noreferrer");
    element.setAttribute("target", "_blank");
  }
  if (node.text !== undefined) element.textContent = node.text;
  for (const child of node.children ?? []) mount(child, document, element);
  if (parent) parent.appendChild(element);
  return element;
}
