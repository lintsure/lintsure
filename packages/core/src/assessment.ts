// The assessment report: one self-contained HTML file, laid out in print pages, so a person can
// read it, annotate it, print it or save it as a PDF from any browser. It is a draft until a
// qualified person reviews it and fills in the sign-off page.
import { DISCLAIMER, NOT_A_VERDICT, nextSteps } from "./index.js";
import { knowledge } from "./knowledge/index.js";
import type { Finding, FrameworkId, Report } from "./types.js";

export interface AssessmentOptions {
  /** Shown on the cover. Defaults to "Your project". */
  project?: string;
  /** Date the report was produced, as YYYY-MM-DD. Passed in so the same input gives the same file. */
  date: string;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const NAME: Record<FrameworkId, string> = { "eu-ai-act": "EU AI Act", gdpr: "GDPR", soc2: "SOC 2", "iso-27001": "ISO/IEC 27001" };
const STATUS: Record<string, string> = { gap: "Gap", partial: "Partial", met: "Met", outside: "Outside code" };
const SEV = ["high", "medium", "low"] as const;
const SKIPPED = "node_modules, .git, dist, build, out, .output, .next, .nuxt, .svelte-kit, .astro, .vercel, .netlify, .wrangler, .turbo, .cache, venv, .venv, __pycache__, coverage";

function page(title: string, body: string, n: number, total: number, project: string) {
  return `<section class="page"><header><span>Lintsure readiness assessment · ${esc(project)}</span><span>Draft until reviewed by a person</span></header>
<h2>${esc(title)}</h2>${body}<footer><span>Not an audit, a certification or legal advice.</span><span>Section ${n} of ${total}</span></footer></section>`;
}

function findingCard(f: Finding, i: number) {
  return `<article class="finding ${f.status}">
  <p class="meta"><b class="st">${f.id} · ${f.status === "gap" ? "Finding" : "Observation"} (${STATUS[f.status]})</b> · risk level ${f.severity} · <code>${esc(f.ruleId)}</code></p>
  <h3>${esc(f.title)}</h3>
  <p class="where"><code>${esc(f.file)}:${f.line}</code></p>
  <dl>
    <dt>Rules it may affect</dt><dd>${f.controls.map((c) => `${NAME[c.framework]} ${esc(c.id)} (${esc(c.title)})`).join("<br>")}</dd>
    <dt>Why it matters</dt><dd>${esc(f.note)}</dd>
    <dt>Possible fix</dt><dd>${esc(f.fix)} Review the change before it is made.</dd>
  </dl>
  <p class="decide"><b>Reviewer decision:</b> ☐ Fix &nbsp; ☐ Accept the risk (record why) &nbsp; ☐ Not applicable (record why) &nbsp; Initials ______ &nbsp; Date ______</p>
</article>`;
}

export function toAssessmentHtml(r: Report, opts: AssessmentOptions): string {
  const project = opts.project?.trim() || "Your project";
  const n = (s: string) => r.findings.filter((f) => f.status === s).length;
  const fws = r.frameworks as FrameworkId[];
  const sorted = [...r.findings].sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));

  const rec = r.record;
  const RESULT = { finding: "Finding", observation: "Observation", "no issue found": "No issue found" } as const;
  const recordBody = rec ? `<p>A dated record of what this run checked and what it saw. It is a readiness record of an automated code check, not an audit.</p>
<table class="counts"><tr><th>Check points</th><th>Findings</th><th>Observations</th><th>Accepted</th><th>Fixed since baseline</th></tr>
<tr><td>${rec.counts.checkPoints}</td><td>${rec.counts.findings}</td><td>${rec.counts.observations}</td><td>${rec.counts.accepted}</td><td>${rec.counts.fixedSinceBaseline}</td></tr></table>
<p>Risk levels of open items: ${rec.counts.byRisk.high} high, ${rec.counts.byRisk.medium} medium, ${rec.counts.byRisk.low} low. A check point is one rule applied to one file (${rec.counts.rulesRun} rules ran).</p>
<h3>What applies, and why</h3><ul>${rec.applies.map((a) => `<li><b>${NAME[a.framework]}</b>: ${esc(a.why)}</li>`).join("")}</ul>
<h3>Results by control</h3><p class="small">Finding: a Gap the code itself shows. Observation: a Partial that depends on context a person must confirm. No issue found: the rules found nothing in the files they read, which does not mean the control is met.</p>
<table><tr><th>Framework</th><th>Control</th><th>Rules</th><th>Check points</th><th>Result</th><th>Items</th></tr>
${rec.byControl.map((b) => `<tr><td>${NAME[b.framework]}</td><td><code>${esc(b.control)}</code> ${esc(b.title)}</td><td>${b.rules.map((x) => `<code>${esc(x)}</code>`).join(" ")}</td><td>${b.checkPoints}</td><td>${RESULT[b.result]}</td><td>${b.findingIds.join(", ") || "-"}</td></tr>`).join("")}</table>` : "";
  const cover = `<section class="page cover">
  <p class="brand">Lintsure</p>
  <h1>Readiness assessment</h1>
  <p class="sub">${esc(project)}</p>
  <table class="facts">
    <tr><th>Date produced</th><td>${esc(opts.date)}</td></tr>
    ${rec ? `<tr><th>Record</th><td>${esc(rec.id)}, checked ${esc(rec.createdAt.replace("T", " ").slice(0, 19))} UTC</td></tr>` : ""}
    ${rec?.scope.commit ? `<tr><th>Code checked</th><td>${rec.scope.branch ? `branch <code>${esc(rec.scope.branch)}</code>, ` : ""}commit <code>${esc(rec.scope.commit)}</code></td></tr>` : ""}
    <tr><th>Frameworks checked</th><td>${fws.map((f) => NAME[f]).join(", ") || "None"}</td></tr>
    <tr><th>Files checked</th><td>${r.filesChecked}${rec ? `, ${rec.counts.checkPoints} check points` : ""}</td></tr>
    <tr><th>Rules version</th><td>${esc(r.rulesVersion)}</td></tr>
    <tr><th>Status of this report</th><td><b>Draft.</b> Not complete until a qualified person reviews it and signs the review page.</td></tr>
  </table>
  <div class="callout"><b>Read this first.</b> ${esc(DISCLAIMER)}</div>
</section>`;

  const summary = `<p>This report shows where your code may not meet the code-related parts of the frameworks above, what could be done about it, and what still has to happen outside code. It is a starting point for a person to review, not a conclusion.</p>
<table class="counts"><tr><th>Gap</th><th>Partial</th><th>Rules with no finding (Met)</th><th>Outside code</th></tr>
<tr><td>${n("gap")}</td><td>${n("partial")}</td><td>${r.met.length}</td><td>${r.outside.length}</td></tr></table>
<h3>By framework</h3>
<table><tr><th>Framework</th><th>Gaps</th><th>Partial</th><th>Rules with no finding</th><th>Outside-code items</th></tr>
${fws.map((f) => `<tr><td>${NAME[f]}</td><td>${r.findings.filter((x) => x.status === "gap" && x.controls.some((c) => c.framework === f)).length}</td><td>${r.findings.filter((x) => x.status === "partial" && x.controls.some((c) => c.framework === f)).length}</td><td>${r.met.filter((m) => m.controls.some((c) => c.framework === f)).length}</td><td>${r.outside.filter((o) => o.framework === f).length}</td></tr>`).join("")}</table>
<div class="callout"><b>What this summary does not mean.</b> ${esc(NOT_A_VERDICT)}</div>`;

  const method = `<h3>What was checked</h3>
<p>Lintsure read ${r.filesChecked} files in the project folder on the computer or CI runner where it ran. Nothing was uploaded. It skipped these folders: ${SKIPPED}, any paths listed under ignore in lintsure.config.yaml, minified files, and any file over 1 MB or binary.</p>
<h3>How results are produced</h3>
<ul><li>A fixed set of rules (version ${esc(r.rulesVersion)}) looks for known patterns, line by line or file by file. It does not use a language model to decide results, so the same code gives the same findings.</li>
<li><b>Gap</b>: a rule found code that may break a control. <b>Partial</b>: a likely problem that depends on context only you can confirm. <b>Met</b>: the rule ran and found nothing in the files it read. <b>Outside code</b>: work that code cannot show.</li>
<li>Rules reflect our reading of the publicly available text of each framework. They are in Beta: their mappings to framework controls await review by a qualified compliance professional.</li></ul>
<h3>Known limits</h3>
<ul><li>Rules can miss real problems and can flag code that is fine.</li><li>They do not follow data across files or functions.</li><li>They mainly cover JavaScript, TypeScript and Python.</li><li>They cannot see infrastructure, cloud settings, or anything outside the folder that was scanned.</li></ul>`;

  const findingsBody = sorted.length
    ? `<p>${sorted.length} possible issue${sorted.length === 1 ? "" : "s"}, most severe first. For each one, a reviewer records a decision.</p>${sorted.map((f, i) => findingCard(f, i + 1)).join("")}`
    : `<p>The current rules found no possible issues in the files they read. That is not the same as having none: rules have limits (see "Scope and method"), and the outside-code work still applies.</p>`;

  const byFramework = fws.map((f) => {
    const k = knowledge.find((x) => x.id === f);
    const hits = r.findings.filter((x) => x.controls.some((c) => c.framework === f));
    const rows = (k?.obligations ?? []).map((o) => {
      const related = hits.filter((h) => o.rules?.includes(h.ruleId));
      const result = o.inCode === "no" ? "Outside code: needs evidence" : related.length ? `${related.length} finding${related.length === 1 ? "" : "s"} to review` : o.inCode === "partly" ? "No finding from the rules; code shows only part of this" : "No finding from the rules";
      return `<tr><td><code>${esc(o.ref)}</code></td><td><b>${esc(o.title)}.</b> ${esc(o.plain)}</td><td>${result}</td></tr>`;
    }).join("");
    return `<h3>${NAME[f]}</h3>${k ? `<p>${esc(k.summary)}</p>` : ""}<table><tr><th>Ref</th><th>What it asks</th><th>What Lintsure saw</th></tr>${rows}</table>`;
  }).join("");

  const outside = r.outside.length
    ? `<p>Code cannot show these. They still need to be done before a full review. Assign an owner to each.</p><table><tr><th>Framework</th><th>Item</th><th>Evidence an auditor may ask for</th><th>Owner</th><th>Done</th></tr>
${r.outside.map((o) => `<tr><td>${NAME[o.framework]} <code>${esc(o.control)}</code></td><td>${esc(o.title)}</td><td>${esc(o.evidence)}</td><td></td><td>☐</td></tr>`).join("")}</table>`
    : `<p>No outside-code items for the frameworks checked.</p>`;

  const next = `<ol>${nextSteps(r).map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
<p>Lintsure suggests; people decide. Re-run Lintsure after changes, and keep each signed report with the rules version it was produced with.</p>`;

  const signoff = `<div class="callout"><b>Human review is required.</b> This report is a draft produced by software. It must be reviewed by a qualified person, such as a compliance professional, before anyone relies on it for an audit, a certification, a customer answer or a business decision.</div>
<table class="sign">
<tr><th>Reviewer name</th><td></td></tr><tr><th>Role and qualification</th><td></td></tr><tr><th>Date of review</th><td></td></tr>
<tr><th>Scope reviewed</th><td>☐ All findings &nbsp; ☐ Outside-code items &nbsp; ☐ Framework applicability</td></tr>
<tr><th>Overall notes</th><td class="tall"></td></tr><tr><th>Signature</th><td class="tall"></td></tr></table>
<p class="small">By signing, the reviewer confirms they reviewed this report. Signing does not turn it into an audit or certification.</p>`;

  const pages: [string, string][] = [
    ["Summary", summary], ...(recordBody ? [["Readiness check record", recordBody] as [string, string]] : []), ["Scope and method", method], ["Possible issues and fixes", findingsBody],
    ["Framework by framework", byFramework || "<p>No frameworks were checked.</p>"], ["Work outside code", outside],
    ["What to do next", next], ["Human review and sign-off", signoff], ["Disclaimer", `<p>${esc(DISCLAIMER)}</p><p>${esc(NOT_A_VERDICT)}</p><p>Lintsure does not decide whether a framework applies to you or whether you meet it. A person makes the final call. Full disclaimer: https://lintsure.com/disclaimer</p>`],
  ];
  const total = pages.length + 1;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lintsure readiness assessment · ${esc(project)} · ${esc(opts.date)}</title>
<style>
:root{--ink:#141413;--muted:#5E5D59;--line:#E4E2DD;--sunken:#F5F4F1;--gap:#B42318;--partial:#8A5A00;--met:#0B6E4F}
*{box-sizing:border-box}body{margin:0;background:#ECEAE5;color:var(--ink);font:14px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
.page{background:#fff;width:210mm;min-height:297mm;margin:16px auto;padding:18mm 18mm 22mm;position:relative;box-shadow:0 2px 12px #0002}
header,footer{display:flex;justify-content:space-between;font-size:10px;color:var(--muted)}header{border-bottom:1px solid var(--line);padding-bottom:6px;margin-bottom:18px}
footer{position:absolute;left:18mm;right:18mm;bottom:10mm;border-top:1px solid var(--line);padding-top:6px}
h1{font-size:40px;letter-spacing:-.03em;margin:40mm 0 4px}h2{font-size:24px;letter-spacing:-.02em;margin:0 0 12px}h3{font-size:16px;margin:20px 0 6px}
.brand{font-weight:700;letter-spacing:-.02em;font-size:18px}.sub{font-size:18px;color:var(--muted);margin:0 0 24px}
table{width:100%;border-collapse:collapse;margin:8px 0 12px;font-size:12.5px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--sunken);font-weight:600}
.counts td{font-size:22px;font-weight:600;text-align:center}.facts th{width:38%}
.callout{border:1px solid var(--ink);border-radius:8px;padding:10px 12px;margin:14px 0;font-size:13px}
code{font:12px ui-monospace,Menlo,Consolas,monospace;background:var(--sunken);padding:1px 4px;border-radius:4px}
.finding{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:10px 0;break-inside:avoid}.finding h3{margin:4px 0 2px}
.finding .meta{margin:0;font-size:12px;color:var(--muted)}.gap .st{color:var(--gap)}.partial .st{color:var(--partial)}
.where{margin:0 0 6px}dl{margin:0;display:grid;grid-template-columns:150px 1fr;gap:4px 10px;font-size:12.5px}dt{color:var(--muted)}dd{margin:0}
.decide{font-size:12px;margin:8px 0 0;padding-top:6px;border-top:1px dashed var(--line)}
.sign td{height:28px}.sign .tall{height:70px}.small{font-size:11.5px;color:var(--muted)}
@page{size:A4;margin:0}@media print{body{background:#fff}.page{margin:0;box-shadow:none;break-after:page}}
</style></head><body>
${cover}
${pages.map(([t, b], i) => page(t, b, i + 2, total, project)).join("\n")}
</body></html>`;
}
