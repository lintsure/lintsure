// Scout (file walk) + Checker (rules) + Auditor (dedupe, sort) + Officer (outside code).
// No network calls anywhere in this package: a test enforces it.
import { readdir, readFile } from "node:fs/promises";
import { basename, extname, join, relative, sep } from "node:path";
import { outsideFor } from "./knowledge/index.js";
import { rules } from "./rules/index.js";
import type { Finding, FrameworkId, Report } from "./types.js";
import { proposalFor } from "./guidance.js";
import { applyReview, fingerprint, isOpen } from "./review.js";
export * from "./review.js";
export { toSarif } from "./sarif.js";
import { buildRecord, type RecordOptions } from "./record.js";
export * from "./record.js";

/** Heading above every proposed change, in every report. Tests check it is there for each finding. */
export const PROPOSAL_HEADING = "Proposed change. Nothing changes until you approve it.";

export * from "./types.js";
export { rules };
export * from "./guidance.js";
export { toAssessmentHtml } from "./assessment.js";
export * from "./knowledge/index.js";
export const RULES_VERSION = "0.3.0";

/** Shown with every result, in every interface. Lintsure prepares; people decide. */
export const DISCLAIMER =
  "Lintsure is a readiness tool, not an audit, a certification or legal advice. " +
  "Its rules reflect our reading of the publicly available text of each framework, and they check code only. " +
  "Work outside code, such as policies, training, contracts and evidence, still has to be done. " +
  "Have a qualified person review the results before any audit, certification or decision.";

/** What a report must never be read as. Used in the report and by the MCP server. */
export const NOT_A_VERDICT =
  "These results do not mean you are compliant, certified or ready for an audit. A control marked Met means only that " +
  "Lintsure's rules found no problem in the files they read.";

/** Plain next steps, so a report always ends with what a person still needs to do. */
export function nextSteps(r: Report): string[] {
  const open = r.findings.filter(isOpen);
  const gaps = open.filter((f) => f.status === "gap").length;
  const partial = open.filter((f) => f.status === "partial").length;
  const expired = r.findings.filter((f) => f.accepted?.expired).length;
  return [
    gaps ? `Review the ${gaps} gap${gaps === 1 ? "" : "s"} and decide how to fix each one. Approve any change before it is made.` : "No gaps were found by the current rules. Keep checking as the code changes.",
    partial ? `Check the ${partial} partial finding${partial === 1 ? "" : "s"}: each depends on context only you can confirm.` : "",
    `Work through the ${r.outside.length} item${r.outside.length === 1 ? "" : "s"} that live outside code. Code checks alone are not enough for a full review.`,
    expired ? `${expired} accepted finding${expired === 1 ? " is" : "s are"} past the review date. Look again, then renew the acceptance or fix it.` : "",
    "Ask a qualified compliance professional to review the results before you rely on them.",
  ].filter(Boolean);
}
export const ALL_FRAMEWORKS: FrameworkId[] = ["gdpr", "soc2", "iso-27001", "eu-ai-act", "owasp-top10"];

/** Reads the frameworks list from lintsure.config.yaml in the repo root, if there is one.
 *  Only the simple list form is supported:
 *    frameworks:
 *      - gdpr
 *  Ids Lintsure doesn't check yet (for example "hipaa") are returned in `skipped`.
 *  An `ignore:` list of paths (relative to the root, for example tests/ or fixtures/) is skipped by scan(). */
export async function readConfig(root: string): Promise<{ frameworks: FrameworkId[] | null; skipped: string[]; ignore: string[] }> {
  let text: string;
  try { text = await readFile(join(root, "lintsure.config.yaml"), "utf8"); } catch { return { frameworks: null, skipped: [], ignore: [] }; }
  const lists: Record<string, string[]> = { frameworks: [], ignore: [] }; let key = ""; let emptyFw = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trimEnd();
    if (/^frameworks\s*:\s*\[\s*\]\s*$/.test(line)) { emptyFw = true; key = ""; continue; }
    const head = line.match(/^(frameworks|ignore)\s*:\s*$/);
    if (head) { key = head[1]; continue; }
    if (key) { const m = line.match(/^\s+-\s*["']?([^"'\s]+)["']?\s*$/); if (m) lists[key].push(m[1]); else if (line.trim()) key = ""; }
  }
  const ignore = lists.ignore.map((p) => p.replace(/\\/g, "/").replace(/^\.?\//, "").replace(/\/+$/, ""));
  if (emptyFw) return { frameworks: [], skipped: [], ignore };
  const ids = lists.frameworks;
  if (!ids.length) return { frameworks: null, skipped: [], ignore };
  const known = ids.filter((i): i is FrameworkId => (ALL_FRAMEWORKS as string[]).includes(i));
  return { frameworks: known, skipped: ids.filter((i) => !known.includes(i as FrameworkId)), ignore };
}

// Dependencies, build output and caches: generated code, not code you wrote.
export const SKIP_DIRS = ["node_modules", ".git", "dist", "build", "out", ".output", ".next", ".nuxt", ".svelte-kit", ".astro", ".vercel", ".netlify", ".wrangler", ".turbo", ".cache", "venv", ".venv", "__pycache__", "coverage"];
const SKIP = new Set(SKIP_DIRS);
const MAX_LINE = 1000; // a line this long means minified or generated code
const MAX_BYTES = 1_000_000;

/** Scout: list files to check, sorted so output order never depends on the file system. */
export async function listFiles(root: string, ignore: string[] = []): Promise<string[]> {
  const out: string[] = [];
  const ignored = (p: string) => { const r = relative(root, p).split(sep).join("/"); return ignore.some((i) => r === i || r.startsWith(i + "/")); };
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name) || /\.min\.(js|css)$/.test(e.name)) continue;
      const p = join(dir, e.name);
      if (ignored(p)) continue;
      if (e.isDirectory()) await walk(p); else if (e.isFile()) out.push(p);
    }
  }
  await walk(root);
  return out.sort();
}

const TEST_PATH = /(^|\/)(tests?|__tests__|__mocks__|spec|fixtures?|e2e)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$/i;
const SECRET_RULES = new Set(["secret.in-source", "config.default-secret-key", "auth.hardcoded-password"]);
const HASH_COMMENTS = new Set([".py", ".rb", ".sh", ".yml", ".yaml", ".toml", ".env"]);

/** Marks lines that are only a comment or sit inside a block comment or Python docstring. Pure. */
export function commentLines(lines: string[], ext: string): boolean[] {
  const hash = HASH_COMMENTS.has(ext), py = ext === ".py";
  let block = false, doc = false;
  return lines.map((raw) => {
    const t = raw.trim();
    if (block) { if (t.includes("*/")) block = false; return true; }
    if (doc) { if (/"""|'''/.test(t)) doc = false; return true; }
    if (py && /^[rbuf]*("""|''')/i.test(t)) { const q = t.match(/"""|'''/)![0]; if (t.split(q).length - 1 === 1) doc = true; return true; }
    if (t.startsWith("/*")) { if (!t.includes("*/")) block = true; return true; }
    return t.startsWith("//") || t.startsWith("*") || t.startsWith("<!--") || (hash && t.startsWith("#"));
  });
}

export async function scan(root: string, frameworks: FrameworkId[] = ALL_FRAMEWORKS, opts: RecordOptions = {}): Promise<Report> {
  const active = rules.filter((r) => r.controls.some((c) => frameworks.includes(c.framework)));
  const findings: Finding[] = [];
  let filesChecked = 0, checkPoints = 0;
  const perRule: Record<string, number> = {};
  const { ignore } = await readConfig(root);
  for (const abs of await listFiles(root, ignore)) {
    const ext = extname(abs) || (abs.endsWith(".env") ? ".env" : "");
    const name = basename(abs);
    const relevant = active.filter((r) => r.extensions.includes(ext) && (!r.fileName || r.fileName.test(name)));
    if (!relevant.length) continue;
    const buf = await readFile(abs);
    if (buf.length > MAX_BYTES || buf.includes(0)) continue; // skip big or binary files
    const file = relative(root, abs).split(sep).join("/");
    const lines = buf.toString("utf8").split(/\r?\n/);
    if (lines.some((l) => l.length > MAX_LINE)) continue; // minified or generated
    filesChecked++;
    checkPoints += relevant.length; // one rule applied to one file is one check point
    for (const r of relevant) perRule[r.id] = (perRule[r.id] ?? 0) + 1;
    const add = (r: (typeof relevant)[number], line: number, status: Finding["status"] = r.status) => {
      const controls = r.controls.filter((c) => frameworks.includes(c.framework));
      findings.push({
        id: "", ruleId: r.id, file, line, status, severity: r.severity, title: r.title, controls, fix: r.fix, note: r.note,
        proposal: proposalFor({ file, line, title: r.title, fix: r.fix, note: r.note, controls }),
        fingerprint: fingerprint(r.id, file, lines[line - 1] ?? ""),
      });
    };
    // Tests and fixtures are full of fake tokens and planted examples: only secret rules look at them.
    const inTests = TEST_PATH.test(file);
    const comment = commentLines(lines, ext);
    for (const r of relevant) {
      if (inTests && !SECRET_RULES.has(r.id)) continue;
      // Comments describe code, they don't run. A real secret pasted into a comment still counts.
      const skip = SECRET_RULES.has(r.id) ? null : comment;
      if (r.test) lines.forEach((text, i) => {
        if (skip?.[i]) return;
        const hit = r.test!(text);
        if (!hit || (r.unlessNear && lines.slice(Math.max(0, i - 8), i + 4).some((l) => r.unlessNear!.test(l)))) return;
        add(r, i + 1, hit === "partial" ? "partial" : r.status);
      });
      if (r.fileTest) for (const n of r.fileTest(lines)) add(r, n);
    }
  }
  // Auditor: one finding per rule per line; stable order.
  const seen = new Set<string>();
  const deduped = findings.filter((f) => { const k = `${f.ruleId}|${f.file}|${f.line}`; return seen.has(k) ? false : (seen.add(k), true); })
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  deduped.forEach((f, i) => { f.id = `F-${String(i + 1).padStart(3, "0")}`; });
  const hit = new Set(deduped.map((f) => f.ruleId));
  const now = opts.now ?? new Date();
  const report = await applyReview({
    rulesVersion: RULES_VERSION,
    frameworks: [...frameworks].sort(),
    findings: deduped,
    // Only the Checker sets Met: a rule that ran and found nothing.
    met: active.filter((r) => !hit.has(r.id)).map((r) => ({ ruleId: r.id, title: r.title, controls: r.controls.filter((c) => frameworks.includes(c.framework)) })),
    outside: outsideFor(frameworks),
    filesChecked,
    disclaimer: DISCLAIMER,
  }, root, now.toISOString().slice(0, 10));
  report.record = await buildRecord(report, root, checkPoints, perRule, active.map((r) => r.id), active, ignore, { ...opts, now });
  return report;
}

const LABEL = { gap: "Gap", partial: "Partial", met: "Met", outside: "Outside code" } as const;
const acceptedLine = (a: NonNullable<Finding["accepted"]>) =>
  `> Accepted by ${a.by} on ${a.date}: ${a.reason}` + (a.expired ? ` (review date ${a.reviewBy} has passed: look at it again)` : a.reviewBy ? ` (review by ${a.reviewBy})` : "");
const ctl = (c: { framework: string; id: string }[]) => c.map((x) => `${x.framework.toUpperCase()} ${x.id}`).join(" · ");

const RESULT = { finding: "Finding", observation: "Observation", "no issue found": "No issue found" } as const;

/** The record block: identification, scope, what applies and why, counts, and results by control. */
function recordLines(r: Report): string[] {
  const c = r.record; if (!c) return [];
  const n = c.counts;
  return [
    "## Readiness check record", "",
    "This is a readiness record of an automated code check, not an audit. It is a draft until a person reviews and signs it.", "",
    "| | |", "|---|---|",
    `| Record | ${c.id} |`, `| Date and time (UTC) | ${c.createdAt.replace("T", " ").slice(0, 19)} |`,
    `| Tool | ${c.tool.name} ${c.tool.version}, run from ${c.source} |`,
    `| Scope | \`${c.scope.folder}\`${c.scope.branch ? `, branch \`${c.scope.branch}\`` : ""}${c.scope.commit ? `, commit \`${c.scope.commit}\`` : ""} |`,
    `| Files read | ${c.scope.filesRead}${c.scope.ignored.length ? ` (ignored by config: ${c.scope.ignored.map((x) => `\`${x}\``).join(", ")})` : ""} |`,
    `| Check points | ${n.checkPoints} (${n.rulesRun} rules, each applied to every file it reads) |`,
    `| Results | ${n.findings} finding${n.findings === 1 ? "" : "s"}, ${n.observations} observation${n.observations === 1 ? "" : "s"}, ${n.accepted} accepted, ${n.fixedSinceBaseline} fixed since baseline, ${n.outsideCode} outside-code items |`,
    `| Risk levels | ${n.byRisk.high} high, ${n.byRisk.medium} medium, ${n.byRisk.low} low |`,
    `| Reviewed by | ${c.review.reviewer ?? "Not yet reviewed"} |`, "",
    "### What applies, and why", "",
    ...c.applies.map((a) => `- **${a.framework}**: ${a.why}`), "",
    "### Results by control", "",
    "A finding is a Gap the code itself shows. An observation is a Partial that depends on context a person must confirm. No issue found means the rules found nothing in the files they read, not that the control is met.", "",
    "| Framework | Control | Rules | Check points | Result | Items |", "|---|---|---|---|---|---|",
    ...c.byControl.map((b) => `| ${b.framework} | ${b.control} ${b.title} | ${b.rules.join(", ")} | ${b.checkPoints} | ${RESULT[b.result]} | ${b.findingIds.join(", ") || "-"} |`), "",
  ];
}

export function toMarkdown(r: Report): string {
  const lines = [
    "# Lintsure report", "",
    `Frameworks: ${r.frameworks.join(", ")} · Rules v${r.rulesVersion}`, "",
    `> ${DISCLAIMER}`, "",
    ...recordLines(r),
    `## Findings (${r.findings.length})`, "",
  ];
  if (r.baseline) lines.splice(lines.length - 2, 0, `Since the baseline of ${r.baseline.created}: ${r.baseline.newCount} new, ${r.baseline.fixed.length} fixed, ${r.baseline.unchangedCount} unchanged.`, "");
  if (!r.findings.length) lines.push("No issues found by the current rules.", "");
  for (const f of r.findings) lines.push(
    `### ${f.id} · ${f.status === "gap" ? "Finding" : "Observation"} (${LABEL[f.status]}) · \`${f.file}:${f.line}\`${f.change === "new" ? " · New since baseline" : ""}`, `**${f.title}** · Risk level: ${f.severity}`, "",
    ...(f.accepted ? [acceptedLine(f.accepted), ""] : []),
    `- Rules: ${ctl(f.controls)}`, `- Auditor note: ${f.note}`, "",
    `**${PROPOSAL_HEADING}**`, "",
    `- Where: \`${f.proposal.where}\``, `- What: ${f.proposal.what}`, `- Why: ${f.proposal.why}`, `- Benefit: ${f.proposal.benefit}`, "",
  );
  if (r.baseline?.fixed.length) lines.push(`## Fixed since baseline (${r.baseline.fixed.length})`, "", ...r.baseline.fixed.map((x) => `- ${x.ruleId} in \`${x.file}\``), "");
  lines.push(`## Met (${r.met.length})`, "", ...r.met.map((m) => `- ${m.title} · ${ctl(m.controls)}`), "");
  lines.push(`## Outside code (${r.outside.length})`, "", "Code can't prove these. They still need to be done before a full review.", "", ...r.outside.map((o) => `- ${o.framework.toUpperCase()} ${o.control} · ${o.title}: ${o.evidence}`), "");
  lines.push("## What to do next", "", ...nextSteps(r).map((s, i) => `${i + 1}. ${s}`), "");
  lines.push("## What this report is not", "", NOT_A_VERDICT, "");
  return lines.join("\n");
}
