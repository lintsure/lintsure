// Scout (file walk) + Checker (rules) + Auditor (dedupe, sort) + Officer (outside code).
// No network calls anywhere in this package: a test enforces it.
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import { outsideFor } from "./knowledge/index.js";
import { rules } from "./rules/index.js";
import type { Finding, FrameworkId, Report } from "./types.js";

export * from "./types.js";
export { rules };
export * from "./guidance.js";
export { toAssessmentHtml } from "./assessment.js";
export * from "./knowledge/index.js";
export const RULES_VERSION = "0.1.1";

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
  const gaps = r.findings.filter((f) => f.status === "gap").length;
  const partial = r.findings.filter((f) => f.status === "partial").length;
  return [
    gaps ? `Review the ${gaps} gap${gaps === 1 ? "" : "s"} and decide how to fix each one. Approve any change before it is made.` : "No gaps were found by the current rules. Keep checking as the code changes.",
    partial ? `Check the ${partial} partial finding${partial === 1 ? "" : "s"}: each depends on context only you can confirm.` : "",
    `Work through the ${r.outside.length} item${r.outside.length === 1 ? "" : "s"} that live outside code. Code checks alone are not enough for a full review.`,
    "Ask a qualified compliance professional to review the results before you rely on them.",
  ].filter(Boolean);
}
export const ALL_FRAMEWORKS: FrameworkId[] = ["gdpr", "soc2", "iso-27001", "eu-ai-act"];

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

export async function scan(root: string, frameworks: FrameworkId[] = ALL_FRAMEWORKS): Promise<Report> {
  const active = rules.filter((r) => r.controls.some((c) => frameworks.includes(c.framework)));
  const findings: Finding[] = [];
  let filesChecked = 0;
  for (const abs of await listFiles(root, (await readConfig(root)).ignore)) {
    const ext = extname(abs) || (abs.endsWith(".env") ? ".env" : "");
    const relevant = active.filter((r) => r.extensions.includes(ext));
    if (!relevant.length) continue;
    const buf = await readFile(abs);
    if (buf.length > MAX_BYTES || buf.includes(0)) continue; // skip big or binary files
    const file = relative(root, abs).split(sep).join("/");
    const lines = buf.toString("utf8").split(/\r?\n/);
    if (lines.some((l) => l.length > MAX_LINE)) continue; // minified or generated
    filesChecked++;
    const add = (r: (typeof relevant)[number], line: number) => findings.push({
      ruleId: r.id, file, line, status: r.status, severity: r.severity, title: r.title,
      controls: r.controls.filter((c) => frameworks.includes(c.framework)), fix: r.fix, note: r.note,
    });
    for (const r of relevant) {
      if (r.test) lines.forEach((text, i) => { if (r.test!(text)) add(r, i + 1); });
      if (r.fileTest) for (const n of r.fileTest(lines)) add(r, n);
    }
  }
  // Auditor: one finding per rule per line; stable order.
  const seen = new Set<string>();
  const deduped = findings.filter((f) => { const k = `${f.ruleId}|${f.file}|${f.line}`; return seen.has(k) ? false : (seen.add(k), true); })
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  const hit = new Set(deduped.map((f) => f.ruleId));
  return {
    rulesVersion: RULES_VERSION,
    frameworks: [...frameworks].sort(),
    findings: deduped,
    // Only the Checker sets Met: a rule that ran and found nothing.
    met: active.filter((r) => !hit.has(r.id)).map((r) => ({ ruleId: r.id, title: r.title, controls: r.controls.filter((c) => frameworks.includes(c.framework)) })),
    outside: outsideFor(frameworks),
    filesChecked,
    disclaimer: DISCLAIMER,
  };
}

const LABEL = { gap: "Gap", partial: "Partial", met: "Met", outside: "Outside code" } as const;
const ctl = (c: { framework: string; id: string }[]) => c.map((x) => `${x.framework.toUpperCase()} ${x.id}`).join(" · ");

export function toMarkdown(r: Report): string {
  const lines = [
    "# Lintsure report", "",
    `Frameworks: ${r.frameworks.join(", ")} · Rules v${r.rulesVersion}`, "",
    `> ${DISCLAIMER}`, "",
    `## Findings (${r.findings.length})`, "",
  ];
  if (!r.findings.length) lines.push("No issues found by the current rules.", "");
  for (const f of r.findings) lines.push(`### ${LABEL[f.status]} · \`${f.file}:${f.line}\``, `**${f.title}** (${f.severity})`, "", `- Rules: ${ctl(f.controls)}`, `- Fix: ${f.fix}`, `- Auditor note: ${f.note}`, "");
  lines.push(`## Met (${r.met.length})`, "", ...r.met.map((m) => `- ${m.title} · ${ctl(m.controls)}`), "");
  lines.push(`## Outside code (${r.outside.length})`, "", "Code can't prove these. They still need to be done before a full review.", "", ...r.outside.map((o) => `- ${o.framework.toUpperCase()} ${o.control} · ${o.title}: ${o.evidence}`), "");
  lines.push("## What to do next", "", ...nextSteps(r).map((s, i) => `${i + 1}. ${s}`), "");
  lines.push("## What this report is not", "", NOT_A_VERDICT, "");
  return lines.join("\n");
}
