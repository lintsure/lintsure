// Scout (file walk) + Checker (rules) + Auditor (dedupe, sort) + Officer (outside code).
// No network calls anywhere in this package: a test enforces it.
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import { outsideFor } from "./knowledge/index.js";
import { rules } from "./rules/index.js";
import type { Finding, FrameworkId, Report } from "./types.js";

export * from "./types.js";
export { rules };
export * from "./knowledge/index.js";
export const RULES_VERSION = "0.1.0";
export const ALL_FRAMEWORKS: FrameworkId[] = ["gdpr", "soc2", "iso-27001", "eu-ai-act"];

/** Reads the frameworks list from lintsure.config.yaml in the repo root, if there is one.
 *  Only the simple list form is supported:
 *    frameworks:
 *      - gdpr
 *  Ids Lintsure doesn't check yet (for example "hipaa") are returned in `skipped`. */
export async function readConfig(root: string): Promise<{ frameworks: FrameworkId[] | null; skipped: string[] }> {
  let text: string;
  try { text = await readFile(join(root, "lintsure.config.yaml"), "utf8"); } catch { return { frameworks: null, skipped: [] }; }
  const ids: string[] = []; let inList = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trimEnd();
    if (/^frameworks\s*:\s*\[\s*\]\s*$/.test(line)) return { frameworks: [], skipped: [] };
    if (/^frameworks\s*:\s*$/.test(line)) { inList = true; continue; }
    if (inList) { const m = line.match(/^\s+-\s*([\w-]+)\s*$/); if (m) ids.push(m[1]); else if (line.trim()) inList = false; }
  }
  const known = ids.filter((i): i is FrameworkId => (ALL_FRAMEWORKS as string[]).includes(i));
  return { frameworks: known, skipped: ids.filter((i) => !known.includes(i as FrameworkId)) };
}

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", "venv", ".venv", "__pycache__", "coverage"]);
const MAX_BYTES = 1_000_000;

/** Scout: list files to check, sorted so output order never depends on the file system. */
export async function listFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name)) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p); else if (e.isFile()) out.push(p);
    }
  }
  await walk(root);
  return out.sort();
}

export async function scan(root: string, frameworks: FrameworkId[] = ALL_FRAMEWORKS): Promise<Report> {
  const active = rules.filter((r) => r.controls.some((c) => frameworks.includes(c.framework)));
  const findings: Finding[] = [];
  for (const abs of await listFiles(root)) {
    const ext = extname(abs) || (abs.endsWith(".env") ? ".env" : "");
    const relevant = active.filter((r) => r.extensions.includes(ext));
    if (!relevant.length) continue;
    const buf = await readFile(abs);
    if (buf.length > MAX_BYTES || buf.includes(0)) continue; // skip big or binary files
    const file = relative(root, abs).split(sep).join("/");
    const lines = buf.toString("utf8").split(/\r?\n/);
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
  };
}

const LABEL = { gap: "Gap", partial: "Partial", met: "Met", outside: "Outside code" } as const;
const ctl = (c: { framework: string; id: string }[]) => c.map((x) => `${x.framework.toUpperCase()} ${x.id}`).join(" · ");

export function toMarkdown(r: Report): string {
  const lines = [
    "# Lintsure report", "",
    `Frameworks: ${r.frameworks.join(", ")} · Rules v${r.rulesVersion}`, "",
    "> A readiness check, not an audit or legal advice.", "",
    `## Findings (${r.findings.length})`, "",
  ];
  if (!r.findings.length) lines.push("No issues found by the current rules.", "");
  for (const f of r.findings) lines.push(`### ${LABEL[f.status]} · \`${f.file}:${f.line}\``, `**${f.title}** (${f.severity})`, "", `- Rules: ${ctl(f.controls)}`, `- Fix: ${f.fix}`, `- Auditor note: ${f.note}`, "");
  lines.push(`## Met (${r.met.length})`, "", ...r.met.map((m) => `- ${m.title} · ${ctl(m.controls)}`), "");
  lines.push(`## Outside code (${r.outside.length})`, "", ...r.outside.map((o) => `- ${o.framework.toUpperCase()} ${o.control} · ${o.title}: ${o.evidence}`), "");
  return lines.join("\n");
}
