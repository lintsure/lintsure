// The readiness check record: a dated, structured account of one run. What was checked, against which
// rules, what applies and why, how many check points, and what was found. It is a readiness record, not
// an audit: no auditor examined anything, and a person still has to review and sign it.
// It never contains source code.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";
import type { FrameworkId, Report, Severity } from "./types.js";

export type ControlResult = "finding" | "observation" | "no issue found" | "not checked";

export interface CheckRecord {
  /** Stable id for this run, for example LS-20261108-1a2b3c. */
  id: string;
  /** When the check ran, ISO 8601 in UTC. */
  createdAt: string;
  kind: "readiness check record";
  tool: { name: "Lintsure"; version: string };
  /** Which interface ran it: cli, mcp or ci. */
  source: string;
  scope: { folder: string; commit?: string; branch?: string; filesRead: number; ignored: string[] };
  /** Each framework checked, and why it was included. */
  applies: { framework: FrameworkId; why: string }[];
  /** Every control the active rules cover, with its result. */
  byControl: { framework: FrameworkId; control: string; title: string; rules: string[]; checkPoints: number; result: ControlResult; findingIds: string[] }[];
  counts: {
    /** One rule applied to one file is one check point. */
    checkPoints: number;
    rulesRun: number;
    /** Partial results: depend on context a person must confirm. */
    observations: number;
    /** Gap results: the code itself shows a problem. */
    findings: number;
    byRisk: Record<Severity, number>;
    accepted: number;
    fixedSinceBaseline: number;
    outsideCode: number;
  };
  /** Filled in by a person. The record is a draft until then. */
  review: { reviewer: string | null; date: string | null; decision: string | null };
}

export interface RecordOptions {
  /** Why each framework was checked. A string applies to all of them. */
  why?: string | Partial<Record<FrameworkId, string>>;
  source?: string;
  /** Time of the run. Defaults to now; tests pass a fixed value. */
  now?: Date;
}

/** Reads the current commit and branch from .git without running git or using the network. */
async function gitInfo(root: string): Promise<{ commit?: string; branch?: string }> {
  try {
    const head = (await readFile(join(root, ".git", "HEAD"), "utf8")).trim();
    if (!head.startsWith("ref:")) return { commit: head.slice(0, 12) };
    const ref = head.slice(5).trim(), branch = ref.replace(/^refs\/heads\//, "");
    try { return { branch, commit: (await readFile(join(root, ".git", ref), "utf8")).trim().slice(0, 12) }; }
    catch {
      const packed = await readFile(join(root, ".git", "packed-refs"), "utf8").catch(() => "");
      const line = packed.split(/\r?\n/).find((l) => l.endsWith(` ${ref}`));
      return { branch, commit: line?.slice(0, 12) };
    }
  } catch { return {}; }
}

export async function buildRecord(r: Report, root: string, checkPoints: number, perRule: Record<string, number>, rulesRun: string[],
  ruleControls: { id: string; controls: { framework: FrameworkId; id: string; title: string }[] }[], ignored: string[], opts: RecordOptions = {}): Promise<CheckRecord> {
  const now = opts.now ?? new Date();
  const createdAt = now.toISOString();
  const hash = createHash("sha256").update(createdAt + r.findings.map((f) => f.fingerprint).join(",")).digest("hex").slice(0, 6);
  const why = (f: FrameworkId) => typeof opts.why === "string" ? opts.why : opts.why?.[f] ?? "Checked by default: no framework list was given.";

  const controls = new Map<string, CheckRecord["byControl"][number]>();
  for (const rule of ruleControls) for (const c of rule.controls) {
    if (!r.frameworks.includes(c.framework)) continue;
    const key = `${c.framework}|${c.id}`;
    const row = controls.get(key) ?? { framework: c.framework, control: c.id, title: c.title, rules: [], checkPoints: 0, result: "no issue found" as ControlResult, findingIds: [] };
    row.rules.push(rule.id); row.checkPoints += perRule[rule.id] ?? 0;
    controls.set(key, row);
  }
  // A control whose rules ran on no file was not checked; "no issue found" would claim more than the scan did (review P2).
  for (const row of controls.values()) if (row.checkPoints === 0) row.result = "not checked";
  for (const f of r.findings) {
    if (f.accepted && !f.accepted.expired) continue;
    for (const c of f.controls) {
      const row = controls.get(`${c.framework}|${c.id}`); if (!row) continue;
      row.findingIds.push(f.id);
      if (f.status === "gap") row.result = "finding"; else if (row.result !== "finding") row.result = "observation";
    }
  }
  const open = r.findings.filter((f) => !f.accepted || f.accepted.expired);
  const byRisk: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of open) byRisk[f.severity]++;

  return {
    id: `LS-${createdAt.slice(0, 10).replace(/-/g, "")}-${hash}`,
    createdAt, kind: "readiness check record",
    tool: { name: "Lintsure", version: r.rulesVersion },
    source: opts.source ?? "cli",
    scope: { folder: basename(root), ...(await gitInfo(root)), filesRead: r.filesChecked, ignored },
    applies: r.frameworks.map((f) => ({ framework: f, why: why(f) })),
    byControl: [...controls.values()].sort((a, b) => a.framework.localeCompare(b.framework) || a.control.localeCompare(b.control, undefined, { numeric: true })),
    counts: {
      checkPoints, rulesRun: rulesRun.length,
      observations: open.filter((f) => f.status === "partial").length,
      findings: open.filter((f) => f.status === "gap").length,
      byRisk, accepted: r.findings.length - open.length,
      fixedSinceBaseline: r.baseline?.fixed.length ?? 0,
      outsideCode: r.outside.length,
    },
    review: { reviewer: null, date: null, decision: null },
  };
}
