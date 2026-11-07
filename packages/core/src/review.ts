// Baseline and accepted findings, read from the repo's own .lintsure/ folder. Nothing is sent anywhere:
// these are files in the user's folder, and the user decides whether to commit them.
// Neither file contains code: only rule ids, file paths, fingerprints (one-way hashes) and people's reasons.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Acceptance, Finding, Report } from "./types.js";

export const BASELINE_FILE = ".lintsure/baseline.json";
export const ACCEPTED_FILE = ".lintsure/accepted.yaml";

/** A short one-way hash of the rule, file and the flagged line with spacing normalised. Moving the line keeps it; editing it changes it. */
export function fingerprint(ruleId: string, file: string, lineText: string): string {
  return createHash("sha256").update(`${ruleId}\n${file}\n${lineText.trim().replace(/\s+/g, " ")}`).digest("hex").slice(0, 16);
}

export interface Baseline { version: 1; created: string; findings: { ruleId: string; file: string; fingerprint: string }[] }
export interface AcceptedEntry { rule: string; where: string; fingerprint: string; reason: string; accepted_by: string; date: string; review_by?: string }

/** The baseline to write for a report: every open finding, without code. Accepted findings are left out. */
export function toBaseline(r: Report, created: string): Baseline {
  return { version: 1, created, findings: r.findings.filter((f) => !f.accepted || f.accepted.expired).map(({ ruleId, file, fingerprint }) => ({ ruleId, file, fingerprint })) };
}

/** Reads the simple list form of accepted.yaml: "- key: value" items with indented "key: value" lines. */
export function parseAccepted(text: string): AcceptedEntry[] {
  const out: Record<string, string>[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").replace(/^#.*$/, "");
    const m = line.match(/^(\s*)(-\s+)?([a-z_]+)\s*:\s*(.*)$/);
    if (!m) continue;
    if (m[2]) out.push({});
    if (!out.length) continue;
    out[out.length - 1][m[3]] = m[4].trim().replace(/^["']|["']$/g, "");
  }
  return out.filter((e) => e.rule && e.fingerprint && e.reason && e.accepted_by) as unknown as AcceptedEntry[];
}

async function readText(path: string) { try { return await readFile(path, "utf8"); } catch { return null; } }

/** Adds acceptances, new/unchanged marks and the list of fixed findings, from the repo's .lintsure/ files. */
export async function applyReview(r: Report, root: string, today: string): Promise<Report> {
  const acceptedText = await readText(join(root, ACCEPTED_FILE));
  const accepted = acceptedText ? parseAccepted(acceptedText) : [];
  for (const f of r.findings) {
    const a = accepted.find((e) => e.rule === f.ruleId && e.fingerprint === f.fingerprint);
    if (a) f.accepted = { reason: a.reason, by: a.accepted_by, date: a.date, reviewBy: a.review_by, expired: !!a.review_by && a.review_by < today } satisfies Acceptance;
  }
  const baseText = await readText(join(root, BASELINE_FILE));
  if (baseText) {
    let base: Baseline | null = null;
    try { base = JSON.parse(baseText); } catch { /* unreadable baseline: treat as none */ }
    if (base?.findings) {
      const known = new Set(base.findings.map((b) => b.fingerprint));
      const now = new Set(r.findings.map((f) => f.fingerprint));
      for (const f of r.findings) f.change = known.has(f.fingerprint) ? "unchanged" : "new";
      r.baseline = {
        created: base.created,
        newCount: r.findings.filter((f) => f.change === "new" && !(f.accepted && !f.accepted.expired)).length,
        unchangedCount: r.findings.filter((f) => f.change === "unchanged").length,
        fixed: base.findings.filter((b) => !now.has(b.fingerprint)),
      };
    }
  }
  return r;
}

/** Findings still needing a decision: not accepted, or accepted but past the review date. */
export const isOpen = (f: Finding) => !f.accepted || f.accepted.expired;
