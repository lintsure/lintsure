// The finding schema. Every rule must fill every field: the site promises file, line,
// rules broken, a fix and an auditor note for each finding.

export type Status = "met" | "partial" | "gap" | "outside";
export type Severity = "high" | "medium" | "low";
export type FrameworkId = "gdpr" | "soc2" | "iso-27001" | "eu-ai-act" | "owasp-top10";

export interface Control { framework: FrameworkId; id: string; title: string }

export interface Rule {
  id: string;
  title: string;
  /** Statuses a rule can produce. Only the Checker may produce "met". */
  status: Exclude<Status, "met" | "outside">;
  severity: Severity;
  controls: Control[];
  fix: string;
  note: string;
  /** Files this rule reads, by extension. */
  extensions: string[];
  /** Optional: only files whose name matches, e.g. /^package\.json$/ so lockfiles are skipped. */
  fileName?: RegExp;
  /** Optional: a line hit is dropped when this appears within 8 lines above or 3 below
   *  (e.g. an exp claim set in the payload just before jwt.encode). */
  unlessNear?: RegExp;
  /** Optional: a hit is dropped when the nearest enclosing JSON key above it matches
   *  (e.g. "peerDependencies", where "*" is the normal range). */
  unlessInKey?: RegExp;
  /** Line rule: true when the line breaks the rule. Must be pure: same line, same answer. */
  test?(line: string): boolean | "partial";
  /** File rule, for checks that need context (e.g. "an AI call with no logging in this file").
   *  Returns 1-based line numbers to flag. Must be pure. */
  fileTest?(lines: string[]): number[];
  mappedBy: string;
  reviewedAt: string;
}

/** A change Lintsure suggests. It is only ever a proposal: a person must approve it first. */
export interface Proposal {
  /** Exactly where: "file:line". */
  where: string;
  /** What would change. */
  what: string;
  /** Why: the problem and the controls it relates to. */
  why: string;
  /** What the person gains if they approve it. */
  benefit: string;
  /** Always true. Nothing changes without an explicit yes. */
  needsApproval: true;
}

export interface Finding {
  /** Finding number within this run, for example F-003. */
  id: string;
  ruleId: string;
  file: string;
  line: number;
  status: Status;
  severity: Severity;
  title: string;
  controls: Control[];
  fix: string;
  note: string;
  /** The suggested change, laid out for a person to approve or decline. */
  proposal: Proposal;
  /** Stable id: rule, file and the flagged line's content (not its number). Contains no code. */
  fingerprint: string;
  /** Set when .lintsure/baseline.json exists: whether the finding is new since then. */
  change?: "new" | "unchanged";
  /** Set when a person accepted this finding in .lintsure/accepted.yaml. */
  accepted?: Acceptance;
}

/** A person's decision to accept a finding, with their reason. Expired acceptances count as open again. */
export interface Acceptance { reason: string; by: string; date: string; reviewBy?: string; expired: boolean }

/** What changed since the baseline: findings that were in the baseline and are now gone. */
export interface BaselineDiff { created: string; newCount: number; unchangedCount: number; fixed: { ruleId: string; file: string; fingerprint: string }[] }

export interface OutsideItem { framework: FrameworkId; control: string; title: string; evidence: string }

export interface Report {
  /** Bump when output format or rule behavior changes. */
  rulesVersion: string;
  frameworks: FrameworkId[];
  findings: Finding[];
  /** Rule ids that ran and found nothing: those controls are Met for the code checked. */
  met: { ruleId: string; title: string; controls: Control[] }[];
  outside: OutsideItem[];
  /** Always present: what the report is and isn't. */
  disclaimer: string;
  /** Files the rules actually read (after skipping folders, large and binary files). */
  filesChecked: number;
  /** Present when the repo has a .lintsure/baseline.json. */
  baseline?: BaselineDiff;
  /** The dated record of this run: scope, what applies and why, check points, results by control, counts. */
  record?: import("./record.js").CheckRecord;
}
