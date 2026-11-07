// The finding schema. Every rule must fill every field: the site promises file, line,
// rules broken, a fix and an auditor note for each finding.

export type Status = "met" | "partial" | "gap" | "outside";
export type Severity = "high" | "medium" | "low";
export type FrameworkId = "gdpr" | "soc2" | "iso-27001" | "eu-ai-act";

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
  /** Line rule: true when the line breaks the rule. Must be pure: same line, same answer. */
  test?(line: string): boolean;
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
}

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
}
