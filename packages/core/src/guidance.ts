// How any agent should talk about and act on Lintsure results. Sent to MCP clients as server instructions
// and tested: the report text must never contain the phrases in FORBIDDEN_CLAIMS, and every finding
// must carry a full proposal (where, what, why, benefit) that needs a person's approval.
import type { Control, Proposal } from "./types.js";

/** The approval rule every agent must follow before doing anything. Part of AGENT_GUIDANCE and every scan reply. */
export const APPROVAL_RULES = `Before you do anything (edit, create or delete a file, run a command, install a package, or treat a framework as applying), stop and present a proposal with all four parts:
1. What you plan to do.
2. Why: the problem and the rule or control it relates to.
3. Where, exactly: the file and line, or the document and section.
4. The benefit to the user if they approve it.
Then ask the user to approve that one proposal and wait. Only a clear yes is approval. Silence, "maybe" or a question is not. Do only what was approved, then show what changed. One proposal at a time.`;

const NAMES: Record<string, string> = { "eu-ai-act": "EU AI Act", gdpr: "GDPR", soc2: "SOC 2", "iso-27001": "ISO 27001", "owasp-top10": "OWASP Top 10" };
const refs = (cs: Control[]) => cs.map((c) => `${NAMES[c.framework]} ${c.id}`).join(", ");

/** Lays a finding out as a proposal a person can approve or decline. */
export function proposalFor(f: { file: string; line: number; title: string; fix: string; note: string; controls: Control[] }): Proposal {
  return {
    where: `${f.file}:${f.line}`,
    what: f.fix,
    why: `${f.title}. ${f.note} Relates to ${refs(f.controls)}.`,
    benefit: `Removes this finding from the code side of ${refs(f.controls)}, so it no longer shows up when this file is reviewed. Work outside code may still be needed.`,
    needsApproval: true,
  };
}

export const AGENT_GUIDANCE = `You are using Lintsure, a readiness tool that checks code against compliance frameworks.

${APPROVAL_RULES}

When you report Lintsure results:
- Never say or imply the user is compliant, certified, approved, audit-ready, "good to go", or that they passed. Lintsure cannot decide that.
- Never make a decision for the user. Present findings and options; the user chooses what to do.
- Every finding comes with a proposal (where, what, why, benefit). Show it as a proposal, never as something you have already done.
- Say that results cover code only, against Lintsure's reading of the publicly available text of each framework.
- Always mention the items outside code (policies, training, contracts, evidence) that still need to be done before a full review.
- Recommend that a qualified person review the results before any audit, certification or business decision.
- A control marked Met only means Lintsure's rules found no problem in the files they read. Say so if you mention Met.`;

/** Phrases that read as a verdict. Lintsure's own output must never claim these. */
export const FORBIDDEN_CLAIMS: RegExp[] = [
  /\byou(?:'re| are) (?:now )?(?:fully )?(?:compliant|certified|audit[- ]ready|ready for (?:an |the )?audit)\b/i,
  /\b(?:good to go|all clear|you passed|passed the audit|guaranteed?)\b/i,
  /\bis (?:now )?(?:fully )?(?:compliant|certified)\b/i,
];
