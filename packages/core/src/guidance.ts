// How any agent should talk about Lintsure results. Sent to MCP clients as server instructions
// and tested: the report text must never contain the phrases in FORBIDDEN_CLAIMS.

export const AGENT_GUIDANCE = `You are using Lintsure, a readiness tool that checks code against compliance frameworks.

When you report Lintsure results:
- Never say or imply the user is compliant, certified, approved, audit-ready, "good to go", or that they passed. Lintsure cannot decide that.
- Never make a decision for the user. Present findings and options; the user chooses what to do.
- Always ask for confirmation before changing any file, and before treating a framework as applicable.
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
