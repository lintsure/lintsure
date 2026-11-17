// SARIF 2.1.0 output, the format GitHub code scanning and many editors read.
// It holds rule ids, file paths, line numbers, messages and fingerprints. It never contains source code.
import type { Report } from "./types.js";
import { rules } from "./rules/index.js";

const SCORE = { high: "8.0", medium: "5.0", low: "2.0" } as const;

export function toSarif(r: Report, version: string) {
  const used = [...new Set(r.findings.map((f) => f.ruleId))];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "Lintsure", version, informationUri: "https://lintsure.com",
        rules: used.map((id) => {
          const rule = rules.find((x) => x.id === id)!;
          return { id, name: id, shortDescription: { text: rule.title }, help: { text: `${rule.fix} ${rule.note}${(rule.seenIn ?? []).map((s) => ` Seen in a real incident: ${s.title} (${s.url})`).join("")}` },
            helpUri: `https://lintsure.com/rules/${id.split(".").join("-")}`,
            // GitHub code scanning ranks alerts by security-severity (0-10) and shows precision.
            properties: { tags: rule.controls.map((c) => `${c.framework} ${c.id}`), "security-severity": SCORE[rule.severity], precision: rule.confidence === "medium" ? "medium" : "high" } };
        }),
      } },
      // The policy this run used, so a code-scanning alert can be traced to the exact rules in force.
      ...(r.policy ? { properties: { "lintsure/policyFingerprint": r.policy.fingerprint, "lintsure/policySha256": r.policy.sha256, "lintsure/rulesActive": r.policy.rulesActive, "lintsure/repoRules": r.policy.repoRules, "lintsure/workspaceRules": r.policy.workspaceRules } } : {}),
      results: r.findings.map((f) => ({
        ruleId: f.ruleId,
        level: f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
        message: { text: `${f.title}. Proposed change (needs your approval): ${f.proposal.what} Why: ${f.proposal.why}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        ...(f.unseen ? { properties: { "lintsure/unseen": f.unseen } } : {}),
        partialFingerprints: { "lintsure/v1": f.fingerprint },
        // SARIF fixes: replace the whole flagged line, or insert before it. Editors and code scanning can offer it.
        ...(f.patch ? { fixes: [{ description: { text: `${f.proposal.what} (needs your approval)` }, artifactChanges: [{ artifactLocation: { uri: f.file }, replacements: [{
          deletedRegion: f.patch.old == null ? { startLine: f.patch.line, startColumn: 1, endLine: f.patch.line, endColumn: 1 } : { startLine: f.patch.line, startColumn: 1, endLine: f.patch.line, endColumn: f.patch.old.length + 1 },
          insertedContent: { text: f.patch.text } }] }] }] } : {}),
        ...(f.change ? { baselineState: f.change } : {}),
        ...(f.accepted && !f.accepted.expired ? { suppressions: [{ kind: "external", justification: `${f.accepted.reason} (accepted by ${f.accepted.by}, ${f.accepted.date})` }] } : {}),
      })),
    }],
  };
}
