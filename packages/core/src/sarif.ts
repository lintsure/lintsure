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
          return { id, name: id, shortDescription: { text: rule.title }, help: { text: `${rule.fix} ${rule.note}` },
            helpUri: `https://lintsure.com/rules/${id.split(".").join("-")}`,
            // GitHub code scanning ranks alerts by security-severity (0-10) and shows precision.
            properties: { tags: rule.controls.map((c) => `${c.framework} ${c.id}`), "security-severity": SCORE[rule.severity], precision: rule.confidence === "medium" ? "medium" : "high" } };
        }),
      } },
      results: r.findings.map((f) => ({
        ruleId: f.ruleId,
        level: f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
        message: { text: `${f.title}. Proposed change (needs your approval): ${f.proposal.what} Why: ${f.proposal.why}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        partialFingerprints: { "lintsure/v1": f.fingerprint },
        ...(f.change ? { baselineState: f.change } : {}),
        ...(f.accepted && !f.accepted.expired ? { suppressions: [{ kind: "external", justification: `${f.accepted.reason} (accepted by ${f.accepted.by}, ${f.accepted.date})` }] } : {}),
      })),
    }],
  };
}
