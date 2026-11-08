// Agent knowledge: Classifier uses applies(), Officer uses obligations that code can't prove.
import type { FrameworkId, OutsideItem } from "../types.js";
import { euAiAct } from "./eu-ai-act.js";
import { gdpr } from "./gdpr.js";
import { iso27001 } from "./iso-27001.js";
import { soc2 } from "./soc2.js";
import { owaspTop10 } from "./owasp-top10.js";
import type { FrameworkKnowledge, Profile } from "./types.js";

export * from "./types.js";
export const knowledge: FrameworkKnowledge[] = [euAiAct, gdpr, soc2, iso27001, owaspTop10];
export const getKnowledge = (id: FrameworkId) => knowledge.find((k) => k.id === id);

/** Classifier: suggest frameworks with a reason. The user confirms; nothing is auto-applied. */
export function classify(p: Profile): { framework: FrameworkId; name: string; reason: string }[] {
  return knowledge.flatMap((k) => { const reason = k.applies(p); return reason ? [{ framework: k.id, name: k.name, reason }] : []; });
}

/** Officer: everything code can't prove, with the evidence an auditor will ask for. */
export function outsideFor(frameworks: FrameworkId[]): OutsideItem[] {
  return knowledge.filter((k) => frameworks.includes(k.id)).flatMap((k) =>
    k.obligations.filter((o) => o.inCode === "no").map((o) => ({ framework: k.id, control: o.ref, title: o.title, evidence: o.evidence ?? o.plain })));
}
