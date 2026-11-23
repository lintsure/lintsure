// Writes plain Markdown docs into packages/core/docs from the engine itself, so they ship inside the npm package
// and a coding agent can read them offline at node_modules/@lintsure/core/docs. Generated: never edit by hand.
// Run after tsc (npm run build does this).
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
const core = await import("../packages/core/dist/src/index.js");
const dir = new URL("../packages/core/docs/", import.meta.url);
rmSync(dir, { recursive: true, force: true }); mkdirSync(dir, { recursive: true });
const head = (t) => `<!-- Generated from Lintsure ${core.RULES_VERSION} by scripts/build-docs.mjs. -->\n# ${t}\n\n`;

const byFw = {};
for (const r of core.rules) for (const c of r.controls) (byFw[c.framework] ??= new Set()).add(r.id);
writeFileSync(new URL("rules.md", dir), head(`Lintsure rules (${core.rules.length})`) + core.rules.map((r) => [
  `## ${r.id}`, `**${r.title}** · status when found: ${r.status} · risk: ${r.severity}${r.confidence === "medium" ? " · medium confidence (shown with --all)" : ""}`, "",
  `- Controls: ${r.controls.map((c) => `${c.framework} ${c.id} (${c.title})`).join("; ")}`,
  `- Fix: ${r.fix}`, `- Note: ${r.note}`,
  `- Real only when: ${core.verifyFor(r.id).real.join(" ")}`,
  `- Not a problem when: ${core.verifyFor(r.id).notReal.join(" ")}`,
  ...(r.unseen ? [`- When Partial, Lintsure can't see: ${r.unseen}`] : []),
  ...(r.seenIn ?? []).map((s) => `- Seen in a real incident: ${s.title} (${s.url})`),
  `- Page: https://lintsure.com/rules/${r.id.replace(/\./g, "-")}`, "",
].join("\n")).join("\n"));

writeFileSync(new URL("frameworks.md", dir), head("Frameworks") + core.knowledge.map((k) => [
  `## ${k.name} (\`${k.id}\`)`, k.summary, "", `Applies to: ${k.whoItAppliesTo}`, "",
  ...(k.timeline ?? []).map((m) => `- ${m.date}: ${m.what}`), ...(k.timeline?.length ? [""] : []),
  ...k.obligations.map((o) => `- ${o.ref} ${o.title} [${o.inCode === "yes" ? "checked in code" : o.inCode === "partly" ? "partly in code" : "outside code"}]: ${o.plain}${o.rules?.length ? ` Rules: ${o.rules.join(", ")}.` : ""}`),
  "", `Our own summary, checked on ${k.checkedOn}. Read the official text for anything you rely on.`, "",
].join("\n")).join("\n"));

writeFileSync(new URL("README.md", dir), head("Lintsure docs for coding agents") + [
  "These files ship with `@lintsure/core`, so you can read them without a network connection.", "",
  "- `rules.md`: every rule: what it looks for, the controls it maps to, how to fix it.",
  "- `frameworks.md`: each framework in plain words, its dates and which parts code can show.",
  "- `agents.md`: how to talk about Lintsure results.", "",
  "Commands: `npx lintsure scan`, `baseline`, `init`, `info`, `setup`, `status`. Run `npx lintsure` for every option.",
  "Full docs: https://lintsure.com/docs", "", core.DISCLAIMER, "",
].join("\n"));

writeFileSync(new URL("agents.md", dir), head("How to use Lintsure as a coding agent") + `${core.AGENT_GUIDANCE}\n\n## Before changing anything\n\n${core.APPROVAL_RULES}\n\n## Triage\n\n${core.TRIAGE_GUIDE}\n`);
console.log(`docs: ${core.rules.length} rules, ${core.knowledge.length} frameworks -> packages/core/docs`);
