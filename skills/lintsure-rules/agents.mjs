// One rules file for every agent: writes the rules from .lintsure/rules.yml into the instruction files other agents
// read (AGENTS.md for Codex and many others, Cursor's rules folder, GitHub Copilot, CLAUDE.md). Lintsure owns only its
// own marked block in shared files, so the user's text around it is never touched.
import { readFileSync, writeFileSync, mkdirSync, existsSync, unlinkSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileRules } from "./lib.mjs";

const START = "<!-- lintsure:rules:start -->", END = "<!-- lintsure:rules:end -->";
export const TARGETS = {
  agents: { file: "AGENTS.md", shared: true, label: "AGENTS.md (Codex, Jules, Amp, Zed and other agents)" },
  cursor: { file: ".cursor/rules/lintsure.mdc", shared: false, label: "Cursor (.cursor/rules/lintsure.mdc)" },
  copilot: { file: ".github/copilot-instructions.md", shared: true, label: "GitHub Copilot (.github/copilot-instructions.md)" },
  claude: { file: "CLAUDE.md", shared: true, label: "CLAUDE.md (Claude Code without the plugin)" },
};

/** The rules as plain instructions. Says honestly where they're checked. */
export function block(root) {
  const rules = fileRules(root);
  if (!rules.length) return null;
  const line = (r) => r.kind === "protect" ? `- ${r.text} (Files: ${r.paths})` : r.kind === "avoid" && r.paths ? `- ${r.text} (In: ${r.paths})` : `- ${r.text}`;
  return [
    "## Project rules (from Lintsure)",
    "",
    "Keep to these in every change. They come from `.lintsure/rules.yml`; change them there, not here.",
    "",
    ...rules.map(line),
    "",
    "If the user asks for something that goes against one of these, do it and say which rule it changes in one line. Lintsure checks these rules automatically in Claude Code with the Lintsure plugin.",
  ].join("\n");
}

function put(path, text, shared) {
  mkdirSync(dirname(path), { recursive: true });
  if (!shared) {
    writeFileSync(path, `---\ndescription: Project rules from Lintsure (.lintsure/rules.yml)\nalwaysApply: true\n---\n\n${text}\n`);
    return;
  }
  const marked = `${START}\n${text}\n${END}`;
  const cur = existsSync(path) ? readFileSync(path, "utf8") : "";
  const i = cur.indexOf(START), j = cur.indexOf(END);
  const next = i >= 0 && j > i ? cur.slice(0, i) + marked + cur.slice(j + END.length) : cur ? `${cur.replace(/\s*$/, "")}\n\n${marked}\n` : `${marked}\n`;
  if (next !== cur) writeFileSync(path, next);
}

/** Which targets already carry Lintsure's rules, so a rules change keeps exactly those in step. */
export function synced(root) {
  return Object.entries(TARGETS).filter(([, t]) => {
    const p = join(root, t.file);
    if (!existsSync(p)) return false;
    return !t.shared || readFileSync(p, "utf8").includes(START);
  }).map(([k]) => k);
}

/** Writes the rules to the chosen targets. Default: AGENTS.md and Cursor, plus Copilot and CLAUDE.md when those files exist. */
export function sync(root, want) {
  const text = block(root);
  if (!text) return { written: [], note: "No rules in .lintsure/rules.yml yet." };
  const keys = want?.length ? want.filter((k) => TARGETS[k]) : ["agents", "cursor", ...["copilot", "claude"].filter((k) => existsSync(join(root, TARGETS[k].file)))];
  for (const k of keys) put(join(root, TARGETS[k].file), text, TARGETS[k].shared);
  return { written: keys.map((k) => TARGETS[k].label) };
}

/** Takes Lintsure's block out again (the user's own text stays). */
export function unsync(root) {
  const done = [];
  for (const [k, t] of Object.entries(TARGETS)) {
    const p = join(root, t.file);
    if (!existsSync(p)) continue;
    const cur = readFileSync(p, "utf8");
    if (!t.shared) { if (cur.includes("Project rules from Lintsure")) { unlinkSync(p); done.push(t.label); } continue; }
    const i = cur.indexOf(START), j = cur.indexOf(END);
    if (i >= 0 && j > i) { writeFileSync(p, (cur.slice(0, i) + cur.slice(j + END.length)).replace(/\n{3,}/g, "\n\n")); done.push(t.label); }
  }
  return done;
}
