#!/usr/bin/env node
// Lintsure rules helper for the lintsure-rules skill. Runs on this machine; nothing is sent anywhere.
//   node rules.mjs suggest            Suggest rules from what the project already has, each with its reason.
//   node rules.mjs write '<json>'     Add rules to .lintsure/rules.yml. <json> is an array of
//                                      {kind, text, pattern?, paths?, in?} (kind: avoid, protect, deps, note).
//   node rules.mjs try '<json>'       Dry run one rule on the repo before writing it: what it matches today.
//                                      Either command also takes @file.json, safer for patterns with backslashes.
//   node rules.mjs list               Show the rules the file holds now, in plain words.
//   node rules.mjs sync [targets]     Write the rules into other agents' instruction files (agents, cursor, copilot,
//                                      claude; comma separated). Default: AGENTS.md and Cursor, plus the others if present.
//   node rules.mjs unsync             Take Lintsure's block out of those files again.
// Suggestions are guesses from files that exist, never claims about what the code does. The user decides.
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, basename } from "node:path";
import { fileRules, globMatch, safePattern, MAX_LINE } from "./lib.mjs";
import { Worker } from "node:worker_threads";
import { profile } from "./profile.mjs";
import { sync, synced, unsync } from "./agents.mjs";

const root = process.cwd(), FILE = join(root, ".lintsure", "rules.yml");
const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".astro", ".output", "coverage", ".wrangler", "vendor", "out"]);
const rel = (f) => relative(root, f).replace(/\\/g, "/");

function files(max = 5000) {
  const out = [];
  const go = (d, depth) => {
    if (out.length >= max || depth > 8) return;
    let ents = []; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.isDirectory()) { if (!SKIP.has(e.name) && (!e.name.startsWith(".") || e.name === ".github")) go(join(d, e.name), depth + 1); }
      else out.push(join(d, e.name));
    }
  };
  go(root, 0);
  return out;
}
/** How many lines in source files already match, so a rule the code breaks everywhere isn't suggested blindly. */
function uses(all, re, only) {
  let n = 0;
  for (const f of all) {
    if (!/\.(m?[jt]sx?|cjs|astro|vue|svelte)$/.test(f) || (only && !only.test(rel(f)))) continue;
    try { if (statSync(f).size > 300_000) continue; for (const line of readFileSync(f, "utf8").split("\n")) if (re.test(line)) n++; } catch { /* skip */ }
  }
  return n;
}

function suggest() {
  const all = files(), paths = all.map(rel), p = profile(root), s = [];
  const has = (re) => paths.find((x) => re.test(x));
  const dirOf = (x) => x.split("/").slice(0, -1).join("/");

  const mig = has(/(^|\/)(migrations?|db\/migrate|prisma\/migrations)\/[^/]+\.(sql|[jt]s|rb|py)$/);
  if (mig) s.push({ id: "protect-migrations", kind: "protect", paths: `${dirOf(mig)}/**`, text: "Don't change database migrations that already exist. Add a new one instead.", why: `Suggested because ${dirOf(mig)}/ holds migrations. New files there are still allowed.` });

  const test = has(/(\.test|\.spec)\.[jt]sx?$|(^|\/)tests?\//);
  if (test) {
    const n = uses(all, /\.(skip|only)\(|\bxit\(|\bxdescribe\(/);
    s.push({ id: "no-skip-tests", kind: "avoid", pattern: "\\.(skip|only)\\(|\\bxit\\(|\\bxdescribe\\(", text: "Never skip or disable tests to make them pass.", why: `Suggested because the project has tests (${test}).${n ? ` Note: ${n} skipped or focused test${n > 1 ? "s" : ""} already exist.` : ""}` });
  }
  if (existsSync(join(root, "package.json"))) s.push({ id: "ask-deps", kind: "deps", text: "Ask me before adding a new package.", why: "Suggested because the project has a package.json. Agents often add packages, or invent ones that don't exist." });

  const logger = has(/(^|\/)(lib|utils?|src)\/(log|logger|logging)\.[jt]s$/);
  if (logger) {
    const n = uses(all, /console\.log\(/, /^(src|app|lib)\//);
    if (n < 5) s.push({ id: "use-logger", kind: "avoid", pattern: "console\\.log\\(", in: "src/**, app/**, lib/**", text: `Use the logger in ${logger}, not console.log.`, why: `Suggested because ${logger} exists${n ? ` (console.log is used ${n} time${n > 1 ? "s" : ""} today)` : ""}.` });
  }
  const cols = Object.entries(p.colors);
  if (cols.length >= 2) s.push({ id: "brand-colours", kind: "note", text: `Use the brand colours (${cols.slice(0, 6).map(([h, n]) => `${n} ${h}`).join(", ")}), not new ones.`, why: "Suggested because the project defines these colours. Drift Guard already flags brand-new colours." });
  const comps = Object.keys(p.components);
  if (comps.length >= 2) s.push({ id: "reuse-components", kind: "note", text: `Reuse the existing components (${comps.slice(0, 8).join(", ")}${comps.length > 8 ? " and more" : ""}) instead of making new ones that do the same thing.`, why: `Suggested because the project has ${comps.length} components.` });
  if (p.content.length) s.push({ id: "real-copy", kind: "note", text: `Use the real quotes, names and copy from ${p.content.slice(0, 3).join(", ")}. Never invent them.`, why: "Suggested because the project keeps content in these files." });
  const wf = has(/^\.github\/workflows\/[^/]+\.ya?ml$/);
  if (wf) s.push({ id: "protect-ci", kind: "protect", paths: ".github/workflows/**", text: "Don't change the CI workflows unless I ask.", why: "Suggested because the project has GitHub workflows. Changes there can leak secrets or skip checks." });
  // The files that tell agents and reviewers what to do. A change there changes what every later check looks for.
  const setters = [["CLAUDE.md", /(^|\/)CLAUDE\.md$/], ["AGENTS.md", /(^|\/)AGENTS\.md$/], ["REVIEW.md", /(^|\/)REVIEW\.md$/], ["CODEOWNERS", /(^|\/)CODEOWNERS$/]].filter(([, re]) => has(re)).map(([n]) => n);
  const claudeDir = existsSync(join(root, ".claude")); // dot folders are not in the file list
  if (setters.length || claudeDir) s.push({ id: "protect-rule-files", kind: "protect", paths: [...setters.flatMap((n) => [n, `**/${n}`]), ...(claudeDir ? [".claude/**"] : [])].join(", "), text: "Don't change the files that set the rules for agents and reviews unless I ask.", why: `Suggested because the project has ${[...setters, ...(claudeDir ? [".claude/"] : [])].join(", ")}. A change there changes what every later check looks for.` });
  const gen = has(/(^|\/)(generated|__generated__)\/|\.gen\.[jt]s$/);
  if (gen) s.push({ id: "protect-generated", kind: "protect", paths: gen.includes("generated/") ? `${gen.slice(0, gen.indexOf("generated/") + 10)}**` : "**/*.gen.*", text: "Don't edit generated files by hand. Change the source and regenerate.", why: `Suggested because ${gen} looks generated.` });
  const env = has(/(^|\/)\.env(\.example|\.sample)?$/);
  if (env || paths.some((x) => /\.env/.test(x))) s.push({ id: "no-secrets", kind: "avoid", pattern: "(sk_live_|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY)", text: "Never put keys or passwords in the code. Read them from environment variables.", why: "Suggested because the project uses environment files." });

  // Drop what the rules file already has.
  const have = fileRules(root), same = (a, b) => a.kind === b.kind && (a.pattern || "") === (b.pattern || "") && (a.paths || "") === (b.paths || "") && (a.kind !== "note" || a.text === b.text);
  return s.filter((x) => !have.some((h) => same(h, x))).slice(0, 10);
}

/** Dry run: what a rule would match in this repo today, before it is written. Matched text is shown cut short, so a key
 *  the code already holds isn't copied in full into the conversation. Pure apart from reading files. */
// The scan runs in a worker that is stopped after 3 seconds, so even a pattern that is slow on a single line ends.
const SCAN = `
const { parentPort, workerData: w } = require("node:worker_threads");
const re = new RegExp(w.pattern, "i");
for (const f of w.files) {
  f.text.split("\\n").forEach((line, i) => { const m = line.slice(0, w.max).match(re); if (m) parentPort.postMessage({ at: f.p + ":" + (i + 1), match: m[0].length > 12 ? m[0].slice(0, 6) + "…" : m[0] }); });
  parentPort.postMessage({ file: true });
}
parentPort.postMessage({ done: true });`;
function scanInWorker(pattern, list, ms = 3000) {
  return new Promise((resolve) => {
    const hits = []; let scanned = 0, w, timer;
    const end = (partial) => { clearTimeout(timer); w?.terminate().catch(() => {}); resolve({ hits, scanned, partial }); };
    try { w = new Worker(SCAN, { eval: true, workerData: { pattern, files: list, max: MAX_LINE } }); } catch { return resolve({ hits, scanned, partial: true }); }
    timer = setTimeout(() => end(true), ms);
    w.on("message", (m) => { if (m.done) end(false); else if (m.file) scanned++; else hits.push(m); });
    w.on("error", () => end(true));
  });
}
async function tryRule(r) {
  const all = files(), inScope = (p) => (!r.in && !r.paths) || globMatch(p, r.kind === "protect" ? r.paths : r.in), out = (p) => !!r.except && globMatch(p, r.except);
  if (r.kind === "avoid") {
    const safe = safePattern(r.pattern, "i");
    if (safe.error) return { ok: false, says: safe.error };
    const list = []; let tooBig = 0;
    for (const f of all) {
      const p = rel(f);
      if (!/\.(m?[jt]sx?|cjs|astro|vue|svelte|py|rb|go|java|kt|php|html|ya?ml|json|toml|env|sh|sql|md)$|(^|\/)\.env/.test(p) || !inScope(p) || out(p)) continue;
      try { if (statSync(f).size > 300_000) { tooBig++; continue; } list.push({ p, text: readFileSync(f, "utf8") }); } catch { tooBig++; }
    }
    const { hits, scanned, partial } = await scanInWorker(r.pattern, list);
    const notRead = tooBig ? ` ${tooBig} file${tooBig > 1 ? "s were" : " was"} not read (over 300 KB or unreadable), so no match there means not checked.` : "";
    const more = partial ? ` It stopped after 3 seconds (${scanned} of ${list.length} files read), so there may be more. If that's on a small repo, the pattern is too slow: simplify it.` : "";
    return { ok: true, kind: "avoid", scanned, notRead: tooBig, partial, hits: hits.length, sample: hits.slice(0, 12),
      says: (hits.length ? `Matches ${hits.length} line${hits.length > 1 ? "s" : ""} in ${scanned} files already. The guard checks new edits, so these won't be flagged, but if this list is long the pattern is probably too broad.` : `Matches nothing in the ${scanned} files it covers today. New code that matches will be flagged.`) + more + notRead };
  }
  if (r.kind === "protect") {
    const hit = all.map(rel).filter(inScope).filter((p) => !out(p));
    return { ok: true, kind: "protect", files: hit.length, sample: hit.slice(0, 12), says: hit.length ? `Protects ${hit.length} existing file${hit.length > 1 ? "s" : ""}. New files there are still allowed.` : "No files match these paths yet. Check the paths are right." };
  }
  if (r.kind === "deps") return { ok: true, kind: "deps", says: existsSync(join(root, "package.json")) || existsSync(join(root, "requirements.txt")) || existsSync(join(root, "pyproject.toml")) ? "Will ask before a new package is added." : "This project has no package file yet, so there's nothing to check until it does." };
  return { ok: true, kind: "note", says: "A note can't be tried: nothing in the code shows whether it was followed. The agent sees it as a reminder." };
}

// YAML writing: append to the end of the rules: block, keep everything else exactly as it is.
const q = (v) => JSON.stringify(String(v));
function item(r) {
  const lines = [];
  const ex = r.except ? [`    except: ${q(r.except)}`] : [];
  if (r.kind === "avoid") lines.push(`  - avoid: ${q(r.pattern)}`, `    say: ${q(r.text)}`, ...(r.in ? [`    in: ${q(r.in)}`] : []), ...ex);
  else if (r.kind === "protect") lines.push(`  - protect: ${q(r.paths)}`, `    say: ${q(r.text)}`, ...ex);
  else if (r.kind === "deps") lines.push(`  - deps: ask`, `    say: ${q(r.text)}`);
  else lines.push(`  - note: ${q(r.text)}`, ...(r.when ? [`    when: ${q(r.when)}`] : []));
  return lines;
}
function write(list) {
  const ok = list.filter((r) => ["avoid", "protect", "deps", "note"].includes(r.kind) && r.text && (r.kind !== "avoid" || r.pattern) && (r.kind !== "protect" || r.paths));
  for (const r of ok) if (r.kind === "avoid") { const s = safePattern(r.pattern); if (s.error) { console.log(`Skipped "${r.text}": ${s.error}`); r.skip = true; } }
  const add = ok.filter((r) => !r.skip);
  if (!add.length) { console.log("Nothing to add."); return; }
  const before = fileRules(root).length;
  let src = existsSync(FILE) ? readFileSync(FILE, "utf8") : "# Project rules for AI agents. Lintsure Drift Guard holds every agent to these.\nrules:\n";
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  let start = lines.findIndex((l) => /^rules:\s*$/.test(l));
  if (start < 0) { if (lines.at(-1) === "") lines.pop(); lines.push("rules:"); start = lines.length - 1; }
  let end = start + 1;
  while (end < lines.length && !/^\S/.test(lines[end])) end++;
  while (end - 1 > start && lines[end - 1].trim() === "") end--; // keep blank lines after the block
  lines.splice(end, 0, ...add.flatMap(item));
  mkdirSync(join(root, ".lintsure"), { recursive: true });
  writeFileSync(FILE, lines.join("\n").replace(/\n*$/, "\n"));
  const after = fileRules(root);
  if (after.length !== before + add.length) { writeFileSync(FILE, src); console.log("Couldn't add the rules safely, so the file was left as it was."); process.exitCode = 1; return; }
  console.log(`Added ${add.length} rule${add.length > 1 ? "s" : ""} to .lintsure/rules.yml:`);
  for (const r of add) console.log(`- ${r.text}`);
  // Files that already carry the rules stay in step; nothing new is created without "sync".
  const keep = synced(root);
  if (keep.length) { const r = sync(root, keep); console.log(`Updated the rules in: ${r.written.join(", ")}.`); }
}

const [cmd, rawArg] = process.argv.slice(2);
// JSON can come from a file (@rule.json): some shells eat the backslashes in a pattern passed inline.
const arg = rawArg?.startsWith("@") ? readFileSync(rawArg.slice(1), "utf8") : rawArg;
/** A pattern with control characters lost its backslashes on the way in (\b became a backspace). */
const mangled = (r) => r.kind === "avoid" && /[\x00-\x1f]/.test(r.pattern || "");
const MANGLED = "The pattern arrived with control characters, so the shell ate its backslashes (\\b turned into a backspace). Write the JSON to a file and pass it as @file.json.";
if (cmd === "suggest") {
  const s = suggest();
  if (!s.length) console.log("No suggestions: the rules file already covers what Lintsure can see in this project.");
  else { s.forEach((x, i) => console.log(`${i + 1}. ${x.text}\n   ${x.why}`)); console.log(`\nJSON: ${JSON.stringify(s)}`); }
} else if (cmd === "write") {
  let list; try { list = JSON.parse(arg || "[]"); } catch { console.log("Pass the rules as one JSON array."); process.exit(1); }
  list = Array.isArray(list) ? list : [list];
  if (list.some(mangled)) { console.log(MANGLED); process.exit(1); }
  write(list);
} else if (cmd === "try") {
  let r; try { r = JSON.parse(arg || "{}"); } catch { console.log("Pass one rule as JSON: {kind, text, pattern?, in?, paths?, except?}"); process.exit(1); }
  if (mangled(r)) { console.log(MANGLED); process.exit(1); }
  const t = await tryRule(r);
  console.log(t.says);
  if (t.sample?.length) console.log(t.sample.map((s) => `- ${typeof s === "string" ? s : `${s.at}  ${s.match}`}`).join("\n") + ((t.hits ?? t.files) > t.sample.length ? `\n- and ${(t.hits ?? t.files) - t.sample.length} more` : ""));
  console.log(`\nJSON: ${JSON.stringify(t)}`);
} else if (cmd === "list") {
  const r = fileRules(root);
  console.log(r.length ? r.map((x) => `- ${x.text}${x.kind === "protect" ? ` (protects ${x.paths})` : ""}`).join("\n") : "No rules file yet.");
} else if (cmd === "sync") {
  const r = sync(root, arg ? arg.split(",").map((x) => x.trim()) : null);
  console.log(r.note ?? `Wrote the project rules to:\n${r.written.map((w) => `- ${w}`).join("\n")}\nYour own text in those files was left as it was.`);
} else if (cmd === "unsync") {
  const d = unsync(root);
  console.log(d.length ? `Took the Lintsure rules out of: ${d.join(", ")}.` : "No Lintsure rules found in other agents' files.");
} else console.log("Use: suggest | try '<json>' | write '<json>' | list | sync [targets] | unsync");
