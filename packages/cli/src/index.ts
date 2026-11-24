#!/usr/bin/env node
// npx lintsure scan [path] [options]      npx lintsure baseline [path]
// Writes reports into the current folder. Never sends anything over the network.
import { execFileSync } from "node:child_process";
import { constants, existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { access, copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { AGENTS, CONNECT_NOTE, MANUAL, detected, status, pick, plan, setup, undo } from "./agents.js";
import { parseActivity, toOtlp } from "./otel.js";
import { ALL_FRAMEWORKS, BASELINE_FILE, DISCLAIMER, RULES_VERSION, classify, isHygiene, isNonShipping, isOpen, nextSteps, readConfig, scan, toAssessmentHtml, toBaseline, toMarkdown, toSarif, type FrameworkId } from "@lintsure/core";

import { choose, chooseMany } from "./menu.js";
import { installSkills, removeSkills, skillFolders, skills } from "./skills.js";

// The old Windows console can't draw block, line or diamond characters reliably, so it gets plain ones.
const legacy = (env = process.env) => process.platform === "win32" && !env.WT_SESSION && !env.TERM_PROGRAM && !env.ConEmuANSI && !env.FORCE_COLOR;
// Brand colours: the logo blue for names and choices, gold for the rail that ties the steps of one task together.
const BLUE = "38;2;98;137;254", GOLD = "38;2;224;176;64";
// A badge: dark text on the logo blue. Without colour the same words stand as they are.
const BADGE = "48;2;98;137;254;38;2;16;24;48";
const tint = (code: string, s: string) => ((process.stdout.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR && process.env.TERM !== "dumb" ? `\x1b[${code}m${s}\x1b[0m` : s);
/** One step of a task: a marked title, then its lines hung on a rail, so a screen reads as a sequence of steps. */
const step = (title: string, body: string[] = []) => { const rail = tint(GOLD, legacy() ? "|" : "│"); console.log([`${tint(GOLD, legacy() ? "*" : "◇")}  ${title}`, ...body.map((b) => `${rail}  ${b}`), rail].join("\n")); };

/** The Prism in half-block characters, to the proportions of the brand mark: four heavy bands with narrow gaps, a solid
 *  tip, and the bottom band split into a long piece and a square. Each character holds two square pixels; `band` and
 *  `gap` are heights in those pixels. Pure. */
function prism(band = 6, gap = 2): string[] {
  const SLOPE = 0.56, height = 4 * band + 3 * gap, half = Math.ceil(SLOPE * height);
  const on = (c: number, h: number) => {
    if (h % (band + gap) >= band || Math.abs(c - half) > SLOPE * (h + 1)) return false; // a gap, or outside the slope
    if (h < 3 * band + 3 * gap) return true;
    const at = (c - half + SLOPE * height) / (2 * SLOPE * height); // bottom band: long piece, gap, square
    return at <= 0.6 || (at >= 0.72 && at <= 0.9);
  };
  return Array.from({ length: height / 2 }, (_, r) => Array.from({ length: 2 * half + 1 }, (_, c) => { const t = on(c, 2 * r), b = on(c, 2 * r + 1); return t && b ? "█" : t ? "▀" : b ? "▄" : " "; }).join(""));
}
/** Start screen for a person at a terminal: the Prism in brand green beside the name, version and first commands.
 *  NO_COLOR is respected; the old Windows console, which can't draw the blocks, gets the name and version only. */
function banner(env = process.env): string {
  if (legacy(env)) return `Lintsure ${RULES_VERSION}\n`;
  const color = !env.NO_COLOR && env.TERM !== "dumb";
  const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const text = [`${paint("38;2;98;137;254", "Lintsure")}${paint("2", `  ${RULES_VERSION}`)}`, "", paint("2", "Everything stays on this machine.")];
  const mark = prism(), width = Math.max(...mark.map((l) => l.length)), top = Math.floor((mark.length - text.length) / 2);
  return "\n" + mark.map((l, i) => (paint("38;2;98;137;254", l.padEnd(width)) + "    " + (text[i - top] ?? "")).trimEnd()).join("\n") + "\n";
}

// Files and folders that mark the top of a software project, in any of the common stacks.
const PROJECT_MARKERS = [".git", "package.json", "pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json", "pubspec.yaml", "Package.swift", "deno.json", "Dockerfile", "docker-compose.yml", "compose.yaml", "lintsure.config.yaml", ".lintsure"];
const isWholeDisk = (dir: string) => dir === homedir() || dirname(dir) === dir; // the home folder or a drive root
/** Whether a folder is a software project or sits inside one: a marker file in the folder itself, or a git repository
 *  around it. Folders above count only through .git, because a stray package.json in a temp or documents folder is
 *  common. The home folder and a drive root never count. */
export const looksLikeProject = (dir: string): boolean => projectSign(dir) !== null;
/** What shows that a folder is a project, in words for a person, or null when nothing does. */
function projectSign(dir: string): string | null {
  if (isWholeDisk(dir)) return null;
  const marker = PROJECT_MARKERS.find((m) => existsSync(join(dir, m)));
  if (marker) return marker === ".git" ? "a git repository" : `it has ${marker}`;
  for (let at = dirname(dir); !isWholeDisk(at); at = dirname(at)) if (existsSync(join(at, ".git"))) return `inside the git repository ${basename(at)}`;
  return null;
}
// Files that say "a project starts here". A git folder, a Lintsure folder or a Dockerfile can sit above several projects.
const MANIFESTS = PROJECT_MARKERS.filter((m) => ![".git", ".lintsure", "lintsure.config.yaml", "Dockerfile", "docker-compose.yml", "compose.yaml"].includes(m));
/** The projects directly inside a folder that is not one itself: a workspace. Empty for a normal project. */
export function subProjects(dir: string): string[] {
  if (MANIFESTS.some((m) => existsSync(join(dir, m)))) return [];
  try { return readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules" && [...MANIFESTS, ".git"].some((m) => existsSync(join(dir, e.name, m)))).map((e) => e.name); }
  catch { return []; }
}
/** The folder and whether a project was found in it, as one step. */
function showFolder(title: string, dir: string): void {
  const sign = projectSign(dir);
  step(`${title}  ${tint(BLUE, basename(dir) || dir)}`, [tint("2", dir), subProjects(dir).length > 1 ? tint(GOLD, `A workspace: ${subProjects(dir).length} projects inside`) : sign ? `${tint("32", "Project found")}: ${sign}` : tint(GOLD, "No project found here")]);
}
/** Asks a person for their project folder. Returns its full path, "" for Enter alone (use this folder), or null to stop.
 *  A pasted path may carry quotes, and ~ stands for the home folder. Only call this at a terminal. */
async function askFolder(allowHere: boolean): Promise<string | null> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (let tries = 0; tries < 3; tries++) {
      const typed = (await rl.question(`Type or paste the path to your project folder, then press Enter.\n${allowHere ? "Enter alone checks this folder anyway. " : ""}q stops.\n> `)).trim().replace(/^["']|["']$/g, "");
      if (typed.toLowerCase() === "q") return null;
      if (!typed) { if (allowHere) return ""; console.log("That would check every file you have. Name one project folder.\n"); continue; }
      const full = resolve(typed.replace(/^~(?=$|[\\/])/, homedir()));
      if (existsSync(full) && statSync(full).isDirectory()) { console.log(`\n${tint("32", "Found")} ${full}${looksLikeProject(full) ? "" : "\nIt doesn't look like a project, so Lintsure checks the folder as it is."}`); return full; }
      console.log(`${tint(GOLD, "Not found:")} no folder at ${full}. Check the path and try again.\n`);
    }
    console.log("Stopped. When you have the path, run: lintsure scan <folder>");
    return null;
  } finally { rl.close(); }
}

// What the start menu offers, in the order a new user needs them. `run` is the command line it stands for.
const START: { label: string; run: string[] | null; show?: string; badge?: boolean }[] = [
  { label: "Check this folder", run: ["scan"] },
  // `show` is the command to learn; the menu itself asks for the folder with --pick.
  { label: "Check another folder", run: ["scan", "--pick"], show: "scan <folder>" },
  { label: "Is everything set up?", run: ["status"] },
  { label: "Connect your coding agent", run: ["setup"] },
  { label: "Give your agent skills", run: ["skills"], badge: true },
  { label: "Every command and option", run: ["--help"] },
  { label: "Quit", run: null },
];
// True once a command was picked from the start menu: that person is using menus, so every command ends with one too.
let viaMenu = false;
let sawMenu = false;   // the command that just ran ended with its own menu
let wantsMenu = false; // the person chose "Main menu"
const HINT = "    Up and Down to move, Enter to run, q to quit";
/** The menu a command ends with when it was started from the start menu: what fits next, then the way back.
 *  Returns the exit code of the command it ran, or undefined when nothing was run (Main menu or Quit). */
async function offer(rows: { text: string; run: string[] | (() => Promise<void>) }[], color: boolean): Promise<number | undefined> {
  sawMenu = true;
  for (;;) {
    const pick = await choose([...rows.map((r) => r.text), "Main menu", "Quit"], HINT, color);
    if (pick === rows.length) wantsMenu = true;
    if (pick === null || pick >= rows.length) return undefined;
    const run = rows[pick].run;
    // A row that only shows something comes back to this menu afterwards.
    if (typeof run === "function") { await run(); console.log(""); continue; }
    sawMenu = false; // the command run next gets its own ending
    return main(run);
  }
}
const COMMANDS = ["scan", "baseline", "init", "info", "setup", "skills", "hook", "fix", "status", "export"];
/** The command someone most likely meant: the same word without dashes, or one within two typing slips. Pure. */
function nearest(word: string): string | undefined {
  const slips = (a: string, b: string) => { let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) { const next = [i]; for (let j = 1; j <= b.length; j++) next[j] = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); row = next; }
    return row[b.length]; };
  return COMMANDS.find((c) => c === word) ?? COMMANDS.map((c) => [slips(c, word), c] as const).filter(([n]) => n <= 2).sort((x, y) => x[0] - y[0])[0]?.[1];
}
const startRows = () => START.map((s) => { const row = s.run ? `${s.label.padEnd(28)}lintsure ${s.show ?? s.run.join(" ")}` : s.label; return s.badge ? tint(BADGE, row) : row; });

const HELP = `lintsure scan [path] [options]
lintsure baseline [path]
lintsure init [path]     Three questions, saved to lintsure.config.yaml
lintsure info [path]     Show the settings a scan would use, and where each comes from
lintsure setup [path]    Add the Lintsure MCP server to this project's agent configs
                         (shows the change; --yes writes it; --undo takes it out;
                         --agents claude,cursor,vscode,gemini,codex;
                         --manual for an agent set up in its own settings)
lintsure skills [path]   Add Lintsure's skills to this project: short instruction files that
                         tell your agent when to check code and how to handle findings
                         (at a terminal you pick which; --yes adds all; --only a,b;
                         --undo takes them out)
lintsure fix [path] [F-001 ...]  Apply the change for findings whose rule knows the exact one
                         (shows it first; --all includes held-back findings; --yes writes it,
                         backs the file up, scans again,
                         and puts the file back if the finding is still there)
lintsure hook [path]     Check the lines you commit: adds a git pre-commit hook that runs
                         lintsure scan --staged --fail-on gap (shows it first; --yes writes it;
                         --undo removes it; an existing hook of your own is left alone)
lintsure status [path]   Check that this project is ready: Node, config, rules, agents
lintsure export --otlp-json [path]  Write .lintsure/activity.jsonl as an OpenTelemetry
                         traces file (lintsure.otlp.json) for your own observability tool

scan options:
  --framework <ids>   Comma list: ${ALL_FRAMEWORKS.join(", ")}
                      (default: lintsure.config.yaml if present, else all)
  --all               Also list medium-confidence findings (held back by default)
  --diff <base>       Only list findings on lines changed since <base>, e.g. origin/main
  --staged            Only list findings on lines that are staged for the next commit
  --json              Also write lintsure-report.json
  --sarif             Also write lintsure.sarif (for GitHub code scanning and editors)
  --report            Also write lintsure-assessment.html, a multi-page report
                      to review, print or save as PDF
  --project <name>    Project name on the assessment cover (default: folder name)
  --fail-on <status>  Exit 1 if any open finding is "gap" or "partial" (for CI). Held-back
                      medium-confidence findings count only with --all
  --new-only          With --fail-on: count only findings that are new since
                      .lintsure/baseline.json
  --github            Print GitHub Actions annotations, so findings show on the lines
  --pick              Ask which folder to check (at a terminal)
  --save-record       Also save this run's readiness check record to
                      .lintsure/records/<id>.json, building a dated history (no code inside)

baseline:
  Saves the current open findings to .lintsure/baseline.json in the scanned folder.
  Later scans show what is new, fixed or unchanged. The file holds rule ids, file
  paths and one-way fingerprints, never code. You decide whether to commit it.

Accept a finding after review by adding it to .lintsure/accepted.yaml, with the
fingerprint from lintsure-report.json, your reason, your name and the date.

${DISCLAIMER}
Lintsure never sends your code anywhere.`;

const VALUE_FLAGS = ["--framework", "--fail-on", "--project", "--diff"];
const BOOL_FLAGS = ["--json", "--sarif", "--report", "--new-only", "--github", "--save-record", "--all", "--pick", "--staged"];

/** Changed line numbers per file from `git diff -U0` output. Pure. */
export function parseDiff(text: string): Record<string, number[]> {
  const out: Record<string, number[]> = {}; let file: string | null = null;
  for (const l of text.split(/\r?\n/)) {
    // Git ends a path with a space in it with a tab, and quotes paths it escapes; run with core.quotePath=false too.
    if (l.startsWith("+++ ")) { file = l === "+++ /dev/null" ? null : l.slice(4).replace(/\t$/, "").replace(/^"(.*)"$/, "$1").replace(/^b\//, ""); continue; }
    const h = file && l.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/);
    if (h) { const start = +h[1], n = h[2] === undefined ? 1 : +h[2]; for (let i = 0; i < n; i++) (out[file!] ??= []).push(start + i); }
  }
  return out;
}

const FRAMEWORK_NAMES: Record<string, string> = { "owasp-top10": "OWASP Top 10", "cwe-top25": "CWE Top 25", gdpr: "GDPR", "eu-ai-act": "EU AI Act", "owasp-llm": "OWASP Top 10 for LLM apps", "owasp-ast": "OWASP Agentic Skills Top 10", "owasp-api": "OWASP API Security Top 10", cra: "EU Cyber Resilience Act" };

/** First-run setup: three questions, saved once, never asked in CI. */
async function init(path: string): Promise<number> {
  const file = join(path, "lintsure.config.yaml");
  if (await access(file).then(() => true, () => false)) { console.error("lintsure.config.yaml already exists. Edit it, or delete it and run init again."); return 2; }
  if (!process.stdin.isTTY || process.env.CI) { console.error("init asks questions, so it needs a terminal. In CI, commit a lintsure.config.yaml instead."); return 2; }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const pick = async (q: string, options: string[]) => {
    console.log(`\n${q}`); options.forEach((o, i) => console.log(`  ${i + 1}. ${o}`));
    for (;;) { const a = Number((await rl.question("> ")).trim() || "1"); if (a >= 1 && a <= options.length) return a; console.log(`Type a number from 1 to ${options.length}.`); }
  };
  console.log("Lintsure setup: 3 questions. Press Enter for the first answer.");
  const what = await pick("1. What should Lintsure check?", ["Security only (OWASP Top 10, CWE Top 25)", "Security and privacy (adds GDPR)", "Everything (all eight frameworks)", "Let me pick"]);
  let chosen: string[] = what === 1 ? ["owasp-top10", "cwe-top25"] : what === 2 ? ["owasp-top10", "cwe-top25", "gdpr"] : [...ALL_FRAMEWORKS];
  if (what === 4) {
    console.log("\nType the numbers you want, separated by commas, or press Enter for all:");
    ALL_FRAMEWORKS.forEach((f, i) => console.log(`  ${i + 1}. ${FRAMEWORK_NAMES[f] ?? f}`));
    const a = (await rl.question("> ")).trim();
    chosen = a ? a.split(",").map((x) => ALL_FRAMEWORKS[Number(x.trim()) - 1]).filter(Boolean) : [...ALL_FRAMEWORKS];
  }
  const why: string[] = [];
  if (what !== 3 && what !== 4) {
    const ai = (await pick("2. Does your app use AI (chat, generated text or images)?", ["Yes", "No"])) === 1;
    const eu = (await pick("3. Do you have, or plan to have, users in the EU?", ["Yes", "No or not sure"])) === 1;
    for (const c of classify({ usesAI: ai, generativeAI: ai, interactsWithPeople: ai, euUsers: eu, personalData: eu }))
      if (!chosen.includes(c.framework)) { chosen.push(c.framework); why.push(`${FRAMEWORK_NAMES[c.framework] ?? c.framework}: ${c.reason}`); }
  }
  rl.close();
  if (!chosen.length) chosen = [...ALL_FRAMEWORKS];
  await writeFile(file, `# Written by lintsure init. Edit freely; run "lintsure info" to check it.\nframeworks:\n${chosen.map((f) => `  - ${f}`).join("\n")}\n`);
  console.log(`\nSaved lintsure.config.yaml with: ${chosen.map((f) => FRAMEWORK_NAMES[f] ?? f).join(", ")}.`);
  why.forEach((w) => console.log(`  Added ${w}`));
  console.log("CI and your teammates will use this file and never see the questions. Run init again after deleting it to change your answers.");
  return 0;
}

async function info(path: string): Promise<number> {
  const c = await readConfig(path);
  const from = await access(join(path, "lintsure.config.yaml")).then(() => "lintsure.config.yaml", () => "default (no lintsure.config.yaml)");
  console.log(`Settings for ${path}`);
  console.log(`  frameworks  ${(c.frameworks ?? ALL_FRAMEWORKS).join(", ")}  (${c.frameworks ? from : "default: all"})`);
  if (c.skipped.length) console.log(`  not checked yet  ${c.skipped.join(", ")}`);
  console.log(`  ignore      ${c.ignore.join(", ") || "-"}`);
  console.log(`  rules       ${Object.entries(c.rules).map(([k, v]) => `${k}: ${v}`).join(", ") || "-"}`);
  console.log(`  show        ${c.show === "all" ? "all findings" : "high confidence only (use --all or show: all for the rest)"}`);
  if (c.problems.length) { console.error("Problems in lintsure.config.yaml:"); c.problems.forEach((p) => console.error(`  ${p}`)); return 2; }
  return 0;
}
const FAIL_ON = ["gap", "partial"];

/** Splits --flag=value into two tokens and checks every flag, so a CI gate can't silently fail open
 *  because of a typo or a bad value (improvement review, P25). Returns an error message or the parsed args. Pure. */
export function parseArgs(argv: string[]): { rest: string[] } | { error: string } {
  const rest = argv.flatMap((a) => (a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a]));
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith("--")) continue;
    if (VALUE_FLAGS.includes(a)) {
      const v = rest[i + 1];
      if (v === undefined || v.startsWith("--")) return { error: `${a} needs a value.` };
      if (a === "--fail-on" && !FAIL_ON.includes(v.toLowerCase())) return { error: `--fail-on must be "gap" or "partial", not "${v}".` };
      i++; continue;
    }
    if (!BOOL_FLAGS.includes(a)) return { error: `Unknown option: ${a}. Run lintsure without arguments for help.` };
  }
  const positional = rest.filter((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1]));
  if (positional.length > 1) return { error: `Expected one folder to scan, got: ${positional.join(", ")}` };
  return { rest };
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...raw] = argv;
  if (cmd === "export") {
    if (!raw.includes("--otlp-json")) { console.error("Choose a format: lintsure export --otlp-json [path]"); return 2; }
    const root = resolve(raw.find((a) => !a.startsWith("--")) ?? ".");
    let text = ""; try { text = await readFile(join(root, ".lintsure", "activity.jsonl"), "utf8"); } catch { /* none yet */ }
    const rows = parseActivity(text);
    if (!rows.length) { console.error("No activity yet in .lintsure/activity.jsonl. The Lintsure plugin writes it while your agent works."); return 2; }
    await writeFile("lintsure.otlp.json", JSON.stringify(toOtlp(rows, RULES_VERSION), null, 2));
    console.log(`Wrote lintsure.otlp.json: ${rows.length} events. Nothing was sent; load the file into your collector or tool (OTLP/JSON).`);
    return 0;
  }
  // lintsure fix: applies a change only where the rule knows the exact one (a setting flipped, a line added). Everything
  // else needs judgement and stays a proposal. Shown first; --yes writes; each file is backed up; a change that does not
  // make its finding go away is put back.
  if (cmd === "fix") {
    const bad = raw.find((a) => a.startsWith("--") && a !== "--yes" && a !== "--all");
    if (bad) { console.error(`Unknown option: ${bad}. Use: lintsure fix [folder] [F-001 ...] [--all] [--yes]`); return 2; }
    const words = raw.filter((a) => !a.startsWith("--")), ids = words.filter((a) => /^F-\d+$/i.test(a)).map((a) => a.toUpperCase());
    const root = resolve(words.find((a) => !/^F-\d+$/i.test(a)) ?? ".");
    if (!existsSync(root)) { console.error(`No folder at ${root}.`); return 2; }
    const config = await readConfig(root);
    if (config.problems.length) { console.error("Problems in lintsure.config.yaml (fix them first):"); config.problems.forEach((p) => console.error(`  ${p}`)); return 2; }
    const frameworks = config.frameworks ?? ALL_FRAMEWORKS;
    // The same list the person saw: --all here when the scan was run with --all, so the finding numbers match.
    const opts = { source: "cli", all: raw.includes("--all") || undefined } as const;
    const before = await scan(root, frameworks, opts);
    const unknown = ids.filter((id) => !before.findings.some((f) => f.id === id));
    if (unknown.length) { console.error(`No finding ${unknown.join(", ")} in this scan. Numbers change when the code does: run lintsure scan again.`); return 2; }
    const wanted = before.findings.filter((f) => isOpen(f) && (!ids.length || ids.includes(f.id)));
    const exact = wanted.filter((f) => f.patch), rest = wanted.length - exact.length;
    for (const f of wanted.filter((x) => !x.patch && ids.includes(x.id))) console.log(`${f.id} has no exact change: its fix needs judgement. The proposal is in the report, or hand it to your coding agent.`);
    if (!exact.length) { console.log(`No finding here has an exact change Lintsure can apply.${rest ? ` ${rest} need a person or a coding agent: lintsure scan` : ""}`); return 0; }
    for (const f of exact) console.log(`${f.id}  ${f.title}\n    ${f.file}:${f.patch!.line}\n${f.patch!.old != null ? `    - ${f.patch!.old.trim()}\n` : ""}${f.patch!.text.replace(/\n$/, "").split("\n").map((t) => `    + ${t.trim()}`).join("\n")}\n`);
    if (!raw.includes("--yes")) {
      console.log(`Nothing changed yet. To apply ${exact.length === 1 ? "it" : `these ${exact.length}`}, run: lintsure fix${ids.length ? " " + ids.join(" ") : ""}${raw.includes("--all") ? " --all" : ""} --yes\nEach file is backed up first (<file>.lintsure-backup).${rest ? `\n${rest} other finding${rest === 1 ? " needs" : "s need"} a person or a coding agent.` : ""}`);
      if (viaMenu && process.stdin.isTTY && process.stdout.isTTY) { console.log(""); const ran = await offer([{ text: `${"Apply these changes".padEnd(54)}lintsure fix --yes`, run: ["fix", ...raw, "--yes"] }], !process.env.NO_COLOR && process.env.TERM !== "dumb"); if (ran !== undefined) return ran; }
      return 0;
    }
    const byFile = new Map<string, typeof exact>();
    for (const f of exact) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
    const originals = new Map<string, string>(), skipped: string[] = [];
    for (const [file, list] of byFile) {
      const path = join(root, file), text = await readFile(path, "utf8"), nl = text.includes("\r\n") ? "\r\n" : "\n", lines = text.split(/\r?\n/);
      // From the bottom up, so an inserted line does not move the ones still to change.
      for (const f of [...list].sort((a, b) => b.patch!.line - a.patch!.line)) {
        const p = f.patch!, at = p.line - 1, add = p.text.replace(/\n$/, "").split("\n");
        if (p.old == null) lines.splice(at, 0, ...add);
        else if (lines[at] === p.old) lines.splice(at, 1, ...add);
        else skipped.push(`${f.id}: ${file}:${p.line} changed since the scan, so it was left alone`);
      }
      const next = lines.join(nl);
      if (next === text) continue;
      // The first backup is the user's original: never overwritten by a later run.
      try { await copyFile(path, path + ".lintsure-backup", constants.COPYFILE_EXCL); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") { skipped.push(`${file}: could not be backed up, so it was left alone`); continue; } }
      originals.set(file, text);
      await writeFile(path, next);
    }
    // Proof: scan again. A file whose findings from these rules did not go down is put back as it was.
    const after = await scan(root, frameworks, opts);
    const count = (r: typeof before, ruleId: string, file: string) => r.findings.filter((f) => f.ruleId === ruleId && f.file === file).length;
    let fixed = 0;
    for (const [file, text] of originals) {
      const mine = byFile.get(file)!, worse = mine.some((f) => count(after, f.ruleId, file) >= count(before, f.ruleId, file));
      if (worse) { await writeFile(join(root, file), text); skipped.push(`${file}: the change did not clear its finding, so the file was put back`); }
      else { fixed += mine.length; console.log(`fixed  ${file}  (${mine.map((f) => f.id).join(", ")}; your original is in ${file}.lintsure-backup)`); }
    }
    skipped.forEach((s) => console.log(`left   ${s}`));
    console.log(`\n${fixed ? `Done! ${fixed} finding${fixed === 1 ? "" : "s"} fixed and checked again.` : "Nothing was changed."} Look at the change before you commit it: git diff`);
    return skipped.length && !fixed ? 1 : 0;
  }
  if (cmd === "hook") {
    const root = resolve(raw.find((a) => !a.startsWith("--")) ?? "."), file = join(root, ".git", "hooks", "pre-commit"), MARK = "# Added by lintsure hook";
    if (!existsSync(join(root, ".git"))) { console.error(`No git repository at ${root}. Run this in the folder that has .git.`); return 2; }
    const now = existsSync(file) ? await readFile(file, "utf8") : null;
    if (raw.includes("--undo")) {
      if (now?.includes(MARK)) { await rm(file); console.log("Removed the pre-commit hook."); }
      else console.log(now === null ? "No pre-commit hook here." : "The pre-commit hook here is not Lintsure's, so it was left alone.");
      return 0;
    }
    // Someone else's hook is never overwritten: say what to add to it.
    if (now !== null && !now.includes(MARK)) { console.error("This repository already has a pre-commit hook of its own. Add this line to it:\n    lintsure scan --staged --fail-on gap"); return 2; }
    console.log(`- pre-commit hook: ${now === null ? "create" : "update"} .git/hooks/pre-commit\n    lintsure scan --staged --fail-on gap`);
    if (!raw.includes("--yes")) { console.log("\nNothing written yet. To apply, run: lintsure hook --yes"); return 0; }
    await mkdir(join(root, ".git", "hooks"), { recursive: true });
    // Pinned to this version when the command is not installed: a moving version in a hook is what the supply-chain rules warn about.
    await writeFile(file, `#!/bin/sh\n${MARK}. Remove with: lintsure hook --undo\n# Checks only the lines being committed and stops the commit on a clear problem.\nif command -v lintsure >/dev/null 2>&1; then lintsure scan --staged --fail-on gap; else npx --yes lintsure@${RULES_VERSION} scan --staged --fail-on gap; fi\n`, { mode: 0o755 });
    console.log("\nWritten. Each commit now checks the lines being committed.\nSkip it once with: git commit --no-verify\nRemove it with: lintsure hook --undo");
    return 0;
  }
  if (cmd === "skills") {
    const root = resolve(raw.find((a, i) => !a.startsWith("--") && raw[i - 1] !== "--only") ?? ".");
    const bad = raw.find((a) => a.startsWith("--") && !["--yes", "--undo", "--only"].includes(a));
    if (bad) { console.error(`Unknown option: ${bad}. Use --yes, --only <names> or --undo.`); return 2; }
    if (!existsSync(root)) { console.error(`No folder at ${root}.`); return 2; }
    if (raw.includes("--undo")) { const said = await removeSkills(root); console.log(said.length ? said.join("\n") : "No Lintsure skills in this project."); return 0; }
    const all = skills(), i = raw.indexOf("--only"), names = i >= 0 ? (raw[i + 1] ?? "").split(",").map((s) => s.trim()) : undefined;
    const unknown = names?.filter((n) => !all.some((s) => s.name === n));
    if (unknown?.length) { console.error(`Unknown skill: ${unknown.join(", ")}. Choose from: ${all.map((s) => s.name).join(", ")}`); return 2; }
    let chosen = names ? all.filter((s) => names.includes(s.name)) : all;
    const folders = skillFolders(root), yes = raw.includes("--yes"), picking = !yes && !names && !!process.stdin.isTTY && !!process.stdout.isTTY;
    console.log("");
    step(tint(BADGE, " Lintsure skills "), ["A skill is a short instruction file. It tells your coding agent when to use Lintsure and what", "to do with what it finds. Connecting gives the agent the tools; skills give it the habit."]);
    showFolder("Project", root);
    step("Where they go", folders.map((f) => `${tint(BLUE, f)}  ${tint("2", f.startsWith(".agents") ? "read by Codex, Cursor, Gemini CLI and many others" : "read by Claude Code")}`));
    if (picking) {
      step(`Found ${all.length} skills. Which do you want?`);
      const width = Math.max(...all.map((s) => s.name.length)) + 2;
      const picked = await chooseMany(all.map((s) => `${s.name.padEnd(width)}${s.about}`), (n) => (n ? `Install the ${n} selected` : "Install (none selected yet)"), "    Up and Down to move, Enter to select or de-select, a for all, q to quit", !process.env.NO_COLOR && process.env.TERM !== "dumb");
      if (!picked?.length) { console.log("Nothing installed. Come back any time: lintsure skills"); return 0; }
      chosen = picked.map((n) => all[n]);
    }
    const apply = yes || picking;
    const steps = await installSkills(root, chosen, apply);
    const word = { add: apply ? "added" : "add", update: apply ? "updated, the earlier files kept as .lintsure-backup" : "update (the files there now are kept as backups)", same: "already there" };
    const lines = steps.map((s) => `${apply ? `${tint("32", "✓")} ` : ""}${s.folder}  ${tint("2", word[s.state])}`);
    if (!apply) { step(`Would install ${chosen.length} skill${chosen.length === 1 ? "" : "s"}`, lines); console.log(`Nothing written yet. To apply, run: lintsure skills ${names ? `--only ${names.join(",")} ` : ""}--yes`); return 0; }
    step(tint("32", `Done! Installed ${chosen.length} skill${chosen.length === 1 ? "" : "s"}`), lines);
    console.log("Restart the agent so it reads them. Take them out any time with: lintsure skills --undo");
    return 0;
  }
  if (cmd === "setup" || cmd === "status") {
    const root = resolve(raw.find((a, i) => !a.startsWith("--") && raw[i - 1] !== "--agents") ?? ".");
    if (cmd === "status") return status(root);
    if (raw.includes("--manual")) { console.log(MANUAL()); return 0; }
    const named = raw.includes("--agents"), here = named ? [] : await detected(root);
    // From the menu, ask which agent. Claude Code used to be the silent choice when the project had no agent folder yet.
    if (viaMenu && !named && !raw.includes("--yes") && !raw.includes("--undo") && process.stdin.isTTY && process.stdout.isTTY) {
      console.log("");
      step("Connect your coding agent", CONNECT_NOTE.split("\n"));
      showFolder("Project", root);
      step("Which agent?");
      const rows = AGENTS.map((a) => ({ text: `${a.name.padEnd(22)}${a.file.padEnd(24)}${here.includes(a) ? "used in this project" : ""}`.trimEnd(), run: ["setup", ...raw, "--agents", a.id] }));
      rows.push({ text: "Another agent (Devin, Windsurf, Zed, ...)", run: ["setup", ...raw, "--manual"] });
      if (here.length > 1) rows.unshift({ text: `All ${here.length} used in this project`, run: ["setup", ...raw, "--agents", here.map((a) => a.id).join(",")] });
      return (await offer(rows, !process.env.NO_COLOR && process.env.TERM !== "dumb")) ?? 0;
    }
    // Typed by hand with no agent named and none found here: say which one this is for, and how to pick another.
    if (!named && !here.length && !raw.includes("--undo")) console.log(`No agent folder in this project, so this is for Claude Code. For another one: lintsure setup --agents ${AGENTS.slice(1).map((a) => a.id).join(" | ")}\nFor an agent set up in its own settings (Devin, Windsurf, Zed): lintsure setup --manual\n`);
    const i = raw.indexOf("--agents");
    const agents = await pick(root, i >= 0 ? raw[i + 1]?.split(",").map((s) => s.trim()) : undefined);
    if (typeof agents === "string") { console.error(agents); return 2; }
    if (raw.includes("--undo")) return undo(root, agents);
    const code = await setup(root, agents, raw.includes("--yes"));
    // From the menu, the preview is followed by the choice to write it, so nobody has to retype the command with --yes.
    // Once the agent is connected, the next thing on offer is the skills that tell it when to use Lintsure.
    if (viaMenu && process.stdin.isTTY && process.stdout.isTTY) {
      const pending = !raw.includes("--yes") && (await Promise.all(agents.map((a) => plan(root, a)))).some((p) => p.text);
      const folder = raw.filter((a, i) => !a.startsWith("--") && raw[i - 1] !== "--agents").slice(0, 1);
      console.log("");
      const ran = await offer([pending ? { text: `${"Write these changes".padEnd(54)}lintsure setup --yes`, run: ["setup", ...raw, "--yes"] } : { text: `${"Install Lintsure's skills for your agent".padEnd(54)}lintsure skills`, run: ["skills", ...folder] }], !process.env.NO_COLOR && process.env.TERM !== "dumb");
      if (ran !== undefined) return ran;
    }
    return code;
  }
  if (cmd === "init" || cmd === "info") return (cmd === "init" ? init : info)(resolve(raw.find((a) => !a.startsWith("--")) ?? "."));
  // The start screen is for a person at a terminal. Piped output and CI logs stay exactly as they were.
  // With no command, a person at a terminal gets the start screen: a menu when keys can be read, a short list when
  // they can't. Piped output and CI logs get the full help text, exactly as before.
  if (!cmd && (process.stdout.isTTY || process.env.FORCE_COLOR)) {
    console.log(banner());
    if (!process.stdin.isTTY || !process.stdout.isTTY) { console.log(startRows().slice(0, -1).map((r) => `    ${r}`).join("\n") + "\n"); return 0; }
    // The menu is home. After each command the person can come back here, so no screen is a dead end.
    const color = !process.env.NO_COLOR && process.env.TERM !== "dumb";
    for (let code = 0; ;) {
      showFolder("You are in", process.cwd());
      const pick = await choose(startRows(), HINT, color);
      const run = pick === null ? null : START[pick].run;
      if (!run) return code;
      viaMenu = true; sawMenu = false; wantsMenu = false;
      code = await main(run);
      if (!sawMenu) await offer([], color); // a command with no menu of its own still ends with the way back
      if (!wantsMenu) return code;
      console.log(`\n${tint(BLUE, "Lintsure")} ${RULES_VERSION}\n`);
    }
  }
  if (cmd === "--version" || cmd === "-v") { console.log(RULES_VERSION); return 0; }
  if (cmd !== "scan" && cmd !== "baseline") {
    if (!cmd || ["--help", "-h", "help"].includes(cmd)) { console.log(HELP); return 0; }
    // A command typed with dashes (lintsure --scan) or misspelt: say what was meant, not the whole manual.
    const guess = nearest(cmd.replace(/^-+/, ""));
    console.error(`Unknown command: ${cmd}${guess ? `\nDid you mean: lintsure ${guess}` : ""}\nRun lintsure --help for every command and option.`);
    return 2;
  }
  const parsed = parseArgs(raw);
  if ("error" in parsed) { console.error(parsed.error); return 2; }
  const { rest } = parsed;
  const flag = (n: string) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
  const path = resolve(rest.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1])) ?? ".");
  const wanted = flag("--framework")?.split(",").map((s) => s.trim()) as FrameworkId[] | undefined;
  if (!existsSync(path)) { console.error(`No folder at ${path}. Pass the project folder to scan, for example: lintsure scan .`); return 2; }
  // No folder was named and this one isn't a project. Lintsure can't guess where the project is: at a terminal it asks,
  // elsewhere it says how to name it. A named folder is taken at its word.
  const namedFolder = rest.some((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1]));
  // --pick: ask for the folder. It is what "Check another folder" in the menu runs.
  if (rest.includes("--pick")) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) { console.error(`--pick asks a question, so it needs a terminal. Name the folder: lintsure ${cmd} <folder>`); return 2; }
    console.log("");
    const where = await askFolder(false);
    return where ? main([cmd, where, ...rest.filter((a) => a !== "--pick")]) : 0;
  }
  if (!namedFolder && !looksLikeProject(path)) {
    const why = `This folder doesn't look like a project: ${path}\nLintsure checks one project folder at a time, and it can't tell where yours is.`;
    if (process.stdin.isTTY && process.stdout.isTTY) {
      console.log(`\n${why}\n`);
      const where = await askFolder(!isWholeDisk(path));
      if (where === null) return 0;
      if (where) return main([cmd, where, ...rest]);
    } else {
      console.error(`${why}\nGo to your project folder first, or name it: lintsure ${cmd} <folder>`);
      if (isWholeDisk(path)) return 2; // a whole home folder or drive is never what was meant
    }
  }

  // A folder that holds several projects is a workspace: one scan would mix their findings together.
  const inside = subProjects(path);
  if (inside.length > 1) {
    if (viaMenu && process.stdin.isTTY && process.stdout.isTTY) {
      console.log("");
      step(`This folder holds ${inside.length} projects. Which one?`);
      const pick = await choose([...inside, "All of them together", "Back"], HINT, !process.env.NO_COLOR && process.env.TERM !== "dumb");
      if (pick === null || pick > inside.length) return 0;
      if (pick < inside.length) { const named = rest.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1])); return main([cmd, join(path, inside[pick]), ...rest.filter((a) => a !== named)]); }
    } else console.error(`This folder holds ${inside.length} projects (${inside.slice(0, 5).join(", ")}${inside.length > 5 ? ", ..." : ""}), so their findings are mixed together below.\nTo check one: lintsure ${cmd} <folder>`);
  }
  const config = await readConfig(path);
  // Checked after the config loads its rule packs, so a pack's framework id is accepted.
  const bad = wanted?.filter((f) => !ALL_FRAMEWORKS.includes(f));
  if (bad?.length) { console.error(`Unknown framework: ${bad.join(", ")}\nChoose from: ${ALL_FRAMEWORKS.join(", ")}`); return 2; }
  if (config.problems.length) { console.error("Problems in lintsure.config.yaml (fix them so the scan checks what you meant):"); config.problems.forEach((p) => console.error(`  ${p}`)); return 2; }
  if (!wanted && config.skipped.length) console.log(`Skipping, not checked yet: ${config.skipped.join(", ")}`);
  const why = wanted ? "Chosen with --framework on the command line." : config.frameworks ? "Listed in lintsure.config.yaml." : undefined;
  const source = process.env.GITHUB_ACTIONS || process.env.CI ? "ci" : "cli";
  const base = flag("--diff"), staged = rest.includes("--staged");
  let changed: { base: string; lines: Record<string, number[]> } | undefined;
  if (base || staged) {
    try { changed = { base: base ?? "your last commit (staged changes only)", lines: parseDiff(execFileSync("git", ["-c", "core.quotePath=false", "diff", "-U0", "--no-color", "--no-ext-diff", "--relative", ...(base ? [base] : ["--cached"]), "--"], { cwd: path, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 << 20 })) }; }
    catch { if (!base) { console.error("--staged needs a git repository, and this folder is not inside one."); return 2; } console.error(`--diff: git could not compare with "${base}".\nCheck that this folder is inside a git repository and that "${base}" exists here (for example: git fetch origin main).`); return 2; }
  }
  // LINTSURE_WORKSPACE_RULES: path to a JSON file of account rules the caller already has (the plugin writes it).
  // Read only to hash into the policy fingerprint; the CLI never fetches them. A file it can't read is an error, not a silent skip.
  let workspaceRules: unknown;
  const wsFile = process.env.LINTSURE_WORKSPACE_RULES;
  if (wsFile) {
    try { workspaceRules = JSON.parse(await readFile(wsFile, "utf8")); }
    catch { console.error(`Couldn't read workspace rules from LINTSURE_WORKSPACE_RULES (${wsFile}).`); process.exit(2); }
  }
  // A large project takes a few seconds: say that work has started, so the screen isn't blank.
  if (process.stdout.isTTY) { console.log(""); showFolder(`${tint(BLUE, "Lintsure")} is checking`, path); }
  const report = await scan(path, wanted ?? config.frameworks ?? ALL_FRAMEWORKS, { why, source, all: rest.includes("--all") || undefined, changed, workspaceRules });
  const date = new Date().toISOString().slice(0, 10);

  if (cmd === "baseline") {
    const file = join(path, BASELINE_FILE);
    await mkdir(dirname(file), { recursive: true });
    const b = toBaseline(report, date);
    await writeFile(file, JSON.stringify(b, null, 2) + "\n");
    console.log(`Saved ${b.findings.length} open finding${b.findings.length === 1 ? "" : "s"} to ${BASELINE_FILE}.`);
    console.log("Later scans will show what is new, fixed or unchanged. The file contains no code; commit it if your team and CI should share it.");
    return 0;
  }

  await writeFile("lintsure-report.md", toMarkdown(report));
  if (rest.includes("--json")) await writeFile("lintsure-report.json", JSON.stringify(report, null, 2));
  if (rest.includes("--sarif")) await writeFile("lintsure.sarif", JSON.stringify(toSarif(report, RULES_VERSION), null, 2));
  if (rest.includes("--save-record") && report.record) {
    const file = join(path, ".lintsure", "records", `${report.record.id}.json`);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ record: report.record, findings: report.findings.map(({ id, ruleId, file, line, status, severity, fingerprint, change, accepted }) => ({ id, ruleId, file, line, status, severity, fingerprint, change, accepted })) }, null, 2) + "\n");
    console.log(`Record saved to .lintsure/records/${report.record.id}.json (no code inside).`);
  }
  if (rest.includes("--report")) await writeFile("lintsure-assessment.html", toAssessmentHtml(report, { project: flag("--project") ?? basename(path), date }));

  const open = report.findings.filter(isOpen);
  const n = (s: string) => open.filter((f) => f.status === s).length;
  const accepted = report.findings.length - open.length;
  const hygiene = open.filter(isHygiene).length;
  if (report.record) console.log(`Record ${report.record.id} · ${report.record.createdAt.replace("T", " ").slice(0, 16)} UTC · ${report.record.counts.checkPoints} check points${report.policy ? ` · Policy #${report.policy.fingerprint}` : ""}`);
  // A check mark only when nothing is open: "✓ 3 gaps" read as a pass.
  console.log(`${open.length ? "!" : "✓"} ${open.length} open findings${hygiene ? ` (${open.length - hygiene} in the code, ${hygiene} repo hygiene)` : ""} · ${n("gap")} gap · ${n("partial")} partial${accepted ? ` · ${accepted} accepted` : ""} · ${report.met.length} rules met · ${report.outside.length} outside code`);
  console.log(`  Read ${report.filesChecked} file${report.filesChecked === 1 ? "" : "s"}${report.filesSkipped ? `, skipped ${report.filesSkipped} (over 1 MB, binary or unreadable)` : ""}`);
  if (report.diffBase) console.log(`  Only lines changed since ${report.diffBase}`);
  { const far = open.filter((f) => f.reach?.status === "unreachable" && !isHygiene(f)).length; if (far) console.log(`  ${far} of the findings in the code ${far === 1 ? "is" : "are"} in files no route or entry point reaches (ranked lower in the report)`); }
  if (report.held) console.log(`  ${report.held} more at medium confidence: run with --all to see ${report.held === 1 ? "it" : "them"}`);
  if (report.baseline) console.log(`  Since the baseline of ${report.baseline.created}: ${report.baseline.newCount} new, ${report.baseline.fixed.length} fixed, ${report.baseline.unchangedCount} unchanged`);
  // Findings in the code first; repo hygiene under its own label (sort is stable, so file order holds within each group).
  const listed = [...report.findings].sort((a, b) => +isHygiene(a) - +isHygiene(b));
  // For a person at a terminal the findings stand apart from the summary and the notes: a ruled heading per group, each
  // file on its own line, and the status in colour. Piped output keeps one line per finding, which other tools read.
  const pretty = (process.stdout.isTTY || !!process.env.FORCE_COLOR) && !rest.includes("--github");
  const color = pretty && !process.env.NO_COLOR && process.env.TERM !== "dumb";
  const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const width = Math.min(process.stdout.columns || 100, 100);
  // The old Windows console can't draw line characters reliably, so it gets plain dashes.
  const dash = legacy() ? "-" : "─";
  const ruled = (title: string) => `\n${paint("38;2;98;137;254", `${dash}${dash} ${title} `)}${paint("2", dash.repeat(Math.max(3, width - title.length - 4)))}`;
  const group = (title: string, items: typeof listed) => {
    if (!items.length) return;
    console.log(ruled(`${title} (${items.length})`));
    let file = "";
    for (const f of items) {
      if (f.file !== file) { file = f.file; console.log(`\n  ${paint("38;2;98;137;254", file)}`); }
      const status = f.accepted && !f.accepted.expired ? "accepted" : f.status;
      const badge = status === "gap" ? paint("1;31", "GAP     ") : status === "partial" ? paint("33", "PARTIAL ") : paint("2", "ACCEPTED");
      console.log(`    ${badge} ${paint("2", String(f.line).padStart(5))}  ${f.title}${f.change === "new" ? paint("36", "  (new)") : ""}`);
    }
  };
  // The first few to fix: gaps before partials, higher risk first, reached code first.
  const inCode = open.filter((f) => !isHygiene(f));
  const order = (f: (typeof open)[number]) => (f.status === "gap" ? 0 : 3) + ({ high: 0, medium: 1, low: 2 } as const)[f.severity] + (f.reach?.status === "unreachable" ? 0.5 : 0);
  // Findings in test, example and data files come last, and never set the tone: they are rarely what to fix first.
  // Agent, skill and MCP findings stay where they are: those rules read tooling folders on purpose.
  const aside = (f: (typeof open)[number]) => !/^(agent|skill|mcp)\./.test(f.ruleId) && (isNonShipping(f.file) || /\.(json|csv)$/i.test(f.file));
  const ranked = [...inCode].sort((a, b) => order(a) + (aside(a) ? 10 : 0) - order(b) - (aside(b) ? 10 : 0)), first = ranked.slice(0, 3);
  const fold = (t: string, pad: string) => t.replace(new RegExp(`(.{1,${width - pad.length - 2}})(\\s+|$)`, "g"), `$1\n${pad}`).trimEnd();
  const reportFile = resolve("lintsure-report.md");
  // A request a person can paste into any coding agent, connected or not: it names the finding and where the proposal is.
  const request = (fs: typeof open) => `Fix ${fs.length === 1 ? "this Lintsure finding" : "these Lintsure findings, one at a time"}: ${fs.map((f) => `${f.id} "${f.title}" at ${f.file}:${f.line}`).join("; ")}. The proposal for ${fs.length === 1 ? "it" : "each"} is in ${reportFile}. Show me ${fs.length === 1 ? "the" : "each"} change before you apply it, then check the file with Lintsure again.`;
  if (pretty) {
    // One line that fits the outcome, so the result is clear before any detail. It reports what the rules found and
    // never calls a project safe: "nothing found" is said in those words.
    const gaps = inCode.filter((f) => f.status === "gap");
    const headline = !open.length ? paint("1;32", "Done! Nothing found by the current rules.")
      : !inCode.length ? paint("1;32", "Done! Nothing in the code. Only housekeeping is left.")
      : gaps.some((f) => f.severity === "high" && !aside(f)) ? `${paint(BLUE, "Lintsure")} ${paint("1;31", "found something that needs your attention.")}`
      : gaps.length ? `${paint(BLUE, "Lintsure")} ${paint("1;33", "found something interesting.")}`
      : inCode.every((f) => f.severity === "low") ? paint("1;33", inCode.length === 1 ? "A minor finding, worth a look." : "Minor findings, worth a look.")
      : paint("1;33", "Worth a look.");
    console.log(`\n${headline}`);
    group("Findings in the code", listed.filter((f) => !isHygiene(f)));
    group("Repo hygiene: housekeeping, not flaws in the code", listed.filter(isHygiene));
    if (first.length) {
      console.log(ruled(`Start here (${first.length} of ${inCode.length})`));
      first.forEach((f, i) => console.log(`\n  ${i + 1}. ${f.title}\n     ${paint("2", `${f.file}:${f.line}`)}\n     ${paint("36", "Fix:")} ${fold(f.fix, "          ")}`));
      if (inCode.length > first.length) console.log(`\n  ${paint("2", `The fix for every finding is in ${resolve("lintsure-report.md")}`)}`);
    }
    console.log(ruled("What next") + "\n");
  } else for (const f of listed) console.log(`${f === listed.find(isHygiene) ? "Repo hygiene (housekeeping, not flaws in the code):\n" : ""}${(f.accepted && !f.accepted.expired ? "accepted" : f.status).padEnd(8)} ${f.file}:${f.line}  ${f.title}${f.change === "new" ? "  (new)" : ""}`);
  if (rest.includes("--github")) for (const f of open) {
    const msg = `${f.title}. Proposed change, needs your approval: ${f.proposal.what}`.replace(/%/g, "%25").replace(/\r?\n/g, " ");
    console.log(`::${f.status === "gap" ? "error" : "warning"} file=${f.file},line=${f.line},title=Lintsure ${f.ruleId}::${msg}`);
  }
  console.log(`Report saved to ${pretty ? resolve("lintsure-report.md") : "lintsure-report.md"}`);
  if (rest.includes("--report")) console.log("Assessment saved to lintsure-assessment.html (open it in a browser to read, print or save as PDF). It is a draft until a qualified person reviews and signs it.");
  console.log("\nNext steps:");
  nextSteps(report).forEach((x, i) => console.log(`  ${i + 1}. ${x}`));
  // The steps above say what to decide. These are the commands that act on this scan, written out so they can be
  // copied; only the ones that apply are listed.
  const given = rest.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1]));
  const here = given ? [given] : [];
  const follow: { label: string; run: string[] }[] = [
    ...(report.held ? [{ label: `Also show the ${report.held} held-back finding${report.held === 1 ? "" : "s"}`, run: ["scan", ...here, "--all"] }] : []),
    ...(open.length && !report.baseline ? [{ label: "Remember these, so later scans show only what is new", run: ["baseline", ...here] }] : []),
    ...(rest.includes("--report") ? [] : [{ label: "Write a printable assessment", run: ["scan", ...here, "--report"] }]),
    ...(open.some((f) => f.patch) ? [{ label: `Apply the ${open.filter((f) => f.patch).length === 1 ? "one exact fix" : `${open.filter((f) => f.patch).length} exact fixes`} Lintsure knows`, run: ["fix", ...here, ...(rest.includes("--all") ? ["--all"] : [])] }] : []),
    { label: "Connect your coding agent, then ask it to fix one", run: ["setup", ...here] },
  ];
  // Menu only: the full proposal for one finding, and a request to paste into a coding agent. Lintsure never edits code.
  const showFix = async () => {
    const list = [...ranked, ...open.filter(isHygiene)].slice(0, 15);
    console.log(`\nWhich finding?${open.length > list.length ? ` (the first ${list.length} of ${open.length}; the rest are in the report)` : ""}`);
    const pick = await choose([...list.map((f) => `${f.id}  ${f.title}  ${f.file}:${f.line}`.slice(0, width - 6)), "Back"], HINT, color);
    if (pick === null || pick >= list.length) return;
    const f = list[pick], row = (name: string, text: string) => console.log(`  ${paint(GOLD, name.padEnd(8))}${fold(text, "          ")}`);
    console.log(ruled(`${f.id}  ${f.title}`) + "\n");
    row("Where", f.proposal.where); row("Change", f.proposal.what); row("Why", f.proposal.why); row("Gain", f.proposal.benefit);
    console.log(`\n  ${paint("2", "Nothing was changed. To hand it over, paste this into your coding agent:")}\n\n  ${fold(request([f]), "  ")}`);
  };
  const fixRows = open.length ? [{ text: "Show the fix for a finding", run: showFix }, ...(first.length ? [{ text: `Hand the first ${first.length === 1 ? "one" : first.length} to your coding agent`, run: async () => console.log(`\n  ${paint("2", "Paste this into your coding agent:")}\n\n  ${fold(request(first), "  ")}`) }] : [])] : [];
  // A folder with a space in its name is quoted, so the line can be pasted as it is.
  const followRows = follow.map((f) => `${f.label.padEnd(54)}lintsure ${f.run.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}`);
  const asMenu = viaMenu && !!process.stdin.isTTY && !!process.stdout.isTTY;
  if (pretty && !asMenu) console.log(`\nRun next:\n${followRows.map((r) => `    ${r}`).join("\n")}`);
  // In a terminal the closing note is dimmed and wrapped at word ends, so it reads as a footnote and never splits a word.
  const wrap = (t: string) => t.split("\n").map((p) => p.replace(new RegExp(`(.{1,${width - 2}})(\\s+|$)`, "g"), "$1\n").trimEnd()).join("\n");
  console.log(`\n${pretty ? paint("2", wrap(DISCLAIMER)) : DISCLAIMER}`);

  if (asMenu) {
    console.log("\nRun next:");
    const ran = await offer([...fixRows, ...follow.map((f, i) => ({ text: followRows[i], run: f.run as string[] | (() => Promise<void>) }))], color);
    if (ran !== undefined) return ran;
  }
  const failOn = flag("--fail-on")?.toLowerCase();
  const counted = rest.includes("--new-only") && report.baseline ? open.filter((f) => f.change === "new") : open;
  if (failOn === "gap" && counted.some((f) => f.status === "gap")) return 1;
  if (failOn === "partial" && counted.length) return 1;
  return 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(2); });
