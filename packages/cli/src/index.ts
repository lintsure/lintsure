#!/usr/bin/env node
// npx lintsure scan [path] [options]      npx lintsure baseline [path]
// Writes reports into the current folder. Never sends anything over the network.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { status, pick, plan, setup, undo } from "./agents.js";
import { parseActivity, toOtlp } from "./otel.js";
import { ALL_FRAMEWORKS, BASELINE_FILE, DISCLAIMER, RULES_VERSION, classify, isHygiene, isOpen, nextSteps, readConfig, scan, toAssessmentHtml, toBaseline, toMarkdown, toSarif, type FrameworkId } from "@lintsure/core";

import { choose } from "./menu.js";

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
  if (process.platform === "win32" && !env.WT_SESSION && !env.TERM_PROGRAM && !env.ConEmuANSI && !env.FORCE_COLOR) return `Lintsure ${RULES_VERSION}\n`;
  const color = !env.NO_COLOR && env.TERM !== "dumb";
  const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const text = [`${paint("1", "Lintsure")}${paint("2", `  ${RULES_VERSION}`)}`, "Keep your AI agents on track and in context.", "", paint("2", "Everything stays on this machine.")];
  const mark = prism(), width = Math.max(...mark.map((l) => l.length)), top = Math.floor((mark.length - text.length) / 2);
  return "\n" + mark.map((l, i) => (paint("38;2;11;110;79", l.padEnd(width)) + "    " + (text[i - top] ?? "")).trimEnd()).join("\n") + "\n";
}

// What the start menu offers, in the order a new user needs them. `run` is the command line it stands for.
const START: { label: string; run: string[] | null }[] = [
  { label: "Check this project", run: ["scan"] },
  { label: "Is everything set up?", run: ["status"] },
  { label: "Connect your coding agent", run: ["setup"] },
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
async function offer(rows: { text: string; run: string[] }[], color: boolean): Promise<number | undefined> {
  sawMenu = true;
  const pick = await choose([...rows.map((r) => r.text), "Main menu", "Quit"], HINT, color);
  if (pick === rows.length) wantsMenu = true;
  if (pick === null || pick >= rows.length) return undefined;
  sawMenu = false; // the command run next gets its own ending
  return main(rows[pick].run);
}
const COMMANDS = ["scan", "baseline", "init", "info", "setup", "status", "export"];
/** The command someone most likely meant: the same word without dashes, or one within two typing slips. Pure. */
function nearest(word: string): string | undefined {
  const slips = (a: string, b: string) => { let row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) { const next = [i]; for (let j = 1; j <= b.length; j++) next[j] = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); row = next; }
    return row[b.length]; };
  return COMMANDS.find((c) => c === word) ?? COMMANDS.map((c) => [slips(c, word), c] as const).filter(([n]) => n <= 2).sort((x, y) => x[0] - y[0])[0]?.[1];
}
const startRows = () => START.map((s) => (s.run ? `${s.label.padEnd(28)}lintsure ${s.run.join(" ")}` : s.label));

const HELP = `lintsure scan [path] [options]
lintsure baseline [path]
lintsure init [path]     Three questions, saved to lintsure.config.yaml
lintsure info [path]     Show the settings a scan would use, and where each comes from
lintsure setup [path]    Add the Lintsure MCP server to this project's agent configs
                         (shows the change; --yes writes it; --undo takes it out;
                         --agents claude,cursor,vscode,gemini)
lintsure status [path]   Check that this project is ready: Node, config, rules, agents
lintsure export --otlp-json [path]  Write .lintsure/activity.jsonl as an OpenTelemetry
                         traces file (lintsure.otlp.json) for your own observability tool

scan options:
  --framework <ids>   Comma list: ${ALL_FRAMEWORKS.join(", ")}
                      (default: lintsure.config.yaml if present, else all)
  --all               Also list medium-confidence findings (held back by default)
  --diff <base>       Only list findings on lines changed since <base>, e.g. origin/main
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
const BOOL_FLAGS = ["--json", "--sarif", "--report", "--new-only", "--github", "--save-record", "--all"];

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

const FRAMEWORK_NAMES: Record<string, string> = { "owasp-top10": "OWASP Top 10", "cwe-top25": "CWE Top 25", gdpr: "GDPR", "eu-ai-act": "EU AI Act", "owasp-llm": "OWASP Top 10 for LLM apps", cra: "EU Cyber Resilience Act" };

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
  const what = await pick("1. What should Lintsure check?", ["Security only (OWASP Top 10, CWE Top 25)", "Security and privacy (adds GDPR)", "Everything (all six frameworks)", "Let me pick"]);
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
  if (cmd === "setup" || cmd === "status") {
    const root = resolve(raw.find((a, i) => !a.startsWith("--") && raw[i - 1] !== "--agents") ?? ".");
    if (cmd === "status") return status(root);
    const i = raw.indexOf("--agents");
    const agents = await pick(root, i >= 0 ? raw[i + 1]?.split(",").map((s) => s.trim()) : undefined);
    if (typeof agents === "string") { console.error(agents); return 2; }
    if (raw.includes("--undo")) return undo(root, agents);
    const code = await setup(root, agents, raw.includes("--yes"));
    // From the menu, the preview is followed by the choice to write it, so nobody has to retype the command with --yes.
    if (viaMenu && !raw.includes("--yes") && process.stdin.isTTY && process.stdout.isTTY && (await Promise.all(agents.map((a) => plan(root, a)))).some((p) => p.text)) {
      console.log("");
      const ran = await offer([{ text: `${"Write these changes".padEnd(54)}lintsure setup --yes`, run: ["setup", ...raw, "--yes"] }], !process.env.NO_COLOR && process.env.TERM !== "dumb");
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
      const pick = await choose(startRows(), HINT, color);
      const run = pick === null ? null : START[pick].run;
      if (!run) return code;
      viaMenu = true; sawMenu = false; wantsMenu = false;
      code = await main(run);
      if (!sawMenu) await offer([], color); // a command with no menu of its own still ends with the way back
      if (!wantsMenu) return code;
      console.log(`\nLintsure ${RULES_VERSION}\n`);
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

  const config = await readConfig(path);
  // Checked after the config loads its rule packs, so a pack's framework id is accepted.
  const bad = wanted?.filter((f) => !ALL_FRAMEWORKS.includes(f));
  if (bad?.length) { console.error(`Unknown framework: ${bad.join(", ")}\nChoose from: ${ALL_FRAMEWORKS.join(", ")}`); return 2; }
  if (config.problems.length) { console.error("Problems in lintsure.config.yaml (fix them so the scan checks what you meant):"); config.problems.forEach((p) => console.error(`  ${p}`)); return 2; }
  if (!wanted && config.skipped.length) console.log(`Skipping, not checked yet: ${config.skipped.join(", ")}`);
  const why = wanted ? "Chosen with --framework on the command line." : config.frameworks ? "Listed in lintsure.config.yaml." : undefined;
  const source = process.env.GITHUB_ACTIONS || process.env.CI ? "ci" : "cli";
  const base = flag("--diff");
  let changed: { base: string; lines: Record<string, number[]> } | undefined;
  if (base) {
    try { changed = { base, lines: parseDiff(execFileSync("git", ["-c", "core.quotePath=false", "diff", "-U0", "--no-color", "--no-ext-diff", "--relative", base, "--"], { cwd: path, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 << 20 })) }; }
    catch { console.error(`--diff: git could not compare with "${base}".\nCheck that this folder is inside a git repository and that "${base}" exists here (for example: git fetch origin main).`); return 2; }
  }
  // LINTSURE_WORKSPACE_RULES: path to a JSON file of account rules the caller already has (the plugin writes it).
  // Read only to hash into the policy fingerprint; the CLI never fetches them. A file it can't read is an error, not a silent skip.
  let workspaceRules: unknown;
  const wsFile = process.env.LINTSURE_WORKSPACE_RULES;
  if (wsFile) {
    try { workspaceRules = JSON.parse(await readFile(wsFile, "utf8")); }
    catch { console.error(`Couldn't read workspace rules from LINTSURE_WORKSPACE_RULES (${wsFile}).`); process.exit(2); }
  }
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
  const dash = process.platform === "win32" && !process.env.WT_SESSION && !process.env.TERM_PROGRAM && !process.env.ConEmuANSI && !process.env.FORCE_COLOR ? "-" : "─";
  const ruled = (title: string) => `\n${paint("1", `${dash}${dash} ${title} `)}${paint("2", dash.repeat(Math.max(3, width - title.length - 4)))}`;
  const group = (title: string, items: typeof listed) => {
    if (!items.length) return;
    console.log(ruled(`${title} (${items.length})`));
    let file = "";
    for (const f of items) {
      if (f.file !== file) { file = f.file; console.log(`\n  ${paint("1", file)}`); }
      const status = f.accepted && !f.accepted.expired ? "accepted" : f.status;
      const badge = status === "gap" ? paint("1;31", "GAP     ") : status === "partial" ? paint("33", "PARTIAL ") : paint("2", "ACCEPTED");
      console.log(`    ${badge} ${paint("2", String(f.line).padStart(5))}  ${f.title}${f.change === "new" ? paint("36", "  (new)") : ""}`);
    }
  };
  if (pretty) {
    group("Findings in the code", listed.filter((f) => !isHygiene(f)));
    group("Repo hygiene: housekeeping, not flaws in the code", listed.filter(isHygiene));
    console.log(ruled("What next") + "\n");
  } else for (const f of listed) console.log(`${f === listed.find(isHygiene) ? "Repo hygiene (housekeeping, not flaws in the code):\n" : ""}${(f.accepted && !f.accepted.expired ? "accepted" : f.status).padEnd(8)} ${f.file}:${f.line}  ${f.title}${f.change === "new" ? "  (new)" : ""}`);
  if (rest.includes("--github")) for (const f of open) {
    const msg = `${f.title}. Proposed change, needs your approval: ${f.proposal.what}`.replace(/%/g, "%25").replace(/\r?\n/g, " ");
    console.log(`::${f.status === "gap" ? "error" : "warning"} file=${f.file},line=${f.line},title=Lintsure ${f.ruleId}::${msg}`);
  }
  console.log("Report saved to lintsure-report.md");
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
    { label: "Connect your coding agent, then ask it to fix one", run: ["setup", ...here] },
  ];
  // A folder with a space in its name is quoted, so the line can be pasted as it is.
  const followRows = follow.map((f) => `${f.label.padEnd(54)}lintsure ${f.run.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}`);
  const asMenu = viaMenu && !!process.stdin.isTTY && !!process.stdout.isTTY;
  if (pretty && !asMenu) console.log(`\nRun next:\n${followRows.map((r) => `    ${r}`).join("\n")}`);
  // In a terminal the closing note is dimmed and wrapped at word ends, so it reads as a footnote and never splits a word.
  const wrap = (t: string) => t.split("\n").map((p) => p.replace(new RegExp(`(.{1,${width - 2}})(\\s+|$)`, "g"), "$1\n").trimEnd()).join("\n");
  console.log(`\n${pretty ? paint("2", wrap(DISCLAIMER)) : DISCLAIMER}`);

  if (asMenu) {
    console.log("\nRun next:");
    const ran = await offer(follow.map((f, i) => ({ text: followRows[i], run: f.run })), color);
    if (ran !== undefined) return ran;
  }
  const failOn = flag("--fail-on")?.toLowerCase();
  const counted = rest.includes("--new-only") && report.baseline ? open.filter((f) => f.change === "new") : open;
  if (failOn === "gap" && counted.some((f) => f.status === "gap")) return 1;
  if (failOn === "partial" && counted.length) return 1;
  return 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(2); });
