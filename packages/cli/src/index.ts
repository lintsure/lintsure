#!/usr/bin/env node
// npx lintsure scan [path] [options]      npx lintsure baseline [path]
// Writes reports into the current folder. Never sends anything over the network.
import { execFileSync } from "node:child_process";
import { access, mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { ALL_FRAMEWORKS, BASELINE_FILE, DISCLAIMER, RULES_VERSION, classify, isOpen, nextSteps, readConfig, scan, toAssessmentHtml, toBaseline, toMarkdown, toSarif, type FrameworkId } from "@lintsure/core";

const HELP = `lintsure scan [path] [options]
lintsure baseline [path]
lintsure init [path]     Three questions, saved to lintsure.config.yaml
lintsure info [path]     Show the settings a scan would use, and where each comes from

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
  --fail-on <status>  Exit 1 if any open finding is "gap" or "partial" (for CI)
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
    if (l.startsWith("+++ ")) { file = l === "+++ /dev/null" ? null : l.slice(4).replace(/^b\//, ""); continue; }
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

async function main(argv: string[]) {
  const [cmd, ...raw] = argv;
  if (cmd === "init" || cmd === "info") return (cmd === "init" ? init : info)(resolve(raw.find((a) => !a.startsWith("--")) ?? "."));
  if (cmd !== "scan" && cmd !== "baseline") { console.log(HELP); return cmd ? 2 : 0; }
  const parsed = parseArgs(raw);
  if ("error" in parsed) { console.error(parsed.error); return 2; }
  const { rest } = parsed;
  const flag = (n: string) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
  const path = resolve(rest.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1])) ?? ".");
  const wanted = flag("--framework")?.split(",").map((s) => s.trim()) as FrameworkId[] | undefined;
  const bad = wanted?.filter((f) => !ALL_FRAMEWORKS.includes(f));
  if (bad?.length) { console.error(`Unknown framework: ${bad.join(", ")}`); return 2; }

  const config = await readConfig(path);
  if (config.problems.length) { console.error("Problems in lintsure.config.yaml (fix them so the scan checks what you meant):"); config.problems.forEach((p) => console.error(`  ${p}`)); return 2; }
  if (!wanted && config.skipped.length) console.log(`Skipping, not checked yet: ${config.skipped.join(", ")}`);
  const why = wanted ? "Chosen with --framework on the command line." : config.frameworks ? "Listed in lintsure.config.yaml." : undefined;
  const source = process.env.GITHUB_ACTIONS || process.env.CI ? "ci" : "cli";
  const base = flag("--diff");
  let changed: { base: string; lines: Record<string, number[]> } | undefined;
  if (base) {
    try { changed = { base, lines: parseDiff(execFileSync("git", ["diff", "-U0", "--no-color", "--no-ext-diff", "--relative", base, "--"], { cwd: path, encoding: "utf8", maxBuffer: 64 << 20 })) }; }
    catch { console.error(`--diff: git could not compare with "${base}". Fetch it first (for example git fetch origin main).`); return 2; }
  }
  const report = await scan(path, wanted ?? config.frameworks ?? ALL_FRAMEWORKS, { why, source, all: rest.includes("--all") || undefined, changed });
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
  if (report.record) console.log(`Record ${report.record.id} · ${report.record.createdAt.replace("T", " ").slice(0, 16)} UTC · ${report.record.counts.checkPoints} check points`);
  // A check mark only when nothing is open: "✓ 3 gaps" read as a pass.
  console.log(`${open.length ? "!" : "✓"} ${open.length} open findings · ${n("gap")} gap · ${n("partial")} partial${accepted ? ` · ${accepted} accepted` : ""} · ${report.met.length} rules met · ${report.outside.length} outside code`);
  if (report.diffBase) console.log(`  Only lines changed since ${report.diffBase}`);
  if (report.held) console.log(`  ${report.held} more at medium confidence: run with --all to see ${report.held === 1 ? "it" : "them"}`);
  if (report.baseline) console.log(`  Since the baseline of ${report.baseline.created}: ${report.baseline.newCount} new, ${report.baseline.fixed.length} fixed, ${report.baseline.unchangedCount} unchanged`);
  for (const f of report.findings) console.log(`${(f.accepted && !f.accepted.expired ? "accepted" : f.status).padEnd(8)} ${f.file}:${f.line}  ${f.title}${f.change === "new" ? "  (new)" : ""}`);
  if (rest.includes("--github")) for (const f of open) {
    const msg = `${f.title}. Proposed change, needs your approval: ${f.proposal.what}`.replace(/%/g, "%25").replace(/\r?\n/g, " ");
    console.log(`::${f.status === "gap" ? "error" : "warning"} file=${f.file},line=${f.line},title=Lintsure ${f.ruleId}::${msg}`);
  }
  console.log("Report saved to lintsure-report.md");
  if (rest.includes("--report")) console.log("Assessment saved to lintsure-assessment.html (open it in a browser to read, print or save as PDF). It is a draft until a qualified person reviews and signs it.");
  console.log("\nNext steps:");
  nextSteps(report).forEach((x, i) => console.log(`  ${i + 1}. ${x}`));
  console.log(`\n${DISCLAIMER}`);

  const failOn = flag("--fail-on")?.toLowerCase();
  const counted = rest.includes("--new-only") && report.baseline ? open.filter((f) => f.change === "new") : open;
  if (failOn === "gap" && counted.some((f) => f.status === "gap")) return 1;
  if (failOn === "partial" && counted.length) return 1;
  return 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(2); });
