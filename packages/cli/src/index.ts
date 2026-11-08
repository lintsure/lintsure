#!/usr/bin/env node
// npx lintsure scan [path] [options]      npx lintsure baseline [path]
// Writes reports into the current folder. Never sends anything over the network.
import { mkdir, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { ALL_FRAMEWORKS, BASELINE_FILE, DISCLAIMER, RULES_VERSION, buildDataMap, isOpen, nextSteps, readConfig, scan, toAssessmentHtml, toBaseline, toDataMapHtml, toDataMapMarkdown, toMarkdown, toSarif, type FrameworkId } from "@lintsure/core";
import { browserCheck, toBrowserMarkdown } from "./browser.js";

const HELP = `lintsure scan [path] [options]
lintsure baseline [path]
lintsure map [path]           Map where personal data goes in your code
lintsure browser <url>        Open your app in a browser and check trackers, consent and headers

scan options:
  --framework <ids>   Comma list: ${ALL_FRAMEWORKS.join(", ")}
                      (default: lintsure.config.yaml if present, else all)
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

map:
  Writes lintsure-data-map.html (a diagram) and lintsure-data-map.md: each place a
  personal data field reaches logs, analytics, a database, email, payments, an AI
  model or an outside API, with the file and line.

browser:
  Needs Playwright: npm i -D playwright && npx playwright install chromium
  Opens the URL as a new visitor, records trackers and tracking cookies before any
  choice, clicks Reject if it finds it, and checks security headers. Writes
  lintsure-browser-check.md, .json and .png. Only visits the URL you give it.

baseline:
  Saves the current open findings to .lintsure/baseline.json in the scanned folder.
  Later scans show what is new, fixed or unchanged. The file holds rule ids, file
  paths and one-way fingerprints, never code. You decide whether to commit it.

Accept a finding after review by adding it to .lintsure/accepted.yaml, with the
fingerprint from lintsure-report.json, your reason, your name and the date.

${DISCLAIMER}
Lintsure never sends your code anywhere.`;

const VALUE_FLAGS = ["--framework", "--fail-on", "--project"];

async function main(argv: string[]) {
  const [cmd, ...rest] = argv;
  if (cmd === "browser") {
    const url = argv[1];
    if (!url || !/^https?:\/\//.test(url)) { console.error("Give the full address of your app, for example: lintsure browser http://localhost:3000"); return 2; }
    const r = await browserCheck(url, { screenshot: "lintsure-browser-check.png" });
    await writeFile("lintsure-browser-check.md", toBrowserMarkdown(r));
    await writeFile("lintsure-browser-check.json", JSON.stringify(r, null, 2));
    console.log(`✓ ${r.findings.length} findings for ${url}`);
    console.log(`  Before any choice: ${r.beforeConsent.trackers.join(", ") || "no known trackers"}`);
    console.log(`  Reject button: ${r.rejectButton ? `"${r.rejectButton}", clicked` : "not found"}`);
    if (r.afterReject) console.log(`  After rejecting: ${r.afterReject.trackers.join(", ") || "no known trackers"}`);
    for (const f of r.findings) console.log(`${f.severity.padEnd(7)} ${f.title}`);
    console.log("Report saved to lintsure-browser-check.md (screenshot: lintsure-browser-check.png)");
    console.log("\nLintsure is a readiness tool, not an audit, a certification or legal advice. This check looked at one page as a new visitor and recognises well-known trackers only. Have a qualified person review the results before any decision.");
    return 0;
  }
  if (cmd === "map") {
    const path = resolve(argv[1] && !argv[1].startsWith("--") ? argv[1] : ".");
    const m = await buildDataMap(path);
    await writeFile("lintsure-data-map.html", toDataMapHtml(m, basename(path)));
    await writeFile("lintsure-data-map.md", toDataMapMarkdown(m));
    const by = new Map<string, number>();
    for (const f of m.flows) by.set(`${f.field} → ${f.destination}`, (by.get(`${f.field} → ${f.destination}`) ?? 0) + 1);
    console.log(`✓ ${m.flows.length} places where personal data reaches a destination, in ${m.filesRead} files`);
    for (const [k, n] of [...by].sort((a, b) => b[1] - a[1])) console.log(`  ${String(n).padStart(3)}  ${k}`);
    console.log("Map saved to lintsure-data-map.html (open it in a browser) and lintsure-data-map.md");
    console.log("It reads code call by call and can miss data passed between files. Check each flow. Not legal advice.");
    return 0;
  }
  if (cmd !== "scan" && cmd !== "baseline") { console.log(HELP); return cmd ? 2 : 0; }
  const flag = (n: string) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
  const path = resolve(rest.find((a, i) => !a.startsWith("--") && !VALUE_FLAGS.includes(rest[i - 1])) ?? ".");
  const wanted = flag("--framework")?.split(",").map((s) => s.trim()) as FrameworkId[] | undefined;
  const bad = wanted?.filter((f) => !ALL_FRAMEWORKS.includes(f));
  if (bad?.length) { console.error(`Unknown framework: ${bad.join(", ")}`); return 2; }

  const config = wanted ? null : await readConfig(path);
  if (config?.skipped.length) console.log(`Skipping, not checked yet: ${config.skipped.join(", ")}`);
  const why = wanted ? "Chosen with --framework on the command line." : config?.frameworks ? "Listed in lintsure.config.yaml." : undefined;
  const source = process.env.GITHUB_ACTIONS || process.env.CI ? "ci" : "cli";
  const report = await scan(path, wanted ?? config?.frameworks ?? ALL_FRAMEWORKS, { why, source });
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
  console.log(`✓ ${open.length} open findings · ${n("gap")} gap · ${n("partial")} partial${accepted ? ` · ${accepted} accepted` : ""} · ${report.met.length} rules met · ${report.outside.length} outside code`);
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

  const failOn = flag("--fail-on");
  const counted = rest.includes("--new-only") && report.baseline ? open.filter((f) => f.change === "new") : open;
  if (failOn === "gap" && counted.some((f) => f.status === "gap")) return 1;
  if (failOn === "partial" && counted.length) return 1;
  return 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(2); });
