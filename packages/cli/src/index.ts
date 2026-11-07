#!/usr/bin/env node
// npx lintsure scan [path] [--framework gdpr,soc2] [--json] [--fail-on gap|partial]
// Writes lintsure-report.md (and .json with --json). Exit code 1 when --fail-on matches.
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { ALL_FRAMEWORKS, readConfig, scan, toMarkdown, type FrameworkId } from "@lintsure/core";

const HELP = `lintsure scan [path] [options]

  --framework <ids>   Comma list: ${ALL_FRAMEWORKS.join(", ")}
                      (default: lintsure.config.yaml if present, else all)
  --json              Also write lintsure-report.json
  --fail-on <status>  Exit 1 if any finding is "gap" or "partial" (for CI)

A readiness check, not an audit or legal advice. Lintsure never uploads your code.`;

async function main(argv: string[]) {
  const [cmd, ...rest] = argv;
  if (cmd !== "scan") { console.log(HELP); return cmd ? 2 : 0; }
  const flag = (n: string) => { const i = rest.indexOf(n); return i >= 0 ? rest[i + 1] : undefined; };
  const path = resolve(rest.find((a, i) => !a.startsWith("--") && !["--framework", "--fail-on"].includes(rest[i - 1])) ?? ".");
  const wanted = flag("--framework")?.split(",").map((s) => s.trim()) as FrameworkId[] | undefined;
  const bad = wanted?.filter((f) => !ALL_FRAMEWORKS.includes(f));
  if (bad?.length) { console.error(`Unknown framework: ${bad.join(", ")}`); return 2; }

  const config = wanted ? null : await readConfig(path);
  if (config?.skipped.length) console.log(`Skipping, not checked yet: ${config.skipped.join(", ")}`);
  const report = await scan(path, wanted ?? config?.frameworks ?? ALL_FRAMEWORKS);
  await writeFile("lintsure-report.md", toMarkdown(report));
  if (rest.includes("--json")) await writeFile("lintsure-report.json", JSON.stringify(report, null, 2));

  const n = (s: string) => report.findings.filter((f) => f.status === s).length;
  console.log(`✓ ${report.findings.length} findings · ${n("gap")} gap · ${n("partial")} partial · ${report.met.length} rules met · ${report.outside.length} outside code`);
  for (const f of report.findings) console.log(`${f.status.padEnd(8)} ${f.file}:${f.line}  ${f.title}`);
  console.log("Report saved to lintsure-report.md");

  const failOn = flag("--fail-on");
  if (failOn === "gap" && n("gap")) return 1;
  if (failOn === "partial" && (n("gap") || n("partial"))) return 1;
  return 0;
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e instanceof Error ? e.message : e); process.exit(2); });
