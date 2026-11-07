// Scores every line rule against the labelled cases in benchmark/cases.json.
// Precision: of the lines a rule flags, how many it should. Recall: of the lines it should flag, how many it does.
// Fails if any rule scores below its recorded minimum in benchmark/scores.json, or gets a status wrong.
// Run: node scripts/benchmark.mjs        Record new minimums: node scripts/benchmark.mjs --record
import { readFileSync, writeFileSync } from "node:fs";
import { rules } from "../packages/core/dist/src/index.js";

const cases = JSON.parse(readFileSync(new URL("../benchmark/cases.json", import.meta.url), "utf8"));
const scoresUrl = new URL("../benchmark/scores.json", import.meta.url);
const recorded = (() => { try { return JSON.parse(readFileSync(scoresUrl, "utf8")); } catch { return {}; } })();
const pct = (n) => Math.round(n * 1000) / 10;

const out = {}; let failed = false;
for (const [id, c] of Object.entries(cases)) {
  if (id.startsWith("_")) continue;
  const rule = rules.find((r) => r.id === id);
  if (!rule?.test) { console.error(`FAIL ${id}: no line rule with this id`); failed = true; continue; }
  let tp = 0, fp = 0, fn = 0; const problems = [];
  for (const item of c.flag) {
    const line = typeof item === "string" ? item : item.line;
    const hit = rule.test(line);
    if (!hit) { fn++; problems.push(`missed: ${line}`); continue; }
    tp++;
    const want = typeof item === "string" ? null : item.status;
    const got = hit === "partial" ? "partial" : rule.status;
    if (want && want !== got) problems.push(`status ${got}, expected ${want}: ${line}`);
  }
  for (const line of c.pass) if (rule.test(line)) { fp++; problems.push(`false alarm: ${line}`); }
  const precision = tp + fp ? tp / (tp + fp) : 1, recall = tp + fn ? tp / (tp + fn) : 1;
  out[id] = { precision: pct(precision), recall: pct(recall), cases: c.flag.length + c.pass.length };
  const min = recorded[id];
  const below = min && (out[id].precision < min.precision || out[id].recall < min.recall);
  const statusWrong = problems.some((p) => p.startsWith("status"));
  if (below || statusWrong) failed = true;
  console.log(`${below || statusWrong ? "FAIL" : "ok  "} ${id.padEnd(26)} precision ${String(out[id].precision).padStart(5)}%  recall ${String(out[id].recall).padStart(5)}%  (${out[id].cases} cases)`);
  for (const p of problems) console.log(`       ${p}`);
}

if (process.argv.includes("--record")) { writeFileSync(scoresUrl, JSON.stringify(out, null, 2) + "\n"); console.log("Recorded new minimums in benchmark/scores.json"); }
else if (failed) { console.error("Benchmark failed: a rule got worse or gave the wrong status."); process.exit(1); }
else console.log("Benchmark passed.");
