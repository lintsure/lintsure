// Format robustness: every benchmark "flag" case that contains a call is re-wrapped the way a formatter would
// (break after the opening bracket, before the closing one) and run through the real scan(). A rule that only
// works when code sits on one line fails here. Pass cases are wrapped too and must stay quiet.
// Usage: node scripts/robustness.mjs [minimum %]   (exits 1 below the minimum)
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const core = await import(new URL("../packages/core/dist/src/index.js", import.meta.url).href);
const cases = JSON.parse(readFileSync(new URL("../benchmark/cases.json", import.meta.url), "utf8").replaceAll("{{}}", ""));
const wrap = (l) => { const a = l.indexOf("("), b = l.lastIndexOf(")"); return a >= 0 && b > a + 1 && !l.includes("\n") ? `${l.slice(0, a + 1)}\n  ${l.slice(a + 1, b)}\n${l.slice(b)}` : null; };
const isPy = (l) => /\b(def |import |print\(|os\.|=\s*True|=\s*False|f["']|request\.(args|form))/.test(l);
const dir = mkdtempSync(join(tmpdir(), "ls-robust-"));
let n = 0, found = 0, newAlarms = 0; const lost = {};
for (const [id, c] of Object.entries(cases)) {
  const rule = core.rules.find((r) => r.id === id);
  if (!rule?.test) continue;
  for (const [kind, list] of [["flag", c.flag], ["pass", c.pass]]) for (const item of list) {
    const line = typeof item === "string" ? item : item.line;
    const w = wrap(line); if (!w) continue;
    if (kind === "flag" && !rule.test(line)) continue;
    const ext = isPy(line) ? ".py" : ".ts";
    const root = join(dir, `${id.replace(/\W/g, "_")}-${kind}-${n + newAlarms}`); rmSync(root, { recursive: true, force: true });
    const { mkdirSync } = await import("node:fs"); mkdirSync(root, { recursive: true });
    writeFileSync(join(root, "app" + ext), w + "\n");
    const r = await core.scan(root, core.ALL_FRAMEWORKS, { all: true });
    const hit = r.findings.some((f) => f.ruleId === id);
    if (kind === "flag") { n++; if (hit) found++; else lost[id] = (lost[id] ?? 0) + 1; }
    else if (hit) { newAlarms++; console.log(`  false alarm after wrapping [${id}]: ${line.slice(0, 90)}`); }
  }
}
rmSync(dir, { recursive: true, force: true });
const pct = Math.round((100 * found) / n);
console.log(`Format robustness: ${found} of ${n} wrapped cases still found (${pct}%). New false alarms from wrapping: ${newAlarms}.`);
if (Object.keys(lost).length) console.log(`Still missed when wrapped: ${Object.entries(lost).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ")}`);
const min = Number(process.argv[2] ?? 0);
if (pct < min) { console.error(`Below the minimum of ${min}%.`); process.exit(1); }
