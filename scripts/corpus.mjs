// Runs each case in benchmark/corpus.mjs as a small project through the real scan() and scores it.
// Precision: of the findings given, how many were right. Recall: of the findings expected from rules that exist, how
// many were given. Gaps: expected findings whose rule doesn't exist yet (reported, never failed).
// Scans with --all; recallShownByDefault counts only hits a user sees without it (medium-confidence rules are held back).
// Repo-level hygiene rules (repo.*, release.*) are left out: every tiny case would trip them.
// Fails if precision or recall drops below benchmark/corpus-scores.json, or a case that passed now fails.
// Run: node scripts/corpus.mjs     Record a new baseline: node scripts/corpus.mjs --record
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
const core = await import(new URL("../packages/core/dist/src/index.js", import.meta.url).href);
const cases = (await import(new URL("../benchmark/corpus.mjs", import.meta.url).href)).default;
const scoresUrl = new URL("../benchmark/corpus-scores.json", import.meta.url);
const known = new Set(core.rules.map((r) => r.id));
const hygiene = (id) => /^(?:repo|release)\./.test(id);
const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 100);

let tpShown = 0, tp = 0, fp = 0, fn = 0, gaps = 0, gapsFound = 0; const byKind = {}, passed = [], lines = [];
for (const c of cases) {
  const root = mkdtempSync(join(tmpdir(), "lintsure-corpus-"));
  try {
    const text = {};
    for (const [f, body] of Object.entries(c.files)) {
      const abs = join(root, f); mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, (text[f] = body.replaceAll("{{}}", "")));
    }
    const lineOf = (e) => text[e.file].split("\n").findIndex((l) => l.includes(e.at)) + 1;
    const got = (await core.scan(root, core.ALL_FRAMEWORKS, { all: true })).findings.filter((f) => !hygiene(f.ruleId)).map((f) => ({ rule: f.ruleId, file: f.file.replaceAll("\\", "/"), line: f.line }));
    // What a default run (no --all) actually shows, from the engine itself rather than a copy of its hold-back list.
    const byDefault = new Set((await core.scan(root, core.ALL_FRAMEWORKS, { all: false })).findings.map((f) => `${f.ruleId}|${f.file.replaceAll("\\", "/")}|${f.line}`));
    const k = (byKind[c.kind] ??= { tp: 0, fp: 0, fn: 0, gaps: 0 });
    const used = new Set(), problems = [];
    for (const e of c.expect) {
      const line = lineOf(e), i = got.findIndex((g, j) => !used.has(j) && g.rule === e.rule && g.file === e.file && g.line === line);
      if (!known.has(e.rule)) { gaps++; k.gaps++; if (i >= 0) gapsFound++; problems.push(`gap (no rule yet): ${e.rule} at ${e.file}:${line}`); continue; }
      if (i >= 0) { used.add(i); tp++; k.tp++; if (byDefault.has(`${e.rule}|${e.file}|${line}`)) tpShown++; } else { fn++; k.fn++; problems.push(`missed: ${e.rule} at ${e.file}:${line}`); }
    }
    got.forEach((g, j) => { if (!used.has(j)) { fp++; k.fp++; problems.push(`false alarm: ${g.rule} at ${g.file}:${g.line}`); } });
    const ok = !problems.some((p) => !p.startsWith("gap"));
    if (ok) passed.push(c.name);
    lines.push(`${ok ? "ok  " : "FAIL"} [${c.kind}] ${c.name}`, ...problems.map((p) => `       ${p}`));
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const now = { precision: pct(tp, tp + fp), recall: pct(tp, tp + fn), recallShownByDefault: pct(tpShown, tp + fn), gapsOpen: gaps - gapsFound, cases: cases.length, passed: passed.sort(),
  byKind: Object.fromEntries(Object.entries(byKind).map(([kind, v]) => [kind, { precision: pct(v.tp, v.tp + v.fp), recall: pct(v.tp, v.tp + v.fn), falseAlarms: v.fp, missed: v.fn, gaps: v.gaps }])) };
console.log(lines.join("\n"));
console.log(`\nprecision ${now.precision}%  recall ${now.recall}% (shown without --all: ${now.recallShownByDefault}%)  (${tp} right, ${fp} false alarms, ${fn} missed)  gaps with no rule: ${now.gapsOpen}  cases passed: ${passed.length}/${cases.length}`);
for (const [kind, v] of Object.entries(now.byKind)) console.log(`  ${kind.padEnd(5)} precision ${String(v.precision).padStart(5)}%  recall ${String(v.recall).padStart(5)}%  false alarms ${v.falseAlarms}  missed ${v.missed}  gaps ${v.gaps}`);

if (process.argv.includes("--record")) { writeFileSync(scoresUrl, JSON.stringify(now, null, 2) + "\n"); console.log("Recorded the baseline in benchmark/corpus-scores.json"); process.exit(0); }
const base = (() => { try { return JSON.parse(readFileSync(scoresUrl, "utf8")); } catch { return null; } })();
if (!base) { console.log("No baseline yet: run with --record."); process.exit(0); }
const lost = base.passed.filter((n) => !passed.includes(n));
if (now.precision < base.precision || now.recall < base.recall || lost.length) {
  console.error(`Corpus got worse than the baseline${lost.length ? `; these passed before: ${lost.join(", ")}` : ""}.`); process.exit(1);
}
console.log("Corpus passed (no worse than the baseline).");
