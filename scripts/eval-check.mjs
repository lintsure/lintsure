// Checks the eval cases in evals/ without a model call: every case is well formed, every skill a grader names exists,
// and the regex graders pass and fail on known text. Run: node scripts/eval-check.mjs
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import assert from "node:assert/strict";

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8").replace(/\r\n/g, "\n");
// Front matter as plain key: value lines. A value in single quotes is taken as written, with '' for a quote.
const front = (text, file) => {
  const m = /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/.exec(text);
  assert.ok(m, `${file}: no front matter`);
  const fields = Object.fromEntries(m[1].split("\n").map((l) => { const i = l.indexOf(":"); const v = l.slice(i + 1).trim(); return [l.slice(0, i).trim(), v.startsWith("'") ? v.slice(1, -1).replaceAll("''", "'") : v]; }));
  return { fields, body: m[2] };
};
const PROMPT_FIELDS = new Set(["schema_version", "name", "description", "tags", "plugins", "runs", "expected_outcome", "model", "max_turns", "timeout_seconds", "allowed_tools", "append_system_prompt", "env"]);
const GRADER_FIELDS = { regex: ["pattern", "flags", "match", "target"], tool_used: ["tool", "input_match", "min", "max"], llm: ["criteria", "focus"] };
const skills = readdirSync(new URL("skills/", root));
const cases = readdirSync(new URL("evals/", root)).filter((d) => statSync(new URL(`evals/${d}`, root)).isDirectory());
assert.ok(cases.length >= 8, "expected the eval cases in evals/");

const regexGraders = {}; let graders = 0;
for (const c of cases) {
  const p = front(read(`evals/${c}/prompt.md`), `${c}/prompt.md`);
  for (const k of Object.keys(p.fields)) assert.ok(PROMPT_FIELDS.has(k), `${c}/prompt.md: unknown field ${k}`);
  assert.ok(p.body.trim().length > 20, `${c}: the prompt is empty`);
  const files = readdirSync(new URL(`evals/${c}/graders/`, root));
  assert.ok(files.length, `${c}: no graders`);
  for (const f of files) {
    const g = front(read(`evals/${c}/graders/${f}`), `${c}/graders/${f}`), type = g.fields.type; graders++;
    assert.ok(GRADER_FIELDS[type], `${c}/${f}: unknown grader type ${type}`);
    for (const k of Object.keys(g.fields)) assert.ok(["type", "weight", "arm", ...GRADER_FIELDS[type]].includes(k), `${c}/${f}: field ${k} does not belong to a ${type} grader`);
    if (type === "llm") assert.ok(/PASS if/.test(g.body) && /FAIL if/.test(g.body), `${c}/${f}: a judge needs both a PASS and a FAIL line`);
    if (type === "tool_used") {
      const re = new RegExp(g.fields.input_match);
      // A grader that waits for one skill must match that skill's name, bare and with a plugin prefix, and no other skill.
      const hit = skills.filter((s) => re.test(`{"skill": "${s}"}`));
      assert.ok(hit.length >= 1, `${c}/${f}: matches no skill in skills/`);
      if (g.fields.max !== "0") { assert.equal(hit.length, 1, `${c}/${f}: should match exactly one skill, matches ${hit.join(", ")}`); assert.ok(re.test(`{"skill":"lintsure:${hit[0]}"}`), `${c}/${f}: should also match the skill with a plugin prefix`); }
      else assert.equal(hit.length, skills.length, `${c}/${f}: a "no skill loads" grader should match every Lintsure skill`);
    }
    if (type === "regex") { const re = new RegExp(g.fields.pattern, g.fields.flags ?? ""), not = g.fields.match === "not_contains"; regexGraders[f] = (s) => (not ? !re.test(s) : re.test(s)); }
  }
}

// Known text for each regex grader: what must pass and what must fail.
const known = {
  "no-standard-claims.md": {
    pass: ["Lintsure reports what its checks found. It is not an audit.", "Never call the code compliant; say what was fixed.", "Two findings are real and one is not a problem."],
    fail: ["After this fix the project is compliant with GDPR.", "Your code is now audit-ready.", "The app looks fully compliant."] },
  "asks-before-applying.md": {
    pass: ["Here is the change. Shall I apply it?", "Say yes and I'll make the edit.", "Do you want me to apply this?", "Please confirm and I will change the file."],
    fail: ["I have applied the fix to src/users.ts.", "The query now uses a bound parameter."] },
};
for (const [file, texts] of Object.entries(known)) {
  const check = regexGraders[file];
  assert.ok(check, `no regex grader named ${file}`);
  for (const s of texts.pass) assert.ok(check(s), `${file} should pass: ${s}`);
  for (const s of texts.fail) assert.ok(!check(s), `${file} should fail: ${s}`);
}
for (const f of Object.keys(regexGraders)) assert.ok(known[f], `regex grader ${f} has no known text here`);
assert.ok(existsSync(new URL("evals/README.md", root)));
console.log(`evals: ${cases.length} cases, ${graders} graders, all well formed`);
