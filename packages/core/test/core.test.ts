import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { classify, knowledge, outsideFor, rules, scan } from "../src/index.js";

const root = fileURLToPath(new URL("../../../../fixtures/sample-app", import.meta.url));

test("same input, same result", async () => {
  assert.deepEqual(await scan(root), await scan(root));
});

const clean = fileURLToPath(new URL("../../../../fixtures/clean-app", import.meta.url));

test("every rule fires on its planted example", async () => {
  const r = await scan(root);
  const fired = new Set(r.findings.map((f) => f.ruleId));
  for (const rule of rules) assert.ok(fired.has(rule.id), `${rule.id} did not fire`);
  assert.equal(r.met.length, 0);
});

test("near misses in clean code are not flagged", async () => {
  const r = await scan(clean);
  assert.deepEqual(r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`), []);
  assert.equal(r.met.length, rules.length);
});

test("known findings stay put", async () => {
  const r = await scan(root);
  const got = r.findings.filter((f) => f.file !== "src/more.ts").map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.deepEqual(got, [
    "ai.call-not-logged@src/ai.ts:3",
    "ai.automated-decision@src/ai.ts:4",
    "ai.call-not-logged@src/ai.ts:4",
    "ai.hides-being-ai@src/ai.ts:5",
    "ai.synthetic-media@src/ai.ts:6",
    "ai.emotion-or-biometric@src/ai.ts:7",
    "transport.plain-http@src/billing.ts:4",
    "secret.in-source@src/config.ts:2",
    "config.debug-on@src/settings.py:2",
    "pii.logged@src/users.ts:5",
  ]);
});

test("every rule fills every field the site promises", () => {
  for (const r of rules) {
    for (const k of ["id", "title", "fix", "note", "mappedBy", "reviewedAt"] as const) assert.ok(r[k], `${r.id} missing ${k}`);
    assert.ok(r.controls.length > 0, `${r.id} has no controls`);
    assert.ok(r.test || r.fileTest, `${r.id} has no test`);
    assert.notEqual(r.status as string, "met", `${r.id}: only the Checker may mark Met`);
  }
});

test("framework filter only keeps chosen frameworks", async () => {
  const r = await scan(root, ["gdpr"]);
  assert.ok(r.findings.every((f) => f.controls.every((c) => c.framework === "gdpr")));
  assert.ok(r.outside.every((o) => o.framework === "gdpr"));
});

test("core makes no network calls", async () => {
  const src = fileURLToPath(new URL("../../src", import.meta.url));
  const files = await readdir(src, { recursive: true });
  for (const f of files.filter((f) => f.endsWith(".ts"))) {
    const text = await readFile(join(src, f), "utf8");
    assert.doesNotMatch(text, /\bfetch\(|from "node:(http|https|net|dgram)"|require\("(http|https|net)"\)/, `${f} looks like it uses the network`);
  }
});

test("knowledge only points at rules that exist, and every rule is explained somewhere", () => {
  const ids = new Set(rules.map((r) => r.id));
  const used = new Set<string>();
  for (const k of knowledge) for (const o of k.obligations) for (const id of o.rules ?? []) { assert.ok(ids.has(id), `${k.id} ${o.ref} points at missing rule ${id}`); used.add(id); }
  for (const id of ids) assert.ok(used.has(id), `rule ${id} isn't linked from any framework obligation`);
});

test("outside-code items come from obligations code can't prove", () => {
  const items = outsideFor(["eu-ai-act"]);
  assert.ok(items.some((i) => i.control === "Art. 9"));
  assert.ok(items.every((i) => i.evidence.length > 0));
});

test("classifier suggests, with reasons", () => {
  const s = classify({ euUsers: true, personalData: true, usesAI: true, decisionArea: "credit", b2bCustomers: true, usMarket: true });
  assert.deepEqual(s.map((x) => x.framework), ["eu-ai-act", "gdpr", "soc2"]);
  assert.match(s[0].reason, /high-risk/);
  assert.deepEqual(classify({ usesAI: true }), []);
});
