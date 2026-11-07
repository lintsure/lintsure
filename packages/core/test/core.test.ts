import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { classify, knowledge, outsideFor, readConfig, rules, scan } from "../src/index.js";

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

test("reads lintsure.config.yaml and skips frameworks not checked yet", async () => {
  const c = await readConfig(fileURLToPath(new URL("../../../../fixtures/config-app", import.meta.url)));
  assert.deepEqual(c.frameworks, ["gdpr", "soc2"]);
  assert.deepEqual(c.skipped, ["hipaa"]);
  assert.deepEqual(await readConfig(root), { frameworks: null, skipped: [] });
});

import { DISCLAIMER, FORBIDDEN_CLAIMS, NOT_A_VERDICT, toMarkdown } from "../src/index.js";

test("every report carries the disclaimer, outside-code reminder and next steps", async () => {
  for (const dir of [root, clean]) {
    const r = await scan(dir);
    assert.equal(r.disclaimer, DISCLAIMER);
    const md = toMarkdown(r);
    assert.ok(md.includes(DISCLAIMER));
    assert.ok(md.includes(NOT_A_VERDICT));
    assert.match(md, /## What to do next/);
    assert.match(md, /outside code\. Code checks alone are not enough for a full review/);
    assert.match(md, /qualified compliance professional/);
  }
});

test("no output claims a verdict, even when everything is Met", async () => {
  const texts = [
    toMarkdown(await scan(clean)), toMarkdown(await scan(root)),
    ...rules.flatMap((r) => [r.title, r.fix, r.note]),
    ...knowledge.flatMap((k) => [k.summary, ...k.obligations.map((o) => o.plain), ...k.watchOut]),
  ];
  // The fixed disclaimer sentences are negations ("do not mean you are compliant"), so they are excluded.
  for (const t of texts.map((x) => x.split(NOT_A_VERDICT).join("").split(DISCLAIMER).join(""))) for (const bad of FORBIDDEN_CLAIMS) assert.doesNotMatch(t, bad, `verdict-like wording: ${t.slice(0, 80)}`);
});

import { toAssessmentHtml } from "../src/index.js";

test("assessment report: every section, every finding, human sign-off, no verdicts", async () => {
  const r = await scan(root);
  const html = toAssessmentHtml(r, { project: "Sample <app>", date: "2026-11-07" });
  for (const h of ["Summary", "Scope and method", "Possible issues and fixes", "Framework by framework", "Work outside code", "What to do next", "Human review and sign-off", "Disclaimer"]) assert.ok(html.includes(`<h2>${h}</h2>`), h);
  for (const f of r.findings) assert.ok(html.includes(`${f.file}:${f.line}`), f.file);
  for (const o of r.outside) assert.ok(html.includes(o.title.replace(/&/g, "&amp;")), o.title);
  assert.ok(html.includes("Sample &lt;app&gt;"), "project name is escaped");
  const e = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  assert.ok(html.includes(e(DISCLAIMER)) && html.includes(e(NOT_A_VERDICT)));
  assert.match(html, /Draft until reviewed by a person/);
  assert.match(html, /Reviewer name/);
  assert.equal(html, toAssessmentHtml(r, { project: "Sample <app>", date: "2026-11-07" }), "same input, same file");
  const body = html.split(e(NOT_A_VERDICT)).join("").split(e(DISCLAIMER)).join("");
  for (const bad of FORBIDDEN_CLAIMS) assert.doesNotMatch(body, bad);
});

test("assessment report on clean code still asks for human review and outside-code work", async () => {
  const html = toAssessmentHtml(await scan(clean), { date: "2026-11-07" });
  assert.match(html, /found no possible issues/);
  assert.match(html, /That is not the same as having none/);
  assert.match(html, /Human review is required/);
});
