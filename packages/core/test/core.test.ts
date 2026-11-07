import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { rules, scan } from "../src/index.js";

const root = fileURLToPath(new URL("../../../../fixtures/sample-app", import.meta.url));

test("same input, same result", async () => {
  assert.deepEqual(await scan(root), await scan(root));
});

test("finds the planted issues in the sample app", async () => {
  const r = await scan(root);
  const got = r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.deepEqual(got, [
    "transport.plain-http@src/billing.ts:4",
    "secret.in-source@src/config.ts:2",
    "pii.logged@src/users.ts:5",
  ]);
});

test("every rule fills every field the site promises", () => {
  for (const r of rules) {
    for (const k of ["id", "title", "fix", "note", "mappedBy", "reviewedAt"] as const) assert.ok(r[k], `${r.id} missing ${k}`);
    assert.ok(r.controls.length > 0, `${r.id} has no controls`);
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
