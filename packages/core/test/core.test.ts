import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { classify, knowledge, outsideFor, readConfig, rules, scan } from "../src/index.js";

const root = fileURLToPath(new URL("../../../../fixtures/sample-app", import.meta.url));

test("same input, same result", async () => {
  const now = new Date("2026-11-08T10:00:00Z");
  assert.deepEqual(await scan(root, undefined, { now }), await scan(root, undefined, { now }));
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
  const got = r.findings.filter((f) => !/^(src\/(more|owasp|page)\.|package\.json|\.github\/)/.test(f.file)).map((f) => `${f.ruleId}@${f.file}:${f.line}`);
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
  assert.deepEqual(s.map((x) => x.framework), ["eu-ai-act", "gdpr", "soc2", "owasp-top10"]);
  assert.match(s[0].reason, /high-risk/);
  assert.deepEqual(classify({ usesAI: true }), []);
});

test("reads lintsure.config.yaml and skips frameworks not checked yet", async () => {
  const c = await readConfig(fileURLToPath(new URL("../../../../fixtures/config-app", import.meta.url)));
  assert.deepEqual(c.frameworks, ["gdpr", "soc2"]);
  assert.deepEqual(c.skipped, ["hipaa"]);
  assert.deepEqual(c.ignore, ["vendor"]);
  assert.deepEqual(await readConfig(root), { frameworks: null, skipped: [], ignore: [] });
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

test("logs: words inside strings are not personal data, interpolated fields are", () => {
  const r = rules.find((x) => x.id === "pii.logged")!;
  assert.equal(r.test!('console.error("Transactional email error:", error);'), false);
  assert.equal(r.test!('logger.warning("Model returned text instead of an email.")'), false);
  assert.equal(r.test!('logger.info(f"reply to {prospect.email} sent")'), true);
  assert.equal(r.test!("console.log(`user ${user.email}`)"), true);
  assert.equal(r.test!("console.log(user.email)"), true);
});

test("TLS rule ignores verify=False on non-HTTP calls", () => {
  const r = rules.find((x) => x.id === "transport.tls-verify-off")!;
  assert.equal(r.test!('find_email("Jane", "Doe", verify=False)'), false);
  assert.equal(r.test!('requests.get(url, verify=False)'), true);
});

test("ignore list, build output and minified files are skipped", async () => {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "ls-"));
  const bad = "console.log(user.email);\n";
  for (const d of ["src", "tests", ".output", "dist"]) await mkdir(join(dir, d));
  await writeFile(join(dir, "src/a.ts"), bad);
  await writeFile(join(dir, "src/b.ts"), "x".repeat(2000) + "\n" + bad);
  await writeFile(join(dir, "src/c.min.js"), bad);
  await writeFile(join(dir, "tests/a.ts"), bad);
  await writeFile(join(dir, ".output/a.js"), bad);
  await writeFile(join(dir, "dist/a.js"), bad);
  await writeFile(join(dir, "lintsure.config.yaml"), "ignore:\n  - tests/\n");
  const r = await scan(dir);
  assert.deepEqual(r.findings.map((f) => f.file), ["src/a.ts"]);
});

import { AGENT_GUIDANCE, APPROVAL_RULES, PROPOSAL_HEADING } from "../src/index.js";

test("guardrail: every finding is a proposal with where, what, why and benefit, and needs approval", async () => {
  const r = await scan(root);
  assert.ok(r.findings.length > 0);
  for (const f of r.findings) {
    const p = f.proposal;
    assert.equal(p.where, `${f.file}:${f.line}`, `${f.ruleId}: proposal must point at the exact line`);
    for (const k of ["what", "why", "benefit"] as const) assert.ok(p[k].length > 10, `${f.ruleId}: proposal.${k} is empty`);
    assert.equal(p.needsApproval, true);
    assert.ok(f.controls.every((c) => p.why.includes(c.id)), `${f.ruleId}: why must name every control`);
  }
  const md = toMarkdown(r);
  assert.equal(md.split(PROPOSAL_HEADING).length - 1, r.findings.length, "every finding in the report needs the approval heading");
});

test("guardrail: agents are told to explain, point, show the benefit, ask and wait", () => {
  for (const part of ["What you plan to do", "Why", "Where, exactly", "benefit", "wait", "Only a clear yes is approval", "One proposal at a time"])
    assert.ok(APPROVAL_RULES.includes(part), `approval rules miss: ${part}`);
  assert.ok(AGENT_GUIDANCE.includes(APPROVAL_RULES), "server instructions must carry the approval rules");
});

import { fingerprint, parseAccepted, toBaseline, toSarif, BASELINE_FILE, ACCEPTED_FILE } from "../src/index.js";

test("fingerprints survive moved lines, change when the line changes, and hold no code", () => {
  const a = fingerprint("pii.logged", "src/a.ts", "  logger.info(`x ${user.email}`);");
  assert.equal(a, fingerprint("pii.logged", "src/a.ts", "logger.info(`x   ${user.email}`);"));
  assert.notEqual(a, fingerprint("pii.logged", "src/a.ts", "logger.info(`x ${user.phone}`);"));
  assert.match(a, /^[0-9a-f]{16}$/);
});

test("baseline marks new, unchanged and fixed; accepted findings are set aside and expire", async () => {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-bl-"));
  await mkdir(join(dir, "src")); await mkdir(join(dir, ".lintsure"));
  await writeFile(join(dir, "src/a.ts"), "console.log(user.email);\napp.use(cors({ origin: \"*\" }));\n");
  const first = await scan(dir);
  await writeFile(join(dir, BASELINE_FILE), JSON.stringify(toBaseline(first, "2026-01-01")));
  const baseText = JSON.stringify(toBaseline(first, "2026-01-01"));
  assert.doesNotMatch(baseText, /console|cors\(/, "baseline must not contain code");

  const cors = first.findings.find((f) => f.ruleId === "cors.any-origin")!;
  await writeFile(join(dir, ACCEPTED_FILE), `- rule: cors.any-origin\n  where: src/a.ts\n  fingerprint: ${cors.fingerprint}\n  reason: Public read-only API\n  accepted_by: J. Smith\n  date: 2026-01-01\n  review_by: 2099-01-01\n`);
  await writeFile(join(dir, "src/a.ts"), "// moved\napp.use(cors({ origin: \"*\" }));\nconst h = md5(user.password);\n");
  const second = await scan(dir);
  assert.equal(second.baseline?.fixed.length, 1, "the email log was fixed");
  assert.equal(second.findings.find((f) => f.ruleId === "cors.any-origin")?.change, "unchanged", "moving a line keeps it the same finding");
  assert.equal(second.findings.find((f) => f.ruleId === "crypto.weak-password-hash")?.change, "new");
  assert.equal(second.findings.find((f) => f.ruleId === "cors.any-origin")?.accepted?.expired, false);
  assert.match(toMarkdown(second), /Accepted by J\. Smith/);
  assert.match(toMarkdown(second), /Fixed since baseline \(1\)/);

  await writeFile(join(dir, ACCEPTED_FILE), `- rule: cors.any-origin\n  fingerprint: ${cors.fingerprint}\n  reason: x\n  accepted_by: J\n  date: 2020-01-01\n  review_by: 2020-06-01\n`);
  const third = await scan(dir);
  assert.equal(third.findings.find((f) => f.ruleId === "cors.any-origin")?.accepted?.expired, true, "past the review date it counts as open again");
});

test("accepted.yaml entries without a reason or a person are ignored", () => {
  assert.equal(parseAccepted("- rule: a\n  fingerprint: f\n  accepted_by: J\n").length, 0);
  assert.equal(parseAccepted("- rule: a\n  fingerprint: f\n  reason: ok\n  accepted_by: J\n").length, 1);
});

test("SARIF output has locations and fingerprints but never source code", async () => {
  const r = await scan(root);
  const sarif = JSON.stringify(toSarif(r, "test"));
  assert.ok(sarif.includes("\"startLine\""));
  assert.ok(sarif.includes("lintsure/v1"));
  assert.doesNotMatch(sarif, /sk_live_|logger\.info\(|md5\(user/, "SARIF must not include code from the flagged lines");
});

test("readiness check record: dated, scoped, explains what applies, counts check points, never called an audit", async () => {
  const now = new Date("2026-11-08T10:00:00Z");
  const r = await scan(root, undefined, { now, why: "Listed in lintsure.config.yaml.", source: "cli" });
  const c = r.record!;
  assert.match(c.id, /^LS-20261108-[0-9a-f]{6}$/);
  assert.equal(c.createdAt, "2026-11-08T10:00:00.000Z");
  assert.equal(c.kind, "readiness check record");
  assert.ok(c.counts.checkPoints >= c.scope.filesRead, "every file read gets at least one check point");
  assert.equal(c.counts.findings + c.counts.observations, r.findings.filter((f) => !f.accepted).length);
  assert.ok(c.applies.every((a) => a.why === "Listed in lintsure.config.yaml."));
  assert.ok(r.findings.every((f, i) => f.id === `F-${String(i + 1).padStart(3, "0")}`));
  const logged = c.byControl.find((b) => b.framework === "gdpr" && b.control === "Art. 32")!;
  assert.equal(logged.result, "finding");
  assert.ok(logged.findingIds.length > 0);
  const md = toMarkdown(r);
  assert.match(md, /Readiness check record/);
  assert.match(md, /not an audit/);
  assert.doesNotMatch(md, /\b(deficienc|nonconformit|audit report)/i, "audit-only terms must not appear");
});

test("comments, docstrings and test files are not read as code", async () => {
  const { commentLines } = await import("../src/index.js");
  assert.deepEqual(commentLines(["// eval(x)", "const a = 1;", "/* start", "md5(p)", "*/", " * note"], ".ts"), [true, false, true, true, true, true]);
  assert.deepEqual(commentLines(['"""', "hmac-sha1 docs", '"""', "x = 1", "# md5"], ".py"), [true, true, true, false, true]);
  assert.deepEqual(commentLines(["#private = 1"], ".ts"), [false]); // JS private field, not a comment
});

test("a JWT whose exp is set a few lines above is not flagged", async () => {
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-jwt-"));
  await writeFile(join(dir, "auth.py"), ['payload = {', '  "sub": uid,', '  "exp": now + ttl,', '}', 'return jwt.encode(payload, key)', ...Array(12).fill(''), 'bad = jwt.encode({"sub": uid}, key)'].join("\n"));
  try {
    const hits = (await scan(dir)).findings.filter((f) => f.ruleId === "jwt.no-expiry").map((f) => f.line);
    assert.deepEqual(hits, [18]);
  } finally { await rm(dir, { recursive: true }); }
});

test("peer dependencies and placeholder secrets in tests are not flagged", async () => {
  const { mkdtemp, writeFile, mkdir, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-peer-"));
  await writeFile(join(dir, "package.json"), JSON.stringify({ dependencies: { a: "latest" }, peerDependencies: { react: "*" } }, null, 2));
  await mkdir(join(dir, "tests"));
  await writeFile(join(dir, "tests", "test_db.py"), 'conn = connect(password="test_password")\n');
  try {
    const f = (await scan(dir)).findings.map((x) => `${x.ruleId}@${x.file}:${x.line}`);
    assert.deepEqual(f, ["deps.unpinned-version@package.json:3"]);
  } finally { await rm(dir, { recursive: true }); }
});

test("lines marked noqa, nosec or lintsure-ignore are treated as reviewed", async () => {
  const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-noqa-"));
  await writeFile(join(dir, "m.py"), ["v = pickle.loads(blob)  # noqa: S301", "w = pickle.loads(blob)  # nosec", "x = pickle.loads(blob)"].join("\n"));
  try {
    const hits = (await scan(dir)).findings.filter((f) => f.ruleId === "deserialize.unsafe").map((f) => f.line);
    assert.deepEqual(hits, [3]);
  } finally { await rm(dir, { recursive: true }); }
});
