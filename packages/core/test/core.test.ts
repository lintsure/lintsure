import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checksFor, classify, knowledge, outsideFor, readConfig, rules, scan as coreScan, type ScanOptions } from "../src/index.js";
import { envNotIgnored } from "../src/rules/stack.js";

// Rule tests look at every finding, including the medium-confidence ones a normal run holds back.
const scan = (dir: string, fw?: Parameters<typeof coreScan>[1], opts: ScanOptions = {}) => coreScan(dir, fw, { all: true, ...opts });

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
  const got = r.findings.filter((f) => !/^(src\/(more|owasp|page|stack-client)\.|package\.json|\.github\/|supabase\/|next\.config|scripts\/|SECURITY\.md|sbom|bin\/|mobile\/|web\/|src\/llm\.)/.test(f.file)).map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.deepEqual(got, [
    "agent.config-runs-remote-code@.claude/settings.json:4",
    "agent.permissions-allow-all@.claude/settings.json:8",
    "agent.instructions-unsafe@.claude/skills/setup/SKILL.md:5",
    "agent.instructions-unsafe@.claude/skills/setup/SKILL.md:6",
    "release.env-not-ignored@.gitignore:1",
    "llm.client-controls-system@app/api/chat/route.ts:4",
    "llm.unbounded-agent-loop@app/api/chat/route.ts:5",
    "auth.no-rate-limit@app/api/login/route.ts:3",
    "ai.call-not-logged@src/ai.ts:3",
    "llm.no-output-limit@src/ai.ts:3",
    "ai.automated-decision@src/ai.ts:4",
    "ai.hides-being-ai@src/ai.ts:5",
    "ai.synthetic-media@src/ai.ts:6",
    "ai.emotion-or-biometric@src/ai.ts:7",
    "transport.plain-http@src/billing.ts:4",
    "secret.in-source@src/config.ts:2",
    "secret.in-source@src/config.ts:3",
    "mcp.tool-uses-secret@src/mcp/server.ts:3",
    "mcp.tool-runs-shell@src/mcp/server.ts:4",
    "config.debug-on@src/settings.py:2",
    "pii.logged@src/users.ts:5",
  ]);
});

test("every rule fills every field the site promises", () => {
  for (const r of rules) {
    for (const k of ["id", "title", "fix", "note", "mappedBy", "reviewedAt"] as const) assert.ok(r[k], `${r.id} missing ${k}`);
    assert.ok(r.controls.length > 0, `${r.id} has no controls`);
    assert.ok(r.test || r.fileTest || r.repoTest, `${r.id} has no test`);
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
  assert.deepEqual(s.map((x) => x.framework), ["eu-ai-act", "gdpr", "owasp-top10", "cwe-top25"]);
  assert.match(s[0].reason, /high-risk/);
  assert.deepEqual(classify({ usesAI: true }), []);
});

test("reads lintsure.config.yaml and skips frameworks not checked yet", async () => {
  const c = await readConfig(fileURLToPath(new URL("../../../../fixtures/config-app", import.meta.url)));
  assert.deepEqual(c.frameworks, ["gdpr", "cra"]);
  assert.deepEqual(c.skipped, ["pci-dss"]);
  assert.deepEqual(c.ignore, ["vendor"]);
  assert.deepEqual(await readConfig(root), { frameworks: null, skipped: [], ignore: [], rules: {}, problems: [] });
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
  // Minified: long lines throughout. A file with just one long line (a data URL, a long prompt) is still read.
  await writeFile(join(dir, "src/b.ts"), ("x".repeat(2000) + "\n").repeat(3) + bad);
  await writeFile(join(dir, "src/d.ts"), "const icon = \"" + "x".repeat(2000) + "\";\n" + "const a = 1;\n".repeat(30) + bad);
  await writeFile(join(dir, "src/c.min.js"), bad);
  await writeFile(join(dir, "tests/a.ts"), bad);
  await writeFile(join(dir, ".output/a.js"), bad);
  await writeFile(join(dir, "dist/a.js"), bad);
  await writeFile(join(dir, "lintsure.config.yaml"), "ignore:\n  - tests/\n");
  const r = await scan(dir);
  assert.deepEqual(r.findings.filter((f) => !f.ruleId.startsWith("repo.")).map((f) => f.file), ["src/a.ts", "src/d.ts"]);
});

// Scanner-level cases from the 139-repo field test. Each one ran through scan(), not just a rule's pattern,
// because the bugs were in how files are read: comments, strings, markers, paths and file types.
test("scanner: what the 139-repo field test found it was missing or getting wrong", async () => {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "ls-scan-"));
  for (const d of ["app", "api/spec", "examples", "vendor/lib", "supabase/migrations"]) await mkdir(join(dir, d), { recursive: true });
  const files: Record<string, string> = {
    // Code after a multi-line prompt string used to be read as a docstring and skipped.
    "app/agent.py": 'PROMPT = """\nYou are helpful.\n"""\nimport os\nos.system("rm -rf " + request.args["p"])\n',
    // A line-length marker for another linter must not hide a live key.
    // Fake keys are split in the source so secret scanners don't mistake this test for a leak.
    "app/keys.py": 'STRIPE = "sk_' + 'live_51HabcdefghijklmnopQRSTUVWX12345"  # noqa: E501\n',
    // A comment before code on the same line doesn't make the code a comment.
    "app/run.js": "/* istanbul ignore next */ eval(req.body.code);\n",
    // .mts files and .env.local were never read.
    "app/server.mts": "eval(req.body.code);\n",
    ".env.local": "NEXT_PUBLIC_OPENAI_API_KEY=sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123\n",
    // A secret that falls back to text in the code.
    "app/auth.py": 'JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")\n',
    // "lintsure-ignore" inside a string is not a marker.
    "app/msg.js": 'eval(req.body.code); const note = "lintsure-ignore";\n',
    // Not shipped: examples and vendored code stay quiet.
    "examples/demo.js": "eval(req.body.code);\n",
    "vendor/lib/jquery.js": "elem.innerHTML = value;\n",
    // A commented-out RLS statement doesn't switch RLS on.
    "supabase/migrations/1.sql": "create table notes (id int);\n-- alter table notes enable row level security;\n",
  };
  for (const [p, t] of Object.entries(files)) await writeFile(join(dir, p), t);
  const r = await scan(dir);
  const got = new Set(r.findings.map((f) => `${f.ruleId}@${f.file}`));
  for (const want of ["cmd.shell-built@app/agent.py", "secret.in-source@app/keys.py", "code.eval@app/run.js", "code.eval@app/server.mts",
    "secret.public-env@.env.local", "config.default-secret-key@app/auth.py", "code.eval@app/msg.js", "supabase.rls-disabled@supabase/migrations/1.sql"])
    assert.ok(got.has(want), `missed ${want}`);
  for (const unwanted of ["code.eval@examples/demo.js", "xss.raw-html@vendor/lib/jquery.js"]) assert.ok(!got.has(unwanted), `flagged ${unwanted}`);
});

test("rules: false alarms from the 139-repo field test stay quiet", async () => {
  const { rules } = await import("../src/index.js");
  const t = (id: string, line: string) => rules.find((r) => r.id === id)!.test!(line);
  assert.equal(t("sql.string-built", "throw new Error(`Could not update user ${id} from ${source}`);"), false);
  assert.equal(t("sql.string-built", "db.prepare(`SELECT * FROM ${TABLE} WHERE id = ?`)"), false);
  assert.equal(t("cmd.shell-built", "const m = pattern.exec(`${prefix}-${id}`);"), false);
  assert.equal(t("ai.hides-being-ai", "Act as a human resources advisor and answer policy questions."), false);
  assert.equal(t("ai.automated-decision", "const s = score(hand); status = 'denied'"), false);
  assert.equal(t("auth.hardcoded-password", "{ email: \"string\", password: \"string\" }"), false);
  assert.equal(t("crypto.weak-password-hash", "const ha1 = md5(`${user}:${realm}:${password}`); // HTTP Digest"), false);
  assert.equal(t("deserialize.unsafe", "const cfg = yaml.load(text, { schema: JSON_SCHEMA });"), false);
  assert.equal(t("transport.plain-http", "fetch(\"http://redis:6379/health\")"), false);
  // and the real thing still fires
  assert.equal(t("sql.string-built", "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)"), true);
  assert.equal(t("config.default-secret-key", "const secret = process.env.SESSION_SECRET || \"dev-secret-2026\";"), true);
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
  await writeFile(join(dir, "src/a.ts"), "console.log(user.email);\napp.use(cors({ origin: \"*\", credentials: true }));\n");
  const first = await scan(dir);
  await writeFile(join(dir, BASELINE_FILE), JSON.stringify(toBaseline(first, "2026-01-01")));
  const baseText = JSON.stringify(toBaseline(first, "2026-01-01"));
  assert.doesNotMatch(baseText, /console|cors\(/, "baseline must not contain code");

  const cors = first.findings.find((f) => f.ruleId === "cors.any-origin")!;
  await writeFile(join(dir, ACCEPTED_FILE), `- rule: cors.any-origin\n  where: src/a.ts\n  fingerprint: ${cors.fingerprint}\n  reason: Public read-only API\n  accepted_by: J. Smith\n  date: 2026-01-01\n  review_by: 2099-01-01\n`);
  await writeFile(join(dir, "src/a.ts"), "// moved\napp.use(cors({ origin: \"*\", credentials: true }));\nconst h = md5(user.password);\n");
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
  // Hand-typed fake keys in tests are skipped; a random-looking one is still flagged.
  await writeFile(join(dir, "tests", "keys.test.ts"), [
    'bot_token = "xoxb-slack-bot-token"', 'const t = "ghp_abcdefghijklmnopqrstuvwxyz0123";',
    "const PEM = '-----BEGIN RSA PRIVATE KEY-----\\nabc\\n-----END RSA PRIVATE KEY-----';", 'const real = "sk-proj-WZRTVpVvZEXF5s0H4y8N5n2BF6lRZhC79Zq";',
  ].join("\n") + "\n");
  try {
    const f = (await scan(dir)).findings.filter((x) => !x.ruleId.startsWith("repo.")).map((x) => `${x.ruleId}@${x.file}:${x.line}`);
    assert.deepEqual(f, ["deps.unpinned-version@package.json:3", "secret.in-source@tests/keys.test.ts:4"]);
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

test("AI calls are recognised in the forms real apps use, and need a record nearby", async () => {
  const { unloggedAiCalls } = await import("../src/rules/index.js");
  const calls = [
    "const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST' });",
    "const result = await chain.invoke({ input });",
    "const response = await ai.models.generateContent({ model, contents });",
    "const c = await openAi.chat.completions.create({ model });",
    "const { object } = await generateObject({ model, schema });",
  ];
  for (const c of calls) assert.deepEqual(unloggedAiCalls([c]), [1], c);
  assert.deepEqual(unloggedAiCalls(["const { data } = await supabase.functions.invoke('generate-title');"]), []);
  assert.deepEqual(unloggedAiCalls(["const r = await chain.invoke({ input });", "await db.insert(aiLogs).values({ output: r });"]), []);
  // A log far away in the same file no longer hides the call; one finding per file, at the first unrecorded call.
  assert.deepEqual(unloggedAiCalls(["console.log('boot');", ...Array(40).fill(""), "const r = await chain.invoke({ input });", "const s = await chain.invoke({ more });"]), [42]);
  // A provider URL in a constant is not a call.
  assert.deepEqual(unloggedAiCalls(['OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"']), []);
  const { mediaModelCalls } = await import("../src/rules/index.js");
  assert.deepEqual(mediaModelCalls(["const MODEL = 'gemini-2.5-flash-image';", "const r = await ai.models.generateContent({ model: MODEL });"]), [2]);
  assert.deepEqual(mediaModelCalls(['DEEPGRAM_TTS_MODELS = ("aura-2", "flux")', "r = client.chat.completions.create(model=m)"]), []);
});

test("Supabase: tables without row level security are found, system schemas and enabled tables are not", async () => {
  const { tablesWithoutRls } = await import("../src/rules/stack.js");
  assert.deepEqual(tablesWithoutRls([
    "create table public.profiles (id uuid);",
    "create table if not exists \"posts\" (id uuid);",
    "alter table posts enable row level security;",
    "create table auth.extra (id uuid);",
    "CREATE TABLE Orders (id int);",
  ]), [1, 5]);
});

test("repository checks: a SECURITY.md in .github/ and an SPDX file count, and only CRA turns them on", async () => {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "ls-"));
  const repo = async (fw: Parameters<typeof scan>[1]) => (await scan(dir, fw)).findings.filter((f) => f.ruleId.startsWith("repo.")).map((f) => `${f.ruleId}@${f.file}`);
  assert.deepEqual(await repo(["gdpr"]), []);
  assert.deepEqual(await repo(["cra"]), ["repo.no-dependency-updates@.github/dependabot.yml", "repo.no-sbom@sbom.cdx.json", "repo.no-security-policy@SECURITY.md"]);
  await mkdir(join(dir, ".github"));
  await writeFile(join(dir, ".github/SECURITY.md"), "Report issues to security@example.com\n");
  await writeFile(join(dir, "app.spdx.json"), "{}\n");
  await writeFile(join(dir, "renovate.json"), "{}\n");
  assert.deepEqual(await repo(["cra"]), []);
});

test("row level security switched on in a later migration counts; the report lists Gaps first", async () => {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-rls-"));
  await mkdir(join(dir, "supabase/migrations"), { recursive: true });
  await writeFile(join(dir, "supabase/migrations/001_init.sql"), "create table notes (id uuid primary key);\ncreate table secrets (id uuid);\n");
  await writeFile(join(dir, "supabase/migrations/002_rls.sql"), "alter table notes enable row level security;\n");
  const r = await scan(dir, ["gdpr"]);
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "supabase.rls-disabled").map((f) => `${f.file}:${f.line}`), ["supabase/migrations/001_init.sql:2"]);
  const md = toMarkdown(await scan(root));
  assert.ok(md.indexOf("Gap") < md.indexOf("Partial"), "Gaps come before Partials");
});

test("rule packs: only @lintsure/pack-* names load, and a registered pack adds its framework and rules", async () => {
  const { loadPacks, registerPack, ALL_FRAMEWORKS: fws } = await import("../src/index.js");
  assert.deepEqual(await loadPacks(["evil-package", "../../steal", "@lintsure/pack-not-installed"]), ["evil-package", "../../steal", "@lintsure/pack-not-installed"]);
  registerPack({ id: "@lintsure/pack-test", forExisting: { "sql.string-built": [{ framework: "test-pack", id: "T.1", title: "Test control" }] },
    knowledge: [{ id: "test-pack", name: "Test pack", kind: "standard", summary: "", whoItAppliesTo: "", applies: () => null, obligations: [], watchOut: [], checkedOn: "2026-11-09" }],
    rules: [] });
  assert.ok(fws.includes("test-pack"));
  const r = await scan(root, ["test-pack"]);
  assert.ok(r.findings.length > 0 && r.findings.every((f) => f.ruleId === "sql.string-built"));
});

// Cases from the improvement review (research/improvement-review.md, P-numbers). Each ran through scan(), and each
// failed on 0.3.6. Fake keys are built at run time so this file never holds a key-shaped string.
async function tinyRepo(files: Record<string, string>) {
  const { mkdtemp, mkdir, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os"); const { join, dirname } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "ls-review-"));
  for (const [p, t] of Object.entries(files)) { await mkdir(dirname(join(dir, p)), { recursive: true }); await writeFile(join(dir, p), t); }
  return dir;
}
const got = (r: Awaited<ReturnType<typeof scan>>) => new Set(r.findings.filter((f) => !f.ruleId.startsWith("repo.")).map((f) => `${f.ruleId}@${f.file}`));

test("review P3/P1: route folders named demo, docs, samples or test are live code, and nothing skipped is Met", async () => {
  const bad = "export async function POST(req) {\n  return Response.json(eval(req.body.code));\n}\n";
  const paths = ["app/api/demo/route.ts", "app/docs/actions.ts", "src/samples/handler.ts", "supabase/functions/test/index.ts"];
  const r = await scan(await tinyRepo(Object.fromEntries([...paths.map((p) => [p, bad]), ["examples/site/app/page.tsx", bad], ["src/tests/a.ts", bad]])));
  for (const p of paths) assert.ok(got(r).has(`code.eval@${p}`), `missed ${p}`);
  assert.ok(!got(r).has("code.eval@examples/site/app/page.tsx") && !got(r).has("code.eval@src/tests/a.ts"), "examples and tests stay skipped");
  const only = await scan(await tinyRepo({ "tests/only.ts": bad }));
  assert.ok(!only.met.some((m) => m.ruleId === "code.eval"), "a rule that only met skipped files is not Met");
});

test("review P2: controls with no check points say not checked", async () => {
  const r = await scan(await tinyRepo({ "schema.sql": "select 1;\n" }));
  const rows = r.record!.byControl;
  assert.ok(rows.every((b) => b.checkPoints > 0 || b.result === "not checked"));
  assert.ok(rows.some((b) => b.result === "not checked"));
});

test("review P8, P13, P14, P19-P21, P11, P17: misses and false alarms", async () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = `${b64({ alg: "HS256" })}.${b64({ iss: "supabase", role: "service_role", exp: 2000000000 })}.q3Zk9vTn1LrXw8yB2mHc5dJf7gKs0p`;
  const ak = "AKIA" + "QZ7MVN3KPL2XW8RT";
  const r = await scan(await tinyRepo({
    "app.py": 'import os\n# Use """ for docstrings in this module\ndef run():\n    os.system("rm -rf " + request.args["p"])\n',
    "deploy.sh": `export AWS_ACCESS_KEY_ID=${ak}\n`, "infra/main.tf": `access_key = "${ak}"\n`, "Dockerfile": `ENV AWS_ACCESS_KEY_ID=${ak}\n`,
    "src/admin.ts": `const key = "${jwt}";\n`,
    "src/db.ts": `const url = "postgres://app:Xk92mQpL7v@db.prod-cluster.acmecorp.net:5432/app";\n`,
    ".env": "NEXT_PUBLIC_FIREBASE_ADMIN_PRIVATE_KEY=abc\nVITE_POSTHOG_PERSONAL_API_KEY=abc\nNEXT_PUBLIC_DATABASE_URL=abc\nNEXT_PUBLIC_SUPABASE_ANON_KEY=abc\n",
    "src/types.ts": "export const Fields = { Secret: 'secret', SECRET: \"SECRET\" };\nconst col = { password: 'String', PASSWORD: \"SECRET\" };\n",
    "auth.py": "import jwt\nhdr = jwt.decode(token, options={\"verify_signature\": False})\nkey = keys[hdr[\"kid\"]]\ndata = jwt.decode(token, key, algorithms=[\"RS256\"])\n",
    "supabase/config.toml": "[functions.wipe]\nverify_jwt = false\n[functions.note]\nverify_jwt = false\n",
    "supabase/functions/wipe/index.ts": "const authHeader = req.headers.get(\"Authorization\");\nconst admin = createClient(url, Deno.env.get(\"SUPABASE_SERVICE_ROLE_KEY\"));\nawait admin.from(\"rows\").delete();\n",
    "supabase/functions/note/index.ts": "// TODO: call verifyToken( ) here\nconst admin = createClient(url, Deno.env.get(\"SUPABASE_SERVICE_ROLE_KEY\"));\n",
    ".github/workflows/a.yml": "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log(\"${{ github.event.issue.title }}\")\n",
  }));
  const g = got(r);
  for (const want of ["cmd.shell-built@app.py", "secret.in-source@deploy.sh", "secret.in-source@infra/main.tf", "secret.in-source@Dockerfile",
    "secret.in-source@src/admin.ts", "secret.in-source@src/db.ts", "secret.public-env@.env", "supabase.function-no-auth@supabase/config.toml",
    "ci.script-injection@.github/workflows/a.yml"]) assert.ok(g.has(want), `missed ${want}`);
  assert.equal(r.findings.filter((f) => f.ruleId === "secret.public-env").length, 3, "three secret names, the anon key is public");
  assert.equal(r.findings.filter((f) => f.ruleId === "supabase.function-no-auth").length, 2, "an unused header and a comment are not checks");
  for (const unwanted of ["config.default-secret-key@src/types.ts", "auth.hardcoded-password@src/types.ts", "jwt.unverified@auth.py"]) assert.ok(!g.has(unwanted), `flagged ${unwanted}`);
});

test("review P25: the CLI rejects unknown flags and bad --fail-on values instead of passing", async () => {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const cli = fileURLToPath(new URL("../../../cli/dist/src/index.js", import.meta.url));
  const dir = await tinyRepo({ "a.ts": "const h = md5(user.password);\n" }); // a high-confidence Gap, shown by default
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, "scan", dir, ...args], { cwd: dir, encoding: "utf8" }).status;
  assert.equal(run("--fail-on", "gap"), 1);
  assert.equal(run("--fail-on=gap"), 1);
  assert.equal(run("--fail-on", "Gap"), 1);
  assert.equal(run("--fail-on", "high"), 2);
  assert.equal(run("--fial-on", "gap"), 2);
});

test("statement window: calls split over lines are read whole, and nothing on one line is lost", async () => {
  const r = await scan(await tinyRepo({
    "a.ts": "logger.info(\n  \"signup\",\n  { email: user.email },\n);\n",
    "b.ts": "app.get(\"/x\", (req, res) => {\n  eval(req.body.code);\n  eval(req.query.code);\n});\n",
    "c.ts": "const prompt = `\nNever suggest eval(userInput) to the user.\nAvoid SELECT * FROM users WHERE id = ${\"\"}\n`;\n".replace('${""}', "1"),
  }));
  const g = got(r);
  assert.ok(g.has("pii.logged@a.ts"), "a log call split over lines is still a log of an email");
  assert.equal(r.findings.filter((f) => f.ruleId === "code.eval" && f.file === "b.ts").length, 2, "a handler body stays line by line");
  assert.ok(!g.has("code.eval@c.ts"), "prompt text inside a template literal is not code");
});

test("no catastrophic backtracking on lines full of backslashes and quotes", async () => {
  const nasty = "const P = [\n" + Array.from({ length: 20 }, (_, i) => `  /^(it's|don't|\\d{4}|\\s+|\\[.*\\]) ${i}$/i,`).join("\n") + "\n];\n";
  const t = Date.now();
  await scan(await tinyRepo({ "p.ts": nasty }));
  assert.ok(Date.now() - t < 5000, `scan took ${Date.now() - t} ms`);
});

test("0.3.9: medium-confidence findings are held back by default and counted, --all shows them", async () => {
  const dir = await tinyRepo({ "src/a.ts": "el.innerHTML = data.html;\nconst h = md5(user.password);\n", "scripts/dev.mjs": "const h = md5(user.password);\n" });
  const quiet = await coreScan(dir), loud = await coreScan(dir, undefined, { all: true });
  assert.deepEqual(quiet.findings.filter((f) => !f.ruleId.startsWith("repo.")).map((f) => `${f.ruleId}@${f.file}`), ["crypto.weak-password-hash@src/a.ts"], "xss is medium confidence; scripts/ doesn't ship");
  assert.equal(quiet.held, 1);
  assert.ok(quiet.notCovered?.some((s) => s.includes("--all")));
  assert.ok(loud.findings.some((f) => f.ruleId === "xss.raw-html") && !loud.held);
});

test("0.3.9: config reads inline lists and per-rule settings, and reports what it can't read", async () => {
  const dir = await tinyRepo({
    "lintsure.config.yaml": "frameworks: [gdpr, owasp-top10]\nrules:\n  crypto.weak-password-hash: off\n  pii.logged: low\n",
    "a.ts": "const h = md5(user.password);\nconsole.log(user.email);\n",
  });
  const c = await readConfig(dir);
  assert.deepEqual(c.frameworks, ["gdpr", "owasp-top10"]);
  assert.deepEqual(c.problems, []);
  const r = await coreScan(dir, c.frameworks!);
  assert.deepEqual(r.findings.map((f) => `${f.ruleId}:${f.severity}`), ["pii.logged:low"]);
  assert.deepEqual(r.rulesOff, ["crypto.weak-password-hash"]);
  const bad = await readConfig(await tinyRepo({ "lintsure.config.yaml": "framework: [gdpr]\nrules:\n  no.such-rule: off\n  pii.logged: maybe\n" }));
  assert.equal(bad.problems.length, 3, bad.problems.join("; "));
});

test("0.3.9: --diff lists only findings on changed lines; a bad config stops the CLI", async () => {
  const { spawnSync, execFileSync } = await import("node:child_process");
  const { writeFile } = await import("node:fs/promises");
  const cli = fileURLToPath(new URL("../../../cli/dist/src/index.js", import.meta.url));
  const dir = await tinyRepo({ "a.ts": "const h = md5(user.password);\n" });
  const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", ...a], { cwd: dir });
  git("init", "-q"); git("add", "."); git("commit", "-qm", "base");
  await writeFile(join(dir, "a.ts"), "const h = md5(user.password);\nconst k = sha1(req.body.password);\n");
  const out = spawnSync(process.execPath, [cli, "scan", dir, "--diff", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout;
  assert.match(out, /a\.ts:2/); assert.doesNotMatch(out, /a\.ts:1 /);
  await writeFile(join(dir, "lintsure.config.yaml"), "framworks: [gdpr]\n");
  assert.equal(spawnSync(process.execPath, [cli, "scan", dir], { cwd: dir, encoding: "utf8" }).status, 2);
});

test("the triage skill file and the MCP triage prompt carry the same text", async () => {
  const { TRIAGE_GUIDE } = await import("../src/index.js");
  const md = (await readFile(fileURLToPath(new URL("../../../../skills/lintsure-triage/SKILL.md", import.meta.url)), "utf8")).replace(/\r\n/g, "\n");
  assert.equal(md.replace(/^---\n[\s\S]*?\n---\n\n/, "").trimEnd(), TRIAGE_GUIDE);
});

test("policy fingerprint: same policy same code, any setting change a new code", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { toMarkdown, toSarif } = await import("../src/index.js");
  const a = await scan(root), b = await scan(root);
  assert.match(a.policy!.fingerprint, /^[0-9A-F]{4}-[0-9A-F]{4}$/);
  assert.equal(a.policy!.fingerprint, b.policy!.fingerprint);
  assert.equal(a.policy!.sha256.slice(0, 8).toUpperCase(), a.policy!.fingerprint.replace("-", ""));
  // Fewer frameworks, a rule switched off, or a re-rated rule each change the code.
  assert.notEqual((await scan(root, ["gdpr"])).policy!.fingerprint, a.policy!.fingerprint);
  const dir = await mkdtemp(join(tmpdir(), "ls-pol-"));
  await writeFile(join(dir, "lintsure.config.yaml"), "rules:\n  pii.logged: off\n");
  const off = await scan(dir);
  await writeFile(join(dir, "lintsure.config.yaml"), "rules:\n  pii.logged: low\n");
  const low = await scan(dir);
  const none = await scan(clean);
  assert.notEqual(off.policy!.fingerprint, none.policy!.fingerprint);
  assert.notEqual(low.policy!.fingerprint, none.policy!.fingerprint);
  assert.notEqual(off.policy!.fingerprint, low.policy!.fingerprint);
  // The Drift Guard's .lintsure/rules.yml counts: adding it changes the code, a comment or blank line doesn't.
  const { mkdir } = await import("node:fs/promises");
  const rdir = await mkdtemp(join(tmpdir(), "ls-rules-"));
  const plain = await scan(rdir);
  assert.equal(plain.policy!.repoRules, false);
  await mkdir(join(rdir, ".lintsure"));
  await writeFile(join(rdir, ".lintsure", "rules.yml"), "rules:\n  - protect: prisma/schema.prisma\n");
  const withRules = await scan(rdir);
  assert.equal(withRules.policy!.repoRules, true);
  assert.notEqual(withRules.policy!.fingerprint, plain.policy!.fingerprint);
  await writeFile(join(rdir, ".lintsure", "rules.yml"), "# owned by platform\nrules:\n\n  - protect: prisma/schema.prisma   # schema\n");
  assert.equal((await scan(rdir)).policy!.fingerprint, withRules.policy!.fingerprint);
  await writeFile(join(rdir, ".lintsure", "rules.yml"), "rules:\n  - protect: prisma/migrations/**\n");
  assert.notEqual((await scan(rdir)).policy!.fingerprint, withRules.policy!.fingerprint);
  // Account rules handed in by the plugin count too; their key order doesn't, their content does.
  const ws1 = await scan(rdir, undefined, { workspaceRules: { rules: [{ id: "W1", avoid: "eval(" }], mode: "strict" } });
  const ws2 = await scan(rdir, undefined, { workspaceRules: { mode: "strict", rules: [{ avoid: "eval(", id: "W1" }] } });
  const ws3 = await scan(rdir, undefined, { workspaceRules: { rules: [{ id: "W1", avoid: "exec(" }], mode: "strict" } });
  assert.equal(ws1.policy!.workspaceRules, true);
  assert.equal(ws1.policy!.fingerprint, ws2.policy!.fingerprint);
  assert.notEqual(ws1.policy!.fingerprint, ws3.policy!.fingerprint);
  assert.notEqual(ws1.policy!.fingerprint, (await scan(rdir)).policy!.fingerprint);
  // The code travels with the report.
  assert.ok(toMarkdown(a).includes(`Policy #${a.policy!.fingerprint}`));
  assert.equal(toSarif(a, "0").runs[0].properties!["lintsure/policyFingerprint"], a.policy!.fingerprint);
});

test("Partial findings say what Lintsure couldn't see, Gaps don't", async () => {
  const r = await scan(root);
  const partial = r.findings.filter((f) => f.status === "partial"), gap = r.findings.filter((f) => f.status === "gap");
  assert.ok(partial.length && partial.every((f) => f.unseen && f.unseen.length > 20));
  assert.ok(gap.every((f) => f.unseen === undefined));
});

test("plan_checks: a described feature maps to the checks it is likely to meet", () => {
  assert.ok(checksFor("users upload a profile picture stored in Supabase").some((r) => r.id === "upload.unrestricted"));
  assert.ok(checksFor("a chat with Claude for customer tickets").some((r) => r.id.startsWith("llm.") || r.id.startsWith("ai.")));
  assert.equal(checksFor("dark mode toggle").length, 0);
  assert.deepEqual(checksFor("login page with password"), checksFor("login page with password"));
});

test("policy fingerprint is the same on every OS", async () => {
  // A fixed value, so CI on Linux catches any difference from Windows or macOS (paths, line endings).
  // It moves with every rules version: update it in the release commit.
  const r = await scan(root);
  assert.equal(r.policy?.fingerprint, "24BF-09DA");
});

test("env files not ignored: Gap with a secret, Partial with public settings, quiet when ignored or example-only", () => {
  const gi = ["node_modules", "dist"];
  assert.deepEqual(envNotIgnored(gi, "", { ".env": "VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9\nVITE_SUPABASE_URL=https://x.supabase.co" }), [{ line: 1, status: "partial" }]);
  assert.deepEqual(envNotIgnored(gi, "", { ".env.local": "SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiJ9" }), [{ line: 1, status: "gap" }]);
  assert.deepEqual(envNotIgnored(gi, "", { ".env": "SUPABASE_PUBLISHABLE_KEY=eyJhbGciOiJIUzI1NiJ9" }), [{ line: 1, status: "partial" }]);
  assert.deepEqual(envNotIgnored([...gi, ".env*"], "", { ".env": "SECRET_KEY=abcdefghijk" }), []);
  assert.deepEqual(envNotIgnored(gi, "", { ".env.example": "SECRET_KEY=changeme-please" }), []);
  assert.deepEqual(envNotIgnored(["!.env.example"], "", { ".env": "A=1" }), [{ line: 1, status: "partial" }]);
});

test("patch fixes: exact changes only where the fix is unambiguous", async () => {
  const t = (id: string, l: string) => rules.find((r) => r.id === id)!.patch!(l);
  assert.equal(t("transport.tls-verify-off", "requests.get(url, verify=False)"), "requests.get(url, verify=True)");
  assert.equal(t("transport.tls-verify-off", "https.Agent({ rejectUnauthorized: false })"), "https.Agent({ rejectUnauthorized: true })");
  assert.equal(t("transport.tls-verify-off", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'"), "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'");
  assert.equal(t("session.cookie-insecure", "res.cookie('sid', v, { httpOnly: false, secure: false })"), "res.cookie('sid', v, { httpOnly: true, secure: true })");
  const r = await scan(root);
  const env = r.findings.find((f) => f.ruleId === "release.env-not-ignored")!;
  assert.equal(env.patch?.old, null);
  assert.match(env.patch!.text, /^# .*\n\.env\n/);
  const maps = r.findings.find((f) => f.ruleId === "build.sourcemaps-public")!;
  assert.match(maps.patch!.text, /productionBrowserSourceMaps: false/);
  assert.ok(r.findings.filter((f) => f.patch && f.patch.old != null).every((f) => f.patch!.text !== f.patch!.old));
});

test("the numbers the README states match the code", async () => {
  // A count in the docs that drifts from the rule registry is a false claim (BugHunter checks its doc counts in CI).
  const readme = await readFile(fileURLToPath(new URL("../../../../README.md", import.meta.url)), "utf8");
  const stated = readme.match(/`packages\/core` \| Finding schema, (\d+) rules/);
  assert.ok(stated, "README should state the rule count");
  assert.equal(Number(stated![1]), rules.length, `README says ${stated![1]} rules, the engine has ${rules.length}`);
  for (const f of ["eu-ai-act", "gdpr", "owasp-top10", "owasp-llm", "cwe-top25", "cra"]) assert.ok(knowledge.some((k) => k.id === f));
});

test("reachability: routes reach helpers through relative and tsconfig-alias imports; unknown when an import can't be resolved", async () => {
  const { buildGraph, reachOf, resolveSpec, tsAliases } = await import("../src/reach.js");
  const files = {
    "app/api/users/route.ts": "import { getUser } from '@/lib/users';\nexport async function GET() { return getUser(); }\n",
    "src/lib/users.ts": "import { query } from './db.js';\nexport const getUser = () => query('x');\n",
    "src/lib/db.ts": "export const query = (s: string) => s;\n",
    "src/lib/orphan.ts": "export const unused = 1;\n",
    "src/lib/maybe.ts": "export const m = 1;\n",
    "src/other.ts": "import { m } from './lib/mabye-typo';\nimport x from 'react';\nconst y = require(name);\n",
  };
  const g = buildGraph(files, '{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"] } } } // comment');
  assert.equal(reachOf(g, "app/api/users/route.ts").status, "entry");
  const db = reachOf(g, "src/lib/db.ts");
  assert.equal(db.status, "reachable");
  assert.deepEqual(db.via, ["app/api/users/route.ts", "src/lib/users.ts", "src/lib/db.ts"]);
  assert.equal(reachOf(g, "src/lib/orphan.ts").status, "unreachable");
  assert.equal(resolveSpec("src/a.ts", "react", new Set(), tsAliases(null)), "external");
  assert.equal(resolveSpec("src/a.ts", "@/missing", new Set(), tsAliases(null)), null);
  assert.equal(tsAliases("{ broken").paths.length, 0);
  const g2 = buildGraph({ "src/a.ts": "import { m } from './nope/maybe';\n", "src/lib/maybe.ts": "export const m = 1;\n" }, null);
  assert.equal(reachOf(g2, "src/lib/maybe.ts").status, "unknown");
});

test("reachability: package.json main/bin and HTML <script src> count as entry points", async () => {
  const { buildGraph, declaredEntries, reachOf } = await import("../src/reach.js");
  const files = { "src/main/main.js": "require('./window');\n", "src/main/window.js": "module.exports = 1;\n", "js/app.js": "import './charts.js';\n", "js/charts.js": "export const c = 1;\n", "bin/cli.mjs": "import '../lib/run.mjs';\n", "lib/run.mjs": "export {};\n" };
  const set = new Set(Object.keys(files));
  const extra = declaredEntries({ "package.json": '{ "main": "src/main/main.js", "bin": { "x": "./bin/cli.mjs" } }' }, { "index.html": '<script type="module" src="./js/app.js?v=2"></script><script src="https://cdn.x/y.js"></script>' }, set);
  assert.deepEqual(extra.sort(), ["bin/cli.mjs", "js/app.js", "src/main/main.js"]);
  const g = buildGraph(files, null, [""], extra);
  assert.equal(reachOf(g, "src/main/window.js").status, "reachable");
  assert.equal(reachOf(g, "js/charts.js").status, "reachable");
  assert.equal(reachOf(g, "lib/run.mjs").status, "reachable");
});

test("tsconfig paths: exact keys, the * catch-all, and a package tsconfig without paths falls back", async () => {
  const { buildGraph, resolveSpec, tsAliases, reachOf } = await import("../src/reach.js");
  const files = new Set(["src/app.ts", "src/lib/x.ts", "node_modules/@apple/x/index.js"]);
  const exact = tsAliases('{ "compilerOptions": { "paths": { "@app": ["./src/app.ts"] } } }');
  assert.equal(resolveSpec("a.ts", "@app", files, exact), "src/app.ts");
  assert.equal(resolveSpec("a.ts", "@apple/x", files, exact), "external");
  const star = tsAliases('{ "compilerOptions": { "paths": { "*": ["./src/*"] } } }');
  assert.equal(resolveSpec("a.ts", "lib/x", files, star), "src/lib/x.ts");
  const g = buildGraph({ "app/page.tsx": "import { x } from '@/lib/x';\n", "packages/ui/src/a.ts": "import '@/lib/x';\n", "lib/x.ts": "export const x = 1;\n" },
    { "": '{ "compilerOptions": { "paths": { "@/*": ["./*"] } } }', "packages/ui": '{ "compilerOptions": { "strict": true } }' });
  assert.equal(reachOf(g, "lib/x.ts").status, "reachable");
  assert.ok(!g.unresolved.get("packages/ui/src/a.ts"), "the root alias applies inside the package");
});

test("code review fixes: linear import regex, YAML comments in quotes, api/ entries only at the root", async () => {
  const { specifiers, buildGraph } = await import("../src/reach.js");
  const { stripYamlComment } = await import("../src/index.js");
  const t0 = Date.now(); specifiers("import ".repeat(20000)); assert.ok(Date.now() - t0 < 200, "import regex must stay linear");
  assert.deepEqual(specifiers("import {\n  a,\n  b\n} from './x';\nexport * from \"./y\";\nimport './z.css';\nconst m = await import('./m');"), ["./x", "./y", "./z.css", "./m"]);
  assert.equal(stripYamlComment('  pattern: "rm # a"  # why'), '  pattern: "rm # a"  ');
  assert.equal(stripYamlComment("# all comment"), "");
  const g = buildGraph({ "api/hello.ts": "export default 1;\n", "src/lib/api/client.ts": "export const c = 1;\n" });
  assert.ok(g.entries.has("api/hello.ts") && !g.entries.has("src/lib/api/client.ts"));
});

test("blankStrings empties quoted text in one pass, even on an unclosed quote with many escapes", async () => {
  const { blankStrings } = await import("../src/index.js");
  assert.equal(blankStrings(`fs.readFileSync("x" + req.query.p)`), `fs.readFileSync("" + req.query.p)`);
  assert.equal(blankStrings(`it's fetch(req.query.u)`), `it's fetch(req.query.u)`); // an unclosed quote is left alone
  const t = Date.now(); blankStrings("'" + "\'".repeat(200_000));
  assert.ok(Date.now() - t < 200, "linear time (CodeQL js/polynomial-redos)");
});

test("files a rule wanted but couldn't read are counted, not silently passed", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-"));
  await writeFile(join(dir, "app.js"), "const a = 1;\n");
  await writeFile(join(dir, "blob.js"), Buffer.from([0x63, 0x00, 0x64]));
  const r = await coreScan(dir);
  assert.equal(r.filesSkipped, 1);
  assert.ok(r.notCovered?.some((l) => l.includes("not checked, not clean")));
});

test("MCP rules: shell and shared credentials only in files that register tools", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-"));
  await writeFile(join(dir, "server.ts"), `import { execSync } from "node:child_process";\nconst token = process.env.GITHUB_TOKEN;\nserver.registerTool("run", {}, async ({ cmd }) => ({ content: [{ type: "text", text: execSync(cmd).toString() }] }));\n`);
  // regex.exec( and db.exec( are not shells; a tool whose name is on the next line still counts.
  await writeFile(join(dir, "regex.ts"), `server.registerTool(\n  "parse",\n  {},\n  async ({ s }) => ({ content: [{ type: "text", text: /a(b)/.exec(s)?.[1] ?? "" }] }),\n);\nconst m = db.exec("select 1");\n`);
  await writeFile(join(dir, "multi.ts"), `import cp from "node:child_process";\nserver.registerTool(\n  "git",\n  {},\n  async ({ args }) => cp.execSync("git " + args),\n);\n`);
  await writeFile(join(dir, "build.ts"), `import { execSync } from "node:child_process";\nexecSync("tsc");\nconst t = process.env.NPM_TOKEN;\n`);
  const r = await coreScan(dir, undefined, { all: true });
  const hits = r.findings.filter((f) => f.ruleId.startsWith("mcp.")).map((f) => `${f.ruleId} ${f.file}:${f.line}`);
  assert.deepEqual(hits.sort(), ["mcp.tool-runs-shell multi.ts:5", "mcp.tool-runs-shell server.ts:3", "mcp.tool-uses-secret server.ts:2"]);
});

test("Lintsure's own report files are never scanned", async () => {
  const { mkdtemp, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(join(tmpdir(), "ls-"));
  for (const f of ["lintsure-report.json", "lintsure.sarif", "lintsure-assessment.html"]) await writeFile(join(dir, f), `{"text": "- /var/run/docker.sock:/var/run/docker.sock"}\n`);
  await writeFile(join(dir, "compose.yml"), "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n");
  const r = await coreScan(dir, undefined, { all: true });
  assert.deepEqual(r.findings.filter((f) => f.ruleId === "docker.socket-mounted").map((f) => f.file), ["compose.yml"]);
});

test("enclosingKeys matches enclosingKey line by line, and stays fast on a large JSON file", async () => {
  const { enclosingKey, enclosingKeys } = await import("../src/index.js");
  const json = JSON.stringify({ a: { examples: { bad: "x", good: { deep: 1 } }, code: "y" }, list: [{ k: 1 }, { k: 2 }] }, null, 2).split("\n");
  assert.deepEqual(enclosingKeys(json), json.map((_, i) => enclosingKey(json, i)));
  const big = JSON.stringify(Object.fromEntries(Array.from({ length: 20000 }, (_, i) => [`k${i}`, { v: i }])), null, 2).split("\n");
  const t = Date.now(); enclosingKeys(big);
  assert.ok(Date.now() - t < 1000, "one pass, not one walk per line");
});

test("field-test fixes: extractall with filter after nested parens, webbrowser.open, alias maps; real cases still caught", async () => {
  const r = rules.find((x) => x.id === "path.user-input")!, s = rules.find((x) => x.id === "config.default-secret-key")!;
  assert.equal(r.test!('tf.extractall(str(skills), filter="data")'), false);
  assert.equal(r.test!("tf.extractall(str(skills))"), "partial");
  assert.equal(r.test!("webbrowser.open(request.args.get('url'))"), false);
  assert.equal(r.test!("with open(request.args.get('path')) as f:"), true);
  assert.equal(s.test!('const MODE = { user: "user", none: "none", secret: "secret" };'), false);
  assert.equal(s.test!("app.use(session({ secret: 'secret', resave: false }))"), true);
});

test("field-test fixes: chmod mask, MCP exec helper with no process module", async () => {
  const w = rules.find((x) => x.id === "fs.world-writable")!;
  assert.equal(w.test!("os.chmod(path, st.st_mode & 0o777)"), false);
  assert.equal(w.test!("fs.chmodSync(dir, 0o777)"), true);
  const m = rules.find((x) => x.id === "mcp.tool-runs-shell")!;
  assert.deepEqual(m.fileTest!(['server.registerTool("remember", {}, async (a) => exec(a));']), []);
  assert.deepEqual(m.fileTest!(['import { exec } from "node:child_process";', 'server.registerTool("run", {}, async (a) => exec(a.cmd));']), [2]);
});
