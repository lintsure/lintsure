// Starts the MCP server and checks every tool reply ends with the disclaimer
// and that the server sends its agent guidance. Run: node scripts/mcp-smoke.mjs
import { spawn } from "node:child_process";
import { DISCLAIMER, AGENT_GUIDANCE, APPROVAL_RULES, FORBIDDEN_CLAIMS, NOT_A_VERDICT, TRIAGE_GUIDE } from "../packages/core/dist/src/index.js";

const p = spawn(process.execPath, ["packages/mcp/dist/src/index.js"], { stdio: ["pipe", "pipe", "inherit"] });
let buf = ""; const waiters = new Map();
p.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiters.get(m.id)?.(m); } });
let id = 0;
const call = (method, params) => new Promise((res) => { const n = ++id; waiters.set(n, res); p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: n, method, params }) + "\n"); });
const fail = (msg) => { console.error("FAIL", msg); p.kill(); process.exit(1); };

const init = await call("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "smoke", version: "1" } });
if (init.result.instructions !== AGENT_GUIDANCE) fail("server instructions missing");
p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
const tools = (await call("tools/list", {})).result.tools;
for (const t of tools) if (t.annotations?.readOnlyHint !== true || t.annotations?.destructiveHint !== false) fail(`${t.name} is not marked read-only`);
console.log("ok read-only hints on", tools.length, "tools");
// Context budget: the tool list is read into every agent session (REA's lesson). Keep it small.
const listBytes = JSON.stringify(tools).length;
if (listBytes > 9000) fail(`tools/list is ${listBytes} bytes, over the 9000 budget`);
console.log("ok tools/list size", listBytes, "bytes");
const calls = [
  ["scan", { path: "fixtures/sample-app" }],
  ["classify", { euUsers: true, personalData: true }],
  ["classify", {}],
  ["classify", { digitalProductEU: true }],
  ["explain_framework", { framework: "gdpr" }],
  ["explain_framework", { framework: "cra" }],
  ["explain_rule", { ruleId: "pii.logged" }],
  ["plan_checks", { feature: "users upload a profile picture stored in Supabase" }],
];
for (const [name, args] of calls) {
  const r = await call("tools/call", { name, arguments: args });
  const texts = r.result?.content?.map((c) => c.text) ?? [];
  if (!texts.at(-1)?.includes(DISCLAIMER)) fail(`${name} reply has no disclaimer`);
  // The fixed disclaimer sentences are negations, so they're removed before the check.
  const body = texts.join(" ").split(NOT_A_VERDICT).join("").split(DISCLAIMER).join("");
  if (FORBIDDEN_CLAIMS.some((re) => re.test(body))) fail(`${name} reply reads like a verdict`);
  if ((name === "scan" || name === "explain_rule") && !texts.join(" ").includes(APPROVAL_RULES)) fail(`${name} reply misses the approval rules`);
  if (name === "classify" && Object.keys(args).length === 0 && !/Ask the user these questions[\s\S]*- digitalProductEU:/.test(texts.join(" "))) fail("classify with no answers should return every question");
  if (name === "classify" && args.digitalProductEU && !texts.join(" ").includes("Cyber Resilience Act")) fail("classify should suggest the Cyber Resilience Act");
  console.log("ok", name);
}
// Bad input gets an error answer, never a crash, and the server keeps answering afterwards.
const bad = [
  ["scan", { path: 42 }], ["explain_rule", {}], ["explain_framework", { framework: "nope" }],
  ["plan_checks", { feature: "x".repeat(5000) }], ["classify", { euUsers: "yes" }], ["no_such_tool", {}],
];
for (const [name, args] of bad) {
  const r = await call("tools/call", { name, arguments: args });
  if (!r.error && !r.result?.isError) fail(`${name} accepted bad input ${JSON.stringify(args).slice(0, 60)}`);
}
// Generated from each tool's own input schema (HexBrain's lesson): every field gets a wrong type, and every tool gets
// non-object arguments, a __proto__ key and an oversized value. Each must be refused or answered as an error, fast.
const wrong = { string: 42, number: "x", integer: "x", boolean: "yes", array: "not-a-list", object: "not-an-object" };
let generated = 0;
for (const t of tools) {
  const props = t.inputSchema?.properties ?? {};
  const cases = [["string-args", "just text"], ["proto", JSON.parse('{"__proto__": {"polluted": true}}')]];
  for (const [k, v] of Object.entries(props)) {
    if (v.type && wrong[v.type] !== undefined) cases.push([`${k}:wrong-type`, { [k]: wrong[v.type] }]);
    if (v.type === "string") cases.push([`${k}:huge`, { [k]: "a".repeat(200_000) }]);
  }
  for (const [label, args] of cases) {
    const t0 = Date.now();
    const r = await call("tools/call", { name: t.name, arguments: args });
    generated++;
    if (Date.now() - t0 > 10_000) fail(`${t.name} ${label} took ${Date.now() - t0} ms`);
    const ok = r.error || r.result?.isError || label === "proto" || (label.endsWith(":huge") && r.result);
    if (!ok) fail(`${t.name} accepted ${label}`);
    if ({}.polluted) fail("prototype polluted");
  }
}
console.log("ok schema-generated bad input:", generated, "cases");
if (!(await call("tools/list", {})).result?.tools?.length) fail("server stopped answering after bad input");
console.log("ok bad input rejected,", bad.length, "cases");
const prompts = (await call("prompts/list", {})).result?.prompts ?? [];
if (!prompts.some((x) => x.name === "triage")) fail("triage prompt missing");
const tri = (await call("prompts/get", { name: "triage", arguments: { files: "src" } })).result?.messages?.[0]?.content?.text ?? "";
if (!tri.includes(TRIAGE_GUIDE) || !tri.includes('["src"]')) fail("triage prompt text wrong");
console.log("ok triage prompt");
p.kill(); console.log("MCP smoke test passed");
