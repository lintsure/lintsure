// Starts the MCP server and checks every tool reply ends with the disclaimer
// and that the server sends its agent guidance. Run: node scripts/mcp-smoke.mjs
import { spawn } from "node:child_process";
import { DISCLAIMER, AGENT_GUIDANCE, APPROVAL_RULES, FORBIDDEN_CLAIMS, NOT_A_VERDICT } from "../packages/core/dist/src/index.js";

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
const calls = [
  ["scan", { path: "fixtures/sample-app" }],
  ["classify", { euUsers: true, personalData: true }],
  ["classify", {}],
  ["explain_framework", { framework: "gdpr" }],
  ["explain_rule", { ruleId: "pii.logged" }],
  ["data_map", { path: "fixtures/sample-app" }],
];
for (const [name, args] of calls) {
  const r = await call("tools/call", { name, arguments: args });
  const texts = r.result?.content?.map((c) => c.text) ?? [];
  if (!texts.at(-1)?.includes(DISCLAIMER)) fail(`${name} reply has no disclaimer`);
  // The fixed disclaimer sentences are negations, so they're removed before the check.
  const body = texts.join(" ").split(NOT_A_VERDICT).join("").split(DISCLAIMER).join("");
  if (FORBIDDEN_CLAIMS.some((re) => re.test(body))) fail(`${name} reply reads like a verdict`);
  if ((name === "scan" || name === "explain_rule") && !texts.join(" ").includes(APPROVAL_RULES)) fail(`${name} reply misses the approval rules`);
  console.log("ok", name);
}
p.kill(); console.log("MCP smoke test passed");
