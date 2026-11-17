// lintsure setup and lintsure doctor: register the Lintsure MCP server with the coding agents a project uses,
// and check that a project is ready. Only project files are written, each shown first and backed up. Nothing is
// downloaded or sent; the agent itself starts the server later with npx.
import { access, copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { RULES_VERSION, readConfig } from "@lintsure/core";

export interface Agent { id: string; name: string; file: string; key: "mcpServers" | "servers"; marker: string }
/** Project-level MCP config files. `marker` is the folder that shows the project uses that agent. */
export const AGENTS: Agent[] = [
  { id: "claude", name: "Claude Code", file: ".mcp.json", key: "mcpServers", marker: ".claude" },
  { id: "cursor", name: "Cursor", file: ".cursor/mcp.json", key: "mcpServers", marker: ".cursor" },
  { id: "vscode", name: "VS Code (Copilot)", file: ".vscode/mcp.json", key: "servers", marker: ".vscode" },
  { id: "gemini", name: "Gemini CLI", file: ".gemini/settings.json", key: "mcpServers", marker: ".gemini" },
];
// Pinned to this version on purpose: a moving "latest" in an agent config is what agent.config-runs-remote-code warns about.
export const serverEntry = (a: Agent) => ({ ...(a.key === "servers" ? { type: "stdio" } : {}), command: "npx", args: ["-y", `@lintsure/mcp@${RULES_VERSION}`] });

const exists = (p: string) => access(p).then(() => true, () => false);

/** What setup would write for one agent: the new file text, or why it skips. Pure apart from reading the file. */
export async function plan(root: string, a: Agent): Promise<{ agent: Agent; path: string; text?: string; skip?: string; existed: boolean }> {
  const path = join(root, a.file);
  const existed = await exists(path);
  let json: Record<string, unknown> = {};
  if (existed) {
    try { json = JSON.parse(await readFile(path, "utf8")); } catch { return { agent: a, path, existed, skip: `${a.file} isn't plain JSON (comments?), so it's left alone. Add the entry by hand.` }; }
  }
  const servers = (json[a.key] ?? {}) as Record<string, unknown>;
  if (JSON.stringify(servers.lintsure) === JSON.stringify(serverEntry(a))) return { agent: a, path, existed, skip: "already set up" };
  return { agent: a, path, existed, text: JSON.stringify({ ...json, [a.key]: { ...servers, lintsure: serverEntry(a) } }, null, 2) + "\n" };
}

/** Agents to set up: the ones named, or the ones whose folder exists, with Claude Code as the default. */
export async function pick(root: string, names?: string[]): Promise<Agent[] | string> {
  if (names) {
    const bad = names.filter((n) => !AGENTS.some((a) => a.id === n));
    return bad.length ? `Unknown agent: ${bad.join(", ")}. Use ${AGENTS.map((a) => a.id).join(", ")}.` : AGENTS.filter((a) => names.includes(a.id));
  }
  const found = [];
  for (const a of AGENTS) if (await exists(join(root, a.marker)) || await exists(join(root, a.file))) found.push(a);
  return found.length ? found : [AGENTS[0]];
}

export async function setup(root: string, agents: Agent[], apply: boolean): Promise<number> {
  const plans = await Promise.all(agents.map((a) => plan(root, a)));
  for (const p of plans) {
    if (p.skip) { console.log(`- ${p.agent.name}: ${p.skip}`); continue; }
    console.log(`- ${p.agent.name}: ${p.existed ? "add to" : "create"} ${p.agent.file}\n    "lintsure": ${JSON.stringify(serverEntry(p.agent))}`);
  }
  const todo = plans.filter((p) => p.text);
  if (!todo.length) return 0;
  if (!apply) { console.log("\nNothing written. Run again with --yes to apply. Existing files are backed up first (<file>.lintsure-backup)."); return 0; }
  for (const p of todo) {
    await mkdir(dirname(p.path), { recursive: true });
    if (p.existed) await copyFile(p.path, p.path + ".lintsure-backup");
    await writeFile(p.path, p.text!);
  }
  console.log(`\nWritten. Restart the agent so it starts the Lintsure MCP server. Run "lintsure doctor" to check.`);
  console.log("For the guards (Drift Guard, Danger Guard) in Claude Code, also install the plugin: /plugin marketplace add lintsure/claude-plugin");
  return 0;
}

/** Readiness check. Never prints secret values. Exit 2 only when the config has problems a scan would refuse. */
export async function doctor(root: string): Promise<number> {
  const line = (ok: boolean | null, what: string, next?: string) => console.log(`${ok === null ? "info" : ok ? "ok  " : "todo"}  ${what}${!ok && next ? `\n      ${next}` : ""}`);
  const major = Number(process.versions.node.split(".")[0]);
  line(major >= 20, `Node.js ${process.versions.node}`, "Lintsure needs Node.js 20 or newer.");
  line(true, `Lintsure rules ${RULES_VERSION}`);
  const config = await readConfig(root);
  const hasConfig = await exists(join(root, "lintsure.config.yaml"));
  line(hasConfig ? !config.problems.length : null, hasConfig ? `lintsure.config.yaml${config.problems.length ? `: ${config.problems.join("; ")}` : " reads cleanly"}` : "No lintsure.config.yaml: scans use all frameworks", hasConfig ? "Fix the lines above." : undefined);
  if (config.packsMissing?.length) line(false, `Rule packs not installed: ${config.packsMissing.join(", ")}`, "Install them next to Lintsure, or remove them from packs:.");
  const rulesFile = await exists(join(root, ".lintsure", "rules.yml"));
  line(rulesFile ? true : null, rulesFile ? ".lintsure/rules.yml found (Drift Guard rules)" : "No .lintsure/rules.yml: the Drift Guard only uses its built-in checks");
  for (const a of AGENTS) {
    const used = await exists(join(root, a.marker)) || await exists(join(root, a.file));
    if (!used) continue;
    const p = await plan(root, a);
    line(p.skip === "already set up", `${a.name}: Lintsure MCP server in ${a.file}`, p.skip && p.skip !== "already set up" ? p.skip : `Run: lintsure setup --agents ${a.id}`);
  }
  line(null, process.env.LINTSURE_API_KEY ? "LINTSURE_API_KEY is set: the plugin will use the hosted workspace" : "No LINTSURE_API_KEY: everything stays on this machine");
  return hasConfig && config.problems.length ? 2 : 0;
}
