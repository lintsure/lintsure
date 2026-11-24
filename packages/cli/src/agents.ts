// lintsure setup and lintsure status: register the Lintsure MCP server with the coding agents a project uses,
// and check that a project is ready. Only project files are written, each shown first and backed up. Nothing is
// downloaded or sent; the agent itself starts the server later with npx.
import { access, chmod, copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { RULES_VERSION, readConfig } from "@lintsure/core";
import { installSkills, skills } from "./skills.js";

export interface Agent { id: string; name: string; file: string; key: "mcpServers" | "servers" | "mcp_servers"; marker: string }
/** Project-level MCP config files. `marker` is the folder that shows the project uses that agent. */
export const AGENTS: Agent[] = [
  { id: "claude", name: "Claude Code", file: ".mcp.json", key: "mcpServers", marker: ".claude" },
  { id: "cursor", name: "Cursor", file: ".cursor/mcp.json", key: "mcpServers", marker: ".cursor" },
  { id: "vscode", name: "VS Code (Copilot)", file: ".vscode/mcp.json", key: "servers", marker: ".vscode" },
  { id: "gemini", name: "Gemini CLI", file: ".gemini/settings.json", key: "mcpServers", marker: ".gemini" },
  // Codex keeps its config as TOML, one table per server. It reads a project's file only for projects marked as trusted.
  { id: "codex", name: "Codex", file: ".codex/config.toml", key: "mcp_servers", marker: ".codex" },
];
/** For agents with no config file in the project (they are set up in their own app or account): what to enter there. */
export const MANUAL = () => `Some agents are set up in their own settings, not by a file in the project: Devin, Windsurf, Zed, Cline and\nothers. Add an MCP server there with these values:\n\n    name      lintsure\n    command   npx\n    args      -y @lintsure/mcp@${RULES_VERSION}\n\nThen ask the agent, in its own chat: Check this project with Lintsure.`;
// Lintsure's own table in a Codex config: from its header to the next table. Only this table is ever written or removed.
const TOML_TABLE = /^\[mcp_servers\.lintsure\][^\n]*\n?(?:(?!\[)[^\n]*\n?)*/m;
export const tomlEntry = () => `[mcp_servers.lintsure]\ncommand = "npx"\nargs = ["-y", "@lintsure/mcp@${RULES_VERSION}"]\n`;
// Pinned to this version on purpose: a moving "latest" in an agent config is what agent.config-runs-remote-code warns about.
export const serverEntry = (a: Agent) => ({ ...(a.key === "servers" ? { type: "stdio" } : {}), command: "npx", args: ["-y", `@lintsure/mcp@${RULES_VERSION}`] });

const exists = (p: string) => access(p).then(() => true, () => false);

/** What setup would write for one agent: the new file text, or why it skips. Pure apart from reading the file. */
export async function plan(root: string, a: Agent): Promise<{ agent: Agent; path: string; text?: string; skip?: string; existed: boolean }> {
  const path = join(root, a.file);
  const existed = await exists(path);
  if (a.key === "mcp_servers") {
    const toml = existed ? await readFile(path, "utf8") : "", now = TOML_TABLE.exec(toml)?.[0];
    if (now?.replace(/\r/g, "").trim() === tomlEntry().trim()) return { agent: a, path, existed, skip: "already set up" };
    return { agent: a, path, existed, text: now ? toml.replace(TOML_TABLE, () => tomlEntry()) : toml + (toml && !toml.endsWith("\n") ? "\n" : "") + (toml.trim() ? "\n" : "") + tomlEntry() };
  }
  let json: Record<string, unknown> = {}, raw = "";
  if (existed) {
    raw = await readFile(path, "utf8");
    try { json = JSON.parse(raw.replace(/^﻿/, "")); } catch { return { agent: a, path, existed, skip: `${a.file} isn't plain JSON (comments?), so it's left alone. Add the entry yourself.` }; }
  }
  const servers = (json[a.key] ?? {}) as Record<string, unknown>;
  if (JSON.stringify(servers.lintsure) === JSON.stringify(serverEntry(a))) return { agent: a, path, existed, skip: "already set up" };
  return { agent: a, path, existed, text: writeJson(raw, { ...json, [a.key]: { ...servers, lintsure: serverEntry(a) } }) };
}

/** JSON in the same style as the file it replaces: its indent (tabs or N spaces) and a leading byte-order mark. Pure. */
export function writeJson(original: string, value: unknown): string {
  const indent = /^\t/m.test(original) ? "\t" : (original.match(/^( +)"/m)?.[1].length ?? 2);
  return (original.startsWith("﻿") ? "﻿" : "") + JSON.stringify(value, null, indent) + "\n";
}

/** The agents this project already uses: the ones whose folder or config file is here. */
export async function detected(root: string): Promise<Agent[]> {
  const found = [];
  for (const a of AGENTS) if (await exists(join(root, a.marker)) || await exists(join(root, a.file))) found.push(a);
  return found;
}
/** What connecting does, in plain words, for the screens that offer it. */
export const CONNECT_NOTE = "Connecting adds one entry to the agent's config file in this project. It tells the agent how to start\nLintsure, so the agent can check code and explain findings itself. Installing the lintsure command does not\ndo this: an agent only knows Lintsure once it is connected.";

/** Agents to set up: the ones named, or the ones whose folder exists, with Claude Code as the default. */
export async function pick(root: string, names?: string[]): Promise<Agent[] | string> {
  if (names) {
    const bad = names.filter((n) => !AGENTS.some((a) => a.id === n));
    return bad.length ? `Unknown agent: ${bad.join(", ")}. Use ${AGENTS.map((a) => a.id).join(", ")}.` : AGENTS.filter((a) => names.includes(a.id));
  }
  const found = await detected(root);
  return found.length ? found : [AGENTS[0]];
}

export async function setup(root: string, agents: Agent[], apply: boolean): Promise<number> {
  const plans = await Promise.all(agents.map((a) => plan(root, a)));
  for (const p of plans) {
    if (p.skip) { console.log(`- ${p.agent.name}: ${p.skip}`); continue; }
    console.log(`- ${p.agent.name}: ${p.existed ? "add to" : "create"} ${p.agent.file}\n    ${p.agent.key === "mcp_servers" ? tomlEntry().trim().replace(/\n/g, "\n    ") : `"lintsure": ${JSON.stringify(serverEntry(p.agent))}`}`);
  }
  const todo = plans.filter((p) => p.text);
  if (!todo.length) { console.log("\nNothing to write. Check the connection with: lintsure status"); return 0; }
  if (!apply) { console.log("\nNothing written yet. To apply, run: lintsure setup --yes\nExisting files are backed up first (<file>.lintsure-backup)."); return 0; }
  for (const p of todo) {
    await mkdir(dirname(p.path), { recursive: true });
    // The first backup is the user's original: never overwrite it on a later run. Owner-only, it may hold tokens.
    if (p.existed) {
      try { await copyFile(p.path, p.path + ".lintsure-backup", constants.COPYFILE_EXCL); await chmod(p.path + ".lintsure-backup", 0o600).catch(() => {}); }
      catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") { console.error(`Couldn't back up ${p.agent.file}, so it was left alone.`); continue; } }
    }
    await writeFile(p.path, p.text!);
  }
  console.log("Undo any time with: lintsure setup --undo");
  console.log(`\nWritten. Restart the agent so it starts the Lintsure MCP server. Run "lintsure status" to check.`);
  console.log("Then ask the agent, in its own chat: Check this project with Lintsure.");
  if (agents.some((a) => a.id === "codex")) console.log("Codex reads a project's .codex/config.toml only for projects you have marked as trusted.");
  console.log("For guards that run while the agent works, add the plugin: lintsure plugin");
  return 0;
}

/** Readiness check. Never prints secret values. Exit 2 only when the config has problems a scan would refuse. */
export async function status(root: string): Promise<number> {
  let todo = 0;
  const line = (ok: boolean | null, what: string, next?: string) => (ok === false && todo++, console.log(`${ok === null ? "info" : ok ? "ok  " : "todo"}  ${what}${!ok && next ? `\n      ${next}` : ""}`));
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
  // Skills: are the ones in this project the ones this version ships? An older or edited copy teaches the agent old habits.
  const steps = await installSkills(root, skills(), false), here = steps.filter((s) => s.state !== "add"), stale = here.filter((s) => s.state === "update");
  if (!here.length) line(null, "No Lintsure skills in this project: add them with lintsure skills");
  else line(!stale.length, `Lintsure skills: ${here.length} installed${stale.length ? `, ${stale.length} differ from this version (${stale.map((s) => s.folder).join(", ")})` : ", all current"}`, "Run: lintsure skills --yes (your copies are kept as backups)");
  const mcp = await mcpRoundTrip();
  if (!mcp) line(null, "MCP server not installed next to this CLI: agents start it with npx, which downloads it on first use");
  else line(!mcp.problems.length, mcp.problems.length ? `MCP server: ${mcp.problems.join("; ")}` : `MCP server ${mcp.version} answers: ${mcp.tools} tools, test call ok`);
  line(null, process.env.LINTSURE_API_KEY ? "LINTSURE_API_KEY is set: the plugin will use the hosted workspace" : "No LINTSURE_API_KEY: everything stays on this machine");
  console.log(todo ? `\nAlmost there: ${todo} thing${todo === 1 ? "" : "s"} to do, marked todo above.` : "\nReady! Everything Lintsure needs is in place.");
  return hasConfig && config.problems.length ? 2 : 0;
}

/** Takes Lintsure's own entry back out, leaving everything else in the file as it is now (later edits included).
 *  A file Lintsure created that is now empty is removed. The original backup is kept. */
export async function undo(root: string, agents: Agent[]): Promise<number> {
  for (const a of agents) {
    const path = join(root, a.file);
    if (a.key === "mcp_servers") {
      const toml = await readFile(path, "utf8").catch(() => "");
      if (!TOML_TABLE.test(toml)) continue;
      const left = toml.replace(TOML_TABLE, "").replace(/\n{3,}/g, "\n\n"), kept = await exists(path + ".lintsure-backup");
      if (!left.trim() && !kept) { await rm(path); console.log(`- ${a.name}: removed ${a.file} (Lintsure had created it)`); }
      else { await writeFile(path, left); console.log(`- ${a.name}: removed the Lintsure entry from ${a.file}${kept ? ` (your original is still in ${a.file}.lintsure-backup)` : ""}`); }
      continue;
    }
    let json: Record<string, unknown>, raw: string;
    try { raw = await readFile(path, "utf8"); json = JSON.parse(raw.replace(/^﻿/, "")); } catch { continue; }
    const servers = (json[a.key] ?? {}) as Record<string, unknown>;
    if (!("lintsure" in servers)) continue;
    delete servers.lintsure;
    const empty = !Object.keys(servers).length && Object.keys(json).length === 1;
    const backup = await exists(path + ".lintsure-backup");
    if (empty && !backup) { await rm(path); console.log(`- ${a.name}: removed ${a.file} (Lintsure had created it)`); }
    else { await writeFile(path, writeJson(raw, json)); console.log(`- ${a.name}: removed the Lintsure entry from ${a.file}${backup ? ` (your original is still in ${a.file}.lintsure-backup)` : ""}`); }
  }
  return 0;
}

/** Starts the locally installed Lintsure MCP server and talks to it the way an agent would: initialize (version must
 *  match these rules), tools/list, and one read-only call. Never downloads: when @lintsure/mcp isn't installed next
 *  to this CLI, it says so. Returns problems found, or null when the server isn't installed here. */
export async function mcpRoundTrip(timeoutMs = 15000): Promise<{ problems: string[]; tools: number; version: string } | null> {
  const { createRequire } = await import("node:module");
  const { spawn } = await import("node:child_process");
  let entry: string;
  try {
    const req = createRequire(import.meta.url), pkgPath = req.resolve("@lintsure/mcp/package.json");
    const pkg = JSON.parse(await readFile(pkgPath, "utf8"));
    entry = join(dirname(pkgPath), typeof pkg.bin === "string" ? pkg.bin : pkg.bin?.["lintsure-mcp"] ?? "dist/src/index.js");
  } catch { return null; }
  const p = spawn(process.execPath, [entry], { stdio: ["pipe", "pipe", "ignore"] });
  let buf = ""; const waiting = new Map<number, (m: any) => void>();
  p.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { try { const m = JSON.parse(buf.slice(0, i)); waiting.get(m.id)?.(m); } catch { /* not ours */ } buf = buf.slice(i + 1); } });
  // A server that fails to start or exits early is reported as a problem, never a crash of the CLI (EPIPE).
  let gone: string | null = null; const fail = new Set<(e: Error) => void>();
  const stop = (why: string) => { gone ??= why; for (const f of fail) f(new Error(gone)); };
  p.on("error", (e) => stop(`MCP server didn't start (${e.message})`));
  p.on("exit", (code) => stop(`MCP server exited${code == null ? "" : ` with code ${code}`} before answering`));
  p.stdin.on("error", () => stop("MCP server closed its input"));
  let id = 0;
  const call = (method: string, params: unknown) => new Promise<any>((res, rej) => {
    if (gone) return rej(new Error(gone));
    const n = ++id, t = setTimeout(() => rej(new Error(`${method} took longer than ${timeoutMs / 1000}s`)), timeoutMs);
    const onFail = (e: Error) => { clearTimeout(t); rej(e); };
    fail.add(onFail);
    waiting.set(n, (m) => { clearTimeout(t); fail.delete(onFail); res(m); });
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: n, method, params }) + "\n");
  });
  const problems: string[] = []; let tools = 0, version = "";
  try {
    const init = await call("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "lintsure-status", version: RULES_VERSION } });
    version = init.result?.serverInfo?.version ?? "";
    if (version !== RULES_VERSION) problems.push(`MCP server is ${version || "unknown"}, the CLI is ${RULES_VERSION}: update both to the same version`);
    p.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    tools = (await call("tools/list", {})).result?.tools?.length ?? 0;
    if (!tools) problems.push("MCP server listed no tools");
    const r = await call("tools/call", { name: "explain_rule", arguments: { ruleId: "pii.logged" } });
    if (r.error || r.result?.isError || !r.result?.content?.length) problems.push("MCP server didn't answer a test call");
  } catch (e) { problems.push(e instanceof Error ? e.message : String(e)); }
  finally { p.kill(); }
  return { problems, tools, version };
}
