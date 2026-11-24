// lintsure plugin: installs the Lintsure guards for the agents a project uses. The guards run while the agent works
// (Drift, Danger, Loop and Threat Guard, and one check at the end of a task), which a skill can't do: a skill is only
// read when the agent decides to read it.
//   Claude Code: its own plugin system does the install, through the `claude` command.
//   Cursor, Codex, Gemini CLI: the plugin is fetched once into the user's home folder and a hooks file is written into
//   the project that points at it. An existing hooks file of the user's own is never changed.
// Getting the plugin is a download from GitHub, so nothing happens until the user has seen the plan and agreed.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { writeJson } from "./agents.js";

// The plugin release that pairs with this engine. Pinned: a moving branch here would be what the supply-chain rules flag.
export const PLUGIN_TAG = "v0.3.5";
const REPO = "https://github.com/lintsure/plugin.git";

export interface GuardAgent { id: string; name: string; marker: string; file?: string; from?: string }
export const GUARD_AGENTS: GuardAgent[] = [
  { id: "claude", name: "Claude Code", marker: ".claude" },
  { id: "cursor", name: "Cursor", marker: ".cursor", file: ".cursor/hooks.json", from: "cursor/hooks.json" },
  { id: "codex", name: "Codex", marker: ".codex", file: ".codex/hooks.json", from: "codex/hooks.json" },
  { id: "gemini", name: "Gemini CLI", marker: ".gemini", file: ".gemini/settings.json", from: "gemini/hooks.json" },
];
const RECORD = ".lintsure/guards.json"; // what was written here, so --undo takes out exactly that

/** The folder that holds the plugin's hooks, fetching it once per version. LINTSURE_PLUGIN_SRC names a local copy
 *  (used by the tests, and by anyone working on the plugin). Throws with a plain reason when it can't be had. */
export function pluginHome(fetchIt: boolean): string {
  const local = process.env.LINTSURE_PLUGIN_SRC;
  if (local) { if (!existsSync(join(local, "hooks"))) throw new Error(`LINTSURE_PLUGIN_SRC has no hooks folder: ${local}`); return local; }
  const home = join(homedir(), ".lintsure", "plugin", PLUGIN_TAG), dir = join(home, "plugins", "lintsure");
  if (existsSync(join(dir, "hooks"))) return dir;
  if (!fetchIt) return dir;
  try { execFileSync("git", ["clone", "--quiet", "--depth", "1", "--branch", PLUGIN_TAG, REPO, home], { stdio: ["ignore", "ignore", "pipe"] }); }
  catch (e) { throw new Error(`Couldn't download the plugin (${PLUGIN_TAG}) with git. ${e instanceof Error ? e.message.split("\n")[0] : ""}`.trim()); }
  return dir;
}

/** A hooks file for one agent, with every command pointing at the plugin on this machine. Pure. */
export function hooksFor(template: unknown, dir: string): unknown {
  const at = dir.replace(/\\/g, "/");
  const fix = (v: unknown): unknown => typeof v === "string"
    ? v.replace(/\$\{(CLAUDE_PLUGIN_ROOT|CURSOR_PLUGIN_ROOT|extensionPath)\}/g, at).replace(/^node hooks\//, `node "${at}/hooks/`).replace(/^(node "[^"]*\/hooks\/[\w.-]+)( |$)/, (m, a: string, b: string) => (a.endsWith('"') ? m : `${a}"${b}`))
    : Array.isArray(v) ? v.map(fix) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fix(x)])) : v;
  return fix(template);
}

export interface GuardStep { agent: GuardAgent; does: "claude" | "create" | "merge" | "skip" | "same"; note: string; text?: string; path?: string }
/** What installing would do for each agent. Reads files only. */
export async function planGuards(root: string, agents: GuardAgent[], dir: string): Promise<GuardStep[]> {
  const steps: GuardStep[] = [];
  for (const a of agents) {
    if (!a.file) { steps.push({ agent: a, does: "claude", note: "claude plugin marketplace add lintsure/plugin, then claude plugin install lintsure@lintsure" }); continue; }
    const path = join(root, a.file);
    let ours: { hooks?: unknown };
    try { ours = hooksFor(JSON.parse(await readFile(join(dir, a.from!), "utf8")), dir) as { hooks?: unknown }; }
    catch { steps.push({ agent: a, does: "skip", note: `this version of the plugin has no guards for ${a.name}` }); continue; }
    if (!existsSync(path)) { steps.push({ agent: a, does: "create", note: `create ${a.file}`, path, text: JSON.stringify(ours, null, 2) + "\n" }); continue; }
    const raw = await readFile(path, "utf8");
    let now: Record<string, unknown>;
    try { now = JSON.parse(raw.replace(/^﻿/, "")); } catch { steps.push({ agent: a, does: "skip", note: `${a.file} isn't plain JSON, so it's left alone` }); continue; }
    if (JSON.stringify(now.hooks) === JSON.stringify(ours.hooks)) { steps.push({ agent: a, does: "same", note: "already installed" }); continue; }
    // Someone's own hooks are never rewritten or merged into: say where the guards' file is, so they can add it.
    if (now.hooks) { steps.push({ agent: a, does: "skip", note: `${a.file} already has hooks of its own, so it's left alone. The guards' hooks to add by hand are in ${join(dir, a.from!)}` }); continue; }
    steps.push({ agent: a, does: "merge", note: `add a hooks section to ${a.file}`, path, text: writeJson(raw, { ...now, hooks: ours.hooks }) });
  }
  return steps;
}

const claudeCli = (args: string[]) => execFileSync("claude", args, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", shell: process.platform === "win32" });

/** Carries out a plan. Returns one line per agent on what happened. */
export async function installGuards(root: string, steps: GuardStep[]): Promise<string[]> {
  const said: string[] = [], wrote: { file: string; how: "create" | "merge" }[] = [];
  for (const s of steps) {
    if (s.does === "claude") {
      try { claudeCli(["plugin", "marketplace", "add", "lintsure/plugin"]); claudeCli(["plugin", "install", "lintsure@lintsure"]); said.push(`${s.agent.name}: installed. Restart Claude Code to load the guards.`); }
      catch { said.push(`${s.agent.name}: the claude command didn't do it. Type these inside Claude Code:\n    /plugin marketplace add lintsure/plugin\n    /plugin install lintsure@lintsure`); }
      continue;
    }
    if (s.does === "skip" || s.does === "same") { said.push(`${s.agent.name}: ${s.note}`); continue; }
    await mkdir(dirname(s.path!), { recursive: true });
    if (s.does === "merge") await copyFile(s.path!, s.path! + ".lintsure-backup").catch(() => {});
    await writeFile(s.path!, s.text!);
    wrote.push({ file: s.agent.file!, how: s.does });
    said.push(`${s.agent.name}: ${s.does === "create" ? "created" : "updated"} ${s.agent.file}. Restart ${s.agent.name} to load the guards.`);
  }
  if (wrote.length) { await mkdir(join(root, ".lintsure"), { recursive: true }); await writeFile(join(root, RECORD), JSON.stringify({ wrote }, null, 2) + "\n"); }
  return said;
}

/** Takes out what installGuards wrote in this project. Claude Code's plugin is removed through its own command. */
export async function removeGuards(root: string, agents: GuardAgent[]): Promise<string[]> {
  const said: string[] = [];
  let wrote: { file: string; how: "create" | "merge" }[] = [];
  try { wrote = JSON.parse(await readFile(join(root, RECORD), "utf8")).wrote ?? []; } catch { /* nothing recorded */ }
  for (const a of agents) {
    if (!a.file) {
      try { claudeCli(["plugin", "uninstall", "lintsure@lintsure"]); said.push(`${a.name}: plugin removed.`); }
      catch { said.push(`${a.name}: remove it inside Claude Code with /plugin uninstall lintsure@lintsure`); }
      continue;
    }
    const mine = wrote.find((w) => w.file === a.file), path = join(root, a.file);
    if (!mine || !existsSync(path)) continue;
    if (mine.how === "create") { await rm(path); said.push(`${a.name}: removed ${a.file}`); }
    else {
      const raw = await readFile(path, "utf8"), json = JSON.parse(raw.replace(/^﻿/, "")) as Record<string, unknown>;
      delete json.hooks;
      await writeFile(path, writeJson(raw, json)); await rm(path + ".lintsure-backup", { force: true }); said.push(`${a.name}: took the hooks section out of ${a.file}`);
    }
  }
  const left = wrote.filter((w) => !agents.some((a) => a.file === w.file));
  if (left.length) await writeFile(join(root, RECORD), JSON.stringify({ wrote: left }, null, 2) + "\n"); else await rm(join(root, RECORD)).catch(() => {});
  return said;
}
