// lintsure skills: copies Lintsure's skill files into a project. A skill is a short instruction file that tells a
// coding agent when to use Lintsure and what to do with what it finds. Only files inside the project are written.
// Nothing is downloaded or sent: the skills ship inside this package.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { copyFile, mkdir, readFile, readdir, rm, rmdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The build copies the repository's skills folder next to dist, so the published package carries it.
const SOURCE = fileURLToPath(new URL("../../skills/", import.meta.url));
// One line a person reads when choosing, in the order a new user needs them. The description inside each skill is
// written for the agent.
const ABOUT: Record<string, string> = {
  "lintsure-setup": "Checks that Lintsure is connected and helps finish the setup",
  "lintsure-check": "Checks risky code right after your agent writes it",
  "lintsure-fix": "Applies one proposed fix: shows it, waits for your yes, re-checks",
  "lintsure-triage": "Sorts findings into real, not a problem, or needs a person",
  "lintsure-ship": "Runs a full check before you launch or deploy",
  "lintsure-rules": "Suggests and saves your project's own rules for every agent",
  "lintsure-stay-on-track": "Re-reads your project rules before big changes in long sessions",
};
/** A skill is a folder: SKILL.md, and for some a few helper scripts beside it. `files` maps each file name to its text. */
export interface Skill { name: string; about: string; files: Record<string, string> }
export const skills = (): Skill[] => {
  const order = Object.keys(ABOUT), rank = (n: string) => (order.indexOf(n) + 1 || order.length + 1);
  return readdirSync(SOURCE).sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)).map((name) => ({ name, about: ABOUT[name] ?? "", files: Object.fromEntries(readdirSync(join(SOURCE, name)).sort().map((f) => [f, readFileSync(join(SOURCE, name, f), "utf8")])) }));
};

/** Where skills go in a project: the shared folder most agents read, and Claude Code's own when the project uses it. */
export const skillFolders = (root: string): string[] => [".agents/skills", ...(existsSync(join(root, ".claude")) || existsSync(join(root, ".mcp.json")) ? [".claude/skills"] : [])];

export type SkillStep = { folder: string; state: "add" | "update" | "same" };
/** What installing would do, skill by skill. With `apply` it also does it. A file that differs from ours (an older
 *  version, or one the user edited) is kept beside the new one as <file>.lintsure-backup. */
export async function installSkills(root: string, chosen: Skill[], apply: boolean): Promise<SkillStep[]> {
  const steps: SkillStep[] = [];
  for (const folder of skillFolders(root)) for (const s of chosen) {
    const dir = join(root, folder, s.name);
    let missing = 0, differs = 0;
    for (const [file, text] of Object.entries(s.files)) {
      const path = join(dir, file), now = await readFile(path, "utf8").catch(() => null);
      if (now === text) continue;
      if (now === null) missing++; else differs++;
      if (!apply) continue;
      await mkdir(dir, { recursive: true });
      if (now !== null) await copyFile(path, path + ".lintsure-backup");
      await writeFile(path, text);
    }
    steps.push({ folder: `${folder}/${s.name}`, state: differs ? "update" : missing ? "add" : "same" });
  }
  return steps;
}

/** Takes Lintsure's skills back out. A file that was edited since is left where it is. Folders left empty are removed. */
export async function removeSkills(root: string): Promise<string[]> {
  const said: string[] = [];
  for (const folder of skillFolders(root)) {
    for (const s of skills()) {
      const dir = join(root, folder, s.name);
      let removed = 0, kept = 0;
      for (const [file, text] of Object.entries(s.files)) {
        const now = await readFile(join(dir, file), "utf8").catch(() => null);
        if (now === null) continue;
        if (now === text) { await rm(join(dir, file)); removed++; } else kept++;
      }
      if (kept) said.push(`- ${folder}/${s.name}: changed since it was installed, so ${kept === 1 ? "that file was" : "those files were"} left alone`);
      else if (removed) said.push(`- ${folder}/${s.name}: removed`);
      await rmdir(dir).catch(() => {}); // stays when an edited file or a backup is still inside
    }
    // Folders Lintsure may have created: removed only when nothing else is in them.
    for (const d of [join(root, folder), ...(folder.startsWith(".agents/") ? [join(root, dirname(folder))] : [])]) if ((await readdir(d).catch(() => ["x"])).length === 0) await rmdir(d).catch(() => {});
  }
  return said;
}
