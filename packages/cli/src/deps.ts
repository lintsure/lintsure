// lintsure deps: asks a public database which of the project's pinned packages have known vulnerabilities.
// This is the one command that uses the network. It sends package names and versions, never code, to api.osv.dev,
// and only after it has said so and been told to go ahead. A scan never does this.
import { readFile } from "node:fs/promises";
import { join } from "node:path";

export interface Pinned { name: string; version: string; ecosystem: "npm" | "PyPI" }

/** Every installed package in an npm lockfile (version 2 or 3), once per name and version. Pure. */
export function fromPackageLock(text: string): Pinned[] {
  const packages = (JSON.parse(text).packages ?? {}) as Record<string, { version?: string; link?: boolean }>;
  const out = new Map<string, Pinned>();
  for (const [path, p] of Object.entries(packages)) {
    const at = path.lastIndexOf("node_modules/");
    if (at < 0 || p.link || !p.version) continue; // the project itself, and links to its own workspaces
    const name = path.slice(at + 13);
    out.set(`${name}@${p.version}`, { name, version: p.version, ecosystem: "npm" });
  }
  return [...out.values()];
}
/** Packages pinned to one exact version in a requirements file. Ranges and unpinned lines can't be looked up. Pure. */
export function fromRequirements(text: string): Pinned[] {
  return text.split(/\r?\n/).flatMap((l) => { const m = /^\s*([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([\w.!+-]+)/.exec(l); return m ? [{ name: m[1], version: m[2], ecosystem: "PyPI" as const }] : []; });
}

/** The pinned packages of a project, and the files they came from.
 *  shortcut: reads package-lock.json and requirements.txt at the top of the folder only; add other lockfiles and nested
 *  folders when someone needs them. */
export async function pinned(root: string): Promise<{ found: Pinned[]; files: string[] }> {
  const found: Pinned[] = [], files: string[] = [];
  for (const [file, read] of [["package-lock.json", fromPackageLock], ["requirements.txt", fromRequirements]] as const) {
    const text = await readFile(join(root, file), "utf8").catch(() => null);
    if (text === null) continue;
    try { const list = read(text); if (list.length) { found.push(...list); files.push(file); } } catch { /* a lockfile that isn't JSON is skipped, not fatal */ }
  }
  return { found, files };
}

/** Known advisory ids per package, from OSV. One request per 500 packages. Throws when the service can't be reached. */
export async function advisories(pkgs: Pinned[], fetcher: typeof fetch = fetch): Promise<Map<Pinned, string[]>> {
  const out = new Map<Pinned, string[]>();
  for (let i = 0; i < pkgs.length; i += 500) {
    const batch = pkgs.slice(i, i + 500);
    const res = await fetcher("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "content-type": "application/json" }, signal: AbortSignal.timeout(20000),
      body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }) });
    if (!res.ok) throw new Error(`api.osv.dev answered ${res.status}`);
    const { results = [] } = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    batch.forEach((p, k) => { const ids = (results[k]?.vulns ?? []).map((v) => v.id); if (ids.length) out.set(p, ids); });
  }
  return out;
}
