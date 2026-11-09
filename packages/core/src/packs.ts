// Rule packs: extra frameworks and rules installed next to Lintsure (for example the Lintsure platform's sector packs).
// Safety: a scanned repo must never be able to run code through Lintsure. So only packages named @lintsure/pack-*
// load, and they're resolved from where Lintsure itself is installed, never from the scanned repo's node_modules.
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { ALL_FRAMEWORKS } from "./index.js";
import { knowledge, type FrameworkKnowledge } from "./knowledge/index.js";
import { rules } from "./rules/index.js";
import type { Control, Rule } from "./types.js";

export interface Pack {
  /** Package name, for example "@lintsure/pack-pci-dss". */
  id: string;
  rules: Rule[];
  knowledge: FrameworkKnowledge[];
  /** Controls this pack adds to rules that already exist, by rule id. */
  forExisting?: Record<string, Control[]>;
}

const PACK_NAME = /^@lintsure\/pack-[a-z0-9-]+$/;
const loaded = new Set<string>();

/** Adds a pack's frameworks, rules and mappings. Loading the same pack twice does nothing. */
export function registerPack(p: Pack): void {
  if (loaded.has(p.id)) return;
  loaded.add(p.id);
  for (const [id, cs] of Object.entries(p.forExisting ?? {})) rules.find((r) => r.id === id)?.controls.push(...cs);
  rules.push(...p.rules);
  for (const k of p.knowledge) {
    knowledge.push(k);
    if (!ALL_FRAMEWORKS.includes(k.id)) ALL_FRAMEWORKS.push(k.id);
  }
}

/** Loads packs by name. Returns the names that couldn't be loaded (wrong name or not installed). */
export async function loadPacks(names: string[]): Promise<string[]> {
  const failed: string[] = [];
  const require = createRequire(import.meta.url);
  for (const name of names) {
    if (!PACK_NAME.test(name)) { failed.push(name); continue; }
    try {
      const mod = await import(pathToFileURL(require.resolve(name)).href);
      registerPack((mod.default ?? mod.pack) as Pack);
    } catch { failed.push(name); }
  }
  return failed;
}
