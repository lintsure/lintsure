// What the rules helper needs to read and check .lintsure/rules.yml. Local files only: nothing here uses the network.
import { readFileSync } from "node:fs";
import { join } from "node:path";

/** Rules from .lintsure/rules.yml in the repo. A small YAML subset: a "rules:" list of items with one kind key
 *  (avoid, protect, deps, note) plus optional "say" and "in". Anything it can't read is skipped, never fatal. */
export function fileRules(root) {
  let src; try { src = readFileSync(join(root, ".lintsure", "rules.yml"), "utf8"); } catch { return []; }
  const val = (v) => { v = v.trim(); if (/^".*"$/.test(v)) { try { return JSON.parse(v); } catch { return v.slice(1, -1); } } if (/^'.*'$/.test(v)) return v.slice(1, -1).replace(/''/g, "'"); return v.replace(/\s+#.*$/, ""); };
  const items = []; let inRules = false, cur = null;
  for (const raw of src.split(/\r?\n/)) {
    if (/^\s*(#|$)/.test(raw)) continue;
    const top = raw.match(/^mode:\s*(quiet|guide|strict)\b/i);
    if (top) { items.mode = top[1].toLowerCase(); continue; }
    if (/^\S/.test(raw)) { inRules = /^rules:\s*$/.test(raw); cur = null; continue; }
    if (!inRules) continue;
    const m = raw.match(/^\s*(-\s+)?([a-z]+):\s*(.*)$/i);
    if (!m) continue;
    if (m[1]) { cur = {}; items.push(cur); }
    if (cur) cur[m[2].toLowerCase()] = val(m[3]);
  }
  const out = items.map((it, i) => {
    const kind = ["avoid", "protect", "deps", "note"].find((k) => k in it);
    if (!kind) return null;
    const v = it[kind], say = it.say || (kind === "note" ? v : ""), except = it.except || null;
    if (kind === "avoid") return { id: `file:${i}`, kind, pattern: v, paths: it.when || it.in || null, except, text: say || `Don't add code matching ${v}.` };
    if (kind === "protect") return { id: `file:${i}`, kind, paths: v, except, text: say || `Don't edit ${v}.` };
    if (kind === "deps") return { id: `file:${i}`, kind, except, text: say || "Don't add new dependencies without asking." };
    // A note with "when:" (or "in:") globs applies only to those files: it's shown when the agent edits one, not in Memory.
    return { id: `file:${i}`, kind, paths: it.when || it.in || null, text: say };
  }).filter((r) => r && r.text);
  out.mode = items.mode;
  return out;
}

/** Small glob: ** any path, * one segment, a bare folder name matches everything under it. */
export function globMatch(path, globs) {
  return String(globs || "").split(",").map((g) => g.trim().replace(/^\.\//, "")).filter(Boolean).some((g) => {
    if (!/[*?]/.test(g)) return path === g || path.startsWith(g.replace(/\/$/, "") + "/");
    // Runs of "**" and "*" collapse to one ".*", so a glob like **/**/** can't build a slow regex.
    const re = g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\/?/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/(?:\u0000|\[\^\/\]\*)*\u0000(?:\u0000|\[\^\/\]\*)*/g, "\u0000").replace(/\u0000/g, ".*");
    return new RegExp(`^${re}$`).test(path);
  });
}

// Rule patterns come from people and from repos (a cloned project's .lintsure/rules.yml), so a pattern is checked before
// it runs: a repeated group that repeats inside, like (a+)+ or (\w*)*, can take minutes on one line, so it's refused.
// Patterns stay under 500 characters and run on lines cut to 2,000, so even an unusual pattern finishes fast.
export const MAX_PATTERN = 500, MAX_LINE = 2000;
// A repeated group that repeats inside, (a+)+, or that offers overlapping choices, (a|aa)*: both can take exponential time,
// and cutting the line doesn't save an exponential pattern, so both shapes are refused. A character class, [ab]+, is fine.
const NESTED = /\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\d*\}|\|)(?:[^()\\]|\\.)*\)(?:[+*]|\{\d*,)/;
/** A rule's pattern as a regex, or the reason it can't be used. Pure. */
export function safePattern(src, flags = "") {
  const p = String(src ?? "");
  if (!p) return { error: "The pattern is empty." };
  if (p.length > MAX_PATTERN) return { error: `The pattern is longer than ${MAX_PATTERN} characters.` };
  if (NESTED.test(p)) return { error: "The pattern repeats a group that repeats inside or offers choices, like (a+)+ or (a|b)*, which can take minutes on a single line. Write it without the repeated group, for example with a character class like [ab]+." };
  try { return { re: new RegExp(p, flags) }; } catch (e) { return { error: `The pattern isn't a valid regular expression: ${e.message}` }; }
}
