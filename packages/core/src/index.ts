// Scout (file walk) + Checker (rules) + Auditor (dedupe, sort) + Officer (outside code).
// No network calls anywhere in this package: a test enforces it.
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, extname, join, relative, sep } from "node:path";
import { outsideFor } from "./knowledge/index.js";
import { MASKED, rules } from "./rules/index.js";
import type { Finding, FrameworkId, Patch, Report, Severity } from "./types.js";
import { proposalFor } from "./guidance.js";
import { applyReview, fingerprint, isOpen } from "./review.js";
export * from "./review.js";
export { toSarif } from "./sarif.js";
import { buildRecord, type RecordOptions } from "./record.js";
export * from "./record.js";

/** Heading above every proposed change, in every report. Tests check it is there for each finding. */
export const PROPOSAL_HEADING = "Proposed change. Nothing changes until you approve it.";

export * from "./types.js";
export { rules };
export * from "./guidance.js";
export { toAssessmentHtml } from "./assessment.js";
export * from "./knowledge/index.js";
export { loadPacks, registerPack, type Pack } from "./packs.js";
export { checksFor } from "./plan.js";
import { configPacks, loadPacks, packFrameworks, packsLoaded } from "./packs.js";
import { buildGraph, declaredEntries, reachOf } from "./reach.js";
export const RULES_VERSION = "0.3.14";

/** Shown with every result, in every interface. Lintsure prepares; people decide. */
export const DISCLAIMER =
  "Lintsure is a readiness tool, not an audit, a certification or legal advice. " +
  "Its rules reflect our reading of the publicly available text of each framework, and they check code only. " +
  "Work outside code, such as policies, training, contracts and evidence, still has to be done. " +
  "Have a qualified person review the results before any audit, certification or decision.";

/** What a report must never be read as. Used in the report and by the MCP server. */
export const NOT_A_VERDICT =
  "These results do not mean you are compliant, certified or ready for an audit. A control marked Met means only that " +
  "Lintsure's rules found no problem in the files they read.";

/** Plain next steps, so a report always ends with what a person still needs to do. */
export function nextSteps(r: Report): string[] {
  const open = r.findings.filter(isOpen);
  const gaps = open.filter((f) => f.status === "gap").length;
  const partial = open.filter((f) => f.status === "partial").length;
  const expired = r.findings.filter((f) => f.accepted?.expired).length;
  return [
    gaps ? `Review the ${gaps} gap${gaps === 1 ? "" : "s"} and decide how to fix each one. Approve any change before it is made.` : "No gaps were found by the current rules. Keep checking as the code changes.",
    partial ? `Check the ${partial} partial finding${partial === 1 ? "" : "s"}: each depends on context only you can confirm.` : "",
    `Work through the ${r.outside.length} item${r.outside.length === 1 ? "" : "s"} that live outside code. Code checks alone are not enough for a full review.`,
    expired ? `${expired} accepted finding${expired === 1 ? " is" : "s are"} past the review date. Look again, then renew the acceptance or fix it.` : "",
    "Ask a qualified compliance professional to review the results before you rely on them.",
  ].filter(Boolean);
}
export const ALL_FRAMEWORKS: FrameworkId[] = ["gdpr", "eu-ai-act", "owasp-top10", "cra", "owasp-llm", "cwe-top25"];

/** Reads the frameworks list from lintsure.config.yaml in the repo root, if there is one.
 *  Lists can be written either way:
 *    frameworks:
 *      - gdpr
 *    frameworks: [gdpr, owasp-top10]
 *  `rules:` switches a rule off or changes its risk level; `show: all` includes medium-confidence findings.
 *  Anything it can't read is returned in `problems`, never silently ignored.
 *  Ids Lintsure doesn't check yet (for example "soc2" without its pack) are returned in `skipped`.
 *  A `packs:` list loads installed @lintsure/pack-* rule packs first, so their frameworks count as known.
 *  An `ignore:` list of paths (relative to the root, for example tests/ or fixtures/) is skipped by scan(). */
export interface Config {
  frameworks: FrameworkId[] | null; skipped: string[]; ignore: string[]; packsMissing?: string[]; packs?: string[];
  /** Per-rule settings: "off" stops a rule; "low" | "medium" | "high" changes its risk level. */
  rules: Record<string, "off" | Severity>;
  /** "all" also shows medium-confidence findings. */
  show?: "all";
  /** Lines Lintsure could not read. The CLI stops with exit code 2 rather than guess (a typo must not widen a scan). */
  problems: string[];
}
const KEYS = new Set(["frameworks", "ignore", "packs", "rules", "show"]);
const RULE_SETTINGS = new Set(["off", "low", "medium", "high"]);

export async function readConfig(root: string): Promise<Config> {
  let text: string;
  try { text = await readFile(join(root, "lintsure.config.yaml"), "utf8"); } catch { return { frameworks: null, skipped: [], ignore: [], rules: {}, problems: [] }; }
  const lists: Record<string, string[]> = { frameworks: [], ignore: [], packs: [] }, ruleSet: Config["rules"] = {}, problems: string[] = [];
  let key = "", emptyFw = false, show: Config["show"];
  const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");
  text.split(/\r?\n/).forEach((raw, n) => {
    const line = raw.replace(/#.*$/, "").trimEnd(), at = `line ${n + 1}`;
    if (!line.trim()) return;
    const top = line.match(/^([\w-]+)\s*:\s*(.*)$/);
    if (top) {
      const [, k, value] = top; key = "";
      if (!KEYS.has(k)) { problems.push(`${at}: unknown setting "${k}" (known: ${[...KEYS].join(", ")})`); return; }
      if (k === "show") { if (unquote(value) === "all") show = "all"; else problems.push(`${at}: show can only be "all"`); return; }
      const inline = value.match(/^\[(.*)\]$/); // frameworks: [gdpr, owasp-top10]
      if (inline && k !== "rules") { const items = inline[1].split(",").map(unquote).filter(Boolean); if (k === "frameworks" && !items.length) emptyFw = true; lists[k].push(...items); return; }
      if (value.trim()) { problems.push(`${at}: write ${k} as a list`); return; }
      key = k; return;
    }
    if (key === "rules") {
      const m = line.match(/^\s+([\w.-]+)\s*:\s*(\S+)\s*$/);
      if (m && RULE_SETTINGS.has(unquote(m[2]))) ruleSet[m[1]] = unquote(m[2]) as Config["rules"][string];
      else problems.push(`${at}: write a rule as "  rule.id: off" (or low, medium, high)`);
      return;
    }
    const m = key && line.match(/^\s+-\s*(.+?)\s*$/);
    if (m) lists[key].push(unquote(m[1])); else problems.push(`${at}: could not read "${line.trim()}"`);
  });
  const ignore = lists.ignore.map((p) => p.replace(/\\/g, "/").replace(/^\.?\//, "").replace(/\/+$/, ""));
  const packsMissing = lists.packs.length ? await loadPacks(lists.packs) : undefined;
  const ruleIds = new Set(rules.map((r) => r.id));
  for (const id of Object.keys(ruleSet)) if (!ruleIds.has(id)) problems.push(`rules: no rule called "${id}"`);
  const base = { ignore, packsMissing, packs: lists.packs, rules: ruleSet, show, problems };
  if (emptyFw) return { frameworks: [], skipped: [], ...base };
  const ids = lists.frameworks;
  if (!ids.length) return { frameworks: null, skipped: [], ...base };
  const known = ids.filter((i): i is FrameworkId => (ALL_FRAMEWORKS as string[]).includes(i));
  return { frameworks: known, skipped: ids.filter((i) => !known.includes(i as FrameworkId)), ...base };
}

// Dependencies, build output and caches: generated code, not code you wrote.
// Also other people's code copied in (vendor, third_party): not code you wrote (field test, 139 repos).
/** The exact change for a finding, when its rule knows one. Pure. */
function patchFor(r: { patch?(l: string): string | null; insert?: string }, line: number, old: string): { patch?: Patch } {
  if (r.insert) return { patch: { line, old: null, text: r.insert } };
  const text = r.patch?.(old);
  return text != null && text !== old ? { patch: { line, old, text } } : {};
}
// What a Partial finding can't show. Rules read lines and statements, not how data moves through the program.
const UNSEEN = "Lintsure reads this code on its own. It can't see where the values come from or whether they're checked elsewhere, so a person needs to look.";
const UNSEEN_TESTS = "This is in a test, fixture or example file. Lintsure can't tell whether it ships or is a throwaway value.";
export const SKIP_DIRS = ["node_modules", ".git", "dist", "build", "out", ".output", ".next", ".nuxt", ".svelte-kit", ".astro", ".vercel", ".netlify", ".wrangler", ".turbo", ".cache", "venv", ".venv", "__pycache__", "coverage", "vendor", "third_party", "bower_components"];
const SKIP = new Set(SKIP_DIRS);
// Bundled builds of libraries checked into a repo, e.g. vue.global.js (field test, 139 repos).
const BUNDLED = /\.(min|global|bundle|umd|prod)\.(js|css)$/;
const MAX_LINE = 1000; // longer lines are minified or generated: they are ignored, not the whole file
const MAX_BYTES = 1_000_000;
/** A file is generated or minified when long lines make up more than a twentieth of it. Pure. */
export const isMinified = (lines: string[]) => lines.filter((l) => l.length > MAX_LINE).length > Math.max(1, lines.length / 20);
/** Normalises file extensions so rules written for .ts also read .mts and .cts, and every .env file is ".env". */
export function extOf(abs: string): string {
  const name = basename(abs);
  if (/^\.env(\.[\w.-]+)?$/.test(name)) return ".env";
  if (/^(Dockerfile|Containerfile)\b|\.Dockerfile$/i.test(name)) return ""; // Dockerfile.prod, api.Dockerfile and Containerfile are Dockerfiles too
  const e = extname(abs);
  return e === ".mts" || e === ".cts" ? ".ts" : e;
}

/** Scout: list files to check, sorted so output order never depends on the file system. */
const OWN_OUTPUT = /^lintsure(-report\.(md|json)|-assessment\.html|\.sarif)$/;
export async function listFiles(root: string, ignore: string[] = []): Promise<string[]> {
  const out: string[] = [];
  const ignored = (p: string) => { const r = relative(root, p).split(sep).join("/"); return ignore.some((i) => r === i || r.startsWith(i + "/")); };
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name) || BUNDLED.test(e.name)) continue;
      const p = join(dir, e.name);
      if (ignored(p)) continue;
      // Lintsure's own reports quote the flagged lines, so scanning them would flag the same code again.
      if (e.isDirectory()) await walk(p); else if (e.isFile() && !OWN_OUTPUT.test(e.name)) out.push(p);
    }
  }
  await walk(root);
  return out.sort();
}

// Code that doesn't ship: tests, fixtures, examples, docs, demos, stories and seed data. Most false alarms in the
// 139-repo field test came from here. Only the secret rules read these paths, and their findings there are Partial.
export const NON_SHIPPING = /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|examples?|samples?|demos?|cookbooks?|docs?|stories|storybook|seeds?|seeders|factories|\.dev|benchmarks?|loadtests?|load-tests?|testdata|test-data|scripts?|\.agents|\.claude|\.cursor|\.devcontainer)\/|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$|(^|\/)(conftest\.py|pytest\.ini|tox\.ini)$|(^|\/)\.env\.(example|sample|template|dist)$|(^|\/)(playwright|vitest|jest|cypress)\.config\.[cm]?[jt]s$/i;
// In Next.js, Remix and Supabase a folder name is a route or a function name: app/api/demo and a function called
// "test" are live endpoints (review P3). Inside these roots only real test files count as non-shipping.
// Example, demo, docs and sample folders inside application source (src/, lib/, server/) are shipping code too.
const LIVE_ROOT = /(^|\/)(app|pages|api|routes|supabase\/functions|src|lib|server)\//;
const NS_FOLDER = /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|examples?|samples?|demos?|cookbooks?|docs?|stories|storybook|seeds?|seeders|benchmarks?|loadtests?|load-tests?|testdata|test-data|scripts?|\.agents|\.claude|\.cursor|\.devcontainer)\//i;
// Dev scripts at the top of a repo (scripts/test-*.mjs, build and seed helpers) and agent tooling (.agents/, .claude/)
// don't ship: they were the largest single source of false alarms in the 0.3.9 labelled sample (44 of 242).
const TEST_FILE = /(^|\/)__tests__\/|(^|\/)test[-_]?(utils?|helpers?|rig)\/|(^|\/)test-[^/]+\.[cm]?[jt]s$|[._-]tests?\/|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$|(^|\/)(conftest\.py|pytest\.ini|tox\.ini)$/i;
// Files named for what they hold: seed.js, seed-users.ts, demo.ts, mock-data.ts, orders.mock.ts, user.fixture.ts.
const DEV_FILE = /(^|\/)(seeds?|demo|mocks?)([-_.][\w.-]*)?\.([cm]?[jt]sx?|py)$|\.(mock|fixtures?)\.[cm]?[jt]sx?$/i;
// Test and fixture folders. Agent-tooling rules read .claude/ and .agents/ on purpose, but a hostile SKILL.md kept as a
// test fixture is a test input, not an instruction anyone's agent loads.
const TEST_PATH = /(^|\/)(tests?|__tests__|fixtures?|__fixtures__|e2e|testdata|test-data)\//i;
/** True for code that doesn't ship: tests, fixtures, examples, docs, stories and seed data. A folder name only counts
 *  when it comes before any app or route root in the path: examples/site/app/page.tsx is an example, while
 *  app/api/demo/route.ts and src/samples/handler.ts are live code. Pure. */
export function isNonShipping(file: string): boolean {
  if (TEST_FILE.test(file)) return true;
  // Shell scripts in scripts/ are often the installer people run (curl ... | sh): those still count.
  if (/\.(sh|bash|zsh|ps1)$/i.test(file) && !/(^|\/)(tests?|__tests__|e2e|fixtures?|examples?|demos?|\.devcontainer)\//i.test(file)) return false;
  const live = LIVE_ROOT.exec(file), ns = NS_FOLDER.exec(file);
  if (!live || (ns && ns.index < live.index)) return NON_SHIPPING.test(file);
  // Under a route root every folder is a URL or function name, so only test files (handled above) are skipped.
  if (/^(app|pages|api|routes|supabase\/functions)$/.test(live[2])) return false;
  // Under src/, lib/ or server/, test folders are still tests; example, demo, docs and sample folders are app code.
  // Dev scripts kept inside the app folder (server/scripts/reset_admin_password.py) and files named for seed, demo
  // or mock data don't ship either (0.3.14 review: 3 false alarms, no real finding in such a file).
  const rest = file.slice(live.index);
  return /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|seeds?|seeders|factories|stories|storybook|scripts?)\//i.test(rest) || DEV_FILE.test(rest);
}
// Rules that also read test files. Not auth.hardcoded-password: test logins are fake by design (field test, 50 repos).
const SECRET_RULES = new Set(["secret.in-source"]); // not config.default-secret-key: a test secret is a test value (review P19)
// Rules that read agent tooling folders on purpose: an agent hook in .claude/ runs on real machines.
// Settings that sit in the branch that only runs outside production (`if IS_PRODUCTION: ... else:`, `if (!isProduction) {`)
// are dev settings (0.3.14 review: 2 of 2). Only for rules about a setting, where the branch decides what ships.
const DEV_BRANCH_RULES = new Set(["config.allowed-hosts-any", "cors.any-origin"]);
/** True when line i sits inside a branch taken only outside production. Reads indentation, up to 30 lines back. Pure. */
export function inDevBranch(lines: string[], i: number): boolean {
  const indent = (l: string) => l.search(/\S/);
  const opens = /^\s*(\}\s*else\s+)?(if|elif)\b/;
  const negated = (l: string) => /!\s*[\w.]*prod|\bnot\s+[\w.]*prod|!==?\s*["']production["']/i.test(l);
  let level = indent(lines[i]);
  for (let k = i - 1; k >= Math.max(0, i - 30) && level > 0; k--) {
    const at = indent(lines[k]);
    if (at < 0 || at >= level) continue;
    level = at;
    if (/^\s*(\}\s*)?else\s*[:{]?\s*$/.test(lines[k])) { // a plain else: its `if` is the nearest opener above at the same indent
      const open = lines.slice(Math.max(0, k - 30), k).reverse().find((x) => indent(x) === at && opens.test(x));
      if (open && /\b(is_?prod(uction)?|production)\b/i.test(open) && !negated(open)) return true;
    } else if (opens.test(lines[k]) && (negated(lines[k]) || /(?<!!\s*)(?<!\bnot\s)\b(is_?dev\w*|DEBUG)\b|===?\s*["']development["']/.test(lines[k]))) return true;
  }
  return false;
}
/** Names of functions in this file that wrap a masking call: `def _refusal(email): return pseudonym(email)`. A value logged
 *  through one is masked too (0.3.14 review). Pure.
 *  shortcut: reads the 12 lines after the definition, not the real function body; parse the body if that misleads. */
export function localMaskers(lines: string[]): string[] {
  return lines.flatMap((l, i) => {
    const m = /^\s*(?:export\s+)?(?:async\s+)?(?:def|function)\s+(\w+)\s*\(|^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(/.exec(l);
    return m && lines.slice(i + 1, i + 13).some((x) => MASKED.test(x)) ? [m[1] ?? m[2]] : [];
  });
}
const TOOLING_RULES = new Set(["agent.config-runs-remote-code", "agent.instructions-unsafe", "agent.permissions-allow-all"]);
// Lines a person already reviewed. lintsure-ignore and the secret allowlist pragma count only in a comment and apply
// to every rule. Other linters' markers (noqa, nosec, NOSONAR) don't hide secrets: `# noqa: E501` is about line length.
const REVIEWED = /(#|\/\/|\/\*|--)\s*(lintsure-ignore|pragma:\s*allowlist secret)\b/;
const OTHER_LINTER = /#\s*(noqa|nosec|nosemgrep|NOSONAR)\b|\/\/\s*(NOSONAR|nosemgrep)\b/i;
// Also hand-typed fake keys: alphabet or number runs, words where random text should be, a whole key block on one line.
const PLACEHOLDER =/test|fake|dummy|example|sample|placeholder|sanitized|mock|xxx|changeme|localhost|["'](password|pass|secret|elastic|admin)["']|abcdef|123456|\b(xox[baprs]|gh[pousr])[-_][a-z]+(-[a-z]+)*\b|PRIVATE KEY-----.*-----END/i;
/** The JSON object key that opens the block a line sits in, e.g. "peerDependencies". Pure. */
export function enclosingKey(lines: string[], i: number): string {
  let depth = 0;
  for (let j = i - 1; j >= 0; j--) {
    const l = lines[j];
    depth += (l.match(/\}/g) ?? []).length - (l.match(/\{/g) ?? []).length;
    if (depth < 0) return l.match(/"([^"]+)"\s*:\s*\{/)?.[1] ?? "";
  }
  return "";
}
/** enclosingKey for every line in one pass (calling it per line was quadratic: minutes on a large JSON file). Pure. */
export function enclosingKeys(lines: string[]): string[] {
  const stack: string[] = [], out: string[] = [];
  for (const l of lines) {
    out.push(stack.length ? stack[stack.length - 1] : "");
    const key = l.match(/"([^"]+)"\s*:\s*\{/)?.[1] ?? "";
    for (const ch of l) if (ch === "{") stack.push(key); else if (ch === "}") stack.pop();
  }
  return out;
}
// Example code that shows a pattern instead of running it (benchmark "fp" cases, self-scan 2026-11-19): a fenced block
// in a doc, a value under an example-style key in JSON data. Only secret rules still look, and only for a real-looking key.
const EXAMPLE_KEY = /^(?:examples?|code|snippets?|samples?|bad|good|before|after|demo|patch|diff|dont|do)$/i;
const EXAMPLE_KEY_ON_LINE = /"(?:examples?|code|snippets?|samples?|bad|good|before|after|demo|patch|diff|dont|do)"\s*:/i;
export function exampleLines(lines: string[], ext: string): boolean[] {
  if (ext === ".md" || ext === ".mdx") { let fence = false; return lines.map((l) => { if (/^\s*(```|~~~)/.test(l)) { fence = !fence; return true; } return fence; }); }
  if (ext === ".json") { const keys = enclosingKeys(lines); return lines.map((l, i) => EXAMPLE_KEY_ON_LINE.test(l) || EXAMPLE_KEY.test(keys[i])); }
  return lines.map(() => false);
}
// Call-sink rules whose match must come from code, not from text inside a '...' or "..." string (a demo diff stored as
// data). Template literals are left alone: `exec(\`zip ${req.body.f}\`)` is real code.
// One hop of request data (benchmark "hop" cases): a request value saved in `target`, then `target` passed to a URL call. Variables assigned from
// the request are found per file, and a later line is reread with the request value written in place. A variable that is
// checked before use (startsWith, includes, a comparison, a test) is left alone. Hits are Partial: the hop is a guess.
// shortcut: one assignment hop inside one file, no reassignment or function-argument flow; upgrade to a real data-flow pass if recall stays low.
const REQUEST_SINK_RULES = new Set(["sql.string-built", "cmd.shell-built", "code.eval", "deserialize.unsafe", "ci.script-injection", "jwt.unverified"]);
const HOP_RULES = new Set(["ssrf.user-url", "redirect.open", "path.user-input"]);
const REQ_VALUE = /\b(?:req\.(?:body|query|params|headers|cookies)|request\.(?:args|form|json|data|GET|POST|query_params|files)|ctx\.query|event\.(?:body|queryStringParameters)|searchParams\.get)\b/;
// A request value cleaned where it is assigned isn't request data any more; a lookup by a request id returns a server
// record (field-test review 2026-11-20: 0 of 8 redirect and path findings were real, all through these).
const SANITIZER = /\b(?:safe\w*|sanitiz\w*|validat\w*|isSafe\w*|isAllowed\w*|encodeURIComponent|encodeURI|quote|basename|secure_filename|parseInt|parseFloat|Number|escape\w*)\s*\(/i;
const LOOKUP = /\.(?:find|findOne|findFirst|findById|findByPk|findUnique|getById|filter)\s*\(|\b(?:get_object_or_404|get_or_404|get\w*ById)\s*\(/;
// Calls that hand the same value back (or join it into a path or URL). Any other call returns a new value.
const PASS = new Set(["join", "resolve", "URL", "String", "str", "decodeURIComponent", "decodeURI", "unquote", "toString", "trim", "toLowerCase", "toUpperCase", "replace", "concat", "slice", "normalize", "format", "Path"]);
const hasName = (t: string, n: string) => new RegExp(`(?<![.\\w])${n}\\b`).test(t);
/** The text with every call that returns a new value blanked, so only values that pass straight through stay. Pure. */
function passThrough(t: string): string {
  for (let k = 0; k < 8; k++) {
    const next = t.replace(/\b(\w+)\s*\(([^()]*)\)/g, (_m, fn: string, args: string) => (PASS.has(fn) ? " " + args + " " : " _ "));
    if (next === t) break;
    t = next;
  }
  return t;
}
const parentsOf = new WeakMap<Map<string, number>, Map<string, string[]>>();
export function taintedNames(lines: string[]): Map<string, number> {
  const out = new Map<string, number>(), parents = new Map<string, string[]>();
  lines.forEach((l, i) => {
    const m = l.match(/^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=(?!=)/) ?? l.match(/^\s*(\w+)\s*=(?!=)/);
    const d = l.match(/^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=/);
    const lhs = [...(m ? [m[1]] : []), ...(d ? d[1].split(",").map((n) => n.split(":").pop()!.split("=")[0].trim()).filter((k) => /^\w+$/.test(k)) : [])];
    if (!lhs.length) return;
    const rhs = l.slice(l.indexOf("=") + 1);
    let from: string[] | null = null;
    if (REQ_VALUE.test(rhs)) from = SANITIZER.test(rhs) || LOOKUP.test(rhs) ? null : [];
    else {
      const via = [...out.keys()].filter((n) => hasName(rhs, n));
      if (via.length && !SANITIZER.test(rhs)) { const kept = passThrough(rhs); const live = via.filter((n) => hasName(kept, n)); if (live.length) from = live; }
    }
    for (const n of lhs) { if (from) { out.set(n, i); parents.set(n, from); } else if (out.has(n)) { out.delete(n); parents.delete(n); } }
  });
  parentsOf.set(out, parents);
  return out;
}
const GUARD = (n: string) => new RegExp(`\\b${n}(?:\\.\\w+)*\\s*(?:\\.(?:startsWith|endsWith|includes|match|test)\\(|[!=]==?)|\\b(?:allow\\w*|isAllowed\\w*|isValid\\w*|isSafe\\w*|is_safe\\w*|validate\\w*|sanitiz\\w*|safe\\w*)\\(\\s*${n}\\b|\\.(?:has|includes|test)\\(\\s*${n}\\b`);
/** Checked between where it was set and line i, or its source was checked before it was copied. Pure. */
function guarded(lines: string[], n: string, i: number, names: Map<string, number>, seen = new Set<string>()): boolean {
  const at = names.get(n);
  if (at === undefined || seen.has(n)) return false;
  seen.add(n);
  if (lines.slice(at + 1, i).some((l) => GUARD(n).test(l))) return true;
  return (parentsOf.get(names)?.get(n) ?? []).some((p) => guarded(lines, p, at, names, seen));
}
export function hopLine(lines: string[], i: number, names: Map<string, number>): string | null {
  let t = lines[i], changed = false;
  for (const [n, at] of names) {
    if (at >= i || !new RegExp(`\\b${n}\\b`).test(t)) continue;
    if (guarded(lines, n, i, names)) continue;
    t = t.replace(new RegExp(`(?<![.\\w])${n}\\b`, "g"), "req.query." + n); changed = true;
  }
  return changed ? t : null;
}
const PROMPT_DOC = /(^|\/)(?:prompts?|personas?|instructions?|system)(?:\/|[._-])|(^|\/)(?:AGENTS|CLAUDE|GEMINI|SKILL|SYSTEM|PROMPT)\.mdx?$|\.prompt\.mdx?$|(^|\/)\.(?:github|cursor|claude)\//i;
const SINK_RULES = new Set(["path.user-input", "ssrf.user-url", "redirect.open", "code.eval", "cmd.shell-built", "deserialize.unsafe"]);
// One pass, no regex: a line with an unclosed quote and many escapes must not cost more than its length (CodeQL js/polynomial-redos).
export function blankStrings(l: string): string {
  let out = "", q = "", start = 0;
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (q) { if (c === "\\") i++; else if (c === q) { out += q + q; q = ""; } continue; }
    if (c === "'" || c === '"') { q = c; start = i; } else out += c;
  }
  return q ? out + l.slice(start) : out; // an unclosed quote is left as it was, like the old regex that didn't match it
}
const HASH_COMMENTS = new Set([".py", ".rb", ".sh", ".yml", ".yaml", ".toml", ".env"]);
const C_LIKE = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".java", ".kt", ".swift", ".go", ".css", ".scss"]);

// Statement window (review step A): formatters split one call over several lines, and a rule that reads one line
// never sees `logger.info("signup", {` and `email: user.email` together. These are the files where that happens.
const JOINABLE = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"]);
// Rules that read whole statements. Only where it was measured to help without "join artifacts" (words from different
// parts of one statement matching together). Measured on 139 repos: SQL, shell, secret-in-log, random-token and
// system-prompt checks gained mostly false alarms when joined (5 of 41 sampled gains real), so they stay line by line.
const JOIN_RULES = new Set(["pii.logged", "pii.to-analytics", "log.injection", "upload.unrestricted", "mass-assignment",
  "ssrf.user-url", "path.user-input", "redirect.open", "nosql.operator-input", "template.user-string", "error.stack-to-client",
  // Narrow call-plus-value patterns, where unrelated parts of a statement rarely complete a match.
  "transport.plain-http", "transport.tls-verify-off", "jwt.unverified", "crypto.weak-cipher", "fs.world-writable",
  "mobile.token-in-plain-storage", "config.debug-on", "cookie.trusted-role", "code.eval",
  // Added with rules/more.ts: call-plus-argument shapes, measured on the robustness check only (not yet on the 139 repos).
  "authz.no-owner-check", "jwt.weak-secret", "jwt.no-algorithm-pin", "proto.pollution"]);
const MAX_JOIN_LINES = 25, MAX_JOIN_CHARS = 2000;
export interface Statement { start: number; end: number; text: string; prose: boolean }
/** Groups lines into statements: lines join while a ( or [ or a template literal is open. Joining stops at a function
 *  body (`=> {`, `) {`), so a handler passed as an argument stays line by line. `prose` marks a multi-line template
 *  literal with no ${} (a prompt or help text), which is text, not code. Lines already blanked as comments are empty. Pure. */
export function statements(lines: string[], py = false): Statement[] {
  // A function body or a Python block starts here: stop joining so the body stays line by line.
  const BODY = py ? /:\s*$/ : /(=>|\))\s*\{\s*$|\bfunction\b[^{]*\{\s*$/;
  const out: Statement[] = [];
  let i = 0;
  while (i < lines.length) {
    let depth = 0, tpl = false, interp = false, j = i;
    for (; j < lines.length && j - i < MAX_JOIN_LINES; j++) {
      const l = lines[j]; let q = "";
      for (let k = 0; k < l.length; k++) {
        const c = l[k];
        if (tpl) { if (c === "\\") k++; else if (c === "`") tpl = false; else if (c === "$" && l[k + 1] === "{") interp = true; continue; }
        if (q) { if (c === "\\") k++; else if (c === q) q = ""; continue; }
        if (c === '"' || c === "'") q = c;
        else if (c === "`") tpl = true;
        else if (py ? c === "#" : c === "/" && l[k + 1] === "/") break;
        else if (c === "(" || c === "[") depth++;
        else if (c === ")" || c === "]") depth = Math.max(0, depth - 1);
      }
      if (!depth && !tpl) break;
      if (!tpl && BODY.test(l.trim())) break;
    }
    const end = Math.min(j, lines.length - 1);
    const text = lines.slice(i, end + 1).map((x) => x.trim()).join(" ").slice(0, MAX_JOIN_CHARS);
    const body = lines.slice(i, end + 1).join("\n");
    // Prose only when the template closes inside this statement: one cut off by the length cap may hold ${} further down.
    out.push({ start: i, end, text, prose: end > i && !tpl && /`[^`]*\n[^`]*`/.test(body) && !interp });
    i = end + 1;
  }
  return out;
}

/** Marks lines that are only a comment or sit inside a block comment, Python docstring or multi-line string. Pure. */
export function commentLines(lines: string[], ext: string): boolean[] {
  const hash = HASH_COMMENTS.has(ext), py = ext === ".py", sql = ext === ".sql";
  let block = false, doc = false, quote = "";
  return lines.map((raw) => {
    const t = raw.trim();
    if (block) { if (t.includes("*/")) block = false; return true; }
    if (doc) { if (t.includes(quote)) doc = false; return true; }
    if (py) {
      if (t.startsWith("#")) return true; // a comment that mentions """ opens no string (review P8)
      const q = t.match(/"""|'''/)?.[0];
      // An odd number of triple quotes opens a string that runs onto the next lines. A docstring line is text;
      // `PROMPT = """` is code whose string continues, and its closing quotes must not open a fake docstring (field test).
      if (q && t.split(q).length % 2 === 0) { doc = true; quote = q; return /^[rbuf]*("""|''')/i.test(t); }
      if (q && /^[rbuf]*("""|''')/i.test(t) && t.endsWith(q)) return true; // one-line docstring
    }
    // `/* note */ code();` is code: only a line that is all comment counts.
    if (t.startsWith("/*")) { const end = t.indexOf("*/"); if (end < 0) { block = true; return true; } return !t.slice(end + 2).trim(); }
    return t.startsWith("//") || (C_LIKE.has(ext) && t.startsWith("*")) || t.startsWith("<!--") || (hash && t.startsWith("#")) || (sql && t.startsWith("--"));
  });
}

export interface ScanOptions extends RecordOptions {
  /** Also list medium-confidence findings. Overrides `show:` in the config when set. */
  all?: boolean;
  /** --diff: only report findings on these changed lines ("/"-separated paths, 1-based lines). */
  changed?: { base: string; lines: Record<string, number[]> };
  /** Workspace rules from a Lintsure account, handed in by the caller (the plugin downloads them with an API key).
   *  The scan never fetches anything; it only hashes what it is given into the policy fingerprint. */
  workspaceRules?: unknown;
}

/** The repo's .lintsure/rules.yml (the Drift Guard's rules), normalized: comments, blank lines and trailing spaces dropped.
 *  null when the file isn't there. */
/** A YAML line without its comment: a # at the start or after a space, outside quotes ("rm # a" keeps its #). Pure. */
export function stripYamlComment(l: string): string {
  let q = "";
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (q) { if (c === q) q = ""; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === "#" && (i === 0 || /\s/.test(l[i - 1]))) return l.slice(0, i);
  }
  return l;
}
async function readRepoRules(root: string): Promise<string | null> {
  try {
    const text = await readFile(join(root, ".lintsure", "rules.yml"), "utf8");
    return text.split(/\r?\n/).map((l) => stripYamlComment(l).trimEnd()).filter((l) => l.trim()).join("\n");
  } catch { return null; }
}

/** JSON with object keys sorted at every level, so the same data always hashes the same. */
const stable = (v: unknown): string => Array.isArray(v) ? `[${v.map(stable).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`
  : JSON.stringify(v ?? null);

/** The policy a scan ran under, as one short code. Same rules and settings give the same code on any machine;
 *  any change (a rule switched off or re-rated, a framework, an ignore path, show: all, a new rules version) gives a new one.
 *  `fingerprint` is the first 8 hex digits of `sha256`, shown as XXXX-XXXX. It names the policy; it doesn't sign anything. */
export function policyFingerprint(p: { frameworks: string[]; rules: { id: string; severity: string }[]; rulesOff: string[]; ignore: string[]; show?: string; repoRules?: string | null; workspaceRules?: unknown; packs?: string[] }) {
  const canon = JSON.stringify({
    rulesVersion: RULES_VERSION,
    frameworks: [...p.frameworks].sort(),
    rules: [...p.rules].sort((a, b) => a.id.localeCompare(b.id)).map((r) => `${r.id}:${r.severity}`),
    rulesOff: [...p.rulesOff].sort(),
    ignore: [...p.ignore].sort(),
    show: p.show ?? "default",
    // Installed rule packs and their versions. Left out when none, so codes from before packs existed stay the same.
    ...(p.packs?.length ? { packs: [...p.packs].sort() } : {}),
    // The Drift Guard's .lintsure/rules.yml, comments and blank lines dropped, so only a real rule change moves the code.
    repoRules: p.repoRules ?? null,
    // Account (workspace) rules, when the caller passed them: key order doesn't matter, content does.
    workspaceRules: p.workspaceRules == null ? null : stable(p.workspaceRules),
  });
  const sha256 = createHash("sha256").update(canon).digest("hex");
  return { fingerprint: `${sha256.slice(0, 4)}-${sha256.slice(4, 8)}`.toUpperCase(), sha256, rulesActive: p.rules.length, repoRules: p.repoRules != null, workspaceRules: p.workspaceRules != null };
}

export async function scan(root: string, frameworks: FrameworkId[] = ALL_FRAMEWORKS, opts: ScanOptions = {}): Promise<Report> {
  const config = await readConfig(root);
  const { ignore } = config;
  // Packs are registered for the whole process; this scan uses only the ones its own config lists.
  const ownPacks = new Set(config.packs ?? []);
  const usable = (packId: string) => !configPacks.has(packId) || ownPacks.has(packId);
  frameworks = frameworks.filter((f) => !packFrameworks.has(f) || usable(packFrameworks.get(f)!));
  const rulesOff = Object.keys(config.rules).filter((id) => config.rules[id] === "off");
  const active = rules.filter((r) => r.controls.some((c) => frameworks.includes(c.framework)) && !rulesOff.includes(r.id));
  const findings: Finding[] = [];
  let filesChecked = 0, checkPoints = 0, nonShipping = 0;
  const perRule: Record<string, number> = {};
  const all = await listFiles(root, ignore);
  // Repository checks look at the file list once, not at file contents. The finding points at the file that's missing.
  const paths = all.map((p) => relative(root, p).split(sep).join("/"));
  for (const r of active.filter((x) => x.repoTest)) {
    checkPoints++; perRule[r.id] = 1;
    const file = r.repoTest!(paths);
    if (!file) continue;
    const controls = r.controls.filter((c) => frameworks.includes(c.framework));
    findings.push({ id: "", ruleId: r.id, file, line: 1, status: r.status, severity: r.severity, title: r.title, controls, fix: r.fix, note: r.note,
      proposal: proposalFor({ file, line: 1, title: r.title, fix: r.fix, note: r.note, controls }), fingerprint: fingerprint(r.id, file, ""),
      ...(r.status === "partial" ? { unseen: r.unseen ?? UNSEEN } : {}) });
  }
  // Every file is read once per scan, with one size and binary guard for every reader (code review: files were read up
  // to four times, one at a time). Reads run 32 at a time; null means too big, binary or unreadable.
  const cache = new Map<string, Promise<string | null>>();
  const textOf = (abs: string) => {
    let t = cache.get(abs);
    if (!t) { t = stat(abs).then(async (st) => { if (st.size > MAX_BYTES) return null; const b = await readFile(abs); return b.includes(0) ? null : b.toString("utf8"); }).catch(() => null); cache.set(abs, t); }
    return t;
  };
  // Prefetch only files some reader needs: a rule that applies to it, a shared-file rule, or reachability.
  const needed = all.filter((abs, k) => {
    const ext = extOf(abs), name = basename(abs), file = paths[k];
    return /\.(m|c)?[jt]sx?$|\.html?$|(^|\/)(package|tsconfig)\.json$/.test(file) || active.some((r) => r.sharedFiles?.test(file)
      || (r.extensions.includes(ext) && (!r.fileName || r.fileName.test(name)) && (!r.pathMatch || r.pathMatch.test(file)) && !r.unlessPath?.test(file)));
  });
  for (let i = 0; i < needed.length; i += 32) await Promise.all(needed.slice(i, i + 32).map(textOf));
  // Say what was not read, so "no findings" is never read as "checked everything".
  let filesSkipped = 0;
  for (const abs of needed) if ((await textOf(abs)) === null) filesSkipped++;
  // Rules that look across files get the joined text of every file they read, read once up front.
  const shared = new Map<string, string>();
  for (const r of active.filter((x) => x.sharedContext)) {
    const texts: string[] = [];
    for (const [k, abs] of all.entries()) {
      const ext = extOf(abs), file = paths[k];
      if (!r.extensions.includes(ext) || (r.fileName && !r.fileName.test(basename(abs))) || (r.pathMatch && !r.pathMatch.test(file)) || r.unlessPath?.test(file)) continue;
      const text = (await textOf(abs)) ?? "";
      // Commented-out lines don't count: "-- alter table x enable row level security" switches nothing on.
      const comment = commentLines(text.split(/\r?\n/), ext);
      texts.push(text.split(/\r?\n/).filter((_, i) => !comment[i]).join("\n"));
    }
    shared.set(r.id, texts.join("\n"));
  }
  // Rules that read two files together (a config entry and the code it points to) get those files by path.
  const sharedFiles = new Map<string, Record<string, string>>();
  for (const r of active.filter((x) => x.sharedFiles)) {
    const files: Record<string, string> = {};
    for (const [k, abs] of all.entries()) if (r.sharedFiles!.test(paths[k])) files[paths[k]] = (await textOf(abs)) ?? "";
    sharedFiles.set(r.id, files);
  }
  for (const abs of all) {
    const ext = extOf(abs);
    const name = basename(abs);
    const file = relative(root, abs).split(sep).join("/");
    const relevant = active.filter((r) => r.extensions.includes(ext) && (!r.fileName || r.fileName.test(name)) && (!r.pathMatch || r.pathMatch.test(file)) && !r.unlessPath?.test(file));
    if (!relevant.length) continue;
    const whole = await textOf(abs);
    if (whole === null) continue; // big, binary or unreadable
    const raw = whole.split(/\r?\n/);
    if (isMinified(raw)) continue; // minified or generated
    // A single very long line (a data URL, a long prompt) is ignored on its own; the rest of the file is still read.
    const lines = raw.map((l) => (l.length > MAX_LINE ? "" : l));
    let ran = 0;
    const add =(r: (typeof relevant)[number], line: number, status: Finding["status"] = r.status) => {
      const controls = r.controls.filter((c) => frameworks.includes(c.framework));
      findings.push({
        id: "", ruleId: r.id, file, line, status, severity: r.severity, title: r.title, controls, fix: r.fix, note: r.note,
        proposal: proposalFor({ file, line, title: r.title, fix: r.fix, note: r.note, controls }),
        fingerprint: fingerprint(r.id, file, lines[line - 1] ?? ""),
        ...(status === "partial" ? { unseen: inTests && !TOOLING_RULES.has(r.id) ? UNSEEN_TESTS : r.unseen ?? UNSEEN } : {}),
        ...patchFor(r, line, lines[line - 1] ?? ""),
      });
    };
    // Tests, fixtures, examples and docs are full of fake tokens and planted examples: only secret rules look at them,
    // and what they find there is Partial (it may be a throwaway key).
    const inTests = isNonShipping(file);
    if (inTests) nonShipping++;
    const comment = commentLines(lines, ext), example = exampleLines(lines, ext);
    let tainted: Map<string, number> | undefined;
    let maskers: string[] | undefined;
    const viaMasker = (text: string) => (maskers ??= localMaskers(lines)).some((n) => text.includes(n + "("));
    // Statements are worked out once per file, on lines with comments blanked.
    const stmts = JOINABLE.has(ext) ? statements(lines.map((l, i) => (comment[i] ? "" : l)), ext === ".py") : [];
    const multi = stmts.filter((s) => s.end > s.start);
    const prose = new Array<boolean>(lines.length).fill(false);
    for (const s of multi) if (s.prose) for (let i = s.start; i <= s.end; i++) prose[i] = true;
    for (const r of relevant) {
      // A markdown page that explains the rule quotes the bad prompt; only prompt files hold real prompts.
      if (r.id === "ai.hides-being-ai" && (ext === ".md" || ext === ".mdx") && !PROMPT_DOC.test(file)) continue;
      const secret = SECRET_RULES.has(r.id);
      if (inTests && !secret && !(TOOLING_RULES.has(r.id) && !TEST_PATH.test(file) && !TEST_FILE.test(file))) continue;
      // Count only what actually ran: a file skipped as a test is not a check point (review P1).
      ran++; checkPoints++; perRule[r.id] = (perRule[r.id] ?? 0) + 1;
      // Comments describe code, they don't run. A real secret pasted into a comment still counts.
      const skip = secret ? null : comment;
      // Prompt and help text inside a multi-line template is words, not code (review P9), except for the rule that
      // reads prompts on purpose.
      const readsText = secret || r.id === "ai.hides-being-ai";
      const hitLines = new Set<number>();
      if (r.test) lines.forEach((text, i) => {
        if (skip?.[i] || (prose[i] && !readsText)) return;
        if (example[i] && !(secret && !PLACEHOLDER.test(text))) return;
        let hit = r.test!(text), probe = text;
        if (!hit && HOP_RULES.has(r.id)) { const h = hopLine(lines, i, (tainted ??= taintedNames(lines))); if (h && r.test!(h)) { hit = "partial"; probe = h; } }
        if (hit && SINK_RULES.has(r.id) && !r.test!(blankStrings(probe))) return;
        if (!hit || (r.unlessNear && lines.slice(Math.max(0, i - 8), i + 4).some((l) => r.unlessNear!.test(l)))) return;
        if (r.unlessInKey && r.unlessInKey.test(enclosingKey(lines, i))) return;
        if (DEV_BRANCH_RULES.has(r.id) && inDevBranch(lines, i)) return;
        if (r.id === "pii.logged" && viaMasker(probe)) return;
        if (inTests && secret && PLACEHOLDER.test(text)) return; // password="test_password", token="xoxb-test-..."
        if (inTests && /PRIVATE KEY/.test(text)) return; // test keys and certificates are fixtures by design (review P24)
        if (REVIEWED.test(text) || (!secret && OTHER_LINTER.test(text))) return; // someone already looked at this line and marked it
        hitLines.add(i);
        add(r, i + 1, hit === "partial" || (inTests && !TOOLING_RULES.has(r.id)) ? "partial" : r.status);
      });
      // A statement spread over several lines: test it as one, and report it only when no single line already did,
      // so line-by-line results never shrink (review step A).
      if (r.test && JOIN_RULES.has(r.id)) for (const s of multi) {
        if (s.prose && !readsText) continue;
        let already = false; for (let i = s.start; i <= s.end; i++) if (hitLines.has(i)) { already = true; break; }
        if (already) continue;
        const hit = r.test(s.text);
        if (hit && r.id === "pii.logged" && viaMasker(s.text)) continue;
        if (!hit || (r.unlessNear && lines.slice(Math.max(0, s.start - 8), s.end + 4).some((l) => r.unlessNear!.test(l)))) continue;
        if (r.unlessInKey && r.unlessInKey.test(enclosingKey(lines, s.start))) continue;
        if (lines.slice(s.start, s.end + 1).some((l) => REVIEWED.test(l) || OTHER_LINTER.test(l))) continue;
        add(r, s.start + 1, hit === "partial" || (inTests && !TOOLING_RULES.has(r.id)) ? "partial" : r.status);
      }
      // File rules see comment lines as blank, so "<img> in a comment" or a commented-out call doesn't count (field test).
      // A Python MCP tool's description is its docstring, so this rule reads docstrings too (it drops # and // lines itself).
      if (r.fileTest) for (const n of r.fileTest(skip && r.id !== "mcp.tool-description-poisoned" ? lines.map((l, i) => (skip[i] ? "" : l)) : lines, shared.get(r.id), sharedFiles.get(r.id)))
        if (!(DEV_BRANCH_RULES.has(r.id) && inDevBranch(lines, (typeof n === "number" ? n : n.line) - 1))) typeof n === "number" ? add(r, n) : add(r, n.line, n.status);
    }
    if (ran) filesChecked++;
  }
  // Auditor: one finding per rule per line; stable order.
  const seen = new Set<string>();
  const unique = findings.filter((f) => { const k = `${f.ruleId}|${f.file}|${f.line}`; return seen.has(k) ? false : (seen.add(k), true); })
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  // Reachability for findings in JS/TS: read the project's own JS/TS files once (skipping very large ones) and follow
  // imports back to entry points. It adds context; it doesn't change any status.
  const JSTS = /\.(m|c)?[jt]sx?$/;
  if (unique.some((f) => JSTS.test(f.file))) {
    const code: Record<string, string> = {};
    for (const [k, abs] of all.entries()) if (JSTS.test(paths[k]) && !/\.d\.ts$/.test(paths[k])) {
      const t = (await textOf(abs)) ?? ""; if (t.length < 500_000) code[paths[k]] = t;
    }
    const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
    const tsconfigs: Record<string, string> = {};
    for (const [k, abs] of all.entries()) if (/(^|\/)tsconfig\.json$/.test(paths[k])) tsconfigs[dirOf(paths[k])] = (await textOf(abs)) ?? "";
    const pkgDirs = paths.filter((p) => /(^|\/)package\.json$/.test(p)).map(dirOf);
    // Entry points no code imports: package.json main/bin/exports and <script src> in HTML pages.
    const pkgs: Record<string, string> = {}, html: Record<string, string> = {};
    for (const [k, abs] of all.entries()) {
      if (/(^|\/)package\.json$/.test(paths[k])) pkgs[paths[k]] = (await textOf(abs)) ?? "";
      else if (/\.html?$/.test(paths[k])) { const t = (await textOf(abs)) ?? ""; if (t.length < 500_000) html[paths[k]] = t; }
    }
    const graph = buildGraph(code, tsconfigs, pkgDirs.length ? pkgDirs : [""], declaredEntries(pkgs, html, new Set(Object.keys(code))));
    for (const f of unique) if (JSTS.test(f.file)) f.reach = reachOf(graph, f.file);
  }
  // A rule that fired still counts as checked (not Met) even when its findings are held back or outside the diff.
  const hit = new Set(unique.map((f) => f.ruleId));
  for (const f of unique) { const s = config.rules[f.ruleId]; if (s && s !== "off") f.severity = s; }
  const showAll = opts.all ?? config.show === "all";
  const medium = new Set(active.filter((r) => r.confidence === "medium").map((r) => r.id));
  // A key in a test or fixture file is usually a fake one (0 of 15 sampled were real): shown only with --all.
  // Request data reaching a query, a shell, eval or a CI script (status Gap) is shown by default even from a held-back
  // rule: the default run found 61% of the benchmark's real problems, and these were most of the rest (2026-11-20).
  const reachesSink = (f: Finding) => f.status === "gap" && REQUEST_SINK_RULES.has(f.ruleId) && !isNonShipping(f.file);
  const isMedium = (f: Finding) => (medium.has(f.ruleId) && !reachesSink(f)) || (SECRET_RULES.has(f.ruleId) && isNonShipping(f.file));
  const changed = opts.changed && new Map(Object.entries(opts.changed.lines).map(([k, v]) => [k, new Set(v)]));
  const inDiff = (f: Finding) => !changed || changed.get(f.file)?.has(f.line) === true;
  const held = showAll ? 0 : unique.filter((f) => isMedium(f) && inDiff(f)).length;
  const deduped = unique.filter((f) => inDiff(f) && (showAll || !isMedium(f)));
  deduped.forEach((f, i) => { f.id = `F-${String(i + 1).padStart(3, "0")}`; });
  const now = opts.now ?? new Date();
  const report = await applyReview({
    rulesVersion: RULES_VERSION,
    frameworks: [...frameworks].sort(),
    policy: policyFingerprint({
      frameworks, rulesOff, ignore, show: opts.all ? "all" : config.show, repoRules: await readRepoRules(root), workspaceRules: opts.workspaceRules,
      packs: packsLoaded.filter((p) => usable(p.slice(0, p.lastIndexOf("@")))),
      rules: active.map((r) => ({ id: r.id, severity: (config.rules[r.id] && config.rules[r.id] !== "off" ? config.rules[r.id] : r.severity) as string })),
    }),
    findings: deduped,
    // Only the Checker sets Met: a rule that read at least one file and found nothing. A rule with nothing to read
    // (mobile rules in a web app) is not Met: nothing was checked.
    met: active.filter((r) => !hit.has(r.id) && (perRule[r.id] ?? 0) > 0).map((r) => ({ ruleId: r.id, title: r.title, controls: r.controls.filter((c) => frameworks.includes(c.framework)) })),
    outside: outsideFor(frameworks),
    filesChecked,
    ...(filesSkipped ? { filesSkipped } : {}),
    disclaimer: DISCLAIMER,
    ...(held ? { held } : {}),
    ...(rulesOff.length ? { rulesOff } : {}),
    ...(opts.changed ? { diffBase: opts.changed.base } : {}),
    notCovered: [
      ...(opts.changed ? [`Only lines changed since ${opts.changed.base} are listed. Older findings in the same files are not shown.`] : []),
      ...(held ? [`${held} medium-confidence finding${held === 1 ? " was" : "s were"} held back. Run with --all to see ${held === 1 ? "it" : "them"}.`] : []),
      ...(rulesOff.length ? [`Switched off in lintsure.config.yaml: ${rulesOff.join(", ")}.`] : []),
      ...(filesSkipped ? [`${filesSkipped} file${filesSkipped === 1 ? " was" : "s were"} not read: over 1 MB, binary or unreadable. No finding there means not checked, not clean.`] : []),
      ...(ignore.length ? [`Ignored by config: ${ignore.join(", ")}.`] : []),
      ...(nonShipping ? [`${nonShipping} test, fixture or tooling file${nonShipping === 1 ? " was" : "s were"} checked only for secrets and agent hooks.`] : []),
      "Each rule reads one file at a time. Data that flows between files, and how the app behaves when it runs, are not checked.",
      "Languages beyond JavaScript, TypeScript and Python get secret and config checks only.",
    ],
  }, root, now.toISOString().slice(0, 10));
  report.record = await buildRecord(report, root, checkPoints, perRule, active.map((r) => r.id), active, ignore, { ...opts, now });
  return report;
}

const LABEL = { gap: "Gap", partial: "Partial", met: "Met", outside: "Outside code" } as const;
const acceptedLine = (a: NonNullable<Finding["accepted"]>) =>
  `> Accepted by ${a.by} on ${a.date}: ${a.reason}` + (a.expired ? ` (review date ${a.reviewBy} has passed: look at it again)` : a.reviewBy ? ` (review by ${a.reviewBy})` : "");
const ctl = (c: { framework: string; id: string }[]) => c.map((x) => `${x.framework.toUpperCase()} ${x.id}`).join(" · ");

const RESULT = { finding: "Finding", observation: "Observation", "no issue found": "No issue found", "not checked": "Not checked (no files)" } as const;

/** The record block: identification, scope, what applies and why, counts, and results by control. */
function recordLines(r: Report): string[] {
  const c = r.record; if (!c) return [];
  const n = c.counts;
  return [
    "## Readiness check record", "",
    "This is a readiness record of an automated code check, not an audit. It is a draft until a person reviews and signs it.", "",
    "| | |", "|---|---|",
    `| Record | ${c.id} |`, `| Date and time (UTC) | ${c.createdAt.replace("T", " ").slice(0, 19)} |`,
    `| Tool | ${c.tool.name} ${c.tool.version}, run from ${c.source} |`,
    `| Scope | \`${c.scope.folder}\`${c.scope.branch ? `, branch \`${c.scope.branch}\`` : ""}${c.scope.commit ? `, commit \`${c.scope.commit}\`` : ""} |`,
    `| Files read | ${c.scope.filesRead}${c.scope.ignored.length ? ` (ignored by config: ${c.scope.ignored.map((x) => `\`${x}\``).join(", ")})` : ""} |`,
    `| Check points | ${n.checkPoints} (${n.rulesRun} rules, each applied to every file it reads) |`,
    `| Results | ${n.findings} finding${n.findings === 1 ? "" : "s"}, ${n.observations} observation${n.observations === 1 ? "" : "s"}, ${n.accepted} accepted, ${n.fixedSinceBaseline} fixed since baseline, ${n.outsideCode} outside-code items |`,
    `| Risk levels | ${n.byRisk.high} high, ${n.byRisk.medium} medium, ${n.byRisk.low} low |`,
    `| Reviewed by | ${c.review.reviewer ?? "Not yet reviewed"} |`, "",
    "### What applies, and why", "",
    ...c.applies.map((a) => `- **${a.framework}**: ${a.why}`), "",
    "### Results by control", "",
    "A finding is a Gap the code itself shows. An observation is a Partial that depends on context a person must confirm. No issue found means the rules found nothing in the files they read, not that the control is met. Not checked means no file of the right kind was read for that control.", "",
    "| Framework | Control | Rules | Check points | Result | Items |", "|---|---|---|---|---|---|",
    ...c.byControl.map((b) => `| ${b.framework} | ${b.control} ${b.title} | ${b.rules.join(", ")} | ${b.checkPoints} | ${RESULT[b.result]} | ${b.findingIds.join(", ") || "-"} |`), "",
  ];
}

// Housekeeping for the repo, not a flaw in the code. These four were 74% of what the 0.3.14 field test showed, so every
// output lists them after the findings in the code. Presentation only: the report data, SARIF and exit code don't change.
// The two Dockerfile hardening basics joined the group after their first field scan: 138 findings in 304 projects, true
// but routine, and they would bury findings in the code.
const HYGIENE_RULES = new Set(["ci.action-unpinned", "repo.no-sbom", "repo.no-security-policy", "repo.no-dependency-updates", "docker.runs-as-root", "docker.image-unpinned"]);
export const isHygiene = (f: { ruleId: string }) => HYGIENE_RULES.has(f.ruleId);

export function toMarkdown(r: Report): string {
  const hygiene = r.findings.filter(isHygiene);
  const lines = [
    "# Lintsure report", "",
    `Frameworks: ${r.frameworks.join(", ")} · Rules v${r.rulesVersion}${r.policy ? ` · Policy #${r.policy.fingerprint} (${r.policy.rulesActive} rules active${r.policy.repoRules ? " + .lintsure/rules.yml" : ""}${r.policy.workspaceRules ? " + workspace rules" : ""})` : ""}`, "",
    `> ${DISCLAIMER}`, "",
    ...recordLines(r),
    `## Findings (${r.findings.length - hygiene.length})`, "",
  ];
  if (r.baseline) lines.splice(lines.length - 2, 0, `Since the baseline of ${r.baseline.created}: ${r.baseline.newCount} new, ${r.baseline.fixed.length} fixed, ${r.baseline.unchangedCount} unchanged.`, "");
  if (r.findings.length === hygiene.length) lines.push(hygiene.length ? "No findings in the code from the current rules. Repo hygiene items follow." : "No issues found by the current rules.", "");
  // Fix first: Gaps before Partials, then by severity; file order within each group.
  const rank = (f: Finding) => (isHygiene(f) ? 6 : 0) + (f.status === "gap" ? 0 : 3) + ({ high: 0, medium: 1, low: 2 } as const)[f.severity];
  const sorted = [...r.findings].sort((a, b) => rank(a) - rank(b));
  for (const f of sorted) lines.push(
    ...(f === sorted[r.findings.length - hygiene.length] ? [`## Repo hygiene (${hygiene.length})`, "", "Housekeeping for the repo, not flaws in the code. Findings in the code come first.", ""] : []),
    `### ${f.id} · ${f.status === "gap" ? "Finding" : "Observation"} (${LABEL[f.status]}) · \`${f.file}:${f.line}\`${f.change === "new" ? " · New since baseline" : ""}`, `**${f.title}** · Risk level: ${f.severity}`, "",
    ...(f.accepted ? [acceptedLine(f.accepted), ""] : []),
    `- Rules: ${ctl(f.controls)}`, `- Auditor note: ${f.note}`, ...(f.unseen ? [`- What Lintsure couldn't see: ${f.unseen}`] : []),
    ...(rules.find((x) => x.id === f.ruleId)?.seenIn ?? []).map((s) => `- Seen in a real incident: ${s.title} (${s.url})`),
    ...(f.reach ? [`- Reached from: ${f.reach.status === "entry" ? "this file is an entry point (route, handler or function)" : f.reach.status === "reachable" ? f.reach.via!.join(" → ") : f.reach.status === "unknown" ? "unknown (an import Lintsure couldn't resolve may lead here)" : "not reached from any entry point Lintsure recognises (it may be loaded some other way, or be unused)"}`] : []), "",
    `**${PROPOSAL_HEADING}**`, "",
    `- Where: \`${f.proposal.where}\``, `- What: ${f.proposal.what}`, `- Why: ${f.proposal.why}`, `- Benefit: ${f.proposal.benefit}`, "",
    ...(f.patch ? [`Exact change (still needs your approval), line ${f.patch.line}:`, "", "```diff",
      ...(f.patch.old != null ? [`- ${f.patch.old}`] : []), ...f.patch.text.replace(/\n$/, "").split("\n").map((t) => `+ ${t}`), "```", ""] : []),
  );
  if (r.baseline?.fixed.length) lines.push(`## Fixed since baseline (${r.baseline.fixed.length})`, "", ...r.baseline.fixed.map((x) => `- ${x.ruleId} in \`${x.file}\``), "");
  lines.push(`## Met (${r.met.length})`, "", ...r.met.map((m) => `- ${m.title} · ${ctl(m.controls)}`), "");
  lines.push(`## Outside code (${r.outside.length})`, "", "Code can't prove these. They still need to be done before a full review.", "", ...r.outside.map((o) => `- ${o.framework.toUpperCase()} ${o.control} · ${o.title}: ${o.evidence}`), "");
  if (r.notCovered?.length) lines.push("## Not covered", "", "No finding here does not mean no problem here.", "", ...r.notCovered.map((s) => `- ${s}`), "");
  lines.push("## What to do next", "", ...nextSteps(r).map((s, i) => `${i + 1}. ${s}`), "");
  lines.push("## What this report is not", "", NOT_A_VERDICT, "");
  return lines.join("\n");
}
