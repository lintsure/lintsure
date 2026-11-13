// Scout (file walk) + Checker (rules) + Auditor (dedupe, sort) + Officer (outside code).
// No network calls anywhere in this package: a test enforces it.
import { readdir, readFile } from "node:fs/promises";
import { basename, extname, join, relative, sep } from "node:path";
import { outsideFor } from "./knowledge/index.js";
import { rules } from "./rules/index.js";
import type { Finding, FrameworkId, Report, Severity } from "./types.js";
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
import { loadPacks } from "./packs.js";
export const RULES_VERSION = "0.4.0";

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
  frameworks: FrameworkId[] | null; skipped: string[]; ignore: string[]; packsMissing?: string[];
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
  const base = { ignore, packsMissing, rules: ruleSet, show, problems };
  if (emptyFw) return { frameworks: [], skipped: [], ...base };
  const ids = lists.frameworks;
  if (!ids.length) return { frameworks: null, skipped: [], ...base };
  const known = ids.filter((i): i is FrameworkId => (ALL_FRAMEWORKS as string[]).includes(i));
  return { frameworks: known, skipped: ids.filter((i) => !known.includes(i as FrameworkId)), ...base };
}

// Dependencies, build output and caches: generated code, not code you wrote.
// Also other people's code copied in (vendor, third_party): not code you wrote (field test, 139 repos).
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
  if (/^Dockerfile\b/i.test(name)) return ""; // Dockerfile.prod is still a Dockerfile
  const e = extname(abs);
  return e === ".mts" || e === ".cts" ? ".ts" : e;
}

/** Scout: list files to check, sorted so output order never depends on the file system. */
export async function listFiles(root: string, ignore: string[] = []): Promise<string[]> {
  const out: string[] = [];
  const ignored = (p: string) => { const r = relative(root, p).split(sep).join("/"); return ignore.some((i) => r === i || r.startsWith(i + "/")); };
  async function walk(dir: string) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name) || BUNDLED.test(e.name)) continue;
      const p = join(dir, e.name);
      if (ignored(p)) continue;
      if (e.isDirectory()) await walk(p); else if (e.isFile()) out.push(p);
    }
  }
  await walk(root);
  return out.sort();
}

// Code that doesn't ship: tests, fixtures, examples, docs, demos, stories and seed data. Most false alarms in the
// 139-repo field test came from here. Only the secret rules read these paths, and their findings there are Partial.
export const NON_SHIPPING = /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|examples?|samples?|demos?|cookbooks?|docs?|stories|storybook|seeds?|seeders|factories|\.dev|benchmarks?|scripts?|\.agents|\.claude|\.cursor)\/|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$|(^|\/)(conftest\.py|pytest\.ini|tox\.ini)$|(^|\/)\.env\.(example|sample|template|dist)$|(^|\/)(playwright|vitest|jest|cypress)\.config\.[cm]?[jt]s$/i;
// In Next.js, Remix and Supabase a folder name is a route or a function name: app/api/demo and a function called
// "test" are live endpoints (review P3). Inside these roots only real test files count as non-shipping.
// Example, demo, docs and sample folders inside application source (src/, lib/, server/) are shipping code too.
const LIVE_ROOT = /(^|\/)(app|pages|api|routes|supabase\/functions|src|lib|server)\//;
const NS_FOLDER = /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|examples?|samples?|demos?|cookbooks?|docs?|stories|storybook|seeds?|seeders|benchmarks?|scripts?|\.agents|\.claude|\.cursor)\//i;
// Dev scripts at the top of a repo (scripts/test-*.mjs, build and seed helpers) and agent tooling (.agents/, .claude/)
// don't ship: they were the largest single source of false alarms in the 0.4.0 labelled sample (44 of 242).
const TEST_FILE = /(^|\/)__tests__\/|(^|\/)test[-_]?(utils?|helpers?|rig)\/|(^|\/)test-[^/]+\.[cm]?[jt]s$|[._-]tests?\/|\.(test|spec|stories)\.[cm]?[jt]sx?$|(^|\/)test_[^/]+\.py$|_test\.(py|go)$|(^|\/)(conftest\.py|pytest\.ini|tox\.ini)$/i;
/** True for code that doesn't ship: tests, fixtures, examples, docs, stories and seed data. A folder name only counts
 *  when it comes before any app or route root in the path: examples/site/app/page.tsx is an example, while
 *  app/api/demo/route.ts and src/samples/handler.ts are live code. Pure. */
export function isNonShipping(file: string): boolean {
  if (TEST_FILE.test(file)) return true;
  // Shell scripts in scripts/ are often the installer people run (curl ... | sh): those still count.
  if (/\.(sh|bash|zsh|ps1)$/i.test(file) && !/(^|\/)(tests?|__tests__|e2e|fixtures?|examples?|demos?)\//i.test(file)) return false;
  const live = LIVE_ROOT.exec(file), ns = NS_FOLDER.exec(file);
  if (!live || (ns && ns.index < live.index)) return NON_SHIPPING.test(file);
  // Under a route root every folder is a URL or function name, so only test files (handled above) are skipped.
  if (/^(app|pages|api|routes|supabase\/functions)$/.test(live[2])) return false;
  // Under src/, lib/ or server/, test folders are still tests; example, demo, docs and sample folders are app code.
  return /(^|\/)(tests?|__tests__|__mocks__|mocks?|spec|fixtures?|__fixtures__|e2e|seeds?|seeders|factories|stories|storybook)\//i.test(file.slice(live.index));
}
// Rules that also read test files. Not auth.hardcoded-password: test logins are fake by design (field test, 50 repos).
const SECRET_RULES = new Set(["secret.in-source"]); // not config.default-secret-key: a test secret is a test value (review P19)
// Lines a person already reviewed. lintsure-ignore and the secret allowlist pragma count only in a comment and apply
// to every rule. Other linters' markers (noqa, nosec, NOSONAR) don't hide secrets: `# noqa: E501` is about line length.
const REVIEWED = /(#|\/\/|\/\*|--)\s*(lintsure-ignore|pragma:\s*allowlist secret)\b/;
const OTHER_LINTER = /#\s*(noqa|nosec)\b|\/\/\s*NOSONAR\b/;
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
  "mobile.token-in-plain-storage", "config.debug-on", "cookie.trusted-role"]);
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
}

export async function scan(root: string, frameworks: FrameworkId[] = ALL_FRAMEWORKS, opts: ScanOptions = {}): Promise<Report> {
  const config = await readConfig(root);
  const { ignore } = config;
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
      proposal: proposalFor({ file, line: 1, title: r.title, fix: r.fix, note: r.note, controls }), fingerprint: fingerprint(r.id, file, "") });
  }
  // Rules that look across files get the joined text of every file they read, read once up front.
  const shared = new Map<string, string>();
  for (const r of active.filter((x) => x.sharedContext)) {
    const texts: string[] = [];
    for (const [k, abs] of all.entries()) {
      const ext = extOf(abs), file = paths[k];
      if (!r.extensions.includes(ext) || (r.fileName && !r.fileName.test(basename(abs))) || (r.pathMatch && !r.pathMatch.test(file)) || r.unlessPath?.test(file)) continue;
      const text = await readFile(abs, "utf8").catch(() => "");
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
    for (const [k, abs] of all.entries()) if (r.sharedFiles!.test(paths[k])) files[paths[k]] = await readFile(abs, "utf8").catch(() => "");
    sharedFiles.set(r.id, files);
  }
  for (const abs of all) {
    const ext = extOf(abs);
    const name = basename(abs);
    const file = relative(root, abs).split(sep).join("/");
    const relevant = active.filter((r) => r.extensions.includes(ext) && (!r.fileName || r.fileName.test(name)) && (!r.pathMatch || r.pathMatch.test(file)) && !r.unlessPath?.test(file));
    if (!relevant.length) continue;
    const buf = await readFile(abs);
    if (buf.length > MAX_BYTES || buf.includes(0)) continue; // skip big or binary files
    const raw = buf.toString("utf8").split(/\r?\n/);
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
      });
    };
    // Tests, fixtures, examples and docs are full of fake tokens and planted examples: only secret rules look at them,
    // and what they find there is Partial (it may be a throwaway key).
    const inTests = isNonShipping(file);
    if (inTests) nonShipping++;
    const comment = commentLines(lines, ext);
    // Statements are worked out once per file, on lines with comments blanked.
    const stmts = JOINABLE.has(ext) ? statements(lines.map((l, i) => (comment[i] ? "" : l)), ext === ".py") : [];
    const multi = stmts.filter((s) => s.end > s.start);
    const prose = new Array<boolean>(lines.length).fill(false);
    for (const s of multi) if (s.prose) for (let i = s.start; i <= s.end; i++) prose[i] = true;
    for (const r of relevant) {
      const secret = SECRET_RULES.has(r.id);
      if (inTests && !secret) continue;
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
        const hit = r.test!(text);
        if (!hit || (r.unlessNear && lines.slice(Math.max(0, i - 8), i + 4).some((l) => r.unlessNear!.test(l)))) return;
        if (r.unlessInKey && r.unlessInKey.test(enclosingKey(lines, i))) return;
        if (inTests && PLACEHOLDER.test(text)) return; // password="test_password", token="xoxb-test-..."
        if (inTests && /PRIVATE KEY/.test(text)) return; // test keys and certificates are fixtures by design (review P24)
        if (REVIEWED.test(text) || (!secret && OTHER_LINTER.test(text))) return; // someone already looked at this line and marked it
        hitLines.add(i);
        add(r, i + 1, hit === "partial" || inTests ? "partial" : r.status);
      });
      // A statement spread over several lines: test it as one, and report it only when no single line already did,
      // so line-by-line results never shrink (review step A).
      if (r.test && JOIN_RULES.has(r.id)) for (const s of multi) {
        if (s.prose && !readsText) continue;
        let already = false; for (let i = s.start; i <= s.end; i++) if (hitLines.has(i)) { already = true; break; }
        if (already) continue;
        const hit = r.test(s.text);
        if (!hit || (r.unlessNear && lines.slice(Math.max(0, s.start - 8), s.end + 4).some((l) => r.unlessNear!.test(l)))) continue;
        if (r.unlessInKey && r.unlessInKey.test(enclosingKey(lines, s.start))) continue;
        if (lines.slice(s.start, s.end + 1).some((l) => REVIEWED.test(l) || OTHER_LINTER.test(l))) continue;
        add(r, s.start + 1, hit === "partial" || inTests ? "partial" : r.status);
      }
      // File rules see comment lines as blank, so "<img> in a comment" or a commented-out call doesn't count (field test).
      if (r.fileTest) for (const n of r.fileTest(skip ? lines.map((l, i) => (skip[i] ? "" : l)) : lines, shared.get(r.id), sharedFiles.get(r.id)))
        typeof n === "number" ? add(r, n) : add(r, n.line, n.status);
    }
    if (ran) filesChecked++;
  }
  // Auditor: one finding per rule per line; stable order.
  const seen = new Set<string>();
  const unique = findings.filter((f) => { const k = `${f.ruleId}|${f.file}|${f.line}`; return seen.has(k) ? false : (seen.add(k), true); })
    .sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  // A rule that fired still counts as checked (not Met) even when its findings are held back or outside the diff.
  const hit = new Set(unique.map((f) => f.ruleId));
  for (const f of unique) { const s = config.rules[f.ruleId]; if (s && s !== "off") f.severity = s; }
  const showAll = opts.all ?? config.show === "all";
  const medium = new Set(active.filter((r) => r.confidence === "medium").map((r) => r.id));
  // A key in a test or fixture file is usually a fake one (0 of 15 sampled were real): shown only with --all.
  const isMedium = (f: Finding) => medium.has(f.ruleId) || (SECRET_RULES.has(f.ruleId) && isNonShipping(f.file));
  const changed = opts.changed && new Map(Object.entries(opts.changed.lines).map(([k, v]) => [k, new Set(v)]));
  const inDiff = (f: Finding) => !changed || changed.get(f.file)?.has(f.line) === true;
  const held = showAll ? 0 : unique.filter((f) => isMedium(f) && inDiff(f)).length;
  const deduped = unique.filter((f) => inDiff(f) && (showAll || !isMedium(f)));
  deduped.forEach((f, i) => { f.id = `F-${String(i + 1).padStart(3, "0")}`; });
  const now = opts.now ?? new Date();
  const report = await applyReview({
    rulesVersion: RULES_VERSION,
    frameworks: [...frameworks].sort(),
    findings: deduped,
    // Only the Checker sets Met: a rule that read at least one file and found nothing. A rule with nothing to read
    // (mobile rules in a web app) is not Met: nothing was checked.
    met: active.filter((r) => !hit.has(r.id) && (perRule[r.id] ?? 0) > 0).map((r) => ({ ruleId: r.id, title: r.title, controls: r.controls.filter((c) => frameworks.includes(c.framework)) })),
    outside: outsideFor(frameworks),
    filesChecked,
    disclaimer: DISCLAIMER,
    ...(held ? { held } : {}),
    ...(rulesOff.length ? { rulesOff } : {}),
    ...(opts.changed ? { diffBase: opts.changed.base } : {}),
    notCovered: [
      ...(opts.changed ? [`Only lines changed since ${opts.changed.base} are listed. Older findings in the same files are not shown.`] : []),
      ...(held ? [`${held} medium-confidence finding${held === 1 ? " was" : "s were"} held back. Run with --all to see ${held === 1 ? "it" : "them"}.`] : []),
      ...(rulesOff.length ? [`Switched off in lintsure.config.yaml: ${rulesOff.join(", ")}.`] : []),
      ...(ignore.length ? [`Ignored by config: ${ignore.join(", ")}.`] : []),
      ...(nonShipping ? [`${nonShipping} test, fixture or tooling file${nonShipping === 1 ? " was" : "s were"} checked for secrets only.`] : []),
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

export function toMarkdown(r: Report): string {
  const lines = [
    "# Lintsure report", "",
    `Frameworks: ${r.frameworks.join(", ")} · Rules v${r.rulesVersion}`, "",
    `> ${DISCLAIMER}`, "",
    ...recordLines(r),
    `## Findings (${r.findings.length})`, "",
  ];
  if (r.baseline) lines.splice(lines.length - 2, 0, `Since the baseline of ${r.baseline.created}: ${r.baseline.newCount} new, ${r.baseline.fixed.length} fixed, ${r.baseline.unchangedCount} unchanged.`, "");
  if (!r.findings.length) lines.push("No issues found by the current rules.", "");
  // Fix first: Gaps before Partials, then by severity; file order within each group.
  const rank = (f: Finding) => (f.status === "gap" ? 0 : 3) + ({ high: 0, medium: 1, low: 2 } as const)[f.severity];
  for (const f of [...r.findings].sort((a, b) => rank(a) - rank(b))) lines.push(
    `### ${f.id} · ${f.status === "gap" ? "Finding" : "Observation"} (${LABEL[f.status]}) · \`${f.file}:${f.line}\`${f.change === "new" ? " · New since baseline" : ""}`, `**${f.title}** · Risk level: ${f.severity}`, "",
    ...(f.accepted ? [acceptedLine(f.accepted), ""] : []),
    `- Rules: ${ctl(f.controls)}`, `- Auditor note: ${f.note}`, "",
    `**${PROPOSAL_HEADING}**`, "",
    `- Where: \`${f.proposal.where}\``, `- What: ${f.proposal.what}`, `- Why: ${f.proposal.why}`, `- Benefit: ${f.proposal.benefit}`, "",
  );
  if (r.baseline?.fixed.length) lines.push(`## Fixed since baseline (${r.baseline.fixed.length})`, "", ...r.baseline.fixed.map((x) => `- ${x.ruleId} in \`${x.file}\``), "");
  lines.push(`## Met (${r.met.length})`, "", ...r.met.map((m) => `- ${m.title} · ${ctl(m.controls)}`), "");
  lines.push(`## Outside code (${r.outside.length})`, "", "Code can't prove these. They still need to be done before a full review.", "", ...r.outside.map((o) => `- ${o.framework.toUpperCase()} ${o.control} · ${o.title}: ${o.evidence}`), "");
  if (r.notCovered?.length) lines.push("## Not covered", "", "No finding here does not mean no problem here.", "", ...r.notCovered.map((s) => `- ${s}`), "");
  lines.push("## What to do next", "", ...nextSteps(r).map((s, i) => `${i + 1}. ${s}`), "");
  lines.push("## What this report is not", "", NOT_A_VERDICT, "");
  return lines.join("\n");
}
