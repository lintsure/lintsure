// Reachability: which entry points (routes, API handlers, middleware, server actions, functions, workers) can reach a
// file through the project's own imports. A small resolver of our own: literal import/export/require/import()
// specifiers, relative paths with the usual extensions and index files, the .js -> .ts swap, and tsconfig
// baseUrl/paths. Packages are outside the project and not followed. A specifier we can't resolve is kept as an
// "unresolved" edge and makes the answer "unknown", never a guess. JavaScript and TypeScript only. Pure.

export type Reach = { status: "entry" | "reachable" | "unreachable" | "unknown"; via?: string[] };
export interface Graph { importers: Map<string, Set<string>>; entries: Set<string>; unresolved: Map<string, string[]> }

const CODE = /\.(m|c)?[jt]sx?$/;
const EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const SPEC = /\bimport\s+(?:type\s+)?(?:[\w$*{}\s,]+\s+from\s+)?["']([^"']+)["']|\bexport\s+(?:type\s+)?[\w$*{}\s,]*\s+from\s+["']([^"']+)["']|\brequire\(\s*["']([^"']+)["']\s*\)|\bimport\(\s*["']([^"']+)["']\s*\)/g;

/** Literal specifiers a file imports. Pure. */
export function specifiers(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(SPEC)) out.push(m[1] ?? m[2] ?? m[3] ?? m[4]);
  return out;
}

// JSON with line and block comments removed, leaving anything inside strings alone (a glob like "src/**" is not a comment). Pure.
export function stripJsonComments(text: string): string {
  let out = "", i = 0, str = false;
  while (i < text.length) {
    const c = text[i], n = text[i + 1];
    if (str) { out += c; if (c === "\\") { out += n ?? ""; i += 2; continue; } if (c === '"') str = false; i++; continue; }
    if (c === '"') { str = true; out += c; i++; continue; }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    out += c; i++;
  }
  return out;
}

/** Path aliases from a tsconfig.json text (comments allowed): baseUrl and paths, as [prefix, targets] pairs. Pure. */
export function tsAliases(text: string | null, root = ""): { root: string; baseUrl: string | null; paths: [string, string[]][] } {
  if (!text) return { root, baseUrl: null, paths: [] };
  try {
    const json = JSON.parse(stripJsonComments(text).replace(/,(\s*[}\]])/g, "$1"));
    const o = json.compilerOptions ?? {}, base = typeof o.baseUrl === "string" ? o.baseUrl.replace(/^\.\/?/, "").replace(/\/$/, "") : null;
    const paths = Object.entries((o.paths ?? {}) as Record<string, string[]>).map(([k, v]) => [k.replace(/\*$/, ""), v.map((t) => t.replace(/\*$/, "").replace(/^\.\//, ""))] as [string, string[]]);
    return { root, baseUrl: base, paths };
  } catch { return { root, baseUrl: null, paths: [] }; }
}

const norm = (p: string) => { const out: string[] = []; for (const s of p.split("/")) { if (s === "..") out.pop(); else if (s && s !== ".") out.push(s); } return out.join("/"); };
const dir = (p: string) => p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "";

/** The project file a specifier points at, "external" for a package, or null when it looks local but can't be found. Pure. */
export function resolveSpec(from: string, spec: string, files: Set<string>, alias: ReturnType<typeof tsAliases>): string | "external" | null {
  const tryAll = (base: string) => {
    const cands = [base, base.replace(/\.(m|c)?js$/, (e) => e.replace("js", "ts")), base.replace(/\.jsx$/, ".tsx"), ...EXTS.map((e) => base + e), ...EXTS.map((e) => `${base}/index${e}`)];
    return cands.find((c) => files.has(c)) ?? null;
  };
  if (spec.startsWith(".")) return tryAll(norm(`${dir(from)}/${spec}`));
  if (spec.startsWith("/")) return tryAll(norm(spec));
  for (const [prefix, targets] of alias.paths) if (prefix ? spec.startsWith(prefix) : spec === prefix) {
    for (const t of targets) { const hit = tryAll(norm(`${alias.root}/${alias.baseUrl ?? ""}/${t}${spec.slice(prefix.length)}`)); if (hit) return hit; }
    return null;
  }
  if (alias.baseUrl != null) { const hit = tryAll(norm(`${alias.root}/${alias.baseUrl}/${spec}`)); if (hit) return hit; }
  // "@/x" and "~/x" with no tsconfig entry are almost always local aliases, so they count as unresolved, not packages.
  return /^[@~#]\//.test(spec) ? null : "external";
}

// Files a request or event starts in: Next.js routes, pages and API routes, middleware, server actions, serverless and
// Supabase/Netlify functions, Workers, Express/Hono/Fastify-style handlers, framework config files, and the top-level
// index/main/server/App file a runtime or bundler starts from.
const ENTRY_PATH = /(^|\/)(app\/(.+\/)?(route|page|layout)\.[jt]sx?|pages\/(.+\/)?[^/]+\.[jt]sx?|middleware\.[jt]s|api\/.+\.[jt]s|supabase\/functions\/[^/]+\/index\.[jt]s|netlify\/functions\/.+\.[jt]s|functions\/.+\.[jt]s|[^/]+\.config\.[cm]?[jt]s|routes\/(.+\/)?\+(page|layout|server)(\.server)?\.[jt]s|hooks\.server\.[jt]s|app\/routes\/.+\.[jt]sx?|app\/(root|entry\.server|entry\.client)\.[jt]sx?|bin\/.+\.[cm]?[jt]sx?)$|^[^/]+\.[cm]?[jt]sx?$/;
// Relative to a package folder (a folder with package.json): the file a runtime or bundler starts from.
const PKG_ENTRY = /^(src\/)?(index|main|server|app|App|cli|worker)\.[cm]?[jt]sx?$/;
const ENTRY_TEXT = /^\s*["']use server["']|\b(app|router|server|api)\.(get|post|put|patch|delete|all|route|use)\s*\(\s*["'`/]|\bexport\s+default\s*\{[^}]*\bfetch\b|\baddEventListener\(\s*["']fetch["']|\bDeno\.serve\(|\bcreateServer\(|\bexport\s+(async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/m;

/** Files a project starts from that no code imports: package.json main/module/bin/exports, and scripts an HTML page
 *  loads with <script src>. Paths come back relative to the project root. Pure. */
export function declaredEntries(pkgs: Record<string, string>, html: Record<string, string>, files: Set<string>): string[] {
  const out: string[] = [];
  const add = (from: string, p: unknown) => { if (typeof p !== "string" || /^(https?:)?\/\//.test(p)) return; const hit = resolveSpec(from, p.startsWith(".") || p.startsWith("/") ? p : `./${p}`, files, tsAliases(null)); if (typeof hit === "string" && hit !== "external") out.push(hit); };
  for (const [path, text] of Object.entries(pkgs)) {
    let j: Record<string, unknown>; try { j = JSON.parse(text); } catch { continue; }
    const at = path.includes("/") ? `${path.slice(0, path.lastIndexOf("/"))}/package.json` : "package.json";
    for (const k of ["main", "module", "browser", "types"]) add(at, j[k]);
    for (const v of typeof j.bin === "string" ? [j.bin] : Object.values((j.bin ?? {}) as object)) add(at, v);
    const walk = (v: unknown): void => { if (typeof v === "string") add(at, v); else if (v && typeof v === "object") Object.values(v).forEach(walk); };
    walk(j.exports);
  }
  for (const [path, text] of Object.entries(html)) for (const m of text.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) add(path, m[1].split(/[?#]/)[0]);
  return out;
}

/** Builds the import graph and the entry points from the project's JS/TS files. Pure. */
export function buildGraph(files: Record<string, string>, tsconfigs: string | null | Record<string, string> = null, pkgDirs: string[] = [""], extraEntries: string[] = []): Graph {
  const set = new Set(Object.keys(files));
  // Each file uses the tsconfig of its nearest folder that has one (monorepos keep one per package).
  const configs = typeof tsconfigs === "string" || tsconfigs === null ? { "": tsconfigs ?? "" } : tsconfigs;
  const aliases = Object.entries(configs).map(([d, t]) => tsAliases(t || null, d)).sort((a, b) => b.root.length - a.root.length);
  const aliasFor = (f: string) => aliases.find((a) => !a.root || f.startsWith(a.root + "/")) ?? tsAliases(null);
  const pkgs = [...pkgDirs].sort((a, b) => b.length - a.length);
  const pkgRel = (f: string) => { const d = pkgs.find((p) => !p || f.startsWith(p + "/")); return d ? f.slice(d.length + 1) : f; };
  const importers = new Map<string, Set<string>>(), entries = new Set<string>(extraEntries.filter((e) => set.has(e))), unresolved = new Map<string, string[]>();
  for (const [f, text] of Object.entries(files)) {
    if (!CODE.test(f)) continue;
    if (ENTRY_PATH.test(f) || PKG_ENTRY.test(pkgRel(f)) || ENTRY_TEXT.test(text)) entries.add(f);
    for (const s of specifiers(text)) {
      const to = resolveSpec(f, s, set, aliasFor(f));
      if (to === "external") continue;
      if (to === null) { (unresolved.get(f) ?? unresolved.set(f, []).get(f)!).push(s); continue; }
      (importers.get(to) ?? importers.set(to, new Set()).get(to)!).add(f);
    }
  }
  return { importers, entries, unresolved };
}

/** Whether an entry point reaches this file, with the shortest chain entry -> ... -> file. "unknown" when nothing
 *  reaches it but an unresolved import somewhere could be pointing at it (same file name). Pure. */
export function reachOf(g: Graph, file: string): Reach {
  if (g.entries.has(file)) return { status: "entry" };
  const prev = new Map<string, string>([[file, ""]]), queue = [file];
  while (queue.length) {
    const cur = queue.shift()!;
    for (const imp of g.importers.get(cur) ?? []) {
      if (prev.has(imp)) continue;
      prev.set(imp, cur);
      if (g.entries.has(imp)) { const via = [imp]; let x = cur; while (x) { via.push(x); x = prev.get(x)!; } return { status: "reachable", via }; }
      queue.push(imp);
    }
  }
  const base = file.replace(/^.*\//, "").replace(/\.[^.]+$/, "").replace(/^index$/, file.split("/").slice(-2, -1)[0] ?? "index");
  const maybe = [...g.unresolved.values()].some((specs) => specs.some((s) => s.replace(/\.[^./]+$/, "").split("/").pop() === base));
  return { status: maybe ? "unknown" : "unreachable" };
}
