// Lintsure project profile: what the project already has, read on this machine and never sent anywhere.
// - Brand: colours defined as CSS custom properties or in a Tailwind config, and font families.
// - Building blocks: components by name. Content: where quotes and copy live (paths only). Pages, and the stack.
// Cached in the temp folder and rebuilt when the key files change, so checks after each edit stay fast.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename, extname, relative } from "node:path";
import { createHash } from "node:crypto";
import { globMatch } from "./lib.mjs";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".astro", ".output", "coverage", ".turbo", ".vercel", ".wrangler", "vendor", "out"]);
const STYLE = /\.(css|scss|sass|less|pcss)$/i;
const UI = /\.(astro|tsx|jsx|vue|svelte|html)$/i;
const GENERIC = new Set(["serif", "sans-serif", "monospace", "system-ui", "ui-sans-serif", "ui-serif", "ui-monospace", "inherit", "initial", "cursive", "fantasy", "emoji", "math", "-apple-system", "blinkmacsystemfont", "segoe ui", "roboto", "helvetica", "arial", "helvetica neue", "apple color emoji", "segoe ui emoji", "noto sans", "var"]);
// A file marked lintsure:private reads as empty, so nothing from it reaches Memory.
const read = (f, max = 200_000) => { try { const st = statSync(f); const t = st.size > max ? "" : readFileSync(f, "utf8"); return /lintsure:private/.test(t.slice(0, 2000)) ? "" : t; } catch { return ""; } };
const hex6 = (h) => { h = h.toLowerCase().replace("#", ""); if (h.length === 3 || h.length === 4) h = h.slice(0, 3).split("").map((c) => c + c).join(""); return h.length >= 6 ? `#${h.slice(0, 6)}` : null; };

function walk(root, max = 4000) {
  const files = [];
  const go = (d, depth) => {
    if (files.length >= max || depth > 8) return;
    let ents = []; try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name.startsWith(".") && e.name !== ".lintsure") { if (e.isDirectory()) continue; }
      const p = join(d, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name)) go(p, depth + 1); } else files.push(p);
    }
  };
  go(root, 0);
  return files;
}

function build(root, files) {
  const rel = (f) => relative(root, f).replace(/\\/g, "/");
  const colors = {}, used = {}, fonts = new Set(), components = {}, content = [], pages = [];
  for (const f of files) {
    const r = rel(f), name = basename(f);
    if (STYLE.test(f) || /tailwind\.config\.[cm]?[jt]s$/.test(name) || (/\.astro$/.test(f) && /layouts?\//.test(r))) {
      const src = read(f);
      // Colours the project names: --brand-green: #0B6E4F; and Tailwind-style  green: '#0B6E4F'
      for (const m of src.matchAll(/(--[\w-]+)\s*:\s*(#[0-9a-f]{3,8})\b/gi)) { const h = hex6(m[2]); if (h) colors[h] ||= m[1]; }
      if (/tailwind\.config/.test(name)) for (const m of src.matchAll(/['"]?([\w-]+)['"]?\s*:\s*['"](#[0-9a-f]{3,8})['"]/gi)) { const h = hex6(m[2]); if (h) colors[h] ||= m[1]; }
      for (const m of src.matchAll(/font-family\s*:\s*([^;}\n]+)|--font[\w-]*\s*:\s*([^;}\n]+)|fontFamily\s*:\s*\{([^}]+)\}/gi)) {
        for (const fam of String(m[1] || m[2] || m[3]).matchAll(/['"]?([A-Za-z][\w .-]+?)['"]?\s*(?:,|$|\])/g)) { const n = fam[1].trim().toLowerCase(); if (n && !GENERIC.has(n) && !n.startsWith("var(")) fonts.add(n); }
      }
    }
    // Colours already used anywhere in the UI count as the project's: only brand-new ones get flagged.
    if (STYLE.test(f) || UI.test(f)) for (const m of read(f).matchAll(/#[0-9a-f]{3,8}\b/gi)) { const h = hex6(m[0]); if (h) { const u = (used[h] ||= []); if (u.length < 3 && !u.includes(r)) u.push(r); } }
    if (UI.test(f) && /(^|\/)components?\//.test(r)) components[name.replace(/\.[^.]+$/, "")] = r;
    if (/(^|\/)(content|data|copy|i18n|locales)\//.test(r) && /\.(md|mdx|json|ya?ml|ts|js)$/.test(f) || /(quote|testimonial|copy|slogan|tagline)/i.test(name)) content.push(r);
    const pg = r.match(/^(?:src\/)?pages\/(.+)\.(astro|tsx|jsx|md|mdx|vue|svelte)$/) || r.match(/^(?:src\/)?app\/(?:(.+)\/)?page\.(tsx|jsx|ts|js)$/);
    if (pg) pages.push("/" + String(pg[1] ?? "").replace(/(^|\/)index$/, "").replace(/\/$/, ""));
  }
  // DESIGN.md (the open format for describing a brand to agents): its tokens are the brand, named as it names them.
  const design = read(join(root, "DESIGN.md")).replace(/\r\n/g, "\n").match(/^---\n([\s\S]*?)\n---/);
  if (design) {
    for (const m of design[1].matchAll(/^\s+([\w-]+):\s*["']?(#[0-9a-f]{3,8})\b/gim)) { const h = hex6(m[2]); if (h) colors[h] = `DESIGN.md ${m[1]}`; }
    for (const m of design[1].matchAll(/fontFamily:\s*["']?([^"'\n]+)/g)) fonts.add(m[1].trim().toLowerCase());
  }
  let stack = [];
  try {
    const pk = JSON.parse(read(join(root, "package.json")) || "{}"), deps = { ...pk.dependencies, ...pk.devDependencies };
    stack = ["astro", "next", "react", "vue", "svelte", "@sveltejs/kit", "nuxt", "remix", "tailwindcss", "express", "fastify", "hono", "prisma", "drizzle-orm"].filter((n) => n in deps);
  } catch { /* no package.json */ }
  return { colors, used, fonts: [...fonts].slice(0, 12), components, content: content.slice(0, 20), pages: [...new Set(pages)].sort().slice(0, 40), stack };
}

/** The profile for this project, from cache when nothing important changed. */
export function profile(root) {
  const files = walk(root);
  const keys = files.filter((f) => STYLE.test(f) || /DESIGN\.md$|tailwind\.config|package\.json$|(^|[\\/])components?[\\/]|(^|[\\/])pages[\\/]|(^|[\\/])content[\\/]/.test(f));
  const stamp = createHash("sha256").update(keys.map((f) => { try { return `${f}:${statSync(f).mtimeMs}`; } catch { return f; } }).join("|")).digest("hex").slice(0, 16);
  const dir = join(tmpdir(), "lintsure-drift"), cache = join(dir, `profile-${createHash("sha256").update(root).digest("hex").slice(0, 12)}.json`);
  try { const c = JSON.parse(readFileSync(cache, "utf8")); if (c.stamp === stamp) return c.profile; } catch { /* rebuild */ }
  const p = build(root, files);
  try { mkdirSync(dir, { recursive: true }); writeFileSync(cache, JSON.stringify({ stamp, profile: p })); } catch { /* fine */ }
  return p;
}

/** At most about 15 lines for the agent. */
export function summary(p) {
  const out = [], cols = Object.entries(p.colors);
  if (p.stack.length) out.push(`- Stack: ${p.stack.join(", ")}`);
  if (cols.length) out.push(`- Brand colours: ${cols.slice(0, 10).map(([h, n]) => `${n} ${h}`).join(", ")}. Use these, not new colours.`);
  if (p.fonts.length) out.push(`- Fonts: ${p.fonts.slice(0, 5).join(", ")}`);
  const comps = Object.keys(p.components);
  if (comps.length) out.push(`- Existing components (reuse them): ${comps.slice(0, 25).join(", ")}${comps.length > 25 ? ` and ${comps.length - 25} more` : ""}`);
  if (p.content.length) out.push(`- Real content and copy lives in: ${p.content.slice(0, 6).join(", ")}. Use it; don't invent quotes, names or claims.`);
  if (p.pages.length) out.push(`- Pages: ${p.pages.slice(0, 15).join(", ")}${p.pages.length > 15 ? " ..." : ""}`);
  return out;
}

const rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
const dist = (a, b) => { const x = rgb(a), y = rgb(b); return Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]); };

/** Checks after an edit: colours and fonts outside the brand, and new components that copy an existing one. */
export function profileChecks(root, rel, text, whole, exceptFiles = "") {
  // A colour that only appears in files with an agreed exception is still off brand everywhere else.
  const normal = (f) => f !== rel && !(exceptFiles && globMatch(f, exceptFiles));
  let p; try { p = profile(root); } catch { return []; }
  const out = [], palette = Object.keys(p.colors), lineOf = (s) => { const i = whole.indexOf(s); return i < 0 ? 0 : whole.slice(0, i).split("\n").length; };
  if ((STYLE.test(rel) || UI.test(rel)) && palette.length >= 2) {
    const seen = new Set();
    for (const line of text.split("\n")) {
      if (/^\s*--[\w-]+\s*:/.test(line)) continue; // defining a brand token is how a palette grows
      for (const m of line.matchAll(/#[0-9a-f]{3,8}\b/gi)) {
        const h = hex6(m[0]); if (!h || p.colors[h] || (p.used?.[h] || []).some(normal) || seen.has(h)) continue;
        if (/^#(fff|ffffff|000|000000)$/i.test(m[0])) continue;
        seen.add(h);
        const near = palette.reduce((a, b) => (dist(h, a) <= dist(h, b) ? a : b));
        out.push({ kind: "off_brand", line: lineOf(m[0]), detail: `Uses the colour ${m[0]}, which isn't in the project's palette. Closest brand colour: ${p.colors[near]} (${near}). Prefer it unless the user asked for this colour.` });
      }
    }
  }
  if (p.fonts.length && (STYLE.test(rel) || UI.test(rel))) {
    for (const m of text.matchAll(/font-family\s*:\s*['"]?([A-Za-z][\w .-]+)/gi)) {
      const n = m[1].trim().toLowerCase();
      if (!GENERIC.has(n) && !p.fonts.includes(n) && !n.startsWith("var")) out.push({ kind: "off_brand", line: lineOf(m[0]), detail: `Uses the font "${m[1].trim()}", which isn't one of the project's fonts (${p.fonts.slice(0, 3).join(", ")}).` });
    }
  }
  if (UI.test(rel) && /(^|\/)components?\//.test(rel)) {
    const name = basename(rel).replace(/\.[^.]+$/, ""), norm = (n) => n.toLowerCase().replace(/(new|copy|v?\d+|alt|2)$/g, "").replace(/[-_]/g, "");
    // The profile may already include this new file, so compare against every other component, not just older ones.
    const twin = Object.entries(p.components).find(([n, r]) => r !== rel && n !== name && norm(n) === norm(name));
    if (twin) out.push({ kind: "duplicate", line: 0, detail: `${name} looks like a copy of ${twin[0]} in ${twin[1]}. Reuse or extend it instead of making a copy.` });
  }
  return out;
}
