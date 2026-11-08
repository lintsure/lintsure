// Data map: where personal data goes in your code. For each line that mentions a personal data field
// and a destination (logs, analytics, a database, an email or payment provider, an AI model...),
// it records an edge: field → destination, with the file and line. Runs locally, never sends code.
// It reads each call up to its closing bracket: data passed through variables or helpers in other files is missed.
import { readFile } from "node:fs/promises";
import { relative, sep, extname } from "node:path";
import { listFiles, readConfig } from "./index.js";

const CODE = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"]);

/** Personal data fields, by the names code usually gives them. Order matters: first match wins. */
export const FIELDS: [string, RegExp][] = [
  ["Email", /\b\w*e-?mail\w*\b/i],
  ["Phone", /\b\w*(phone|mobile|msisdn)\w*\b/i],
  ["Password", /\b\w*(password|passwd)\w*\b/i],
  ["Full name", /\b(full_?name|first_?name|last_?name|given_?name|family_?name|display_?name|username|user_?name)\b/i],
  ["Address", /\b(street|address_?line\d?|postcode|post_?code|zip_?code|billing_?address|shipping_?address|home_?address)\b/i],
  ["Date of birth", /\b(dob|date_?of_?birth|birth_?date|birthday)\b/i],
  ["Government ID", /\b(ssn|social_?security|passport\w*|national_?id|tax_?id|pesel|nin)\b/i],
  ["Payment card", /\b(card_?number|credit_?card|cc_?number|cvv|cvc|iban)\b/i],
  ["IP address", /\b(ip_?address|remote_?addr|client_?ip|x-forwarded-for|req\.ip)\b/i],
  ["Location", /\b(latitude|longitude|geo_?location|gps)\b/i],
  ["Health data", /\b(diagnosis|medical\w*|health_?\w+|prescription|blood_?type|mrn)\b/i],
];

/** Destinations, grouped so the map stays readable. First match wins. */
export const DESTINATIONS: { group: string; name: string; test: RegExp }[] = [
  { group: "Logs", name: "Application logs", test: /\b(console\.(log|info|warn|error|debug)|logger\.\w+|log\.(info|warn|error|debug)|logging\.\w+)\s*\(/ },
  { group: "Analytics", name: "PostHog", test: /\bposthog\.\w+\(/i },
  { group: "Analytics", name: "Segment", test: /\b(analytics|segment)\.(identify|track|page)\(/ },
  { group: "Analytics", name: "Mixpanel", test: /\bmixpanel\.\w+/i },
  { group: "Analytics", name: "Amplitude", test: /\bamplitude\.\w+/i },
  { group: "Analytics", name: "Google Analytics", test: /\b(gtag|ga)\(/ },
  { group: "Analytics", name: "Intercom", test: /\bIntercom\(|\bintercom\.\w+/ },
  { group: "Error tracking", name: "Sentry", test: /\bSentry\.(setUser|captureException|captureMessage|setContext)\(/ },
  { group: "AI model", name: "OpenAI", test: /\bopenai\.(chat|responses|completions|embeddings)\b/i },
  { group: "AI model", name: "Anthropic", test: /\banthropic\.messages\b|\bclient\.messages\.create\(/i },
  { group: "AI model", name: "AI model", test: /\b(generateText|streamText|generateObject)\(/ },
  { group: "Email", name: "Resend", test: /\bresend\.emails\.send\(/i },
  { group: "Email", name: "SendGrid", test: /\bsgMail\.send\(|\bsendgrid\b/i },
  { group: "Email", name: "Postmark", test: /\bpostmark\b/i },
  { group: "Email", name: "Email (SMTP)", test: /\b(transporter|nodemailer)\.sendMail\(|\bsend_mail\(/ },
  { group: "Payments", name: "Stripe", test: /\bstripe\.(customers|checkout|paymentIntents|subscriptions|invoices)\b/i },
  { group: "Storage", name: "File storage", test: /\b(s3|r2|bucket|storage)\.(upload|putObject|put|from)\(|\bPutObjectCommand\b/i },
  { group: "Database", name: "Database", test: /\b(prisma\.\w+\.(create|update|upsert)|\.insert(One|Many)?\(|\.create\(|\.save\(|INSERT INTO|UPDATE \w+ SET|db\.(query|execute)\(|supabase\.from\()/i },
  { group: "Browser storage", name: "Browser storage", test: /\b(localStorage|sessionStorage)\.setItem\(|document\.cookie\s*=/ },
  { group: "Outside API", name: "Outside API", test: /\b(fetch|axios(\.(post|put|patch))?|requests\.(post|put|patch)|httpx\.(post|put))\s*\(/ },
];

/** Known services, named from the URL an outside call goes to. */
const HOSTS: [RegExp, string, string][] = [
  [/api\.resend\.com/, "Email", "Resend"], [/api\.sendgrid\.com/, "Email", "SendGrid"], [/api\.postmarkapp\.com/, "Email", "Postmark"],
  [/api\.mailgun\.net/, "Email", "Mailgun"], [/api\.stripe\.com/, "Payments", "Stripe"], [/api\.openai\.com/, "AI model", "OpenAI"],
  [/api\.anthropic\.com/, "AI model", "Anthropic"], [/hooks\.slack\.com|slack\.com\/api/, "Messaging", "Slack"],
  [/api\.hubapi\.com/, "CRM", "HubSpot"], [/api\.airtable\.com/, "Database", "Airtable"], [/googleapis\.com/, "Outside API", "Google APIs"],
];

export interface DataFlow { field: string; group: string; destination: string; file: string; line: number }
export interface DataMap {
  filesRead: number;
  flows: DataFlow[];
  /** Fields seen anywhere in code, even when no destination was found on the same line. */
  fieldsSeen: string[];
}

/** Drops plain text inside quotes (keeping template ${...} parts), so "Enter your email" isn't counted. */
const codeOnly = (l: string) => l.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, (s) => (s.match(/\{[^}]*\}/g) ?? []).join(" "));

/** The text of a call that starts on lines[i]: up to the closing bracket, at most 15 lines. */
export function callSpan(lines: string[], i: number): string {
  let depth = 0, out = "";
  for (let j = i; j < Math.min(lines.length, i + 15); j++) {
    out += lines[j] + "\n";
    for (const ch of codeOnly(lines[j])) { if (ch === "(" || ch === "{" || ch === "[") depth++; else if (ch === ")" || ch === "}" || ch === "]") depth--; }
    if (depth <= 0 && j > i - 1) break;
  }
  return out;
}

/** Pure: the flows in one call (the line where a destination starts, plus the rest of that call). */
export function flowsInLine(text: string, span = text): { field: string; group: string; destination: string }[] {
  const dest = DESTINATIONS.find((d) => d.test.test(text));
  if (!dest) return [];
  const host = dest.name === "Outside API" ? HOSTS.find(([re]) => re.test(span)) : undefined;
  const named = host ? { group: host[1], name: host[2] } : { group: dest.group, name: dest.name };
  const code = codeOnly(span);
  return FIELDS.filter(([, re]) => re.test(code)).map(([field]) => ({ field, group: named.group, destination: named.name }));
}

export async function buildDataMap(root: string): Promise<DataMap> {
  const { ignore } = await readConfig(root);
  const flows: DataFlow[] = []; const seen = new Set<string>(); let filesRead = 0;
  for (const abs of await listFiles(root, ignore)) {
    if (!CODE.has(extname(abs))) continue;
    const buf = await readFile(abs);
    if (buf.length > 1_000_000 || buf.includes(0)) continue;
    const lines = buf.toString("utf8").split(/\r?\n/);
    if (lines.some((l) => l.length > 1000)) continue; // minified or generated
    filesRead++;
    const file = relative(root, abs).split(sep).join("/");
    lines.forEach((text, i) => {
      const code = codeOnly(text);
      for (const [name, re] of FIELDS) if (re.test(code)) seen.add(name);
      if (DESTINATIONS.some((d) => d.test.test(text))) for (const f of flowsInLine(text, callSpan(lines, i))) flows.push({ ...f, file, line: i + 1 });
    });
  }
  return { filesRead, flows, fieldsSeen: FIELDS.map(([n]) => n).filter((n) => seen.has(n)) };
}

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const NOTE = "This map reads code call by call. It shows where a personal data field appears inside a call to a destination. Data passed through variables, helpers or other files may be missing, and some lines may be listed that don't send personal data. Check each one. It is a starting point for your record of processing, not the record itself.";

export function toDataMapMarkdown(m: DataMap): string {
  const byDest = new Map<string, DataFlow[]>();
  for (const f of m.flows) byDest.set(`${f.group} · ${f.destination}`, [...(byDest.get(`${f.group} · ${f.destination}`) ?? []), f]);
  return [
    "# Lintsure data map", "",
    `${m.flows.length} place${m.flows.length === 1 ? "" : "s"} where personal data reaches a destination, in ${m.filesRead} files read.`, "",
    `> ${NOTE}`, "",
    ...[...byDest].flatMap(([d, fl]) => [`## ${d}`, "", ...fl.map((f) => `- **${f.field}** · \`${f.file}:${f.line}\``), ""]),
    `Personal data fields seen in code: ${m.fieldsSeen.join(", ") || "none"}.`, "",
  ].join("\n");
}

/** A self-contained HTML page: fields on the left, destinations on the right, a line for each flow. */
export function toDataMapHtml(m: DataMap, project: string): string {
  const fields = [...new Set(m.flows.map((f) => f.field))];
  const dests = [...new Set(m.flows.map((f) => `${f.group}|${f.destination}`))];
  const rowH = 54, top = 60, h = Math.max(fields.length, dests.length) * rowH + top + 30, w = 900;
  const fy = (i: number) => top + i * rowH + (Math.max(0, dests.length - fields.length) * rowH) / 2;
  const dy = (i: number) => top + i * rowH + (Math.max(0, fields.length - dests.length) * rowH) / 2;
  const pairs = new Map<string, DataFlow[]>();
  for (const f of m.flows) { const k = `${f.field}→${f.group}|${f.destination}`; pairs.set(k, [...(pairs.get(k) ?? []), f]); }
  const links = [...pairs].map(([k, fl]) => {
    const [field, dest] = k.split("→"); const y1 = fy(fields.indexOf(field)) + 18, y2 = dy(dests.indexOf(dest)) + 18;
    return `<path d="M260 ${y1} C 450 ${y1}, 450 ${y2}, 640 ${y2}" class="link" style="stroke-width:${Math.min(8, 1.5 + fl.length)}"><title>${esc(field)} → ${esc(dest.split("|")[1])}: ${fl.length}</title></path>`;
  }).join("");
  const box = (x: number, y: number, label: string, sub: string, cls: string) =>
    `<g class="${cls}"><rect x="${x}" y="${y}" width="240" height="36" rx="9"/><text x="${x + 14}" y="${y + 23}">${esc(label)}</text>${sub ? `<text x="${x + 226}" y="${y + 23}" text-anchor="end" class="sub">${esc(sub)}</text>` : ""}</g>`;
  const count = (pred: (f: DataFlow) => boolean) => String(m.flows.filter(pred).length);
  const svg = `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-label="Data map">
  <text x="20" y="34" class="head">Personal data</text><text x="880" y="34" class="head" text-anchor="end">Where it goes</text>
  ${links}
  ${fields.map((f, i) => box(20, fy(i), f, count((x) => x.field === f), "field")).join("")}
  ${dests.map((d, i) => { const [g, n] = d.split("|"); return box(640, dy(i), n, g === n ? "" : g, "dest"); }).join("")}
</svg>`;
  const rows = m.flows.map((f) => `<tr><td>${esc(f.field)}</td><td>${esc(f.destination)} <span class="g">${esc(f.group)}</span></td><td><code>${esc(f.file)}:${f.line}</code></td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lintsure data map · ${esc(project)}</title>
<style>
:root{--ink:#141413;--muted:#5E5D59;--faint:#8A8984;--line:#E4E2DD;--canvas:#FBFBF9;--accent:#0B6E4F}
body{margin:0;background:var(--canvas);color:var(--ink);font:15px/1.55 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:48px 24px 80px}h1{font-size:34px;letter-spacing:-.03em;margin:0}
.lead{color:var(--muted);margin:8px 0 24px}.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:16px;margin:20px 0}
svg text{font:14px -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:var(--ink)}svg .head{font-size:12px;font-weight:600;letter-spacing:.06em;fill:var(--faint);text-transform:uppercase}
.field rect{fill:#fff;stroke:var(--ink)}.dest rect{fill:#F5F4F1;stroke:var(--line)}svg .sub{fill:var(--faint);font-size:12px}
.link{fill:none;stroke:var(--accent);opacity:.35}.link:hover{opacity:.9}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{border-bottom:1px solid var(--line);padding:8px 6px;text-align:left}th{font-size:12px;color:var(--faint);text-transform:uppercase;letter-spacing:.05em}
code{font:13px ui-monospace,Menlo,Consolas,monospace}.g{color:var(--faint);font-size:12px}.note{font-size:13px;color:var(--muted);border-left:2px solid var(--line);padding-left:12px}
</style></head><body><main>
<h1>Where personal data goes</h1>
<p class="lead">${esc(project)} · ${m.flows.length} place${m.flows.length === 1 ? "" : "s"} where personal data reaches a destination, in ${m.filesRead} files read.</p>
${m.flows.length ? `<div class="card">${svg}</div>` : `<p>No flows found by the current patterns. That doesn't mean there are none.</p>`}
<p class="note">${esc(NOTE)}</p>
${m.flows.length ? `<h2>Every flow</h2><table><tr><th>Field</th><th>Destination</th><th>Where</th></tr>${rows}</table>` : ""}
<p class="note">Made by Lintsure, an open-source readiness tool. It runs on your machine and never sends your code anywhere. Not legal advice.</p>
</main></body></html>`;
}
