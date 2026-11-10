// Rules for the stacks AI app builders use most (Supabase, Next.js, Vite): open databases and secrets
// shipped to the browser, two of the most damaging mistakes in apps built quickly.
// Pattern-based and single-file like the rest, so each rule says when it may be wrong. Beta.
import type { Control, Rule } from "../types.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const GDPR32: Control = { framework: "gdpr", id: "Art. 32", title: "Security of processing" };
const OW = (n: string, title: string): Control => ({ framework: "owasp-top10", id: `A${n}:2025`, title });
const A01 = OW("01", "Broken Access Control"), A02 = OW("02", "Security Misconfiguration"), A04 = OW("04", "Cryptographic Failures");
const rule = (r: Omit<Rule, "mappedBy" | "reviewedAt">): Rule => ({ ...r, ...DRAFT });

// Tables in schemas Supabase manages itself; RLS on these is not the app's job.
const SYSTEM_SCHEMA = /^(auth|storage|realtime|extensions|supabase_\w+|pg_\w+|graphql\w*|vault)\./i;
/** Tables created in this SQL file with no "enable row level security" for them in the same file. Pure. */
export function tablesWithoutRls(lines: string[], shared?: string): number[] {
  const text = (shared ?? lines.join("\n")).toLowerCase();
  const out: number[] = [];
  lines.forEach((l, i) => {
    const m = /^\s*create\s+table\s+(if\s+not\s+exists\s+)?([\w."]+)/i.exec(l);
    if (!m) return;
    const full = m[2].replace(/"/g, "");
    if (SYSTEM_SCHEMA.test(full)) return;
    const name = full.split(".").pop()!.toLowerCase();
    const rls = new RegExp(`alter\\s+table\\s+(only\\s+)?(if\\s+exists\\s+)?("?\\w+"?\\.)?"?${name}"?\\s+enable\\s+row\\s+level\\s+security`);
    if (!rls.test(text)) out.push(i + 1);
  });
  return out;
}

// Signs that a function checks its caller: a user session, a JWT, a webhook signature or a shared secret.
const CALLER_CHECK = /auth\.getUser\(|auth\.getClaims\(|getClaims\(|jwtVerify\(|verify(Jwt|JWT|Token|Signature|Webhook|Request)\w*\(|constructEvent(Async)?\(|createHmac\(|timingSafeEqual|crypto\.subtle\.(verify|importKey)|Deno\.env\.get\(\s*["'][A-Z_]*(WEBHOOK|CRON|SHARED|SIGNING|CALLBACK|FUNCTION)[A-Z_]*SECRET["']/i;
// Reading a header is not checking it: the header must be compared, or a request must be turned away with 401/403
// (review P11: reading Authorization and passing it on, unchecked, is the stock template).
const HEADER_COMPARED = /headers\.get\([^)]*\)[^;\n]*(!==?|===?)|(!==?|===?)[^;\n]*headers\.get\(/;
const DENIES = /status\s*:\s*40[13]\b|\b40[13]\s*\)/;
/** Code with comments removed, so "// TODO: call verifyToken()" doesn't count as a check. Pure. */
const stripComments = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
const HIGH_IMPACT = /SERVICE_ROLE|service_role|sb_secret_|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY/;
/** In supabase/config.toml: functions with verify_jwt = false whose code shows no caller check of its own. Pure. */
export function functionsWithoutAuth(lines: string[], _shared?: string, files: Record<string, string> = {}): Array<{ line: number; status: "gap" | "partial" }> {
  const out: Array<{ line: number; status: "gap" | "partial" }> = [];
  let fn = "";
  lines.forEach((l, i) => {
    const head = /^\s*\[functions\.([\w-]+)\]/.exec(l);
    if (head) { fn = head[1]; return; }
    if (/^\s*\[/.test(l)) { fn = ""; return; }
    if (!fn || !/^\s*verify_jwt\s*=\s*false\b/.test(l)) return;
    const own = Object.entries(files).filter(([p]) => p.includes(`supabase/functions/${fn}/`));
    if (!own.length) return; // the code isn't in this repo: nothing to judge
    // Follow imports of shared helpers (../_shared/auth.ts), so a check kept in a helper counts.
    const imported = Object.entries(files).filter(([p]) => /\/_shared\//.test(p) && own.some(([, t]) => t.includes(p.split("/").pop()!.replace(/\.(ts|js|mjs)$/, ""))));
    const text = [...own, ...imported].map(([, t]) => stripComments(t)).join("\n");
    if (CALLER_CHECK.test(text) || HEADER_COMPARED.test(text) || (DENIES.test(text) && /headers\.get\(/.test(text))) return;
    out.push({ line: i + 1, status: HIGH_IMPACT.test(own.map(([, t]) => t).join("\n")) ? "gap" : "partial" });
  });
  return out;
}

// Browser-exposed env prefixes: Next.js, Vite, Expo, Create React App, Nuxt, SvelteKit/Astro (PUBLIC_).
// No bare PUBLIC_: it matches ordinary constants like PUBLIC_WITH_PRIVATE_AGENT.
const PUBLIC_ENV = /\b(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC)_[A-Z0-9_]*/g;
// Services whose API keys are always server-side secrets (widget and analytics keys are often public, so not these).
const SECRET_SERVICE = /OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|DEEPSEEK|COHERE|REPLICATE|ELEVENLABS|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|AWS|DATABASE|PINECONE|GITHUB_TOKEN/;
// Supabase projects keep their SQL in supabase/. Prisma or Drizzle migrations elsewhere talk to a database the
// browser can't reach, so row level security isn't the point there (found in the field test: 263 false alarms).
const SUPABASE_DIR = /(^|\/)supabase\//;
// Keys that are public by design and fine in the browser.
const PUBLIC_BY_DESIGN = /ANON|PUBLISHABLE|_PK_|PUBLIC_KEY|FIREBASE|MAPS|MAPBOX|POSTHOG|SENTRY_DSN|ALGOLIA_SEARCH|SITE_KEY|MEASUREMENT_ID|URL$|_URL_/;
// Words that make a name secret whatever service it belongs to. They win over the public list above:
// NEXT_PUBLIC_FIREBASE_ADMIN_PRIVATE_KEY and VITE_POSTHOG_PERSONAL_API_KEY are secrets (review P14).
const SECRET_WORD = /SECRET|PRIVATE|SERVICE_ROLE|SB_SECRET|PASSWORD|PERSONAL_(API_KEY|ACCESS_TOKEN|TOKEN)|(DATABASE|POSTGRES|DB|MONGO(DB)?|REDIS)_URL|CONNECTION_STRING/;
/** A browser-exposed env name that holds a secret. Pure. */
export function publicSecretName(n: string): boolean {
  if (/FIREBASE\w*DATABASE_URL/.test(n)) return false; // Firebase's Realtime Database URL is public config
  if (SECRET_WORD.test(n)) return true;
  if (PUBLIC_BY_DESIGN.test(n)) return false;
  return SECRET_SERVICE.test(n) && /KEY|TOKEN/.test(n);
}

export const stackRules: Rule[] = [
  rule({ id: "supabase.rls-disabled", title: "Database table without row level security", status: "partial", severity: "high", controls: [GDPR32, A01],
    fix: "Add `alter table <name> enable row level security;` and a policy that limits each row to its owner, for example `using (auth.uid() = user_id)`.",
    note: "In Supabase, a table without row level security can be read and changed by anyone with your public anon key, which ships in every browser. Lintsure looks across every SQL file in supabase/. Marked Partial: it may be switched on outside these files, for example in the dashboard.", extensions: [".sql"],
    pathMatch: SUPABASE_DIR,
    sharedContext: true, // RLS is often switched on in a later migration (field test, 50 repos)
    fileTest: tablesWithoutRls }),
  rule({ id: "supabase.policy-allows-all", title: "Database policy that lets everyone in", status: "partial", severity: "high", controls: [GDPR32, A01],
    fix: "Limit the policy to the right people, for example `using (auth.uid() = user_id)`. Keep `using (true)` only for data that is meant to be public, such as published posts.",
    note: "`using (true)` or `with check (true)` turns row level security on but lets every request through, so the table is as open as having no security at all. Marked Partial: public read access can be intended.", extensions: [".sql"],
    pathMatch: SUPABASE_DIR,
    // A read-only policy (for select) that is open on purpose, such as published posts, is common and fine;
    // open insert, update, delete or "all" policies are the risk (field test, 139 repos).
    fileTest: (lines) => lines.flatMap((l, i) => {
      if (!/\b(using|with\s+check)\s*\(\s*true\s*\)/i.test(l)) return [];
      const start = lines.slice(Math.max(0, i - 8), i + 1).join(" ");
      return /\bfor\s+select\b/i.test(start.slice(start.toLowerCase().lastIndexOf("create policy"))) ? [] : [i + 1];
    }) }),
  rule({ id: "supabase.function-no-auth", title: "Supabase Edge Function anyone can call", status: "partial", severity: "high", controls: [GDPR32, A01],
    fix: "Keep verify_jwt on for this function, or check the caller yourself at the top of the handler: supabase.auth.getUser() for users, or the provider's signature for a webhook.",
    note: "verify_jwt = false switches off Supabase's check that the caller is logged in, so anyone who knows the URL can call the function. Webhooks do this on purpose and verify a signature instead. Lintsure flags it only when the function's own code shows no check of its own. Marked Gap when the function also uses the service-role key or a paid AI API, because then anyone can read or change data, or spend your credits.",
    extensions: [".toml"], fileName: /^config\.toml$/, pathMatch: SUPABASE_DIR,
    sharedFiles: /(^|\/)supabase\/functions\/.+\.(ts|js|mjs)$/,
    fileTest: functionsWithoutAuth }),
  rule({ id: "secret.public-env", title: "Secret in a variable the browser can see", status: "gap", severity: "high", controls: [GDPR32, A04],
    fix: "Rename the variable without the public prefix (NEXT_PUBLIC_, VITE_ and so on), use it only in server code, and rotate the key, since it has already been shipped to browsers.",
    note: "Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_ or REACT_APP_ are copied into the JavaScript every visitor downloads. Anyone can read a secret, service-role or private key put there. Keys that are public by design (Supabase anon, Stripe publishable, Firebase) are not flagged.",
    extensions: [...CODE, ".env"],
    unlessPath: /\.d\.ts$/, // type declarations (env.d.ts) name variables, they don't ship values (field test)
    test: (l) => {
      if (/^\s*(readonly\s+)?[A-Z0-9_]+\??\s*:\s*string\b/.test(l)) return false; // a typed field, not a value
      return (l.match(PUBLIC_ENV) ?? []).some(publicSecretName);
    } }),
  rule({ id: "supabase.service-key-in-client", title: "Supabase service-role key used in browser code", status: "gap", severity: "high", controls: [GDPR32, A01],
    fix: "Use the service-role key only in server code (API routes, server actions, edge functions). In browser code, use the anon key with row level security, and rotate the service-role key if it was ever shipped.",
    note: "The service-role key skips every row level security rule. In a file marked \"use client\", or in browser-exposed env vars, it reaches every visitor, who can then read and change your whole database.", extensions: CODE,
    fileTest: (lines) => lines.some((l) => /^\s*["']use client["']/.test(l))
      ? lines.flatMap((l, i) => (/SERVICE_ROLE|service_role|sb_secret_/.test(l) ? [i + 1] : [])) : [] }),
  rule({ id: "build.sourcemaps-public", title: "Source maps published in production", status: "partial", severity: "low", controls: [A02],
    fix: "Turn off browser source maps for production, or upload them privately to your error tracker instead of serving them.",
    note: "Public source maps let anyone read your original front-end code, comments and file structure, which makes other weaknesses easier to find. Marked Partial: some teams publish them on purpose.", extensions: CODE,
    // Only Next.js's browser source maps: Vite's sourcemap: true is normal in libraries and CLIs (field test: 5 false alarms).
    fileName: /^next\.config\./,
    test: (l) => /productionBrowserSourceMaps\s*:\s*true/.test(l) }),
];
