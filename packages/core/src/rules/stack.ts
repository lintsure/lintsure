// Rules for the stacks AI app builders use most (Supabase, Next.js, Vite). Chosen from what developers
// report breaking most often in vibe-coded apps: open databases and secrets shipped to the browser.
// Pattern-based and single-file like the rest, so each rule says when it may be wrong. Beta.
import type { Control, Rule } from "../types.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const GDPR32: Control = { framework: "gdpr", id: "Art. 32", title: "Security of processing" };
const CC61: Control = { framework: "soc2", id: "CC6.1", title: "Logical access security" };
const A83: Control = { framework: "iso-27001", id: "A.8.3", title: "Information access restriction" };
const A824: Control = { framework: "iso-27001", id: "A.8.24", title: "Use of cryptography" };
const OW = (n: string, title: string): Control => ({ framework: "owasp-top10", id: `A${n}:2025`, title });
const A01 = OW("01", "Broken Access Control"), A02 = OW("02", "Security Misconfiguration"), A04 = OW("04", "Cryptographic Failures");
const rule = (r: Omit<Rule, "mappedBy" | "reviewedAt">): Rule => ({ ...r, ...DRAFT });

// Tables in schemas Supabase manages itself; RLS on these is not the app's job.
const SYSTEM_SCHEMA = /^(auth|storage|realtime|extensions|supabase_\w+|pg_\w+|graphql\w*|vault)\./i;
/** Tables created in this SQL file with no "enable row level security" for them in the same file. Pure. */
export function tablesWithoutRls(lines: string[]): number[] {
  const text = lines.join("\n").toLowerCase();
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

export const stackRules: Rule[] = [
  rule({ id: "supabase.rls-disabled", title: "Database table without row level security", status: "partial", severity: "high", controls: [GDPR32, CC61, A83, A01],
    fix: "Add `alter table <name> enable row level security;` and a policy that limits each row to its owner, for example `using (auth.uid() = user_id)`.",
    note: "In Supabase, a table without row level security can be read and changed by anyone with your public anon key, which ships in every browser. Marked Partial: it may be enabled in another migration.", extensions: [".sql"],
    pathMatch: SUPABASE_DIR,
    fileTest: tablesWithoutRls }),
  rule({ id: "supabase.policy-allows-all", title: "Database policy that lets everyone in", status: "partial", severity: "high", controls: [GDPR32, CC61, A83, A01],
    fix: "Limit the policy to the right people, for example `using (auth.uid() = user_id)`. Keep `using (true)` only for data that is meant to be public, such as published posts.",
    note: "`using (true)` or `with check (true)` turns row level security on but lets every request through, so the table is as open as having no security at all. Marked Partial: public read access can be intended.", extensions: [".sql"],
    pathMatch: SUPABASE_DIR,
    test: (l) => /\b(using|with\s+check)\s*\(\s*true\s*\)/i.test(l) }),
  rule({ id: "secret.public-env", title: "Secret in a variable the browser can see", status: "gap", severity: "high", controls: [GDPR32, CC61, A824, A04],
    fix: "Rename the variable without the public prefix (NEXT_PUBLIC_, VITE_ and so on), use it only in server code, and rotate the key, since it has already been shipped to browsers.",
    note: "Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_ or REACT_APP_ are copied into the JavaScript every visitor downloads. Anyone can read a secret, service-role or private key put there. Keys that are public by design (Supabase anon, Stripe publishable, Firebase) are not flagged.",
    extensions: [...CODE, ".env"],
    test: (l) => {
      const names = l.match(PUBLIC_ENV) ?? [];
      const risky = names.filter((n) => !PUBLIC_BY_DESIGN.test(n));
      return risky.some((n) => /SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|SB_SECRET/.test(n) || (SECRET_SERVICE.test(n) && /KEY|TOKEN/.test(n)));
    } }),
  rule({ id: "supabase.service-key-in-client", title: "Supabase service-role key used in browser code", status: "gap", severity: "high", controls: [GDPR32, CC61, A83, A01],
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
