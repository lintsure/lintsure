// OWASP API Security Top 10 (2023): tags for existing rules, and one rule of its own. Ids and names only; every
// description is our own wording. Not affiliated with or endorsed by OWASP. Beta: awaiting professional review.
import type { Control, Rule } from "../types.js";

const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const API = (n: number, title: string): Control => ({ framework: "owasp-api", id: `API${n}:2023`, title });
const API1 = API(1, "Broken Object Level Authorization"), API2 = API(2, "Broken Authentication"),
  API3 = API(3, "Broken Object Property Level Authorization"), API4 = API(4, "Unrestricted Resource Consumption"),
  API5 = API(5, "Broken Function Level Authorization"), API7 = API(7, "Server Side Request Forgery"),
  API8 = API(8, "Security Misconfiguration"), API10 = API(10, "Unsafe Consumption of APIs");

/** Rules that already exist and say something about an API risk. */
export const apiForExisting: Record<string, Control[]> = {
  "authz.no-owner-check": [API1], "supabase.rls-disabled": [API1], "supabase.policy-allows-all": [API1],
  "auth.hardcoded-password": [API2], "jwt.unverified": [API2], "jwt.no-expiry": [API2], "jwt.no-algorithm-pin": [API2],
  "jwt.weak-secret": [API2], "crypto.weak-password-hash": [API2], "session.cookie-insecure": [API2],
  "auth.no-rate-limit": [API2, API4],
  "mass-assignment": [API3],
  "llm.no-output-limit": [API4], "llm.unbounded-agent-loop": [API4], "upload.unrestricted": [API4],
  "cookie.trusted-role": [API5], "supabase.function-no-auth": [API5], "cloud.function-url-no-auth": [API5],
  "ssrf.user-url": [API7],
  "cors.any-origin": [API8], "config.debug-on": [API8], "error.stack-to-client": [API8], "graphql.introspection": [API8],
  "config.allowed-hosts-any": [API8],
  "transport.tls-verify-off": [API8, API10], "transport.plain-http": [API10],
};

// A route file that is its own endpoint (Next.js route handlers and API pages, Nuxt server routes, SvelteKit endpoints),
// with "admin" as a part of its path. Frameworks that mount routers elsewhere are left out: the check may sit in the
// file that mounts them.
const ADMIN_ENDPOINT = /^(?=.*(^|\/)admin[\/.-])(?=.*(^|\/)(app\/.*\/route|pages\/api\/.+|server\/api\/.+|routes\/.*\+server)\.[cm]?[jt]s$)/i;
const HANDLER = /export\s+(async\s+)?(function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+default\s+(async\s+)?function|export\s+default\s+defineEventHandler|export\s*\{[^}]*\b(GET|POST|PUT|PATCH|DELETE)\b/;
// Anything that looks like the caller is being identified or checked. "admin" alone is not it: the path already says that.
const ACCESS_CHECK = /\b(role|roles|isAdmin|is_admin|requireAdmin|adminOnly|assertAdmin|permission\w*|authori[sz]\w*|getServerSession|getSession|auth\s*\(|getUser|currentUser|session|verify\w*|clerk\w*|getToken|jwt|requireAuth|withAuth|protect\w*|guard\w*|api[-_]?key|bearer|unauthori[sz]ed|forbidden|40[13])\b|\b\w*(require|ensure|assert|check|verify|with|is)\w*Admin\w*\s*\(|\badmin(Handler|Guard|Auth|Only|Route|Middleware)\w*\s*\(/i;
// Middleware that lets every API path through unchecked: an early return for /api, or a matcher that leaves api out.
const SKIPS_API = /startsWith\(\s*["'\x60]\/api\/?["'\x60]\s*\)\s*\)?\s*\{?\s*return\s+(true|NextResponse\.next|next\()|\(\?![^)\n]*\bapi\b/;

/** An admin endpoint whose file shows no sign of checking who is calling, in a project whose middleware has no check
 *  either or lets API paths through. Line of the first handler, or nothing. Pure. */
export function adminRouteNoCheck(lines: string[], _shared?: string, files: Record<string, string> = {}): Array<{ line: number; status: "partial" }> {
  if (ACCESS_CHECK.test(lines.join("\n")) || Object.values(files).some((t) => ACCESS_CHECK.test(t) && !SKIPS_API.test(t))) return [];
  const i = lines.findIndex((l) => HANDLER.test(l));
  return i < 0 ? [] : [{ line: i + 1, status: "partial" }];
}

export const apiRules: Rule[] = [
  { id: "authz.admin-route-no-check", title: "Admin endpoint with no access check in sight", status: "partial", severity: "high", controls: [API5, { framework: "owasp-top10", id: "A01:2025", title: "Broken Access Control" }],
    fix: "Check the caller's role at the top of the handler and return 403 when it is not an admin. Do it on the server: hiding the admin page in the browser does not protect the endpoint behind it.",
    note: "Anyone who knows or guesses the address can call an endpoint. An admin endpoint that never looks at who is calling gives every visitor admin actions (CWE-862, CWE-285).",
    unseen: "Lintsure looked for a role, session or token check in this file and in the project's middleware. It can't see a check in a gateway, a reverse proxy or a wrapper it doesn't recognise.",
    extensions: [".ts", ".js", ".mjs", ".cjs"], pathMatch: ADMIN_ENDPOINT, unlessPath: /\.(test|spec)\.[cm]?[jt]s$/,
    sharedFiles: /(^|\/)(middleware|proxy|hooks\.server)\.[cm]?[jt]s$/,
    fileTest: adminRouteNoCheck, ...DRAFT },
];
