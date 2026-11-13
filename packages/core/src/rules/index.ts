// v0 rule set. Pattern-based, deterministic, no network. Each rule maps to every
// framework it touches. Mappings are a first draft: the auditor must review each
// one (mappedBy / reviewedAt) before a framework leaves Beta.
import type { Rule } from "../types.js";
import { owaspForExisting, owaspRules } from "./owasp.js";
import { stackRules } from "./stack.js";
import { craForExisting, craRules } from "./cra.js";
import { standardsForExisting, standardsRules } from "./standards.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"];
// Beta: mapped by us from our own reading of the public texts.
const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };

const LOG_CALL = /\b(console\.(log|info|warn|error|debug)|logger\.\w+|log\.(info|warn|error|debug)|logging\.\w+|print)\s*\(/;
// Drops the text of string literals but keeps interpolations, so "email error" is ignored and `${user.email}` or f"{user.email}" is not.
// [^\\] keeps the two alternatives apart: with "." a run of backslashes could match two ways, which backtracks
// exponentially on text such as an array of regular expressions (found when statements were joined).
const codeOnly = (l: string) => l.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, (s) => (s.match(/\{[^}]*\}/g) ?? []).join(" "));
// Helpers that hide the raw value before it is logged.
const MASKED = /\b\w*(mask|hash|pseudonym|redact|anonymi[sz]e|obfuscate|scrub)\w*\s*\(/i;
const PII = /\b(e-?mail|phone|ssn|social_?security|passport|date_?of_?birth|dob|password|passwd|credit_?card|card_?number|iban)\b/i;
// The arguments of the first log call on a line, up to its matching ")". Other code on the same line is ignored.
function logArgs(l: string): string | null {
  const m = LOG_CALL.exec(l); if (!m) return null;
  let depth = 0, i = m.index + m[0].length - 1;
  for (let j = i; j < l.length; j++) { if (l[j] === "(") depth++; else if (l[j] === ")" && --depth === 0) return l.slice(i + 1, j); }
  return l.slice(i + 1);
}
// Values that usually come from a request or the user. SQL built from them is a Gap; from other values, Partial.
const USER_INPUT = /\b(req|request|params|query|body|input|args|form|ctx|event|payload|searchParams|user_input)\b/;
const SQL_PARTS = /\$\{([^}]*)\}|\bf["'][^"']*\{([^}]*)\}|["']\s*\+\s*([\w.[\]]+)|\.format\(([^)]*)\)|%s["']\s*%\s*([^\n]+)/g;

// Key formats with a fixed, documented prefix, so a match is almost never anything else. Written from each
// provider's published token format. Generic "key = random string" guessing is left out on purpose: too noisy.
const KEY_FORMATS = new RegExp([
  "\\b[sr]k_live_[0-9a-zA-Z]{10,}", // Stripe secret and restricted keys
  "\\b(AKIA|ASIA)[0-9A-Z]{16}\\b", // AWS access key ids
  "\\bgh[pousr]_[0-9A-Za-z]{30,}", "\\bgithub_pat_[0-9A-Za-z_]{40,}", // GitHub tokens
  "\\bglpat-[0-9A-Za-z_-]{20,}", // GitLab personal tokens
  "\\bxox[baprs]-[0-9A-Za-z-]{10,}", "hooks\\.slack\\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{20,}", // Slack
  "\\bsk-ant-(api|admin)\\d{2}-[0-9A-Za-z_-]{20,}", // Anthropic
  "\\bsk-(proj|svcacct|admin)-[0-9A-Za-z_-]{20,}", "\\bsk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20}", // OpenAI
  "\\bSG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}", // SendGrid
  "\\bnpm_[0-9A-Za-z]{36}\\b", "\\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{20,}", // npm and PyPI publish tokens
  "\\bhf_[A-Za-z]{34}\\b", // Hugging Face
  "\\bshp(at|ss|ca|pa)_[0-9a-fA-F]{32}\\b", // Shopify
  "-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
].join("|"));
// Example values from provider docs (AKIAIOSFODNN7EXAMPLE and the like) and obvious fill-ins.
const DOC_EXAMPLE = /EXAMPLE|X{6,}|x{6,}|0{12,}|1234567890abcdef/;
// More fixed-prefix secrets this audience leaks: Stripe webhook secrets, Supabase secret keys, Resend keys (review P13).
const MORE_KEYS = /\bwhsec_[0-9A-Za-z]{24,}|\bsb_secret_[0-9A-Za-z_-]{20,}|\bre_[0-9A-Za-z]{8,}_[0-9A-Za-z]{16,}/;
/** A Supabase (or any) JWT whose payload says role: service_role. Decoded exactly, so near-zero false alarms. Pure. */
export function serviceRoleJwt(l: string): boolean {
  for (const m of l.matchAll(/eyJ[\w-]{10,}\.(eyJ[\w-]{10,})\.[\w-]{10,}/g)) {
    try { if (/"role"\s*:\s*"service_role"/.test(Buffer.from(m[1], "base64url").toString("utf8"))) return true; } catch { /* not a JWT */ }
  }
  return false;
}
/** A database connection URL with an inline password that isn't a local default or a placeholder. Pure. */
export function dbUrlWithPassword(l: string): boolean {
  if (/placeholder|e\.g\.|for example|format:/i.test(l)) return false; // documentation of the format, not a value
  const m = /\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?):\/\/([^:\s"'`/@]+):([^@\s"'`]{4,})@([^/\s"'`:?]+)/.exec(l);
  if (!m) return false;
  const [, , user, pass, host] = m;
  // Only internet hosts: single names (db, hoppscotch-db) are containers on a private network; example.com is a sample.
  if (!host.includes(".") || /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.)|(^|\.)example\.(com|org|net)$|\.local$|\.internal$/i.test(host)) return false;
  // Values built at run time ({$pass}, ${pass}, %s) and stand-ins (pass, testpass, changeme) aren't stored passwords (field test, 139 repos).
  if (/[{}$%<>[\]]/.test(user + pass + host)) return false;
  return pass !== user && !/^(pass|pw|pwd|test\w*|dev\w*|demo\w*|local\w*)$|password|passwd|changeme|secret|example|xxx|your|\*{3}|placeholder|postgres$|root$|admin$/i.test(pass);
}

export const rules: Rule[] = [
  {
    id: "pii.logged",
    title: "Personal data written to logs",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Mask or remove the personal field before logging, for example mask(user.email).",
    note: "Logs are copied to many places and kept for a long time. Personal data in them is hard to find and delete.",
    extensions: CODE,
    // ::add-mask:: tells GitHub Actions to hide the value in its logs.
    // A value passed through a masking or hashing helper first (maskEmail(), pseudonym(), hash()) is not the raw value:
    // every false alarm on 56 new repos in the 0.3.9 review was masked this way (12 of 12).
    test: (l) => { const a = logArgs(l); return a !== null && !l.includes("::add-mask::") && PII.test(codeOnly(a)) && !MASKED.test(a); },
    ...DRAFT,
  },
  {
    id: "secret.in-source",
    title: "Secret or private key committed to source",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Move the secret to an environment variable or secrets manager, then rotate it: it is already in your git history.",
    note: "Anyone with read access to the repo, or a leaked copy of it, can use this key.",
    // Every text format a key ends up in: shell, Terraform, Go, Ruby, PHP, notebooks, Vue and Svelte files, Dockerfiles
    // ("" is extensionless files), not only JavaScript and Python (review P13).
    extensions: [...CODE, ".env", ".json", ".yaml", ".yml", ".toml", ".sh", ".bash", ".zsh", ".ps1", ".vue", ".svelte", ".astro", ".tf", ".tfvars", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".swift", ".ipynb", ".properties", ".ini", ".cfg", ".conf", ".xml", ".gradle", ""],
    // A key header that ends right at a quote (or "...") is code looking for a key, e.g. key.includes('-----BEGIN PRIVATE KEY-----').
    test: (l) => { if (/\bplaceholder\s*[=:]/i.test(l)) return false; // a form's example text (placeholder="sk_live_...")
      const m = l.match(KEY_FORMATS) ?? l.match(MORE_KEYS);
      // Placeholders say so: xoxb-your-bot-token, ghp_...fake..., a PEM header followed by "...", or by prose
      // ("starts with -----BEGIN PRIVATE KEY----- and"). 0 of 7 sampled secret findings were real (0.3.9 review).
      return (!!m && !DOC_EXAMPLE.test(m[0]) && !/your[-_]|fake|dummy|placeholder|changeme|sample/.test(m[0]) /* lowercase words: real keys are random */
        && !/PRIVATE KEY( BLOCK)?-----(["'`]|\.\.\.|\\n\s*\.\.\.|\s+[a-zA-Z])/.test(l)) || serviceRoleJwt(l) || dbUrlWithPassword(l); },
    // Translation files mention "API key" and "secret" in every language, never a real key. Type definition files
    // carry documentation examples, and secret-scanner configs list known test keys on purpose (0.3.9 review).
    unlessPath: /(^|\/)(locales?|i18n|translations?|lang)\/|\.d\.ts$|(^|\/)(\.gitleaks\.toml|\.secrets\.baseline|\.trufflehog\.ya?ml)$/i,
    ...DRAFT,
  },
  {
    id: "transport.plain-http",
    title: "Data sent over plain HTTP",
    status: "partial", severity: "medium",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Use https:// for every external call.",
    note: "Marked Partial: the call may carry no sensitive data. Confirm, then switch to HTTPS anyway.",
    extensions: CODE,
    // Loopback, private ranges and single-label service names (http://redis:6379) stay on the machine or network (field test).
    test: (l) => /\b(fetch|axios\.\w+|requests\.\w+|http\.(get|request))\s*\(\s*["'`]http:\/\/(?!localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|\[::1\]|host\.docker\.internal)[\w-]+\.[\w.-]+/.test(l),
    ...DRAFT,
  },
  {
    id: "pii.to-analytics",
    title: "Personal data sent to an analytics or tracking tool",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 5(1)(c)", title: "Data minimisation" },
    ],
    fix: "Send an internal user ID instead of the email or name. If personal data must go there, list the tool as a processor.",
    note: "Analytics vendors keep what you send them. Personal data there needs a lawful basis and a processing agreement.",
    extensions: CODE,
    test: (l) => /\b(posthog|analytics|mixpanel|amplitude|segment|heap|gtag|ga|intercom|hotjar|sentry)\.(identify|track|capture|people\.set|setUser|setUserProperties|register)\s*\(/i.test(l) && PII.test(l),
    ...DRAFT,
  },
  {
    id: "pii.in-url",
    title: "Personal data or tokens in a URL",
    status: "partial", severity: "medium",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Send it in the request body or a header instead of the query string.",
    note: "URLs end up in server logs, browser history and referrer headers. Marked Partial: confirm the value is real personal data.",
    extensions: CODE,
    // OAuth and vendor APIs require tokens in some URLs; a sampled token param was never a real problem (0.3.9 labels).
    // Placeholders ([YOUR-PASSWORD], {email}) and localhost examples are documentation.
    test: (l) => /["'`][^"'`]*[?&](e-?mail|phone|ssn|api_?key|password)=(?![[{<]|\$\{?[A-Z_]+\}?["'`&])/i.test(l) && !/localhost|127\.0\.0\.1/.test(l),
    ...DRAFT,
  },
  {
    id: "crypto.weak-password-hash",
    title: "Passwords hashed with a weak or fast algorithm",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Use a password hashing function made for it: argon2id, scrypt or bcrypt.",
    note: "MD5 and SHA-1 are fast, so leaked hashes can be cracked quickly.",
    extensions: CODE,
    // Sentences in strings ("the server asked for an MD5 password hash") are messages, not hashing (field test).
    // The hash must be applied to a password. HMAC, HTTP Digest and fixed vendor formats require the algorithm;
    // they don't store passwords (field test, 139 repos).
    test: (l) => { const c = l.replace(/(["'`])(?:(?!\1)\S)*\s(?:(?!\1).)*\1/g, '""');
      return /\b(md5|sha1)\b[^;\n]{0,60}\bpass(word|wd)?\b/i.test(c) && !/hmac|digest\s*(auth|access)|\brealm\b|\bnonce\b|cookie/i.test(c); },
    ...DRAFT,
  },
  {
    id: "transport.tls-verify-off",
    title: "TLS certificate checks turned off",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Remove the override and trust a proper certificate. For self-signed certs in tests, scope it to the test only.",
    note: "With checks off, anyone on the network path can read or change the traffic.",
    extensions: [...CODE, ".env"],
    test: (l) => /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|\b(requests|httpx|session|client|Client|AsyncClient|urlopen)\b.*\bverify\s*=\s*False|InsecureSkipVerify\s*:\s*true|verify_mode\s*=\s*ssl\.CERT_NONE|cert_reqs\s*=\s*ssl\.CERT_NONE/.test(l), // naming CERT_NONE in a settings map isn't switching it on
    ...DRAFT,
  },
  {
    id: "sql.string-built",
    title: "SQL query built from strings",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Use parameterized queries or your ORM's query builder. If the inserted value is fixed text from your own code, confirm it can never come from a user.",
    note: "String-built SQL can let an attacker read or change your data (SQL injection). Marked Gap when the inserted value looks like user input, Partial when it may be fixed text from your code.",
    extensions: CODE,
    test: (l) => {
      // SQL keywords are written in UPPER or lower case; "Select a plan from..." in a sentence is not SQL.
      // A keyword after a dot or before "(" is a method call (hash.update(...), select(Model) in SQLAlchemy), not SQL text.
      // A statement's shape: SELECT ... FROM, INSERT INTO, UPDATE x SET, DELETE FROM. "Could not update user ${id} from ..." is a message.
      if (!/(?<![.\w])(SELECT\b(?!\s*\()[^"'`]*\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w."`${}]+\s+SET\b|DELETE\s+FROM\b)/i.test(l)) return false;
      if (/\b(throw|Error|message|msg)\b/.test(l) && !/\.(query|execute|exec|raw|run|prepare|all|get)\s*\(/.test(l)) return false;
      const parts = [...l.matchAll(SQL_PARTS)].map((m) => m.slice(1).find(Boolean) ?? "");
      if (!parts.length) return false;
      if (parts.some((p) => USER_INPUT.test(p))) return true;
      // Table and column names, placeholder lists and CONSTANTS are your own text, not values (field test, 139 repos).
      return parts.every((p) => /^\s*([A-Z][A-Z0-9_]*|[\w.]*(table|Table|TABLE|column|Column|cols|fields|placeholders?|Placeholders|schema|Schema|alias|orderBy|sortField|direction)\w*)\s*$/.test(p)) ? false : "partial";
    },
    // Tagged templates from Postgres.js, Drizzle, Prisma and similar send ${} values as parameters, not as SQL text (field test).
    unlessNear: /(?<![.\w])(sql|safeSql|tx|Prisma\.sql)(<[^>`]*>)?\s*`|\$queryRaw\s*`/,
    // Migrations are schema text the team writes and runs once; 6 of 24 sampled false alarms were migrations (0.3.9).
    unlessPath: /(^|\/)(migrations?|alembic\/versions)\//,
    ...DRAFT,
  },
  {
    id: "cors.any-origin",
    title: "API open to any website, with cookies or credentials",
    status: "partial", severity: "high",
    controls: [
    ],
    fix: "List the exact origins that may call the API. Never combine an open or reflected origin with credentials.",
    note: "Any website can then make logged-in requests on your users' behalf and read the answers. An open origin without credentials is fine for a public API and is not reported (as in CodeQL's CORS check). Marked Partial: confirm the endpoint returns private data.",
    extensions: CODE,
    // Only the dangerous pairing: an open or reflected origin plus credentials in the same config (0 of 19 sampled
    // open-origin findings without credentials were real, 0.3.9 labels).
    fileTest: (lines) => lines.flatMap((l, i) => {
      if (!/Access-Control-Allow-Origin["']?\s*[,:]\s*(["']\*["']|[\w.]*(req|request)\.headers?(\.get\(|\[|\.)\s*["']?origin)|origin\s*:\s*(["']\*["']|true\b|[\w.]*(req|request)\.headers?\.origin)|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']|allow_origin_regex\s*=\s*["']\.\*/.test(l)) return [];
      const near = lines.slice(Math.max(0, i - 12), i + 13).join("\n");
      return /credentials["']?\s*[:=,]\s*["']?true|Allow-Credentials["']?\s*[,:]\s*["']?true|CORS_ALLOW_CREDENTIALS\s*=\s*True|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True/i.test(near) ? [i + 1] : [];
    }),
    unlessPath: /(^|\/)(vite|webpack|rollup|next|nuxt|astro)\.config\.|openapi|swagger/i, // dev servers and published API specs (field test)
    ...DRAFT,
  },
  {
    id: "session.cookie-insecure",
    title: "Session cookie without Secure or HttpOnly",
    status: "partial", severity: "low",
    controls: [
    ],
    fix: "Set secure: true and httpOnly: true on session cookies.",
    note: "Without these flags a session cookie can be read by scripts or sent over plain HTTP. Marked Partial: confirm it is a session cookie.",
    extensions: CODE,
    // A bare `secure: false` is usually a client, proxy or database option: it counts only near a cookie being set
    // (0.3.9 labels: 9 of 14 false alarms had no cookie in sight). CSRF cookies are meant to be readable by scripts.
    fileTest: (lines) => lines.flatMap((l, i) => {
      if (!/\b(httpOnly|secure)\s*:\s*false\b|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False/.test(l)) return [];
      const near = lines.slice(Math.max(0, i - 6), i + 4).join("\n");
      return /\b(res|response|reply|ctx|cookies?)\.(cookie|set|setCookie)\s*\(|Set-Cookie|\bcookie\s*:\s*\{|cookieOptions|serialize\(|SESSION_COOKIE/i.test(near)
        && !/csrf|xsrf/i.test(near) && !/\b(smtp|createTransport|nodemailer|ignoreTLS|requireTLS)\b/i.test(near) ? [i + 1] : [];
    }),
    ...DRAFT,
  },
  {
    id: "config.debug-on",
    title: "Debug mode switched on in code",
    status: "partial", severity: "medium",
    controls: [
    ],
    fix: "Read debug from an environment variable that is off in production.",
    note: "Debug pages can show stack traces, settings and secrets. Marked Partial: it may only run locally.",
    extensions: CODE,
    test: (l) => /^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True/.test(l),
    ...DRAFT,
  },
];

// --- EU AI Act -------------------------------------------------------------
// Code can show *signals* for the AI Act, not the legal risk tier itself. These rules
// flag what an auditor would ask about; the Classifier and the user decide the tier.

// How apps call models in practice (field test, 18 repos): SDK clients under any name, Gemini's generateContent,
// the Vercel AI SDK, LangChain chains, and plain fetch calls to the provider's API. supabase.functions.invoke is not AI.
const AI_CALL = new RegExp([
  /\b(openai|anthropic|client)\.(chat\.completions|responses|messages|completions)\.create\s*\(/.source,
  /\b\w+\.chat\.completions\.create\s*\(/.source,
  /\.generateContent(Stream)?\s*\(/.source,
  /\b(generateText|streamText|generateObject|streamObject)\s*\(/.source,
  /\b(model|clf|classifier|pipeline)\.(predict|predict_proba|invoke|generate)\s*\(/.source,
  /\b(chain|llm|chatModel|agent|runnable)\w*\.(invoke|stream|batch)\s*\(/.source,
  // A provider URL counts only inside a request call, not where it's stored in a constant.
  /\b(fetch|axios(\.\w+)?|requests\.\w+|httpx\.\w+|ky(\.\w+)?)\s*\(\s*[`"'][^`"']*(api\.openai\.com\/v1\/(chat|responses|completions|images|audio)|api\.anthropic\.com\/v1\/messages|generativelanguage\.googleapis\.com|openrouter\.ai\/api|api\.groq\.com|api\.mistral\.ai|api\.deepseek\.com)/.source,
].join("|"), "i");
const NOT_AI = /\bfunctions\.invoke\s*\(/;
export const isAiCall = (l: string) => AI_CALL.test(l) && !NOT_AI.test(l);
/** The first AI call in a file with no log or save between 10 lines above and 30 below (one finding per file). Pure. */
export const unloggedAiCalls = (lines: string[]) => {
  const i = lines.findIndex((l, i) => isAiCall(l) && !lines.slice(Math.max(0, i - 10), i + 31).some((x) => LOGGED.test(x)));
  return i < 0 ? [] : [i + 1];
};
// Image, voice and video models. "flux" alone is left out: Deepgram uses it for speech-to-text.
const MEDIA_MODEL = /["'`](dall-e-\d|gpt-image-[\w.]+|imagen-[\w.-]+|gemini-[\w.-]*-image[\w.-]*|tts-1[\w-]*|gpt-4o[\w-]*-tts|veo-[\w.-]+|sora-[\w.-]+|eleven_[\w]+|black-forest-labs\/flux[\w./-]*|stable-diffusion[\w./-]*)["'`]/i;
/** AI calls in a file that names an image, voice or video model. Pure. */
export const mediaModelCalls = (lines: string[]) =>
  lines.some((l) => MEDIA_MODEL.test(l)) ? lines.flatMap((l, i) => (isAiCall(l) ? [i + 1] : [])) : [];
// Whole words only: "banner" is not "ban" (field test, 139 repos).
// Letters may not touch the word, but underscores may: loan_denied counts, banner doesn't.
const DECISION = /(?<![a-z])(approve[ds]?|approval|reject(ed|ion)?|deny|denied|decline[ds]?|eligib(le|ility)|hire[ds]?|hiring|shortlist(ed)?|credit[_ ]?(score|limit|decision)|loan|underwrit[a-z]*|admit(ted)?|admission|ban(ned)?|suspend(ed)?)(?![a-z])/i;
const LOGGED = /\b(logger|log|logging|audit|auditLog|console)\.\w+\s*\(|\binsert\w*\s*\(|\.save\s*\(/;

rules.push(
  {
    id: "ai.automated-decision",
    title: "AI makes a decision about a person with no human check in the code",
    status: "partial", severity: "high",
    controls: [
      { framework: "eu-ai-act", id: "Art. 14", title: "Human oversight" },
      { framework: "gdpr", id: "Art. 22", title: "Automated individual decisions" },
    ],
    fix: "Route the result to a review step where a person can confirm or override it, and record who did.",
    note: "Credit, hiring, admission and similar decisions about people are high-risk under Annex III. Marked Partial: a review step may exist elsewhere.",
    extensions: CODE,
    // A model's output and a decision word on the same line, e.g. status = model.predict(x) > 0.5 ? "approved" : "rejected".
    // score() and invoke() are too generic: a music score, a memory ranking (field test).
    test: (l) => /\b(predict|predict_proba|classify|generateText|generateObject)\w*\s*\(|\.chat\.completions\.create\s*\(/.test(l) && DECISION.test(l),
    ...DRAFT,
  },
  {
    id: "ai.call-not-logged",
    title: "AI call with no record kept near it",
    status: "partial", severity: "medium",
    controls: [
      { framework: "eu-ai-act", id: "Art. 12", title: "Record-keeping" },
    ],
    fix: "Log each AI call: time, model and version, input reference and output, without raw personal data.",
    note: "High-risk systems must keep logs that let you trace what the AI did. Marked Partial: logging may happen in a wrapper or another file.",
    extensions: CODE,
    fileTest: unloggedAiCalls,
    // Examples, docs and the provider adapters inside AI libraries aren't where an app keeps its records (field test, 50 repos).
    unlessPath: /(^|\/)(examples?|samples?|cookbooks?|docs?|libs)\/|(^|\/)(providers?|adapters?|llms?|model-runtime|integrations)\//i,
    ...DRAFT,
  },
  {
    id: "ai.hides-being-ai",
    title: "AI told to hide that it is an AI",
    status: "partial", severity: "high",
    controls: [{ framework: "eu-ai-act", id: "Art. 50(1)", title: "Transparency for AI interacting with people" }],
    fix: "Remove the instruction and tell users they are talking to an AI.",
    note: "People must be told when they interact with an AI system, unless it is obvious. Marked Partial: role-play wording can be harmless.",
    extensions: [...CODE, ".md", ".txt", ".yaml", ".yml", ".json"],
    unlessPath: /(^|\/)(README|CHANGELOG|CONTRIBUTING|SECURITY|LICENSE)[^/]*$|(^|\/)docs?\//i, // text about the rule, not a prompt
    // "Act as a human resources advisor" is a job title, not a disguise.
    test: (l) => /\b(pretend|act|behave|pose)\s+(to\s+be\s+|as\s+|like\s+)(a\s+)?(real\s+)?(human|person)\b(?!\s+(resources?|readable|reviewer))|\bnever\s+(say|reveal|mention|admit|disclose)\b.{0,40}\b(ai|a\.i\.|bot|language model|assistant)\b/i.test(l),
    ...DRAFT,
  },
  {
    id: "ai.synthetic-media",
    title: "AI-generated images, audio or video",
    status: "partial", severity: "medium",
    controls: [{ framework: "eu-ai-act", id: "Art. 50(2)", title: "Marking AI-generated content" }],
    fix: "Mark generated media as AI-made in a machine-readable way (for example C2PA metadata) and label deepfakes for viewers.",
    note: "Marked Partial: you may already add marking after this call. Confirm it does.",
    extensions: CODE,
    test: (l) => /\bimages\.(generate|edit)\s*\(|\baudio\.speech\.create\s*\(|\b(textToSpeech|text_to_speech|generateImage|generate_image|generateVideo|generate_video)\s*\(|\b(StableDiffusion\w*|DiffusionPipeline)\b/.test(l),
    // Also: a generic AI call (e.g. generateContent) in a file that names an image, voice or video model.
    fileTest: mediaModelCalls,
    ...DRAFT,
  },
  {
    id: "ai.emotion-or-biometric",
    title: "Emotion recognition or biometric categorisation",
    status: "partial", severity: "high",
    controls: [
      { framework: "eu-ai-act", id: "Art. 5(1)(f)", title: "Prohibited: emotion recognition at work and in education" },
      { framework: "eu-ai-act", id: "Annex III(1)", title: "High-risk: biometrics" },
      { framework: "gdpr", id: "Art. 9", title: "Special categories of personal data" },
    ],
    fix: "Check whether this use is banned or high-risk before shipping. Remove it if it infers emotions of staff or students.",
    note: "Some uses are banned outright since February 2025 (emotion recognition at work or in education); others are high-risk. Marked Partial: whether a ban applies depends on whose data is analysed and where, which code can't show.",
    extensions: CODE,
    test: (l) => /\b(detect|recogni[sz]e|analy[sz]e|infer|predict)\w*_?(emotion|sentiment_from_face|facial_expression)|\bemotion(s)?\s*[:=]\s*\w*\.(detect|analy)|\bDeepFace\.analyze\s*\(|\bdetect_faces?\b.*\bemotion|\b(face_recognition|FaceAttributes|DetectFaces)\b/i.test(l),
    ...DRAFT,
  },
);

// OWASP Top 10:2025: map the rules above, then add the OWASP rules.
for (const r of rules) r.controls.push(...(owaspForExisting[r.id] ?? []));
rules.push(...owaspRules);
// Supabase, Next.js and Vite: open databases and secrets reaching the browser.
rules.push(...stackRules);
for (const r of rules) r.controls.push(...(craForExisting[r.id] ?? []));
rules.push(...craRules);
rules.push(...standardsRules);
// After the push, so the new LLM rules also get their CWE tags.
for (const r of rules) r.controls.push(...(standardsForExisting[r.id] ?? []));

// Measured on 270 findings reviewed one by one from 139 public repositories (0.3.9). These rules were real in fewer than
// half of their sampled findings, so they are held back unless --all (show: all) is set, and the report says how many.
// A rule moves back to high confidence when a fresh labelled sample shows it is real in most findings.
const MEDIUM_CONFIDENCE = new Set(["xss.raw-html", "error.empty-catch", "sql.string-built", "code.eval", "cmd.shell-built",
  "ai.call-not-logged", "llm.no-output-limit", "pii.in-url", "html.script-no-sri", "ai.synthetic-media", "session.cookie-insecure",
  // One real or fewer in their labelled samples (5 to 6 findings each): small samples, so these are re-measured each release.
  "jwt.unverified", "jwt.no-expiry", "mass-assignment", "transport.tls-verify-off", "crypto.weak-cipher", "crypto.weak-random-token",
  "ci.script-injection", "log.injection", "log.secret", "auth.hardcoded-password", "mobile.cleartext-traffic", "config.debug-on",
  "mobile.token-in-plain-storage",
  // 0 of 7 real in the 0.3.9 review: the data was the app's own database, cache or worker pipe.
  "deserialize.unsafe",
  // Reworked in 0.3.9 to need credentials; not yet measured on a fresh sample.
  "cors.any-origin"]);
for (const r of rules) if (MEDIUM_CONFIDENCE.has(r.id)) r.confidence = "medium";
