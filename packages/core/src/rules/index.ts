// v0 rule set. Pattern-based, deterministic, no network. Each rule maps to every
// framework it touches. Mappings are a first draft: the auditor must review each
// one (mappedBy / reviewedAt) before a framework is called "Available".
import type { OutsideItem, Rule } from "../types.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"];
const DRAFT = { mappedBy: "draft", reviewedAt: "pending" };

const LOG_CALL = /\b(console\.(log|info|warn|error|debug)|logger\.\w+|log\.(info|warn|error|debug)|logging\.\w+|print)\s*\(/;
const PII = /\b(e-?mail|phone|ssn|social_?security|passport|date_?of_?birth|dob|password|passwd|credit_?card|card_?number|iban)\b/i;

export const rules: Rule[] = [
  {
    id: "pii.logged",
    title: "Personal data written to logs",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
      { framework: "soc2", id: "CC6.1", title: "Logical access security" },
      { framework: "iso-27001", id: "A.8.11", title: "Data masking" },
    ],
    fix: "Mask or remove the personal field before logging, for example mask(user.email).",
    note: "Logs are copied to many places and kept for a long time. Personal data in them is hard to find and delete.",
    extensions: CODE,
    test: (l) => LOG_CALL.test(l) && PII.test(l),
    ...DRAFT,
  },
  {
    id: "secret.in-source",
    title: "Secret or private key committed to source",
    status: "gap", severity: "high",
    controls: [
      { framework: "soc2", id: "CC6.1", title: "Logical access security" },
      { framework: "iso-27001", id: "A.8.24", title: "Use of cryptography" },
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Move the secret to an environment variable or secrets manager, then rotate it: it is already in your git history.",
    note: "Anyone with read access to the repo, or a leaked copy of it, can use this key.",
    extensions: [...CODE, ".env", ".json", ".yaml", ".yml", ".toml"],
    test: (l) => /(sk_live_[0-9a-zA-Z]{10,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{30,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)/.test(l),
    ...DRAFT,
  },
  {
    id: "transport.plain-http",
    title: "Data sent over plain HTTP",
    status: "partial", severity: "medium",
    controls: [
      { framework: "soc2", id: "CC6.7", title: "Transmission of data" },
      { framework: "iso-27001", id: "A.8.20", title: "Network security" },
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Use https:// for every external call.",
    note: "Marked Partial: the call may carry no sensitive data. Confirm, then switch to HTTPS anyway.",
    extensions: CODE,
    test: (l) => /\b(fetch|axios\.\w+|requests\.\w+|http\.(get|request))\s*\(\s*["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(l),
    ...DRAFT,
  },
  {
    id: "pii.to-analytics",
    title: "Personal data sent to an analytics or tracking tool",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 5(1)(c)", title: "Data minimisation" },
      { framework: "gdpr", id: "Art. 28", title: "Processors" },
      { framework: "soc2", id: "P6.1", title: "Disclosure to third parties" },
      { framework: "iso-27001", id: "A.5.34", title: "Privacy and protection of PII" },
    ],
    fix: "Send an internal user ID instead of the email or name, and list the tool as a processor.",
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
      { framework: "soc2", id: "CC6.1", title: "Logical access security" },
      { framework: "iso-27001", id: "A.8.11", title: "Data masking" },
    ],
    fix: "Send it in the request body or a header instead of the query string.",
    note: "URLs end up in server logs, browser history and referrer headers. Marked Partial: confirm the value is real personal data.",
    extensions: CODE,
    test: (l) => /["'`][^"'`]*[?&](e-?mail|phone|ssn|token|api_?key|password|access_token)=/i.test(l),
    ...DRAFT,
  },
  {
    id: "crypto.weak-password-hash",
    title: "Passwords hashed with a weak or fast algorithm",
    status: "gap", severity: "high",
    controls: [
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
      { framework: "soc2", id: "CC6.1", title: "Logical access security" },
      { framework: "iso-27001", id: "A.8.24", title: "Use of cryptography" },
    ],
    fix: "Use a password hashing function made for it: argon2id, scrypt or bcrypt.",
    note: "MD5 and SHA-1 are fast, so leaked hashes can be cracked quickly.",
    extensions: CODE,
    test: (l) => /\b(md5|sha1)\b/i.test(l) && /pass(word|wd)?/i.test(l),
    ...DRAFT,
  },
  {
    id: "transport.tls-verify-off",
    title: "TLS certificate checks turned off",
    status: "gap", severity: "high",
    controls: [
      { framework: "soc2", id: "CC6.7", title: "Transmission of data" },
      { framework: "iso-27001", id: "A.8.20", title: "Network security" },
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Remove the override and trust a proper certificate. For self-signed certs in tests, scope it to the test only.",
    note: "With checks off, anyone on the network path can read or change the traffic.",
    extensions: [...CODE, ".env"],
    test: (l) => /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CERT_NONE/.test(l),
    ...DRAFT,
  },
  {
    id: "sql.string-built",
    title: "SQL query built from strings",
    status: "gap", severity: "high",
    controls: [
      { framework: "soc2", id: "CC7.1", title: "Detect and fix vulnerabilities" },
      { framework: "iso-27001", id: "A.8.28", title: "Secure coding" },
      { framework: "gdpr", id: "Art. 32", title: "Security of processing" },
    ],
    fix: "Use parameterized queries or your ORM's query builder.",
    note: "String-built SQL can let an attacker read or change your data (SQL injection).",
    extensions: CODE,
    test: (l) => /\b(SELECT|INSERT|UPDATE|DELETE)\b[^"'`]*\b(FROM|INTO|SET|WHERE)\b/i.test(l) && /(\$\{|["']\s*\+\s*\w|\bf["'][^"']*\{|%s["']\s*%|\.format\()/.test(l),
    ...DRAFT,
  },
  {
    id: "cors.any-origin",
    title: "API open to requests from any website",
    status: "partial", severity: "medium",
    controls: [
      { framework: "soc2", id: "CC6.6", title: "Boundary protection" },
      { framework: "iso-27001", id: "A.8.20", title: "Network security" },
    ],
    fix: "List the exact origins that may call the API.",
    note: "Marked Partial: fine for a public, read-only API. Risky when the API uses cookies or returns user data.",
    extensions: CODE,
    test: (l) => /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|origin\s*:\s*(["']\*["']|true\b)|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["']/.test(l),
    ...DRAFT,
  },
  {
    id: "session.cookie-insecure",
    title: "Session cookie without Secure or HttpOnly",
    status: "partial", severity: "medium",
    controls: [
      { framework: "soc2", id: "CC6.1", title: "Logical access security" },
      { framework: "iso-27001", id: "A.8.5", title: "Secure authentication" },
    ],
    fix: "Set secure: true and httpOnly: true on session cookies.",
    note: "Without these flags a session cookie can be read by scripts or sent over plain HTTP. Marked Partial: confirm it is a session cookie.",
    extensions: CODE,
    test: (l) => /\b(httpOnly|secure)\s*:\s*false\b|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False/.test(l),
    ...DRAFT,
  },
  {
    id: "config.debug-on",
    title: "Debug mode switched on in code",
    status: "partial", severity: "medium",
    controls: [
      { framework: "soc2", id: "CC8.1", title: "Change management" },
      { framework: "iso-27001", id: "A.8.9", title: "Configuration management" },
    ],
    fix: "Read debug from an environment variable that is off in production.",
    note: "Debug pages can show stack traces, settings and secrets. Marked Partial: it may only run locally.",
    extensions: CODE,
    test: (l) => /^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True/.test(l),
    ...DRAFT,
  },
];

// What code can't prove. The Officer lists these as "Outside code".
export const outside: OutsideItem[] = [
  { framework: "gdpr", control: "Art. 30", title: "Records of processing activities", evidence: "A written register of what personal data you process and why." },
  { framework: "gdpr", control: "Art. 28", title: "Agreements with processors", evidence: "Signed data processing agreements with each vendor that handles personal data." },
  { framework: "soc2", control: "CC6.2", title: "Access reviews", evidence: "A dated record of who has access, reviewed each quarter." },
  { framework: "soc2", control: "CC1.4", title: "Security training", evidence: "Training records for everyone with access to systems." },
  { framework: "iso-27001", control: "A.5.20", title: "Supplier security agreements", evidence: "Security terms in supplier contracts." },
  { framework: "iso-27001", control: "A.6.3", title: "Awareness and training", evidence: "Training plan and completion records." },
  { framework: "eu-ai-act", control: "Art. 9", title: "Risk management system", evidence: "A documented, maintained AI risk management process." },
  { framework: "eu-ai-act", control: "Art. 11", title: "Technical documentation", evidence: "Technical documentation of the AI system, per Annex IV." },
];
