// v0 rule set. Pattern-based, deterministic, no network. Each rule maps to every
// framework it touches. Mappings are a first draft: the auditor must review each
// one (mappedBy / reviewedAt) before a framework leaves Beta.
import type { Rule } from "../types.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"];
// Beta: mapped by us, awaiting review by a qualified compliance professional.
const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };

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

// --- EU AI Act -------------------------------------------------------------
// Code can show *signals* for the AI Act, not the legal risk tier itself. These rules
// flag what an auditor would ask about; the Classifier and the user decide the tier.

const AI_CALL = /\b(openai|anthropic|client)\.(chat\.completions|responses|messages|completions)\.create\s*\(|\bgenerateText\s*\(|\bstreamText\s*\(|\b(model|clf|classifier|pipeline)\.(predict|predict_proba|invoke|generate)\s*\(/;
const DECISION = /\b(approv|reject|deny|denied|declin|eligib|hire|hiring|shortlist|credit|loan|underwrit|admit|admission|ban|suspend)\w*/i;
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
    test: (l) => /\b(predict|predict_proba|score|classify|completion|generateText|invoke)\w*\s*\(/.test(l) && DECISION.test(l),
    ...DRAFT,
  },
  {
    id: "ai.call-not-logged",
    title: "AI call with no record kept in this file",
    status: "partial", severity: "medium",
    controls: [
      { framework: "eu-ai-act", id: "Art. 12", title: "Record-keeping" },
      { framework: "soc2", id: "CC7.2", title: "Monitoring of system components" },
    ],
    fix: "Log each AI call: time, model and version, input reference and output, without raw personal data.",
    note: "High-risk systems must keep logs that let you trace what the AI did. Marked Partial: logging may happen in another file.",
    extensions: CODE,
    fileTest: (lines) => lines.some((l) => LOGGED.test(l)) ? [] : lines.flatMap((l, i) => (AI_CALL.test(l) ? [i + 1] : [])),
    ...DRAFT,
  },
  {
    id: "ai.hides-being-ai",
    title: "AI told to hide that it is an AI",
    status: "gap", severity: "high",
    controls: [{ framework: "eu-ai-act", id: "Art. 50(1)", title: "Transparency for AI interacting with people" }],
    fix: "Remove the instruction and tell users they are talking to an AI.",
    note: "People must be told when they interact with an AI system, unless it is obvious.",
    extensions: [...CODE, ".md", ".txt", ".yaml", ".yml", ".json"],
    test: (l) => /\b(pretend|act|behave|pose)\s+(to\s+be\s+|as\s+|like\s+)(a\s+)?(real\s+)?(human|person)\b|\bnever\s+(say|reveal|mention|admit|disclose)\b.{0,40}\b(ai|a\.i\.|bot|language model|assistant)\b/i.test(l),
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
    ...DRAFT,
  },
  {
    id: "ai.emotion-or-biometric",
    title: "Emotion recognition or biometric categorisation",
    status: "gap", severity: "high",
    controls: [
      { framework: "eu-ai-act", id: "Art. 5(1)(f)", title: "Prohibited: emotion recognition at work and in education" },
      { framework: "eu-ai-act", id: "Annex III(1)", title: "High-risk: biometrics" },
      { framework: "gdpr", id: "Art. 9", title: "Special categories of personal data" },
    ],
    fix: "Check whether this use is banned or high-risk before shipping. Remove it if it infers emotions of staff or students.",
    note: "Some uses are banned outright since February 2025. Others are high-risk. This needs a human decision, not a code fix.",
    extensions: CODE,
    test: (l) => /\b(detect|recogni[sz]e|analy[sz]e|infer|predict)\w*_?(emotion|sentiment_from_face|facial_expression)|\bemotion(s)?\s*[:=]\s*\w*\.(detect|analy)|\bDeepFace\.analyze\s*\(|\bdetect_faces?\b.*\bemotion|\b(face_recognition|FaceAttributes|DetectFaces)\b/i.test(l),
    ...DRAFT,
  },
);

