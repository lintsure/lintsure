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
