// Before code is written: which Lintsure checks a planned feature is likely to meet, so the agent can avoid them.
// Plain word matching against what each rule is about, plus a few feature words. No model, same answer every time.
import { rules } from "./rules/index.js";
import type { Rule } from "./types.js";

// Feature words people use, mapped to the rule id parts they usually lead to.
const TOPICS: [RegExp, string[]][] = [
  [/\b(log ?in|sign ?(in|up)|auth\w*|password|session|account|oauth|sso)\b/i, ["session", "jwt", "password", "csrf", "cookie", "redirect", "secret"]],
  [/\b(upload\w*|files?|images?|attachments?|download\w*)\b/i, ["upload", "path"]],
  [/\b(pay\w*|stripe|checkout|billing|cards?|invoices?)\b/i, ["secret", "webhook", "transport", "pii"]],
  [/\b(ai|llm|gpt|claude|chat\w*|prompts?|agents?|openai|anthropic|model)\b/i, ["ai", "llm"]],
  [/\b(databases?|sql|quer\w*|supabase|postgres|tables?|prisma|mongo\w*)\b/i, ["sql", "supabase", "nosql", "mass"]],
  [/\b(users?|profiles?|emails?|personal|customers?|analytics|tracking|gdpr)\b/i, ["pii", "gdpr"]],
  [/\b(webhooks?|fetch\w*|urls?|proxy|crawl\w*|scrap\w*|preview)\b/i, ["ssrf", "transport", "redirect"]],
  [/\b(api|endpoints?|routes?|server|backend|handlers?)\b/i, ["cors", "error", "sql", "mass", "config"]],
  [/\b(shell|commands?|exec\w*|scripts?|cli|deploy\w*|ci|github actions?|workflows?)\b/i, ["cmd", "ci", "deps", "code"]],
  [/\b(hooks?|mcp|cursor|claude code|agent config)\b/i, ["agent"]],
  [/\b(env\w*|keys?|secrets?|tokens?|config\w*)\b/i, ["secret", "release", "config"]],
  [/\b(html|render\w*|templates?|markdown|comments?|rich text)\b/i, ["xss", "template"]],
  [/\b(mobile|android|ios|react native|expo)\b/i, ["mobile"]],
];
const STOP = new Set(["with", "that", "this", "from", "into", "user", "users", "make", "build", "want", "need", "should", "will", "page", "feature", "add", "new", "the", "and", "for", "mode", "toggle", "button", "show", "list", "screen", "simple", "dark", "light"]);

/** The rules a described feature most likely runs into, best match first. Pure. */
export function checksFor(description: string, max = 8): Rule[] {
  const text = description.slice(0, 2000);
  const parts = new Set(TOPICS.filter(([re]) => re.test(text)).flatMap(([, p]) => p));
  const words = new Set((text.toLowerCase().match(/[a-z]{4,}/g) ?? []).filter((w) => !STOP.has(w)));
  const scored = rules.map((r) => {
    const idParts = r.id.split(/[.-]/);
    let s = idParts.some((p) => parts.has(p)) ? 3 : 0;
    for (const w of new Set(`${r.title} ${r.id}`.toLowerCase().match(/[a-z]{4,}/g) ?? [])) if (words.has(w)) s += 2;
    return { r, s: s + (s && r.severity === "high" ? 1 : 0) };
  });
  return scored.filter((x) => x.s > 0).sort((a, b) => b.s - a.s || a.r.id.localeCompare(b.r.id)).slice(0, max).map((x) => x.r);
}
