import type { FrameworkKnowledge } from "./types.js";

// Own-words summaries. OWASP texts are CC BY-SA 4.0: we reference IDs and names only.
// Not affiliated with or endorsed by OWASP or MITRE.

export const owaspLlm: FrameworkKnowledge = {
  id: "owasp-llm", name: "OWASP Top 10 for LLM Applications 2025", kind: "standard",
  summary: "The ten most serious security risks in apps built on large language models: prompt injection, leaking sensitive data, supply chain, poisoned data, unsafe use of model output, too much agency, system prompt leakage, weak vector stores, misinformation and runaway usage. It's an awareness list, not a law or certification.",
  whoItAppliesTo: "Any team that builds a feature on an AI model: chatbots, assistants, agents, retrieval (RAG) and AI features inside other apps.",
  applies(p) {
    if (p.usesAI && (p.generativeAI || p.interactsWithPeople)) return "Your product sends text to an AI model and shows or acts on what comes back, so the common LLM risks apply.";
    return null;
  },
  obligations: [
    { ref: "LLM01:2025", title: "Prompt Injection", inCode: "partly", rules: ["llm.user-input-in-system-prompt"],
      plain: "User text, web pages or files can carry instructions that change what the model does. Keep instructions and user content apart, and limit what the model can do.",
      evidence: "How prompts are built, and tests with hostile input." },
    { ref: "LLM02:2025", title: "Sensitive Information Disclosure", inCode: "partly", rules: ["secret.in-source", "secret.public-env", "pii.logged", "log.secret"],
      plain: "Keys, personal data and internal details must not reach the model, its logs or its answers unless they're meant to.",
      evidence: "What data is sent to the model provider, and the provider's data retention terms." },
    { ref: "LLM03:2025", title: "Supply Chain", inCode: "partly", rules: ["deps.unpinned-version", "deps.install-script"],
      plain: "Models, datasets, plugins and packages come from others. Pin and check them like any dependency.",
      evidence: "Where each model and dataset comes from, and its licence." },
    { ref: "LLM04:2025", title: "Data and Model Poisoning", inCode: "no",
      plain: "Training, fine-tuning or retrieval data can be tampered with to change the model's behaviour.",
      evidence: "Data sources, who can change them, and checks on new data." },
    { ref: "LLM05:2025", title: "Improper Output Handling", inCode: "yes", rules: ["llm.output-to-sink"],
      plain: "Treat what the model returns as untrusted. Never run it as code, a shell command or SQL, and escape it before showing it as HTML.",
      evidence: "How model output is validated before use." },
    { ref: "LLM06:2025", title: "Excessive Agency", inCode: "no",
      plain: "Tools and permissions given to an agent should be the minimum it needs, with a person approving anything risky.",
      evidence: "A list of the tools each agent can call and which need approval." },
    { ref: "LLM07:2025", title: "System Prompt Leakage", inCode: "partly", rules: ["llm.user-input-in-system-prompt"],
      plain: "Assume users can read the system prompt. Don't put secrets or access rules in it, and don't mix user text into it.",
      evidence: "System prompts reviewed for secrets and access logic." },
    { ref: "LLM08:2025", title: "Vector and Embedding Weaknesses", inCode: "no",
      plain: "Retrieval stores must keep one user's or customer's documents away from another's, and resist planted content.",
      evidence: "Access rules on the vector store and tests across two accounts." },
    { ref: "LLM09:2025", title: "Misinformation", inCode: "no",
      plain: "Models state wrong things confidently. Show sources, say it's AI and keep a person in the loop where it matters.",
      evidence: "How answers are checked and how users are told the limits." },
    { ref: "LLM10:2025", title: "Unbounded Consumption", inCode: "partly", rules: ["llm.no-output-limit", "ai.call-not-logged"],
      plain: "Limit output size, request rate and cost per user, so one person can't run up a bill or take the service down.",
      evidence: "Rate limits, spending alerts and usage monitoring." },
  ],
  watchOut: ["Prompt injection has no complete fix today. Reduce what a fooled model can do, rather than relying on filters alone.", "Lintsure reads one line or file at a time, so prompts built across several files may be missed."],
  checkedOn: "2026-11-09",
};

export const cweTop25: FrameworkKnowledge = {
  id: "cwe-top25", name: "CWE Top 25 (2025)", kind: "standard",
  summary: "MITRE's yearly list of the 25 most dangerous software weaknesses, ranked from real vulnerability data. Security teams, scanners and buyers use CWE numbers as a shared language, so mapping findings to them makes reports easy to compare.",
  whoItAppliesTo: "Anyone writing software. It's a reference list, not a law or certification.",
  applies(p) { return p.b2bCustomers || p.governmentCustomers ? "Security teams and buyers often ask how you handle the CWE Top 25." : null; },
  obligations: [
    { ref: "CWE-79, CWE-89, CWE-78, CWE-77, CWE-94", title: "Injection: scripting, SQL, commands and code", inCode: "yes", rules: ["xss.raw-html", "template.user-string", "sql.string-built", "cmd.shell-built", "code.eval", "llm.output-to-sink"], plain: "Input never becomes part of a page, query, command or code without the right handling." },
    { ref: "CWE-862, CWE-863, CWE-284, CWE-639", title: "Missing or broken authorization", inCode: "partly", rules: ["supabase.rls-disabled", "supabase.policy-allows-all", "supabase.service-key-in-client", "cookie.trusted-role", "fs.world-writable", "mass-assignment"], plain: "Every action and record is checked against what the user may do.", evidence: "Access tests between two accounts." },
    { ref: "CWE-352", title: "Cross-site request forgery", inCode: "yes", rules: ["csrf.disabled"], plain: "Other sites can't make a signed-in user's browser perform actions." },
    { ref: "CWE-22, CWE-434", title: "Path traversal and dangerous uploads", inCode: "yes", rules: ["path.user-input", "upload.unrestricted"], plain: "File paths and uploads are limited to what's expected." },
    { ref: "CWE-502, CWE-20", title: "Unsafe deserialization and input validation", inCode: "partly", rules: ["deserialize.unsafe", "nosql.operator-input", "mass-assignment"], plain: "Untrusted data is validated and never turned back into objects unsafely." },
    { ref: "CWE-918", title: "Server-side request forgery", inCode: "yes", rules: ["ssrf.user-url"], plain: "The server doesn't fetch any address a user picks." },
    { ref: "CWE-200", title: "Exposure of sensitive information", inCode: "partly", rules: ["pii.logged", "pii.in-url", "log.secret", "error.stack-to-client", "build.sourcemaps-public", "secret.public-env"], plain: "Personal data, secrets and internals don't leak into logs, URLs, errors or the browser." },
    { ref: "CWE-770", title: "Resources without limits", inCode: "partly", rules: ["llm.no-output-limit"], plain: "Expensive work, including AI calls, has limits.", evidence: "Rate limits and quotas." },
    { ref: "CWE-306", title: "Missing authentication for a critical function", inCode: "no", plain: "Every sensitive endpoint requires a signed-in user. Needs a route-by-route review.", evidence: "A list of endpoints and their authentication." },
    { ref: "CWE-787, 416, 125, 120, 476, 121, 122", title: "Memory safety", inCode: "no", plain: "Buffer and pointer errors in C and C++. Lintsure doesn't check these languages; use a memory-safe language or a dedicated tool.", evidence: "Results from a C/C++ analyser or fuzzing." },
  ],
  watchOut: ["The list ranks weaknesses by data from published vulnerabilities; it changes a little each year.", "Seven of the 25 are memory-safety weaknesses that don't apply to JavaScript, TypeScript or Python code."],
  checkedOn: "2026-11-09",
};

