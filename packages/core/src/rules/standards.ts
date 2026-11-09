// OWASP Top 10 for LLM Applications 2025, the 2025 CWE Top 25 (MITRE), and mobile app checks.
// Our own reading of the public texts; we cite IDs only. Beta.
import type { Control, Rule } from "../types.js";
import { isAiCall } from "./index.js";

const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const c = (framework: Control["framework"]) => (id: string, title: string): Control => ({ framework, id, title });
const LLM = c("owasp-llm"), CWE = c("cwe-top25");
const W = (n: number, title: string) => CWE(`CWE-${n}`, title);
const LLM01 = LLM("LLM01:2025", "Prompt Injection"), LLM02 = LLM("LLM02:2025", "Sensitive Information Disclosure"),
  LLM03 = LLM("LLM03:2025", "Supply Chain"), LLM05 = LLM("LLM05:2025", "Improper Output Handling"),
  LLM07 = LLM("LLM07:2025", "System Prompt Leakage"), LLM10 = LLM("LLM10:2025", "Unbounded Consumption");
const GDPR32: Control = { framework: "gdpr", id: "Art. 32", title: "Security of processing" };
const OW = (n: string, title: string): Control => ({ framework: "owasp-top10", id: `A${n}:2025`, title });
const A04 = OW("04", "Cryptographic Failures"), A06 = OW("06", "Insecure Design");

/** LLM and CWE controls for rules that already exist. Merged by id in rules/index.ts. */
export const standardsForExisting: Record<string, Control[]> = {
  "secret.in-source": [LLM02], "secret.public-env": [LLM02, W(200, "Exposure of Sensitive Information")], "pii.logged": [LLM02, W(200, "Exposure of Sensitive Information")],
  "log.secret": [LLM02, W(200, "Exposure of Sensitive Information")], "deps.unpinned-version": [LLM03], "deps.install-script": [LLM03],
  "xss.raw-html": [W(79, "Cross-site Scripting")], "template.user-string": [W(79, "Cross-site Scripting"), W(94, "Code Injection")],
  "sql.string-built": [W(89, "SQL Injection")], "nosql.operator-input": [W(20, "Improper Input Validation")],
  "csrf.disabled": [W(352, "Cross-Site Request Forgery")], "path.user-input": [W(22, "Path Traversal")],
  "cmd.shell-built": [W(78, "OS Command Injection"), W(77, "Command Injection")], "code.eval": [W(94, "Code Injection")],
  "llm.output-to-sink": [W(94, "Code Injection")], "upload.unrestricted": [W(434, "Unrestricted Upload of File with Dangerous Type")],
  "deserialize.unsafe": [W(502, "Deserialization of Untrusted Data")], "ssrf.user-url": [W(918, "Server-Side Request Forgery")],
  "supabase.rls-disabled": [W(862, "Missing Authorization")], "supabase.policy-allows-all": [W(284, "Improper Access Control")],
  "supabase.service-key-in-client": [W(284, "Improper Access Control")], "cookie.trusted-role": [W(863, "Incorrect Authorization")],
  "fs.world-writable": [W(284, "Improper Access Control")], "mass-assignment": [W(20, "Improper Input Validation"), W(639, "Authorization Bypass Through User-Controlled Key")],
  "pii.in-url": [W(200, "Exposure of Sensitive Information")], "error.stack-to-client": [W(200, "Exposure of Sensitive Information")],
  "build.sourcemaps-public": [W(200, "Exposure of Sensitive Information")], "llm.no-output-limit": [W(770, "Allocation of Resources Without Limits or Throttling")],
  "ai.call-not-logged": [LLM10],
};

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"];
// Words for what a model sends back, so its output can be followed to a dangerous place on the same line.
const MODEL_OUTPUT = /\b(completion|response|result|output|reply|answer|generation|llmResponse|aiResponse)\b[\w.?[\]]*\.(choices|content|text|output_text|message)\b|\.output_text\b|\bresult\.text\b/;
const SINKS = /\b(eval|exec|execSync|spawn|new Function)\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML|\.(query|execute|raw)\s*\(|\bsubprocess\.|\bos\.system\(/;
// User input inside a system prompt: the model can't tell the app's instructions from the user's text.
const USER_TEXT = /\$\{[^}]*\b(req\.(body|query|params)|request\.(json|form|args)|input|userInput|message|prompt|query|body)\b[^}]*\}|\{(user_input|user_message|query|message)\}/;

const rule = (r: Omit<Rule, "mappedBy" | "reviewedAt">): Rule => ({ ...r, ...DRAFT });
export const standardsRules: Rule[] = [
  // OWASP Top 10 for LLM Applications
  rule({ id: "llm.user-input-in-system-prompt", title: "User text placed inside the AI's system instructions", status: "partial", severity: "high", controls: [LLM01, LLM07],
    fix: "Keep the system prompt fixed. Send what the user typed as a separate user message, and never put it inside the system instructions.",
    note: "Text in the system prompt is treated as the app's own instructions. If user text goes there, a user can rewrite the rules the AI follows (prompt injection). Marked Partial: the inserted value may be safe text your app controls.",
    extensions: CODE,
    test: (l) => /\b(role\s*:\s*["']system["']|system(Prompt|_prompt|Message|_message|Instruction)?\s*[:=]|["']system["']\s*,)/.test(l) && USER_TEXT.test(l) }),
  rule({ id: "llm.output-to-sink", title: "AI output run as code, a command, a query or page HTML", status: "gap", severity: "high", controls: [LLM05],
    fix: "Treat model output like input from a stranger: validate it against what you expect, escape it for HTML, and never run it as code, a shell command or SQL.",
    note: "A model's reply can be steered by anyone who can influence its input. Passing it straight to eval, a shell, a database query or innerHTML lets them run code or change data.",
    extensions: CODE,
    test: (l) => MODEL_OUTPUT.test(l) && SINKS.test(l) }),
  rule({ id: "llm.no-output-limit", title: "AI call with no limit on how much it may generate", status: "partial", severity: "low", controls: [LLM10],
    fix: "Set a maximum output size on each call (max_tokens, maxTokens or max_output_tokens), and limit how often each user can call it.",
    note: "Without a limit, one request can run up a large bill or tie up the service (unbounded consumption). Marked Partial: the limit may be set in a shared client or wrapper.",
    extensions: CODE,
    fileTest: (lines) => lines.flatMap((l, i) => isAiCall(l) && !lines.slice(Math.max(0, i - 15), i + 20).some((x) => /max_?(output_?)?tokens|maxOutputTokens|max_completion_tokens|maxTokens/i.test(x)) ? [i + 1] : []).slice(0, 1) }),

  // Mobile apps (React Native, Expo, Android, iOS)
  rule({ id: "mobile.token-in-plain-storage", title: "Token or password saved in the phone's plain storage", status: "gap", severity: "high", controls: [GDPR32, A04],
    fix: "Store tokens and passwords in the platform's secure storage: expo-secure-store, react-native-keychain, the Android Keystore or the iOS Keychain.",
    note: "AsyncStorage and SharedPreferences aren't encrypted. Other apps on a rooted phone, or a device backup, can read what's saved there.",
    extensions: [".ts", ".tsx", ".js", ".jsx", ".kt", ".java"],
    test: (l) => /\b(AsyncStorage\.(setItem|multiSet)|MMKV\(\)\.set|\.putString)\s*\(/.test(l) && /token|password|secret|session|jwt|api_?key/i.test(l) }),
  rule({ id: "mobile.cleartext-traffic", title: "App allows unencrypted network traffic", status: "gap", severity: "high", controls: [GDPR32, A04],
    fix: "Turn off cleartext traffic (usesCleartextTraffic false on Android, no NSAllowsArbitraryLoads on iOS) and use HTTPS everywhere. Allow exceptions per domain only if you must.",
    note: "With cleartext allowed, anyone on the same Wi-Fi can read and change what the app sends and receives.",
    extensions: [".xml", ".plist", ".json"], fileName: /^(AndroidManifest\.xml|network_security_config\.xml|Info\.plist|app\.json|app\.config\.json)$/,
    test: (l) => /usesCleartextTraffic["']?\s*[=:]\s*["']?true|cleartextTrafficPermitted\s*=\s*"true"|<key>NSAllowsArbitraryLoads<\/key>/.test(l) }),
  rule({ id: "mobile.backup-allowed", title: "App data included in device backups", status: "partial", severity: "low", controls: [GDPR32],
    fix: "Set android:allowBackup=\"false\", or limit what's backed up with backup rules that leave out tokens and personal data.",
    note: "Backups can be copied off the phone and read elsewhere. Marked Partial: backing up non-sensitive settings is fine.",
    extensions: [".xml", ".json"], fileName: /^(AndroidManifest\.xml|app\.json|app\.config\.json)$/,
    test: (l) => /allowBackup["']?\s*[=:]\s*["']?true/.test(l) }),
  rule({ id: "mobile.webview-any-origin", title: "In-app browser that loads any website", status: "partial", severity: "medium", controls: [A06],
    fix: "List only the sites the WebView should open in originWhitelist, and open other links in the phone's browser.",
    note: "A WebView that accepts any origin can be sent to a page that abuses the bridge between the web page and your app. Marked Partial: it may only ever load your own content.",
    extensions: [".tsx", ".jsx", ".ts", ".js"],
    test: (l) => /originWhitelist\s*=\s*\{\s*\[\s*["']\*["']\s*\]\s*\}/.test(l) }),
];
