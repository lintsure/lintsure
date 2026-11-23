// Rules added from the realistic benchmark (benchmark/corpus.mjs, "gap" cases), 2026-11-20. Same approach as the other
// rule files: patterns on a line or a file, no data flow across files, our own wording. Beta: awaiting review.
import type { Control, Rule } from "../types.js";
import { AGENT_CONFIG, poisonedDescription } from "./owasp.js";

const CODE = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"];
const JS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const MARKUP = [...CODE, ".html", ".vue", ".svelte", ".astro"];
const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const A = (n: string, title: string): Control => ({ framework: "owasp-top10", id: `A${n}:2025`, title });
const A01 = A("01", "Broken Access Control"), A02 = A("02", "Security Misconfiguration"), A04 = A("04", "Cryptographic Failures"),
  A06 = A("06", "Insecure Design"), A07 = A("07", "Authentication Failures"), A08 = A("08", "Software or Data Integrity Failures");
const rule = (r: Omit<Rule, "mappedBy" | "reviewedAt">): Rule => ({ ...r, ...DRAFT });

// A record looked up by an id from the request, with nothing on or near the line that ties it to the signed-in user.
const BY_REQUEST_ID = /\b(findUnique|findUniqueOrThrow|findFirst|findById|findByPk|findOne|findOneBy|get_object_or_404)\s*\([^;]*\b(req\.(params|query|body)|request\.(args|view_args|json)|params)\b[^;]*\bid\b|\.objects\.get\([^)]*\b(id|pk)\s*=\s*request\./;
const OWNER = /\b(userId|user_id|ownerId|owner_id|owner|tenantId|tenant_id|orgId|org_id|accountId|account_id|req\.user|request\.user|session\.user|currentUser|authorize|can\(|policy|permission)\b/;
// A web-socket server that never looks at where the connection came from.
const WS_SERVER = /\bnew\s+(WebSocketServer|WebSocket\.Server|WSServer)\s*\(|\bnew\s+Server\s*\([^)]*\bcors\b|\bio\s*=\s*new\s+Server\s*\(/;
/** Lines that start a web-socket server in a file with no origin check (verifyClient, an origin test, allowRequest). Pure. */
export function wsNoOrigin(lines: string[]): number[] {
  const text = lines.join("\n");
  // `origin: "*"` and `origin: true` name the origin without checking it, so they don't count as a check.
  if (/\bverifyClient\b|\borigin\b|\ballowRequest\b|\bnoServer\s*:\s*true/.test(text.replace(/\borigin\s*:\s*(["'`]\*["'`]|true\b)/g, ""))) return [];
  return lines.flatMap((l, i) => (WS_SERVER.test(l) ? [i + 1] : []));
}
// Both sides of a comparison look like a secret value: a signature, token or key against an expected one.
const SECRETISH = String.raw`[\w.$\[\]"'-]*(?:signature|token|secret|hmac|digest|api_?key|apikey|password_hash)[\w.\[\]"'-]*`;
const UNSAFE_COMPARE = new RegExp(String.raw`(?<![\w.])${SECRETISH}\s*(?:===?|!==?)\s*${SECRETISH}`, "i");

// A file that registers tools an AI agent can call over MCP (TypeScript or Python SDKs).
const MCP_TOOL = /\.registerTool\(|\.tool\(\s*["'`]|@(mcp|server|app)\.tool\b|setRequestHandler\(\s*CallToolRequestSchema/;
const SHELL = /(?<![.\w$])(execSync|exec|execFile|execFileSync|spawn|spawnSync)\s*\(|\b(child_process|childProcess|cp)\.(execSync|exec|execFile|execFileSync|spawn|spawnSync)\s*\(|\bos\.(system|popen)\s*\(|\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True/;
const ENV_SECRET = /\b(process\.env|os\.environ(\.get)?|os\.getenv)\s*[.[(]\s*["']?\w*(TOKEN|SECRET|API_?KEY|PASSWORD|CREDENTIALS?)\w*/i;
/** Lines matching re in a file that registers MCP tools; nothing in other files. Pure. */
export function inMcpServer(lines: string[], re: RegExp): number[] {
  if (!lines.some((l) => MCP_TOOL.test(l))) return [];
  return lines.flatMap((l, i) => (re.test(l) && !/^\s*(\/\/|#)/.test(l) ? [i + 1] : []));
}
const LLM03 = { framework: "owasp-llm", id: "LLM03:2026", title: "Excessive Agency" } as Control;
const LLM04 = { framework: "owasp-llm", id: "LLM04:2026", title: "Supply Chain" } as Control;
const LLM01 = { framework: "owasp-llm", id: "LLM01:2026", title: "Prompt Injection" } as Control;

/** MCP config: a server run from a version that can change after you approved it (Partial), or reached over plain HTTP (Gap). Pure.
 *  shortcut: reads npx-style args only ("-y", "pkg"); add uvx and docker image tags when a field test shows them. */
export function mcpConfigUnsafe(lines: string[]): Array<{ line: number; status: "gap" | "partial" }> {
  if (!lines.some((l) => /"(mcpServers|servers|context_servers)"\s*:/.test(l))) return [];
  const out: Array<{ line: number; status: "gap" | "partial" }> = [];
  lines.forEach((l, i) => {
    if (/"(url|serverUrl|endpoint)"\s*:\s*"http:\/\/(?!localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)/.test(l)) { out.push({ line: i + 1, status: "gap" }); return; }
    if (/@latest"/.test(l)) { out.push({ line: i + 1, status: "partial" }); return; }
    const yes = /"(-y|--yes)"\s*,?\s*(.*)$/.exec(l);
    if (!yes) return;
    const same = /^"([^"]+)"/.exec(yes[2].trim()), next = /^\s*"([^"]+)"/.exec(lines[i + 1] ?? "");
    const pkg = same?.[1] ?? next?.[1];
    if (pkg && /^(@[\w.-]+\/)?[\w.-]+$/.test(pkg)) out.push({ line: same ? i + 1 : i + 2, status: "partial" });
  });
  return out;
}

const DOCKERFILE = /^(Dockerfile|Containerfile)|\.Dockerfile$/i;
const NATIVE = [".java", ".kt", ".swift", ".go", ".dart"];
// An IV or nonce that is the same for every message: zero bytes or fixed text. Reusing one with the same key breaks
// AES-GCM outright and leaks patterns in CBC. A buffer that is filled with random bytes on the next lines is fine (unlessNear).
const STATIC_IV = /\b(iv|IV|nonce|initVector|initializationVector)\s*[:=]\s*(Buffer\.alloc\(\s*\d+\s*(,\s*0\s*)?\)|Buffer\.from\(\s*["'][^"']+["'])|\b(iv|nonce)\s*=\s*(b["'][^"']+["']|bytes\(\s*\d+\s*\))|\b(Iv|GCM)ParameterSpec\(\s*(\d+\s*,\s*)?(new\s+byte\[\d+\]|ByteArray\(\d+\)|"[^"]+"\.(getBytes|toByteArray)\()|\b(iv|nonce)\s*:?=\s*\[\]byte\("[^"]+"\)/;
/** Key sizes and work factors below what current guidance accepts. Pure. */
export function weakCryptoParameter(l: string): boolean {
  if (/^\s*(\/\/|#|\*)/.test(l)) return false;
  // PBKDF2 under 10,000 rounds (OWASP asks for 600,000 with SHA-256; a four-digit count is far off any guidance).
  if (/\bpbkdf2(Sync)?\(\s*[^,]+,\s*[^,]+,\s*\d{1,4}\s*,|\bpbkdf2_hmac\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\d{1,4}\s*[,)]|\bPBEKeySpec\(\s*[^,]+,\s*[^,]+,\s*\d{1,4}\s*,/.test(l)) return true;
  if (/\bPBKDF2\w*\(/.test(l) && /\biterations\s*=\s*\d{1,4}\s*[,)]/.test(l)) return true;
  // bcrypt below 10 rounds.
  if (/\bbcrypt\.(hash|hashSync|genSalt|genSaltSync)\(\s*(?:[^,()]+,\s*)?[1-9]\s*[,)]|\bgensalt\(\s*(?:rounds\s*=\s*)?[1-9]\s*\)/.test(l)) return true;
  // RSA keys under 2048 bits.
  return /\bmodulusLength\s*:\s*(512|768|1024)\b|\bkey_size\s*=\s*(512|768|1024)\b|\brsa\.GenerateKey\(\s*[^,]+,\s*(512|768|1024)\s*\)|\b\w*([Kk]eyGen|kpg|[Gg]enerator)\w*\.initialize\(\s*(512|768|1024)\s*[,)]|\bopenssl\s+genrsa\b[^|;\n]*\s(512|768|1024)\b/.test(l);
}
/** Android release build that can be debugged: the manifest flag, or `debuggable true` inside the release block of build.gradle. Pure. */
export function debuggableBuild(lines: string[]): number[] {
  return lines.flatMap((l, i) => {
    if (/android:debuggable\s*=\s*"true"/.test(l)) return [i + 1];
    if (!/\b(isDebuggable\s*=\s*true|debuggable\s+true|debuggable\s*=\s*true)\b/.test(l)) return [];
    const block = lines.slice(Math.max(0, i - 12), i).reverse().find((x) => /^\s*(release|debug|getByName\("(release|debug)"\)|named\("(release|debug)"\))\s*\{/.test(x)) ?? "";
    return /release/.test(block) ? [i + 1] : [];
  });
}
const GDPR = (id: string, title: string): Control => ({ framework: "gdpr", id, title });
/** A line that declares a stored field with one of these names: SQL column, Prisma, Mongoose, Sequelize, TypeORM, Django,
 *  SQLAlchemy. A TypeScript type (`cvv: string`) describes a form value, not storage, so it doesn't count. Pure. */
export function storedField(names: string): (l: string) => boolean {
  const re = new RegExp(String.raw`\b(${names})\b["']?\s*(:\s*(\{\s*type\s*:\s*)?(String|Number|Boolean|DataTypes\.\w+|Sequelize\.\w+|Schema\.Types\.\w+)\b|\s+(VARCHAR|CHAR|TEXT|INT|INTEGER|SMALLINT|BOOLEAN|JSONB?)\b|\s+(String|Int|Boolean|Json)\??\s*(@|$)|\s*=\s*(models|db|sa|sqlalchemy)\.\w+\(|\s*=\s*(mapped_column|Column)\(|\s*:\s*Mapped\[)`, "i");
  return (l) => !/^\s*(\/\/|#|--|\*)/.test(l) && (re.test(l) || (/@(Column|Prop)\(/.test(l) && new RegExp(String.raw`\b(${names})\b`, "i").test(l))) && (/@(Column|Prop)\(/.test(l) || !/:\s*(string|number|boolean)\b/.test(l));
}
const CARD_CODE = storedField("cvv2?|cvc2?|card_?security_?code|card_?verification_?(code|value)");
const SPECIAL = storedField("religion|religious_?belief|ethnicity|ethnic_?origin|sexual_?orientation|political_?(affiliation|opinion|party)|trade_?union(_?membership)?|hiv_?status|genetic_?data");
const CONSENT_WORD = /consent|marketing|newsletter|subscribe|opt[-_ ]?in|promotional/i;
/** A consent or marketing checkbox that starts ticked, or its state that starts as true. Pure. */
export function consentPreticked(lines: string[]): number[] {
  return lines.flatMap((l, i) => {
    // State that starts true for a consent value; a flag that only shows the banner is not consent.
    const st = /\[\s*(\w+)\s*,\s*set\w+\s*\]\s*=\s*useState(<[^>]*>)?\(\s*true\s*\)/.exec(l);
    if (st && CONSENT_WORD.test(st[1]) && !/show|open|visible|banner|modal|dialog|loading|seen/i.test(st[1])) return [i + 1];
    // `checked={value}` is controlled state; only a bare attribute or a literal true pre-ticks the box.
    const attrs = l.replace(/\b(defaultChecked|checked)\s*=\s*\{(?!\s*true\s*\})[^}]*\}/g, "");
    // A variable or arrow parameter named `checked` (`const checked = ...`, `checked => ...`) is code, not the attribute.
    if (/^\s*(const|let|var|return|if)\b/.test(l) || !/(^|\s)(defaultChecked|checked)(\s*=\s*(\{\s*true\s*\}|["'](checked|true)["'])(\s|\/?>|$)|(?!\s*=)(\s|\/?>|$))/.test(attrs)) return [];
    const near = lines.slice(Math.max(0, i - 4), i + 5).join("\n");
    return /type\s*=\s*["']checkbox["']|<Checkbox\b/.test(near) && CONSENT_WORD.test(near) ? [i + 1] : [];
  });
}
const IAC = [".tf", ".json", ".yml", ".yaml"];
// Ports that should never face the internet: remote login, databases, caches, search and the Docker API.
const ADMIN_PORTS = [22, 23, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 9200, 9300, 11211, 27017, 5984, 2375, 2376];
const OPEN_CIDR = /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"|\bCidrIp(v6)?\s*:\s*["']?(0\.0\.0\.0\/0|::\/0)|source_ranges\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|source_address_prefix\s*=\s*"(\*|0\.0\.0\.0\/0|Internet)"/;
/** A firewall rule that lets the whole internet reach an admin or database port. Reads the block around the open range:
 *  inbound only, and only when the ports are written there. Pure.
 *  shortcut: reads up to 10 lines either side of the range, not the parsed block; parse HCL if rules get longer. */
export function networkOpen(lines: string[]): number[] {
  return lines.flatMap((l, i) => {
    if (!OPEN_CIDR.test(l) || /^\s*(#|\/\/)/.test(l)) return [];
    const head = /^\s*(ingress|egress|resource|rule|allow|deny|security_rule|-\s*IpProtocol|SecurityGroup(Ingress|Egress))\b/;
    let a = i, b = i;
    while (a > 0 && i - a < 10 && !head.test(lines[a])) a--;
    while (b < lines.length - 1 && b - i < 10 && !/^\s*\}\s*$/.test(lines[b]) && !(b > i && head.test(lines[b + 1]))) b++;
    const block = lines.slice(a, b + 1).join("\n");
    if (/^\s*egress\b|SecurityGroupEgress|type\s*=\s*"egress"|direction\s*=\s*"(Outbound|EGRESS)"/im.test(block)) return [];
    if (/protocol\s*=\s*"(-1|all)"|IpProtocol\s*:\s*["']?-1/.test(block)) return [i + 1];
    const n = (re: RegExp) => { const m = re.exec(block); return m ? Number(m[1]) : null; };
    const lo = n(/\b(?:from_port|FromPort)\s*[=:]\s*"?(\d+)/), hi = n(/\b(?:to_port|ToPort)\s*[=:]\s*"?(\d+)/);
    const single = [...block.matchAll(/\b(?:ports|destination_port_ranges?)\s*=\s*\[?([^\]\n]*)/g)].flatMap((m) => [...m[1].matchAll(/\d+/g)].map((x) => Number(x[0])));
    if (lo !== null && ADMIN_PORTS.some((p) => p >= lo && p <= (hi ?? lo))) return [i + 1];
    return single.some((p) => ADMIN_PORTS.includes(p)) ? [i + 1] : [];
  });
}
/** A policy statement that allows every action on every resource. A Deny statement with the same wildcards is a guard. Pure. */
export function iamAllowAll(lines: string[]): number[] {
  return lines.flatMap((l, i) => {
    if (!/"?\bAction"?\s*[:=]\s*\[?\s*["']\*["']|\bactions\s*=\s*\[\s*"\*"\s*\]/.test(l)) return [];
    const near = lines.slice(Math.max(0, i - 6), i + 7).join("\n");
    return /"?\bResource"?\s*[:=]\s*\[?\s*["']\*["']|\bresources\s*=\s*\[\s*"\*"\s*\]/.test(near) && !/\bEffect"?\s*[:=]\s*["']Deny["']/i.test(near) ? [i + 1] : [];
  });
}
// `from x import y` inside a RUN python block is not a FROM instruction.
const from = (l: string) => (/\bimport\b/.test(l) ? null : /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(l));
// Official server images start as root and drop to their own user in the entrypoint.
const DROPS_ROOT = /^(docker\.io\/)?(library\/)?(mysql|mariadb|postgres|redis|mongo|rabbitmq|memcached|elasticsearch|influxdb|grafana\/grafana|clickhouse\/clickhouse-server)(:|@|$)/i;
/** Dockerfile whose last stage never switches away from root: the last FROM line, or its `USER root` line. Pure. */
export function dockerRunsAsRoot(lines: string[]): number[] {
  let last = -1;
  lines.forEach((l, i) => { if (from(l)) last = i; });
  if (last < 0) return [];
  // Images built to run without root, and `scratch` (nothing to switch to), are left alone.
  if (/nonroot|rootless|unprivileged|chainguard|\bscratch\b/i.test(from(lines[last])![1]) || DROPS_ROOT.test(from(lines[last])![1])) return [];
  const users = lines.map((l, i) => [i, /^\s*USER\s+(\S+)/i.exec(l)?.[1]] as const).filter(([i, u]) => i > last && u);
  if (!users.length) return [last + 1];
  const [line, user] = users[users.length - 1];
  return /^(root|0)(:|$)/.test(user!) ? [line + 1] : [];
}
/** FROM lines with no tag or the `latest` tag. A stage name, a digest, a build argument and `scratch` are not images to pin. Pure. */
export function dockerImageUnpinned(lines: string[]): number[] {
  const stages = new Set<string>();
  return lines.flatMap((l, i) => {
    const m = from(l);
    if (!m) return [];
    const image = m[1];
    if (m[2]) stages.add(m[2].toLowerCase());
    if (stages.has(image.toLowerCase()) && image.toLowerCase() !== m[2]?.toLowerCase()) return [];
    if (image === "scratch" || image.includes("$") || image.includes("@sha256:")) return [];
    const tag = /:([^/:]+)$/.exec(image)?.[1];
    return !tag || tag === "latest" ? [i + 1] : [];
  });
}
// A secret given a value at build time stays in the image's layers and history for anyone who pulls it.
const BUILD_SECRET = /^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)(=|\s+)["']?(?!changeme|change[_-]me|example|your[_-]|placeholder|dummy|xxx|none\b|null\b|true\b|false\b)[^\s"'$<{]{6,}/i;

export const moreRules: Rule[] = [
  rule({ id: "crypto.static-iv", title: "Encryption with a fixed IV or nonce", status: "gap", severity: "medium", controls: [A04, GDPR("Art. 32", "Security of processing")],
    fix: "Make a new random IV for every message (crypto.randomBytes, os.urandom, SecureRandom) and store it next to the ciphertext. It doesn't need to be secret, only never reused.",
    note: "With the same key and the same IV, two messages can be compared and partly recovered. In AES-GCM a repeated nonce lets an attacker forge messages (CWE-329, CWE-323).",
    extensions: [...CODE, ...NATIVE], test: (l) => STATIC_IV.test(l) && !/^\s*(\/\/|#|\*)/.test(l),
    unlessNear: /randomFill|getRandomValues|randomBytes|rand\.Read|SecureRandom|nextBytes|urandom|secrets\.token/ }),
  rule({ id: "crypto.weak-parameters", title: "Key size or work factor too low", status: "gap", severity: "medium", controls: [A04, GDPR("Art. 32", "Security of processing")],
    fix: "Use RSA keys of 2048 bits or more, bcrypt with 10 rounds or more, and PBKDF2 with the iteration count current guidance gives (600,000 for SHA-256), or switch to Argon2.",
    note: "Short keys can be factored and low work factors make stolen password hashes cheap to crack on ordinary hardware (CWE-326, CWE-916).",
    extensions: [...CODE, ...NATIVE, ".sh", ".bash", ""], test: weakCryptoParameter }),
  rule({ id: "mobile.debuggable-build", title: "Android release build that can be debugged", status: "gap", severity: "medium", controls: [A02, GDPR("Art. 32", "Security of processing")],
    fix: "Remove android:debuggable from the manifest and keep debuggable false in the release build type. The build tools set it for debug builds on their own.",
    note: "A debuggable app lets anyone with the phone attach a debugger, read its private files and change what it does (CWE-489).",
    extensions: [".xml", ".gradle", ".kts"], fileName: /^(AndroidManifest\.xml|build\.gradle(\.kts)?)$/, fileTest: debuggableBuild }),
  rule({ id: "privacy.consent-preticked", title: "Consent box that starts ticked", status: "gap", severity: "medium", controls: [GDPR("Art. 7", "Conditions for consent")],
    fix: "Start the box empty and let the person tick it. Store when they did and the wording they saw.",
    note: "Consent has to be an active choice. A box that is ticked for the person is not consent under the GDPR, so anything sent on that basis has no legal ground (Art. 7, recital 32).",
    extensions: MARKUP, fileTest: consentPreticked,
    unseen: "Lintsure can't tell whether this box is the legal basis for anything. A ticked box for a setting the person already chose earlier is fine." }),
  rule({ id: "privacy.special-category-field", title: "Sensitive category of personal data stored", status: "partial", severity: "medium", controls: [GDPR("Art. 9", "Special categories of personal data")],
    fix: "Check that you need this field at all. If you do, write down the Art. 9 exception you rely on, usually explicit consent, and limit who can read it.",
    note: "Religion, ethnicity, sexual orientation, political views, union membership, health and genetic data may not be processed unless a specific exception applies. Marked Partial: the exception is a decision outside the code.",
    extensions: [...CODE, ".sql", ".prisma"], test: (l) => SPECIAL(l) }),
  rule({ id: "payment.card-code-stored", title: "Card security code stored", status: "gap", severity: "high", controls: [GDPR("Art. 32", "Security of processing"), A02],
    fix: "Never store the card security code. Send the card straight to your payment provider and keep only the token it gives back.",
    note: "The three or four digit code exists to prove the card is in the buyer's hand. Card scheme rules (PCI DSS 3.3.1) forbid keeping it after authorisation, even encrypted, and a leak makes every stored card usable.",
    extensions: [...CODE, ".sql", ".prisma"], test: (l) => CARD_CODE(l) }),
  rule({ id: "cloud.database-public", title: "Database reachable from the internet", status: "gap", severity: "high", controls: [A01, A02],
    fix: "Set publicly_accessible to false, put the database in a private subnet, and reach it through the app, a bastion or a VPN.",
    note: "A database with a public address is one leaked or guessed password away from a full data breach, and it is found by scanners within hours (CWE-284).",
    extensions: [...IAC, ".ts", ".py"], test: (l) => /\bpublicly_accessible\s*=\s*true\b|\bPubliclyAccessible\s*:\s*["']?true\b|\bpubliclyAccessible\s*:\s*true\b|\bpublicly_accessible\s*=\s*True\b/.test(l) && !/^\s*(#|\/\/)/.test(l) }),
  rule({ id: "cloud.network-open", title: "Admin or database port open to the whole internet", status: "gap", severity: "high", controls: [A01, A02],
    fix: "Limit the rule to the addresses that need it (your office, a VPN, a bastion), or remove it and use a session manager.",
    note: "Remote login and database ports that accept connections from 0.0.0.0/0 are scanned and attacked all day (CWE-284).",
    extensions: IAC, fileTest: networkOpen,
    unseen: "Lintsure reads this file only. It can't see a network ACL or a firewall in front that narrows the rule." }),
  rule({ id: "cloud.iam-allow-all", title: "Policy that allows every action on every resource", status: "gap", severity: "high", controls: [A01, A02],
    fix: "List the actions and resources the role really needs. Start from what it calls today and add as you go.",
    note: "Whoever gets this role's credentials, through a leaked key or a compromised service, controls the whole account (CWE-732).",
    extensions: IAC, fileTest: iamAllowAll }),
  rule({ id: "cloud.function-url-no-auth", title: "Function URL that anyone can call", status: "partial", severity: "medium", controls: [A01, A07],
    fix: "Use AWS_IAM as the authorization type, or check a signature or token in the function before doing anything.",
    note: "With authorization set to NONE the function runs for anyone who has the URL. Marked Partial: public webhooks do this on purpose and check a signature in code.",
    extensions: IAC, test: (l) => /\bauthorization_type\s*=\s*"NONE"|\bAuthType\s*:\s*["']?NONE\b/.test(l) && !/^\s*(#|\/\/)/.test(l) }),
  rule({ id: "docker.runs-as-root", title: "Container image that runs as root", status: "partial", severity: "low", controls: [A02],
    fix: "Add a user and switch to it in the last stage, for example `RUN adduser -D app` then `USER app`, or use a base image built to run without root.",
    note: "With no USER line the app runs as root inside the container. A bug that lets someone run code then starts with full rights in the container, which makes breaking out to the host much easier (CWE-250). Marked Partial: the platform may set the user when it starts the container.",
    extensions: [""], fileName: DOCKERFILE, fileTest: dockerRunsAsRoot,
    unseen: "Lintsure can't see a user set at run time (Kubernetes runAsUser, docker run --user) or one the base image already sets." }),
  rule({ id: "docker.image-unpinned", title: "Base image with no fixed version", status: "partial", severity: "low", controls: [A08],
    fix: "Name a version, for example `FROM node:22.11-slim`, and update it on purpose. Pin a digest for anything you ship to others.",
    note: "With no tag, or `latest`, every build can pull a different image, so a broken or tampered release reaches you without any change in your repo (CWE-829).",
    extensions: [""], fileName: DOCKERFILE, fileTest: dockerImageUnpinned }),
  rule({ id: "docker.secret-in-build", title: "Secret given a value in a Dockerfile", status: "gap", severity: "high", controls: [A02, A08],
    fix: "Pass the secret when the container starts (an environment variable or a mounted secret), or use `RUN --mount=type=secret` for build steps. Rotate the value: it is in every image built so far.",
    note: "ENV and ARG values are stored in the image. Anyone who can pull the image, or read its build history, can read the secret (CWE-798).",
    extensions: [""], fileName: DOCKERFILE, test: (l) => BUILD_SECRET.test(l) }),
  rule({ id: "mcp.config-unsafe-server", title: "MCP server run from a moving version or over plain HTTP", status: "partial", severity: "medium", controls: [LLM04, A08],
    fix: "Pin the server to an exact version you have looked at, for example some-server@1.4.2, and update it on purpose. Use https for a remote server.",
    note: "An agent trusts the tools this server offers. With no version, or @latest, the next start can load different code and different tool descriptions than the ones you approved. Over plain HTTP anyone on the network path can change them (OWASP LLM04, CWE-829).",
    extensions: [".json"], pathMatch: AGENT_CONFIG,
    unseen: "Lintsure can't see whether a lockfile or a private registry pins this package somewhere else.",
    fileTest: mcpConfigUnsafe }),
  // The model reads a tool's description before it decides to call the tool, so text there works as an instruction
  // (tool poisoning, first reported for MCP in 2025). Any string in the server file counts: Python tools use the docstring.
  rule({ id: "mcp.tool-description-poisoned", title: "MCP tool description that gives the agent orders", status: "gap", severity: "high", controls: [LLM01, LLM04],
    fix: "Rewrite the description so it only says what the tool does and what it takes. Remove anything that tells the agent to ignore instructions, keep something from the user or read other files, and delete any invisible characters.",
    note: "An agent reads tool descriptions as part of its instructions. A description that says to hide a step, ignore earlier rules or read key files can take over every agent that connects to this server (OWASP LLM01, CWE-1427).", extensions: [...CODE, ".json"],
    unseen: "Lintsure reads this server's source, not the servers it connects to. It can't tell a real attack from a security tool that lists these phrases to detect them.",
    // A scanner that lists these phrases to catch them is not an attack: lines that build a pattern or name an attempt are
    // skipped, and in a JSON manifest only "description" values are read (field test: 6 of 6 new findings were detectors).
    fileTest: (lines) => {
      const code = lines.some((l) => MCP_TOOL.test(l));
      if (!code && !lines.some((l) => /"inputSchema"\s*:/.test(l))) return [];
      return lines.flatMap((l, i) => (poisonedDescription(l) && !/^\s*(\/\/|#)/.test(l) && (code || /"description"\s*:/.test(l))
        && !/re\.compile\(|new RegExp\(|\(\?i\)|\b(attempt|detect\w*|patterns?|injection)\b/i.test(l) ? [i + 1] : []));
    } }),
  rule({ id: "mcp.tool-runs-shell", title: "MCP tool that runs shell commands", status: "partial", severity: "high", controls: [LLM03, A06],
    fix: "Run a fixed program with execFile and an argument list, never a command string. Check every argument against an allow-list, and ask the user before anything that changes files or systems.",
    note: "The agent decides what to pass to this tool, and anything it reads (a web page, an issue, a file) can steer it. If tool input reaches the command, a prompt injection becomes a shell on this machine (CWE-78).", extensions: CODE,
    unseen: "Lintsure can't tell whether the tool's input reaches the command, or whether the command is fixed.",
    fileTest: (lines) => (lines.some((l) => /child_process|\bexeca\b|\bimport subprocess\b|\bfrom subprocess\b|\bimport os\b|\bshelljs\b|\bzx\b/.test(l)) ? inMcpServer(lines, SHELL) : []) }),
  rule({ id: "mcp.tool-uses-secret", title: "MCP server reads a credential every tool shares", status: "partial", severity: "low", controls: [LLM03, A01],
    fix: "Give the server a token with only the access its tools need, read-only where it can be. Split tools that write into a separate server or token.",
    note: "Every tool in this server acts with this credential's full access, so the riskiest tool sets the blast radius for all of them. A separate key name doesn't narrow anything if the key itself can do more.", extensions: CODE,
    confidence: "medium",
    unseen: "Lintsure can't see what this credential is allowed to do.",
    // One finding per credential name: the same key read in five places is still one shared key.
    fileTest: (lines) => { const seen = new Set<string>(); return inMcpServer(lines, ENV_SECRET).filter((n) => { const k = lines[n - 1].match(ENV_SECRET)![0]; return !seen.has(k) && !!seen.add(k); }); } }),

  rule({ id: "authz.no-owner-check", title: "Record loaded by an id from the request, with no owner check", status: "partial", severity: "high", controls: [A01],
    fix: "Look the record up by its id and the signed-in user (or tenant) together, for example where: { id, userId: req.user.id }, or check the owner before returning it.",
    note: "Anyone who changes the id in the URL can read or change someone else's record (insecure direct object reference, CWE-639).", extensions: CODE,
    unseen: "Lintsure can't see checks done in middleware or another function, so the owner may already be verified.",
    confidence: "medium",
    test: (l) => BY_REQUEST_ID.test(l) && !OWNER.test(l),
    unlessNear: OWNER }),
  rule({ id: "jwt.no-algorithm-pin", title: "Token verified without saying which algorithm is allowed", status: "partial", severity: "medium", controls: [A07],
    fix: "Pass the algorithm you sign with, for example jwt.verify(token, key, { algorithms: [\"RS256\"] }), or algorithms=[\"HS256\"] in PyJWT.",
    note: "Without a fixed list, some library versions accept a token signed with a different algorithm than you meant, for example one signed with your public key (CWE-347).", extensions: CODE,
    confidence: "medium",
    // Also an options object written on the line that has no algorithms list.
    test: (l) => /\bjwt\.verify\(\s*[^,()]+,\s*[^,()]+\)/.test(l) || /\bjwt\.verify\(\s*[^,()]+,\s*[^,()]+,\s*\{(?![^}]*\balgorithms\b)[^{}]*\}\s*\)/.test(l) || /\bjwt\.decode\(\s*[\w.]+\s*,\s*[\w."']+\s*\)/.test(l) }),
  rule({ id: "jwt.weak-secret", title: "Token signed with a short secret written in the code", status: "gap", severity: "high", controls: [A04, A07],
    fix: "Read the signing key from the environment or a secret store, and make it at least 32 random bytes.",
    note: "Anyone who reads the code, or guesses a short key, can sign their own login tokens (CWE-798, CWE-521).", extensions: CODE,
    test: (l) => /\bjwt\.(sign|verify|encode|decode)\(\s*(?:\{[^{}]*\}|[^,(){}]+)\s*,\s*["'][^"']{1,31}["']/.test(l) }),
  rule({ id: "proto.pollution", title: "Request data deep-merged into an object", status: "gap", severity: "high", controls: [A08],
    fix: "Copy only the fields you expect, or validate the body with a schema first. If you must merge, drop __proto__, constructor and prototype keys.",
    note: "A body like {\"__proto__\": {\"isAdmin\": true}} can change every object in the app (prototype pollution, CWE-1321).", extensions: JS,
    test: (l) => /(?:\b(?:_\.merge|_\.mergeWith|_\.defaultsDeep|deepmerge|deepMerge|mergeDeep|merge)\s*\(|\$\.extend\(\s*true\s*,)[^;]*\b(req\.(body|query)|request\.(body|json))/.test(l) }),
  rule({ id: "html.tabnabbing", title: "Link opens a new tab without rel=\"noopener\"", status: "partial", severity: "low", controls: [A06],
    fix: "Add rel=\"noopener noreferrer\" to links with target=\"_blank\".",
    note: "Current browsers already treat target=\"_blank\" as noopener, so this matters mainly for older browsers and webviews: the opened page could redirect your tab (CWE-1022).", extensions: MARKUP,
    // Held back by default (2,246 shown on 195 repos, field test 2026-11-20): low risk in current browsers, and JSX puts rel on the next line.
    confidence: "medium",
    test: (l) => /\btarget\s*=\s*\{?\s*["']_blank["']/.test(l) && !/\brel\s*=\s*\{?\s*["'][^"']*\bno(opener|referrer)\b/.test(l),
    unlessNear: /\brel\s*=\s*\{?\s*["'][^"']*\bno(opener|referrer)\b/ }),
  rule({ id: "ws.no-origin-check", title: "Web-socket server with no origin check", status: "partial", severity: "medium", controls: [A01],
    fix: "Check the Origin header when a connection opens (verifyClient in ws, cors.origin or allowRequest in socket.io) and allow only your own sites.",
    note: "Browsers don't stop other sites opening a web socket to you, so a page on any site can use a signed-in visitor's cookies against it (cross-site WebSocket hijacking, CWE-1385).", extensions: JS,
    unseen: "Lintsure can't see an origin check done in a proxy or an upgrade handler in another file.",
    fileTest: wsNoOrigin }),
  rule({ id: "k8s.privileged", title: "Container runs privileged or shares the host", status: "gap", severity: "high", controls: [A02],
    fix: "Remove privileged, hostNetwork, hostPID and hostIPC, set allowPrivilegeEscalation: false, and run as a non-root user.",
    note: "A privileged container, or one sharing the host's network or processes, can take over the machine it runs on if it is broken into (CWE-250).", extensions: [".yml", ".yaml"],
    // Also the one-line form, securityContext: {privileged: true}, and Compose's host namespaces.
    test: (l) => /^\s*-?\s*(privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*true\b/.test(l) || /^\s*-?\s*runAsUser\s*:\s*0\s*$/.test(l)
      || /\bsecurityContext\s*:\s*\{[^}]*\b(privileged|allowPrivilegeEscalation)\s*:\s*true\b/.test(l) || /^\s*(network_mode|pid|ipc)\s*:\s*["']?host["']?\s*(#.*)?$/.test(l)
      // Capabilities that amount to host access, written on one line, and security profiles switched off.
      || /^\s*-?\s*(cap_add|add)\s*:\s*\[[^\]]*\b(SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)\b/.test(l) || /\b(seccomp|apparmor)[:=]unconfined\b/i.test(l),
    // The same capabilities as list items: the nearest key above must be cap_add or add, never drop.
    fileTest: (lines) => lines.flatMap((l, i) => {
      if (!/^\s*-\s*["']?(SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL)["']?\s*(#.*)?$/.test(l)) return [];
      const key = lines.slice(Math.max(0, i - 6), i).reverse().find((x) => /^\s*-?\s*[\w-]+\s*:\s*(#.*)?$/.test(x)) ?? "";
      return /^\s*-?\s*(cap_add|add)\s*:/.test(key) ? [i + 1] : [];
    }) }),
  rule({ id: "docker.socket-mounted", title: "Docker socket mounted into a container", status: "partial", severity: "high", controls: [A02],
    fix: "Don't mount /var/run/docker.sock. If the container really needs Docker, point it at a separate, locked-down Docker daemon over TLS, or use a rootless or socket-proxy setup that allows only the calls it needs.",
    note: "Whatever runs in the container gets the host's Docker, and with it the whole machine: it can start a privileged container that mounts the host's disk (CWE-250). Mounting it read-only (:ro) doesn't help, because the API still works.", extensions: [".yml", ".yaml", ".json", ".sh", ""],
    unseen: "Lintsure can't tell whether this container is meant to manage Docker (a CI runner or a reverse proxy) or whether the host is a throwaway machine.",
    // A mount, not a client setting: DOCKER_HOST=unix:///var/run/docker.sock only says where to connect.
    // A socket proxy is the fix this rule asks for: the mount into the proxy itself is not a finding (0.3.14 review, 2 of 2).
    // The service's image is the nearest `image:` line above the mount.
    fileTest: (lines) => lines.flatMap((l, i) => {
      if (!/(?<!unix:\/)\/var\/run\/docker\.sock\b|\/\/\.\/pipe\/docker_engine/.test(l) || /^\s*#|DOCKER_HOST\s*[:=]/.test(l)) return [];
      const image = lines.slice(Math.max(0, i - 60), i).reverse().find((x) => /^\s*image\s*:/.test(x)) ?? "";
      return /socket-proxy/i.test(image) ? [] : [i + 1];
    }) }),
  rule({ id: "cloud.public-bucket", title: "Storage bucket open to the public", status: "gap", severity: "high", controls: [A01],
    fix: "Keep the bucket private and block public access. Share single files with short-lived signed URLs instead.",
    note: "Anyone on the internet can list or download what's in a public bucket, and with write access, replace it (CWE-284).", extensions: [".tf", ".json", ".yml", ".yaml", ...CODE],
    test: (l) => /\bacl\s*[:=]\s*["']public-read(-write)?["']/i.test(l) || /\bblock_?public_?(acls|policy)\s*[:=]\s*false\b/i.test(l) || /\bpublicReadAccess\s*:\s*true\b/.test(l) || /"Principal"\s*:\s*"\*"/.test(l) && /s3:|"Effect"\s*:\s*"Allow"/.test(l) }),
  rule({ id: "crypto.unsafe-compare", title: "Secret compared with == instead of a constant-time check", status: "partial", severity: "medium", controls: [A04],
    fix: "Use crypto.timingSafeEqual (Node) or hmac.compare_digest (Python) to compare signatures, tokens and keys.",
    note: "A plain comparison stops at the first wrong character, so response times can leak the secret bit by bit (timing attack, CWE-208).", extensions: CODE,
    confidence: "medium",
    test: (l) => UNSAFE_COMPARE.test(l) && !/\b(null|undefined|typeof|length)\b|["']\s*\)?\s*$/.test(l.replace(/\/\/.*$/, "").split(/===?|!==?/)[1] ?? ""),
    unlessNear: /timingSafeEqual|compare_digest|safeCompare|constantTime|secureCompare/ }),
  rule({ id: "graphql.introspection", title: "GraphQL introspection switched on", status: "partial", severity: "low", controls: [A02],
    fix: "Turn introspection off in production, for example introspection: process.env.NODE_ENV !== \"production\".",
    note: "Introspection hands anyone a full map of your API, including fields you never meant to advertise (CWE-200).", extensions: CODE,
    test: (l) => /\bintrospection\s*:\s*true\b/.test(l) }),
  // ML models are code: a pickled checkpoint or a model repo's own Python runs when it is loaded (2026-11-20).
  rule({ id: "ml.unsafe-model-load", title: "Model loaded in a way that can run code", status: "gap", severity: "high", controls: [A08, LLM04],
    fix: "Load weights only: torch.load(path, weights_only=True), or use safetensors. Don't pass trust_remote_code=True; if a model needs it, pin the exact revision you reviewed.",
    note: "A model checkpoint saved with pickle can carry code that runs the moment it is loaded, and trust_remote_code=True runs Python from the model's repository on your server (CWE-502). Since PyTorch 2.6, torch.load loads weights only by default, so a plain call is Partial: it depends on your PyTorch version.",
    extensions: [".py", ".ipynb"],
    unseen: "Lintsure can't see which PyTorch version runs this, or whether the model file comes only from you.",
    test: (l) => {
      if (/^\s*#/.test(l)) return false;
      // torch.load inside a string (a list of forbidden calls) isn't a call.
      if (/^[^"'`]*\btorch\.load\s*\(/.test(l)) return /weights_only\s*=\s*False/.test(l) ? true : /weights_only\s*=/.test(l) ? false : /\)/.test(l) ? "partial" : false;
      // A pinned revision means someone chose that exact code; still Partial, never quiet.
      if (/\btrust_remote_code\s*=\s*True\b/.test(l)) return "partial";
      return false;
    } }),
  // Images ship with well-known first-run passwords; a compose file or manifest that keeps them leaves the service open.
  rule({ id: "config.default-service-password", title: "Database or service left on its default password", status: "partial", severity: "high", controls: [A07, A02],
    fix: "Set a long random password from a secret store or an untracked .env file, for example POSTGRES_PASSWORD=${POSTGRES_PASSWORD} with no default.",
    note: "These defaults are published in every image's documentation, so anyone who can reach the port can log in (CWE-1393). Marked Partial: fine on a laptop with the port bound to 127.0.0.1, not on a server.",
    extensions: [".yml", ".yaml", ".env", "", ".tf", ".tfvars", ".json", ".toml", ".sh"],
    // CI service containers are thrown away after the run; example, dev, local, test and preview files use the defaults
    // on purpose, whatever their naming (field test 2026-11-20: most hits were these).
    unlessPath: /(^|\/)\.github\/|(^|\/)(integration|e2e|tests?|examples?|samples?|templates?)\/|(^|[\/._-])(example|sample|template|dev|development|local|test|testing|ci|e2e|preview|uffizzi|dusk)([._-][^\/]*)?$|(^|[\/._-])(dev|local|test|ci)[._-]/i,
    // One finding per variable per file: a fallback reused in a connection string is the same weak password.
    fileTest: (lines) => { const seen = new Set<string>(); return lines.flatMap((l, i) => { const k = defaultPasswordKey(l); if (!k || seen.has(k)) return []; seen.add(k); return [i + 1]; }); } }),
];

/** The service password variable on this line when it's set to a well-known default, else null. Pure. */
export function defaultPasswordKey(l: string): string | null {
      if (/^\s*#/.test(l)) return null;
      const v = String.raw`\s*[:=]\s*["']?`, end = String.raw`["']?\s*(?:#.*)?$`;
      const pairs: [string, string][] = [
        ["POSTGRES_PASSWORD|PGPASSWORD|DB_PASSWORD|DATABASE_PASSWORD", "postgres|password|admin|root|changeme|secret"],
        ["MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MARIADB_ROOT_PASSWORD|MARIADB_PASSWORD", "root|password|admin|mysql|changeme|secret"],
        ["MYSQL_ALLOW_EMPTY_PASSWORD|MARIADB_ALLOW_EMPTY_ROOT_PASSWORD", "yes|true|1"],
        // The password alone: the matching default username would only repeat the same account.
        ["MINIO_ROOT_PASSWORD|MINIO_SECRET_KEY", "minioadmin"],
        ["RABBITMQ_DEFAULT_PASS", "guest"],
        ["GF_SECURITY_ADMIN_PASSWORD", "admin"],
        ["ELASTIC_PASSWORD", "changeme|elastic"],
        ["MONGO_INITDB_ROOT_PASSWORD|MONGODB_ROOT_PASSWORD", "password|admin|example|mongo|root|changeme"],
        ["REDIS_PASSWORD", "redis|password|changeme"],
        ["PGADMIN_DEFAULT_PASSWORD|KEYCLOAK_ADMIN_PASSWORD|KC_BOOTSTRAP_ADMIN_PASSWORD|KEYCLOAK_PASSWORD", "admin|password|changeme"],
      ];
      // KEY=default, KEY: default, - KEY=default, ENV KEY=default, and a ${KEY:-default} fallback.
      for (const [k, d] of pairs) {
        const m = new RegExp(String.raw`(?:^|[\s"'-])(?:ENV\s+)?(${k})${v}(?:${d})${end}`, "i").exec(l) ?? new RegExp(String.raw`\$\{(${k}):?-(?:${d})\}`, "i").exec(l);
        if (m) return m[1].toUpperCase();
      }
      return null;
}
