// Rules added from the realistic benchmark (benchmark/corpus.mjs, "gap" cases), 2026-11-20. Same approach as the other
// rule files: patterns on a line or a file, no data flow across files, our own wording. Beta: awaiting review.
import type { Control, Rule } from "../types.js";

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
  if (/\bverifyClient\b|\borigin\b|\ballowRequest\b|\bnoServer\s*:\s*true/.test(text)) return [];
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

export const moreRules: Rule[] = [
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
    test: (l) => /\bjwt\.verify\(\s*[^,()]+,\s*[^,()]+\)/.test(l) || /\bjwt\.decode\(\s*[\w.]+\s*,\s*[\w."']+\s*\)/.test(l) }),
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
    test: (l) => /^\s*-?\s*(privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*true\b/.test(l) || /^\s*-?\s*runAsUser\s*:\s*0\s*$/.test(l) }),
  rule({ id: "docker.socket-mounted", title: "Docker socket mounted into a container", status: "partial", severity: "high", controls: [A02],
    fix: "Don't mount /var/run/docker.sock. If the container really needs Docker, point it at a separate, locked-down Docker daemon over TLS, or use a rootless or socket-proxy setup that allows only the calls it needs.",
    note: "Whatever runs in the container gets the host's Docker, and with it the whole machine: it can start a privileged container that mounts the host's disk (CWE-250). Mounting it read-only (:ro) doesn't help, because the API still works.", extensions: [".yml", ".yaml", ".json", ".sh", ""],
    unseen: "Lintsure can't tell whether this container is meant to manage Docker (a CI runner or a reverse proxy) or whether the host is a throwaway machine.",
    // A mount, not a client setting: DOCKER_HOST=unix:///var/run/docker.sock only says where to connect.
    test: (l) => /(?<!unix:\/)\/var\/run\/docker\.sock\b|\/\/\.\/pipe\/docker_engine/.test(l) && !/^\s*#|DOCKER_HOST\s*[:=]/.test(l) }),
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
