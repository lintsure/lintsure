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

export const moreRules: Rule[] = [
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
    test: (l) => /\btarget\s*=\s*\{?\s*["']_blank["']/.test(l) && !/\brel\s*=\s*\{?\s*["'][^"']*\bno(opener|referrer)\b/.test(l) }),
  rule({ id: "ws.no-origin-check", title: "Web-socket server with no origin check", status: "partial", severity: "medium", controls: [A01],
    fix: "Check the Origin header when a connection opens (verifyClient in ws, cors.origin or allowRequest in socket.io) and allow only your own sites.",
    note: "Browsers don't stop other sites opening a web socket to you, so a page on any site can use a signed-in visitor's cookies against it (cross-site WebSocket hijacking, CWE-1385).", extensions: JS,
    unseen: "Lintsure can't see an origin check done in a proxy or an upgrade handler in another file.",
    fileTest: wsNoOrigin }),
  rule({ id: "k8s.privileged", title: "Container runs privileged or shares the host", status: "gap", severity: "high", controls: [A02],
    fix: "Remove privileged, hostNetwork, hostPID and hostIPC, set allowPrivilegeEscalation: false, and run as a non-root user.",
    note: "A privileged container, or one sharing the host's network or processes, can take over the machine it runs on if it is broken into (CWE-250).", extensions: [".yml", ".yaml"],
    test: (l) => /^\s*-?\s*(privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*true\b/.test(l) || /^\s*-?\s*runAsUser\s*:\s*0\s*$/.test(l) }),
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
];
