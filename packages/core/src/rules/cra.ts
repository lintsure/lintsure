// EU Cyber Resilience Act (Regulation (EU) 2024/2847), Annex I. Our own reading of the public text. Beta.
// Most of Annex I Part I is already covered by existing rules, so they get CRA tags here; the new rules
// cover what only CRA asks of a repo: a way to report vulnerabilities, a parts list (SBOM) and safe updates.
import type { Control, Rule } from "../types.js";

const DRAFT = { mappedBy: "beta", reviewedAt: "pending" };
const P1 = (l: string, title: string): Control => ({ framework: "cra", id: `Annex I Part I (2)(${l})`, title });
const P2 = (n: string, title: string): Control => ({ framework: "cra", id: `Annex I Part II (${n})`, title });
const DEFAULTS = P1("b", "Secure by default configuration"), ACCESS = P1("d", "Protection from unauthorised access"),
  CONFIDENTIAL = P1("e", "Confidentiality of data"), INTEGRITY = P1("f", "Integrity of data and programs"),
  MINIMAL = P1("g", "Data minimisation"), SURFACE = P1("j", "Limited attack surface"), LOGGING = P1("l", "Security logging");
const COMPONENTS = P2("1", "Components identified, including an SBOM"), DISCLOSURE = P2("5", "Coordinated vulnerability disclosure policy"),
  UPDATES = P2("7", "Updates distributed securely");
const A03: Control = { framework: "owasp-top10", id: "A03:2025", title: "Software Supply Chain Failures" };
const A08: Control = { framework: "owasp-top10", id: "A08:2025", title: "Software or Data Integrity Failures" };

const tag = (c: Control, ids: string[]) => Object.fromEntries(ids.map((id) => [id, [c]]));
/** CRA controls for rules that already exist. Merged by id in rules/index.ts. */
export const craForExisting: Record<string, Control[]> = mergeTags(
  tag(DEFAULTS, ["config.debug-on", "config.allowed-hosts-any", "config.default-secret-key", "cors.any-origin", "build.sourcemaps-public", "csrf.disabled", "session.cookie-insecure"]),
  tag(ACCESS, ["auth.hardcoded-password", "jwt.unverified", "jwt.no-expiry", "supabase.rls-disabled", "supabase.policy-allows-all", "supabase.service-key-in-client", "supabase.function-no-auth", "cookie.trusted-role", "path.user-input", "fs.world-writable"]),
  tag(CONFIDENTIAL, ["transport.plain-http", "transport.tls-verify-off", "crypto.weak-cipher", "crypto.weak-password-hash", "crypto.weak-random-token", "secret.in-source", "secret.public-env"]),
  tag(INTEGRITY, ["sql.string-built", "cmd.shell-built", "code.eval", "deserialize.unsafe", "xss.raw-html", "template.user-string", "nosql.operator-input", "xml.external-entities", "mass-assignment", "html.script-no-sri"]),
  tag(MINIMAL, ["pii.logged", "pii.in-url", "pii.to-analytics"]),
  tag(SURFACE, ["ssrf.user-url", "redirect.open", "upload.unrestricted", "error.stack-to-client"]),
  tag(LOGGING, ["log.secret", "log.injection"]),
  tag(COMPONENTS, ["deps.unpinned-version", "deps.install-script"]),
  tag(UPDATES, ["ci.action-unpinned", "ci.prt-checkout-head"]),
);
function mergeTags(...maps: Record<string, Control[]>[]) {
  const out: Record<string, Control[]> = {};
  for (const m of maps) for (const [id, cs] of Object.entries(m)) (out[id] ??= []).push(...cs);
  return out;
}

// Where a security policy is usually kept; GitHub reads all three.
const POLICY = /^(\.github\/|docs\/)?security\.(md|txt|rst)$/i;
// SBOM files in CycloneDX or SPDX format, by common names.
const SBOM = /(^|\/)(sbom|bom)[\w.-]*\.(json|xml|spdx)$|\.(cdx|spdx)(\.json|\.xml)?$|\.spdx$/i;

const WORKFLOWS = /(^|\/)\.github\/workflows\//;
// Event fields anyone can set by opening an issue, pull request or comment, or naming a branch.
const UNTRUSTED = /\$\{\{\s*github\.(head_ref|event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|workflow_run)[\w.*[\]]*\.(title|body|message|label|ref|email|name|head_branch))\b/;
const BINARY = /\.(exe|dll|so|dylib|jar|class|pyc|o|a|bin|msi|apk)$/i;
const UPDATER = /^\.github\/dependabot\.ya?ml$|(^|\/)(renovate\.json5?|\.renovaterc(\.json)?)$|^\.github\/renovate\.json5?$/;
const FIXES = P2("2", "Vulnerabilities fixed without delay");

// Security scanners people wire into CI. A scan whose failure is thrown away gates nothing.
// A scanner's name inside a path (/opt/hostedtoolcache/CodeQL) is not a scan.
const SCANNER = /(?<![\/.\w-])(trivy|semgrep|gitleaks|trufflehog|snyk|grype|checkov|tfsec|bandit|osv-scanner|pip-audit|codeql|dependency-check|zap-baseline|(npm|yarn|pnpm)\s+audit|safety\s+check)\b/i;
const CI_FILES = /(^|\/)(\.github\/workflows\/|\.gitlab-ci|\.circleci\/|azure-pipelines|bitbucket-pipelines|\.buildkite\/)/;
/** CI lines where a security scan can't fail the build: `|| true`, a soft-fail flag, or continue-on-error on the scan's step. Pure. */
export function scanCannotFail(lines: string[]): number[] {
  return lines.flatMap((l, i) => {
    if (/^\s*#/.test(l)) return [];
    // Output written to a file is a report collected for a later step, not a result thrown away (review: 4 of 4).
    if (SCANNER.test(l) && /\|\|\s*(true\b|exit\s+0\b|:\s*$|echo\b)|--exit-code[= ]0\b|--soft-fail\b|--no-fail\b/.test(l)) return /\s>\s*\S/.test(l.replace(/[12]?>\s*(&1|\/dev\/null)/g, "")) ? [] : [i + 1];
    // continue-on-error belongs to a step: look a few lines either side, stopping at the next step.
    if (!/^\s*(continue-on-error|allow_failure)\s*:\s*true\b/.test(l)) return [];
    const from = lines.slice(Math.max(0, i - 6), i).reverse(), to = lines.slice(i + 1, i + 7);
    const cut = (xs: string[]) => { const k = xs.findIndex((x) => /^\s*-\s+(name|uses|run)\s*:/.test(x)); return k < 0 ? xs : xs.slice(0, k + 1); };
    const before = cut(from), after = to.slice(0, Math.max(0, to.findIndex((x) => /^\s*-\s+(name|uses|run)\s*:/.test(x)) < 0 ? to.length : to.findIndex((x) => /^\s*-\s+(name|uses|run)\s*:/.test(x))));
    // In a `uses:` line the scanner's name is part of the action's path (aquasecurity/trivy-action).
    // Uploading a report, or a step named for installing the tool, is not the scan.
    if ([...before, ...after].some((x) => /upload-sarif|^\s*-?\s*name\s*:.*\binstall/i.test(x))) return [];
    return [...before, ...after].some((x) => SCANNER.test(x) || /\buses:.*(trivy|semgrep|gitleaks|trufflehog|snyk|codeql|checkov|grype)/i.test(x)) ? [i + 1] : [];
  });
}
// Public indexes people add on purpose and that hold their own package names (GPU builds of PyTorch and friends).
const KNOWN_INDEX = /download\.pytorch\.org|pypi\.org|pypi\.nvidia\.com|test\.pypi\.org/;
/** A package source that can be swapped under you. Gap for plain HTTP or TLS checks off; Partial for a second index. Pure. */
export function unsafeSource(l: string): boolean | "partial" {
  if (/^\s*(#|\/\/)/.test(l)) return false;
  if (/(^|\s)(--index-url|-i|--extra-index-url)[= ]\s*http:\/\/(?!localhost|127\.0\.0\.1)|^\s*(@[\w-]+:)?registry\s*=\s*http:\/\/(?!localhost|127\.0\.0\.1)|^\s*(extra-)?index-url\s*=\s*http:\/\/(?!localhost|127\.0\.0\.1)/.test(l)) return true;
  if (/^\s*strict-ssl\s*=\s*false\b|\bnpm\s+config\s+set\s+strict-ssl\s+false\b/.test(l)) return true;
  if (/(^|\s)--trusted-host[= ]\s*(?!localhost|127\.0\.0\.1)\S|^\s*trusted-host\s*=\s*(?!localhost|127\.0\.0\.1)\S/.test(l)) return "partial";
  // pip takes the highest version from any index, so a public package with an internal name wins (dependency confusion).
  return /(^|\s)--extra-index-url[= ]\s*\S|^\s*extra-index-url\s*=\s*\S/.test(l) && !KNOWN_INDEX.test(l) ? "partial" : false;
}

export const craRules: Rule[] = [
  { id: "ci.scan-cannot-fail", title: "Security scan in CI that can never fail the build", status: "partial", severity: "low", controls: [UPDATES, A03],
    fix: "Let the scan fail the job. If it is too noisy, limit it to high severity or to new findings instead of ignoring its result.",
    note: "With `|| true`, a soft-fail flag or continue-on-error, the scan runs and reports but nothing stops a build that has findings, so it gives a sense of safety it doesn't deliver. Marked Partial: some teams read the report by hand on purpose.",
    extensions: [".yml", ".yaml"], pathMatch: CI_FILES, fileTest: scanCannotFail, ...DRAFT },
  { id: "deps.unsafe-source", title: "Packages fetched from a source that can be swapped", status: "gap", severity: "medium", controls: [COMPONENTS, A03, A08],
    fix: "Use one index or registry over https. For private packages, point only their scope or name at the private registry (npm: @scope:registry=..., pip: --index-url with a proxy that serves both) instead of adding a second index.",
    note: "Over plain HTTP, or with certificate checks off, anyone on the network path can serve a different package. With a second pip index, a public package that takes an internal name with a higher version is installed instead (dependency confusion, CWE-829). Partial for the second-index case: your internal names may already be reserved.",
    extensions: [".txt", ".conf", ".cfg", ".ini", ".toml", ".sh", ".bash", ".yml", ".yaml", ""],
    fileName: /^(requirements[\w.-]*\.txt|constraints[\w.-]*\.txt|pip\.(conf|ini)|\.npmrc|\.yarnrc|pyproject\.toml|setup\.cfg)$|\.(sh|bash|ya?ml)$|^(Dockerfile|Containerfile)|\.Dockerfile$/i,
    test: unsafeSource, ...DRAFT },
  { id: "repo.no-security-policy", title: "No way for people to report a vulnerability", status: "partial", severity: "medium", controls: [DISCLOSURE],
    fix: "Add a SECURITY.md to the repository root (or .github/) saying where to report a vulnerability, what to include and how soon you'll reply.",
    note: "The Cyber Resilience Act expects a policy for coordinated vulnerability disclosure and a contact address for reports. Marked Partial: the policy may live on your website, or you scanned a subfolder of a larger repo.",
    extensions: [], repoTest: (files) => (files.some((f) => POLICY.test(f)) ? null : "SECURITY.md"), ...DRAFT },
  { id: "repo.no-sbom", title: "No software bill of materials (SBOM)", status: "partial", severity: "low", controls: [COMPONENTS],
    fix: "Generate an SBOM in CycloneDX or SPDX format at release, for example with `npx @cyclonedx/cyclonedx-npm` or `syft`, and keep it with each release.",
    note: "The Cyber Resilience Act asks makers to list the components in their product, at least the top-level dependencies, in a machine-readable SBOM. Marked Partial: it may be generated in CI or at release instead of kept in the repo; if so, accept this finding with that reason.",
    extensions: [], repoTest: (files) => (files.some((f) => SBOM.test(f)) ? null : "sbom.cdx.json"), ...DRAFT },
  { id: "update.unverified-download", title: "Downloaded script run without a check", status: "partial", severity: "medium", controls: [UPDATES, A03, A08],
    fix: "Download the file first, check it against a published checksum or signature, then run it. Or install from a package manager that verifies packages.",
    note: "Piping `curl` or `wget` straight into a shell runs whatever the server sends at that moment, with no check that it is the file you expect. Marked Partial: well-known installers over HTTPS are a common, accepted risk.",
    extensions: [".sh", ".bash", ".yml", ".yaml", ""], fileName: /\.(sh|bash|ya?ml)$|^(Dockerfile|Containerfile)|\.Dockerfile$/i,
    // Quoted text is dropped first: `echo "Install via: curl ... | bash"` tells a person what to run, it runs nothing (field test).
    // A script served from this machine (a CI test of the project's own installer) or an installer pinned to a version
    // in its URL is not a moving download (0.3.9 review: 8 of 10 sampled findings were these, or prose).
    test: (l) => /\b(curl|wget)\b[^|#\n]*\|\s*(sudo\s+)?(-\S+\s+)*(ba|z|da)?sh\b/.test(l.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, '""'))
      && !/\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b/.test(l) && !/https?:\/\/\S*\/v?\d+\.\d+(\.\d+)?\/\S*install/.test(l),
    // The URL is a variable set to this machine a few lines up: BASE_URL=http://127.0.0.1:8765, then curl "$BASE_URL/get.sh" | bash.
    // shortcut: any such assignment within 8 lines counts, tie it to the variable the curl uses if that ever hides a real one.
    unlessNear: /^\s*(export\s+)?[A-Za-z_]\w*=["']?https?:\/\/(localhost|127\.0\.0\.1)\b/,
    // YAML is only run as a script in CI and compose files; elsewhere (manifests, risk registers) it is prose.
    unlessPath: /^(?!.*(\.github\/workflows|\.gitlab-ci|\.circleci|bitbucket-pipelines|azure-pipelines|\.buildkite|docker-compose|(^|\/)compose\.)).*\.ya?ml$/i, ...DRAFT },
  { id: "ci.write-all-permissions", title: "Workflow gives its token write access to everything", status: "gap", severity: "medium", controls: [UPDATES, A03],
    fix: "Replace `permissions: write-all` with only what the job needs, for example `permissions: contents: read`, and grant write access per job where it's really used.",
    note: "With write-all, any step that is compromised, including a third-party action, can push code, change releases or edit issues with the workflow's token.",
    extensions: [".yml", ".yaml"], pathMatch: WORKFLOWS, test: (l) => /^\s*permissions:\s*["']?write-all\b/.test(l),
    // A pull_request_target workflow with no permissions block at all gets the repository default, which is often write.
    fileTest: (lines) => (lines.some((l) => /^\s*permissions\s*:/.test(l)) ? [] : lines.flatMap((l, i) => (/^\s*(-\s*)?pull_request_target\b|^\s*on\s*:.*\bpull_request_target\b/.test(l) ? [{ line: i + 1, status: "partial" as const }] : []))), ...DRAFT },
  { id: "ci.script-injection", title: "Text from a pull request or issue pasted into a workflow command", status: "gap", severity: "high", controls: [UPDATES, A03, A08],
    fix: "Pass the value through an environment variable instead, for example `env: TITLE: ${{ github.event.issue.title }}` and then use \"$TITLE\" in the script.",
    note: "Anyone who opens an issue or pull request controls its title, body and branch name. Pasted into a `run:` step, that text becomes part of the shell command and can run anything with the workflow's secrets.",
    extensions: [".yml", ".yaml"], pathMatch: WORKFLOWS, fileTest: untrustedInRun, ...DRAFT },
  { id: "repo.binary-committed", title: "Compiled program committed to the repository", status: "partial", severity: "low", controls: [COMPONENTS],
    fix: "Remove the file and build it from source in CI, or download it at build time from a release with a checksum.",
    note: "Nobody can review what a compiled file does, and it isn't covered by dependency checks. Marked Partial: some projects keep a reviewed binary on purpose.",
    extensions: [], repoTest: (files) => files.find((f) => BINARY.test(f) && !/gradle-wrapper\.jar$/.test(f) && !/(^|\/)(tests?|__tests__|spec|fixtures?|__fixtures__|testdata|test-data|e2e|examples?|samples?)\//i.test(f)) ?? null, ...DRAFT },
  { id: "repo.no-dependency-updates", title: "No automated dependency updates", status: "partial", severity: "low", controls: [FIXES],
    fix: "Turn on Dependabot (add .github/dependabot.yml) or Renovate (renovate.json), so security fixes in your dependencies reach you as pull requests.",
    note: "The Cyber Resilience Act expects vulnerabilities to be fixed without delay, including in the components you use. Marked Partial: updates may be handled another way, such as a hosted setting.",
    extensions: [], repoTest: (files) => (files.some((f) => UPDATER.test(f)) ? null : ".github/dependabot.yml"), ...DRAFT },
];

/** Lines in a GitHub Actions `run:` step that paste text an outsider controls. Pure. */
export function untrustedInRun(lines: string[]): number[] {
  const out: number[] = [];
  let runIndent = -1; // indent of the `run: |` key while inside its block
  // A job that only runs for people with write access gets its PR fields from trusted authors (0.3.14 review).
  // shortcut: a step-level `if` counts for the rest of its job too, read job and step conditions apart if that misleads.
  let trusted = false;
  lines.forEach((l, i) => {
    const indent = l.search(/\S/);
    if (/^ {2}[\w-]+:\s*(#.*)?$/.test(l)) trusted = false; // next job
    if (runIndent < 0 && /author_association\s*==\s*["'](OWNER|MEMBER|COLLABORATOR)["']/.test(l)) trusted = true;
    if (trusted) { if (runIndent >= 0 && indent >= 0 && indent <= runIndent) runIndent = -1; const r = /^(\s*-?\s*)(?:run|script):\s*[|>][-+]?\s*$/.exec(l); if (r) runIndent = r[1].length; return; }
    if (runIndent >= 0 && indent >= 0 && indent <= runIndent) runIndent = -1;
    // Also `script:` in actions/github-script, where the text becomes JavaScript instead of shell (review P17).
    const run = /^(\s*-?\s*)(?:run|script):\s*(.*)$/.exec(l);
    if (run) { if (/^[|>][-+]?\s*$/.test(run[2])) { runIndent = run[1].length; return; } if (UNTRUSTED.test(run[2])) out.push(i + 1); return; }
    if (runIndent >= 0 && UNTRUSTED.test(l)) out.push(i + 1);
  });
  return out;
}
