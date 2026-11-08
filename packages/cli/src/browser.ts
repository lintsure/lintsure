// Browser check: opens your app in a real browser on your machine and watches what it does before and
// after someone clicks "Reject" on the cookie banner, and which security headers it sends.
// It only visits the URL you give it. It reads no code and sends nothing to Lintsure.
// Needs Playwright (an optional add-on): npm i -D playwright && npx playwright install chromium
import { createRequire } from "node:module";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** Well-known analytics and advertising hosts. Self-hosted or proxied trackers won't match. */
export const TRACKERS: [RegExp, string][] = [
  [/(^|\.)google-analytics\.com$|(^|\.)analytics\.google\.com$/, "Google Analytics"],
  [/(^|\.)googletagmanager\.com$/, "Google Tag Manager"],
  [/(^|\.)doubleclick\.net$|(^|\.)googleadservices\.com$|(^|\.)googlesyndication\.com$/, "Google Ads"],
  [/(^|\.)connect\.facebook\.net$|^www\.facebook\.com$/, "Meta Pixel"],
  [/(^|\.)i\.posthog\.com$|(^|\.)posthog\.com$/, "PostHog"],
  [/(^|\.)segment\.(io|com)$/, "Segment"],
  [/(^|\.)mixpanel\.com$|(^|\.)mxpnl\.com$/, "Mixpanel"],
  [/(^|\.)amplitude\.com$/, "Amplitude"],
  [/(^|\.)hotjar\.(com|io)$/, "Hotjar"],
  [/(^|\.)clarity\.ms$/, "Microsoft Clarity"],
  [/(^|\.)bat\.bing\.com$/, "Microsoft Ads"],
  [/(^|\.)snap\.licdn\.com$|(^|\.)px\.ads\.linkedin\.com$/, "LinkedIn Insight"],
  [/(^|\.)analytics\.tiktok\.com$/, "TikTok Pixel"],
  [/(^|\.)ads-twitter\.com$|(^|\.)analytics\.twitter\.com$/, "X Pixel"],
  [/(^|\.)fullstory\.com$/, "FullStory"],
  [/(^|\.)heapanalytics\.com$|(^|\.)heap\.io$/, "Heap"],
];
/** Cookie names analytics and ad tools set. */
const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|ph_|_hj|mp_|amp_|ajs_|_clck|_clsk|_uet|li_|_ttp|_tt_)/;
const REJECT = /^\s*(reject( all)?|decline( all)?|deny( all)?|refuse( all)?|only (necessary|essential)( cookies)?|necessary (cookies )?only|use necessary cookies only|continue without accepting)\s*$/i;

export const trackerFor = (url: string): string | null => {
  try { const h = new URL(url).hostname; return TRACKERS.find(([re]) => re.test(h))?.[1] ?? null; } catch { return null; }
};

export interface BrowserFinding { severity: "high" | "medium" | "low"; title: string; detail: string; relates: string }
export interface BrowserReport {
  url: string; checkedAt: string;
  beforeConsent: { trackers: string[]; cookies: string[] };
  rejectButton: string | null;
  afterReject: { trackers: string[]; cookies: string[] } | null;
  headers: Record<string, string | null>;
  findings: BrowserFinding[];
  screenshot: string;
}

const HEADERS = ["content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy", "x-frame-options"];

export async function browserCheck(url: string, opts: { screenshot: string; wait?: number }): Promise<BrowserReport> {
  let pw: typeof import("playwright");
  // npx runs Lintsure from its own cache, so look for Playwright in the user's project first.
  const fromProject = async () => import(pathToFileURL(createRequire(join(process.cwd(), "package.json")).resolve("playwright")).href);
  try { const m: any = await fromProject().catch(() => import("playwright")); pw = m.chromium ? m : m.default; if (!pw?.chromium) throw new Error(); }
  catch { throw new Error("The browser check needs Playwright, an optional add-on. Install it in your project with:\n  npm i -D playwright\n  npx playwright install chromium"); }
  const browser = await pw.chromium.launch();
  try {
    const context = await browser.newContext(); // fresh visitor: no cookies, no stored consent
    const page = await context.newPage();
    const seen = new Set<string>();
    page.on("request", (r) => { const t = trackerFor(r.url()); if (t) seen.add(t); });
    const res = await page.goto(url, { waitUntil: "load", timeout: 30000 });
    await page.waitForTimeout(opts.wait ?? 4000);
    const headers = Object.fromEntries(HEADERS.map((h) => [h, res?.headers()[h] ?? null]));
    const cookieNames = async () => (await context.cookies()).map((c) => c.name).filter((n) => TRACKING_COOKIE.test(n));
    const beforeConsent = { trackers: [...seen], cookies: await cookieNames() };
    await page.screenshot({ path: opts.screenshot });

    // Look for a reject button, the way a visitor would.
    const buttons = page.getByRole("button").or(page.getByRole("link"));
    let rejectButton: string | null = null;
    for (const b of await buttons.all()) {
      const name = ((await b.textContent()) ?? "").trim();
      if (REJECT.test(name) && await b.isVisible().catch(() => false)) { rejectButton = name; await b.click(); break; }
    }
    let afterReject: BrowserReport["afterReject"] = null;
    if (rejectButton) {
      seen.clear();
      await page.waitForTimeout(1500);
      await page.reload({ waitUntil: "load" }); // the choice should hold on the next page view
      await page.waitForTimeout(opts.wait ?? 4000);
      afterReject = { trackers: [...seen], cookies: await cookieNames() };
    }

    const findings: BrowserFinding[] = [];
    if (beforeConsent.trackers.length) findings.push({ severity: "high", title: "Trackers load before anyone agrees",
      detail: `${beforeConsent.trackers.join(", ")} loaded as soon as the page opened, before a choice was made on the cookie banner.`,
      relates: "GDPR Art. 6 and 7 (lawful basis and consent), ePrivacy Directive Art. 5(3)" });
    if (beforeConsent.cookies.length) findings.push({ severity: "high", title: "Tracking cookies set before anyone agrees",
      detail: `Cookies ${beforeConsent.cookies.join(", ")} were stored before a choice was made.`, relates: "ePrivacy Directive Art. 5(3), GDPR Art. 7" });
    if (afterReject?.trackers.length) findings.push({ severity: "high", title: "Trackers still load after \"Reject\"",
      detail: `After clicking "${rejectButton}" and reloading, ${afterReject.trackers.join(", ")} still loaded.`, relates: "GDPR Art. 7(3) (withdrawing consent), ePrivacy Directive Art. 5(3)" });
    if (!rejectButton && (beforeConsent.trackers.length || beforeConsent.cookies.length)) findings.push({ severity: "medium", title: "No clear reject button found",
      detail: "Trackers or tracking cookies are present, but no button labelled Reject, Decline or Only necessary was found on the first screen. Refusing should be as easy as accepting.",
      relates: "GDPR Art. 7(3), EDPB guidelines on consent" });
    if (!headers["content-security-policy"]) findings.push({ severity: "medium", title: "No Content-Security-Policy header", detail: "A CSP limits which scripts can run and reduces the damage of cross-site scripting.", relates: "OWASP A02:2025 Security Misconfiguration" });
    if (url.startsWith("https:") && !headers["strict-transport-security"]) findings.push({ severity: "medium", title: "No Strict-Transport-Security header", detail: "HSTS tells browsers to always use HTTPS for your site.", relates: "OWASP A02:2025, A04:2025" });
    if (!headers["x-content-type-options"]) findings.push({ severity: "low", title: "No X-Content-Type-Options header", detail: "Set it to nosniff so browsers don't guess file types.", relates: "OWASP A02:2025" });
    if (!headers["x-frame-options"] && !/frame-ancestors/.test(headers["content-security-policy"] ?? "")) findings.push({ severity: "low", title: "Page can be shown inside other sites", detail: "Without X-Frame-Options or a CSP frame-ancestors rule, other sites can embed your pages, which enables clickjacking.", relates: "OWASP A02:2025" });
    if (!headers["referrer-policy"]) findings.push({ severity: "low", title: "No Referrer-Policy header", detail: "Without it, full page addresses (which can contain personal data) may be sent to other sites.", relates: "OWASP A02:2025, GDPR Art. 32" });

    return { url, checkedAt: new Date().toISOString(), beforeConsent, rejectButton, afterReject, headers, findings, screenshot: opts.screenshot };
  } finally { await browser.close(); }
}

export function toBrowserMarkdown(r: BrowserReport): string {
  const list = (a: string[]) => (a.length ? a.join(", ") : "none");
  return [
    "# Lintsure browser check", "",
    `${r.url} · checked ${r.checkedAt.replace("T", " ").slice(0, 16)} UTC`, "",
    "> This check opened your page as a new visitor in a browser on your machine. It recognises well-known trackers by their web address, so self-hosted or proxied tools may not show up, and consent may be handled in ways it can't see. Check each finding. It is a readiness check, not legal advice.", "",
    "## What happened", "",
    `- **Before any choice:** trackers ${list(r.beforeConsent.trackers)}; tracking cookies ${list(r.beforeConsent.cookies)}`,
    `- **Reject button:** ${r.rejectButton ? `found ("${r.rejectButton}") and clicked` : "not found on the first screen"}`,
    ...(r.afterReject ? [`- **After rejecting and reloading:** trackers ${list(r.afterReject.trackers)}; tracking cookies ${list(r.afterReject.cookies)}`] : []),
    `- **Screenshot:** ${r.screenshot}`, "",
    `## Findings (${r.findings.length})`, "",
    ...(r.findings.length ? r.findings.flatMap((f) => [`### ${f.title} (${f.severity})`, "", f.detail, "", `Relates to: ${f.relates}`, ""]) : ["Nothing found by the current checks.", ""]),
    "## Security headers", "",
    ...HEADERS.map((h) => `- \`${h}\`: ${r.headers[h] ? "set" : "missing"}`), "",
  ].join("\n");
}
