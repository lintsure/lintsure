// Browser check smoke test: serves a page that loads a tracker before consent and ignores "Reject",
// then checks the browser check reports both. Needs Playwright: npx playwright install chromium
// Run: node scripts/browser-smoke.mjs
import { createServer } from "node:http";
import { browserCheck } from "../packages/cli/dist/src/browser.js";

const page = `<!doctype html><html><body>
<h1>Shop</h1>
<div id="banner"><p>We use cookies.</p><button onclick="document.getElementById('banner').remove()">Accept all</button>
<button onclick="localStorage.setItem('consent','no');document.getElementById('banner').remove()">Reject all</button></div>
<script>
  document.cookie = "_ga=GA1.1.123; path=/";
  fetch("https://www.google-analytics.com/g/collect?v=2").catch(() => {});
</script></body></html>`;

const server = createServer((req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(page); }).listen(0);
const url = `http://127.0.0.1:${server.address().port}/`;
const fail = (m) => { console.error("FAIL", m); server.close(); process.exit(1); };
try {
  const r = await browserCheck(url, { screenshot: "browser-smoke.png", wait: 1500 });
  const titles = r.findings.map((f) => f.title);
  if (!r.beforeConsent.trackers.includes("Google Analytics")) fail("tracker before consent not seen");
  if (!r.beforeConsent.cookies.includes("_ga")) fail("tracking cookie before consent not seen");
  if (r.rejectButton !== "Reject all") fail(`reject button not found (got ${r.rejectButton})`);
  if (!titles.includes('Trackers still load after "Reject"')) fail("tracker after reject not reported");
  if (!titles.includes("No Content-Security-Policy header")) fail("missing CSP not reported");
  console.log("ok", titles.length, "findings:", titles.join(" | "));
  console.log("Browser smoke test passed");
} catch (e) { fail(e.message); } finally { server.close(); }
