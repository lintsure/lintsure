// Checks every "seen in a real incident" source on a rule: the page (or its machine-readable copy) must answer and
// contain every expected word, so a citation can't quietly drift from what it claims. Fails on any miss, and fails
// closed when a source can't be read. Maintainer tool, run by hand before a release: node scripts/check-sources.mjs
// The engine itself never fetches anything; this script is not shipped.
import { rules } from "../packages/core/dist/src/index.js";
let bad = 0, n = 0;
for (const r of rules) for (const s of r.seenIn ?? []) {
  n++;
  const problems = [];
  if (!s.expect?.length) problems.push("no expected words");
  if (!/^CVE-\d{4}-\d+/.test(s.title) && !/\(.+\)$/.test(s.title)) problems.push("title should name the CVE or the source");
  try {
    const res = await fetch(s.check ?? s.url, { redirect: "follow", headers: { "user-agent": "Mozilla/5.0 lintsure-source-check" }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) problems.push(`HTTP ${res.status}`);
    else {
      const text = (await res.text()).toLowerCase();
      const missing = (s.expect ?? []).filter((w) => !text.includes(w.toLowerCase()));
      if (missing.length) problems.push(`source doesn't mention: ${missing.join(", ")}`);
    }
  } catch (e) { problems.push(`couldn't read it (${e.message})`); }
  if (problems.length) { bad++; console.log(`FAIL ${r.id}: ${s.url}
     ${problems.join("; ")}`); } else console.log(`ok   ${r.id}: ${s.url}`);
}
console.log(`${n} sources, ${bad} failed.`); process.exit(bad || !n ? 1 : 0);
