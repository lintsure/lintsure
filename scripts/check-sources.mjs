// Checks that every "seen in a real incident" link on a rule still answers. Maintainer tool, run by hand before a
// release: node scripts/check-sources.mjs. The engine itself never fetches anything; this script is not shipped.
import { rules } from "../packages/core/dist/src/index.js";
let bad = 0, n = 0;
for (const r of rules) for (const s of r.seenIn ?? []) {
  n++;
  try {
    const res = await fetch(s.url, { method: "GET", redirect: "follow", headers: { "user-agent": "lintsure-source-check" }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) { bad++; console.log(`FAIL ${res.status} ${r.id}: ${s.url}`); } else console.log(`ok   ${r.id}: ${s.url}`);
  } catch (e) { bad++; console.log(`FAIL ${r.id}: ${s.url} (${e.message})`); }
  if (!/^CVE-\d{4}-\d+|\(.+\)$/.test(s.title)) { bad++; console.log(`FAIL ${r.id}: title should name the CVE or the source`); }
}
console.log(`${n} sources, ${bad} problems.`); process.exit(bad ? 1 : 0);
