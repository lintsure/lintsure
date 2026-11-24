---
description: "The flagged value is a constant: the fix skill should say so and change nothing."
tags: [fix]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Fix Lintsure finding F-007 "SQL built from a string" at src/report.ts:5.

```ts
// src/report.ts
const TABLES = { daily: "report_daily", weekly: "report_weekly" } as const;
export async function latest(kind: keyof typeof TABLES) {
  const table = TABLES[kind];
  // line 5
  return db.query(`select * from ${table} order by created_at desc limit 1`);
}
```
