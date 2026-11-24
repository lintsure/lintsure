---
description: "A request to fix one finding: the fix skill should show the change and wait for a yes."
tags: [fix]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Fix Lintsure finding F-003 "SQL built from a string" at src/users.ts:4.

```ts
// src/users.ts
export async function findUser(req: Request) {
  const name = new URL(req.url).searchParams.get("name");
  // line 4
  const rows = await db.query(`select id, name from users where name = '${name}'`);
  return Response.json(rows);
}
```
