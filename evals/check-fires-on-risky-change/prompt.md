---
description: A new login route that logs the password: the check skill should load.
tags: [trigger]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
I just added this login route. Is there anything I should look at before I commit?

```ts
// app/api/login/route.ts
export async function POST(req: Request) {
  const { email, password } = await req.json();
  console.log("login attempt", email, password);
  const user = await db.users.findByEmail(email);
  if (!user || user.password !== password) return new Response(null, { status: 401 });
  return Response.json({ token: sign({ id: user.id }, "dev-secret") });
}
```
