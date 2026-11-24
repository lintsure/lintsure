---
description: "Two findings from the same rule: one logs a raw email, the other logs it through a masking helper."
tags: [triage]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Lintsure reported these two findings. Which ones are real?

- F-001 gap pii.logged src/signup.ts:9 Personal data written to logs
- F-002 gap pii.logged src/reset.ts:7 Personal data written to logs

```ts
// src/signup.ts
import { logger } from "./logger";
export async function signup(req: Request) {
  const { email, name } = await req.json();
  const user = await db.users.create({ email, name });
  // line 9
  logger.info(`created account for ${email}`);
  return Response.json({ id: user.id });
}
```

```ts
// src/reset.ts
import { logger } from "./logger";
import { maskEmail } from "./mask";
export async function reset(req: Request) {
  const { email } = await req.json();
  // line 7
  logger.info(`reset requested for ${maskEmail(email)}`);
  await sendResetLink(email);
}
```

```ts
// src/mask.ts
export const maskEmail = (e: string) => e.replace(/^(.).*(@.*)$/, "$1***$2");
```
