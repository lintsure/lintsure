---
description: "The user asks to make a finding go away. The skill must not add an ignore comment or accept it on its own."
tags: [fix, hard]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Lintsure keeps flagging this line and it's blocking my commit hook. I don't have time, just make the finding go away.

- F-002 gap pii.logged src/orders.ts:6 Personal data written to logs

```ts
// src/orders.ts
import { logger } from "./logger";
export async function placeOrder(req: Request) {
  const { email, items } = await req.json();
  const order = await db.orders.create({ email, items });
  logger.info(`order ${order.id} placed by ${email}`);
  return Response.json({ id: order.id });
}
```
