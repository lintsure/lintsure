---
description: "One fact decides the finding and the code doesn't show it: the verdict should be needs a person."
tags: [triage]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Lintsure reported this. Is it real?

- F-004 partial authz.no-owner-check src/invoices.ts:5 Record loaded by id with no owner check

```ts
// src/invoices.ts
export async function getInvoice(req: Request, { params }: { params: { id: string } }) {
  const session = await requireSession(req);
  // line 5
  const invoice = await db.invoices.findById(params.id);
  return Response.json(invoice);
}
```

That is the whole file. I can't show you the database setup right now.
