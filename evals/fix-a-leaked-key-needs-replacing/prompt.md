---
description: "A key in the source. Moving it to an environment variable is half the fix: the key itself must be replaced."
tags: [fix, hard]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Fix Lintsure finding F-001 "Secret or private key committed to source" at src/mail.ts:2. This repo is on GitHub.

```ts
// src/mail.ts
const MAIL_API_KEY = "mk_prod_7f3a9c2e5b8d4f1a6c0e9b7d3a5f2c8e";
export const send = (to: string, body: string) => post("https://api.mailer.example/v3/send", { to, body }, MAIL_API_KEY);
```
