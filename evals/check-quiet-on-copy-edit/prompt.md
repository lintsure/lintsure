---
description: A label change has no security angle: no Lintsure skill should load.
tags: [trigger]
plugins: ["../.."]
model: sonnet
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
---
Change the button label from "Sign in" to "Log in" in this component and keep everything else as it is.

```tsx
export function SubmitButton() {
  return <button type="submit" className="btn">Sign in</button>;
}
```
