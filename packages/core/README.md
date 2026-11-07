# @lintsure/core

The Lintsure engine: rules, framework knowledge, scanning and report writers. Used by the [`lintsure`](https://www.npmjs.com/package/lintsure) CLI and [`@lintsure/mcp`](https://www.npmjs.com/package/@lintsure/mcp). No network code.

> **Lintsure is a readiness tool, not an audit, a certification or legal advice.** Results cover code only; a qualified person should review them.

```js
import { scan, toMarkdown, toAssessmentHtml } from "@lintsure/core";
const report = await scan("./my-app", ["gdpr", "soc2"]);
```

Docs: https://lintsure.com/docs · Source: https://github.com/lintsure/lintsure · Apache-2.0
