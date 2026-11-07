# Lintsure

Compliance checks for the code your AI writes.

Lintsure checks your repo against the rules that apply to you (GDPR, SOC 2, ISO/IEC 27001, the EU AI Act) and shows the **file and line**, **which rules it breaks across every framework**, **a fix**, and **an auditor note** for each finding.

- **Never uploads your code.** The engine makes no network calls. A test enforces it.
- **Same input, same result.** The Checker is a fixed rule engine, not a language model.
- **No fake green ticks.** Only the Checker can mark a control Met. What code can't prove is listed as Outside code.

> A readiness tool, not an audit or legal advice.

> **Status: early (v0.1).** Three draft rules. Rule mappings are pending auditor review. Not published to npm yet.

## Use it

```bash
# terminal
npx lintsure scan
npx lintsure scan ./my-app --framework gdpr,soc2 --json --fail-on gap

# Claude Code
claude mcp add lintsure -- npx -y @lintsure/mcp
```

Then ask your agent: *"check this repo for compliance"*.

## Repo layout

| Path | What |
|---|---|
| `packages/core` | Finding schema, rules, Scout (file walk), Checker, Auditor (dedupe, sort), Officer (outside-code list) |
| `packages/cli` | `lintsure scan` |
| `packages/mcp` | MCP server over stdio: `scan`, `explain_rule` |
| `fixtures/sample-app` | A tiny app with planted issues, used by tests |

## Develop

```bash
npm install
npm test            # build + tests
npm run scan:sample # run the CLI on the sample app
```

## Writing a rule

Rules live in `packages/core/src/rules/`. Each rule must have an id, title, status (`gap` or `partial`), severity, the controls it maps to in every framework, a fix, an auditor note, `mappedBy` and `reviewedAt`. Tests fail if any field is missing or if a rule tries to return `met`. A rule's `test(line)` must be pure: same line, same answer.

## License

Apache-2.0. Contributions are accepted under the [DCO](https://developercertificate.org/): sign off your commits with `git commit -s`.
