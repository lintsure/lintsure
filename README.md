<p align="center">
  <img src="https://lintsure.com/apple-touch-icon.png" width="72" height="72" alt="Lintsure logo">
</p>

<h1 align="center">Lintsure</h1>

<p align="center"><strong>Compliance checks for the code your AI writes.</strong><br>
Open source · Runs on your machine · Same input, same result</p>

<p align="center">
  <a href="https://github.com/lintsure/lintsure/actions/workflows/ci.yml"><img src="https://github.com/lintsure/lintsure/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-141413" alt="License: Apache-2.0"></a>
  <a href="https://lintsure.com/docs"><img src="https://img.shields.io/badge/docs-lintsure.com%2Fdocs-0B6E4F" alt="Docs"></a>
  <a href="https://www.npmjs.com/package/lintsure"><img src="https://img.shields.io/npm/v/lintsure?label=npm&color=141413" alt="npm version"></a>
  <a href="https://github.com/lintsure/lintsure/releases"><img src="https://img.shields.io/github/v/release/lintsure/lintsure?color=141413" alt="Latest release"></a>
  <a href="https://www.npmjs.com/package/@lintsure/mcp"><img src="https://img.shields.io/badge/MCP-@lintsure%2Fmcp-0B6E4F" alt="MCP server"></a>
  <img src="https://img.shields.io/node/v/lintsure?color=141413" alt="Node version">
  <img src="https://img.shields.io/badge/rules-Beta-B45309" alt="Rules: Beta">
</p>

> **Important: Lintsure is a readiness tool, not an audit, a certification or legal advice.**
> Its rules reflect our reading of the publicly available text of each framework, and they check **code only**. Work outside code, such as policies, training, contracts and evidence, still has to be done. Have a qualified person review the results before any audit, certification or decision. See [DISCLAIMER.md](DISCLAIMER.md).

## What it does

Lintsure reads your repository and checks it against the EU AI Act, GDPR, SOC 2 and ISO/IEC 27001. Every finding shows:

- the **file and line**
- a **status**: Gap, Partial, Met or Outside code
- **every control it touches**, across all four frameworks at once
- a **suggested fix** and a plain **auditor note**

It also lists what code can't prove (access reviews, training records, contracts) and the evidence an auditor will ask for, and can write a multi-page **assessment report** with a human review and sign-off page (`--report`).

```text
✓ 3 findings · 2 gap · 1 partial · 13 rules met · 22 outside code
partial  src/billing.ts:4  Data sent over plain HTTP
gap      src/config.ts:2   Secret or private key committed to source
gap      src/users.ts:5    Personal data written to logs
```

## Built to inform, not to decide

- **Never uploads your code.** The engine has no network code. A test fails the build if any appears.
- **Same input, same result.** The Checker is a fixed rule engine, not a language model.
- **No fake green ticks.** Only the Checker can mark a control Met, and Met only means the rules found no problem in the files they read.
- **Never decides for you.** Every report and every MCP reply ends with the disclaimer and the next steps a person still needs to take. The MCP server tells coding agents not to call you compliant, certified or ready, not to make decisions, and to ask before changing anything. Tests check that Lintsure's own wording never claims a verdict.

## Try it

> **Status: v0.1, Beta.** All rules are in Beta until their mappings are reviewed by a qualified compliance professional. 

```bash
npx lintsure scan
```

Use it inside Claude Code:

```bash
claude mcp add lintsure -- npx -y @lintsure/mcp
```

From source: `git clone`, `npm install`, `npm test`, then `node packages/cli/dist/src/index.js scan /path/to/your-app`.

Then ask: *check this repo for compliance*. Setup for Cursor, Codex and Windsurf, every CLI flag, the report format and the full rules reference are in the **[docs](https://lintsure.com/docs)**.

Run it on every pull request with **[lintsure/action](https://github.com/lintsure/action)**.

## What's inside

| Path | What |
|---|---|
| `packages/core` | Finding schema, 16 rules, framework knowledge, scan, config reader, report writer, safety wording |
| `packages/cli` | The `lintsure` command |
| `packages/mcp` | MCP server: `scan`, `classify`, `explain_framework`, `explain_rule` |
| `fixtures/` | Planted problems, near misses and a config example used by the tests |
| `scripts/mcp-smoke.mjs` | Starts the MCP server and checks every reply carries the disclaimer |

## Help Lintsure grow

Lintsure is free and built in the open. If it helped you:

- ⭐ **Star this repo**, so more teams can find it
- **Share it** with a founder or engineer who's facing an audit
- **[Send a review](https://lintsure.com/review)** if you run it at your company. Good or bad, we read every one
- **[Request a demo](https://lintsure.com/demo)** of the team platform (history, PR checks, evidence log, expert review)

## Get help

- Questions: [hello@lintsure.com](mailto:hello@lintsure.com)
- Support: [support@lintsure.com](mailto:support@lintsure.com)
- Security issues: see [SECURITY.md](SECURITY.md). Please don't open a public issue.
- Bugs and ideas: [open an issue](https://github.com/lintsure/lintsure/issues)

## What's new

See [CHANGELOG.md](CHANGELOG.md) or [lintsure.com/changelog](https://lintsure.com/changelog).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every rule needs a planted example, a near miss, and a link from the framework knowledge; `npm test` checks all of it.

## License

[Apache-2.0](LICENSE). Contributions are accepted under the [DCO](https://developercertificate.org/): sign off your commits with `git commit -s`.
