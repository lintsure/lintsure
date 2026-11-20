<p align="center">
  <img src="assets/logo.svg" width="72" height="72" alt="Lintsure logo">
</p>

<h1 align="center">Lintsure</h1>

<p align="center"><strong>Keep your AI coding agents on track and in context.</strong><br>
Lintsure checks the code Claude Code, Cursor, Codex and other agents write, and holds them to your project's rules. It finds secrets in source, databases left open, made-up imports and unsafe agent settings, and maps each finding to OWASP, GDPR and the EU AI Act. It runs on your machine and never sends your code anywhere.</p>

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

## Try it

Check the project in the current folder. Nothing to install, and nothing leaves your machine:

```bash
npx lintsure scan
```

```text
! 3 open findings · 2 gap · 1 partial · 61 rules met · 30 outside code
  Read 214 files
partial  src/billing.ts:4  Data sent over plain HTTP
gap      src/config.ts:2   Secret or private key committed to source
gap      src/users.ts:5    Personal data written to logs
```

Connect it to the coding agents this project uses, so they check their own work before they say they're done. It shows the change first and backs up any file it edits:

```bash
npx lintsure setup --yes
```

In Claude Code, the plugin adds guards that work while the agent edits: Drift Guard (your project's rules, made-up imports), Danger Guard (risky shell commands), Secret Guard and Loop Guard.

```text
/plugin marketplace add lintsure/claude-plugin
/plugin install lintsure@lintsure
```

### With Docker

Scan a project with Node's official image, using the published package:

```bash
docker run --rm -v "$PWD:/work" -w /work node:22-slim npx -y lintsure scan
```

The report (`lintsure-report.md`) is written into the mounted folder. Add `--fail-on gap` to fail a CI job on clear problems.

To run the MCP server in a container, for directories and tools that start servers that way, build the image in this repo. It serves over stdio and reads the code mounted at `/workspace`:

```bash
docker build -t lintsure-mcp https://github.com/lintsure/lintsure.git
docker run -i --rm -v "$PWD:/workspace:ro" lintsure-mcp
```

> **Important: Lintsure is a readiness tool, not an audit, a certification or legal advice.**
> Its rules reflect our reading of the publicly available text of each framework, and they check **code only**. Work outside code, such as policies, training, contracts and evidence, still has to be done. Have a qualified person review the results before any audit, certification or decision. See [DISCLAIMER.md](DISCLAIMER.md).

## What it does

Lintsure sits between your AI coding agent and your codebase. It does three things:

1. **Checks the code your agent writes.** 89 rules look for problems that AI-written code often has: secrets committed to source, databases without row level security, personal data written to logs, AI output used without a human check, agent configs that run remote code, and more. It reads JavaScript, TypeScript and Python, plus config and secret checks for every file.
2. **Maps each finding to the standards you connect.** Six frameworks are built in: OWASP Top 10, OWASP LLM Top 10, CWE Top 25, GDPR, the EU AI Act and the EU Cyber Resilience Act. You pick which ones apply in `lintsure.config.yaml`.
3. **Keeps your agent on your rules.** The MCP server lets the agent ask which checks apply before it writes code (`plan_checks`) and scan its own work before it says it's done. The [Claude Code plugin](https://github.com/lintsure/claude-plugin) adds Drift Guard, which holds the agent to the rules you write in `.lintsure/rules.yml`.

Every finding shows:

- the **file and line**
- a **status**: Gap, Partial, Met or Outside code
- **every control it touches**, across every framework you check
- a **suggested fix** and a plain **auditor note**

It also lists what code can't prove (access reviews, training records, contracts), and it can write a multi-page **assessment report** with a human review and sign-off page (`--report`).

**Common questions it answers:** Is there a security scanner for code written by Claude Code or Cursor? How do I stop my AI agent from committing secrets? Is there an MCP server that checks code against OWASP or GDPR? How do I make my coding agent follow project rules?

## Built to inform, not to decide

- **Never uploads your code.** The engine has no network code. A test fails the build if any appears.
- **Same input, same result.** The Checker is a fixed rule engine, not a language model.
- **No fake green ticks.** Only the Checker can mark a control Met, and Met only means the rules found no problem in the files they read.
- **Never decides for you.** Every report and every MCP reply ends with the disclaimer and the next steps a person still needs to take. The MCP server tells coding agents not to call you compliant, certified or ready, not to make decisions, and to ask before changing anything. Tests check that Lintsure's own wording never claims a verdict.

## What it doesn't do

We'd rather say this up front than have you find out later:

- **Not a pentest.** It reads source files. It doesn't run your app, send requests to a live site or test a deployed server.
- **Not a full code analyzer.** Rules are pattern checks on lines and statements, plus a few checks across files. They don't follow data through your whole program, so some findings are marked Partial for a person to confirm.
- **Not a dependency scanner.** It flags risky install patterns and unpinned versions, not known vulnerabilities in the packages you use.
- **Not an audit or legal advice.** A Met control means the rules found no problem in the files they read, nothing more.

**Using it with an AI agent:** Lintsure is a defensive review of code you own. If you ask an agent to run it, say that ("review my own repo against OWASP Top 10 and fix what you find"), which describes the work accurately.

## More ways to run it

> **Status: Beta.** All rules are in Beta: their mappings are our own reading of the public texts, not independently reviewed. 

Add it to the coding agents this project uses (Claude Code, Cursor, VS Code, Gemini CLI). It shows the change first and backs up any file it edits:

```bash
npx lintsure setup          # preview
npx lintsure setup --yes    # write it
npx lintsure status         # check Node, config, rules and agents
```

Or add it yourself in Claude Code: `claude mcp add lintsure -- npx -y @lintsure/mcp`.

From source: `git clone`, `npm install`, `npm test`, then `node packages/cli/dist/src/index.js scan /path/to/your-app`.

Then ask: *check this repo for compliance*. Setup for Cursor, Codex and Devin Desktop (formerly Windsurf), every CLI flag, the report format and the full rules reference are in the **[docs](https://lintsure.com/docs)**.

Run it on every pull request with **[lintsure/action](https://github.com/lintsure/action)**.

**Docs offline:** the `@lintsure/core` package includes plain Markdown docs (`docs/rules.md`, `docs/frameworks.md`, `docs/agents.md`), generated from the rules themselves, so a coding agent can read them from `node_modules/@lintsure/core/docs` without going online.

## What's inside

| Path | What |
|---|---|
| `packages/core` | Finding schema, 89 rules, framework knowledge, scan, config reader, report writer, policy fingerprint, pack loader, safety wording |
| `packages/cli` | The `lintsure` command: `scan`, `baseline`, `init`, `info`, `setup`, `status`, `export` |
| `packages/mcp` | MCP server: `scan`, `plan_checks`, `classify`, `explain_framework`, `explain_rule` |
| `fixtures/` | Planted problems, near misses and a config example used by the tests |
| `scripts/mcp-smoke.mjs` | Starts the MCP server: every reply carries the disclaimer, bad input is rejected, the tool list stays small |
| `scripts/cli-smoke.mjs` | `setup` and `status` in a temporary project |
| `scripts/check-sources.mjs` | Checks the real-incident links on rules still answer (run before a release) |

## Get it from the official places only

Lintsure is published only as `lintsure`, `@lintsure/core` and `@lintsure/mcp` on npm, from [github.com/lintsure](https://github.com/lintsure), and at [lintsure.com](https://lintsure.com). A security tool is a good target for lookalikes: a repo or package with a similar name is not ours.

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

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md). Our accessibility commitment, and how to report a barrier, is in [ACCESSIBILITY.md](ACCESSIBILITY.md).

## License

[Apache-2.0](LICENSE). Contributions are accepted under the [DCO](https://developercertificate.org/): sign off your commits with `git commit -s`.
