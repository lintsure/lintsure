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

## Get started

Connect Lintsure to the coding agents this project uses. It asks a few questions (which agents, this project or every project), shows the change first and backs up any file it edits. After that, your coding agents check their own work before they say they're done:

```bash
npx lintsure setup
```

Run it in your project's folder, the one with your code in it. Somewhere else? Name the folder: `npx lintsure setup path/to/your/project`. To connect Lintsure for every project on this machine, use `npx lintsure setup --everywhere`.

Asking your agent to install it? Open your project in the agent first. If the agent starts in an empty or temporary folder, Lintsure has nothing to connect to, and it will say so.

Want a report right away instead? `npx lintsure scan` checks the project in the current folder and prints what it finds. Nothing to install, and nothing leaves your machine:

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

The plugin adds guards that work while the agent edits: Drift Guard (your project's rules, made-up imports), Danger Guard (risky shell commands), Secret Guard and Loop Guard. One command installs it for Claude Code, Cursor, Codex and Gemini CLI, and it shows what it will write first:

```bash
npx lintsure plugin
```

In Claude Code you can also add it from inside the agent:

```text
/plugin marketplace add lintsure/plugin
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

1. **Checks the code your agent writes.** 116 rules look for problems that AI-written code often has: secrets committed to source, databases without row level security, personal data written to logs, AI output used without a human check, agent configs that run remote code, and more. It reads JavaScript, TypeScript and Python, plus config and secret checks for every file.
2. **Maps each finding to the standards you connect.** Eight frameworks are built in: OWASP Top 10, the OWASP API Security Top 10, OWASP LLM Top 10, the OWASP Agentic Skills Top 10, CWE Top 25, GDPR, the EU AI Act and the EU Cyber Resilience Act. You pick which ones apply in `lintsure.config.yaml`.
3. **Keeps your agent on your rules.** The MCP server lets the agent ask which checks apply before it writes code (`plan_checks`) and scan its own work before it says it's done. The [Claude Code plugin](https://github.com/lintsure/plugin) adds Drift Guard, which holds the agent to the rules you write in `.lintsure/rules.yml`.

Every finding shows:

- the **file and line**
- a **status**: Gap, Partial, Met or Outside code
- **every control it touches**, across every framework you check
- a **suggested fix** and a plain **auditor note**

It also lists what code can't prove (access reviews, training records, contracts), and it can write a multi-page **assessment report** with a human review and sign-off page (`--report`).

**Common questions it answers:** Is there a security scanner for code written by Claude Code or Cursor? How do I stop my AI agent from committing secrets? Is there an MCP server that checks code against OWASP or GDPR? How do I make my coding agent follow project rules?

## How it connects

There are five ways to use Lintsure. They all run the same engine, on your machine or your own CI runner, and none of them sends your code anywhere. Start with the first and add the others when you want the agent to do the checking itself.

| Way | What you run | What you get |
|---|---|---|
| **CLI** | `npx lintsure scan` | A report in your terminal and in a file. It runs when you ask. |
| **MCP server** | `npx lintsure setup` | Your agent can call Lintsure itself: ask which checks apply before it writes code, scan its own work, and explain a finding. |
| **Skills** | `npx lintsure skills` | Short instructions that tell the agent when to use Lintsure and how to read what it finds. |
| **Plugin** | `npx lintsure plugin` | Guards that run on every edit and command, without anyone asking. The code lives in [lintsure/plugin](https://github.com/lintsure/plugin). |
| **GitHub Action** | `uses: lintsure/action@v1` | The same check on every pull request, with findings on the changed lines. The code lives in [lintsure/action](https://github.com/lintsure/action). |

The MCP server gives the agent a tool it can choose to use. The plugin is what makes checking happen every time.

Some agents commit and push for you without running git hooks. A check that must never be skipped belongs in CI, which is what the Action is for.

## Built to inform, not to decide

- **Never uploads your code.** The engine has no network code. A test fails the build if any appears.
- **Same input, same result.** The Checker is a fixed rule engine, not a language model.
- **No fake green ticks.** Only the Checker can mark a control Met, and Met only means the rules found no problem in the files they read.
- **Never decides for you.** Every report and every MCP reply ends with the disclaimer and the next steps a person still needs to take. The MCP server tells coding agents not to call you compliant, certified or ready, not to make decisions, and to ask before changing anything. Tests check that Lintsure's own wording never claims a verdict.

## What it doesn't do

We'd rather say this up front than have you find out later:

- **Not a pentest.** It reads source files. It doesn't run your app, send requests to a live site or test a deployed server.
- **Not a full code analyzer.** Rules are pattern checks on lines and statements, plus a few checks across files. They don't follow data through your whole program, so some findings are marked Partial for a person to confirm.
- **Not a dependency scanner.** A scan flags risky install patterns and unpinned versions, not known vulnerabilities in the packages you use. `lintsure deps` looks your pinned packages up on OSV, and only when you ask, because that one uses the network.
- **Not an audit or legal advice.** A Met control means the rules found no problem in the files they read, nothing more.

**Using it with an AI agent:** Lintsure is a defensive review of code you own. If you ask an agent to run it, say that ("review my own repo against OWASP Top 10 and fix what you find"), which describes the work accurately.

## More ways to run it

> **Status: Beta.** All rules are in Beta: their mappings are our own reading of the public texts, not independently reviewed. 

Add it to the coding agents this project uses (Claude Code, Cursor, VS Code, Gemini CLI). It shows the change first and backs up any file it edits:

```bash
npx lintsure setup          # asks: every project, or only this one
npx lintsure setup --here   # preview for this folder
npx lintsure setup --yes    # write it
npx lintsure setup --everywhere --yes   # your own agent settings, for every project
npx lintsure skills         # add skills that tell the agent when to use Lintsure
npx lintsure status         # check Node, config, rules and agents
npx lintsure deps           # look up pinned packages for known vulnerabilities (asks first: this one uses the network)
```

Or add it yourself in Claude Code: `claude mcp add lintsure -- npx -y @lintsure/mcp`.

From source: `git clone`, `npm install`, `npm test`, then `node packages/cli/dist/src/index.js scan /path/to/your-app`.

Then ask: *check this repo for compliance*. Setup for Cursor, Codex and Devin Desktop (formerly Windsurf), every CLI flag, the report format and the full rules reference are in the **[docs](https://lintsure.com/docs)**.

Run it on every pull request with **[lintsure/action](https://github.com/lintsure/action)**.

**Docs offline:** the `@lintsure/core` package includes plain Markdown docs (`docs/rules.md`, `docs/frameworks.md`, `docs/agents.md`), generated from the rules themselves, so a coding agent can read them from `node_modules/@lintsure/core/docs` without going online.

## What's inside

| Path | What |
|---|---|
| `packages/core` | Finding schema, 116 rules, framework knowledge, scan, config reader, report writer, policy fingerprint, pack loader, safety wording |
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
