# Changelog

All notable changes to Lintsure. Also on the website: [lintsure.com/changelog](https://lintsure.com/changelog).

## 0.3.4 · 2026-11-09 · Supabase and frontend secret checks

Five new rules (52 in total) for two of the most damaging mistakes in AI-built apps, open databases and secrets in the browser, and clearer MCP tool definitions (4bb46a0).

### New rules
- `supabase.rls-disabled` (Partial): a table created in a `supabase/` migration with no `enable row level security` for it in the same file. System schemas (auth, storage and so on) are skipped.
- `supabase.policy-allows-all` (Partial): `using (true)` or `with check (true)` in a Supabase policy.
- `supabase.service-key-in-client` (Gap): the service-role key referenced in a `"use client"` file.
- `secret.public-env` (Gap): secrets, or keys for AI, email, payment and database services, in browser-exposed variables (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`). Keys that are public by design (Supabase anon, Stripe publishable, Firebase, Maps) are allowed.
- `build.sourcemaps-public` (Partial): `productionBrowserSourceMaps: true` in a Next.js config.
- Tested on the 18 field-test repos before release: the first version produced 290 false alarms (Prisma and Drizzle migrations, widget and analytics keys, Vite source maps in libraries). After tightening, 4 hits, all correct.
- Rules can now be limited to a path (`pathMatch`).

### MCP tools
- Descriptions start with what the tool does, say what it returns and which tool to call first.
- Every input has a description and an example, including all ten `classify` questions.
- `explain_framework` marks each date as already applying or upcoming.

### Knowledge
- GDPR: start date (25 May 2018) added.
- OWASP Top 10: the `classify` reason no longer assumes a web app.

## 0.3.3 · 2026-11-09 · Cleaner packages

- Removes two unused files that shipped by mistake in 0.3.1 and 0.3.2: `datamap.js` in `@lintsure/core` and `browser.js` in `lintsure`. They were left over from features we've set aside for now, and nothing loaded them. The build now empties its output folders first, so old files can't slip in again (a8ef8d6).

## 0.3.2 · 2026-11-09 · Security update

- Upgrades zod to 4.6.7. Versions before 4.6.6 can use up memory when validating oversized input (GHSA-mrhx-c7xc-m3w5). Lintsure's inputs are small, so the real risk was low, but `npm audit` is now clean (4b8a19d).
- Corrects the OWASP Top 10 "checked on" date to 2026-11-08 (e16ea59).

## 0.3.1 · 2026-11-08 · Tested on 18 real repos

We ran Lintsure on 15 public apps built with Lovable, Bolt, v0 and Claude Code, and on three large AI apps (Dify, Open WebUI, LobeHub). The first run produced about 1,600 findings on the 15 small apps, and over 90% were our mistakes. This release fixes them, and every fix has a new test or benchmark case.

### Fewer false alarms
- Package rules read only `package.json`, and skip `peerDependencies`. Lockfiles and peer ranges use `"*"` on purpose (d320369, e94fdfb).
- Comments, block comments and Python docstrings aren't read as code. A real secret pasted into a comment still counts (d320369).
- Test files and fixtures are only checked for secrets, and obvious placeholders like `password="test_password"` are skipped (d320369, e94fdfb).
- Lines marked `# noqa`, `# nosec`, `// NOSONAR` or `lintsure-ignore` are treated as already reviewed (e94fdfb).
- Safe log lines such as `{ hasToken: !!token }` and `token[:8]` aren't flagged as leaking secrets (d320369).
- A JWT whose `exp` is set a few lines above `jwt.encode` isn't flagged (3e64e86).
- `CERT_NONE` listed as a settings option, a method named `eval`, `self.secret = secret`, and `pull_request_target` jobs that only run after merge are no longer flagged (e94fdfb).

### EU AI Act rules find more
- AI calls are recognised in the forms real apps use: any `*.chat.completions.create`, Gemini `generateContent`, Vercel `generateObject` and `streamObject`, LangChain `chain.invoke`, and direct calls to the OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral and DeepSeek APIs (c8c1a9c).
- "AI call with no record" needs a log or save near the call, not anywhere in the file, and reports once per file (c8c1a9c).
- "AI-generated images, audio or video" also flags AI calls in files that name an image, voice or video model (c8c1a9c).

### Also
- `glama.json` and a Dockerfile for MCP directories that run servers in a container (108c26e).

## 0.3.0 · 2026-11-08 · OWASP Top 10:2025

A fifth framework, in Beta: the OWASP Top 10:2025, covering all ten categories in our own words.

### New rules (31)
- A01 Broken Access Control: file paths from request data, open redirects, server-side request forgery, CSRF switched off, world-writable files, permissions read from cookies.
- A02 Security Misconfiguration: Django accepting any host, default or placeholder secret keys, XML parsers that load external entities.
- A03 Software Supply Chain Failures: dependencies with no version limit, install scripts that download code, unpinned third-party GitHub Actions, pull_request_target workflows that check out untrusted code.
- A04 Cryptographic Failures: predictable random numbers for secrets, weak ciphers and ECB mode, JWTs accepted without checking the signature.
- A05 Injection: shell commands built from strings, eval and new Function, HTML inserted without escaping, templates built from request data, query objects taken straight from the request.
- A06 Insecure Design: uploads with no type or size limit, whole request bodies saved to a model.
- A07 Authentication Failures: passwords in code, JWTs with no expiry.
- A08 Software or Data Integrity Failures: unsafe deserialisation, third-party scripts without integrity checks.
- A09 Security Logging and Alerting Failures: secrets in logs, raw request data in logs.
- A10 Mishandling of Exceptional Conditions: errors caught and ignored, error details sent to users.

### Also
- Eleven existing rules now also map to the OWASP categories they relate to.
- Each category lists what code can't show (for example ownership checks between users, known vulnerable dependencies, login protections, alerting) under work outside code.
- Rules that depend on request data are a Gap when request data is on the same line, and Partial otherwise.
- Every new rule has a planted example, a near miss and benchmark cases. 45 rules are now scored in the benchmark.
- Mapped to the OWASP Top 10:2025 in our own words. Not affiliated with or endorsed by the OWASP Foundation.

## 0.2.0 · 2026-11-08 · Reports you can act on, rules you can measure

### Readiness check record
- Every run produces a dated record: record id, date and time (UTC), tool and rules version, the branch and commit checked, and where it ran (CLI, MCP or CI).
- It lists what applies and why (chosen on the command line, listed in `lintsure.config.yaml`, chosen in the agent, or checked by default).
- It counts check points (one rule applied to one file), findings (Gaps), observations (Partials), accepted and fixed items, outside-code items, and open items by risk level.
- A results-by-control table shows, for every control the rules cover, which rules ran, how many check points, the result and the items behind it.
- Findings are numbered (F-001, F-002) and show their risk level. The record appears in the Markdown, JSON and HTML reports, and `--save-record` keeps a copy in `.lintsure/records/` to build a dated history.
- It is called a readiness record, not an audit, and it is a draft until a person reviews it. A test checks that audit-only terms never appear.

### Reports
- `lintsure baseline` saves today's findings to `.lintsure/baseline.json`. Every later report says what is new, fixed or unchanged.
- Accept a finding after review in `.lintsure/accepted.yaml`, with a reason, a name, a date and an optional review date. Accepted findings stay in the report but don't fail CI; past the review date they count as open again.
- Each finding has a fingerprint (a one-way hash of rule, file and line content), so moving code doesn't make old findings look new.
- `--sarif` writes `lintsure.sarif` for GitHub code scanning; `--github` prints line annotations; `--new-only` fails only on new findings.
- None of these files contain source code.

### GitHub Action
- Findings show on their lines in the pull request.
- With a baseline, only new findings fail the job (`new-only`, on by default).
- Optional SARIF output and an opt-in pull request comment that lists new findings, never code.

### Rules and accuracy
- New benchmark: labelled lines every rule must catch or must not flag. The build fails if any rule scores lower than before. Scores are on the docs Rules page.
- Personal data in logs: only the log call's own arguments are checked, so other code on the same line no longer causes false alarms.
- SQL built from strings: Gap when the inserted value looks like user input, Partial when it may be fixed text from your own code. Sentences such as "Select a plan from..." are no longer read as SQL.

## 0.1.3 · 2026-11-08 · Ask first, every time

Commit 37dd1f5.

A hard rule for every agent that uses Lintsure: explain, point, show the benefit, ask, and wait.

- Every finding now carries a proposal with four parts: where (the exact file and line), what would change, why (the problem and the controls it relates to) and the benefit. It is marked as needing approval.
- Reports show each proposal under "Proposed change. Nothing changes until you approve it."
- The MCP server tells agents to present a proposal and wait for a clear yes before any action: editing, creating or deleting files, running commands, installing packages, or treating a framework as applying. One proposal at a time.
- Every MCP tool is marked read-only for clients.
- Tests fail if a finding lacks any part of its proposal, if a report misses the approval heading, or if a scan reply misses the approval rules.

## 0.1.2 · 2026-11-07 · Listed in the MCP Registry

- `@lintsure/mcp` gains the `mcpName` field the official MCP Registry uses to confirm ownership (9617924).
- `server.json` added, and Lintsure is listed in the registry as `io.github.lintsure/lintsure`.

## 0.1.1 · 2026-11-07 · Less noise

Fewer false alarms on real projects. Running on a folder of seven projects, findings dropped from 153 to 68 with no real problem lost.

- Skips build output and caches (`.output`, `out`, `.nuxt`, `.svelte-kit`, `.astro`, `.vercel`, `.wrangler`, `.turbo`, `.cache`) and minified files (b936098)
- New `ignore:` list in `lintsure.config.yaml` to skip paths such as tests or fixtures (b936098)
- "Personal data written to logs" no longer flags words inside a message, like "email error", but still flags values put into it, like `{user.email}` (b936098)
- "TLS certificate checks turned off" only flags `verify=False` on HTTP client calls (b936098)

## 0.1.0 · 2026-11-07 · First public release

The engine, CLI, MCP server and [GitHub Action](https://github.com/lintsure/action) are open source. 16 draft rules across the EU AI Act, GDPR, SOC 2 and ISO/IEC 27001, with a human review step built into every result.

> Lintsure is a readiness tool, not an audit, a certification or legal advice. See [DISCLAIMER.md](DISCLAIMER.md).

### Engine and rules
- Core engine, CLI and MCP server, with tests that run the same input twice and expect the same result (e0d5cae)
- 8 GDPR and SOC 2 rules, each with a planted example and a near miss that must not be flagged (d4c2de7)
- 5 EU AI Act rules, and rules that can read a whole file (e6da1be)
- Plain-English knowledge of each framework, used to suggest frameworks and list work outside code (54bf93d)
- Choose frameworks with `lintsure.config.yaml` (dcfbe9c)

### Human in the loop
- Every report and every MCP reply carries the disclaimer, the work outside code and the next steps for a person (9a7860d)
- The MCP server tells coding agents not to give verdicts, not to decide, and to ask before any change (9a7860d)
- Tests fail if Lintsure's own wording claims you are compliant, certified or ready (9a7860d)

### Reports
- Multi-page assessment report with findings, possible fixes, an outside-code checklist and a human sign-off page: `lintsure scan --report` (0465c6a)
- Clearer CLI summary line (1a55089)

### Not yet
- Auditor-reviewed rule mappings
- The team platform
