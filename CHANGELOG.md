# Changelog

All notable changes to Lintsure. Also on the website: [lintsure.com/changelog](https://lintsure.com/changelog).

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
