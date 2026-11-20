# lintsure

**Keep your AI coding agents on track and in context.** Lintsure checks the code Claude Code, Cursor, Codex and other agents write, and holds them to your project's rules. It finds secrets in source, databases left open, unsafe agent settings, request data reaching a query or a shell, and more, and maps each finding to OWASP, GDPR and the EU AI Act. It runs on your machine and never uploads your code.

```bash
npx lintsure scan                                 # check the project in this folder
npx lintsure setup --yes                          # connect it to the coding agents this project uses
npx lintsure scan --fail-on gap                   # fail a CI job on clear problems
npx lintsure baseline                             # then later scans show only what's new
npx lintsure scan --report --project "My app"     # multi-page assessment to review and sign
npx lintsure status                               # check Node, config, rules and agents
```

```text
! 3 open findings · 2 gap · 1 partial · 61 rules met · 30 outside code
  Read 214 files
partial  src/billing.ts:4  Data sent over plain HTTP
gap      src/config.ts:2   Secret or private key committed to source
gap      src/users.ts:5    Personal data written to logs
```

Every finding shows the file and line, a suggested fix, a plain note on why it matters, and the framework controls it may affect. It also says which files it couldn't read, so "nothing found" never means "checked everything".

In Claude Code, the [plugin](https://github.com/lintsure/claude-plugin) adds guards that work while the agent edits: Drift Guard, Danger Guard, Secret Guard and Loop Guard.

With Docker: `docker run --rm -v "$PWD:/work" -w /work node:22-slim npx -y lintsure scan`

> **Lintsure is a readiness tool, not an audit, a certification or legal advice.** It checks code only, against our reading of the publicly available text of each framework. Work outside code still has to be done, and a qualified person should review the results before any audit or decision.

- Docs: https://lintsure.com/docs/cli
- Source: https://github.com/lintsure/lintsure
- Disclaimer: https://lintsure.com/disclaimer

If it helps you, please star the repo, share it, or [send a review](https://lintsure.com/review). Apache-2.0.
