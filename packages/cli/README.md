# lintsure

Readiness checks for the code your AI writes: EU AI Act, GDPR, OWASP Top 10, OWASP LLM Top 10, CWE Top 25 and the EU Cyber Resilience Act. Runs on your machine and never uploads your code.

> **Lintsure is a readiness tool, not an audit, a certification or legal advice.** It checks code only, against our reading of the publicly available text of each framework. Work outside code still has to be done, and a qualified person should review the results before any audit or decision.

```bash
npx lintsure scan
npx lintsure scan ./my-app --framework gdpr,owasp-top10 --json --fail-on gap
npx lintsure scan --report --project "My app"   # multi-page assessment to review and sign
```

Every finding shows the file and line, the rules it may affect across all four frameworks, a suggested fix and a plain note on why it matters.

- Docs: https://lintsure.com/docs/cli
- Source: https://github.com/lintsure/lintsure
- Disclaimer: https://lintsure.com/disclaimer

If it helps you, please ⭐ the repo, share it, or [send a review](https://lintsure.com/review). Apache-2.0.
