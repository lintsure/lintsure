---
type: llm
---
PASS if the response calls F-001 (src/signup.ts) real or confirmed because the email is logged as it is, and calls F-002 (src/reset.ts) not a problem because the email goes through maskEmail before it is logged.
FAIL if both are called real, if both are dismissed, or if the verdicts are the wrong way round.
