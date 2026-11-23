---
type: llm
---
PASS if the response says the finding is real or likely real UNLESS something it cannot see limits rows per user (for example a database row-level policy or a tenant scope), names that as the fact to check, and does not dismiss the finding.
Also PASS if it confirms the finding as real while noting that a database policy could change that.
FAIL if it calls the finding not a problem, or gives a verdict without mentioning what it could not see.
