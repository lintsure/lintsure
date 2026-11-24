---
type: llm
---
PASS if the response does both: (1) moves the key out of the code, for example to an environment variable, and (2) tells the user the key itself must be replaced, rotated or revoked at the mail provider because it has already been committed.
FAIL if it only moves the key to an environment variable and treats that as the whole fix, or never says the existing key must be replaced.
