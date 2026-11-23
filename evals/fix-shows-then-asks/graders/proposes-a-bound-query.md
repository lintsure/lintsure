---
type: llm
---
PASS if the response shows a changed version of the query that passes `name` as a bound parameter (a placeholder such as $1 or ?, or the driver's tagged template) instead of joining it into the SQL text.
FAIL if the proposed code still joins the value into the string, or if no change is shown.
