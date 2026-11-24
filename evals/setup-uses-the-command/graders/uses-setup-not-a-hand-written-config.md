---
type: llm
---
PASS if the response points the user to the `lintsure setup` command for Cursor (for example `lintsure setup --agents cursor`), says it shows the change first and writes it with `--yes`, and does not present a hand-written config as the way to do it.
FAIL if the main answer is a JSON block to paste by hand, especially one that runs the server from an unpinned or `@latest` version, with no mention of `lintsure setup`.
