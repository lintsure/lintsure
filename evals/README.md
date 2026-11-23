# Evals for Lintsure's skills

Test cases for the seven skills in `skills/`, in the format `claude plugin eval` reads. Each case is a folder with a
`prompt.md` and one grader per file in `graders/`.

What they check:

- **A skill loads when it should.** A risky change, a launch, a request to fix a finding.
- **No skill loads when it shouldn't.** A label change, an unrelated coding task.
- **The verdict is right.** A real finding beside a look-alike that is safe; a finding that needs a fact the code doesn't show.
- **The skill keeps its promises.** It shows a change and asks first, and it never calls code compliant.

Run them from this folder. Every run is a real model call that is billed to your plan:

```
claude plugin eval . --no-publish --max-cost-usd 5
```

`node scripts/eval-check.mjs` is free. It checks that every case is well formed, that each named skill exists, and that
the regex graders pass and fail on known text. It runs as part of `npm test`.

The cases use code pasted into the prompt, so they need no MCP server and no shell.
