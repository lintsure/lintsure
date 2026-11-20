# @lintsure/mcp

**Keep your AI coding agents on track.** Lintsure as an MCP server for Claude Code, Cursor, Codex, Devin Desktop (formerly Windsurf) and other MCP clients: the agent asks which checks apply before it writes code, and scans its own work before it says it is done. Runs on your machine over stdio, never writes files, never uploads your code.

> **Lintsure is a readiness tool, not an audit, a certification or legal advice.** It tells your coding agent not to call you compliant, certified or ready, not to decide for you, and to ask before changing anything. A person makes the final call.

```bash
claude mcp add lintsure -- npx -y @lintsure/mcp
```

Then ask your agent: *check this repo for security problems*.

Tools: `scan`, `plan_checks`, `classify`, `explain_framework`, `explain_rule`. Setup for Cursor, Codex and Devin Desktop (formerly Windsurf): https://lintsure.com/docs/mcp

Source: https://github.com/lintsure/lintsure · Apache-2.0
