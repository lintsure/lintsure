#!/usr/bin/env node
// Lintsure MCP server over stdio. Works with any MCP client (Claude Code, Cursor, Codex, Windsurf).
// Read-only: it never writes files. The Fixer's suggestions come back as text for your agent to apply.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";
import { ALL_FRAMEWORKS, rules, scan, toMarkdown, type FrameworkId } from "@lintsure/core";

const server = new McpServer({ name: "lintsure", version: "0.1.0" });
const fw = z.array(z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]])).optional()
  .describe("Frameworks to check. Default: all available.");

server.tool("scan", "Check a repo for compliance gaps. Returns findings with file, line, rules broken, fix and auditor note.",
  { path: z.string().default(".").describe("Repo path"), frameworks: fw },
  async ({ path, frameworks }) => {
    const report = await scan(resolve(path), frameworks ?? ALL_FRAMEWORKS);
    return { content: [{ type: "text", text: toMarkdown(report) }, { type: "text", text: JSON.stringify(report) }] };
  });

server.tool("explain_rule", "Explain a Lintsure rule: what it checks, which controls it maps to, and how to fix it.",
  { ruleId: z.string() },
  async ({ ruleId }) => {
    const r = rules.find((x) => x.id === ruleId);
    const text = r ? `${r.title}\nControls: ${r.controls.map((c) => `${c.framework} ${c.id}`).join(", ")}\nFix: ${r.fix}\nNote: ${r.note}` : `No rule named ${ruleId}.`;
    return { content: [{ type: "text", text }] };
  });

await server.connect(new StdioServerTransport());
