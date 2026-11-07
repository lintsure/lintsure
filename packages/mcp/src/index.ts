#!/usr/bin/env node
// Lintsure MCP server over stdio. Works with any MCP client (Claude Code, Cursor, Codex, Windsurf).
// Read-only: it never writes files. The Fixer's suggestions come back as text for your agent to apply.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";
import { ALL_FRAMEWORKS, classify, getKnowledge, rules, scan, toMarkdown, type FrameworkId } from "@lintsure/core";

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

server.tool("classify", "Suggest which frameworks apply, with a reason for each. Ask the user to confirm before checking.",
  {
    euUsers: z.boolean().optional(), personalData: z.boolean().optional(), specialCategoryData: z.boolean().optional(),
    usesAI: z.boolean().optional(), generativeAI: z.boolean().optional(), interactsWithPeople: z.boolean().optional(),
    decisionArea: z.enum(["none", "credit", "employment", "education", "essential-services", "insurance", "biometrics", "law-enforcement", "migration", "justice", "critical-infrastructure"]).optional(),
    b2bCustomers: z.boolean().optional(), wantsCertification: z.boolean().optional(), usMarket: z.boolean().optional(),
  },
  async (profile) => {
    const s = classify(profile);
    const text = s.length ? s.map((x) => `- ${x.name}: ${x.reason}`).join("\n") + "\n\nConfirm this list with the user before running scan." : "None of the available frameworks clearly apply from these answers.";
    return { content: [{ type: "text", text }] };
  });

server.tool("explain_framework", "Explain a framework in plain words: who it applies to, key dates, what it asks, and what code can and can't prove.",
  { framework: z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]]) },
  async ({ framework }) => {
    const k = getKnowledge(framework)!;
    const text = [
      `# ${k.name}`, k.summary, "", `Applies to: ${k.whoItAppliesTo}`,
      ...(k.timeline ? ["", "Key dates:", ...k.timeline.map((m) => `- ${m.date}: ${m.what}`)] : []),
      "", "What it asks:", ...k.obligations.map((o) => `- ${o.ref} ${o.title} [${o.inCode === "yes" ? "checked in code" : o.inCode === "partly" ? "partly in code" : "outside code"}]: ${o.plain}`),
      "", "Watch out:", ...k.watchOut.map((w) => `- ${w}`),
      "", `Knowledge checked on ${k.checkedOn}. Not legal advice.`,
    ].join("\n");
    return { content: [{ type: "text", text }] };
  });

await server.connect(new StdioServerTransport());
