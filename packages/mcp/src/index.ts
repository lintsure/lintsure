#!/usr/bin/env node
// Lintsure MCP server over stdio. Works with any MCP client (Claude Code, Cursor, Codex, Windsurf).
// Read-only: it never writes files. The Fixer's suggestions come back as text for your agent to apply.
// Every response carries the disclaimer, and the server tells the calling agent how to talk about results.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";
import { AGENT_GUIDANCE, ALL_FRAMEWORKS, DISCLAIMER, classify, getKnowledge, nextSteps, readConfig, rules, scan, toMarkdown, type FrameworkId } from "@lintsure/core";

const server = new McpServer({ name: "lintsure", version: "0.1.1" }, { instructions: AGENT_GUIDANCE });
const fw = z.array(z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]])).optional()
  .describe("Frameworks to check. Default: lintsure.config.yaml in the repo, else all available.");
// Every answer ends with the same disclaimer, so no tool output can be read as a verdict.
const reply = (...texts: string[]) => ({ content: [...texts, `---\n${DISCLAIMER}`].map((text) => ({ type: "text" as const, text })) });

server.tool("scan", "Check a repo's code for compliance gaps. Returns findings with file, line, rules broken, fix and auditor note, plus what still needs doing outside code. Results are for a person to review; never present them as a pass, a certification or a decision.",
  { path: z.string().default(".").describe("Repo path"), frameworks: fw },
  async ({ path, frameworks }) => {
    const root = resolve(path);
    const report = await scan(root, frameworks ?? (await readConfig(root)).frameworks ?? ALL_FRAMEWORKS);
    const steps = nextSteps(report).map((s, i) => `${i + 1}. ${s}`).join("\n");
    return reply(toMarkdown(report), JSON.stringify(report), `Before acting, ask the user which findings to work on. Next steps for the user:\n${steps}`);
  });

server.tool("explain_rule", "Explain a Lintsure rule: what it checks, which controls it maps to, and how to fix it.",
  { ruleId: z.string() },
  async ({ ruleId }) => {
    const r = rules.find((x) => x.id === ruleId);
    return reply(r ? `${r.title}\nControls: ${r.controls.map((c) => `${c.framework} ${c.id}`).join(", ")}\nSuggested fix: ${r.fix}\nNote: ${r.note}\nShow the change to the user and apply it only after they approve.` : `No rule named ${ruleId}.`);
  });

server.tool("classify", "Suggest which frameworks may apply, with a reason for each. These are suggestions only: the user decides, ideally with a compliance professional.",
  {
    euUsers: z.boolean().optional(), personalData: z.boolean().optional(), specialCategoryData: z.boolean().optional(),
    usesAI: z.boolean().optional(), generativeAI: z.boolean().optional(), interactsWithPeople: z.boolean().optional(),
    decisionArea: z.enum(["none", "credit", "employment", "education", "essential-services", "insurance", "biometrics", "law-enforcement", "migration", "justice", "critical-infrastructure"]).optional(),
    b2bCustomers: z.boolean().optional(), wantsCertification: z.boolean().optional(), usMarket: z.boolean().optional(),
  },
  async (profile) => {
    const s = classify(profile);
    return reply(s.length
      ? `These frameworks may apply, based on the answers given:\n${s.map((x) => `- ${x.name}: ${x.reason}`).join("\n")}\n\nThis is a suggestion, not a legal determination. Ask the user to confirm the list before running scan.`
      : "None of the available frameworks clearly apply from these answers. That is not a conclusion that no rules apply; ask the user, or a compliance professional, to confirm.");
  });

server.tool("explain_framework", "Explain a framework in plain words: who it applies to, key dates, what it asks, and what code can and can't prove.",
  { framework: z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]]) },
  async ({ framework }) => {
    const k = getKnowledge(framework)!;
    return reply([
      `# ${k.name}`, k.summary, "", `Applies to: ${k.whoItAppliesTo}`,
      ...(k.timeline ? ["", "Key dates:", ...k.timeline.map((m) => `- ${m.date}: ${m.what}`)] : []),
      "", "What it asks:", ...k.obligations.map((o) => `- ${o.ref} ${o.title} [${o.inCode === "yes" ? "checked in code" : o.inCode === "partly" ? "partly in code" : "outside code"}]: ${o.plain}`),
      "", "Watch out:", ...k.watchOut.map((w) => `- ${w}`),
      "", `Summary in our own words, checked on ${k.checkedOn}. Read the official text for anything you rely on.`,
    ].join("\n"));
  });

await server.connect(new StdioServerTransport());
