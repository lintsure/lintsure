#!/usr/bin/env node
// Lintsure MCP server over stdio. Works with any MCP client (Claude Code, Cursor, Codex, Devin Desktop).
// Read-only: it never writes files. The Fixer's suggestions come back as text for your agent to apply.
// Every response carries the disclaimer, and the server tells the calling agent how to talk about results.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";
import { AGENT_GUIDANCE, APPROVAL_RULES, ALL_FRAMEWORKS, DISCLAIMER, classify, getKnowledge, nextSteps, readConfig, rules, scan, toMarkdown, type FrameworkId } from "@lintsure/core";

const server = new McpServer({ name: "lintsure", version: "0.3.3" }, { instructions: AGENT_GUIDANCE });
// Every tool only reads. Clients can show this; none of them may treat a Lintsure tool as making changes.
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const fw = z.array(z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]])).optional()
  .describe("Frameworks to check, for example [\"gdpr\", \"owasp-top10\"]. Leave out to use lintsure.config.yaml in the repo, or all five if there is none.");
// Every answer ends with the same disclaimer, so no tool output can be read as a verdict.
const reply = (...texts: string[]) => ({ content: [...texts, `---\n${DISCLAIMER}`].map((text) => ({ type: "text" as const, text })) });

server.tool("scan",
  "Scan a repository's source code for compliance and security gaps against the chosen frameworks. Returns a Markdown report and the same data as JSON: each finding with file, line, status (Gap or Partial), the controls it relates to, a suggested fix and a proposal the user must approve, plus work that can't be checked in code. Read-only: it never changes files. Call classify first if you don't know which frameworks apply. Results are for a person to review, never a pass, certification or decision.",
  {
    path: z.string().default(".").describe("Folder to scan, absolute or relative to where the server runs. Example: \".\" for the current project, or \"apps/web\"."),
    frameworks: fw,
  }, RO,
  async ({ path, frameworks }) => {
    const root = resolve(path);
    const cfg = (await readConfig(root)).frameworks;
    const why = frameworks ? "Chosen by the user through their coding agent." : cfg ? "Listed in lintsure.config.yaml." : undefined;
    const report = await scan(root, frameworks ?? cfg ?? ALL_FRAMEWORKS, { why, source: "mcp" });
    const steps = nextSteps(report).map((s, i) => `${i + 1}. ${s}`).join("\n");
    return reply(toMarkdown(report), JSON.stringify(report),
      `${APPROVAL_RULES}\n\nEach finding above already has its proposal (where, what, why, benefit). Ask the user which one to work on first.\n\nNext steps for the user:\n${steps}`);
  });

server.tool("explain_rule",
  "Explain one Lintsure rule in plain words: what it looks for, which framework controls it relates to (for example GDPR Art. 32 or OWASP A05), why it matters and how to fix it. Use it when the user asks about a finding from scan. Returns text; read-only.",
  { ruleId: z.string().describe("The rule id shown on a scan finding. Examples: \"pii.logged\" (personal data in logs), \"secret.in-source\", \"supabase.rls-disabled\". The full list is at lintsure.com/rules.") }, RO,
  async ({ ruleId }) => {
    const r = rules.find((x) => x.id === ruleId);
    return reply(r ? `${r.title}\nControls: ${r.controls.map((c) => `${c.framework} ${c.id}`).join(", ")}\nSuggested fix: ${r.fix}\nNote: ${r.note}\n\n${APPROVAL_RULES}` : `No rule named ${ruleId}. Rule ids look like "pii.logged"; see lintsure.com/rules.`);
  });

const yes = (what: string) => z.boolean().optional().describe(what);
server.tool("classify",
  "Suggest which compliance frameworks may apply to a product, with a short reason for each, from a few yes/no answers about it. Answer what you know and leave the rest out. Returns a list of frameworks to confirm with the user before running scan. Suggestions only: the user decides, ideally with a compliance professional. Read-only.",
  {
    euUsers: yes("True if the product has users or customers in the EU."),
    personalData: yes("True if it stores or processes data about people, such as names, emails, addresses or IP addresses."),
    specialCategoryData: yes("True if it handles sensitive data: health, biometrics, ethnicity, religion, politics, sexual orientation or union membership."),
    usesAI: yes("True if any feature uses an AI model, including third-party ones like OpenAI or Gemini."),
    generativeAI: yes("True if the AI creates text, images, audio or video that people see."),
    interactsWithPeople: yes("True if people talk or chat with the AI directly, for example a chatbot or voice assistant."),
    decisionArea: z.enum(["none", "credit", "employment", "education", "essential-services", "insurance", "biometrics", "law-enforcement", "migration", "justice", "critical-infrastructure"]).optional()
      .describe("If the AI helps decide something important about people, the area it decides in. Example: \"employment\" for screening job applicants, \"credit\" for loan scoring. Use \"none\" otherwise."),
    b2bCustomers: yes("True if it sells to businesses, whose security teams may ask for SOC 2 or ISO 27001."),
    wantsCertification: yes("True if customers or partners ask for a security certificate or report, such as ISO 27001 or a SOC 2 report."),
    usMarket: yes("True if it sells in the United States."),
  }, RO,
  async (profile) => {
    const s = classify(profile);
    return reply(s.length
      ? `These frameworks may apply, based on the answers given:\n${s.map((x) => `- ${x.name}: ${x.reason}`).join("\n")}\n\nThis is a suggestion, not a legal determination. Ask the user to confirm the list before running scan.`
      : "None of the available frameworks clearly apply from these answers. That is not a conclusion that no rules apply; ask the user, or a compliance professional, to confirm.");
  });

server.tool("explain_framework",
  "Explain a compliance framework in plain words: what it is, who it applies to, key dates (marked as already applying or upcoming), what it asks for, which parts Lintsure can check in code and which need work outside code. Use it before a scan to help the user understand what applies. Returns text; read-only.",
  { framework: z.enum(ALL_FRAMEWORKS as [FrameworkId, ...FrameworkId[]]).describe("Which framework to explain: \"eu-ai-act\", \"gdpr\", \"soc2\", \"iso-27001\" or \"owasp-top10\".") }, RO,
  async ({ framework }) => {
    const k = getKnowledge(framework)!;
    const today = new Date().toISOString().slice(0, 10);
    return reply([
      `# ${k.name}`, k.summary, "", `Applies to: ${k.whoItAppliesTo}`,
      ...(k.timeline ? ["", "Key dates:", ...k.timeline.map((m) => `- ${m.date} (${m.date <= today ? "already applies" : "upcoming"}): ${m.what}`)] : []),
      "", "What it asks:", ...k.obligations.map((o) => `- ${o.ref} ${o.title} [${o.inCode === "yes" ? "checked in code" : o.inCode === "partly" ? "partly in code" : "outside code"}]: ${o.plain}`),
      "", "Watch out:", ...k.watchOut.map((w) => `- ${w}`),
      "", `Summary in our own words, checked on ${k.checkedOn}. Read the official text for anything you rely on.`,
    ].join("\n"));
  });

await server.connect(new StdioServerTransport());
