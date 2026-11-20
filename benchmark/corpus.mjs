// Realistic cases for scripts/corpus.mjs: small projects run through the real scan(), not single lines.
// Each case lists the findings a good checker should give. `at` is a piece of the flagged line.
// A rule id that doesn't exist yet marks a known gap: it is counted, not failed, until the rule is built.
// `kind` groups the score: "fp" = shapes that fooled the scanner before, "hop" = request data passed through a
// variable, "gap" = attack classes with no rule yet, "safe" = the safe way to write it, "base" = plain true positives.
// Fake keys are split with {{}} so secret scanners don't mistake them for real ones.
export default [
  // ---- fp: things that are not running code ----
  { name: "guide quotes a bad prompt", kind: "fp", files: { "src/pages/guides/labels.md": `# Label AI content

Don't write prompts like this:

\`\`\`js
const system = "You are Sam, a human support agent. Never say you are an AI.";
\`\`\`

Tell people they are talking to an AI instead.
` }, expect: [] },
  { name: "guide prose describes a bad prompt", kind: "fp", files: { "src/pages/guides/ai-act.md": `# The AI Act for developers

If your AI talks with people, they must know it is an AI. A system prompt that tells the model to pose as a human breaks this.
- The checker flags prompts like "pretend to be a human" or "never reveal you are an AI".
` }, expect: [] },
  { name: "prompt file tells the AI to pose as human", kind: "base", files: { "prompts/support.md": `You are Sam from the support team.
Never reveal you are an AI. If asked, say you are a human agent.
` }, expect: [{ rule: "ai.hides-being-ai", file: "prompts/support.md", at: "Never reveal" }] },
  { name: "rule data with a fake key example", kind: "fp", files: { "src/data/rules.json": `{
  "rules": [
    { "id": "secret.in-source", "example": { "code": "export const stripeKey = \\"sk_{{}}live_FAKEFAKEFAKEFAKE0000\\";" } },
    { "id": "ai.hides-being-ai", "example": { "code": "const system = \\"Never reveal you are an AI, act human.\\";" } }
  ]
}
` }, expect: [] },
  { name: "demo diff stored as strings", kind: "fp", files: { "src/components/Demo.tsx": `const DEMO = {
  patch: [[" ", "const name = req.query.name as string;"], ["+", "  const data = fs.readFileSync(req.query.path);"]],
};
export const Demo = () => <pre>{DEMO.patch.map((p) => p.join(" ")).join("\\n")}</pre>;
` }, expect: [] },

  // ---- base: plain true positives in realistic files ----
  { name: "sql built from the request", kind: "base", files: { "src/routes/users.ts": `import { db } from "../db";
export async function getUser(req, res) {
  const rows = await db.query("SELECT * FROM users WHERE email = '" + req.query.email + "'");
  res.json(rows);
}
` }, expect: [{ rule: "sql.string-built", file: "src/routes/users.ts", at: "SELECT * FROM users" }] },
  { name: "fetch of a request url", kind: "base", files: { "src/routes/preview.ts": `export async function preview(req, res) {
  const page = await fetch(req.query.url);
  res.send(await page.text());
}
` }, expect: [{ rule: "ssrf.user-url", file: "src/routes/preview.ts", at: "fetch(req.query.url)" }] },
  { name: "flask ssrf", kind: "base", files: { "app.py": `import requests
from flask import Flask, request
app = Flask(__name__)

@app.get("/preview")
def preview():
    return requests.get(request.args["url"]).text
` }, expect: [{ rule: "ssrf.user-url", file: "app.py", at: "requests.get(request.args" }] },
  { name: "jwt alg none accepted", kind: "base", files: { "src/auth.ts": `import jwt from "jsonwebtoken";
export const read = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ["HS256", "none"] });
` }, expect: [{ rule: "jwt.unverified", file: "src/auth.ts", at: "none" }] },
  { name: "cors reflects origin with credentials", kind: "base", files: { "src/server.ts": `import express from "express";
const app = express();
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});
` }, expect: [{ rule: "cors.any-origin", file: "src/server.ts", at: "req.headers.origin" }] },
  { name: "live key in config", kind: "base", files: { "src/config.ts": `export const stripe = { key: "sk_{{}}live_51HxQkLmNo{{}}PqRsTuVwXyZ{{}}0123456789abcdefABCDEF" };
` }, expect: [{ rule: "secret.in-source", file: "src/config.ts", at: "stripe" }] },
  { name: "shell built from input", kind: "base", files: { "src/zip.ts": `import { exec } from "node:child_process";
export const zip = (req) => exec(\`zip -r out.zip \${req.body.folder}\`);
` }, expect: [{ rule: "cmd.shell-built", file: "src/zip.ts", at: "exec(" }] },

  // ---- hop: request data goes through a variable first (the most common real shape) ----
  { name: "ssrf through a variable", kind: "hop", files: { "src/routes/fetch.ts": `export async function proxy(req, res) {
  const target = req.query.url as string;
  const r = await fetch(target);
  res.send(await r.text());
}
` }, expect: [{ rule: "ssrf.user-url", file: "src/routes/fetch.ts", at: "fetch(target)" }] },
  { name: "ssrf through a template url", kind: "hop", files: { "src/routes/host.ts": `export async function ping(req, res) {
  const r = await fetch(\`\${req.query.host}/health\`);
  res.json({ ok: r.ok });
}
` }, expect: [{ rule: "ssrf.user-url", file: "src/routes/host.ts", at: "fetch(" }] },
  { name: "open redirect through a variable", kind: "hop", files: { "src/routes/login.ts": `export function done(req, res) {
  const next = req.query.next as string;
  res.redirect(next);
}
` }, expect: [{ rule: "redirect.open", file: "src/routes/login.ts", at: "res.redirect(next)" }] },
  { name: "path through path.join", kind: "hop", files: { "src/routes/files.ts": `import fs from "node:fs";
import path from "node:path";
export function file(req, res) {
  const p = path.join(__dirname, "uploads", req.params.name);
  res.send(fs.readFileSync(p));
}
` }, expect: [{ rule: "path.user-input", file: "src/routes/files.ts", at: "readFileSync(p)" }] },
  { name: "zip slip on extract", kind: "hop", files: { "unpack.py": `import zipfile

def unpack(upload, dest):
    with zipfile.ZipFile(upload) as z:
        z.extractall(dest)
` }, expect: [{ rule: "path.user-input", file: "unpack.py", at: "extractall" }] },

  // ---- gap: attack classes with no rule yet ----
  { name: "record looked up with no owner check", kind: "gap", files: { "src/routes/invoices.ts": `import { prisma } from "../db";
export async function invoice(req, res) {
  const inv = await prisma.invoice.findUnique({ where: { id: req.params.id } });
  res.json(inv);
}
` }, expect: [{ rule: "authz.no-owner-check", file: "src/routes/invoices.ts", at: "findUnique" }] },
  { name: "jwt verify without an algorithm list", kind: "gap", files: { "src/verify.ts": `import jwt from "jsonwebtoken";
export const who = (t: string) => jwt.verify(t, publicKey);
` }, expect: [{ rule: "jwt.no-algorithm-pin", file: "src/verify.ts", at: "jwt.verify" }] },
  { name: "jwt signed with a short literal secret", kind: "gap", files: { "src/sign.ts": `import jwt from "jsonwebtoken";
export const token = (id: string) => jwt.sign({ id }, "secret123", { expiresIn: "1h" });
` }, expect: [{ rule: "jwt.weak-secret", file: "src/sign.ts", at: "secret123" }] },
  { name: "deep merge of the request body", kind: "gap", files: { "src/settings.ts": `import _ from "lodash";
export function save(req, res) {
  const settings = _.merge({}, defaults, req.body);
  res.json(settings);
}
` }, expect: [{ rule: "proto.pollution", file: "src/settings.ts", at: "_.merge" }] },
  { name: "new tab link without noopener", kind: "gap", files: { "src/Footer.tsx": `export const Footer = ({ url }) => <a href={url} target="_blank">Docs</a>;
` }, expect: [{ rule: "html.tabnabbing", file: "src/Footer.tsx", at: "_blank" }] },
  { name: "websocket server with no origin check", kind: "gap", files: { "src/ws.ts": `import { WebSocketServer } from "ws";
const wss = new WebSocketServer({ port: 8080 });
wss.on("connection", (s) => s.on("message", (m) => s.send(m)));
` }, expect: [{ rule: "ws.no-origin-check", file: "src/ws.ts", at: "new WebSocketServer" }] },
  { name: "privileged kubernetes pod", kind: "gap", files: { "k8s/deploy.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: api:1.2.0
          securityContext:
            privileged: true
` }, expect: [{ rule: "k8s.privileged", file: "k8s/deploy.yaml", at: "privileged: true" }] },
  { name: "public s3 bucket", kind: "gap", files: { "infra/main.tf": `resource "aws_s3_bucket_acl" "files" {
  bucket = aws_s3_bucket.files.id
  acl    = "public-read"
}
` }, expect: [{ rule: "cloud.public-bucket", file: "infra/main.tf", at: "public-read" }] },
  { name: "token compared with ==", kind: "gap", files: { "src/webhook.ts": `export function check(req) {
  return req.headers["x-signature"] == process.env.WEBHOOK_SECRET;
}
` }, expect: [{ rule: "crypto.unsafe-compare", file: "src/webhook.ts", at: "==" }] },
  { name: "graphql introspection on", kind: "gap", files: { "src/graphql.ts": `import { ApolloServer } from "@apollo/server";
export const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
` }, expect: [{ rule: "graphql.introspection", file: "src/graphql.ts", at: "introspection: true" }] },

  // ---- safe: the right way to write it; nothing should fire ----
  { name: "parameterised sql", kind: "safe", files: { "src/routes/users.ts": `import { db } from "../db";
export async function getUser(req, res) {
  const rows = await db.query("SELECT * FROM users WHERE email = $1", [req.query.email]);
  res.json(rows);
}
` }, expect: [] },
  { name: "request value only in an encoded query string", kind: "safe", files: { "src/search.ts": `export async function search(req, res) {
  const r = await fetch(\`https://api.example.com/v1/search?q=\${encodeURIComponent(req.query.q)}\`);
  res.json(await r.json());
}
` }, expect: [] },
  { name: "jwt verify with a pinned algorithm", kind: "safe", files: { "src/auth.ts": `import jwt from "jsonwebtoken";
export const read = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { algorithms: ["HS256"] });
` }, expect: [] },
  { name: "new tab link with noopener", kind: "safe", files: { "src/Footer.tsx": `export const Footer = ({ url }) => <a href={url} target="_blank" rel="noopener noreferrer">Docs</a>;
` }, expect: [] },
  { name: "path kept inside its folder", kind: "safe", files: { "src/routes/files.ts": `import fs from "node:fs";
import path from "node:path";
const ROOT = path.resolve("uploads");
export function file(req, res) {
  const p = path.resolve(ROOT, String(req.params.name));
  if (!p.startsWith(ROOT + path.sep)) return res.status(400).end();
  res.send(fs.readFileSync(p));
}
` }, expect: [] },
  { name: "secret read from the environment", kind: "safe", files: { "src/config.ts": `export const stripe = { key: process.env.STRIPE_SECRET_KEY };
` }, expect: [] },
  { name: "request url checked against an allowlist before fetch", kind: "safe", files: { "src/routes/proxy.ts": `const ALLOWED = new Set(["api.example.com"]);
export async function proxy(req, res) {
  const url = new URL(String(req.query.u));
  if (!ALLOWED.has(url.host)) return res.status(400).end();
  const r = await fetch(url);
  res.send(await r.text());
}
` }, expect: [] },
  { name: "variable holds a fixed url", kind: "safe", files: { "src/status.ts": `export async function status(req, res) {
  const target = "https://status.example.com/api";
  const r = await fetch(target);
  res.json(await r.json());
}
` }, expect: [] },
  { name: "redirect only to a fixed path", kind: "safe", files: { "src/routes/login.ts": `export function done(req, res) {
  res.redirect("/dashboard");
}
` }, expect: [] },
  // ---- rules with no cases before 2026-11-20: one plain catch and one safe version each ----
  { name: "mcp tool runs what the agent passes", kind: "base", files: { "src/server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
const server = new McpServer({ name: "ops", version: "1.0.0" });
server.registerTool("run", { description: "Run a command" }, async ({ cmd }) => ({
  content: [{ type: "text", text: execSync(cmd).toString() }],
}));
` }, expect: [{ rule: "mcp.tool-runs-shell", file: "src/server.ts", at: "execSync(cmd)" }] },
  { name: "mcp tool with no process at all", kind: "safe", files: { "src/server.ts": `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({ name: "notes", version: "1.0.0" });
const notes = new Map();
server.registerTool("save", { description: "Save a note" }, async ({ id, text }) => {
  notes.set(id, text);
  return { content: [{ type: "text", text: "saved" }] };
});
` }, expect: [] },
  { name: "mcp server shares one token across tools", kind: "base", files: { "server.py": `import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("github")
TOKEN = os.getenv("GITHUB_TOKEN")

@mcp.tool()
def list_issues(repo: str) -> str:
    return gh(repo, TOKEN)
` }, expect: [{ rule: "mcp.tool-uses-secret", file: "server.py", at: "GITHUB_TOKEN" }] },
  { name: "supabase table without row level security", kind: "base", files: { "supabase/migrations/001_init.sql": `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  body text
);
` }, expect: [{ rule: "supabase.rls-disabled", file: "supabase/migrations/001_init.sql", at: "create table public.notes" }] },
  { name: "supabase table with row level security and a policy", kind: "safe", files: { "supabase/migrations/001_init.sql": `create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users not null,
  body text
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all using (auth.uid() = user_id);
` }, expect: [] },
  { name: "edge function with the jwt check off and no auth", kind: "base", files: {
    "supabase/config.toml": `[functions.chat]
verify_jwt = false
`,
    "supabase/functions/chat/index.ts": `import OpenAI from "npm:openai";
const openai = new OpenAI({ apiKey: Deno.env.get("OPENAI_API_KEY") });
Deno.serve(async (req) => {
  const { prompt } = await req.json();
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: prompt }], max_tokens: 300 });
  return Response.json(r);
});
` }, expect: [{ rule: "supabase.function-no-auth", file: "supabase/config.toml", at: "verify_jwt = false" }, { rule: "ai.call-not-logged", file: "supabase/functions/chat/index.ts", at: "chat.completions.create" }] },
  { name: "service role key in a client component", kind: "base", files: { "src/lib/supabase-browser.ts": `"use client";
import { createClient } from "@supabase/supabase-js";
export const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
` }, expect: [{ rule: "supabase.service-key-in-client", file: "src/lib/supabase-browser.ts", at: "SUPABASE_SERVICE_ROLE_KEY" }] },
  { name: "service role key in a server route", kind: "safe", files: { "app/api/admin/route.ts": `import { createClient } from "@supabase/supabase-js";
const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export async function POST() {
  await admin.from("jobs").insert({ kind: "cleanup" });
  return Response.json({ ok: true });
}
` }, expect: [] },
  { name: "workflow puts an issue title into a shell step", kind: "base", files: { ".github/workflows/triage.yml": `name: triage
on:
  issues:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: \${{ github.event.issue.title }}"
` }, expect: [{ rule: "ci.script-injection", file: ".github/workflows/triage.yml", at: "github.event.issue.title" }] },
  { name: "workflow passes the issue title through env", kind: "safe", files: { ".github/workflows/triage.yml": `name: triage
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "New issue: $TITLE"
` }, expect: [] },
  { name: "pull_request_target checks out the pull request", kind: "base", files: { ".github/workflows/preview.yml": `name: preview
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
` }, expect: [{ rule: "ci.prt-checkout-head", file: ".github/workflows/preview.yml", at: "head.sha" }] },
  { name: "ai call with no output limit and no log", kind: "base", files: { "src/summarise.ts": `import OpenAI from "openai";
const openai = new OpenAI();
export async function summarise(text: string) {
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: text }] });
  return r.choices[0].message.content;
}
` }, expect: [{ rule: "llm.no-output-limit", file: "src/summarise.ts", at: "chat.completions.create" }, { rule: "ai.call-not-logged", file: "src/summarise.ts", at: "chat.completions.create" }] },
  { name: "ai call with a limit and a log", kind: "safe", files: { "src/summarise.ts": `import OpenAI from "openai";
import { logger } from "./logger";
const openai = new OpenAI();
export async function summarise(text: string) {
  const r = await openai.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 400, messages: [{ role: "user", content: text }] });
  logger.info("ai.summarise", { model: r.model, tokens: r.usage?.total_tokens });
  return r.choices[0].message.content;
}
` }, expect: [] },
  { name: "deploy compose keeps the default database password", kind: "base", files: { "docker-compose.yml": `services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD:-postgres}
  app:
    environment:
      DATABASE_URL: postgresql://postgres:\${POSTGRES_PASSWORD:-postgres}@db/app
  storage:
    image: minio/minio
    environment:
      MINIO_ROOT_PASSWORD: minioadmin
` }, expect: [{ rule: "config.default-service-password", file: "docker-compose.yml", at: "POSTGRES_PASSWORD: ${" }, { rule: "config.default-service-password", file: "docker-compose.yml", at: "MINIO_ROOT_PASSWORD" }] },
  { name: "default passwords in CI and local dev files", kind: "safe", files: {
    ".github/workflows/ci.yml": `jobs:
  test:
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: postgres
`,
    "docker-compose-local.yaml": `services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
`,
    "docker-compose.yml": `services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
` }, expect: [] },
  { name: "dockerfile bakes in the mysql root password", kind: "base", files: { "Dockerfile": `FROM mysql:8
ENV MYSQL_ROOT_PASSWORD=root
` }, expect: [{ rule: "config.default-service-password", file: "Dockerfile", at: "MYSQL_ROOT_PASSWORD" }] },
  { name: "torch.load named in a list of forbidden calls", kind: "fp", files: { "app/security.py": `FORBIDDEN = [
    ("torch", "load", "torch.load() is forbidden: unsafe deserialization"),
]
` }, expect: [] },
];
