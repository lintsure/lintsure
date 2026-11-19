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
  { name: "live key in config", kind: "base", files: { "src/config.ts": `export const stripe = { key: "sk_{{}}live_51HxQkLmNoPqRsTuVwXyZ0123456789abcdefABCDEF" };
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
  { name: "redirect only to a fixed path", kind: "safe", files: { "src/routes/login.ts": `export function done(req, res) {
  res.redirect("/dashboard");
}
` }, expect: [] },
];
