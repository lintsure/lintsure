// lintsure setup and status in a temporary project: preview writes nothing, --yes writes and backs up,
// other servers are kept, a second run changes nothing, a file with comments is left alone.
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
const CLI = fileURLToPath(new URL("../packages/cli/dist/src/index.js", import.meta.url));
const run = (...a) => execFileSync(process.execPath, [CLI, ...a], { encoding: "utf8" });
const T = mkdtempSync(join(tmpdir(), "ls-setup-"));
mkdirSync(join(T, ".cursor")); writeFileSync(join(T, ".cursor/mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
mkdirSync(join(T, ".vscode")); writeFileSync(join(T, ".vscode/mcp.json"), "// comment\n{}");
run("setup", T);
assert.equal(JSON.parse(readFileSync(join(T, ".cursor/mcp.json"), "utf8")).mcpServers.lintsure, undefined, "preview must not write");
const out = run("setup", T, "--yes");
assert.match(out, /isn't plain JSON/);
const cur = JSON.parse(readFileSync(join(T, ".cursor/mcp.json"), "utf8")).mcpServers;
assert.ok(cur.other && cur.lintsure.args.join(" ").match(/@lintsure\/mcp@\d+\.\d+\.\d+$/));
assert.ok(existsSync(join(T, ".cursor/mcp.json.lintsure-backup")));
assert.equal(readFileSync(join(T, ".vscode/mcp.json"), "utf8"), "// comment\n{}");
assert.match(run("setup", T, "--yes"), /Cursor: already set up/);
const doc = run("status", T);
assert.match(doc, /ok +Cursor: Lintsure MCP server/);
assert.match(doc, /ok +MCP server \d+\.\d+\.\d+ answers: \d+ tools, test call ok/);
assert.throws(() => run("setup", T, "--agents", "nope"));
// A second --yes run must not overwrite the first backup (it holds the user's original).
writeFileSync(join(T, ".cursor/mcp.json.lintsure-backup"), "ORIGINAL");
run("setup", T, "--yes");
assert.equal(readFileSync(join(T, ".cursor/mcp.json.lintsure-backup"), "utf8"), "ORIGINAL");
// --undo takes only Lintsure's entry out; other servers stay; a file Lintsure created alone is removed.
mkdirSync(join(T, ".gemini")); run("setup", T, "--agents", "gemini", "--yes");
assert.ok(existsSync(join(T, ".gemini/settings.json")));
run("setup", T, "--undo");
const after = JSON.parse(readFileSync(join(T, ".cursor/mcp.json"), "utf8")).mcpServers;
assert.ok(after.other && !after.lintsure);
assert.ok(!existsSync(join(T, ".gemini/settings.json")));
// export --otlp-json: activity log -> OpenTelemetry file, run inside the project folder; bad lines skipped.
mkdirSync(join(T, ".lintsure"), { recursive: true });
writeFileSync(join(T, ".lintsure/activity.jsonl"), [JSON.stringify({ at: "2026-11-18T09:00:00.000Z", type: "catch", kind: "made_up", file: "src/a.ts", line: 3, outcome: "caught", session: "s1" }), "not json", ""].join("\n"));
execFileSync(process.execPath, [CLI, "export", "--otlp-json", "."], { cwd: T, encoding: "utf8" });
const spans = JSON.parse(readFileSync(join(T, "lintsure.otlp.json"), "utf8")).resourceSpans[0].scopeSpans[0].spans;
assert.equal(spans.length, 2);
assert.ok(spans[1].attributes.some((a) => a.key === "gen_ai.tool.name" && a.value.stringValue === "lintsure.guard.made_up"));
assert.ok(spans.every((x) => x.traceId.length === 32 && x.spanId.length === 16));
rmSync(T, { recursive: true, force: true });
console.log("CLI setup/status smoke test passed");
