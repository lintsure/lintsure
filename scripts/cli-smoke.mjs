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
// setup keeps the file's style: tab indent and a byte-order mark survive, and --undo keeps them too.
const BOM = String.fromCharCode(0xfeff), NL = "\n", TAB = "\t";
mkdirSync(join(T, ".gemini"), { recursive: true });
writeFileSync(join(T, ".gemini/settings.json"), BOM + "{" + NL + TAB + '"theme": "dark"' + NL + "}" + NL);
run("setup", T, "--agents", "gemini", "--yes");
const styled = readFileSync(join(T, ".gemini/settings.json"), "utf8");
assert.ok(styled.startsWith(BOM) && styled.includes(NL + TAB + '"mcpServers"'), "tab indent and BOM kept");
run("setup", T, "--agents", "gemini", "--undo");
assert.ok(readFileSync(join(T, ".gemini/settings.json"), "utf8").startsWith(BOM + "{" + NL + TAB + '"theme"'));
// --diff sees a changed file whose name has a space in it (git quotes or tab-ends such paths).
const G = join(T, "diffrepo"); mkdirSync(G);
const git = (...a) => execFileSync("git", a, { cwd: G, stdio: "ignore" });
git("init", "-q"); writeFileSync(join(G, "a b.ts"), "export const x = 1;" + NL); git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init");
writeFileSync(join(G, "a b.ts"), "export const x = 1;" + NL + 'const api = fetch("http://api.example.com/data");' + NL);
const d = execFileSync(process.execPath, [CLI, "scan", ".", "--diff", "HEAD"], { cwd: G, encoding: "utf8" });
assert.ok(d.includes("a b.ts:2"), "finding on the changed line of a path with a space");
// Start screen: plain when piped; the Prism for a terminal (FORCE_COLOR stands in for one here); no colour with NO_COLOR.
const start = (env) => execFileSync(process.execPath, [CLI], { encoding: "utf8", env: { ...process.env, FORCE_COLOR: "", NO_COLOR: "", ...env } });
assert.ok(start({}).startsWith("lintsure scan"), "piped start screen is the plain command list");
const shown = start({ FORCE_COLOR: "1" });
assert.ok(shown.includes("█") && shown.includes("\x1b[38;2;11;110;79m") && shown.includes("lintsure scan [path]"), "terminal start screen has the Prism in brand green, then the command list");
const plain = start({ FORCE_COLOR: "1", NO_COLOR: "1" });
assert.ok(plain.includes("█") && !plain.includes("\x1b["), "NO_COLOR keeps the Prism and drops the colour");
assert.equal(plain.split("\n").slice(1, 16).filter((l) => /[█▀▄]/.test(l)).length, 12, "the Prism has four bands of three lines");
rmSync(T, { recursive: true, force: true });
console.log("CLI setup/status smoke test passed");
