// lintsure setup and status in a temporary project: preview writes nothing, --yes writes and backs up,
// other servers are kept, a second run changes nothing, a file with comments is left alone.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
const CLI = fileURLToPath(new URL("../packages/cli/dist/src/index.js", import.meta.url));
// The agent running these tests must not change what setup picks.
for (const k of Object.keys(process.env)) if (/^(CLAUDECODE$|GEMINI_CLI$|CURSOR_|CODEX_)/.test(k)) delete process.env[k];
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
assert.ok(shown.includes("█") && shown.includes("\x1b[38;2;98;137;254m") && shown.includes("lintsure --help") && !shown.includes("scan options:"), "terminal start screen has the Prism in its blue (#6289FE) and the short list, not the manual");
assert.ok(run("--help").startsWith("lintsure scan") && run("--help").includes("scan options:"), "--help prints the full manual and exits 0");
// Scan output: grouped and ruled for a terminal, one line per finding when piped (other tools read that form).
const SAMPLE = fileURLToPath(new URL("../fixtures/sample-app", import.meta.url));
const scanOut = (env) => execFileSync(process.execPath, [CLI, "scan", SAMPLE], { cwd: T, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "", NO_COLOR: "", ...env } });
assert.ok(/^gap +\.claude\/settings\.json:4  /m.test(scanOut({})), "piped scan keeps status, file:line and title on one line");
const term = scanOut({ FORCE_COLOR: "1", NO_COLOR: "1" });
assert.ok(/── Findings in the code \(\d+\) ─+/.test(term) && /── Repo hygiene: [^\n]+\(\d+\) ─+/.test(term) && /\n  \.claude\/settings\.json\n    GAP +4  /.test(term), "terminal scan groups findings under ruled headings, by file");
assert.ok(/Run next:\n {4}Also show the \d+ held-back findings +lintsure scan "?[^"\n]+"? --all\n/.test(term) && term.includes("lintsure baseline") && !scanOut({}).includes("Run next"), "terminal scan ends with the commands to run next; piped output does not");
assert.ok(term.includes("Lintsure found something that needs your attention.") && /── Start here \(3 of \d+\) ─+\n\n  1\. [^\n]+\n     [^\n]+:\d+\n     Fix: \S/.test(term), "terminal scan opens with a headline and ends with the first fixes");
const CLEAN = fileURLToPath(new URL("../fixtures/clean-app", import.meta.url));
const calm = execFileSync(process.execPath, [CLI, "scan", CLEAN], { cwd: T, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "1", NO_COLOR: "1" } });
assert.ok(calm.includes("Done! Nothing found by the current rules.") && !calm.includes("Start here") && !scanOut({}).includes("needs your attention"), "a clean scan says Done; piped output has no headline");
assert.ok(!term.includes("\x1b[") && term.trimEnd().split("\n").slice(-4).every((l) => l.length <= 100), "NO_COLOR drops colour; the closing note is wrapped at word ends");
// A folder that is not a project: the scan says so and how to name the project; with a marker file it says nothing.
const loose = mkdtempSync(join(tmpdir(), "ls-loose-")); writeFileSync(join(loose, "todo.txt"), "shopping list\n");
const inLoose = (...a) => spawnSync(process.execPath, [CLI, ...a], { cwd: loose, encoding: "utf8" });
const said = inLoose("scan");
assert.ok(said.stderr.includes("This folder doesn't look like a project") && said.stderr.includes("lintsure scan <folder>") && said.status === 0, "no project here: say so, say how to name one, still scan when piped");
assert.ok(!inLoose("scan", ".").stderr.includes("doesn't look like"), "a folder that was named is taken at its word");
writeFileSync(join(loose, "package.json"), "{}\n");
assert.ok(!inLoose("scan").stderr.includes("doesn't look like"), "a marker file makes it a project");
mkdirSync(join(loose, "src")); mkdirSync(join(loose, ".git"));
assert.ok(!spawnSync(process.execPath, [CLI, "scan"], { cwd: join(loose, "src"), encoding: "utf8" }).stderr.includes("doesn't look like"), "a folder inside a git repository counts");
rmSync(loose, { recursive: true, force: true });
assert.ok(spawnSync(process.execPath, [CLI, "scan", "--pick"], { encoding: "utf8" }).stderr.includes("--pick asks a question, so it needs a terminal") && shown.includes("Check another folder        lintsure scan <folder>"));
// A command typed with dashes gets a hint, not the manual.
try { run("--scan"); assert.fail("unknown command should exit 2"); } catch (e) { assert.equal(e.status, 2); assert.ok(String(e.stderr).includes("Did you mean: lintsure scan") && !String(e.stdout).includes("scan options:")); }
assert.match(run("--version"), /^\d+\.\d+\.\d+\s*$/);
// No dead ends: a typing slip gets the nearest command, a wrong value gets the valid ones, a finished setup says what to run.
const fails = (...a) => { try { run(...a); } catch (e) { return String(e.stderr) + String(e.stdout); } assert.fail(`lintsure ${a.join(" ")} should fail`); };
assert.ok(fails("scna").includes("Did you mean: lintsure scan") && fails("statsu").includes("lintsure status") && !fails("frobnicate").includes("Did you mean"));
assert.ok(fails("scan", T, "--framework", "nope").includes("Choose from: gdpr"));
assert.ok(!/usage: git|--output <file>/.test(fails("scan", T, "--diff", "no-such-branch")), "git's own usage text stays out of the --diff message");
const fresh = mkdtempSync(join(tmpdir(), "ls-nav-"));
// Codex: a TOML table is added without touching the rest of the file, found again, updated in place and taken out.
const cx = mkdtempSync(join(tmpdir(), "ls-codex-")), cfg = join(cx, ".codex/config.toml");
mkdirSync(join(cx, ".codex")); writeFileSync(cfg, "model = \"x\"\n\n[mcp_servers.other]\ncommand = \"y\"\n");
assert.ok(run("setup", cx).includes("[mcp_servers.lintsure]") && !readFileSync(cfg, "utf8").includes("lintsure"), "the Codex preview shows the table and writes nothing");
assert.match(run("setup", cx, "--yes"), /marked as trusted/);
assert.match(readFileSync(cfg, "utf8"), /^model = "x"\n\n\[mcp_servers\.other\]\ncommand = "y"\n\n\[mcp_servers\.lintsure\]\ncommand = "npx"\nargs = \["-y", "@lintsure\/mcp@\d+\.\d+\.\d+"\]\n$/);
assert.match(run("setup", cx, "--yes"), /Codex: already set up/);
writeFileSync(cfg, readFileSync(cfg, "utf8").replace(/mcp@[\d.]+/, "mcp@0.0.1") + "\n[mcp_servers.last]\ncommand = \"z\"\n");
run("setup", cx, "--yes");
assert.ok(!readFileSync(cfg, "utf8").includes("0.0.1") && readFileSync(cfg, "utf8").includes("[mcp_servers.last]"), "an older Lintsure table is updated in place; tables after it stay");
run("setup", cx, "--undo");
assert.ok(!readFileSync(cfg, "utf8").includes("lintsure") && readFileSync(cfg, "utf8").includes("[mcp_servers.other]") && readFileSync(cfg, "utf8").includes("[mcp_servers.last]"));
assert.match(run("setup", cx, "--manual"), /name +lintsure\n +command +npx\n +args +-y @lintsure\/mcp@/);
rmSync(cx, { recursive: true, force: true });
// With no agent folder and none named, setup says it is for Claude Code and how to pick another; a named agent is not told about Claude's plugin.
assert.match(run("setup", fresh), /^No agent folder in this project, so this is for Claude Code\. For another one: lintsure setup --agents cursor \| vscode \| gemini \| codex\nFor an agent set up in its own settings/);
const cursorOnly = run("setup", fresh, "--agents", "cursor", "--yes");
assert.ok(cursorOnly.includes("Then ask the agent") && !cursorOnly.includes("claude-plugin") && !cursorOnly.includes("No agent folder"));
assert.ok(run("setup", fresh, "--agents", "claude", "--yes").includes("lintsure plugin"));
run("setup", fresh, "--yes");
assert.match(run("setup", fresh, "--yes"), /already set up\n\nNothing to write\. Check the connection with: lintsure status/);
rmSync(fresh, { recursive: true, force: true });
// The menu's pure parts: arrows wrap, Home and End jump, the chosen row is marked with or without colour.
// Skills: a preview writes nothing; --yes copies them into the shared folder, and into Claude Code's only when the
// project uses it; a second run changes nothing; an older copy is backed up; --undo leaves an edited copy alone.
const sk = mkdtempSync(join(tmpdir(), "ls-skills-")), at = (...p) => join(sk, ...p);
const seen = run("skills", sk);
assert.ok(seen.includes("No project found here") && seen.includes(".agents/skills/lintsure-check  add") && seen.includes("Would install 7 skills") && seen.includes("lintsure skills --yes") && !existsSync(at(".agents")), "the skills preview lists the files and writes nothing");
assert.ok(fails("skills", sk, "--only", "nope").includes("Choose from: lintsure-setup, lintsure-check, lintsure-fix, lintsure-triage, lintsure-prelaunch, lintsure-rules, lintsure-stay-on-track"));
assert.match(run("skills", sk, "--only", "lintsure-check", "--yes"), /Done! Installed 1 skill\n.*✓ \.agents\/skills\/lintsure-check  added/);
assert.ok(/^---\r?\nname: lintsure-check\r?\n/.test(readFileSync(at(".agents/skills/lintsure-check/SKILL.md"), "utf8")) && !existsSync(at(".claude")) && !existsSync(at(".agents/skills/lintsure-prelaunch")));
mkdirSync(at(".claude")); writeFileSync(at(".agents/skills/lintsure-check/SKILL.md"), "older");
const again = run("skills", sk, "--yes");
assert.ok(again.includes("Project found: it has .agents") === false && again.includes(".claude/skills/lintsure-triage  added") && again.includes("lintsure-check  updated") && readFileSync(at(".agents/skills/lintsure-check/SKILL.md.lintsure-backup"), "utf8") === "older");
assert.ok(!/  (added|updated)/.test(run("skills", sk, "--yes")), "a second run changes nothing");
writeFileSync(at(".claude/skills/lintsure-prelaunch/SKILL.md"), "mine");
assert.ok(execFileSync(process.execPath, [at(".agents/skills/lintsure-rules/rules.mjs"), "list"], { cwd: sk, encoding: "utf8" }).includes("No rules file yet"), "the installed rules helper runs on its own");
const gone = run("skills", sk, "--undo");
assert.ok(gone.includes(".claude/skills/lintsure-prelaunch: changed since it was installed") && readFileSync(at(".claude/skills/lintsure-prelaunch/SKILL.md"), "utf8") === "mine" && !existsSync(at(".agents/skills/lintsure-triage")) && !existsSync(at(".agents/skills/lintsure-rules")) && existsSync(at(".agents/skills/lintsure-check/SKILL.md.lintsure-backup")), "undo removes Lintsure's copies and keeps an edited one and the backup");
rmSync(sk, { recursive: true, force: true });
// lintsure fix: shows the exact change first, writes it with --yes, keeps the original, and scans again.
const fx = mkdtempSync(join(tmpdir(), "ls-fix-")), fxFile = join(fx, "src/agent.ts");
mkdirSync(join(fx, "src")); writeFileSync(join(fx, "package.json"), "{}\n");
const unsafe = 'import https from "node:https";' + NL + "export const agent = new https.Agent({ rejectUnauthorized: false });" + NL;
writeFileSync(fxFile, unsafe);
const inFx = (...a) => spawnSync(process.execPath, [CLI, ...a], { cwd: fx, encoding: "utf8" });
// Observe mode: the gate says what it would have done and lets the run pass.
assert.equal(inFx("scan", ".", "--all", "--fail-on", "gap").status, 1);
const watched = inFx("scan", ".", "--all", "--fail-on", "gap", "--observe");
assert.ok(watched.status === 0 && watched.stdout.includes("Observe mode: --fail-on gap would have failed this run"), "observe mode reports and passes");
// A verdict saved in confirmed.yaml comes back on the next scan; history lists saved records.
assert.ok(inFx("history").stdout.includes("No saved records in this project yet"));
inFx("scan", ".", "--all", "--json", "--save-record");
const tls = JSON.parse(readFileSync(join(fx, "lintsure-report.json"), "utf8")).findings.find((f) => f.ruleId === "transport.tls-verify-off");
mkdirSync(join(fx, ".lintsure"), { recursive: true });
writeFileSync(join(fx, ".lintsure/confirmed.yaml"), `- rule: ${tls.ruleId}\n  fingerprint: ${tls.fingerprint}\n  confirmed_by: reviewer\n  date: 2026-11-24\n  note: the agent is used for real requests\n`);
inFx("scan", ".", "--all", "--json");
assert.deepEqual(JSON.parse(readFileSync(join(fx, "lintsure-report.json"), "utf8")).findings.find((f) => f.ruleId === "transport.tls-verify-off").confirmed, { by: "reviewer", date: "2026-11-24", note: "the agent is used for real requests" });
assert.ok(readFileSync(join(fx, "lintsure-report.md"), "utf8").includes("Confirmed as real by reviewer on 2026-11-24"));
assert.match(inFx("history").stdout, /When \(UTC\) +Findings[\s\S]*\n1 record\./);
const preview = inFx("fix", "--all");
assert.ok(preview.stdout.includes("- export const agent = new https.Agent({ rejectUnauthorized: false });") && preview.stdout.includes("Nothing changed yet") && readFileSync(fxFile, "utf8") === unsafe, "fix shows the change and writes nothing");
assert.ok(inFx("fix", "F-999").stderr.includes("No finding F-999 in this scan"));
const applied = inFx("fix", "--all", "--yes");
assert.ok(applied.stdout.includes("fixed and checked again") && !readFileSync(fxFile, "utf8").includes("rejectUnauthorized: false") && readFileSync(fxFile + ".lintsure-backup", "utf8") === unsafe, "fix --yes changes the line, keeps the original and confirms with a second scan");
assert.ok(inFx("fix", "--all").stdout.includes("No finding here has an exact change"), "nothing left to apply afterwards");
// fix --undo puts the file back as it was and clears the backup.
const undone = inFx("fix", "--undo");
assert.ok(undone.stdout.includes("back   src/agent.ts") && readFileSync(fxFile, "utf8") === unsafe && !existsSync(fxFile + ".lintsure-backup") && inFx("fix", "--undo").stdout.includes("Nothing to undo"), "fix --undo restores the original");
rmSync(fx, { recursive: true, force: true });
// lintsure deps: reads the lockfile, says what it would send, and sends nothing without --yes.
const { fromPackageLock, fromRequirements, advisories } = await import(new URL("../packages/cli/dist/src/deps.js", import.meta.url).href);
const lock = JSON.stringify({ packages: { "": { name: "app", version: "1.0.0" }, "node_modules/left-pad": { version: "1.3.0" }, "node_modules/a/node_modules/@scope/b": { version: "2.0.0" }, "node_modules/local": { link: true } } });
assert.deepEqual(fromPackageLock(lock).map((p) => `${p.name}@${p.version}`), ["left-pad@1.3.0", "@scope/b@2.0.0"], "the project itself and linked workspaces are left out");
assert.deepEqual(fromRequirements("requests==2.33.0\nflask>=2\n# note\nuvicorn[standard]==0.30.1\n").map((p) => `${p.name}@${p.version}`), ["requests@2.33.0", "uvicorn@0.30.1"], "only exact pins can be looked up");
// The lookup itself, against a stand-in for the service: what is sent holds names and versions and nothing else.
let sent = null;
const found = await advisories(fromPackageLock(lock), async (_url, init) => { sent = JSON.parse(init.body); return { ok: true, json: async () => ({ results: [{ vulns: [{ id: "GHSA-test-0001" }] }, {}] }) }; });
assert.deepEqual(sent, { queries: [{ package: { name: "left-pad", ecosystem: "npm" }, version: "1.3.0" }, { package: { name: "@scope/b", ecosystem: "npm" }, version: "2.0.0" }] });
assert.deepEqual([...found].map(([p, ids]) => `${p.name}: ${ids.join()}`), ["left-pad: GHSA-test-0001"]);
const dp = mkdtempSync(join(tmpdir(), "ls-deps-")); writeFileSync(join(dp, "package-lock.json"), lock);
const asked = spawnSync(process.execPath, [CLI, "deps", dp], { encoding: "utf8" });
assert.ok(asked.stdout.includes("about 2 packages from package-lock.json") && asked.stdout.includes("never sends code") && asked.stdout.includes("Nothing sent yet"), "deps says what it would send and waits for --yes");
rmSync(dp, { recursive: true, force: true });
// A workspace (several projects, no manifest of its own) is named as one, and the scan still runs when piped.
const ws = mkdtempSync(join(tmpdir(), "ls-ws-"));
for (const p of ["api", "web"]) { mkdirSync(join(ws, p)); writeFileSync(join(ws, p, "package.json"), "{}\n"); }
const mixed = spawnSync(process.execPath, [CLI, "scan", ws], { cwd: ws, encoding: "utf8" });
assert.ok(mixed.stderr.includes("This folder holds 2 projects (api, web)") && mixed.stderr.includes("lintsure scan <folder>") && mixed.status === 0, "a workspace is named, with how to check one project");
assert.ok(!spawnSync(process.execPath, [CLI, "scan", join(ws, "api")], { cwd: ws, encoding: "utf8" }).stderr.includes("This folder holds"), "one project inside it is a normal project");
rmSync(ws, { recursive: true, force: true });
// --staged lists only what is staged; the commit hook is shown first, written with --yes, and never replaces someone else's.
const st = mkdtempSync(join(tmpdir(), "ls-staged-")), gitIn = (...a) => execFileSync("git", a, { cwd: st, stdio: "ignore" });
const inSt = (...a) => spawnSync(process.execPath, [CLI, ...a], { cwd: st, encoding: "utf8" });
assert.ok(inSt("scan", ".", "--staged").stderr.includes("--staged needs a git repository"), "--staged outside git says so");
gitIn("init", "-q"); writeFileSync(join(st, "package.json"), "{}\n"); writeFileSync(join(st, "a.ts"), "export const x = 1;" + NL);
gitIn("add", "-A"); gitIn("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init");
writeFileSync(join(st, "a.ts"), "export const x = 1;" + NL + 'const api = fetch("http://api.example.com/data");' + NL);
assert.ok(!inSt("scan", ".", "--staged").stdout.includes("a.ts:2"), "an unstaged change is not listed");
gitIn("add", "a.ts");
const stagedOut = inSt("scan", ".", "--staged", "--fail-on", "gap");
assert.ok(stagedOut.stdout.includes("a.ts:2") && stagedOut.stdout.includes("staged changes only"), "a staged line is listed");
const hookFile = join(st, ".git/hooks/pre-commit");
assert.ok(inSt("hook").stdout.includes("Nothing written yet") && !existsSync(hookFile), "the hook is shown first");
assert.ok(inSt("hook", "--yes").stdout.includes("Each commit now checks") && readFileSync(hookFile, "utf8").includes("lintsure scan --staged --fail-on gap"));
assert.ok(inSt("hook", "--undo").stdout.includes("Removed") && !existsSync(hookFile));
writeFileSync(hookFile, "#!/bin/sh\necho mine\n");
assert.ok(inSt("hook", "--yes").stderr.includes("already has a pre-commit hook") && readFileSync(hookFile, "utf8").includes("echo mine") && inSt("hook", "--undo").stdout.includes("left alone"), "someone else's hook is never touched");
// status says whether installed skills still match the shipped ones.
assert.ok(inSt("status").stdout.includes("No Lintsure skills in this project"));
inSt("skills", "--yes");
assert.match(inSt("status").stdout, /ok +Lintsure skills: 7 installed, all current/);
writeFileSync(join(st, ".agents/skills/lintsure-check/SKILL.md"), "older");
assert.match(inSt("status").stdout, /todo +Lintsure skills: 7 installed, 1 differ from this version/);
rmSync(st, { recursive: true, force: true });
// lintsure plugin, against a stand-in plugin folder: no download and no call to the claude command.
{
  const src = join(T, "plugin-src"), proj = join(T, "plugin-proj");
  const plug = (...a) => spawnSync(process.execPath, [CLI, "plugin", proj, ...a], { encoding: "utf8", env: { ...process.env, LINTSURE_PLUGIN_SRC: src, NO_COLOR: "1" } });
  for (const d of ["hooks", "cursor", "codex", "gemini"]) mkdirSync(join(src, d), { recursive: true });
  writeFileSync(join(src, "cursor/hooks.json"), JSON.stringify({ version: 1, hooks: { sessionStart: [{ command: "node hooks/cursor.mjs remember" }], stop: [{ command: 'node "${CURSOR_PLUGIN_ROOT}/hooks/cursor.mjs" end' }] } }));
  writeFileSync(join(src, "codex/hooks.json"), JSON.stringify({ hooks: { Stop: [{ command: 'node "${CLAUDE_PLUGIN_ROOT}/hooks/agents.mjs" codex end' }] } }));
  writeFileSync(join(src, "gemini/hooks.json"), JSON.stringify({ hooks: { SessionEnd: [{ command: 'node "${extensionPath}/hooks/agents.mjs" gemini end' }] } }));
  mkdirSync(join(proj, ".gemini"), { recursive: true }); mkdirSync(join(proj, ".codex"));
  writeFileSync(join(proj, ".gemini/settings.json"), '{"theme":"dark"}');
  writeFileSync(join(proj, ".codex/hooks.json"), '{"hooks":{"Stop":[]}}');
  const all = ["--agents", "cursor,codex,gemini"], at = src.replace(/\\/g, "/");
  assert.ok(plug(...all).stdout.includes("Nothing installed yet") && !existsSync(join(proj, ".cursor")), "the plan is shown first");
  assert.ok(plug(...all, "--yes").stdout.includes("Cursor: created .cursor/hooks.json"));
  const cur = JSON.parse(readFileSync(join(proj, ".cursor/hooks.json"), "utf8")).hooks;
  assert.deepEqual([cur.sessionStart[0].command, cur.stop[0].command], [`node "${at}/hooks/cursor.mjs" remember`, `node "${at}/hooks/cursor.mjs" end`], "every command points at the plugin on this machine");
  const gem = JSON.parse(readFileSync(join(proj, ".gemini/settings.json"), "utf8"));
  assert.ok(gem.theme === "dark" && gem.hooks.SessionEnd[0].command.includes(at), "the user's own settings are kept");
  assert.equal(readFileSync(join(proj, ".codex/hooks.json"), "utf8"), '{"hooks":{"Stop":[]}}', "someone's own hooks are never changed");
  assert.ok(plug(...all, "--yes").stdout.includes("Cursor: already installed"));
  plug("--undo");
  assert.ok(!existsSync(join(proj, ".cursor/hooks.json")) && !("hooks" in JSON.parse(readFileSync(join(proj, ".gemini/settings.json"), "utf8"))) && !existsSync(join(proj, ".lintsure/guards.json")), "--undo takes out exactly what was written");
  assert.equal(plug("--agents", "nope").status, 2);
}
// Run from a folder that isn't a project, with no folder named: skills and plugin stop and say where to go, and
// setup asks which of the two ways the user wants. A home folder stands in for the user's own, so nothing real is touched.
{
  const empty = mkdtempSync(join(tmpdir(), "ls-nowhere-")), home = mkdtempSync(join(tmpdir(), "ls-home-"));
  const at = (cwd, ...a) => spawnSync(process.execPath, [CLI, ...a], { cwd, encoding: "utf8", env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" } });
  for (const c of ["skills", "plugin"]) {
    const r = at(empty, c, "--yes");
    assert.ok(r.status === 2 && r.stderr.includes("No project found in") && r.stderr.includes(`lintsure ${c} --here`), `${c} stops outside a project`);
  }
  assert.ok(!existsSync(join(empty, ".agents")) && at(empty, "skills", "--here", "--yes").status === 0 && existsSync(join(empty, ".agents/skills/lintsure-check")), "--here uses the folder anyway");
  const ask = at(empty, "setup", "--yes");
  assert.ok(ask.status === 0 && ask.stdout.includes("No project found in") && ask.stdout.includes("lintsure setup --everywhere") && ask.stdout.includes("ask them which of the two"), "outside a project, setup asks and writes nothing");
  assert.ok(!existsSync(join(empty, ".mcp.json")));
  mkdirSync(join(empty, "proj/.git"), { recursive: true });
  const inProj = at(join(empty, "proj"), "setup").stdout;
  assert.ok(inProj.includes("2. Only this project (proj)") && inProj.includes("lintsure setup --here") && !inProj.includes("No project found"), "inside a project, plain setup still asks which way");
  assert.ok(at(join(empty, "proj"), "setup", "--here").stdout.includes("Nothing written yet. To apply, run: lintsure setup --yes"));
  // Every project: the entry goes into the user's own agent settings, and --undo takes it out.
  assert.equal(at(empty, "setup", "--everywhere").status, 2, "no agent in the home folder: say so");
  mkdirSync(join(home, ".cursor")); mkdirSync(join(home, ".codex"));
  writeFileSync(join(home, ".codex/config.toml"), 'model = "x"\n');
  assert.ok(at(empty, "setup", "--everywhere").stdout.includes("To apply, run: lintsure setup --everywhere --yes") && !existsSync(join(home, ".cursor/mcp.json")));
  at(empty, "setup", "--everywhere", "--yes");
  assert.ok(JSON.parse(readFileSync(join(home, ".cursor/mcp.json"), "utf8")).mcpServers.lintsure && /model = "x"\n\n\[mcp_servers\.lintsure\]/.test(readFileSync(join(home, ".codex/config.toml"), "utf8")));
  at(empty, "setup", "--everywhere", "--undo");
  assert.ok(!existsSync(join(home, ".cursor/mcp.json")) && !readFileSync(join(home, ".codex/config.toml"), "utf8").includes("lintsure"), "--everywhere --undo takes it out");
  rmSync(empty, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true });
}
{
  const { callingAgent } = await import(new URL("../packages/cli/dist/src/agents.js", import.meta.url).href);
  assert.deepEqual([callingAgent({ CODEX_SANDBOX: "1" })?.id, callingAgent({ CLAUDECODE: "1" })?.id, callingAgent({})], ["codex", "claude", undefined]);
  const d = mkdtempSync(join(tmpdir(), "ls-caller-")), out = spawnSync(process.execPath, [CLI, "setup", d], { encoding: "utf8", env: { ...process.env, CODEX_SANDBOX: "1" } }).stdout;
  assert.ok(out.includes("running inside Codex") && out.includes(".codex/config.toml"), "setup connects the agent that ran it");
  rmSync(d, { recursive: true, force: true });
}
const { moved, frame, frameMany } = await import(new URL("../packages/cli/dist/src/menu.js", import.meta.url).href);
assert.deepEqual([moved("down", 0, 5), moved("down", 4, 5), moved("up", 0, 5), moved("end", 1, 5), moved("home", 3, 5), moved("x", 2, 5)], [1, 0, 4, 4, 0, 2]);
assert.deepEqual(frame(["a", "b"], 1, false), ["    a", "  > b"]);
assert.equal(frame(["a", "b"], 0, true)[0], "\x1b[38;2;98;137;254m  > a\x1b[0m", "chosen row is in the logo blue, not bold");
// The pick-any list: a filled circle for a picked row (green in colour), an empty one otherwise, none on closing rows.
assert.deepEqual(frameMany(["a", "b"], new Set([1]), ["Install", "Quit"], 2, false), ["    ○ a", "    ● b", "  > Install", "    Quit"]);
assert.ok(frameMany(["a"], new Set([0]), ["Quit"], 0, true)[0].includes("\x1b[32m●\x1b[0m"), "a picked row's circle is green");
const plain = start({ FORCE_COLOR: "1", NO_COLOR: "1" });
assert.ok(!plain.includes("on track and in context") && plain.includes("Give your agent skills      lintsure skills"), "the start screen has no tagline and offers the skills");
assert.ok(plain.includes("█") && !plain.includes("\x1b["), "NO_COLOR keeps the Prism and drops the colour");
assert.equal(plain.split("\n").slice(1, 16).filter((l) => /[█▀▄]/.test(l)).length, 12, "the Prism has four bands of three lines");
rmSync(T, { recursive: true, force: true });
console.log("CLI setup/status smoke test passed");
