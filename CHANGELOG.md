# Changelog

All notable changes to Lintsure. Also on the website: [lintsure.com/changelog](https://lintsure.com/changelog).

## 0.3.16 · 2026-11-24 · Two new frameworks, eight new checks, fixes you can apply

### Fewer false alarms
- **Stored lines in JSON data files are not read as running code.** A file of saved findings, review notes or samples keeps other people's lines under keys such as `text`, `context`, `excerpt`, `fix` and `note`. Checks no longer fire on those lines. A key found there is still counted and is shown with `--all`, like a key in a test file.
- **Code shown as text is not counted as code.** A log call inside a quoted string, on a page between two tags, or in a template literal with nothing filled in is text: a line drawn into an image, a slide, a code sample. A Python f-string and a template literal with `${...}` still count.
- A JSON file that quotes code registering an MCP tool is read as data: only its `description` values are checked.
- **A personal-data log line inside a development-only branch is not reported**, including a flag such as `APP_DEV === "1"` on the same line.
- **"Start here" and the headline leave test, example and data files aside.** They are still listed; they no longer lead.
- On our own workspace these took a scan from 177 findings in the code to 68, most of the rest being test cases planted on purpose.

### New
- **Three more checks:** retrieved or stored text placed in an AI's system instructions (`llm.retrieved-text-in-system-prompt`), an agent memory that is written but never deleted (`privacy.memory-no-delete`), and a Dockerfile that copies the whole project with no `.dockerignore` keeping `.env` out (`docker.copies-everything`, listed with repo hygiene).
- **More AI calls are recognised:** LiteLLM, Ollama, the Python Gemini SDK, Mistral, Bedrock, and a generator component run on its own. The AI logging and limit checks now see them.
- **`lintsure scan --staged`** lists only findings on lines staged for the next commit, and **`lintsure hook`** adds a git pre-commit hook that runs it. The hook is shown first, written with `--yes`, removed with `--undo`, and never replaces a hook of your own.
- **`lintsure fix`** applies the change for findings whose rule knows the exact one, such as a setting to flip or a line to add. It shows the change first; `--yes` writes it, backs the file up, scans again, and puts the file back if the finding is still there. Findings that need judgement stay proposals.
- **`lintsure deps`** looks up the project's pinned packages (from `package-lock.json` and `requirements.txt`) in the public OSV database. It is the only command that uses the network. It first says what it will send, package names and versions and never code, and sends it only with `--yes`. A scan stays fully local.
- **Links to the same weakness in other standards.** Rules that name a CWE number carry a link to a public catalogue that maps it across standards, in `explain_rule` and `docs/rules.md`. A link only: nothing is fetched.
- **`--observe`** with `--fail-on` says when a run would have failed and lets it pass, so a team can watch the gate before it blocks anyone.
- **`lintsure fix --undo`** puts back what the last fix changed.
- **`lintsure history`** lists the records saved with `scan --save-record`, oldest first.
- **A verdict can be kept.** A finding a reviewer read against the code and found real can be recorded in `.lintsure/confirmed.yaml`. Later scans show it as confirmed, in the terminal, the report and the JSON. The triage skill offers to write it, with your yes.
- **Repeated accepts are noticed.** When the same rule has been accepted three times or more, the next steps suggest writing that down once as a setting.
- **The pre-launch skill is now `lintsure-prelaunch`** (it was `lintsure-ship`). It is a check before launch, and other tools use "ship" for a different thing. `lintsure skills` points out an old copy.
- **A workspace is named as one.** A folder that holds several projects and is not one itself gets a notice, and from the menu a list to pick from, so findings from different projects are not mixed without warning.
- **`lintsure status` checks the skills.** It says how many are installed and whether any differ from the ones this version ships.
- **Skills go into more agent folders:** `.kiro/skills`, `.continue/skills` and `.kilocode/skills` when the project uses those agents.
- **The triage skill sorts where a value comes from** into four trust levels, and **the ship skill lists what a scan cannot see**: one customer reaching another's data, rules that differ by route, too much in a reply, steps that can be skipped, two requests at once.
- **Every rule now says what makes a finding real.** Two lists per rule: what must hold before a finding is called real, and what makes it not a problem. Sixteen rules have their own lists, written from findings reviewed against real code; the rest use the lists for their kind. The `explain_rule` tool returns them, `docs/rules.md` carries them, and the triage and fix skills work from them.
- **Evals for the seven skills.** Eleven test cases in `evals/` check that a skill loads when it should, stays out of the way when it shouldn't, tells a real finding from a look-alike, and shows a change before it applies one. They run with `claude plugin eval`; a free check of the cases themselves runs with the tests.
- **A seventh framework: the OWASP Agentic Skills Top 10.** It lists ten risks in the skills, instruction files and tool servers that coding agents load. The list is version 1.0 from an OWASP incubator project and was in public review when we mapped it. Seven of its ten risks have checks; the other three (scanning, governance, reuse across platforms) can't be seen in code and are listed as such. Use it with `--framework owasp-ast`.
- **An eighth framework: the OWASP API Security Top 10 (2023).** Twenty-six existing checks now map to it, covering seven of its ten risks. Three have no check, because they can't be read from code: abuse of business flows, old API versions left running, and how far a third-party API's answers are trusted beyond its transport. Use it with `--framework owasp-api`.
- **An admin endpoint with no access check in sight** (`authz.admin-route-no-check`). For route files that are their own endpoint (Next.js, Nuxt, SvelteKit) with `admin` in the path: Partial when the file checks no role, session or token, and the project's middleware has no check either or lets API paths through.
- **Four more new checks** (114 rules in all, with the three below):
  - a skill that tells the agent to follow a page on the internet (`skill.fetches-remote-instructions`)
  - a skill that changes the agent's own instructions or settings, such as `AGENTS.md` or `.claude/settings.json` (`skill.writes-agent-memory`)
  - a skill that is allowed any shell command (`skill.unrestricted-shell`)
  - an MCP server that listens on every network interface (`mcp.server-binds-all-interfaces`)
- All four are shown as Partial: each names what Lintsure can't see, such as whether writing to those files is the skill's stated job.
- **The agent checks read more agents.** Hook files for Codex, Copilot, Cursor on Windows and Mastra, Zed's project settings and `opencode.json` are read as agent config. Rules, steering, prompt and instruction folders are read as instructions for Kiro, Continue, Copilot, Cline, Windsurf, Roo, Kilo Code, OpenCode, Junie and others. Continue's `permissions.yaml` is read: the whole shell or every tool on its allow list is a finding.
- Existing agent checks now map to the new list too: unsafe agent instructions, agent configs that download and run code, agent permissions that allow everything, and MCP servers run from a moving version.

## 0.3.15 · 2026-11-23 · 17 new checks, fewer false alarms, a start menu, skills for any agent

### New
- **17 new checks** (106 rules in all):
  - **Agents and MCP:** an MCP tool description that gives the agent orders (`mcp.tool-description-poisoned`), and an MCP server run from a moving version or over plain HTTP (`mcp.config-unsafe-server`).
  - **CI and supply chain:** a security scan in CI that can never fail the build (`ci.scan-cannot-fail`), and packages fetched from a source that can be swapped (`deps.unsafe-source`).
  - **Containers:** an image that runs as root (`docker.runs-as-root`), a base image with no fixed version (`docker.image-unpinned`), and a secret given a value in a Dockerfile (`docker.secret-in-build`).
  - **Infrastructure files:** a database reachable from the internet (`cloud.database-public`), an admin or database port open to the world (`cloud.network-open`), a policy that allows everything (`cloud.iam-allow-all`), and a function URL anyone can call (`cloud.function-url-no-auth`).
  - **Privacy:** a consent box that starts ticked (`privacy.consent-preticked`), a sensitive category of personal data stored (`privacy.special-category-field`), and a card security code stored (`payment.card-code-stored`).
  - **Cryptography and mobile:** encryption with a fixed IV or nonce (`crypto.static-iv`), a key size or work factor that is too low (`crypto.weak-parameters`), and an Android release build that can be debugged (`mobile.debuggable-build`).
- **Agent instruction files are checked for hidden characters.** Invisible Unicode tags, direction overrides and runs of zero-width characters in `SKILL.md`, `AGENTS.md` and similar files are a finding, and so is an order to read key files such as `~/.aws/credentials`.
- **Existing rules catch more.** Mass assignment through an update call or Prisma's `data`; a JWT check with no algorithm list or with the expiry ignored; a websocket origin set to `"*"`; a real password used when the environment variable is missing; `curl -k` in scripts; one-line `privileged: true`, host namespaces, added capabilities and switched-off security profiles in Compose and Kubernetes files.
- **Weak ciphers and switched-off TLS checks are found in Java, Kotlin, Swift, Go and Dart**, not only JavaScript, TypeScript and Python.
- **`api.Dockerfile` and `Containerfile` are scanned.**
- **A start menu.** `lintsure` with no arguments shows the Prism and a short menu when a person runs it in a terminal: Up and Down to move, Enter to run. The full manual is behind `lintsure --help`.
- **Findings are easier to read in a terminal.** Ruled headings split findings in the code, repo hygiene and what to do next; each file gets its own block; the status is in colour.
- **A scan ends with the commands to run next**, such as `lintsure scan --all` for held-back findings or `lintsure baseline` to remember today's. Only the ones that apply are listed.
- **A mistyped command gets a hint.** `lintsure --scan` answers "Did you mean: lintsure scan" where it used to print the whole manual. `lintsure --version` is new.
- **Skills for any agent.** `lintsure skills` adds seven short instruction files to a project: setup, check, fix, triage, ship, rules and stay on track. They tell an agent when to use Lintsure and what to do with what it finds. They go into `.agents/skills`, which Codex, Cursor, Gemini CLI and many others read, and into `.claude/skills` when the project uses Claude Code. At a terminal you pick which ones from a list; `--yes`, `--only` and `--undo` work everywhere. Earlier copies are backed up, and a copy you edited is never removed.
- **Connect asks which agent.** The menu lists Claude Code, Cursor, VS Code, Gemini CLI and Codex, and marks the ones the project already uses. **Codex is new**: its entry goes into `.codex/config.toml`. `lintsure setup --manual` prints the values for agents that are set up in their own settings, such as Devin, Windsurf and Zed.
- **The fix for a finding, from the menu.** After a scan you can pick a finding and see where it is, what to change, why, and what you gain, with a request to paste into your coding agent. Lintsure still never edits code.
- **A scan opens with one line that fits the outcome and ends with the first three fixes.** "Nothing found by the current rules" is said in those words.
- **A folder that is not a project is named as such.** At a terminal Lintsure asks for the project folder; elsewhere it says how to name it. "Check another folder" in the menu and `lintsure scan --pick` ask for one directly, and every screen says whether a project was found.
- **No dead ends in the menu.** Every command started from the menu ends with what fits next, then "Main menu" and "Quit".
- Piped output, CI logs and the report files are unchanged by all of the above, and `NO_COLOR` is respected.

### Changed
- **Repo hygiene is listed after findings in the code** in the CLI, the Markdown report and the MCP reply, so a missing security policy no longer sits above a leaked key. The two Dockerfile basics (root user, unpinned image) are in this group. JSON and SARIF output are unchanged.
- **Within the same status and risk level, code no route or entry point reaches is ranked lower.** It is a tie-break only: nothing is hidden.
- **A masking helper imported from another file counts.** A log line that passes an email through a helper defined elsewhere in the project is no longer reported when that helper masks the value.

### Fewer false alarms
From findings on 304 public repos, reviewed one by one against the code:
- **Code that doesn't ship.** Seed, demo, mock and dev-script files inside the app folder, and packages in a monorepo that share a route folder's name (`apps/api/`), are no longer read as live code.
- **Context nearby is read.** A setting inside the branch that only runs outside production, a consent check around an analytics call, a signing-key lookup after a token peek, a socket proxy, a policy for `service_role` alone, a scan whose report is saved for a later step, and a line already marked for another scanner.
- **Test values are recognised.** A private key with no real key body, a "secret" that decodes to a sentence, logins in example and browser-test folders, and `NEXT_PUBLIC_` values in a Dockerfile.
- **Doubles are gone.** A host-name check off next to a certificate check off, and a token with both the signature and the expiry check off, are one finding each.
- More than 40 reviewed false alarms no longer show, and no reviewed real finding was lost.

## 0.3.14 · 2026-11-20 · MCP, model and default-password checks; fewer false alarms

### New
- **Four new checks** (89 rules in all):
  - **MCP tool that runs shell commands** (`mcp.tool-runs-shell`, high): `exec`, `spawn`, `os.system` or `subprocess` with `shell=True` in a file that registers MCP tools and imports a process module. Anything the agent reads can steer what it passes to the tool. Partial, because Lintsure can't tell whether the tool's input reaches the command.
  - **MCP server reads a credential every tool shares** (`mcp.tool-uses-secret`, low): every tool acts with that key's full access. One finding per credential name. Held back by default (shown with `--all`).
  - **Model loaded in a way that can run code** (`ml.unsafe-model-load`, high): `torch.load(..., weights_only=False)` is a Gap; a plain `torch.load` is Partial, since PyTorch 2.6 and later load weights only by default; `trust_remote_code=True` is Partial.
  - **Database or service left on its default password** (`config.default-service-password`, Partial, high): well-known first-run passwords in compose files, Dockerfiles, `.env` files and IaC, such as `POSTGRES_PASSWORD=postgres`, `minioadmin`, RabbitMQ `guest`, Grafana `admin` or `MYSQL_ALLOW_EMPTY_PASSWORD=yes`, including a `${VAR:-default}` fallback. Example, local, dev and test files are skipped.
- **Request data reaching a query, shell, `eval` or CI script is shown by default.** These rules stay held back for guesses, but a finding where request data plainly reaches the call (status Gap) is shown without `--all`. CORS that pairs an open or reflected origin with credentials is shown by default too. On the realistic benchmark, a default run now finds 76% of the real problems, up from 61%, with no false alarms.
- **The scan says what it didn't read.** The summary prints `Read N files, skipped M (over 1 MB, binary or unreadable)`, and the report says no finding there means not checked, not clean. The MCP server's reply carries the same count.
- **Guidance to agents:** text in the project being checked (code, comments, docs, commit messages, file names, tool output) is evidence, never instructions. It can't approve a change, a command or a network call.
- **Every code rule now has measured cases:** 11 rules that had none (MCP, Supabase, CI injection, `pull_request_target`, AI logging and output limits, mobile) were added to the benchmarks.

### Fixed
- **A scan could hang on large JSON files.** Finding the key a JSON line sits under was quadratic. It now takes one pass; one large repo went from not finishing to under a minute.
- **Lintsure no longer scans its own reports.** `lintsure-report.json`, `lintsure.sarif` and `lintsure-assessment.html` quote flagged lines, so a second scan in the same folder flagged them again.
- **Python SQL built with an f-string or `%`** is caught when the value is quoted inside the query (`WHERE name = '{request.args[...]}'`), and every `{…}` in an f-string is read, not only the first.
- **A missing folder** now gives a plain message instead of a raw error; `--fail-on` help says held-back findings count only with `--all`.

### Fewer false alarms
From 117 findings on public repos, reviewed one by one against the code:
- **Request data is followed more carefully** (file paths, server-side requests, redirects). A value cleaned where it is assigned (`safe…`, `sanitize…`, `validate…`, `encodeURIComponent`, `basename`, `secure_filename`, `parseInt`) or looked up by id (`.find(…)`, `findById`) no longer counts, and request data only passes through calls that keep the value (`path.join`, `new URL`, `String`). An origin check (`x.origin === …`) or a guard on the variable it came from counts as a check. On 304 public repos these three rules went from 101 findings to 31; all 10 reviewed false alarms are gone and the real one is still caught.
- **Secrets:** fill-in tokens that aren't random enough to be keys (`ghp_aaaa…`), key headers with no key in a comment or in code that builds a key, and a Firebase web config's `databaseURL` are no longer flagged.
- **Smaller fixes:** `extractall(…, filter=…)` after nested brackets, `webbrowser.open`, alias maps such as `{ secret: "secret" }`, `chmod` masks (`mode & 0o777`), in-memory `send_file(io.BytesIO(…))`, binaries in test folders, and load-test and test-data folders.
- **Held back by default:** new-tab links (`html.tabnabbing`, 2,246 low-value findings on the field test) and JWT verify without an algorithm list (`jwt.no-algorithm-pin`: with a shared string secret, current libraries already allow only HMAC).

## 0.3.13 · 2026-11-20 · Docker socket check

### New
- **Docker socket mounted into a container** (`docker.socket-mounted`): `/var/run/docker.sock`, or the Windows `docker_engine` pipe, mounted in a compose file, a Kubernetes `hostPath`, a devcontainer mount or `docker run -v`. Whatever runs in that container gets the host's Docker and with it the whole machine; mounting it read-only doesn't stop that. Partial, since CI runners and reverse proxies sometimes need it. A `DOCKER_HOST` setting and commented-out lines don't count. 85 rules in all.

### Fixed
- Blanking quoted text (used to tell a demo string from real code) now takes one pass over the line. The old pattern slowed down with the square of the line length on an unclosed quote followed by many escapes (CodeQL `js/polynomial-redos`). Same results on every case checked.

## 0.3.12 · 2026-11-20 · Fewer false alarms, ten new checks

### New
- **Ten new checks** (84 rules in all, up from 74):
  - **Record loaded with no owner check** (`authz.no-owner-check`): a record looked up by an id from the request, with nothing tying it to the signed-in user. Partial and held back by default (shown with `--all`), since the check may live in middleware.
  - **Token verified without an algorithm list** (`jwt.no-algorithm-pin`) and **token signed with a short secret written in the code** (`jwt.weak-secret`).
  - **Request data deep-merged into an object** (`proto.pollution`): `_.merge`, `deepmerge` and `$.extend(true, …)` on the request body.
  - **Web-socket server with no origin check** (`ws.no-origin-check`).
  - **Container runs privileged or shares the host** (`k8s.privileged`) and **storage bucket open to the public** (`cloud.public-bucket`), in Kubernetes YAML, Terraform, CDK and SDK calls.
  - **Secret compared with == instead of a constant-time check** (`crypto.unsafe-compare`). Held back by default.
  - **New-tab link without rel="noopener"** (`html.tabnabbing`, low: current browsers already protect against it) and **GraphQL introspection on** (`graphql.introspection`, low).
- **Request data followed through one variable:** the SSRF, open redirect and file path checks now catch a request value saved to a variable and used a few lines later, unless the variable is checked first (startsWith, includes, a comparison, an allowlist). These findings are Partial. Also caught: template URLs that start with request data, archive extraction without Python's `filter=` (zip slip), and `"none"` anywhere in a JWT algorithm list.
- **Realistic benchmark** (`benchmark/corpus.mjs`, run by `npm test`): 36 small projects scored through the real scan, not single lines. It covers text that isn't code, request data through a variable, safe versions that must stay quiet, and plain true positives, and fails if precision, recall or a passing case gets worse.

### Fewer false alarms
- **Example code is no longer read as running code:** fenced code blocks in docs, values under example-style keys in JSON data (`example`, `code`, `snippet`, `bad`, `good` and similar), and calls that only appear inside a quoted string, such as a demo diff stored as text. Secret checks still look there, unless the key is plainly fake.
- **The hidden-AI prompt check** (`ai.hides-being-ai`) reads markdown only in prompt files (`prompts/`, `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.github`, `.cursor`, `.claude`), not in guides that explain the rule.
- On our own website repo, a default scan went from 9 findings to 1 (the one left is a real, accepted dev-only log). On the realistic benchmark, precision went from 60% to 100%.

### Other
- Repo: Dependabot config, a CycloneDX SBOM (`npm run sbom`), CodeQL advanced setup, community files (code of conduct, issue and PR templates, accessibility statement).

## 0.3.11 · 2026-11-18 · Policy fingerprint

### New
- **Policy fingerprint:** every scan report (JSON, Markdown, SARIF and the CLI summary line) names the policy it ran under as a short code like `#3F2A-9C1D`. The same rules and settings give the same code on any machine; switching a rule off, re-rating it, or changing frameworks, ignore paths, `.lintsure/rules.yml` or installed rule packs gives a new one. It names the policy; it doesn't sign anything.
- **Agent config downloads and runs code** (`agent.config-runs-remote-code`): flags Claude Code hooks, MCP server commands, Cursor, VS Code and Gemini CLI settings that pipe a download into a shell or run it straight away.
- Rule packs can carry a `version`, which goes into the policy fingerprint.
- **Env files not kept out of git** (`release.env-not-ignored`): the project uses `.env` files but `.gitignore` has no line for them, so the next `git add .` can publish them. Gap when a file holds a secret-looking value, Partial when it only has public settings. Examples like `.env.example` don't count. On 223 public projects: 17 hits; checked individually, all 17 had the env file already committed and 2 held a real secret (a Supabase service-role key, a database password).
- **Agent instructions that override, hide or download and run** (`agent.instructions-unsafe`): skills, `AGENTS.md`, `CLAUDE.md`, Cursor and Copilot rules that tell an agent to ignore its earlier instructions, keep something from the user or send secrets out (Gap), or pipe a download into a shell (Partial). Lines that warn about these, or say they're blocked, don't count. On 223 public projects: 9 hits, all download-and-run lines, checked individually.
- **Agent settings that skip every permission prompt** (`agent.permissions-allow-all`): committed Claude Code, Gemini CLI, Codex, Continue or VS Code settings that bypass permissions or allow every shell command (OWASP LLM03). On 223 public projects: no hits.
- **AI agent loop with no real step limit** (`llm.unbounded-agent-loop`): a Vercel AI SDK loop that never stops (Gap) or allows hundreds of steps (Partial). On 223 public projects: 2 hits, both high step limits, checked individually.
- **The browser chooses the AI's system instructions** (`llm.client-controls-system`): a route that takes `system` from the request body and passes it to the model. On 223 public projects: no hits.
- **Vercel AI SDK and Vercel libraries:** the AI checks recognise `generateText`, `streamText`, `generateObject`, the agent class and the SDK's image, speech, video and transcription calls; saving a chat in `onFinish` or turning on telemetry counts as keeping a record. The public-key check knows Blob read-write tokens, Vercel tokens, Edge Config connection strings and AI Gateway, v0, xAI, OpenRouter, Fireworks, Together and Perplexity keys; the analytics check knows `@vercel/analytics`' `track()`.
- **What Lintsure couldn't see:** every Partial finding now says what the rule can't tell from the code (for example where a value comes from), in the Markdown report, JSON and SARIF.
- **Seen in a real incident:** rules can cite a public incident with a primary source. First three: Claude Code project hooks (CVE-2025-59536), tj-actions/changed-files (CVE-2025-30066) and Lovable apps without row level security (CVE-2025-48757). `scripts/check-sources.mjs` checks the links before a release.
- **`lintsure setup`** adds the Lintsure MCP server to the agents a project uses (Claude Code, Cursor, VS Code, Gemini CLI). It shows the change first, writes only with `--yes`, keeps your file's indentation, backs up a file once without ever overwriting that first backup, pins the MCP version and leaves files with comments alone. `--undo` takes out only Lintsure's entry.
- **`lintsure export --otlp-json`** turns the local activity log into an OpenTelemetry traces file (one trace per agent session, one span per guard catch, decision or scan, GenAI attribute names plus `lintsure.*`). It writes a file and sends nothing.
- **`lintsure status`** checks Node, `lintsure.config.yaml`, rule packs, `.lintsure/rules.yml`, which agents have the MCP server, and starts the locally installed MCP server for a real round trip (version, tool list, one call), without printing any secret.
- **`plan_checks` MCP tool:** describe a feature before building it and get the checks it is likely to meet, with how to avoid each. Word matching on the description, not a code review.
- **Login or password reset with no rate limit in sight** (`auth.no-rate-limit`): sign-in, sign-up, one-time-code and reset handlers with no limiter in the file, middleware or package.json, and no auth provider that limits on its own. Partial and held back by default (shown with `--all`), since a firewall or gateway may limit outside the code. On 223 public projects: 1 hit, checked individually and real.
- **Reached from:** findings in JavaScript and TypeScript now say whether a route, API handler, middleware, server action, function, worker or app entry reaches the file through the project's own imports, with the chain (`app/api/users/route.ts → lib/users.ts → lib/db.ts`). Our own small resolver: relative imports, `.js` to `.ts`, index files, tsconfig `paths` per package, SvelteKit, Remix, monorepo package roots, files named in `package.json` (`main`, `bin`, `exports`) and scripts an HTML page loads. An import it can't resolve makes the answer "unknown", never a guess. It adds context and doesn't change any status yet. A file it can't connect to an entry point is shown as "not reached from any entry point Lintsure recognises": it may be loaded some other way, or be unused.
- **Exact fixes:** where the fix is unambiguous, a finding carries the exact change, shown as a diff in the report, as `patch` in JSON and as SARIF `fixes` that editors and code scanning can offer. First rules: env lines for `.gitignore`, Next.js browser source maps off, TLS checks back on (`verify=True`, `rejectUnauthorized: true`), and Secure/HttpOnly on session cookies. Lintsure never writes it; a person approves it.
- **Docs inside the package:** `@lintsure/core` now ships `docs/` (every rule, every framework, how agents should use the results), generated from the code on every build, so agents can read them offline.
- The MCP server is tested with bad input (wrong types, unknown tools, oversized text) and its tool list is kept under a size budget, since agents read it every session.

### Fewer false alarms
- **Code run from a string:** a call or method head that a formatter split over several lines is now read as one statement, and text inside a string left open at the end of a line is ignored. Wrapping no longer creates false alarms in the format test (2 before, 0 now).
- **User text in a system prompt:** an error's own message (`${error.message}`) no longer counts as user text.

### Fixes and speed
- Each file is read once per scan, 32 at a time, with one size and binary check for every reader. The two largest test projects (about 15,000 files) scan about three times faster with the same findings.
- `--diff` now sees changed files whose path has a space or an accented letter (before, their findings were dropped).
- The MCP server refuses to scan when `lintsure.config.yaml` has a problem, as the CLI does, and accepts framework ids from rule packs. Packs listed in one repo's config no longer carry over into scans of another repo.
- `--all` now changes the policy fingerprint, and a `#` inside a quoted value in `.lintsure/rules.yml` is no longer treated as a comment.

### Field test
On 223 public projects cloned for our field tests (scanned locally, nothing run). On the 103 of them with a stored 0.3.10 result, older rules gained no findings and lost 2, both intended (an error message no longer counted as user text, and an AI SDK call with telemetry on now counts as recorded). Results and the script: `research/field-0311/` in the Lintsure workspace.

## 0.3.10 · 2026-11-13 · Tested on new projects

We ran 0.3.9 on 56 public projects it had never seen, created since June and built with Lovable, Bolt, Supabase, Claude Code and Cursor, and reviewed 110 more findings one by one against the code. A normal run was right 44% of the time on the new projects and 48% on a fresh sample from the original 139. Four checks caused most of the false alarms. This release fixes them.

### Fewer false alarms
- **Personal data in logs:** a value passed through a masking or hashing helper first, such as `maskEmail()`, `pseudonym()` or `hash()`, is no longer counted. Every false alarm from this check on the new projects was masked this way.
- **Downloaded scripts run without a check:** a script served from `localhost` or `127.0.0.1` (a CI test of a project's own installer) and an installer pinned to a version in its URL are no longer reported. YAML files outside CI and compose files are read as text, not scripts.
- **Secrets in code:** obvious placeholders (`xoxb-your-bot-token`, `...fake...`, a key header followed by `...` or by prose), TypeScript `.d.ts` files and secret-scanner config files such as `.gitleaks.toml` are skipped. None of the 7 sampled secret findings was real.
- **Unsafe deserialization** is now medium confidence and held back by default: none of 7 sampled was real (the data was the app's own database, cache or worker pipe).
- `.devcontainer/` is treated as dev tooling, like `scripts/`.

### Result
- On the reviewed findings a normal run shows: 52% real before, 61% now (59% on the 139, 67% on the 56 new projects), with no finding reviewed as real lost. These are measured on the same findings the fixes were chosen from, so they lean optimistic; the next fresh sample will check them.
- A normal run on the 139 lists 1,328 findings (1,366 in 0.3.9). On the 56 new projects it lists 222 (246).

## 0.3.9 · 2026-11-13 · Fewer, truer findings

Most findings on real projects were not real problems: in a sample of 270 findings reviewed one by one against the code from 139 public repositories, 28 were. A tool that cries wolf gets switched off, and then the real findings are ignored too. This release measures every loud rule and shows only what is usually right.

### Confidence levels
- Every rule is now high or medium confidence, set from findings reviewed one by one on the 139 repositories. A normal run lists high-confidence findings and counts the rest: "47 more at medium confidence: run with --all". Use `--all`, `show: all` in the config, `all: true` in MCP or `show-all: true` in the Action to see them.
- 25 rules are medium confidence for now, including raw HTML, empty catch blocks, SQL and shell commands built from strings, `eval`, AI logging and output limits, and JWT checks. Most were real in one finding of five or fewer. Samples for some rules are small (5 or 6 findings), so each rule is measured again every release and moves back when a fresh sample shows it is usually right.
- Secrets found in test and fixture files are held back the same way: none of 15 sampled was real.
- **Result on the 139 repositories:** a default run lists 1,366 findings instead of 5,947. Of the reviewed findings it still lists, 58% are real, up from 16%. Every finding reviewed as real in 0.3.8 is still found, with `--all` where it is medium confidence.

### Rules that changed
- **`cors.any-origin`** reports only the dangerous pairing: an open or reflected origin together with credentials. An open origin alone is normal for a public API (none of 19 sampled was a problem), as in CodeQL's CORS check.
- **`session.cookie-insecure`** needs a cookie being set nearby. A bare `secure: false` is usually a client, proxy or database option. CSRF cookies are meant to be readable.
- **`pii.in-url`** no longer reports tokens, which OAuth and vendor APIs put in URLs by design, or placeholders such as `[YOUR-PASSWORD]`.
- **`sql.string-built`** skips migrations folders: schema text the team writes and runs once.
- **`xss.raw-html`** treats any `sanitize...()` or `esc...()` / `escape...()` helper as escaping.
- **`secret.in-source`** skips translation files, which say "API key" in every language.
- **Code that doesn't ship:** top-level `scripts/` folders, `test-*.js` scripts, `test-utils` folders and agent tooling (`.agents/`, `.claude/`, `.cursor/`) are checked for secrets only, like tests. They were the largest single source of false alarms (44 of 242). Shell scripts in `scripts/` still count, since they are often the installer people run.

### New: check only what changed
- `lintsure scan --diff origin/main` lists only findings on lines changed since that base. The GitHub Action does this on pull requests by default (`changed-only: auto`).

### New: setup and settings that explain themselves
- `lintsure init` asks three questions (what to check, does the app use AI, EU users) and writes `lintsure.config.yaml`. It never overwrites a file and never runs in CI.
- `lintsure info` shows the settings a scan would use and where each came from.
- The config file takes `rules:` to switch a rule off or change its risk level, `show: all`, and inline lists such as `frameworks: [gdpr, owasp-top10]`. Unknown settings, unknown rule ids and unreadable lines now stop the CLI with exit code 2. Before, `frameworks: [gdpr]` was silently ignored and all six frameworks ran.
- Rules switched off are listed in the report and the record.

### New: a "Not covered" section in every report
- It lists what this run did not look at: medium-confidence findings held back, rules switched off, ignored paths, files checked for secrets only, lines outside the diff, and the fixed limits (one file at a time, no runtime behaviour, secret and config checks only beyond JavaScript, TypeScript and Python). No finding in a place does not mean no problem there.

### MCP: a reply an agent can use
- `scan` now returns a short list by default: Gaps first, each with file and line, rule, risk level and a one-line fix, then counts and Not covered. 200 findings used to produce about 129,000 tokens; the default reply now lists 25.
- New inputs: `files`, `rules`, `status`, `limit`, `all` and `format` (`full` gives the complete report and JSON). After a fix, call `scan` with the file and rule to confirm it is gone.

### New: a triage skill for coding agents
- The MCP server now offers a `triage` prompt (in Claude Code: `/mcp__lintsure__triage`), so every MCP client gets it with nothing to install, and the server's instructions point agents to it. The same text is in `skills/lintsure-triage/SKILL.md`, and a test keeps the two equal.
- It teaches Claude, Codex or Cursor to sort each finding into confirmed, not a problem or needs a person, by following where the value comes from, what checks it, and where it ends up. It reads code only and changes nothing without the user's yes. Its approach follows the triage method in OpenAI's Codex Security (Apache-2.0).

### SARIF
- Results now carry a level by risk (high, medium, low) and rules carry `security-severity` and `precision`, so GitHub code scanning can rank them.

### Scan time
- 313 seconds for the 139 repositories (305 in 0.3.8).

## 0.3.8 · 2026-11-10 · Code the way formatters write it

Formatters such as Prettier and Black split one call over several lines, and a check that reads one line at a time never saw `logger.info("signup", {` and `email: user.email,` together. Selected checks now read the whole statement.

- **Format robustness:** every benchmark case is re-wrapped the way a formatter would and run through a real scan. 36 of 96 (38%) were still found in 0.3.7; 81 of 96 (84%) are found now. `npm test` fails if this drops below 80%.
- **Which checks read whole statements, and why only these:** personal data in logs and analytics, log injection, file uploads, mass assignment, server-side request forgery, file paths, redirects, NoSQL queries, server-side templates, error details, plain HTTP, TLS checks, unverified JWTs, weak ciphers, file permissions, mobile token storage, debug mode and cookie roles.
  - We first turned it on for every check. On 139 public repositories it added 692 findings, and only 5 of 41 sampled were real. Words from different parts of one statement matched together, such as a constant system message beside a separate user message, or `Math.random()` as a React key beside the text "Password updated".
  - SQL, shell commands, secrets in logs, random tokens and AI system prompts stay line by line until that can be done reliably.
- **What it found on the 139 repositories:** 67 new findings, including emails sent to analytics in multi-line `identify` calls, JWTs decoded with `verify_signature: False` over several lines, and a multi-line upload setup with no size or type limit. All 31 previously confirmed real problems are still found.
- **Prompt text is not code:** a multi-line template literal with no `${}`, such as a system prompt, is no longer read as code by the code checks. A prompt that says "never suggest eval(userInput)" is no longer an eval finding. The check for prompts that tell an AI to hide being an AI still reads them.
- **Fixed: catastrophic backtracking.** The pattern that blanks out string contents could take minutes on a line full of backslashes and quotes, such as an array of regular expressions. It is now linear, with a test.
- **Scan time:** about 40% longer on the 139 repositories (216 to 305 seconds for 28.7 million lines).

## 0.3.7 · 2026-11-10 · Honest gates and records

An independent review of 0.3.6 reproduced 29 problems, each with a small test project. This release fixes the most serious ones, and every fix has a test that failed on 0.3.6. On the same 139 field-test repositories, 31 of the 33 confirmed real problems are still found, and confirmed false alarms drop from 92 to 82.

### Fixed: a CI gate that could pass when it should fail
- `--fail-on=gap`, `--fail-on Gap`, a bad value such as `--fail-on high`, and a mistyped option such as `--fial-on` used to exit 0, so a pipeline could pass with Gaps present. Now `--flag=value` works, values are case-insensitive, and an unknown option or a bad value exits 2.
- The summary line no longer starts with a check mark when findings are open.

### Fixed: live code skipped because of a folder name (a 0.3.6 regression)
- In Next.js, Remix and Supabase, a folder name is a URL or a function name. `app/api/demo/route.ts`, `app/docs/actions.ts` and a Supabase function called `test` are live endpoints, and are checked again. Inside route folders only real test files are skipped.
- Example, demo, docs and sample folders inside `src/`, `lib/` or `server/` are now checked as app code. Test, seed, factory and storybook folders are still skipped.

### Fixed: the record saying more than the scan did
- Check points and "files read" now count only rules that actually ran. A rule whose only files were skipped is no longer Met.
- A control whose rules read no file now says "Not checked" instead of "No issue found".

### Secrets
- Secrets are found in every text format: shell scripts, Dockerfiles, Terraform, Go, Ruby, PHP, Java, Kotlin, C#, notebooks, Vue, Svelte and Astro files, and more.
- New: Supabase service-role JWTs (decoded, so the role is read exactly), database URLs with a real inline password on an internet host, Stripe webhook secrets, Supabase secret keys and Resend keys.
- Browser-exposed variable names: words that mean secret (SECRET, PRIVATE, SERVICE_ROLE, PASSWORD, PERSONAL API key, database URL) now win over the public-by-design list. `NEXT_PUBLIC_FIREBASE_ADMIN_PRIVATE_KEY` and `VITE_POSTHOG_PERSONAL_API_KEY` are found.
- Test keys and certificates, form placeholders and documented URL formats are no longer reported.

### Fewer misses and false alarms
- **`supabase.function-no-auth`:** comments no longer count as a check, and reading the Authorization header is not a check unless it's compared or the request is turned away with 401/403.
- **Python:** a comment that mentions `"""` no longer hides the code after it.
- **Default secrets:** field-name enums and labels such as `Secret: 'secret'` and `SECRET: "SECRET"` are no longer default secrets, and test files are no longer checked for them.
- **Hard-coded passwords:** column types and labels (`password: 'String'`) are not passwords.
- **JWT:** Python peek-then-verify (an unverified decode followed by a verified one) is not reported.
- **CI script injection:** `ci.script-injection` also reads `script:` blocks in `actions/github-script`.

## 0.3.6 · 2026-11-10 · Fewer false alarms

We ran Lintsure on 139 public repositories (82 of them written partly or mostly with AI tools) and reviewed 249 of its findings one by one against the actual code (AI reviewers reading the code, with a sample re-checked by us). Only 13% were real problems. This release fixes what that showed. On the same 139 repositories, Gaps fall from 792 to 284, 31 of the 33 confirmed real problems are still found, and 60 of the 152 confirmed false alarms are gone. There is more to do; most remaining false alarms need multi-line analysis, which is next.

### How files are read
- Tests, fixtures, examples, docs, demos, stories, seed data and test-runner configs are no longer checked, except for leaked secrets, which are reported there as Partial.
- `vendor/`, `third_party/` and bundled library builds (`*.global.js`, `*.bundle.js`) are skipped as other people's code.
- **Fixed:** in Python, code after a multi-line string (`PROMPT = """ ... """`) was skipped as if it were a docstring.
- **Fixed:** `# noqa`, `# nosec` and `NOSONAR` no longer hide leaked secrets, and `lintsure-ignore` only counts in a comment.
- **Fixed:** `.env.local` and other `.env.*` files, `.mts`/`.cts` files and `Dockerfile.*` are now read.
- **Fixed:** one very long line (a data URL, a long prompt) no longer hides the whole file; only minified files are skipped.
- **Fixed:** `/* note */ code();` is read as code, a Markdown bullet is no longer a comment, and a commented-out SQL line no longer counts as switching row level security on.
- A rule with no files to read is no longer reported as Met.

### New checks
- `supabase.function-no-auth`: a Supabase Edge Function with `verify_jwt = false` whose own code never checks the caller (no user session, JWT, webhook signature or shared secret). It's a Gap when the function also uses the service-role key or a paid AI API. It reads `supabase/config.toml` and the function's code together.
- `config.default-secret-key` now also catches signing secrets that fall back to text in the code, such as `os.getenv("JWT_SECRET", "change-me-in-production")` or `process.env.SESSION_SECRET || "dev-secret"`.

### Fewer false alarms
- **SQL:** needs a real statement shape (SELECT…FROM, INSERT INTO, UPDATE…SET, DELETE FROM). Error messages and constant table or column names are ignored.
- **Shell commands:** `regex.exec()` and `db.exec()` are no longer read as shell commands.
- **Weak password hash:** the hash must be applied to a password; HMAC and HTTP Digest are protocol choices.
- **Plain HTTP:** private and local addresses and single-name service hosts (`http://redis:6379`) are skipped.
- **CORS:** dev-server configs and API specs are skipped.
- **Secrets in browser variables:** type declarations (`env.d.ts`) are skipped.
- **Open database policies:** read-only `for select using (true)` policies are treated as intentional.
- **`pull_request_target`:** only the actual checkout of pull-request code is flagged.
- **Deserialisation:** `yaml.load` only with an unsafe loader; `node-serialize` still counts. It's a Gap only when request data is on the line.
- **XML:** Python's standard XML parsers are no longer flagged.
- **Script integrity (SRI):** payment, analytics and captcha scripts that can't use it are skipped.
- **AI output into code:** only in files that actually call an AI model.
- **iOS cleartext traffic:** `NSAllowsArbitraryLoads` only when set to true.
- **AI rules:** decision words match whole words ("banner" is not "ban"), and "act as a human resources advisor" is a job title, not a disguise.
- **Passwords in code:** validation messages such as `password: "Required"` are not passwords.

### Honest severity
- Empty catch blocks are now Partial and low; most are deliberate fallbacks.
- Emotion or biometric analysis and "AI hides that it's an AI" are now Partial: whether they're banned depends on context the code can't show.
- Raw HTML is now medium, cookie flags low and script integrity low.

### Mappings
- Removed GDPR Art. 28 from personal data sent to analytics; code can't show a missing processor agreement.
- Removed the LLM06 tag from "AI call with no record kept"; logging isn't a consumption limit.
- Added CWE-79, CWE-78 and CWE-89 to "AI output run as code".

The benchmark now also runs file-level rules, and a new scanner-level test runs every case above through a real scan.

## 0.3.5 · 2026-11-09

Findings now cite the **OWASP Top 10 for LLM Applications 2026**, published in August 2026, instead of the 2025 edition. No rule changed what it finds; only the references moved:

| Rule | 2025 reference | 2026 reference |
|---|---|---|
| `llm.user-input-in-system-prompt` | LLM01, LLM07 System Prompt Leakage | LLM01, LLM08 Hidden Context Exposure |
| `llm.output-to-sink` | LLM05 | LLM10 Improper Output Handling |
| `llm.no-output-limit`, `ai.call-not-logged` | LLM10 | LLM06 Unbounded Consumption |
| `deps.unpinned-version`, `deps.install-script` | LLM03 | LLM04 Supply Chain |
| `secret.*`, `pii.logged`, `log.secret` | LLM02 | LLM02 (unchanged) |

Baselines and accepted findings keep working: they're keyed to the rule and the line, not to framework references.

## 0.3.4 · 2026-11-09 · Common Ground

Six frameworks focused on what every developer ships: the EU AI Act, GDPR, OWASP Top 10, OWASP Top 10 for LLM Applications, the 2025 CWE Top 25 and the EU Cyber Resilience Act. 66 rules (19 new), cross-file checks, fewer false alarms after a field test on 100 public repositories, and clearer MCP tool definitions (4bb46a0).

### Frameworks: a sharper open-source set
- **Added:** `owasp-llm` (OWASP Top 10 for LLM Applications 2025), `cwe-top25` (2025 CWE Top 25, MITRE) and `cra` (EU Cyber Resilience Act, below). These apply to almost every codebase and are where an open, local checker gives the most value.
- **Moved to the Lintsure team platform:** SOC 2 and ISO/IEC 27001. They are certification and audit programmes run by an organisation: controls, evidence, policies and an auditor's review, most of it outside code. Their mappings now come with the platform's workspace and evidence features, where they're most useful. Every rule that used to map to them is still in the open checker and still finds the same problems; versions 0.3.3 and earlier keep their SOC 2 and ISO mappings.
- New rules: `llm.user-input-in-system-prompt`, `llm.output-to-sink`, `llm.no-output-limit`, `mobile.token-in-plain-storage`, `mobile.cleartext-traffic`, `mobile.backup-allowed`, `mobile.webview-any-origin`.
- `classify` takes new answers used by rule packs: `mobileApp`, `healthDataUS`, `governmentCustomers`, `euConsumers`, `cardPayments`.
- File rules now see comment lines as blank.
- Rule packs: `packs:` in `lintsure.config.yaml` loads installed `@lintsure/pack-*` packages, resolved only from Lintsure's own install, never from the scanned repo. `registerPack` and `loadPacks` are exported. `FrameworkId` accepts pack-defined ids.

### EU Cyber Resilience Act (Beta)
- New framework id `cra` with an own-words knowledge file: Annex I Part I and II, Art. 13(2), Art. 14 reporting, documentation and CE marking, timeline (in force 10 Dec 2024, reporting from 11 Sep 2026, full application 11 Dec 2027).
- 46 existing rules now also map to Annex I controls (secure defaults, access, confidentiality, integrity, data minimisation, attack surface, logging, components, secure updates).
- `repo.no-security-policy` (Partial): no `SECURITY.md` in the root, `.github/` or `docs/`.
- `repo.no-sbom` (Partial): no CycloneDX or SPDX file in the repo.
- `update.unverified-download` (Partial): `curl` or `wget` piped into a shell in shell scripts, YAML and Dockerfiles. Quoted text is ignored, so `echo "Install via: curl … | bash"` isn't flagged (found in the field test: 4 of 7 first hits).
- Rules can now be repository checks (`repoTest`): they look at the file list once and point at the missing file. They only run when `cra` is selected.
- `classify` takes a new answer, `digitalProductEU`.

### CI, repository and secret checks
- `ci.write-all-permissions` (Gap): `permissions: write-all` in a GitHub Actions workflow.
- `ci.script-injection` (Gap): issue, comment or pull request text (title, body, branch name and so on) pasted into a `run:` step. Values passed through `env:` or used in `if:` are not flagged.
- `repo.binary-committed` (Partial): compiled files (.exe, .dll, .so, .jar and so on) in the repo; the Gradle wrapper is allowed.
- `repo.no-dependency-updates` (Partial): no Dependabot or Renovate config.
- `secret.in-source` now recognises GitHub fine-grained and app tokens, GitLab, Slack webhooks, Anthropic, OpenAI, SendGrid, npm, PyPI, Hugging Face and Shopify tokens, AWS temporary keys, and DSA, encrypted and PGP private keys. Provider documentation examples (such as AWS's `AKIAIOSFODNN7EXAMPLE`) are skipped.
- In test files, hand-typed fake keys are skipped (alphabet or number runs, words instead of random text, a whole key block on one line). Field test: secret alerts on the 18 repos went from 11 to 5.

### Fewer false alarms (field test on 50 public repos: 2,214 findings down to 1,593)
- `auth.hardcoded-password`: skips translation folders and translated or stand-in values, and no longer reads test files.
- `sql.string-built`: skips safe tagged templates (`sql`, `tx`, `safeSql`, `Prisma.sql`, `$queryRaw`) and method calls such as `hash.update(` or SQLAlchemy `select(`.
- `ai.call-not-logged`: skips examples, docs and AI library adapters (new rule option `unlessPath`).
- `xss.raw-html`: skips clearing an element, DOMPurify output and JSON-LD built with `JSON.stringify`.

- Second round on 50 more public repos (124,737 files, 94 seconds): `supabase.rls-disabled` now reads every SQL file in `supabase/` together (rule option `sharedContext`); `code.eval` ignores methods named `eval` and Playwright's `$$eval`; `secret.in-source` ignores code that checks for a key header and honours `pragma: allowlist secret`; `xss.raw-html` ignores fixed markup; `sql.string-built` recognises `sql<T>\``; `session.cookie-insecure` ignores SMTP settings; `crypto.weak-cipher` needs an encryption context; `crypto.weak-password-hash` ignores sentences; `log.secret` allows logging a token's length; `pii.logged` ignores GitHub's `::add-mask::`.
- Reports list Gaps first, then by severity.

### Agent guidance
- Agents now check each Partial finding before showing it: try to rule it out from the surrounding code, then report it as likely real, needing the user's check (with the one fact to confirm), or ruled out (with a reason, recorded only if the user agrees). A missing extra safeguard is called a hardening suggestion, not a vulnerability.

### New rules
- `supabase.rls-disabled` (Partial): a table created in a `supabase/` migration with no `enable row level security` for it in the same file. System schemas (auth, storage and so on) are skipped.
- `supabase.policy-allows-all` (Partial): `using (true)` or `with check (true)` in a Supabase policy.
- `supabase.service-key-in-client` (Gap): the service-role key referenced in a `"use client"` file.
- `secret.public-env` (Gap): secrets, or keys for AI, email, payment and database services, in browser-exposed variables (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`). Keys that are public by design (Supabase anon, Stripe publishable, Firebase, Maps) are allowed.
- `build.sourcemaps-public` (Partial): `productionBrowserSourceMaps: true` in a Next.js config.
- Tested on the 18 field-test repos before release: the first version produced 290 false alarms (Prisma and Drizzle migrations, widget and analytics keys, Vite source maps in libraries). After tightening, 4 hits, all correct.
- Rules can now be limited to a path (`pathMatch`).

### MCP tools
- Descriptions start with what the tool does, say what it returns and which tool to call first.
- Every input has a description and an example. `classify` called with no answers returns its eleven questions, from one list that also describes the inputs.
- `explain_framework` marks each date as already applying or upcoming.

### Knowledge
- GDPR: start date (25 May 2018) added.
- OWASP Top 10: the `classify` reason no longer assumes a web app.

## 0.3.3 · 2026-11-09 · Cleaner packages

- Removes two unused files that shipped by mistake in 0.3.1 and 0.3.2: `datamap.js` in `@lintsure/core` and `browser.js` in `lintsure`. They were left over from features we've set aside for now, and nothing loaded them. The build now empties its output folders first, so old files can't slip in again (a8ef8d6).

## 0.3.2 · 2026-11-09 · Security update

- Upgrades zod to 4.6.7. Versions before 4.6.6 can use up memory when validating oversized input (GHSA-mrhx-c7xc-m3w5). Lintsure's inputs are small, so the real risk was low, but `npm audit` is now clean (4b8a19d).
- Corrects the OWASP Top 10 "checked on" date to 2026-11-08 (e16ea59).

## 0.3.1 · 2026-11-08 · Tested on 18 real repos

We ran Lintsure on 15 public apps built with Lovable, Bolt, v0 and Claude Code, and on three large AI apps (Dify, Open WebUI, LobeHub). The first run produced about 1,600 findings on the 15 small apps, and over 90% were our mistakes. This release fixes them, and every fix has a new test or benchmark case.

### Fewer false alarms
- Package rules read only `package.json`, and skip `peerDependencies`. Lockfiles and peer ranges use `"*"` on purpose (d320369, e94fdfb).
- Comments, block comments and Python docstrings aren't read as code. A real secret pasted into a comment still counts (d320369).
- Test files and fixtures are only checked for secrets, and obvious placeholders like `password="test_password"` are skipped (d320369, e94fdfb).
- Lines marked `# noqa`, `# nosec`, `// NOSONAR` or `lintsure-ignore` are treated as already reviewed (e94fdfb).
- Safe log lines such as `{ hasToken: !!token }` and `token[:8]` aren't flagged as leaking secrets (d320369).
- A JWT whose `exp` is set a few lines above `jwt.encode` isn't flagged (3e64e86).
- `CERT_NONE` listed as a settings option, a method named `eval`, `self.secret = secret`, and `pull_request_target` jobs that only run after merge are no longer flagged (e94fdfb).

### EU AI Act rules find more
- AI calls are recognised in the forms real apps use: any `*.chat.completions.create`, Gemini `generateContent`, Vercel `generateObject` and `streamObject`, LangChain `chain.invoke`, and direct calls to the OpenAI, Anthropic, Gemini, OpenRouter, Groq, Mistral and DeepSeek APIs (c8c1a9c).
- "AI call with no record" needs a log or save near the call, not anywhere in the file, and reports once per file (c8c1a9c).
- "AI-generated images, audio or video" also flags AI calls in files that name an image, voice or video model (c8c1a9c).

### Also
- `glama.json` and a Dockerfile for MCP directories that run servers in a container (108c26e).

## 0.3.0 · 2026-11-08 · OWASP Top 10:2025

A fifth framework, in Beta: the OWASP Top 10:2025, covering all ten categories in our own words.

### New rules (31)
- A01 Broken Access Control: file paths from request data, open redirects, server-side request forgery, CSRF switched off, world-writable files, permissions read from cookies.
- A02 Security Misconfiguration: Django accepting any host, default or placeholder secret keys, XML parsers that load external entities.
- A03 Software Supply Chain Failures: dependencies with no version limit, install scripts that download code, unpinned third-party GitHub Actions, pull_request_target workflows that check out untrusted code.
- A04 Cryptographic Failures: predictable random numbers for secrets, weak ciphers and ECB mode, JWTs accepted without checking the signature.
- A05 Injection: shell commands built from strings, eval and new Function, HTML inserted without escaping, templates built from request data, query objects taken straight from the request.
- A06 Insecure Design: uploads with no type or size limit, whole request bodies saved to a model.
- A07 Authentication Failures: passwords in code, JWTs with no expiry.
- A08 Software or Data Integrity Failures: unsafe deserialisation, third-party scripts without integrity checks.
- A09 Security Logging and Alerting Failures: secrets in logs, raw request data in logs.
- A10 Mishandling of Exceptional Conditions: errors caught and ignored, error details sent to users.

### Also
- Eleven existing rules now also map to the OWASP categories they relate to.
- Each category lists what code can't show (for example ownership checks between users, known vulnerable dependencies, login protections, alerting) under work outside code.
- Rules that depend on request data are a Gap when request data is on the same line, and Partial otherwise.
- Every new rule has a planted example, a near miss and benchmark cases. 45 rules are now scored in the benchmark.
- Mapped to the OWASP Top 10:2025 in our own words. Not affiliated with or endorsed by the OWASP Foundation.

## 0.2.0 · 2026-11-08 · Reports you can act on, rules you can measure

### Readiness check record
- Every run produces a dated record: record id, date and time (UTC), tool and rules version, the branch and commit checked, and where it ran (CLI, MCP or CI).
- It lists what applies and why (chosen on the command line, listed in `lintsure.config.yaml`, chosen in the agent, or checked by default).
- It counts check points (one rule applied to one file), findings (Gaps), observations (Partials), accepted and fixed items, outside-code items, and open items by risk level.
- A results-by-control table shows, for every control the rules cover, which rules ran, how many check points, the result and the items behind it.
- Findings are numbered (F-001, F-002) and show their risk level. The record appears in the Markdown, JSON and HTML reports, and `--save-record` keeps a copy in `.lintsure/records/` to build a dated history.
- It is called a readiness record, not an audit, and it is a draft until a person reviews it. A test checks that audit-only terms never appear.

### Reports
- `lintsure baseline` saves today's findings to `.lintsure/baseline.json`. Every later report says what is new, fixed or unchanged.
- Accept a finding after review in `.lintsure/accepted.yaml`, with a reason, a name, a date and an optional review date. Accepted findings stay in the report but don't fail CI; past the review date they count as open again.
- Each finding has a fingerprint (a one-way hash of rule, file and line content), so moving code doesn't make old findings look new.
- `--sarif` writes `lintsure.sarif` for GitHub code scanning; `--github` prints line annotations; `--new-only` fails only on new findings.
- None of these files contain source code.

### GitHub Action
- Findings show on their lines in the pull request.
- With a baseline, only new findings fail the job (`new-only`, on by default).
- Optional SARIF output and an opt-in pull request comment that lists new findings, never code.

### Rules and accuracy
- New benchmark: labelled lines every rule must catch or must not flag. The build fails if any rule scores lower than before. Scores are on the docs Rules page.
- Personal data in logs: only the log call's own arguments are checked, so other code on the same line no longer causes false alarms.
- SQL built from strings: Gap when the inserted value looks like user input, Partial when it may be fixed text from your own code. Sentences such as "Select a plan from..." are no longer read as SQL.

## 0.1.3 · 2026-11-08 · Ask first, every time

Commit 37dd1f5.

A hard rule for every agent that uses Lintsure: explain, point, show the benefit, ask, and wait.

- Every finding now carries a proposal with four parts: where (the exact file and line), what would change, why (the problem and the controls it relates to) and the benefit. It is marked as needing approval.
- Reports show each proposal under "Proposed change. Nothing changes until you approve it."
- The MCP server tells agents to present a proposal and wait for a clear yes before any action: editing, creating or deleting files, running commands, installing packages, or treating a framework as applying. One proposal at a time.
- Every MCP tool is marked read-only for clients.
- Tests fail if a finding lacks any part of its proposal, if a report misses the approval heading, or if a scan reply misses the approval rules.

## 0.1.2 · 2026-11-07 · Listed in the MCP Registry

- `@lintsure/mcp` gains the `mcpName` field the official MCP Registry uses to confirm ownership (9617924).
- `server.json` added, and Lintsure is listed in the registry as `io.github.lintsure/lintsure`.

## 0.1.1 · 2026-11-07 · Less noise

Fewer false alarms on real projects. Running on a folder of seven projects, findings dropped from 153 to 68 with no real problem lost.

- Skips build output and caches (`.output`, `out`, `.nuxt`, `.svelte-kit`, `.astro`, `.vercel`, `.wrangler`, `.turbo`, `.cache`) and minified files (b936098)
- New `ignore:` list in `lintsure.config.yaml` to skip paths such as tests or fixtures (b936098)
- "Personal data written to logs" no longer flags words inside a message, like "email error", but still flags values put into it, like `{user.email}` (b936098)
- "TLS certificate checks turned off" only flags `verify=False` on HTTP client calls (b936098)

## 0.1.0 · 2026-11-07 · First public release

The engine, CLI, MCP server and [GitHub Action](https://github.com/lintsure/action) are open source. 16 draft rules across the EU AI Act, GDPR, SOC 2 and ISO/IEC 27001, with a human review step built into every result.

> Lintsure is a readiness tool, not an audit, a certification or legal advice. See [DISCLAIMER.md](DISCLAIMER.md).

### Engine and rules
- Core engine, CLI and MCP server, with tests that run the same input twice and expect the same result (e0d5cae)
- 8 GDPR and SOC 2 rules, each with a planted example and a near miss that must not be flagged (d4c2de7)
- 5 EU AI Act rules, and rules that can read a whole file (e6da1be)
- Plain-English knowledge of each framework, used to suggest frameworks and list work outside code (54bf93d)
- Choose frameworks with `lintsure.config.yaml` (dcfbe9c)

### Human in the loop
- Every report and every MCP reply carries the disclaimer, the work outside code and the next steps for a person (9a7860d)
- The MCP server tells coding agents not to give verdicts, not to decide, and to ask before any change (9a7860d)
- Tests fail if Lintsure's own wording claims you are compliant, certified or ready (9a7860d)

### Reports
- Multi-page assessment report with findings, possible fixes, an outside-code checklist and a human sign-off page: `lintsure scan --report` (0465c6a)
- Clearer CLI summary line (1a55089)

### Not yet
- The team platform
