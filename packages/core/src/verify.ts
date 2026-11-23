// What a reviewer checks before calling a finding real. A rule matches a pattern; these lists say what has to be true
// for the match to matter, and what makes it harmless. They come from findings reviewed one by one against the code in
// our field tests: each "not a problem when" line is a false alarm we have seen. Used by explain_rule and the triage skill.

export interface Verify {
  /** All of these should hold before a finding is called real. */
  real: string[];
  /** Any one of these makes it not a problem, if you can point to the evidence. */
  notReal: string[];
}

const SHIPS = "The file is part of what runs for users: not a test, a fixture, an example, a seed script or a dev tool.";
const NOT_SHIPPED = "The file never runs for users: a test, a fixture, an example, documentation or a one-off script.";

// By kind of rule, for rules with no list of their own. First match wins.
const FAMILIES: [RegExp, Verify][] = [
  [/^(sql|nosql|cmd|code|xss|template|path|ssrf|redirect|proto|deserialize|xml|log\.injection|llm\.output-to-sink|upload)\b/, {
    real: ["The value comes from outside your code: a request, a form, a file upload, a model's answer or another service.", "It reaches the flagged call unchanged, with no escaping, parameter binding, allow-list or schema check on the way.", SHIPS],
    notReal: ["The value is a constant, or is built only from constants and your own config.", "A check on the way makes it safe: a parameterised query, an escaping helper, an allow-list, a validator that rejects anything unexpected.", NOT_SHIPPED],
  }],
  [/^(secret|log\.secret|auth\.hardcoded-password|jwt\.weak-secret|config\.default|docker\.secret|supabase\.service-key|mobile\.token)\b/, {
    real: ["The value is a working credential, or the place where one will be put: long, random-looking, or with a provider's prefix.", "Code that runs for users reads it, or it is in a file that gets committed or shipped.", "Nothing replaces it before it is used: no environment variable or secret store overrides it in production."],
    notReal: ["It is a placeholder or an example: a made-up value, a documented test key, or text that only describes a key.", "It is public by design, such as a publishable or anon key meant for the browser.", "It is a fallback for local development only, and production fails to start without the real one."],
  }],
  [/^(pii|privacy|payment|ai\.emotion|ai\.automated)\b/, {
    real: ["The field identifies a person, or is sensitive on its own: an email, a name, a phone number, an address, health or payment data.", "It leaves the place it belongs: into a log, a URL, an analytics tool, a third party or long-term storage.", "Nothing masks, hashes or removes it first, and no consent or stated need covers this use."],
    notReal: ["The value is masked, hashed or shortened before this line, in this file or by an imported helper.", "The field is an internal id or a label that says nothing about a person.", "It is test or seed data with made-up people.", NOT_SHIPPED],
  }],
  [/^(authz|auth|jwt|cookie|session|csrf|supabase|cloud\.function|ws|cors|graphql)\b/, {
    real: ["Someone who should not have access can reach this code path: the endpoint, table or function is exposed.", "Nothing earlier enforces the check: no middleware, gateway, database policy or wrapper covers this path.", "What it guards matters: other people's data, an account, money, or an action with lasting effect."],
    notReal: ["The check exists somewhere else that covers this path, and you can name the file and line.", "The data or action is public on purpose.", "The line only runs outside production, inside a branch that checks the environment.", NOT_SHIPPED],
  }],
  [/^(deps|ci|docker|k8s|repo|update|release|build|html\.script|cloud|fs|mobile)\b/, {
    real: ["The file is used for a real build, release or deployment, not kept as an example.", "The weak setting is the one in effect: nothing later in the file or in another file overrides it.", "It gives something to gain: a secret within reach, a wider permission, or code that can change without a change in this repo."],
    notReal: ["The setting is pinned or tightened somewhere else that takes effect: a lockfile, a digest, a platform default, a runtime flag.", "The file is a local development or test setup that never reaches a real environment.", "The thing is first-party: your own action, image or script, in a repo you control."],
  }],
  [/^(agent|skill|mcp|llm|ai|ml)\b/, {
    real: ["An agent or model will read or run this: the file is where the agent looks, or the call is in code that ships.", "The text or input is used as written: it is an instruction or a live value, not a quoted example or a warning about one.", "A person does not see or approve the step before it takes effect."],
    notReal: ["The file is a detector, a test set or documentation that lists these patterns to catch or explain them.", "It is the stated job of the skill or tool, and the user is asked before it happens.", "A limit set elsewhere applies: the agent's own permission prompts, an output cap, a sandbox."],
  }],
  [/./, {
    real: ["The flagged line does what the finding says, in code or config that is in effect.", "Nothing nearby or elsewhere cancels it out.", SHIPS],
    notReal: ["A stronger setting elsewhere takes effect over this one.", "The line only runs outside production.", NOT_SHIPPED],
  }],
];

// Rules with their own list: the ones that produce most findings in the field, and the ones where the generic list misleads.
const SPECIFIC: Record<string, Verify> = {
  "pii.logged": {
    real: ["The logged value is personal data: an email, a name, a phone number, an address, or an object that holds them (a whole user or request body).", "The log line runs in production code, at a level that is switched on there.", "The value is logged as it is, not through a masking or hashing helper."],
    notReal: ["A helper masks or hashes the value first, in this file or imported from another one.", "Only an internal id, a count or a status is logged, even if the variable is named after a person.", "The line is in a seed, demo, migration or debugging script that never runs for users.", "The log level is debug and production runs at info or above, with evidence in the logger config."],
  },
  "secret.in-source": {
    real: ["The value has the shape of a working key: a provider prefix, enough length and randomness, a full key body.", "It is in a file that is committed, not one that .gitignore keeps out.", "It is not replaced at build or run time by an environment variable."],
    notReal: ["It is a placeholder: repeated or sequential characters, the word example or test, or a value from the provider's own documentation.", "It decodes to ordinary text, or is a hash, an id or a public key.", "It is in a test or fixture and was never a real credential. If in doubt, treat it as real: a leaked key must be replaced, not just removed."],
  },
  "sql.string-built": {
    real: ["A value from a request, a form or another outside source is joined into the SQL text.", "The query runs with that text: no parameter binding and no query builder between them.", SHIPS],
    notReal: ["Only constants, column names from a fixed list, or numbers your code computed are joined in.", "The joined value is checked against an allow-list first (a sort column picked from a map, for example).", "The driver's tagged template or the ORM binds the value even though the code looks like string building."],
  },
  "path.user-input": {
    real: ["Part of the path comes from a request, an upload's file name or another outside source.", "The path is used to read, write, delete or serve a file without being resolved and checked against a base folder.", SHIPS],
    notReal: ["The path is resolved and then checked to start with the allowed folder.", "The outside value is only a key into a fixed list of paths.", "The value is an id that passes a strict pattern (digits or a UUID) before it is used."],
  },
  "ssrf.user-url": {
    real: ["The address the server fetches comes from a request or stored user input.", "No allow-list of hosts is applied, and private and local addresses are not blocked.", "The response, or a difference in timing or errors, gets back to the caller."],
    notReal: ["The host is fixed in code and only the path or a query value varies, and that part is encoded.", "The address is checked against an allow-list before the request.", "The fetch runs in the browser, not on the server."],
  },
  "authz.no-owner-check": {
    real: ["The record is looked up by an id the caller supplies.", "The query does not also filter by the signed-in user, their team or their tenant.", "The table holds records that belong to different users, and no database policy limits rows per user."],
    notReal: ["The query filters by the caller's own id, or the id comes from the session and not the request.", "Row level security or a tenant scope on the client enforces ownership for this table.", "The record is public, or the endpoint is for admins and checks the admin role."],
  },
  "authz.admin-route-no-check": {
    real: ["The endpoint does something only an admin should: reads all users, changes roles, deletes records, sees billing.", "No role, session or token is checked in the handler or in a wrapper around it.", "The project's middleware does not cover this path, or covers pages only and lets API paths through."],
    notReal: ["A wrapper or helper with a name Lintsure did not recognise checks the role: name the file and line.", "A gateway or reverse proxy in front of the app limits this path to admins, with evidence in config.", "The endpoint is public on purpose despite its path, such as an admin sign-in."],
  },
  "auth.no-rate-limit": {
    real: ["The endpoint checks a password, a one-time code or a reset token.", "No limiter is applied in the handler, the middleware or the framework config.", "The auth provider does not limit attempts on its own side for this flow."],
    notReal: ["The route hands the attempt to an auth provider that limits and locks out by itself.", "A firewall, gateway or hosting rule limits this path, with evidence.", "The endpoint only starts a flow and never tells the caller whether a guess was right."],
  },
  "supabase.policy-allows-all": {
    real: ["The policy applies to insert, update, delete or all, and its condition is simply true.", "The role it applies to includes anon or authenticated, not only service_role.", "The table holds data that should differ per user."],
    notReal: ["The policy is select-only on a table meant to be public reading.", "The policy is for service_role alone.", "A later migration drops or replaces this policy."],
  },
  "jwt.unverified": {
    real: ["The token's contents are used to decide who the caller is or what they may do.", "The signature is not verified anywhere before that use.", SHIPS],
    notReal: ["The decode only reads a header or a claim to pick the key, and a verify call follows.", "The token was already verified by the framework, a gateway or the auth library before this line.", "The decode runs in the browser to show a name or an expiry, and the server verifies on every request."],
  },
  "llm.user-input-in-system-prompt": {
    real: ["Text a user or an outside document supplies is placed in the system or developer message.", "The model can call tools or its answer is acted on, so changed instructions have an effect.", "Nothing separates the outside text from the instructions or strips instruction-like content."],
    notReal: ["Only a value from a fixed list (a language, a tone, a plan name) goes into the prompt.", "The outside text goes in the user message, and the system message stays fixed.", "The model has no tools and its answer is only shown back to the same user."],
  },
  "agent.instructions-unsafe": {
    real: ["The file is one an agent reads as its own instructions.", "The line tells the agent to drop earlier instructions, hide something from the user, send secrets out, or download and run a script.", "It is written as an instruction, not quoted as an example of an attack."],
    notReal: ["The line warns about the phrase or tells the agent to refuse it.", "The file is a detector's test data or documentation about prompt injection.", "A download-and-run line is a documented installer for a tool you chose, from a source you trust and pin."],
  },
  "ci.action-unpinned": {
    real: ["The action is third-party: not from actions/, github/ or your own organisation.", "It is pinned to a tag or a branch, which its owner can move, not to a full commit SHA.", "The job that uses it has secrets, a write token or a deploy step within reach."],
    notReal: ["The action belongs to your own organisation or is vendored in this repo.", "The job has no secrets and a read-only token, and nothing it produces is published.", "A policy outside the file pins or allow-lists actions for the whole organisation."],
  },
  "deps.unpinned-version": {
    real: ["The dependency is installed with no version, a wildcard or latest.", "No lockfile fixes the version for the build that ships.", "The install runs in a build or deploy, not only on a developer's machine."],
    notReal: ["A committed lockfile pins the exact version and the build installs from it.", "The line is in documentation or an example command.", "It is a tool run once by a developer, never part of the build."],
  },
  "docker.runs-as-root": {
    real: ["The image is the one that runs in production, not a build stage or a dev container.", "No USER line sets a non-root user in the final stage, and the base image runs as root.", "Nothing at run time sets the user: no runAsUser, no --user flag."],
    notReal: ["The base image already switches to a non-root user.", "The orchestrator sets the user or runs the container rootless, with evidence in its config.", "The Dockerfile is for local development or CI only."],
  },
  "update.unverified-download": {
    real: ["A script or binary is downloaded and then run or installed.", "No checksum or signature is checked, and the address is not pinned to a version.", "It runs in a build, a deploy or on users' machines, not only once on a developer's laptop."],
    notReal: ["A checksum or signature is verified before the file is run.", "The address includes an exact version or commit and the source is one you trust.", "The line is from a README telling a person what to run, not something a pipeline runs."],
  },
};

/** The review lists for a rule: its own, or the ones for its kind. Never empty. Pure. */
export function verifyFor(ruleId: string): Verify {
  return SPECIFIC[ruleId] ?? FAMILIES.find(([re]) => re.test(ruleId))![1];
}
/** Ids that have their own list, for the test that checks each one names a real rule. */
export const VERIFY_IDS = Object.keys(SPECIFIC);
/** The lists as text an agent or a person can work through. Pure. */
export function verifyText(ruleId: string): string {
  const v = verifyFor(ruleId);
  return `Call it real only when all of these hold:\n${v.real.map((x) => `- ${x}`).join("\n")}\nIt is not a problem when any one of these holds, and you can point to the evidence:\n${v.notReal.map((x) => `- ${x}`).join("\n")}`;
}
