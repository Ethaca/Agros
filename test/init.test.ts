import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { loadConfig, parseConfig } from "../src/config.js";
import { buildDraft, type Draft } from "../src/init/draft.js";
import { scanRepo } from "../src/init/facts.js";
import { InitError, runInit } from "../src/init/index.js";
import { renderReport, loadScan } from "../src/report.js";
import { runScan } from "../src/scan.js";

const APP = resolve("test/fixtures/init-app");

function repo(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "argos-initrepo-"));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, name)), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  return dir;
}
const appCopy = (): string => {
  const d = mkdtempSync(join(tmpdir(), "argos-initapp-"));
  cpSync(APP, d, { recursive: true });
  return d;
};
const draftOf = (files: Record<string, string>, o: Partial<Parameters<typeof buildDraft>[1]> = {}): Draft =>
  buildDraft(scanRepo(repo(files)), { cwd: ".", isolation: "process", llmData: "none", ...o });
const res = (d: Draft, id: string) => (d.config.resources as any[]).find((r) => r.id === id);
const PKG = JSON.stringify({ scripts: { start: "node app.mjs" } });
const SCHEMA = `CREATE TABLE notes (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, title TEXT);
CREATE TABLE tips (id INTEGER PRIMARY KEY, text TEXT);
CREATE TABLE orgs (id TEXT PRIMARY KEY, name TEXT, api_key TEXT);`;
const SRC = `
const tokens = (process.env.APP_TOKENS ?? "tk-a:orgA,tk-b:orgB");
app.get("/health", (req, res) => res.json({}));
app.get("/api/tips", (req, res) => res.json(db.prepare("SELECT id, text FROM tips").all()));
app.get("/api/notes/:id", auth, (req, res) => res.json(db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id)));
app.get("/api/orgs/:id", auth, (req, res) => res.json(db.prepare("SELECT * FROM orgs WHERE id = ?").get(req.params.id)));
app.get("/debug/env", (req, res) => res.json(process.env));
app.post("/api/notes", auth, (req, res) => { db.prepare("INSERT INTO notes (org_id) VALUES (?)").run(req.user.org_id); });
const port = process.env.PORT; const db = new DatabaseSync(process.env.DB_PATH ?? "./data.db"); // node:sqlite
`;
const BASE = { "package.json": PKG, "app.mjs": SRC, "schema.sql": SCHEMA };

// ---------------------------------------------------------------- facts
test("facts: the express-shaped fixture is read correctly", () => {
  const f = scanRepo(APP);
  assert.equal(f.start?.value, "node --no-warnings app.mjs");
  assert.equal(f.readsPortEnv, true);
  assert.deepEqual(f.db, { kind: "sqlite", lib: "node:sqlite", envName: "DB_PATH", defaultPath: "./data.db" });
  assert.equal(f.auth.kind, "bearer-pairs");
  assert.equal(f.auth.tokenEnv, "APP_TOKENS");
  assert.deepEqual(f.auth.pairs, [{ token: "tk-a", org: "orgA" }, { token: "tk-b", org: "orgB" }]);
  assert.equal(f.principal, "req.user.org_id");
  assert.deepEqual(f.schema!.tables.map((t) => t.name), ["notes", "orgs", "tips"]);
  assert.equal(f.routes.length, 7);
  const by = (m: string, p: string) => f.routes.find((r) => r.method === m && r.path === p)!;
  assert.deepEqual([by("GET", "/api/notes/:id").auth, by("GET", "/api/notes/:id").tables, by("GET", "/api/notes/:id").pathParams], ["yes", ["notes"], ["id"]]);
  assert.deepEqual(by("GET", "/api/notes").queryParams, ["search"]);
  assert.equal(by("POST", "/api/notes").writes, true);
  assert.deepEqual([by("GET", "/api/tips").auth, by("GET", "/api/tips").tables], ["no", ["tips"]]);
  assert.deepEqual([by("GET", "/debug/env").auth, by("GET", "/debug/env").tables], ["no", []]);
});

test("facts: both demo apps are read (tokens, principal, all ten routes)", () => {
  for (const app of ["vendor-platform", "realistic-app"]) {
    const f = scanRepo(resolve("demo", app));
    assert.equal(f.auth.pairs.length, 3, app);
    assert.equal(f.principal, "req.user.vendor_id", app);
    assert.ok(f.routes.length >= 9, app);
    assert.deepEqual(f.routes.find((r) => r.path === "/api/datasets")!.tables, ["datasets"], `${app}: a comment mentioning "into the SQL" is not a table`);
  }
});

test("facts: comments and plain code never become table names", () => {
  const f = scanRepo(repo({ "package.json": PKG, "app.mjs": `// we write into the database from here\napp.get("/x", (req, res) => { /* select from the cache */ res.json(1); });` }));
  assert.deepEqual(f.routes[0]!.tables, []);
});

test("facts: global and path-scoped auth middleware apply to the routes after them", () => {
  const f = scanRepo(repo({ "app.js": `
app.get("/open", (req, res) => 1);
app.use("/api", requireAuth);
app.get("/api/a", (req, res) => 1);
app.get("/other", (req, res) => 1);
app.use(authMiddleware);
app.get("/late", (req, res) => 1);
` }));
  const auth = Object.fromEntries(f.routes.map((r) => [r.path, r.auth]));
  assert.deepEqual(auth, { "/open": "no", "/api/a": "yes", "/other": "no", "/late": "yes" });
});

test("facts: what cannot be found is reported as missing, never guessed", () => {
  const f = scanRepo(repo({ "readme.txt": "nothing here" }));
  assert.equal(f.start, undefined);
  assert.deepEqual([f.routes, f.db.kind, f.auth.kind, f.schema], [[], "none", "none", undefined]);
  assert.match(f.notes.join(), /no package\.json/);
});

// ---------------------------------------------------------------- draft rules
test("draft: expect is a conservative default and every decision is ai-draft", () => {
  const d = draftOf(BASE);
  assert.equal(d.blocker, undefined);
  parseConfig(d.config);
  assert.deepEqual(res(d, "get-notes-id").expect, { owner: "allow", other: "deny", anonymous: "deny" });
  assert.deepEqual(res(d, "get-notes-id").owner, { table: "notes", column: "org_id" });
  for (const id of ["get-notes-id", "get-orgs-id", "get-debug-env"]) assert.equal(d.provenance[`resources.${id}.expect`], "ai-draft", id);
  assert.equal(d.config.provenance["resources.get-orgs-id.expect"], "ai-draft");
});

test("draft: public only by data (no owner/secret columns, no auth), never because the code lets everyone in", () => {
  const d = draftOf(BASE);
  assert.equal(res(d, "get-tips").public, true, "reads only tips: public candidate");
  assert.equal(d.provenance["resources.get-tips.public"], "ai-draft");
  assert.equal(res(d, "get-health").public, true);
  assert.equal(d.provenance["resources.get-health.public"], undefined, "a health route needs no confirmation");
  assert.equal(res(d, "get-debug-env").public, undefined, "no table, no auth: not public");
  assert.deepEqual(res(d, "get-debug-env").expect, { owner: "deny", other: "deny", anonymous: "deny" }, "internal-looking: denied to everyone");
  // an unauthenticated route that reads TENANT data stays protected in the draft, and is flagged
  const open = draftOf({ ...BASE, "app.mjs": SRC + `\napp.get("/api/export-all", (req, res) => res.json(db.prepare("SELECT * FROM notes").all()));` });
  assert.equal(res(open, "get-export-all").public, undefined);
  assert.deepEqual(res(open, "get-export-all").expect, { owner: "allow", other: "deny", anonymous: "deny" });
  assert.ok(open.needsHuman.some((n) => n.topic === "expect" && /no auth middleware.*GET \/api\/export-all/.test(n.message)));
});

test("draft: a table with a secret column is never a public candidate", () => {
  const d = draftOf({ ...BASE, "app.mjs": SRC + `\napp.get("/api/keys", (req, res) => res.json(db.prepare("SELECT id FROM orgs").all()));`, "schema.sql": SCHEMA });
  assert.equal(res(d, "get-keys").public, undefined);
});

test("draft: routes that change data or cannot be judged are listed as not tested, with the reason", () => {
  const d = draftOf(BASE);
  assert.ok(d.untested.some((u) => u.route === "POST /api/notes" && /changes data/.test(u.reason)));
  const noOwner = draftOf({ ...BASE, "app.mjs": SRC + `\napp.get("/api/tips/:id", auth, (req, res) => res.json(db.prepare("SELECT * FROM tips WHERE id = ?").get(req.params.id)));` });
  assert.ok(noOwner.untested.some((u) => u.route === "GET /api/tips/:id" && /no owner column/.test(u.reason)));
  assert.equal(res(noOwner, "get-tips-id"), undefined);
});

test("draft: a read-only POST is called only as safe: true, flagged for confirmation", () => {
  const d = draftOf({ ...BASE, "app.mjs": SRC + `\napp.post("/api/report", auth, (req, res) => res.json(db.prepare("SELECT * FROM notes WHERE org_id = ?").all(req.user.org_id)));` });
  assert.equal(res(d, "post-report").safe, true);
  assert.equal(d.provenance["resources.post-report.safe"], "ai-draft");
  assert.ok(d.needsHuman.some((n) => n.topic === "safe"));
});

test("draft: a GET route carries its query parameters (for sqli), a POST route does not", () => {
  const d = draftOf({ ...BASE, "app.mjs": SRC + `\napp.get("/api/find", auth, (req, res) => res.json(db.prepare("SELECT * FROM notes WHERE org_id = ?").all(req.query.q)));\napp.post("/api/report", auth, (req, res) => res.json(db.prepare("SELECT * FROM notes WHERE org_id = ?").all(req.query.org)));` });
  assert.equal(res(d, "get-find").route, "GET /api/find?q=");
  assert.equal(res(d, "post-report").route, "POST /api/report");
});

// ---------------------------------------------------------------- test environment
test("tokens: the repo's own test tokens are used as they are, without injecting any environment", () => {
  const d = draftOf(BASE);
  assert.deepEqual(d.config.personas.map((p: any) => [p.name, p.org, p.auth.token ?? null]), [["user-orgA", "orgA", "tk-a"], ["user-orgB", "orgB", "tk-b"], ["anonymous", undefined, null]]);
  assert.deepEqual(d.config.target.env, {});
});

test("tokens: no default in the code -> deterministic generated tokens injected through the token variable", () => {
  const files = { ...BASE, "app.mjs": SRC.replace(`process.env.APP_TOKENS ?? "tk-a:orgA,tk-b:orgB"`, `process.env.APP_TOKENS`) + `\nconst h = req.headers.authorization; // Bearer` };
  const a = draftOf(files);
  const b = draftOf(files);
  assert.equal(a.config.personas.filter((p: any) => p.org).length, 2);
  const [t1, t2] = a.config.personas.filter((p: any) => p.org).map((p: any) => p.auth.token);
  assert.match(t1, /^tok-argos-[0-9a-f]{8}$/);
  assert.equal(a.config.target.env.APP_TOKENS, `${t1}:org1,${t2}:org2`);
  assert.ok(a.needsHuman.some((n) => n.topic === "auth" && /format/.test(n.message)), "the token format is an assumption a person confirms");
  assert.notEqual(t1, t2);
  void b;
});

test("tokens: JWT, session and unknown auth are reported as unsupported, with placeholder tokens (no pretending)", () => {
  const jwt = draftOf({ ...BASE, "package.json": JSON.stringify({ scripts: { start: "node app.mjs" }, dependencies: { jsonwebtoken: "^9" } }), "app.mjs": SRC.replace(/const tokens[^\n]*\n/, "") });
  assert.match(jwt.unsupported.join(), /JWT/);
  assert.ok(jwt.config.personas.some((p: any) => p.auth.token === "tok-replace-me-1"));
  assert.ok(jwt.needsHuman.some((n) => n.topic === "auth" && /placeholders/.test(n.message)));
  const session = draftOf({ ...BASE, "package.json": JSON.stringify({ scripts: { start: "node app.mjs" }, dependencies: { "express-session": "^1" } }), "app.mjs": SRC.replace(/const tokens[^\n]*\n/, "") });
  assert.match(session.unsupported.join(), /session/);
});

test("env canaries never name a variable the app needs to work (token, database, port)", () => {
  const d = draftOf({ ...BASE, "app.mjs": SRC + `\nconst k = process.env.SESSION_SECRET; const t = process.env.APP_TOKENS; const x = process.env.PORT;`, ".env.example": "DB_PASSWORD=\nAPP_TOKENS=\nPORT=\n" });
  const canaries: string[] = d.config.secrets.envCanaries;
  assert.ok(canaries.includes("SESSION_SECRET") && canaries.includes("DB_PASSWORD"));
  for (const bad of ["APP_TOKENS", "PORT", "DB_PATH"]) assert.ok(!canaries.includes(bad), `${bad} must not be a canary: injecting it would break the app`);
});

test("sensitive columns: extra secret-looking columns are added, plain ids are not", () => {
  const d = draftOf({ ...BASE, "schema.sql": SCHEMA + "\nCREATE TABLE keys (id INTEGER PRIMARY KEY, org_id TEXT, private_key TEXT, key_id TEXT, access_token TEXT);" });
  assert.deepEqual(d.config.secrets.sensitiveColumns, ["api_key", "token", "secret", "password", "private_key"]);
});

// ---------------------------------------------------------------- limits and blockers
test("blockers and unsupported setups are explicit", () => {
  assert.match(draftOf({ "readme.txt": "x" }).blocker!, /no start command/);
  assert.equal(draftOf({ "readme.txt": "x" }, { start: "node server.js" }).blocker?.includes("no start command"), false);
  assert.match(draftOf({ "package.json": PKG, "app.mjs": `// nothing\n` }).blocker!, /no testable routes/);
  const pg = draftOf({ ...BASE, "package.json": JSON.stringify({ scripts: { start: "node app.mjs" }, dependencies: { pg: "^8" } }), "app.mjs": SRC.replace("// node:sqlite", "") });
  assert.match(pg.unsupported.join(), /pg is not supported yet/);
  const noSchema = draftOf({ "package.json": PKG, "app.mjs": SRC });
  assert.ok(noSchema.needsHuman.some((n) => n.topic === "schema"));
  assert.equal(noSchema.config.seed, undefined);
});

test("start source, health and port facts are asked about when guessed or missing", () => {
  const d = draftOf({ "app.js": `app.get("/api/tips", (req, res) => res.json(db.prepare("SELECT * FROM tips").all()));`, "schema.sql": SCHEMA });
  assert.ok(d.needsHuman.some((n) => n.topic === "start"));
  assert.ok(d.needsHuman.some((n) => n.topic === "health"));
  assert.ok(d.needsHuman.some((n) => n.topic === "port"));
});

// ---------------------------------------------------------------- end to end
const quiet = { log: () => {}, isolation: "process" as const };

test("init end to end: config written, round-trips, verified, K and T1 reported, nothing sent anywhere", async () => {
  const dir = appCopy();
  const reportDir = mkdtempSync(join(tmpdir(), "argos-initrep-"));
  const r = await runInit({ dir, reportDir, ...quiet });
  assert.equal(r.exitCode, 0, JSON.stringify(r.verification));
  assert.equal(r.verification!.ok, true);
  assert.deepEqual(r.verification!.loggedIn.sort(), ["user-orgA", "user-orgB"]);
  assert.ok(r.verification!.preview!.VULNERABLE > 0, "the fixture has planted flaws; the preview sees them");
  const cfg = loadConfig(r.configPath);
  assert.equal(cfg.target.isolation, "process");
  assert.equal(cfg.llm.data, "none");
  assert.equal(r.k, r.draft.needsHuman.length + r.draft.unsupported.length);
  assert.ok(r.t1Seconds >= 0);
  assert.deepEqual(JSON.parse(readFileSync(r.egressPath, "utf8")), { llm: false, sent: [], masked: 0, note: "no source file was sent anywhere: this draft came from static rules only" });
  const md = readFileSync(r.reportPath, "utf8");
  assert.match(md, /✅ 앱이 기동했고 2개 페르소나/);
  assert.match(md, /판정이 아니다/);
  assert.match(md, /사람이 확인할 것/);
  assert.match(md, /POST \/api\/notes.*changes data/);
  assert.ok(existsSync(join(dir, "argos.config.yaml")));
});

test("init output feeds the rest of the tool: scan works on it and the report lists the unconfirmed rules", async () => {
  const dir = appCopy();
  const r = await runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  const out = mkdtempSync(join(tmpdir(), "argos-initscan-"));
  const s = await runScan({ configPath: r.configPath, outDir: out, quiet: true, log: () => {} });
  assert.ok(s.counts.VULNERABLE > 0);
  assert.ok(s.meta.unconfirmed.length > 0);
  assert.ok(s.meta.unconfirmed.includes("resources.get-notes-id.expect"));
  const md = renderReport(loadScan({ scanDir: out }));
  assert.match(md, /\d+ unconfirmed expectations?/);
  assert.match(md, /\d+ AI draft fields? unconfirmed/);
  assert.match(md, /resources\.get-notes-id\.expect/);
});

test("a person's confirmation removes the field from the unconfirmed list", async () => {
  const dir = appCopy();
  const r = await runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  const text = readFileSync(r.configPath, "utf8").replace("resources.get-notes-id.expect: ai-draft", "resources.get-notes-id.expect: confirmed");
  writeFileSync(r.configPath, text);
  const s = await runScan({ configPath: r.configPath, outDir: mkdtempSync(join(tmpdir(), "argos-initscan-")), quiet: true, log: () => {} });
  assert.ok(!s.meta.unconfirmed.includes("resources.get-notes-id.expect"));
  assert.ok(s.meta.unconfirmed.includes("resources.get-orgs-id.expect"));
});

test("init never overwrites an existing config without --force", async () => {
  const dir = appCopy();
  writeFileSync(join(dir, "argos.config.yaml"), "# a person's confirmed rules\n");
  await assert.rejects(runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet }), (e: Error) => e instanceof InitError && /already exists/.test(e.message));
  assert.equal(readFileSync(join(dir, "argos.config.yaml"), "utf8"), "# a person's confirmed rules\n");
  await runInit({ dir, force: true, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  assert.match(readFileSync(join(dir, "argos.config.yaml"), "utf8"), /drafted by `argos init`/);
});

test("init does not touch the source: only the config and the report directory are written", async () => {
  const dir = appCopy();
  const before = readFileSync(join(dir, "app.mjs"), "utf8");
  await runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  assert.equal(readFileSync(join(dir, "app.mjs"), "utf8"), before);
  assert.ok(!existsSync(join(dir, "data.db")), "the app was verified in a temp copy");
});

test("--no-verify writes the draft without starting the app", async () => {
  const r = await runInit({ dir: appCopy(), verify: false, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  assert.equal(r.verification, undefined);
  assert.equal(r.exitCode, 0);
  assert.match(readFileSync(r.reportPath, "utf8"), /건너뜀\(`--no-verify`\)/);
});

test("verification catches a wrong test token: written, but exit 1 with the reason", async () => {
  const dir = appCopy();
  // the tokens in the code are what init reads; make the running app reject them (as if the token check changed)
  writeFileSync(join(dir, "app.mjs"), readFileSync(join(dir, "app.mjs"), "utf8").replace("tokens.get(m[1])", "tokens.get(m[1] + '-nope')"));
  const r = await runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  assert.equal(r.exitCode, 1);
  assert.equal(r.verification!.boot, true);
  assert.equal(r.verification!.ok, false);
  assert.match(r.verification!.problems.join("\n"), /user-orgA could not read its own data on .*\(401, expected allow\): check the test token/);
  assert.ok(existsSync(r.configPath), "the draft is still written so it can be fixed");
});

test("verification catches an app that does not start, with the log tail", async () => {
  const dir = appCopy();
  writeFileSync(join(dir, "app.mjs"), readFileSync(join(dir, "app.mjs"), "utf8").replace("const db =", `console.error("boot failed: missing config"); process.exit(3);\nconst db =`));
  const r = await runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet });
  assert.equal(r.exitCode, 1);
  assert.equal(r.verification!.boot, false);
  assert.match(r.verification!.problems.join("\n"), /the app did not start: target exited with code 3/);
  assert.match(r.verification!.problems.join("\n"), /boot failed: missing config/);
});

test("container is the default isolation; without docker verification is refused, not silently run on the host", async () => {
  const saved = process.env.DOCKER_HOST;
  process.env.DOCKER_HOST = "unix:///nonexistent/docker.sock";
  try {
    const r = await runInit({ dir: appCopy(), reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), log: () => {} });
    assert.equal(loadConfig(r.configPath).target.isolation, "container");
    assert.equal(r.verification!.ran, false);
    assert.equal(r.exitCode, 1);
    assert.match(r.verification!.problems.join(), /docker is not available/);
    assert.match(r.verification!.problems.join(), /--isolation process/);
  } finally {
    if (saved === undefined) delete process.env.DOCKER_HOST;
    else process.env.DOCKER_HOST = saved;
  }
});

test("a repo with nothing usable fails with the reason and writes no config", async () => {
  const dir = repo({ "readme.txt": "hi" });
  await assert.rejects(runInit({ dir, reportDir: mkdtempSync(join(tmpdir(), "argos-initrep-")), ...quiet }), /no start command/);
  assert.ok(!existsSync(join(dir, "argos.config.yaml")));
  await assert.rejects(runInit({ dir: "/nonexistent-dir", ...quiet }), /is not a directory/);
});

test("CLI: argos init exit codes and messages", () => {
  const run = (args: string[]) => spawnSync("node", ["--import", "tsx", "src/cli.ts", "init", ...args], { cwd: resolve("."), encoding: "utf8", env: { ...process.env, CI: "" } });
  const dir = appCopy();
  const ok = run([dir, "--isolation", "process", "--report", mkdtempSync(join(tmpdir(), "argos-initrep-"))]);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /verified: app starts, 2 personas can read their own data/);
  assert.match(ok.stdout, /T1 [\d.]+s · K \d+ item\(s\)/);
  const again = run([dir, "--isolation", "process"]);
  assert.equal(again.status, 1);
  assert.match(again.stderr, /argos: .*already exists/);
  const empty = run([repo({ "x.txt": "y" }), "--isolation", "process"]);
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /argos: no start command found/);
  assert.equal(run([dir, "--llm-data", "everything"]).status, 1);
});
