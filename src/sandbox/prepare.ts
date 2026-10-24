// Runs ONLY inside the network-disabled preparation container. Never import on the host.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { Config, loadConfig } from "../config.js";
import { scanRepo } from "../init/facts.js";
import { buildDraft } from "../init/draft.js";
import { hashConfigText, makeEnvCanaries, seedDatabase } from "../seed.js";

const root = "/work/target";
const safeFile = (p: string) => !p.split("/").some((s) => /^(?:\.env(?:\..*)?|\.git|\.ssh|\.aws|\.npmrc|\.yarnrc.*|node_modules|out)$/i.test(s)) && !/\.(?:pem|key|p12|pfx|db|sqlite|sqlite3)(?:-.*)?$/i.test(p);

try {
  mkdirSync(root, { recursive: true });
  // Archive path traversal is handled by tar inside the container, never on the laptop.
  const unpacked = spawnSync("tar", ["xz", "--no-same-owner", "--no-same-permissions", "--strip-components=1", "-C", root], {
    stdio: ["inherit", "ignore", "pipe"], timeout: 20_000, maxBuffer: 64 * 1024,
  });
  if (unpacked.status !== 0) throw new Error("Archive extraction failed or exceeded its limit");
  let count = 0, bytes = 0;
  function inspect(dir: string) {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name), rel = relative(root, path), st = lstatSync(path);
      if (!safeFile(rel)) { rmSync(path, { recursive: true, force: true }); continue; }
      if (st.isSymbolicLink() || (!st.isDirectory() && !st.isFile()) || (st.isFile() && st.nlink !== 1)) throw new Error("Archive links and special files are unsupported");
      if (++count > 2000 || (bytes += st.isFile() ? st.size : 0) > 32 * 1024 * 1024 || st.size > 1024 * 1024) throw new Error("Repository exceeds the demo source limits");
      if (st.isDirectory()) inspect(path);
    }
  }
  inspect(root);
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const dependencies = Object.keys(pkg.dependencies ?? {});
  if (dependencies.some((d) => d !== "express") || !dependencies.includes("express")) throw new Error("Only Express with node:sqlite is supported by the offline demo image");
  const entry = ["app.mjs", "app.js", "server.mjs", "server.js"].find((p) => existsSync(join(root, p)));
  if (!entry) throw new Error("No supported root JavaScript entrypoint");
  // Even schema discovery executes untrusted SQL: it stays in this preparation container.
  const facts = scanRepo(root);
  if (facts.db.kind !== "sqlite" || facts.db.lib !== "node:sqlite" || !facts.db.envName) throw new Error("The demo requires node:sqlite with an environment-configurable database path");
  if (!facts.auth.tokenEnv || !["bearer-pairs", "bearer-env"].includes(facts.auth.kind)) throw new Error("A configurable Bearer token:organization mapping is required");
  if (!facts.readsPortEnv) throw new Error("The app must accept the PORT environment variable");
  const draft = buildDraft(facts, { cwd: ".", isolation: "container", llmData: "none", start: `node ${entry}` });
  if (draft.blocker || draft.unsupported.length) throw new Error("Automatic test setup is unsupported for this application");
  const provided = existsSync(join(root, "argos.config.yaml"));
  const cfg = provided ? loadConfig(join(root, "argos.config.yaml")) : Config.parse(draft.config);
  if (!cfg.seed || cfg.resources.length > 60 || cfg.personas.length > 4) throw new Error("Unsupported schema or test matrix size");
  const orgs = [...new Set(cfg.personas.flatMap((p) => p.org ? [p.org] : []))];
  if (orgs.length < 2 || orgs.length > 3 || orgs.some((o) => !/^[a-zA-Z0-9_-]{1,40}$/.test(o))) throw new Error("Two or three synthetic organizations are required");
  // Never reuse source tokens, source env values, npm scripts, or customer container/start settings.
  cfg.personas = orgs.map((org) => ({ name: `user-${org}`, org, auth: { type: "bearer" as const, token: `argos-test-${randomBytes(24).toString("hex")}` } }));
  cfg.personas.push({ name: "anonymous", auth: { type: "none" } });
  cfg.target = { start: `node ${entry}`, cwd: ".", baseUrl: "http://127.0.0.1:0", readyPath: cfg.target.readyPath, isolation: "container", runtime: "node", container: { memory: "512m", cpus: "1", pids: 128 }, env: {
    [facts.auth.tokenEnv]: cfg.personas.filter((p) => p.auth.type === "bearer").map((p) => `${p.auth.type === "bearer" ? p.auth.token : ""}:${p.org}`).join(","),
    [facts.db.envName]: "/tmp/argos-test.db",
  } };
  cfg.seed = { schema: cfg.seed.schema, dbPath: ".argos-test.db" };
  const untested = facts.routes.filter((r) => !cfg.resources.some((s) => s.route.split("?")[0] === `${r.method} ${r.path}`)).map((r) => `${r.method} ${r.path}: not included in the test policy`);
  // Writes are outside the first service adapter even when source config marks them safe.
  for (const r of cfg.resources) if (!r.route.startsWith("GET ")) { r.safe = false; untested.push(`${r.route}: write/non-GET execution disabled`); }
  cfg.resources = cfg.resources.filter((r) => r.route.startsWith("GET "));
  cfg.checks = ["bola", "unauth", "sqli", "secrets"];
  cfg.secrets.staticScan = false;
  cfg.secrets.envCanaries = ["JWT_SECRET", "SECRET_KEY", "API_KEY"];
  cfg.mode = "report";
  cfg.llm = { provider: "anthropic", data: "none" };
  const key = hashConfigText(randomBytes(32).toString("hex"));
  const envCanaries = makeEnvCanaries(cfg, key);
  const manifest = { ...seedDatabase(cfg, { workdir: root, seedKey: key }), envCanaries };
  for (const c of envCanaries) cfg.target.env[c.name] = c.marker;
  symlinkSync("/opt/argos/node_modules", join(root, "node_modules"));
  writeFileSync("/work/launch.json", JSON.stringify({ entry, env: cfg.target.env }));
  console.log(JSON.stringify({ supported: true, cfg, manifest, policy: provided ? "repository" : "draft", untested }));
} catch {
  // Never export raw SQL/source/parser errors: they can contain repository secrets.
  console.log(JSON.stringify({ supported: false, reason: "Automatic preparation failed: supported adapter is root Express + node:sqlite + configurable Bearer token/org mapping; archive, schema and resource limits also apply." }));
}
