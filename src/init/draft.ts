import { createHash } from "node:crypto";
import { basename } from "node:path";
import { isSensitiveColumn } from "../seed.js";
import { ownerColumnOf, type RepoFacts, type RouteFact, type Table } from "./facts.js";

/**
 * Steps 2 and 4 of `argos init`: turn FACTS into a config draft with deterministic rules (no LLM).
 *
 * The rule that matters most: `expect` ("who may see what") is NOT inferred from how the code behaves. If it were,
 * a bug would become the rule and the scan would come out green. The default is conservative (the owner may read,
 * other orgs and anonymous may not), and every drafted decision is marked `ai-draft` for a person to confirm.
 */

export type Topic = "expect" | "public" | "safe" | "auth" | "start" | "health" | "port" | "db" | "schema" | "env" | "route";

export interface NeedsHuman {
  topic: Topic;
  message: string;
  where?: string;
}

export interface Draft {
  config: Record<string, any>;
  /** `ai-draft` for everything decided here. */
  provenance: Record<string, "ai-draft">;
  needsHuman: NeedsHuman[];
  /** Things argos cannot do for this repo yet, with the reason. */
  unsupported: string[];
  /** Routes found in the source but not put into the config, with the reason. */
  untested: { route: string; reason: string }[];
  /** What was found, for the report. */
  found: string[];
  /** Why no usable config could be drafted (nothing is written in that case). */
  blocker?: string;
}

export interface DraftOptions {
  /** target.cwd as seen from the config file. */
  cwd: string;
  isolation: "process" | "container";
  llmData: "files" | "none";
  /** Explicit start command (overrides detection). */
  start?: string;
}

const HEALTH = /^\/(?:health|healthz|ping|ready|readyz|live|livez|status)$/i;
const INTERNAL = /^\/(?:debug|admin|internal|env|metrics|_)/i;
const SENSITIVE_EXTRA = /secret|token|key|password|passwd|credential/i;
const CANARY_NAME = /SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL/i;
const DEFAULT_SENSITIVE = ["api_key", "token", "secret", "password"];
const DEFAULT_CANARIES = ["JWT_SECRET", "SECRET_KEY", "API_KEY", "STRIPE_SECRET_KEY"];

const sha8 = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 8);

function slug(r: RouteFact): string {
  const parts = r.path
    .split("/")
    .filter((s) => s && s !== "api")
    .map((s) => (s.startsWith(":") ? s.slice(1) : s));
  return `${r.method.toLowerCase()}-${parts.join("-") || "root"}`.replace(/[^a-z0-9-]/gi, "-");
}

/** Query parameters go into the route only for GET: that is what the sqli check tests. */
const routeString = (r: RouteFact): string => `${r.method} ${r.path}${r.method === "GET" && r.queryParams.length ? "?" + r.queryParams.map((q) => `${q}=`).join("&") : ""}`;

export function buildDraft(facts: RepoFacts, opts: DraftOptions): Draft {
  const needsHuman: NeedsHuman[] = [];
  const unsupported: string[] = [];
  const untested: Draft["untested"] = [];
  const found: string[] = [];
  const provenance: Draft["provenance"] = {};
  const tables = new Map<string, Table>((facts.schema?.tables ?? []).map((t) => [t.name.toLowerCase(), t]));
  const ask = (topic: Topic, message: string, where?: string) => needsHuman.push({ topic, message, ...(where ? { where } : {}) });

  // ---- target
  const start = opts.start ? { value: opts.start, source: "--start" } : facts.start;
  if (!start) {
    return { config: {}, provenance, needsHuman, unsupported, untested, found, blocker: "no start command found (package.json scripts.start/main, app.mjs, server.js, …). Pass --start \"<command>\"." };
  }
  found.push(`start command: \`${start.value}\` (${start.source})`);
  if (!opts.start && start.source.includes("guessed")) ask("start", `start command guessed from a file name: ${start.value}`, start.source);
  if (!facts.readsPortEnv) ask("port", "the app does not read process.env.PORT: Argos passes PORT, so a hard-coded port will not work", "source");

  const target: Record<string, any> = { start: start.value, cwd: opts.cwd, baseUrl: "http://127.0.0.1:0", readyPath: "/health", env: {}, isolation: opts.isolation };

  // ---- health
  const health = facts.routes.find((r) => r.method === "GET" && HEALTH.test(r.path));
  if (health) {
    target.readyPath = health.path;
    found.push(`health route: GET ${health.path} (${health.file}:${health.line})`);
  } else ask("health", "no health route found: Argos waits for GET /health to return 200. Add one or set target.readyPath", "target.readyPath");

  // ---- database
  const config: Record<string, any> = { version: 1, target };
  if (facts.db.kind === "other") {
    unsupported.push(`database: ${facts.db.lib} is not supported yet (only SQLite). Ownership checks need seeded data, so they cannot run.`);
  } else if (facts.db.kind === "none") ask("db", "no database library found: nothing to seed, ownership checks (bola, secrets) will have no data", "seed");
  if (facts.schema) {
    found.push(`schema: ${facts.schema.file} (${facts.schema.tables.length} tables: ${facts.schema.tables.map((t) => t.name).join(", ")})`);
    if (facts.db.kind === "sqlite" || facts.db.kind === "none") {
      const dbPath = facts.db.defaultPath ?? "./data.db";
      config.seed = { schema: facts.schema.file, dbPath };
      if (facts.db.envName && !facts.db.defaultPath) target.env[facts.db.envName] = dbPath;
      if (facts.schema.otherSqlFiles.length) ask("schema", `other .sql files were ignored: ${facts.schema.otherSqlFiles.join(", ")} (only ${facts.schema.file} is used as the seed schema)`, facts.schema.file);
    }
  } else if (facts.schemaProblem) {
    unsupported.push(`schema: ${facts.schemaProblem}`);
  } else ask("schema", "no .sql schema file found: ownership checks need one (seed.schema)", "seed.schema");

  // ---- personas and test tokens (deterministic, never an LLM)
  const personas: Record<string, any>[] = [];
  const auth = facts.auth;
  const seedBase = basename(facts.root);
  const tokenAt = (i: number) => `tok-argos-${sha8(`${seedBase}:${i}`)}`;
  if (auth.kind === "bearer-pairs" && auth.pairs.length >= 2) {
    found.push(`test tokens: ${auth.pairs.length} token:org pairs are the default of ${auth.tokenEnv} in the code (already test values)`);
    for (const p of auth.pairs.slice(0, 3)) personas.push({ name: `user-${p.org}`, org: p.org, auth: { type: "bearer", token: p.token } });
  } else if (auth.kind === "bearer-env" || auth.kind === "bearer-pairs") {
    const pairs = [1, 2].map((i) => ({ token: tokenAt(i), org: `org${i}` }));
    for (const p of pairs) personas.push({ name: `user-${p.org}`, org: p.org, auth: { type: "bearer", token: p.token } });
    if (auth.tokenEnv) {
      target.env[auth.tokenEnv] = pairs.map((p) => `${p.token}:${p.org}`).join(",");
      ask("auth", `generated test tokens and set ${auth.tokenEnv}="token:org,…": assumed that is the format the app expects`, `target.env.${auth.tokenEnv}`);
    } else ask("auth", "the app reads Bearer tokens but no token environment variable was found: set personas[].auth.token to values the app accepts", "personas");
  } else {
    for (const i of [1, 2]) personas.push({ name: `user-org${i}`, org: `org${i}`, auth: { type: "bearer", token: `tok-replace-me-${i}` } });
    if (auth.kind === "jwt") unsupported.push("authentication: JWT. Argos cannot create tokens your app accepts yet. Put valid test tokens into personas[].auth.token.");
    else if (auth.kind === "session") unsupported.push("authentication: session/cookie login is not supported yet (only Bearer tokens).");
    else if (auth.kind === "none") ask("auth", "no authentication was found in the code: every route looks public. The personas below are placeholders", "personas");
    else unsupported.push("authentication: the way the app checks credentials could not be determined. Put valid test tokens into personas[].auth.token.");
    ask("auth", "test tokens are placeholders (tok-replace-me-*): replace them with values the app accepts", "personas");
  }
  personas.push({ name: "anonymous", auth: { type: "none" } });
  config.personas = personas;
  provenance["personas"] = "ai-draft";

  // ---- resources
  const sensitiveExtra = [...new Set((facts.schema?.tables ?? []).flatMap((t) => t.columns.map((c) => c.name)).filter((n) => SENSITIVE_EXTRA.test(n) && !/_id$/i.test(n) && !isSensitiveColumn(n, DEFAULT_SENSITIVE)))].sort();
  const sensitiveCols = (t: Table): boolean => t.columns.some((c) => isSensitiveColumn(c.name, [...DEFAULT_SENSITIVE, ...sensitiveExtra]));

  const resources: Record<string, any>[] = [];
  const used = new Set<string>();
  const unauthWithData: string[] = [];
  const internalLike: string[] = [];
  for (const r of facts.routes) {
    const where = `${r.file}:${r.line}`;
    const rs = routeString(r);
    if (r.method !== "GET" && r.writes) {
      untested.push({ route: `${r.method} ${r.path}`, reason: `changes data (INSERT/UPDATE/DELETE): Argos only calls routes that are read-only (${where})` });
      continue;
    }
    const known = r.tables.map((t) => tables.get(t)).filter((t): t is Table => !!t);
    const ownerTable = known.find((t) => ownerColumnOf(t));
    const owner = ownerTable ? { table: ownerTable.name, column: ownerColumnOf(ownerTable)! } : undefined;
    const isHealth = HEALTH.test(r.path);
    const internal = INTERNAL.test(r.path);
    const ownerless = r.tables.length > 0 && known.length === r.tables.length && known.every((t) => !ownerColumnOf(t) && !sensitiveCols(t));
    const publicRoute = isHealth || (r.method === "GET" && r.auth === "no" && ownerless && !internal);

    let id = slug(r);
    for (let n = 2; used.has(id); n++) id = `${slug(r)}-${n}`;
    used.add(id);

    if (publicRoute) {
      resources.push({ id, route: rs, public: true });
      if (!isHealth) {
        provenance[`resources.${id}.public`] = "ai-draft";
        ask("public", `${rs} is treated as public: no auth middleware and it only reads ${r.tables.join(", ")} (no owner or secret columns). Confirm this is meant to be public.`, where);
      }
      continue;
    }
    if (r.method === "GET" && r.pathParams.length && !owner) {
      untested.push({ route: `${r.method} ${r.path}`, reason: `no owner column found in ${r.tables.join(", ") || "any table"}, so access cannot be judged by data (${where})` });
      continue;
    }

    const res: Record<string, any> = { id, route: rs };
    if (owner) res.owner = owner;
    if (r.method !== "GET") {
      res.safe = true;
      provenance[`resources.${id}.safe`] = "ai-draft";
      ask("safe", `${rs} is called by the scan: its handler only reads data (no INSERT/UPDATE/DELETE). Confirm it has no side effects.`, where);
    }
    res.expect = internal ? { owner: "deny", other: "deny", anonymous: "deny" } : { owner: "allow", other: "deny", anonymous: "deny" };
    provenance[`resources.${id}.expect`] = "ai-draft";
    if (internal) internalLike.push(rs);
    if (r.auth === "no" && (owner || known.length)) unauthWithData.push(rs);
    resources.push(res);
  }
  config.resources = resources;

  if (unauthWithData.length) {
    ask("expect", `no auth middleware found on routes that read tenant data: ${unauthWithData.join(", ")}. The draft expects anonymous access to be denied, so the scan reports it if it works.`, "resources");
  }
  if (internalLike.length) ask("expect", `internal-looking routes are expected to be denied to everyone: ${internalLike.join(", ")}`, "resources");
  const expectCount = resources.filter((r) => r.expect).length;
  if (expectCount) ask("expect", `review the ${expectCount} drafted access rules (resources[].expect). They are a conservative default (owner may read, other orgs and anonymous may not), not read from the code.`, "resources[].expect");

  // ---- secrets, fix
  const excluded = new Set(["PORT", ...(auth.tokenEnv ? [auth.tokenEnv] : []), ...(facts.db.envName ? [facts.db.envName] : []), ...Object.keys(target.env)]);
  const canaries = [...new Set([...DEFAULT_CANARIES, ...facts.usedEnv, ...facts.envKeys].filter((n) => (DEFAULT_CANARIES.includes(n) || CANARY_NAME.test(n)) && !excluded.has(n)))];
  config.secrets = {
    ...(sensitiveExtra.length ? { sensitiveColumns: [...DEFAULT_SENSITIVE, ...sensitiveExtra] } : {}),
    envCanaries: canaries,
  };
  if (!sensitiveExtra.length) delete config.secrets.sensitiveColumns;
  if (facts.principal) {
    config.fix = { principal: facts.principal };
    provenance["fix.principal"] = "ai-draft";
    found.push(`caller's org inside handlers: \`${facts.principal}\` (used by argos fix)`);
  }
  if (facts.envKeys.length) ask("env", `.env.example lists ${facts.envKeys.join(", ")}: values are not copied. Set the ones the app needs in target.env (test values only).`, ".env.example");

  config.checks = ["bola", "unauth", "sqli", "secrets"];
  config.mode = "report";
  config.llm = { provider: "anthropic", data: opts.llmData };
  if (Object.keys(provenance).length) config.provenance = provenance;

  found.push(`routes: ${facts.routes.length} found, ${resources.length} put into the config, ${untested.length} not tested`);
  if (!resources.length) {
    return { config, provenance, needsHuman, unsupported, untested, found, blocker: "no testable routes found (nothing that reads data and can be judged). Check the source layout or pass an OpenAPI file." };
  }
  return { config, provenance, needsHuman, unsupported, untested, found };
}
