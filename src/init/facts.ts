import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { DatabaseSync } from "node:sqlite";

/**
 * Step 1 of `argos init` for the express-sqlite adapter: collect FACTS from the repository, deterministically
 * and without an LLM. Anything that cannot be found is reported as missing (never guessed).
 * Read-only: nothing here writes to the repository.
 */

export interface Column {
  name: string;
  type: string;
  pk: boolean;
}
export interface Table {
  name: string;
  columns: Column[];
}

export interface RouteFact {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  file: string;
  line: number;
  pathParams: string[];
  queryParams: string[];
  bodyParams: string[];
  /** Tables the handler's SQL reads or writes. */
  tables: string[];
  /** The handler contains INSERT/UPDATE/DELETE. */
  writes: boolean;
  auth: "yes" | "no";
  authName?: string;
}

export type AuthKind = "bearer-pairs" | "bearer-env" | "jwt" | "session" | "unknown" | "none";

export interface RepoFacts {
  root: string;
  start?: { value: string; source: string };
  readsPortEnv: boolean;
  routes: RouteFact[];
  schema?: { file: string; tables: Table[]; otherSqlFiles: string[] };
  /** Reason the schema could not be read, when a .sql file exists but did not load. */
  schemaProblem?: string;
  db: { kind: "sqlite" | "other" | "none"; lib?: string; envName?: string; defaultPath?: string };
  auth: {
    kind: AuthKind;
    /** Environment variable holding the tokens (e.g. DEMO_TOKENS). */
    tokenEnv?: string;
    /** `token:org` pairs found as a default literal in the code: test tokens the repo already provides. */
    pairs: { token: string; org: string }[];
  };
  /** e.g. `req.user.vendor_id` */
  principal?: string;
  envKeys: string[];
  usedEnv: string[];
  notes: string[];
}

const SKIP_DIRS = new Set(["node_modules", ".git", "out", ".omc", "dist", "build", "coverage"]);
const SOURCE = /\.(?:[cm]?js|[jt]sx?)$/;
const MAX_BYTES = 1_000_000;

function walk(root: string, pick: (name: string) => boolean): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) visit(p);
      } else if (st.size <= MAX_BYTES && pick(name)) out.push(p);
    }
  };
  visit(root);
  return out.sort();
}

const read = (p: string): string => readFileSync(p, "utf8");
const lineOf = (text: string, index: number): number => text.slice(0, index).split("\n").length;
const uniq = <T>(xs: T[]): T[] => [...new Set(xs)];

const ROUTE_RE = /\b(?:app|router|api)\.(get|post|put|patch|delete)\(\s*(["'`])(\/[^"'`]*)\2([^\n]*)/g;
const AUTHISH = /auth|jwt|session|passport|protect|guard|login|requireuser|verify|ensure/i;
const USE_RE = /\b(?:app|router)\.use\(\s*(?:(["'`])(\/[^"'`]*)\1\s*,\s*)?([A-Za-z_][\w.]*)\s*\)/g;

/** String literal contents that look like SQL. Comments and plain code are ignored ("... into the SQL" is not a table). */
function sqlStrings(body: string): string {
  return [...body.matchAll(/(["'`])((?:\\.|(?!\1)[^\\])*)\1/g)]
    .map((m) => m[2]!)
    .filter((t) => /\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(t))
    .join("\n");
}

/** Middleware identifiers between the path literal and the handler on the registration line. */
function middlewareOf(rest: string): string[] {
  const names: string[] = [];
  for (const tok of rest.split(",")) {
    const t = tok.trim();
    if (/^[A-Za-z_][\w.]*$/.test(t)) names.push(t);
    else break; // the handler (arrow function, async, function) starts here
  }
  return names;
}

function extractRoutes(root: string): RouteFact[] {
  const routes: RouteFact[] = [];
  for (const file of walk(root, (n) => SOURCE.test(n))) {
    const text = read(file);
    const rel = relative(root, file);
    const matches = [...text.matchAll(ROUTE_RE)];
    if (!matches.length) continue;

    const uses = [...text.matchAll(USE_RE)]
      .filter((m) => AUTHISH.test(m[3]!))
      .map((m) => ({ at: m.index!, prefix: m[2] ?? "", name: m[3]! }));

    matches.forEach((m, i) => {
      const end = matches[i + 1]?.index ?? text.length;
      const body = text.slice(m.index!, end);
      const path = m[3]!.split("?")[0]!;
      const mw = middlewareOf(m[4]!.replace(/^\s*,/, ""));
      const own = mw.find((x) => AUTHISH.test(x));
      const global = uses.find((u) => u.at < m.index! && path.startsWith(u.prefix));
      const authName = own ?? global?.name;

      const sql = sqlStrings(body);
      const tables = uniq([...sql.matchAll(/\b(?:FROM|JOIN|INTO|UPDATE)\s+["`]?([A-Za-z_]\w*)/gi)].map((t) => t[1]!.toLowerCase()));
      const queryParams = uniq([
        ...[...body.matchAll(/req\.query\.(\w+)/g)].map((q) => q[1]!),
        ...[...body.matchAll(/req\.query\[\s*["'](\w+)["']\s*\]/g)].map((q) => q[1]!),
        ...[...body.matchAll(/\{([^}]*)\}\s*=\s*req\.query/g)].flatMap((q) => q[1]!.split(",").map((x) => x.trim().split(/[:=\s]/)[0]!).filter(Boolean)),
      ]);
      const bodyParams = uniq([
        ...[...body.matchAll(/req\.body\??\.(\w+)/g)].map((q) => q[1]!),
        ...[...body.matchAll(/\{([^}]*)\}\s*=\s*req\.body/g)].flatMap((q) => q[1]!.split(",").map((x) => x.trim().split(/[:=\s]/)[0]!).filter(Boolean)),
      ]);
      routes.push({
        method: m[1]!.toUpperCase() as RouteFact["method"],
        path,
        file: rel,
        line: lineOf(text, m.index!),
        pathParams: [...path.matchAll(/:(\w+)/g)].map((p) => p[1]!),
        queryParams,
        bodyParams,
        tables,
        writes: /\b(?:INSERT\s+INTO|UPDATE\s+["`]?\w+["`]?\s+SET|DELETE\s+FROM)\b/i.test(sql),
        auth: authName ? "yes" : "no",
        ...(authName ? { authName } : {}),
      });
    });
  }
  return routes;
}

function readSchema(root: string): Pick<RepoFacts, "schema" | "schemaProblem"> {
  const files = walk(root, (n) => /\.sql$/i.test(n) && !/^seed/i.test(n) && !/\.(?:test|spec)\./i.test(n));
  let best: { file: string; tables: Table[] } | undefined;
  const failed: string[] = [];
  for (const file of files) {
    const db = new DatabaseSync(":memory:");
    try {
      db.exec(read(file));
      const names = (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as unknown as { name: string }[]).map((r) => r.name);
      const tables: Table[] = names.map((name) => ({
        name,
        columns: (db.prepare(`PRAGMA table_info("${name.replace(/"/g, '""')}")`).all() as unknown as { name: string; type: string; pk: number }[]).map((c) => ({ name: c.name, type: c.type, pk: c.pk > 0 })),
      }));
      if (!best || tables.length > best.tables.length) best = { file: relative(root, file), tables };
    } catch {
      failed.push(relative(root, file));
    } finally {
      db.close();
    }
  }
  if (best) return { schema: { ...best, otherSqlFiles: files.map((f) => relative(root, f)).filter((f) => f !== best!.file) } };
  return failed.length ? { schemaProblem: `${failed.join(", ")} is not valid SQLite SQL (another database dialect?)` } : {};
}

function detectDb(deps: string[], sources: string): RepoFacts["db"] {
  const other = deps.find((d) => ["pg", "postgres", "mysql", "mysql2", "mongoose", "mongodb", "prisma", "@prisma/client", "sequelize", "typeorm", "knex"].includes(d));
  const sqlite = /node:sqlite/.test(sources) ? "node:sqlite" : deps.find((d) => ["better-sqlite3", "sqlite3", "sqlite"].includes(d));
  if (other && !sqlite) return { kind: "other", lib: other };
  if (!sqlite) return { kind: "none" };
  const m =
    /new\s+DatabaseSync\(\s*process\.env\.(\w+)\s*(?:\?\?|\|\|)\s*(["'`])([^"'`]+)\2/.exec(sources) ??
    /new\s+(?:Database|sqlite3\.Database)\(\s*process\.env\.(\w+)\s*(?:\?\?|\|\|)\s*(["'`])([^"'`]+)\2/.exec(sources);
  if (m) return { kind: "sqlite", lib: sqlite, envName: m[1], defaultPath: m[3] };
  const lit = /new\s+(?:DatabaseSync|Database|sqlite3\.Database)\(\s*(["'`])([^"'`]+)\1/.exec(sources);
  return { kind: "sqlite", lib: sqlite, ...(lit ? { defaultPath: lit[2] } : {}) };
}

function detectAuth(deps: string[], sources: string, routes: RouteFact[]): RepoFacts["auth"] {
  const m = [...sources.matchAll(/process\.env\.(\w+)\s*(?:\?\?|\|\|)\s*(["'`])([^"'`]+)\2/g)].find(
    (x) => /TOKEN|AUTH|KEY/i.test(x[1]!) && /^[^,:\s]+:[^,:\s]+(?:,[^,:\s]+:[^,:\s]+)*$/.test(x[3]!),
  );
  if (m) {
    return { kind: "bearer-pairs", tokenEnv: m[1], pairs: m[3]!.split(",").map((p) => ({ token: p.split(":")[0]!, org: p.split(":")[1]! })) };
  }
  if (deps.some((d) => ["jsonwebtoken", "jose", "express-jwt", "passport-jwt"].includes(d)) || /jwt\.verify\(/.test(sources)) return { kind: "jwt", pairs: [] };
  if (deps.some((d) => ["express-session", "cookie-session", "passport", "next-auth"].includes(d)) || /req\.session\b/.test(sources)) return { kind: "session", pairs: [] };
  const tokenEnv = [...sources.matchAll(/process\.env\.(\w*(?:TOKEN|AUTH)\w*)/g)][0]?.[1];
  if (/authorization/i.test(sources) && /bearer/i.test(sources)) return { kind: "bearer-env", ...(tokenEnv ? { tokenEnv } : {}), pairs: [] };
  if (routes.some((r) => r.auth === "yes")) return { kind: "unknown", pairs: [] };
  return { kind: "none", pairs: [] };
}

function detectStart(root: string, pkg: Record<string, any> | undefined): RepoFacts["start"] {
  const scripts = pkg?.scripts as Record<string, string> | undefined;
  if (scripts?.start) return { value: /^node\s/.test(scripts.start) ? scripts.start : "npm start", source: "package.json scripts.start" };
  if (typeof pkg?.main === "string") return { value: `node ${pkg.main}`, source: "package.json main" };
  for (const f of ["app.mjs", "server.mjs", "index.mjs", "app.js", "server.js", "index.js"]) {
    if (existsSync(join(root, f))) return { value: `node ${f}`, source: `${f} (guessed from the file name)` };
  }
  return undefined;
}

export function scanRepo(root: string): RepoFacts {
  const notes: string[] = [];
  const pkgPath = join(root, "package.json");
  let pkg: Record<string, any> | undefined;
  if (existsSync(pkgPath)) {
    try {
      pkg = JSON.parse(read(pkgPath));
    } catch {
      notes.push("package.json is not valid JSON");
    }
  } else notes.push("no package.json (not a Node project?)");

  const deps = Object.keys({ ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) });
  const files = walk(root, (n) => SOURCE.test(n));
  const sources = files.map(read).join("\n");
  const routes = extractRoutes(root);
  const schema = readSchema(root);
  const auth = detectAuth(deps, sources, routes);

  const envFile = [".env.example", ".env.sample", ".env.template"].map((n) => join(root, n)).find(existsSync);
  const envKeys = envFile ? uniq([...read(envFile).matchAll(/^\s*([A-Z][A-Z0-9_]*)\s*=/gm)].map((m) => m[1]!)) : [];
  const usedEnv = uniq([...sources.matchAll(/process\.env\.([A-Z][A-Z0-9_]*)/g)].map((m) => m[1]!));

  let principal: string | undefined;
  const ownerLike = schema.schema ? ownerColumns(schema.schema.tables) : [];
  for (const col of ownerLike) {
    const m = new RegExp(`\\breq\\.(?:user|auth)\\.${col}\\b`).exec(sources);
    if (m) {
      principal = m[0];
      break;
    }
  }

  return {
    root,
    start: detectStart(root, pkg),
    readsPortEnv: /process\.env\.PORT\b/.test(sources),
    routes,
    ...schema,
    db: detectDb(deps, sources),
    auth,
    ...(principal ? { principal } : {}),
    envKeys,
    usedEnv,
    notes,
  };
}

/** Owner-column names present in the schema, in priority order. */
export const OWNER_COLUMNS = ["vendor_id", "org_id", "organization_id", "tenant_id", "account_id", "company_id", "customer_id", "owner_id", "user_id"];
const TENANT_TABLES = /^(?:vendors?|orgs?|organi[sz]ations?|tenants?|accounts?|compan(?:y|ies)|customers?)$/i;

export function ownerColumns(tables: Table[]): string[] {
  const present = new Set(tables.flatMap((t) => t.columns.map((c) => c.name)));
  return OWNER_COLUMNS.filter((c) => present.has(c));
}

/** The column that says "who owns this row", or undefined when the table has none. */
export function ownerColumnOf(table: Table): string | undefined {
  const col = OWNER_COLUMNS.find((c) => table.columns.some((x) => x.name === c));
  if (col) return col;
  if (TENANT_TABLES.test(table.name)) return table.columns.find((c) => c.pk)?.name;
  return undefined;
}
