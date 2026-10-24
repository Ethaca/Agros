import { createHash } from "node:crypto";
import { hasCredentials, userKey, type Config } from "./config.js";
import { isSensitiveColumn, SeedError, type SeedManifest } from "./seed.js";
import type { DbHandle, SqlValue } from "./stack.js";

/**
 * PostgreSQL seeding for runtime jvm (docs/SPRING_SUPPORT_PLAN.md §3). Runs after the app's own migrations:
 * the schema is read from the live DB (information_schema + pg_catalog), never invented.
 * Two or more orgs, one user per (org, persona user), org-owned and user-owned rows per resource,
 * all FK / NOT NULL / unique / enum / CHECK-in constraints satisfied. Markers go into a text column
 * that is likely to be serialized (title/name/...); secret markers into sensitive columns.
 * Unsupported structures raise SeedError (reported as unverified, not a crash).
 */

export type ColKind = "int" | "num" | "bool" | "uuid" | "text" | "time" | "json" | "bytea" | "enum" | "array" | "other";

export interface PgColumn {
  name: string;
  udt: string;
  kind: ColKind;
  nullable: boolean;
  /** Column default expression, or "identity" for identity columns. */
  dflt: string | null;
  maxLen: number | null;
  /** Allowed values (enum type or CHECK ... IN / = ANY list). */
  values?: string[];
}

export interface PgFk {
  cols: string[];
  refTable: string;
  refCols: string[];
}

export interface PgTable {
  name: string;
  columns: PgColumn[];
  pk: string[];
  uniques: string[][];
  fks: PgFk[];
}

export type PgSchema = Map<string, PgTable>;

const IGNORED_TABLES = /^(flyway_schema_history|databasechangelog|databasechangeloglock)$/;

const s = (v: SqlValue | undefined): string => (v === null || v === undefined ? "" : String(v));
const list = (v: SqlValue | undefined): string[] => s(v).split(",").filter(Boolean);
const unq = (name: string): string => name.replace(/^public\./, "").replace(/^"(.*)"$/, "$1");

export const qi = (id: string): string => `"${id.replace(/"/g, '""')}"`;
export const lit = (v: string): string => `'${v.replace(/'/g, "''")}'`;

function kindOf(dataType: string, udt: string, enums: Map<string, string[]>): ColKind {
  if (dataType === "ARRAY") return "array";
  if (enums.has(udt)) return "enum";
  if (/^int[248]$/.test(udt)) return "int";
  if (/^(numeric|float[48]|money)$/.test(udt)) return "num";
  if (udt === "bool") return "bool";
  if (udt === "uuid") return "uuid";
  if (/^(text|varchar|bpchar|citext|name)$/.test(udt)) return "text";
  if (/^(timestamp|timestamptz|date|time|timetz|interval)$/.test(udt)) return "time";
  if (/^jsonb?$/.test(udt)) return "json";
  if (udt === "bytea") return "bytea";
  return "other";
}

/** `CHECK ((status)::text = ANY ((ARRAY['A'::character varying, 'B'])::text[]))` / `CHECK (x IN ('a','b'))` -> column + values. */
export function parseCheckIn(def: string): { column: string; values: string[] } | undefined {
  const m = /\(*\s*"?([A-Za-z_][A-Za-z0-9_]*)"?\)?(?:::[a-z ]+)?\s*(?:=\s*ANY|IN)\s*\(/i.exec(def);
  if (!m) return undefined;
  const values = [...def.slice(m.index + m[0].length).matchAll(/'((?:[^']|'')*)'/g)].map((x) => x[1]!.replace(/''/g, "'"));
  return values.length ? { column: m[1]!, values } : undefined;
}

/** Result columns avoid the name `t`: DbHandle implementations wrap queries as `json_agg(t) FROM (...) t`. */
export async function discoverSchema(db: DbHandle): Promise<PgSchema> {
  const enums = new Map<string, string[]>();
  for (const r of await db.query(
    `SELECT t.typname::text AS typ, e.enumlabel::text AS label FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid ORDER BY t.typname, e.enumsortorder`,
  )) {
    (enums.get(s(r.typ)) ?? enums.set(s(r.typ), []).get(s(r.typ))!).push(s(r.label));
  }

  const schema: PgSchema = new Map();
  for (const r of await db.query(
    `SELECT table_name::text AS tbl FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`,
  )) {
    const name = s(r.tbl);
    if (!IGNORED_TABLES.test(name)) schema.set(name, { name, columns: [], pk: [], uniques: [], fks: [] });
  }

  for (const r of await db.query(
    `SELECT table_name::text AS tbl, column_name::text AS c, data_type::text AS dt, udt_name::text AS udt, is_nullable::text AS n,
            column_default::text AS d, is_identity::text AS ident, character_maximum_length::text AS len
       FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position`,
  )) {
    const t = schema.get(s(r.tbl));
    if (!t) continue;
    const udt = s(r.udt);
    const kind = kindOf(s(r.dt), udt, enums);
    t.columns.push({
      name: s(r.c),
      udt,
      kind,
      nullable: s(r.n) === "YES",
      dflt: s(r.ident) === "YES" ? "identity" : r.d === null || r.d === undefined || s(r.d) === "" ? null : s(r.d),
      maxLen: r.len === null || r.len === undefined || s(r.len) === "" ? null : Number(r.len),
      ...(kind === "enum" ? { values: enums.get(udt) } : {}),
    });
  }

  for (const r of await db.query(
    `SELECT c.conrelid::regclass::text AS tbl, c.contype::text AS typ,
            array_to_string(ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n, o)
              JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.o), ',') AS cols,
            CASE WHEN c.contype = 'f' THEN c.confrelid::regclass::text END AS rt,
            array_to_string(ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n, o)
              JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.o), ',') AS rcols,
            pg_get_constraintdef(c.oid)::text AS def
       FROM pg_constraint c JOIN pg_namespace ns ON ns.oid = c.connamespace
      WHERE ns.nspname = 'public' AND c.contype IN ('p', 'f', 'c') ORDER BY c.conname`,
  )) {
    const t = schema.get(unq(s(r.tbl)));
    if (!t) continue;
    const typ = s(r.typ);
    if (typ === "p") t.pk = list(r.cols);
    else if (typ === "f") t.fks.push({ cols: list(r.cols), refTable: unq(s(r.rt)), refCols: list(r.rcols) });
    else if (typ === "c") {
      const chk = parseCheckIn(s(r.def));
      const col = chk && t.columns.find((c) => c.name === chk.column);
      if (col && !col.values) col.values = chk!.values;
    }
  }

  for (const r of await db.query(
    `SELECT t.relname::text AS tbl, array_to_string(ARRAY(SELECT a.attname::text FROM unnest(i.indkey) k(n)
              JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.n), ',') AS cols
       FROM pg_index i JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace ns ON ns.oid = t.relnamespace
      WHERE ns.nspname = 'public' AND i.indisunique`,
  )) {
    const t = schema.get(s(r.tbl));
    const cols = list(r.cols);
    if (t && cols.length) t.uniques.push(cols);
  }
  return schema;
}

/** One seeded user (persona user inside an org). */
export interface SeededUser {
  org: string;
  user: string;
  /** Primary key of the users row ("" when the app has no users table). */
  id: string;
  email?: string;
  username?: string;
  /** Value for the token's `sub` claim (cfg.auth.claims.subject). */
  subject: string;
  roles: string[];
}

/** SeedManifest plus what the JVM pipeline needs. Lives in memory only: rows may hold secret markers. */
export interface PgSeedManifest extends SeedManifest {
  /** `<org>/<user>` -> seeded user. */
  users: Record<string, SeededUser>;
  /** persona name -> `<org>/<user>` key of its user (personas with org only). */
  personaUsers: Record<string, string>;
  /** org -> primary key (or owner-column value) identifying the org. */
  orgIds: Record<string, string>;
  /** table -> context (`<org>`, `<org>/<user>` or `*`) -> inserted column values (as text). */
  rows: Record<string, Record<string, Record<string, string | null>>>;
  /** table -> primary key column (single-column keys only). */
  pk: Record<string, string>;
  /** Tables that received rows, in insert order. */
  tables: string[];
  /** resourceId -> why no marker could be planted (no suitable text column). */
  unobservable: Record<string, string>;
}

type Resource = Config["resources"][number];

const ORG_TABLE_NAMES = /^(organizations?|orgs?|tenants?|teams?|workspaces?|companies|company|accounts?)$/;
const USER_TABLE_NAMES = /^(app_)?(users?|accounts?|members?|user_accounts?|people|persons?)$/;
const ORG_COL = /^(org|organization|organisation|tenant|team|workspace|company)_?id$/i;
const MARKER_COLS = ["title", "name", "description", "body", "content", "text", "label", "subject", "summary", "note", "notes", "display_name"];
const MEMBERSHIP_NAMES = /member|role|authorit|user_org|org_user/;

function hex(seedKey: string, ...parts: (string | number)[]): string {
  return createHash("sha256").update([seedKey, ...parts].join("|")).digest("hex");
}

function uuidOf(seedKey: string, ...parts: string[]): string {
  const h = hex(seedKey, "uuid", ...parts);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const isEmailCol = (n: string) => /e?mail/i.test(n);
const isUsernameCol = (n: string) => /^(user_?name|login|handle|nickname)$/i.test(n);
const isRoleCol = (n: string) => /^(role|roles|role_name|authority|user_role)$/i.test(n);

function normRole(role: string, allowed: string[] | undefined): string {
  if (!allowed?.length) return role;
  const bare = role.replace(/^ROLE_/i, "").toLowerCase();
  return allowed.find((v) => v.replace(/^ROLE_/i, "").toLowerCase() === bare) ?? allowed[0]!;
}

/** Seed the run's PostgreSQL (after migrations). Throws SeedError on unsupported structure or SQL failure. */
export async function seedPostgres(cfg: Config, db: DbHandle, opts: { seedKey: string; schema?: PgSchema }): Promise<PgSeedManifest> {
  let schema: PgSchema;
  try {
    schema = opts.schema ?? (await discoverSchema(db));
  } catch (e) {
    throw new SeedError(`cannot read the database schema: ${(e as Error).message}`);
  }
  if (!schema.size) throw new SeedError("database has no tables in schema public (did the migrations run?)");
  const plan = planSeed(cfg, schema, opts.seedKey);
  for (const stmt of plan.statements) {
    let rows;
    const sql = stmt.build();
    try {
      rows = await db.query(sql);
    } catch (e) {
      throw new SeedError(`insert into ${stmt.table} failed: ${(e as Error).message.split("\n")[0]}`);
    }
    stmt.after(rows[0] ? s(Object.values(rows[0])[0]) : undefined);
  }
  return plan.finish();
}

interface Stmt {
  table: string;
  /** INSERT statement (built lazily, see planSeed). */
  build(): string;
  /** Called with the RETURNING value (primary key as text). */
  after(pk: string | undefined): void;
}

interface Ctx {
  org: string;
  user?: string;
  /** Membership rows: one per role. */
  role?: string;
}
const ctxKey = (c: Ctx): string => (c.user ? `${c.org}/${c.user}` : c.org);

/**
 * Build the INSERT plan. Statements run in order; values referring to an earlier row's primary key
 * are resolved lazily (each statement's SQL is produced when it is about to run).
 */
export function planSeed(cfg: Config, schema: PgSchema, seedKey: string): { statements: Stmt[]; finish(): PgSeedManifest } {
  const table = (name: string, what: string): PgTable => {
    const t = schema.get(name);
    if (!t) throw new SeedError(`${what}: table "${name}" not found in the database (tables: ${[...schema.keys()].join(", ")})`);
    return t;
  };
  const col = (t: PgTable, name: string, what: string): PgColumn => {
    const c = t.columns.find((x) => x.name === name);
    if (!c) throw new SeedError(`${what}: column "${t.name}.${name}" not found`);
    return c;
  };
  const fkOf = (t: PgTable, c: string): PgFk | undefined => t.fks.find((f) => f.cols.length === 1 && f.cols[0] === c);
  const singlePk = (t: PgTable): string | undefined => (t.pk.length === 1 ? t.pk[0] : undefined);

  // --- personas -> orgs and users
  const orgs = [...new Set(cfg.personas.map((p) => p.org).filter((o): o is string => !!o))];
  if (orgs.length < 2) throw new SeedError("need personas in at least 2 orgs to seed cross-org data");
  const userList: { org: string; user: string; roles: string[] }[] = [];
  const personaUsers: Record<string, string> = {};
  for (const p of cfg.personas) {
    if (!p.org || p.auth.type === "none") continue;
    const key = `${p.org}/${userKey(p)}`;
    personaUsers[p.name] = key;
    const ex = userList.find((u) => `${u.org}/${u.user}` === key);
    if (!ex) userList.push({ org: p.org, user: userKey(p), roles: [...(p.roles ?? [])] });
    else if (hasCredentials(p)) for (const r of p.roles ?? []) if (!ex.roles.includes(r)) ex.roles.push(r);
  }

  // --- which table is the org table / users table
  let orgTable: string | undefined;
  let usersTable: string | undefined;
  const setRole = (kind: "org" | "users", name: string, why: string) => {
    const cur = kind === "org" ? orgTable : usersTable;
    if (cur && cur !== name) throw new SeedError(`unsupported structure: ${kind} table is ambiguous (${cur} vs ${name}, ${why})`);
    if (kind === "org") orgTable = name;
    else usersTable = name;
  };
  for (const r of cfg.resources) {
    if (!r.owner) continue;
    const t = table(r.owner.table, `resources.${r.id}.owner`);
    col(t, r.owner.column, `resources.${r.id}.owner`);
    const kind = r.owner.scope === "user" ? "users" : "org";
    const fk = fkOf(t, r.owner.column);
    if (fk) setRole(kind, fk.refTable, `resources.${r.id}.owner`);
    else if (singlePk(t) === r.owner.column) setRole(kind, t.name, `resources.${r.id}.owner`);
  }
  if (!orgTable) {
    // org_id-like FK on any owner table, else a table named like an org
    for (const r of cfg.resources) {
      const t = r.owner && schema.get(r.owner.table);
      const fk = t?.fks.find((f) => f.cols.length === 1 && ORG_COL.test(f.cols[0]!));
      if (fk) { orgTable = fk.refTable; break; }
    }
    orgTable ??= [...schema.keys()].find((n) => ORG_TABLE_NAMES.test(n) && n !== usersTable);
  }
  const needsUsers = cfg.personas.some((p) => p.auth.type === "jwt") || cfg.resources.some((r) => r.owner?.scope === "user");
  if (!usersTable && needsUsers) {
    usersTable = [...schema.values()].find((t) => t.name !== orgTable && USER_TABLE_NAMES.test(t.name) && t.columns.some((c) => isEmailCol(c.name) || isUsernameCol(c.name)))?.name;
  }
  if (cfg.resources.some((r) => r.owner?.scope === "user") && !usersTable) {
    throw new SeedError("unsupported structure: user-owned resources need a users table (none found; set owner.column to a column referencing it)");
  }
  const subjectMode = cfg.auth?.claims.subject ?? "id";
  if (usersTable && cfg.auth) {
    const ut = schema.get(usersTable)!;
    if (subjectMode === "email" && !ut.columns.some((c) => isEmailCol(c.name))) throw new SeedError(`unsupported structure: auth.claims.subject is email but ${usersTable} has no email column`);
    if (subjectMode === "username" && !ut.columns.some((c) => isUsernameCol(c.name))) throw new SeedError(`unsupported structure: auth.claims.subject is username but ${usersTable} has no username column`);
    if (subjectMode === "id" && !singlePk(ut)) throw new SeedError(`unsupported structure: ${usersTable} has no single-column primary key for the token subject`);
  }

  // --- membership tables: FK to users plus an org link or role column
  const membership = new Set<string>();
  if (usersTable) {
    for (const t of schema.values()) {
      if (t.name === usersTable || t.name === orgTable || !MEMBERSHIP_NAMES.test(t.name)) continue;
      if (cfg.resources.some((r) => r.owner?.table === t.name)) continue;
      const toUser = t.fks.some((f) => f.refTable === usersTable);
      const orgLink = t.fks.some((f) => f.refTable === orgTable) || t.columns.some((c) => isRoleCol(c.name));
      if (toUser && orgLink) membership.add(t.name);
    }
  }

  // --- tables to seed and their contexts
  const scopeOf = new Map<string, "org" | "user" | "global">();
  if (orgTable) scopeOf.set(orgTable, "org");
  if (usersTable) scopeOf.set(usersTable, "user");
  for (const m of membership) scopeOf.set(m, "user");
  const tableResources = new Map<string, Resource[]>();
  for (const r of cfg.resources) {
    if (!r.owner) continue;
    (tableResources.get(r.owner.table) ?? tableResources.set(r.owner.table, []).get(r.owner.table)!).push(r);
    if (r.owner.scope === "user") scopeOf.set(r.owner.table, "user");
    else if (!scopeOf.has(r.owner.table)) scopeOf.set(r.owner.table, "org");
  }
  for (const r of cfg.resources) {
    for (const p of Object.values(r.pathParams ?? {})) {
      table(p.table, `resources.${r.id}.pathParams`);
      if (!scopeOf.has(p.table)) scopeOf.set(p.table, "org");
    }
    if (r.writeVerify) table(r.writeVerify.table, `resources.${r.id}.writeVerify`);
  }
  // closure over NOT NULL foreign keys
  for (let changed = true; changed; ) {
    changed = false;
    for (const name of [...scopeOf.keys()]) {
      const t = schema.get(name)!;
      for (const f of t.fks) {
        const required = f.cols.some((c) => !t.columns.find((x) => x.name === c)?.nullable);
        if (required && !scopeOf.has(f.refTable)) {
          table(f.refTable, `foreign key ${name}.${f.cols.join(",")}`);
          scopeOf.set(f.refTable, "global");
          changed = true;
        }
      }
    }
  }
  // a "global" dependency that itself links to the org (or users) is seeded per org
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, sc] of scopeOf) {
      if (sc !== "global") continue;
      if (schema.get(name)!.fks.some((f) => f.refTable !== name && (scopeOf.get(f.refTable) === "org" || scopeOf.get(f.refTable) === "user"))) {
        scopeOf.set(name, "org");
        changed = true;
      }
    }
  }

  // --- topological order over FKs between seeded tables (nullable edges may be dropped to break cycles)
  const order: string[] = [];
  const pending = [...scopeOf.keys()].sort((a, b) => (a === orgTable ? -1 : b === orgTable ? 1 : a === usersTable ? -1 : b === usersTable ? 1 : 0));
  const deps = (name: string, strict: boolean) => {
    const t = schema.get(name)!;
    return t.fks
      .filter((f) => f.refTable !== name && scopeOf.has(f.refTable))
      .filter((f) => !strict || f.cols.some((c) => !t.columns.find((x) => x.name === c)?.nullable))
      .map((f) => f.refTable);
  };
  while (pending.length) {
    let i = pending.findIndex((n) => deps(n, false).every((d) => order.includes(d)));
    if (i < 0) i = pending.findIndex((n) => deps(n, true).every((d) => order.includes(d)));
    if (i < 0) throw new SeedError(`unsupported structure: circular NOT NULL foreign keys between ${pending.join(", ")}`);
    order.push(...pending.splice(i, 1));
  }
  for (const name of order) {
    const t = schema.get(name)!;
    for (const f of t.fks) {
      if (f.refTable === name && f.cols.some((c) => !t.columns.find((x) => x.name === c)?.nullable)) {
        throw new SeedError(`unsupported structure: ${name}.${f.cols.join(",")} is a NOT NULL self reference`);
      }
    }
  }

  // --- state
  const manifest: PgSeedManifest = {
    markers: {}, secrets: [], ids: {}, users: {}, personaUsers, orgIds: {}, rows: {}, pk: {}, tables: [], unobservable: {},
  };
  let counter = 0;
  let secretN = 0;
  let markerN = 0;
  const rowOf = (tbl: string, c: Ctx | "*"): Record<string, string | null> | undefined => {
    const byCtx = manifest.rows[tbl];
    if (!byCtx) return undefined;
    if (c === "*") return byCtx["*"] ?? Object.values(byCtx)[0];
    return byCtx[ctxKey(c)] ?? byCtx[c.org] ?? (c.user ? undefined : Object.entries(byCtx).find(([k]) => k.startsWith(`${c.org}/`))?.[1]) ?? byCtx["*"];
  };
  /** The org's first user (persona order): creator / author of org-level rows. */
  const firstUser = (org: string): string | undefined => userList.find((u) => u.org === org)?.user;

  const orgValue = (org: string, c: PgColumn): string => {
    const i = orgs.indexOf(org);
    if (c.kind === "int" || c.kind === "num") return String(1_000_000 + i + 1);
    if (c.kind === "uuid") return uuidOf(seedKey, "org", org);
    return org;
  };

  const contextsFor = (name: string): Ctx[] => {
    const sc = scopeOf.get(name)!;
    if (sc === "global") return [{ org: orgs[0]! }];
    if (sc === "org") return orgs.map((org) => ({ org }));
    if (membership.has(name)) {
      const t = schema.get(name)!;
      const roleCol = t.columns.find((c) => isRoleCol(c.name));
      return userList.flatMap((u) => (roleCol && u.roles.length > 1 ? u.roles.map((role) => ({ org: u.org, user: u.user, role })) : [{ org: u.org, user: u.user, role: u.roles[0] }]));
    }
    return userList.map((u) => ({ org: u.org, user: u.user }));
  };

  const statements: Stmt[] = [];
  for (const name of order) {
    const t = schema.get(name)!;
    const sc = scopeOf.get(name)!;
    const resources = tableResources.get(name) ?? [];
    const pk = singlePk(t);
    if (pk) manifest.pk[name] = pk;
    const sensitive = (c: PgColumn) => c.kind === "text" && isSensitiveColumn(c.name, cfg.secrets.sensitiveColumns);
    const special = (c: PgColumn) => isEmailCol(c.name) || isUsernameCol(c.name) || isRoleCol(c.name) || !!c.values || !!fkOf(t, c.name);
    // marker column: a likely-serialized text column, long enough for a marker
    const markerCol = t.columns.find((c) => MARKER_COLS.includes(c.name.toLowerCase()) && c.kind === "text" && !sensitive(c) && !special(c) && (c.maxLen ?? 999) >= 24)
      ?? t.columns.find((c) => c.kind === "text" && !sensitive(c) && !special(c) && c.name !== pk && (c.maxLen ?? 999) >= 24);
    if (!markerCol) for (const r of resources) manifest.unobservable[r.id] = `no text column in ${name} to plant a marker in`;
    const ownerOf = new Map(resources.map((r) => [r.owner!.column, r.owner!.scope ?? "org"]));

    for (const ctx of contextsFor(name)) {
      const key = sc === "global" ? "*" : sc === "user" ? ctxKey(ctx) : ctx.org;
      const values: { col: string; sql: string; text: string | null }[] = [];
      const marker = markerCol ? `ARGOS_R${++markerN}_${hex(seedKey, "row", name, key).slice(0, 8)}` : undefined;

      // Built when it is about to run: foreign keys point at rows inserted by earlier statements.
      const build = (): string => {
        for (const c of t.columns) {
          const add = (text: string | null, sql?: string) => values.push({ col: c.name, sql: sql ?? (text === null ? "NULL" : lit(text)), text });
          const fk = fkOf(t, c.name);
          const ownerScope = ownerOf.get(c.name);

          // Primary key: let the DB assign it when it can.
          if (c.name === pk && !fk && c.dflt) continue;
          if (c.name === pk && !fk && ownerScope !== "org") {
            if (c.kind === "uuid") add(uuidOf(seedKey, name, key));
            else if (c.kind === "int" || c.kind === "num") add(String(1_000_000 + ++counter));
            else add(`${name}-${key}-${hex(seedKey, name, key).slice(0, 6)}`.slice(0, c.maxLen ?? 200));
            continue;
          }
          if (fk) {
            const ref = fk.refTable;
            let target: Record<string, string | null> | undefined;
            if (ref === name) target = undefined;
            else if (ref === usersTable && sc === "user" && ctx.user) target = rowOf(ref, ctx);
            else if (ref === usersTable) target = rowOf(ref, { org: ctx.org, user: firstUser(ctx.org) });
            else if (scopeOf.has(ref)) target = rowOf(ref, scopeOf.get(ref) === "global" ? "*" : ctx);
            const v = target?.[fk.refCols[0]!];
            if (v === undefined || v === null) {
              if (!c.nullable && !c.dflt) throw new SeedError(`unsupported structure: no row to reference for ${name}.${c.name} -> ${ref}`);
              continue;
            }
            add(v);
            continue;
          }
          if (ownerScope === "org") { add(orgValue(ctx.org, c)); continue; }
          if (ownerScope === "user") { add(ctx.user ?? firstUser(ctx.org) ?? ctx.org); continue; }
          if (ORG_COL.test(c.name) && !orgTable && (c.kind === "text" || c.kind === "int" || c.kind === "uuid")) { add(orgValue(ctx.org, c)); continue; }

          if (c.dflt && !(c.kind === "text" && (c === markerCol || sensitive(c)))) continue; // DB default
          const u = ctx.user ?? firstUser(ctx.org) ?? "x";
          const n = ++counter;
          const h = hex(seedKey, name, key, c.name).slice(0, 6);
          if (c.kind === "enum" || c.values) {
            const vals = c.values ?? [];
            if (!vals.length) throw new SeedError(`unsupported structure: ${name}.${c.name} has no allowed values`);
            const role = ctx.role ?? userList.find((x) => x.org === ctx.org && x.user === ctx.user)?.roles[0];
            add(isRoleCol(c.name) && role ? normRole(role, vals) : vals[0]!);
            continue;
          }
          if (c.kind === "text") {
            if (c === markerCol && marker) { add(marker); continue; }
            if (sensitive(c)) {
              const m = `ARGOS_SECRET_${++secretN}_${hex(seedKey, "secret", name, c.name, key).slice(0, 6)}`;
              if ((c.maxLen ?? 999) >= m.length) {
                manifest.secrets.push({ table: name, column: c.name, org: ctx.org, marker: m });
                add(m);
                continue;
              }
            }
            if (!c.nullable || MARKER_COLS.includes(c.name.toLowerCase()) || isEmailCol(c.name) || isUsernameCol(c.name)) {
              let v: string;
              if (isEmailCol(c.name)) v = `${u.replace(/[^A-Za-z0-9._-]/g, "")}.${h}@${ctx.org.replace(/[^A-Za-z0-9-]/g, "") || "org"}.example.test`;
              else if (isUsernameCol(c.name)) v = `${ctx.user ?? u}-${ctx.org}-${h}`.replace(/[^A-Za-z0-9._-]/g, "");
              else if (isRoleCol(c.name)) v = ctx.role ?? userList.find((x) => x.org === ctx.org && x.user === ctx.user)?.roles[0] ?? "USER";
              else if (/url|uri|link|website/i.test(c.name)) v = `https://example.test/${n}`;
              else if (/phone|mobile|tel/i.test(c.name)) v = `+1555${String(n).padStart(7, "0")}`;
              else if (/slug|code|key|handle/i.test(c.name)) v = `${ctx.org}-${h}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
              else v = `argos-${n}-${h}`;
              add(c.maxLen ? v.slice(0, c.maxLen) : v);
            }
            continue;
          }
          if (c.nullable) continue;
          if (c.kind === "int" || c.kind === "num") add(String(n), String(n));
          else if (c.kind === "bool") add(/active|enabled|verified|confirmed/i.test(c.name) ? "true" : "false", /active|enabled|verified|confirmed/i.test(c.name) ? "true" : "false");
          else if (c.kind === "uuid") add(uuidOf(seedKey, name, key, c.name));
          else if (c.kind === "time") add(null, c.udt === "interval" ? "interval '1 day'" : "now()");
          else if (c.kind === "json") add("{}");
          else if (c.kind === "array") add("{}");
          else if (c.kind === "bytea") add(null, "'\\x00'::bytea");
          else throw new SeedError(`unsupported structure: ${name}.${c.name} has type ${c.udt} with no default`);
        }

        const returning = pk ? ` RETURNING ${qi(pk)}::text AS pk` : "";
        const sql = values.length
          ? `INSERT INTO ${qi(name)} (${values.map((v) => qi(v.col)).join(", ")}) VALUES (${values.map((v) => v.sql).join(", ")})${returning}`
          : `INSERT INTO ${qi(name)} DEFAULT VALUES${returning}`;
        return sql;
      };
      const recordCtx = ctx;
      statements.push({
        table: name,
        build,
        after: (pkValue) => {
          const row: Record<string, string | null> = Object.fromEntries(values.map((v) => [v.col, v.text]));
          if (pk && pkValue !== undefined) row[pk] = pkValue;
          const byCtx = (manifest.rows[name] ??= {});
          if (!byCtx[key]) byCtx[key] = row; // first membership row per user wins
          if (!manifest.tables.includes(name)) manifest.tables.push(name);
          const id = pk ? row[pk] ?? undefined : undefined;
          if (name === orgTable && id !== undefined) manifest.orgIds[recordCtx.org] ??= id;
          for (const r of resources) {
            if (marker) {
              (manifest.markers[r.id] ??= {})[key] = marker;
              manifest.markers[r.id]![recordCtx.org] ??= marker;
            }
            if (id !== undefined) {
              (manifest.ids[r.id] ??= {})[key] = id;
              manifest.ids[r.id]![recordCtx.org] ??= id;
            }
          }
        },
      });
    }
  }

  const finish = (): PgSeedManifest => {
    // org identifiers when the org is a plain column value
    for (const org of orgs) {
      if (manifest.orgIds[org] !== undefined) continue;
      const r = cfg.resources.find((x) => x.owner && (x.owner.scope ?? "org") === "org");
      const t = r && schema.get(r.owner!.table);
      const c = t?.columns.find((x) => x.name === r!.owner!.column);
      manifest.orgIds[org] = c ? orgValue(org, c) : org;
    }
    for (const u of userList) {
      const key = `${u.org}/${u.user}`;
      const row = usersTable ? manifest.rows[usersTable]?.[key] : undefined;
      const ut = usersTable ? schema.get(usersTable) : undefined;
      const email = ut && row ? row[ut.columns.find((c) => isEmailCol(c.name))?.name ?? ""] ?? undefined : undefined;
      const username = ut && row ? row[ut.columns.find((c) => isUsernameCol(c.name))?.name ?? ""] ?? undefined : undefined;
      const id = ut && row && singlePk(ut) ? row[singlePk(ut)!] ?? "" : "";
      const subject = subjectMode === "email" ? email : subjectMode === "username" ? username : id;
      manifest.users[key] = {
        org: u.org,
        user: u.user,
        id,
        ...(email ? { email } : {}),
        ...(username ? { username } : {}),
        subject: subject || u.user,
        roles: u.roles,
      };
    }
    return manifest;
  };
  return { statements, finish };
}
