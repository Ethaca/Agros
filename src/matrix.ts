import { createHash } from "node:crypto";
import { actionOf, hasCredentials, routeParams, userKey, type Config } from "./config.js";
import { fillParams, fillPath, parseRoute, sendAs, type HttpResult, type Persona } from "./http.js";
import { maskMarker, orgMarkers, redact, type SeedManifest } from "./seed.js";
import { lit, qi, type PgSeedManifest } from "./seed-pg.js";
import type { DbHandle } from "./stack.js";
import type { Access, Evidence, Matrix, MatrixCell, Observed, Verdict } from "./types.js";

type Resource = Config["resources"][number];
type Relation = NonNullable<MatrixCell["relation"]>;

export interface Obs {
  status: number | null;
  body: string;
  /** Markers of the requested org's data (any table); undefined for resources without rows. */
  markers?: string[];
  /** Persona is requesting its own row (a 404 then is an error, not hidden existence). */
  ownRequest: boolean;
  /** Collection route (no path param) asked by a persona for another org's data: a response without that
   *  org's markers means the list was scoped to the caller, which is the correct behaviour. */
  scopedList?: boolean;
}

/** SPEC 6.4: 2xx + requested row's marker -> allow; 401/403 -> deny; 404 -> deny (own request: error); 2xx w/o marker -> allow-empty. */
export function observe(o: Obs): Observed {
  const s = o.status;
  if (s === null) return "error";
  if (s >= 200 && s < 300) {
    if (o.markers === undefined) return "allow";
    if (o.markers.some((m) => o.body.includes(m))) return "allow";
    return o.scopedList ? "deny" : "allow-empty";
  }
  if (s === 401 || s === 403) return "deny";
  if (s === 404) return o.ownRequest ? "error" : "deny";
  return "error";
}

/** expected deny + allow -> VULNERABLE. Contrast failures and ambiguous results are SUSPECTED/SKIPPED, never OK. */
export function verdictFor(expected: Access, observed: Observed): Verdict {
  if (observed === "error") return "SKIPPED";
  if (expected === "deny") {
    if (observed === "deny") return "OK";
    return observed === "allow" ? "VULNERABLE" : "SUSPECTED";
  }
  return observed === "allow" ? "OK" : "SUSPECTED";
}

const normRole = (r: string): string => r.replace(/^ROLE_/i, "").toUpperCase();

/** Does the persona hold one of the resource's roles? Resources without `roles` allow every role. */
export function roleAllowed(persona: Persona, resource: Resource): boolean {
  if (!resource.roles?.length) return true;
  const want = new Set(resource.roles.map(normRole));
  return (persona.roles ?? []).some((r) => want.has(normRole(r)));
}

export interface Plan {
  persona: Persona;
  resource: Resource;
  target?: string;
  /** User whose row is requested (user-scoped rows / same-org other user). */
  targetUser?: string;
  relation?: Relation;
  expected: Access;
}

/** Users that own data: one per (org, user key) of personas with valid credentials, in persona order. */
function usersOf(cfg: Config): { org: string; user: string }[] {
  const out: { org: string; user: string }[] = [];
  for (const p of cfg.personas) {
    if (!p.org || !hasCredentials(p)) continue;
    if (!out.some((u) => u.org === p.org && u.user === userKey(p))) out.push({ org: p.org, user: userKey(p) });
  }
  return out;
}

/**
 * subject × target org × target owner × resource × action. Legacy configs (one persona per org, no roles,
 * no user scope) give exactly the old persona × resource × org plan.
 */
export function plan(cfg: Config): Plan[] {
  const orgs = [...new Set(cfg.personas.map((p) => p.org).filter((o): o is string => !!o))];
  const users = usersOf(cfg);
  const firstUser = (org: string) => users.find((u) => u.org === org)?.user;
  const out: Plan[] = [];
  for (const persona of cfg.personas) {
    for (const resource of cfg.resources) {
      const exp = resource.expect;
      const userScope = resource.owner?.scope === "user";
      // A broken token may rightly be rejected even on a public route (Spring answers 401): nothing to test there.
      if (resource.public && persona.invalid) continue;
      if (resource.public) {
        out.push({ persona, resource, expected: "allow" });
      } else if (persona.invalid) {
        const target = resource.owner ? (persona.org ?? orgs[0]) : undefined;
        const targetUser = userScope && target ? (persona.org ? userKey(persona) : firstUser(target)) : undefined;
        out.push({ persona, resource, ...(target ? { target } : {}), ...(targetUser ? { targetUser } : {}), relation: "invalid-token", expected: exp!.anonymous });
      } else if (!resource.owner) {
        if (persona.org && !roleAllowed(persona, resource)) out.push({ persona, resource, relation: "role", expected: exp!.member ?? "deny" });
        else out.push({ persona, resource, expected: persona.org ? exp!.owner : exp!.anonymous });
      } else if (!persona.org) {
        const targetUser = userScope ? firstUser(orgs[0]!) : undefined;
        out.push({ persona, resource, target: orgs[0], ...(targetUser ? { targetUser } : {}), expected: exp!.anonymous });
      } else {
        const me = userKey(persona);
        const denied = !roleAllowed(persona, resource);
        out.push({
          persona, resource, target: persona.org,
          ...(userScope ? { targetUser: me } : {}),
          ...(denied ? { relation: "role" as const, expected: exp!.member ?? "deny" } : { expected: exp!.owner }),
        });
        if (userScope) {
          for (const u of users) {
            if (u.org === persona.org && u.user !== me) {
              out.push({ persona, resource, target: persona.org, targetUser: u.user, relation: "same-org", expected: exp!.sameOrgOther ?? "deny" });
            }
          }
        }
        for (const o of orgs) {
          if (o === persona.org) continue;
          const targetUser = userScope ? firstUser(o) : undefined;
          out.push({ persona, resource, target: o, ...(targetUser ? { targetUser } : {}), expected: exp!.other });
        }
      }
    }
  }
  return out;
}

function cellBase(p: Plan, withAction: boolean): Omit<MatrixCell, "expected" | "observed" | "verdict" | "evidence"> {
  return {
    persona: p.persona.name,
    resource: p.resource.id,
    ...(p.target ? { target: p.target } : {}),
    ...(p.targetUser ? { targetUser: p.targetUser } : {}),
    ...(p.relation ? { relation: p.relation } : {}),
    ...(withAction ? { action: actionOf(p.resource) } : {}),
  };
}

function skipped(p: Plan, request: string, note: string, withAction = false): MatrixCell {
  return { ...cellBase(p, withAction), expected: p.expected, observed: "error", verdict: "SKIPPED", evidence: { request, note } };
}

export interface MatrixOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  /** persona name -> bearer token minted for this run (jwt personas). Never serialized. */
  tokens?: Record<string, string>;
  /** Per-run database: enables write actions and their DB state verification (runtime jvm). */
  db?: DbHandle;
  /** persona name -> reason: the persona's auth precheck failed, its cells are unverified. */
  skipPersonas?: Record<string, string>;
  /** Whole run unverified (e.g. no persona passed the auth precheck). */
  skipAll?: string;
}

export interface DetailedMatrix {
  matrix: Matrix;
  /** Full responses, index-aligned with matrix.cells (undefined when no request was sent). Never serialize these. */
  raw: (HttpResult | undefined)[];
}

export async function runMatrix(cfg: Config, baseUrl: string, manifest: SeedManifest, opts: MatrixOptions = {}): Promise<Matrix> {
  return (await runMatrixDetailed(cfg, baseUrl, manifest, opts)).matrix;
}

const isPg = (m: SeedManifest): m is PgSeedManifest => "rows" in m && "users" in m;

/** Values a request template may use. */
interface Ctx {
  org?: string;
  user?: string;
}

/** `projectId` -> projects / project; `document_id` -> documents. */
function tableGuess(param: string): string[] {
  const base = param.replace(/_?id$/i, "").replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  return base ? [`${base}s`, base, `${base}es`] : [];
}

function rowFor(m: PgSeedManifest, table: string, c: Ctx): Record<string, string | null> | undefined {
  const byCtx = m.rows[table];
  if (!byCtx) return undefined;
  return (c.org && c.user ? byCtx[`${c.org}/${c.user}`] : undefined) ?? (c.org ? byCtx[c.org] : undefined) ?? byCtx["*"];
}

let uniqueN = 0;
function substitute(value: unknown, c: Ctx, m: SeedManifest, seed: string): unknown {
  if (typeof value === "string") {
    const whole = /^\$id:([A-Za-z_][A-Za-z0-9_]*)$/.exec(value);
    const resolveId = (table: string): string | undefined => {
      if (!isPg(m)) return undefined;
      const pk = m.pk[table];
      return pk ? rowFor(m, table, c)?.[pk] ?? undefined : undefined;
    };
    if (whole) {
      const id = resolveId(whole[1]!);
      return id !== undefined && /^\d+$/.test(id) ? Number(id) : id ?? null;
    }
    const pgm = isPg(m) ? m : undefined;
    const u = c.org && c.user ? pgm?.users[`${c.org}/${c.user}`] : undefined;
    const tag = createHash("sha256").update(`${seed}|${++uniqueN}`).digest("hex").slice(0, 8);
    return value
      .replace(/\$id:([A-Za-z_][A-Za-z0-9_]*)/g, (_x, t: string) => resolveId(t) ?? "")
      .replace(/\$orgId\b/g, (c.org && pgm?.orgIds[c.org]) || c.org || "")
      .replace(/\$userId\b/g, u?.id ?? "")
      .replace(/\$org\b/g, c.org ?? "")
      .replace(/\$user\b/g, c.user ?? "")
      .replace(/\$marker\b/g, `ARGOS_W_${tag}`)
      .replace(/\$unique\b/g, `argos-w-${tag}`);
  }
  if (Array.isArray(value)) return value.map((v) => substitute(v, c, m, seed));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, c, m, seed)]));
  return value;
}

interface Built {
  method: string;
  path: string;
  json?: unknown;
  query?: Record<string, string>;
  markers?: string[];
  /** Data owner of the request: target org/user, or the persona's own org/user for resources without rows. */
  ctx: Ctx;
}

/** Turn a plan into a concrete request, or a reason why it cannot be sent. */
function buildRequest(cfg: Config, p: Plan, manifest: SeedManifest): Built | { skip: string } {
  const { method, path } = parseRoute(p.resource.route);
  const jvm = cfg.target.runtime === "jvm";
  const params = routeParams(path);
  const key = p.target && p.targetUser ? `${p.target}/${p.targetUser}` : p.target;
  const markers = key
    ? p.targetUser ? [manifest.markers[p.resource.id]?.[key]].filter((x): x is string => !!x) : orgMarkers(manifest, key)
    : undefined;
  const rowId = key ? manifest.ids[p.resource.id]?.[key] : undefined;
  const pg = isPg(manifest) ? manifest : undefined;
  const ctx: Ctx = p.target ? { org: p.target, user: p.targetUser } : { org: p.persona.org, user: p.persona.org ? userKey(p.persona) : undefined };

  if (p.target && !markers?.length) {
    const why = pg?.unobservable[p.resource.id];
    return { skip: why ? `marker not observable: ${why}` : `no seeded row for ${p.targetUser ? `user "${key}"` : `org "${p.target}"`}` };
  }
  if (!jvm && !p.resource.pathParams) {
    if (p.target && rowId === undefined) return { skip: `no seeded row for org "${p.target}"` };
  }

  let filled: string;
  if (!jvm && !p.resource.pathParams) filled = fillPath(path, rowId ?? 1);
  else {
    let missing: string | undefined;
    filled = fillParams(path, (name) => {
      const spec = p.resource.pathParams?.[name];
      const last = name === params[params.length - 1];
      let v: string | number | undefined;
      if (spec && pg) {
        const row = rowFor(pg, spec.table, ctx);
        v = row?.[spec.column ?? pg.pk[spec.table] ?? ""] ?? undefined;
      } else if (last && rowId !== undefined) v = rowId;
      else if (pg) {
        const t = tableGuess(name).find((x) => pg.rows[x]);
        v = t ? rowFor(pg, t, ctx)?.[pg.pk[t] ?? ""] ?? undefined : undefined;
      }
      v ??= rowId;
      if (v === undefined) missing ??= name;
      return v ?? 1;
    });
    if (missing) return { skip: `no seeded row for path parameter "${missing}"` };
  }
  const seed = `${p.persona.name}|${p.resource.id}|${key ?? ""}`;
  const json = method === "GET" ? undefined : p.resource.body ? substitute(p.resource.body, ctx, manifest, seed) : {};
  const query = p.resource.query ? (substitute(p.resource.query, ctx, manifest, seed) as Record<string, string>) : undefined;
  return { method, path: filled, json, query, markers, ctx };
}

/** Count + hash of the verified column for the rows a write should (or should not) touch. */
function snapshotWhere(r: Resource, ctx: Ctx, manifest: SeedManifest): string | { skip: string } {
  const wv = r.writeVerify!;
  let where: string;
  if (wv.where) {
    where = Object.entries(wv.where)
      .map(([k, v]) => `${qi(k)}::text = ${lit(String(substitute(v, ctx, manifest, "where")))}`)
      .join(" AND ");
  } else {
    const pg = isPg(manifest) ? manifest : undefined;
    const pk = pg?.pk[wv.table];
    const id = pg && pk ? rowFor(pg, wv.table, ctx)?.[pk] : undefined;
    if (!pk || id === undefined || id === null) return { skip: `writeVerify: no seeded ${wv.table} row to compare (set writeVerify.where)` };
    where = `${qi(pk)}::text = ${lit(id)}`;
  }
  return where;
}

async function dbSnapshot(db: DbHandle, r: Resource, ctx: Ctx, manifest: SeedManifest): Promise<string | { skip: string }> {
  const wv = r.writeVerify!;
  const where = snapshotWhere(r, ctx, manifest);
  if (typeof where !== "string") return where;
  const rows = await db.query(
    `SELECT count(*)::text AS n, md5(coalesce(string_agg(${qi(wv.column)}::text, ',' ORDER BY ${qi(wv.column)}::text), '')) AS h FROM ${qi(wv.table)} WHERE ${where}`,
  );
  return `${rows[0]?.n}:${rows[0]?.h}`;
}

/**
 * Delete probes: keep a copy of the targeted rows and put back whatever the request removed, so a
 * successful attack cannot take away the row later probes (and the owner's own control) need.
 * Rows removed by ON DELETE CASCADE in other tables are not restored.
 */
async function saveRows(db: DbHandle, r: Resource, ctx: Ctx, manifest: SeedManifest): Promise<(() => Promise<void>) | undefined> {
  const where = snapshotWhere(r, ctx, manifest);
  if (typeof where !== "string") return undefined;
  const t = qi(r.writeVerify!.table);
  const rows = await db.query(`SELECT row_to_json(x)::text AS j FROM ${t} x WHERE ${where}`);
  const saved = rows.map((x) => String(x.j));
  return async () => {
    for (const j of saved) await db.exec(`INSERT INTO ${t} SELECT * FROM json_populate_record(NULL::${t}, ${lit(j)}) ON CONFLICT DO NOTHING;`);
  };
}

/** Build the full plan matrix against a running target. Requests run sequentially. */
export async function runMatrixDetailed(
  cfg: Config,
  baseUrl: string,
  manifest: SeedManifest,
  opts: MatrixOptions = {},
): Promise<DetailedMatrix> {
  const plans = plan(cfg);
  const jvm = cfg.target.runtime === "jvm";
  uniqueN = 0; // $unique / $marker values are reproducible per run
  const cells: MatrixCell[] = new Array(plans.length);
  const raw: (HttpResult | undefined)[] = new Array(plans.length).fill(undefined);
  const withAction = (r: Resource) => jvm || !!r.action;

  // jvm: reads first, then writes (attacks before the owner's own write), deletes last, so one write
  // cannot remove the row another request needs (a row a delete probe removed is restored). Output keeps plan order.
  const rank = (p: Plan): number => {
    if (!jvm) return 0;
    const a = actionOf(p.resource);
    return a === "read" ? 0 : (a === "delete" ? 4 : 2) + (p.expected === "allow" ? 1 : 0);
  };
  const order = plans.map((_, i) => i).sort((a, b) => rank(plans[a]!) - rank(plans[b]!) || a - b);

  for (const i of order) {
    const p = plans[i]!;
    const { method } = parseRoute(p.resource.route);
    const wa = withAction(p.resource);
    const write = actionOf(p.resource) !== "read" || method !== "GET";
    if (method !== "GET" && !p.resource.safe) {
      cells[i] = skipped(p, p.resource.route, "non-GET route not marked safe: true", wa);
      continue;
    }
    if (jvm && write && (!opts.db || cfg.target.isolation !== "container")) {
      cells[i] = skipped(p, p.resource.route, "write not run: needs a one-off database (db + container isolation)", wa);
      continue;
    }
    if (opts.skipAll) {
      cells[i] = skipped(p, p.resource.route, `미검증: ${opts.skipAll}`, wa);
      continue;
    }
    const personaSkip = opts.skipPersonas?.[p.persona.name];
    if (personaSkip) {
      cells[i] = skipped(p, p.resource.route, `미검증: 정상 대조 실패 — ${personaSkip}`, wa);
      continue;
    }
    const token = opts.tokens?.[p.persona.name];
    if (p.persona.auth.type === "jwt" && !token) {
      cells[i] = skipped(p, p.resource.route, "no token was minted for this persona", wa);
      continue;
    }
    const b = buildRequest(cfg, p, manifest);
    if ("skip" in b) {
      cells[i] = skipped(p, p.resource.route, b.skip, wa);
      continue;
    }

    const verify = jvm && write && p.resource.writeVerify && opts.db ? opts.db : undefined;
    let before: string | undefined;
    if (verify) {
      try {
        const s = await dbSnapshot(verify, p.resource, b.ctx, manifest);
        if (typeof s !== "string") {
          cells[i] = skipped(p, p.resource.route, s.skip, wa);
          continue;
        }
        before = s;
      } catch (e) {
        cells[i] = skipped(p, p.resource.route, `DB state check failed: ${(e as Error).message.split("\n")[0]}`, wa);
        continue;
      }
    }

    let restore: (() => Promise<void>) | undefined;
    if (verify && actionOf(p.resource) === "delete") {
      try {
        restore = await saveRows(verify, p.resource, b.ctx, manifest);
      } catch {
        restore = undefined; // verdict still comes from the snapshot; later probes may find the row gone
      }
    }

    const res: HttpResult = await sendAs(baseUrl, p.persona, b.method, b.path, { timeoutMs: opts.timeoutMs, maxResponseBytes: opts.maxResponseBytes, json: b.json, query: b.query, token });
    raw[i] = res;
    const me = p.persona.org ? userKey(p.persona) : undefined;
    const own = !!p.target && p.target === p.persona.org && (!p.targetUser || p.targetUser === me) && !p.relation;
    // Collection route: no path param picks a row of the owner table (e.g. /projects/{projectId}/documents
    // lists documents). A param without a pathParams entry is taken to address the owner table (legacy :id).
    const ownerTable = p.resource.owner?.table;
    const collection = !routeParams(parseRoute(p.resource.route).path).some((n) => (p.resource.pathParams?.[n]?.table ?? ownerTable) === ownerTable);

    let observed: Observed;
    let dbNote: string | undefined;
    let dbRestoreNote: string | undefined;
    if (jvm && write) {
      let changed: boolean | undefined;
      if (verify && before !== undefined) {
        try {
          const after = await dbSnapshot(verify, p.resource, b.ctx, manifest);
          changed = typeof after === "string" ? after !== before : undefined;
        } catch {
          changed = undefined;
        }
      }
      if (restore && changed) {
        try {
          await restore();
        } catch (e) {
          dbRestoreNote = `deleted row could not be restored: ${(e as Error).message.split("\n")[0]}`;
        }
      }
      const s = res.status;
      const denied = s === 401 || s === 403 || s === 404;
      if (s === null) observed = "error";
      else if (changed === true) observed = "allow";
      else if (changed === undefined && verify) observed = "error";
      else if (s >= 200 && s < 300) observed = "allow-empty";
      else observed = denied ? "deny" : "error";
      dbNote = !verify
        ? "DB state not verified (no writeVerify): a 2xx alone is not proof"
        : changed === undefined
          ? "DB state could not be re-read"
          : changed
            ? `DB changed (${p.resource.writeVerify!.table}.${p.resource.writeVerify!.column})`
            : `DB unchanged (${p.resource.writeVerify!.table}.${p.resource.writeVerify!.column})`;
    } else {
      observed = observe({
        status: res.status,
        body: res.body,
        markers: b.markers,
        ownRequest: own,
        // A list scoped to the caller (no other org's / other user's markers) is the correct, denying behaviour.
        scopedList: collection && (!p.relation || p.relation === "same-org") && !!p.persona.org && !!p.target && !own,
      });
    }
    const ev = evidenceFor(res, b.markers, manifest);
    if (dbRestoreNote) dbNote = dbNote ? `${dbNote}; ${dbRestoreNote}` : dbRestoreNote;
    if (dbNote) ev.note = ev.note ? `${dbNote}; ${ev.note}` : dbNote;
    cells[i] = { ...cellBase(p, wa), expected: p.expected, observed, verdict: verdictFor(p.expected, observed), evidence: ev };
  }

  // jvm: when the owner's own successful read lacks the seeded marker, the marker is not observable on this
  // resource (DTO does not serialize that column, filtering...): nothing on it can be concluded from markers.
  if (jvm) {
    for (const r of cfg.resources) {
      if (actionOf(r) !== "read") continue;
      const own = plans.some((p, i) => p.resource.id === r.id && !p.relation && p.target === p.persona.org && (!p.targetUser || p.targetUser === userKey(p.persona)) && cells[i]!.observed === "allow-empty");
      if (!own) continue;
      plans.forEach((p, i) => {
        const c = cells[i]!;
        if (p.resource.id !== r.id || c.observed !== "allow-empty") return;
        cells[i] = { ...c, verdict: "SKIPPED", evidence: { ...c.evidence, note: `marker not observable: the owner's own 2xx response did not contain the seeded marker${c.evidence.note ? `; ${c.evidence.note}` : ""}` } };
      });
    }
  }

  return {
    matrix: {
      personas: cfg.personas.map((x) => x.name),
      resources: cfg.resources.map((r) => r.id),
      cells,
    },
    raw,
  };
}

export interface PrecheckResult {
  /** persona -> reason its valid token could not be confirmed (its cells become unverified). */
  failed: Record<string, string>;
  /** One line per probe, no tokens. */
  notes: string[];
  /** Set when no persona with credentials passed: the whole run is unverified. */
  skipAll?: string;
}

/**
 * Before the matrix (runtime jvm): a valid token must reach something the persona may read (contrast),
 * wrong-signature / expired tokens and anonymous requests must be rejected (401/403). A failing contrast
 * means "unverified", never "secure".
 */
export async function authPrecheck(cfg: Config, baseUrl: string, manifest: SeedManifest, opts: MatrixOptions = {}): Promise<PrecheckResult> {
  const plans = plan(cfg);
  const failed: Record<string, string> = {};
  const notes: string[] = [];
  const contrastOf = (persona: Persona): Plan | undefined =>
    plans.find((p) => p.persona === persona && !p.relation && p.expected === "allow" && !p.resource.public &&
      actionOf(p.resource) === "read" && parseRoute(p.resource.route).method === "GET" &&
      (!p.target || (p.target === persona.org && (!p.targetUser || p.targetUser === userKey(persona)))));
  const send = async (persona: Persona, p: Plan): Promise<{ request: string; status: number | null; ok2xx: boolean } | { skip: string }> => {
    const b = buildRequest(cfg, { ...p, persona }, manifest);
    if ("skip" in b) return b;
    const res = await sendAs(baseUrl, persona, b.method, b.path, { timeoutMs: opts.timeoutMs, query: b.query, token: opts.tokens?.[persona.name] });
    return { request: res.request, status: res.status, ok2xx: res.status !== null && res.status >= 200 && res.status < 300 };
  };

  let probe: Plan | undefined;
  for (const persona of cfg.personas.filter(hasCredentials)) {
    if (persona.auth.type === "jwt" && !opts.tokens?.[persona.name]) {
      failed[persona.name] = "no token was minted";
      continue;
    }
    const c = contrastOf(persona);
    if (!c) {
      failed[persona.name] = "no readable resource to confirm the token with";
      continue;
    }
    const r = await send(persona, c);
    if ("skip" in r) failed[persona.name] = r.skip;
    else if (!r.ok2xx) failed[persona.name] = `${r.request} -> ${r.status ?? "no response"} with a valid token`;
    else {
      notes.push(`auth precheck: ${persona.name} ${r.request} -> ${r.status}`);
      probe ??= c;
    }
  }
  for (const [name, why] of Object.entries(failed)) notes.push(`auth precheck failed: ${name}: ${why}`);

  // Rejections: only meaningful once some contrast worked (otherwise a dead route would look like a rejection).
  if (probe) {
    for (const persona of cfg.personas.filter((x) => !hasCredentials(x))) {
      if (persona.auth.type === "jwt" && !opts.tokens?.[persona.name]) continue;
      const r = await send(persona, probe);
      if ("skip" in r) continue;
      const rejected = r.status === 401 || r.status === 403;
      notes.push(`auth precheck: ${persona.name} (${persona.invalid ?? "anonymous"}) ${r.request} -> ${r.status ?? "no response"}${rejected ? "" : " (expected 401/403)"}`);
    }
  }
  const valid = cfg.personas.filter(hasCredentials);
  const skipAll = valid.length && valid.every((p) => failed[p.name]) ? "정상 대조 실패 (no persona's valid token reached its own data)" : undefined;
  return { failed, notes, ...(skipAll ? { skipAll } : {}) };
}

/** M4: request line, status, and a short body excerpt with markers masked. */
function evidenceFor(res: HttpResult, markers: string[] | undefined, manifest: SeedManifest): Evidence {
  const ev: Evidence = { request: redact(res.request, manifest) };
  if (res.status !== null) ev.status = res.status;
  const hit = markers?.find((m) => res.body.includes(m));
  if (hit !== undefined) ev.marker = maskMarker(hit);
  // A response carrying an env canary is an environment dump: never echo any of it (it holds host PATH/HOME etc.).
  const dumpsEnv = (manifest.envCanaries ?? []).some((k) => res.body.includes(k.marker));
  const note = res.error ?? (dumpsEnv ? "body withheld: response contains the process environment" : redact(res.body.slice(0, 160), manifest));
  if (note) ev.note = note;
  return ev;
}

const ICON: Record<Verdict, string> = { VULNERABLE: "🔴", SUSPECTED: "🟡", OK: "🟢", SKIPPED: "⚪" };

/** Markdown table (also readable in a terminal): rows = persona → target, columns = resources. */
export function renderMatrixMarkdown(m: Matrix): string {
  const rowKeys: string[] = [];
  const grid = new Map<string, MatrixCell>();
  for (const c of m.cells) {
    const tgt = c.target ? (c.targetUser ? `${c.target}/${c.targetUser}` : c.target) : undefined;
    const key = tgt ? `${c.persona} → ${tgt}` : c.persona;
    if (!rowKeys.includes(key)) rowKeys.push(key);
    grid.set(`${key}|${c.resource}`, c);
  }
  const head = `| persona → data | ${m.resources.join(" | ")} |`;
  const sep = `|---|${m.resources.map(() => "---").join("|")}|`;
  const rows = rowKeys.map((k) => {
    const cols = m.resources.map((r) => {
      const c = grid.get(`${k}|${r}`);
      return c ? `${ICON[c.verdict]} ${c.expected}/${c.observed}` : "–";
    });
    return `| ${k} | ${cols.join(" | ")} |`;
  });
  return [head, sep, ...rows, "", "cell = verdict expected/observed · 🔴 VULNERABLE 🟡 SUSPECTED 🟢 OK ⚪ SKIPPED"].join("\n");
}
