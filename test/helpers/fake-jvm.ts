import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { userKey, type Config } from "../../src/config.js";
import type { PgSeedManifest } from "../../src/seed-pg.js";
import type { DbHandle, SqlRow } from "../../src/stack.js";

/**
 * A Spring-like app for the springConfig() resources, backed by an in-memory "database" that the
 * matrix's writeVerify snapshot queries can read. No docker.
 */

export interface Flaws {
  /** Documents: skip the owner check (same-org users can read/update each other's documents). */
  noOwnerCheck?: boolean;
  /** Projects / documents: skip the org check. */
  noOrgCheck?: boolean;
  /** Admin endpoints: skip the role check. */
  noRoleCheck?: boolean;
  /** Accept tokens with a wrong signature / expired. */
  acceptInvalid?: boolean;
  /** PUT answers 200 without writing. */
  writeNoop?: boolean;
  /** Document DTO does not serialize the title (marker not observable). */
  omitTitle?: boolean;
  /** Reject every token (broken auth setup). */
  rejectAll?: boolean;
  /** Echo the Authorization header in error bodies. */
  echoAuth?: boolean;
}

type Row = Record<string, string>;

export interface FakeJvm {
  manifest: PgSeedManifest;
  tokens: Record<string, string>;
  db: DbHandle & { tables: Record<string, Row[]> };
}

const md5 = (s: string) => createHash("md5").update(s).digest("hex");

export function fakeJvm(cfg: Config): FakeJvm {
  const tables: Record<string, Row[]> = { organizations: [], app_users: [], projects: [], documents: [] };
  const m: PgSeedManifest = {
    markers: {}, secrets: [], ids: {}, users: {}, personaUsers: {}, orgIds: {}, rows: {}, pk: { organizations: "id", app_users: "id", projects: "id", documents: "id" }, tables: ["organizations", "app_users", "projects", "documents"], unobservable: {},
  };
  const put = (table: string, key: string, row: Row) => {
    tables[table]!.push(row);
    (m.rows[table] ??= {})[key] ??= row;
  };
  const mark = (res: string[], key: string, org: string, marker: string, id: string) => {
    for (const r of res) {
      (m.markers[r] ??= {})[key] = marker;
      m.markers[r]![org] ??= marker;
      (m.ids[r] ??= {})[key] = id;
      m.ids[r]![org] ??= id;
    }
  };
  const orgs = [...new Set(cfg.personas.map((p) => p.org).filter((o): o is string => !!o))];
  let n = 0;
  for (const org of orgs) {
    const id = `o-${org}`;
    m.orgIds[org] = id;
    put("organizations", org, { id, name: org });
    const pid = String(100 + ++n);
    const marker = `ARGOS_R${n}_p${org}`;
    put("projects", org, { id: pid, org_id: id, name: marker });
    mark(["project-list", "project-read"], org, org, marker, pid);
  }
  const tokens: Record<string, string> = {};
  for (const p of cfg.personas) {
    if (p.auth.type !== "jwt" || !p.org) continue;
    const key = `${p.org}/${userKey(p)}`;
    m.personaUsers[p.name] = key;
    tokens[p.name] = p.invalid ? `bad.${p.name}.token-value-xyz` : `good.${p.name}.token-value-xyz`;
    if (p.invalid || m.users[key]) continue;
    const uid = `u-${p.org}-${userKey(p)}`;
    const umarker = `ARGOS_R${++n}_u${userKey(p)}`;
    put("app_users", key, { id: uid, org_id: m.orgIds[p.org]!, display_name: umarker, role: (p.roles ?? ["MEMBER"])[0]! });
    mark(["admin-users"], key, p.org, umarker, uid);
    m.users[key] = { org: p.org, user: userKey(p), id: uid, subject: uid, roles: p.roles ?? [] };
    const did = `d-${p.org}-${userKey(p)}`;
    const dmarker = `ARGOS_R${++n}_d${userKey(p)}`;
    put("documents", key, { id: did, org_id: m.orgIds[p.org]!, project_id: m.rows.projects![p.org]!.id!, owner_id: uid, title: dmarker });
    mark(["document-read", "document-update"], key, p.org, dmarker, did);
  }

  const db = {
    tables,
    async query(sql: string): Promise<SqlRow[]> {
      const t = /FROM "([^"]+)" WHERE (.*)$/s.exec(sql);
      const col = /string_agg\("([^"]+)"::text/.exec(sql);
      if (!t || !col) throw new Error(`fake db: unsupported SQL ${sql}`);
      const conds = [...t[2]!.matchAll(/"([^"]+)"::text = '([^']*)'/g)].map((x) => [x[1]!, x[2]!] as const);
      const rows = tables[t[1]!]!.filter((r) => conds.every(([k, v]) => r[k] === v));
      const vals = rows.map((r) => r[col[1]!] ?? "").sort();
      return [{ n: String(rows.length), h: md5(vals.join(",")) }];
    },
    async exec(): Promise<void> {},
  };
  return { manifest: m, tokens, db };
}

export function fakeJvmApp(f: FakeJvm, cfg: Config, flaws: Flaws = {}): Promise<Server & { url: string }> {
  const byToken = new Map(Object.entries(f.tokens).map(([name, tok]) => [tok, cfg.personas.find((p) => p.name === name)!]));
  const json = (res: import("node:http").ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };
  return new Promise((ok) => {
    const srv = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const url = new URL(req.url!, "http://x");
        const path = url.pathname;
        if (path === "/healthz") return json(res, 200, { status: "ok" });
        const auth = req.headers.authorization ?? "";
        const p = byToken.get(auth.replace(/^Bearer /, ""));
        const unauthorized = () => json(res, 401, flaws.echoAuth ? { error: "unauthorized", got: auth } : { error: "unauthorized" });
        if (!p || flaws.rejectAll || (p.invalid && !flaws.acceptInvalid)) return unauthorized();
        const me = f.manifest.users[f.manifest.personaUsers[p.name]!]!;
        const orgId = f.manifest.orgIds[me.org]!;
        const admin = (p.roles ?? []).includes("ADMIN");
        const T = f.db.tables;

        if (path === "/api/projects" && req.method === "GET") return json(res, 200, { content: T.projects!.filter((r) => r.org_id === orgId) });
        if (path === "/api/projects" && req.method === "POST") {
          if (!admin && !flaws.noRoleCheck) return json(res, 403, {});
          const b = JSON.parse(body || "{}") as { name?: string };
          if (!b.name) return json(res, 400, {});
          const row = { id: String(900 + T.projects!.length), org_id: orgId, name: b.name };
          T.projects!.push(row);
          return json(res, 201, row);
        }
        let mm = /^\/api\/projects\/(\w+)$/.exec(path);
        if (mm && req.method === "GET") {
          const r = T.projects!.find((x) => x.id === mm![1]);
          if (!r || (r.org_id !== orgId && !flaws.noOrgCheck)) return json(res, 404, {});
          return json(res, 200, r);
        }
        mm = /^\/api\/projects\/(\w+)\/documents\/([\w-]+)$/.exec(path);
        if (mm) {
          const d = T.documents!.find((x) => x.id === mm![2] && x.project_id === mm![1]);
          if (!d || (d.org_id !== orgId && !flaws.noOrgCheck) || (d.owner_id !== me.id && !flaws.noOwnerCheck)) return json(res, 404, {});
          if (req.method === "GET") return json(res, 200, flaws.omitTitle ? { id: d.id } : d);
          if (req.method === "PUT") {
            const b = JSON.parse(body || "{}") as { title?: string; body?: string };
            if (!b.title || !b.body) return json(res, 400, {});
            if (!flaws.writeNoop) d.title = b.title;
            return json(res, 200, { id: d.id });
          }
        }
        if (path === "/api/admin/users" && req.method === "GET") {
          if (!admin && !flaws.noRoleCheck) return json(res, 403, {});
          return json(res, 200, T.app_users!.filter((r) => r.org_id === orgId));
        }
        json(res, 404, {});
      });
    }).listen(0, "127.0.0.1", () => {
      (srv as Server & { url: string }).url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
      ok(srv as Server & { url: string });
    });
  });
}
