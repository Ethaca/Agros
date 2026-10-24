import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { discoverSchema, parseCheckIn, seedPostgres, type PgSeedManifest } from "../src/seed-pg.js";
import { SeedError } from "../src/seed.js";
import { dockerAvailable, startPg, type PgContainer } from "./helpers/pg-docker.js";
import { FIXTURE_MIGRATION, springConfig } from "./helpers/spring-config.js";

test("parseCheckIn: Postgres-normalized IN lists", () => {
  assert.deepEqual(parseCheckIn("CHECK (((role)::text = ANY ((ARRAY['ADMIN'::character varying, 'MEMBER'::character varying])::text[])))"), { column: "role", values: ["ADMIN", "MEMBER"] });
  assert.deepEqual(parseCheckIn("CHECK ((status = ANY (ARRAY['a'::text, 'it''s'::text])))"), { column: "status", values: ["a", "it's"] });
  assert.equal(parseCheckIn("CHECK (((slug)::text ~ '^[a-z]+$'::text))"), undefined);
});

const docker = dockerAvailable();
let pg: PgContainer | undefined;
let m: PgSeedManifest | undefined;

before(async () => {
  if (!docker) return;
  pg = await startPg();
  await pg.exec(readFileSync(FIXTURE_MIGRATION, "utf8"));
  m = await seedPostgres(springConfig(), pg, { seedKey: "k" });
});
after(() => pg?.stop());

test("pg seed: schema discovery reads PK/FK/unique/CHECK lists", { skip: !docker && "docker not available" }, async () => {
  const schema = await discoverSchema(pg!);
  const docs = schema.get("documents")!;
  assert.deepEqual(docs.pk, ["id"]);
  assert.ok(docs.fks.some((f) => f.cols[0] === "project_id" && f.refTable === "projects"));
  assert.deepEqual(schema.get("app_users")!.columns.find((c) => c.name === "role")!.values, ["ADMIN", "MEMBER"]);
  assert.equal(schema.get("projects")!.columns.find((c) => c.name === "id")!.dflt, "identity");
  assert.ok(schema.get("organizations")!.uniques.some((u) => u.join() === "slug"));
});

test("pg seed: two orgs, one user per persona user, rows per org / per user, valid constraints", { skip: !docker && "docker not available" }, async () => {
  const count = async (t: string) => Number((await pg!.query(`SELECT count(*)::int AS n FROM ${t}`))[0]!.n);
  assert.equal(await count("organizations"), 2);
  assert.equal(await count("app_users"), 5); // alice-admin, alice-member, alice-member2, bob-admin, bob-member
  assert.equal(await count("projects"), 2);
  assert.equal(await count("documents"), 5);
  // user roles follow persona roles
  const roles = await pg!.query(`SELECT role, count(*)::int AS n FROM app_users GROUP BY role ORDER BY role`);
  assert.deepEqual(roles.map((r) => [r.role, r.n]), [["ADMIN", 2], ["MEMBER", 3]]);
  // documents point at the same org's project and the owning user
  const bad = await pg!.query(`SELECT d.id FROM documents d JOIN projects p ON p.id = d.project_id JOIN app_users u ON u.id = d.owner_id WHERE p.org_id <> d.org_id OR u.org_id <> d.org_id`);
  assert.equal(bad.length, 0);
});

test("pg seed: manifest maps personas to users, subjects, ids and markers", { skip: !docker && "docker not available" }, async () => {
  const mm = m!;
  assert.equal(mm.personaUsers["forged"], "orgA/alice-member", "invalid persona reuses the real user");
  const alice = mm.users["orgA/alice-admin"]!;
  assert.match(alice.subject, /^[0-9a-f-]{36}$/, "subject: id = app_users UUID");
  assert.equal(alice.subject, alice.id);
  // user-scoped resource: ids and markers per user, plus an org-level default
  const ids = mm.ids["document-read"]!;
  assert.ok(ids["orgA/alice-member"] && ids["orgA/alice-member2"] && ids["orgA/alice-member"] !== ids["orgA/alice-member2"]);
  const mk = mm.markers["document-read"]!;
  assert.ok(mk["orgA/alice-member"]!.startsWith("ARGOS_R"));
  const row = await pg!.query(`SELECT title FROM documents WHERE id = '${ids["orgA/alice-member"]}'`);
  assert.equal(row[0]!.title, mk["orgA/alice-member"]);
  // org-scoped: project ids by org (identity column assigned by the DB)
  assert.ok(/^\d+$/.test(String(mm.ids["project-read"]!["orgA"])));
  assert.notEqual(mm.ids["project-read"]!["orgA"], mm.ids["project-read"]!["orgB"]);
  // secrets in sensitive columns (organizations.api_key, documents.share_token)
  assert.ok(mm.secrets.some((s) => s.table === "organizations" && s.column === "api_key"));
  assert.ok(mm.secrets.some((s) => s.table === "documents" && s.column === "share_token"));
  assert.deepEqual(Object.keys(mm.orgIds).sort(), ["orgA", "orgB"]);
});

test("pg seed: unsupported structure is a SeedError, not a crash", { skip: !docker && "docker not available" }, async () => {
  const cfg = springConfig();
  cfg.resources.push({ id: "ghost", route: "GET /api/ghosts", owner: { table: "ghosts", column: "org_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } });
  await assert.rejects(seedPostgres(cfg, pg!, { seedKey: "k" }), (e: Error) => e instanceof SeedError && /table "ghosts" not found/.test(e.message));
});
