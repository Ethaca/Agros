import { test } from "node:test";
import assert from "node:assert/strict";
import { parse } from "yaml";
import { readFileSync } from "node:fs";
import { loadConfig, parseConfig, ConfigError } from "../src/config.js";
import { Matrix } from "../src/types.js";

const example = () => parse(readFileSync("examples/argos.config.yaml", "utf8"));

test("example config loads and applies defaults", () => {
  const cfg = loadConfig("examples/argos.config.yaml");
  assert.equal(cfg.mode, "report");
  assert.equal(cfg.secrets.allowOwnerSecretRead, false);
});

test("missing required field reports location and reason", () => {
  const raw = example();
  delete raw.target.start;
  assert.throws(() => parseConfig(raw), (e: Error) => e instanceof ConfigError && e.message.startsWith("target.start:"));
});

test("unknown key is rejected", () => {
  const raw = example();
  raw.bogus = 1;
  assert.throws(() => parseConfig(raw), /bogus|Unrecognized/);
});

test("invalid enum is rejected", () => {
  const raw = example();
  raw.mode = "loud";
  assert.throws(() => parseConfig(raw), /^ConfigError|mode:/);
});

test("needs an anonymous persona and two authenticated personas", () => {
  const raw = example();
  raw.personas = raw.personas.filter((p: any) => p.name !== "anonymous");
  assert.throws(() => parseConfig(raw), /anonymous/);
  const raw2 = example();
  raw2.personas = [raw2.personas[0], raw2.personas[2]];
  assert.throws(() => parseConfig(raw2), /at least 2/);
});

test("non-public resource requires expect", () => {
  const raw = example();
  delete raw.resources[0].expect;
  assert.throws(() => parseConfig(raw), /resources\.0\.expect/);
});

test("duplicate persona names are rejected", () => {
  const raw = example();
  raw.personas[1].name = "vendor1";
  assert.throws(() => parseConfig(raw), /duplicate/);
});

test("matrix contract schema accepts the SPEC example", () => {
  const m = Matrix.parse({
    personas: ["vendor1", "vendor2", "anonymous"],
    resources: ["dataset-read"],
    cells: [{
      persona: "vendor2", resource: "dataset-read", expected: "deny", observed: "allow",
      verdict: "VULNERABLE",
      evidence: { request: "GET /api/datasets/d1", status: 200, marker: "ARGOS_" },
    }],
  });
  assert.equal(m.cells[0]!.verdict, "VULNERABLE");
});

// --- runtime jvm (Spring) additions: optional, additive, version stays 1

import { springRaw } from "./helpers/spring-config.js";
import { actionOf, dbImageOf, routeParams } from "../src/config.js";

test("jvm config: valid, with documented defaults", () => {
  const cfg = parseConfig(springRaw());
  assert.equal(cfg.version, 1);
  assert.equal(cfg.target.runtime, "jvm");
  assert.deepEqual(cfg.db, {
    kind: "postgres", migrations: "flyway",
    env: { url: "SPRING_DATASOURCE_URL", user: "SPRING_DATASOURCE_USERNAME", password: "SPRING_DATASOURCE_PASSWORD" },
  });
  assert.deepEqual(cfg.auth!.env, {
    jwkSetUri: "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI",
    issuerUri: "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI",
  });
  assert.deepEqual(cfg.auth!.claims.roles, { claim: "roles" });
  const minimal = parseConfig({ ...springRaw(), db: { kind: "postgres" }, auth: { type: "jwt-issuer" } });
  assert.equal(minimal.db!.migrations, "app");
  assert.equal(minimal.auth!.claims.subject, "id");
  assert.equal(dbImageOf(minimal), "postgres:16-alpine");
  const viaContainer = parseConfig({ ...springRaw(), db: { kind: "postgres" }, target: { ...springRaw().target, container: { dbImage: "postgres:17" } } });
  assert.equal(dbImageOf(viaContainer), "postgres:17");
  assert.equal(dbImageOf(parseConfig({ ...springRaw(), db: { kind: "postgres", image: "postgres:15" }, target: { ...springRaw().target, container: { dbImage: "postgres:17" } } })), "postgres:15");
});

test("legacy configs are unchanged: runtime node, no db/auth, bearer personas", () => {
  const cfg = loadConfig("examples/argos.config.yaml");
  assert.equal(cfg.target.runtime, "node");
  assert.equal(cfg.db, undefined);
  assert.equal(cfg.auth, undefined);
  assert.deepEqual(Object.keys(cfg.target.container).sort(), ["cpus", "memory", "pids"]);
});

test("jvm config: rule violations name the field", () => {
  const bad = (mut: (r: any) => void, re: RegExp) => {
    const r = springRaw();
    mut(r);
    assert.throws(() => parseConfig(r), re);
  };
  bad((r) => delete r.auth, /personas\.0\.auth: auth\.type "jwt" needs the top-level `auth` section/);
  bad((r) => (r.personas[0].auth = { type: "bearer", token: "x" }, r.personas[0].invalid = "expired"), /personas\.0\.invalid: only valid with auth\.type "jwt"/);
  bad((r) => (r.target.runtime = "node"), /db: requires target\.runtime: jvm|auth: requires/);
  bad((r) => (r.target.isolation = "process"), /target\.isolation: runtime jvm runs only in containers/);
  bad((r) => (r.resources[3].pathParams.nope = { table: "x" }), /resources\.3\.pathParams\.nope: route has no :nope/);
  bad((r) => (r.seed = { schema: "s.sql", dbPath: "d.db" }), /seed: use either seed/);
  bad((r) => (r.personas[2].name = "x", r.personas[2].user = undefined, r.personas[1].user = "x"), /duplicate "orgA\/x"/);
  bad((r) => (r.resources[1].owner.scope = "team"), /resources\.1\.owner\.scope/);
  bad((r) => (r.db.migrations = "hibernate"), /db\.migrations/);
});

test("{param} routes count as parameterized; action defaults from the method", () => {
  assert.deepEqual(routeParams("/api/projects/{projectId}/documents/:documentId"), ["projectId", "documentId"]);
  const r = springRaw();
  delete r.resources[2].owner; // GET /api/projects/{projectId} without owner
  assert.throws(() => parseConfig(r), /resources\.2\.owner: required for parameterized GET routes/);
  const cfg = parseConfig(springRaw());
  assert.deepEqual(cfg.resources.map(actionOf), ["read", "read", "read", "read", "update", "read", "create"]);
});

test("report.lang defaults to en, accepts ko, rejects anything else", () => {
  assert.equal(parseConfig(example()).report.lang, "en");
  const ko = example();
  ko.report = { lang: "ko" };
  assert.equal(parseConfig(ko).report.lang, "ko");
  const bad = example();
  bad.report = { lang: "fr" };
  assert.throws(() => parseConfig(bad), /report\.lang/);
});
