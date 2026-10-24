import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { parseConfig, type Config } from "../src/config.js";
import {
  seedDatabase, SeedError, maskMarker, redact, allMarkers, hashConfigText, isSensitiveColumn,
} from "../src/seed.js";

function cfg(over: Record<string, unknown> = {}): Config {
  return parseConfig({
    version: 1,
    target: { start: "node app.mjs" },
    seed: { schema: "schema.sql", dbPath: "./data.db" },
    personas: [
      { name: "vendor1", org: "v1", auth: { type: "bearer", token: "t1" } },
      { name: "vendor2", org: "v2", auth: { type: "bearer", token: "t2" } },
      { name: "anonymous", auth: { type: "none" } },
    ],
    resources: [
      { id: "dataset-read", route: "GET /api/datasets/:id", owner: { table: "datasets", column: "vendor_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "dataset-list", route: "GET /api/datasets", owner: { table: "datasets", column: "vendor_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "vendor-read", route: "GET /api/vendors/:id", owner: { table: "vendors", column: "id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "health", route: "GET /health", public: true },
    ],
    ...over,
  });
}

function workdir(): string {
  const d = mkdtempSync(join(tmpdir(), "argos-seed-test-"));
  cpSync(resolve("test/fixtures/seed-app"), d, { recursive: true });
  return d;
}

test("seeds one row per (owner table, org) with markers", () => {
  const wd = workdir();
  const m = seedDatabase(cfg(), { workdir: wd, seedKey: "k" });
  const db = new DatabaseSync(join(wd, "data.db"));
  const rows = db.prepare("SELECT vendor_id, name, rows FROM datasets ORDER BY vendor_id").all() as any[];
  assert.equal(rows.length, 2);
  assert.equal(rows[0].name, m.markers["dataset-read"]!.v1);
  assert.equal(rows[1].name, m.markers["dataset-read"]!.v2);
  assert.equal(rows[0].rows, 1);
  assert.match(rows[0].name, /^ARGOS_dataset-read_v1_[0-9a-f]{6}$/);
  // resources sharing a table share the marker
  assert.equal(m.markers["dataset-list"]!.v1, m.markers["dataset-read"]!.v1);
  db.close();
});

test("sensitive columns get secret markers, non-owner text gets owner marker", () => {
  const wd = workdir();
  const m = seedDatabase(cfg(), { workdir: wd, seedKey: "k" });
  const db = new DatabaseSync(join(wd, "data.db"));
  const v = db.prepare("SELECT id, name, api_key FROM vendors WHERE id = 'v1'").get() as any;
  assert.match(v.api_key, /^ARGOS_SECRET_\d+_[0-9a-f]{6}$/);
  assert.match(v.name, /^ARGOS_vendor-read_v1_/);
  assert.equal(m.secrets.length, 2);
  assert.deepEqual(m.secrets.map((s) => [s.table, s.column, s.org]), [["vendors", "api_key", "v1"], ["vendors", "api_key", "v2"]]);
  db.close();
});

test("deterministic for the same seedKey, different for another", () => {
  const a = seedDatabase(cfg(), { workdir: workdir(), seedKey: hashConfigText("cfg") });
  const b = seedDatabase(cfg(), { workdir: workdir(), seedKey: hashConfigText("cfg") });
  const c = seedDatabase(cfg(), { workdir: workdir(), seedKey: hashConfigText("other") });
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
});

test("re-seeding the same workdir starts from a fresh DB", () => {
  const wd = workdir();
  seedDatabase(cfg(), { workdir: wd, seedKey: "k" });
  seedDatabase(cfg(), { workdir: wd, seedKey: "k" });
  const db = new DatabaseSync(join(wd, "data.db"));
  assert.equal((db.prepare("SELECT count(*) AS n FROM datasets").get() as any).n, 2);
  db.close();
});

test("mask keeps only the first 6 chars; redact strips full markers", () => {
  const m = seedDatabase(cfg(), { workdir: workdir(), seedKey: "k" });
  const full = m.secrets[0]!.marker;
  assert.equal(maskMarker(full), "ARGOS_");
  const out = redact(`leaked ${full} and ${m.markers["dataset-read"]!.v1}`, m);
  for (const marker of allMarkers(m)) assert.ok(!out.includes(marker), "no full marker survives redact");
  assert.match(out, /ARGOS_…/);
});

test("clear errors: missing table, bad owner column, escape, seed.rows, no seed", () => {
  const wd = workdir();
  const missingTable = cfg({ resources: [{ id: "x", route: "GET /x/:id", owner: { table: "nope", column: "c" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } }] });
  assert.throws(() => seedDatabase(missingTable, { workdir: wd, seedKey: "k" }), /table "nope" not found/);
  const badCol = cfg({ resources: [{ id: "x", route: "GET /x/:id", owner: { table: "datasets", column: "zzz" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } }] });
  assert.throws(() => seedDatabase(badCol, { workdir: wd, seedKey: "k" }), /owner column "datasets.zzz"/);
  assert.throws(() => seedDatabase(cfg({ seed: { schema: "schema.sql", dbPath: "../escape.db" } }), { workdir: wd, seedKey: "k" }), /escapes the working copy/);
  assert.throws(() => seedDatabase(cfg({ seed: { schema: "schema.sql", dbPath: "./d.db", rows: "seed.json" } }), { workdir: wd, seedKey: "k" }), SeedError);
  assert.throws(() => seedDatabase(cfg({ seed: undefined }), { workdir: wd, seedKey: "k" }), /no `seed` section/);
  assert.ok(!existsSync(join(wd, "..", "escape.db")));
});

test("sensitive column name matching is case-insensitive substring", () => {
  assert.ok(isSensitiveColumn("API_KEY", ["api_key"]));
  assert.ok(isSensitiveColumn("user_password_hash", ["password"]));
  assert.ok(!isSensitiveColumn("name", ["api_key", "token"]));
});
