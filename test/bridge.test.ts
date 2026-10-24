import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  annotateConfig,
  bridgeFindings,
  extractOwnerTable,
  extractRoute,
  parseArgosApiFindings,
  renderDraftConfig,
  type ArgosApiFinding,
} from "../src/bridge.js";
import { loadConfig, parseConfig } from "../src/config.js";
import { parse } from "yaml";

const realFindings = () => parseArgosApiFindings(JSON.parse(readFileSync("test/fixtures/argos-api-findings.json", "utf8")));

test("extractRoute pulls METHOD /path from an express handler quote", () => {
  assert.equal(extractRoute('app.get("/api/datasets/:id", auth, (req, res) => {'), "GET /api/datasets/:id");
  assert.equal(extractRoute("router.post('/api/export', (req,res)=>{})"), "POST /api/export");
  assert.equal(extractRoute("const x = 1;"), null);
});

test("extractOwnerTable reads the table from a SQL quote", () => {
  assert.equal(extractOwnerTable('db.prepare("SELECT * FROM datasets WHERE id = ?")'), "datasets");
  assert.equal(extractOwnerTable("no sql here"), null);
});

test("parseArgosApiFindings accepts both an array and {findings:[]}", () => {
  const arr = [{ id: "F1", category: "API1" }];
  assert.equal(parseArgosApiFindings(arr).length, 1);
  assert.equal(parseArgosApiFindings({ findings: arr }).length, 1);
  assert.throws(() => parseArgosApiFindings({ nope: 1 }));
});

test("bridgeFindings maps real Argos API output to Argos resources and checks", () => {
  const { resources, checks, unmapped } = bridgeFindings(realFindings());
  const routes = resources.map((r) => r.route).sort();
  // The two BOLA routes and the debug route are extractable from the quotes.
  assert.deepEqual(routes, ["GET /api/datasets/:id", "GET /api/vendors/:id", "GET /debug/env"]);
  // API1 -> bola, API5/API9 -> unauth.
  assert.deepEqual(checks, ["bola", "unauth"]);
  // The datasets route inferred its owner table from the SELECT.
  const ds = resources.find((r) => r.route === "GET /api/datasets/:id")!;
  assert.equal(ds.check, "bola");
  assert.equal(ds.ownerTableHint, "datasets");
  assert.ok(ds.from.length >= 1);
  // Nothing in this fixture is an unsupported category, so unmapped is empty.
  assert.deepEqual(unmapped, []);
});

test("bridgeFindings records categories Argos cannot execute as unmapped", () => {
  const findings: ArgosApiFinding[] = [
    { id: "X1", category: "API7", title: "SSRF", evidence: 'app.get("/fetch", (r)=>fetch(r.query.url))' },
  ];
  const { resources, unmapped } = bridgeFindings(findings);
  assert.equal(resources.length, 0);
  assert.equal(unmapped[0]!.id, "X1");
});

test("renderDraftConfig produces YAML that parses and keeps the inferred routes", () => {
  const yaml = renderDraftConfig(bridgeFindings(realFindings()));
  const raw = parse(yaml) as { resources: { route: string }[]; checks: string[] };
  assert.ok(raw.resources.some((r) => r.route === "GET /api/datasets/:id"));
  assert.deepEqual(raw.checks, ["bola", "unauth"]);
  // The draft is structurally valid (placeholders are non-empty), so `argos scan`
  // reaches the boot step and fails there on the TODO start command, not on schema.
  const cfg = parseConfig(raw);
  assert.equal(cfg.resources.find((r) => r.route === "GET /api/datasets/:id")!.owner!.table, "datasets");
});

test("annotateConfig matches findings to the demo config by route", () => {
  const cfg = loadConfig("demo/vendor-platform/argos.config.yaml");
  const { matched, unmatchedFindings } = annotateConfig(cfg, realFindings());
  const ids = matched.map((m) => m.resourceId).sort();
  // Both configured BOLA/secret routes that Argos API flagged should match.
  assert.ok(ids.includes("dataset-read"));
  assert.ok(ids.includes("vendor-profile"));
  // /debug/env is a configured resource too.
  assert.ok(ids.includes("debug-env"));
  // Findings whose route isn't a configured resource are reported, not dropped.
  assert.ok(Array.isArray(unmatchedFindings));
});
