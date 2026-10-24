import { test } from "node:test";
import assert from "node:assert/strict";
import { parseConfig } from "../src/config.js";
import { secrets } from "../src/checks/secrets.js";
import type { HttpResult } from "../src/http.js";
import type { SeedManifest } from "../src/seed.js";
import type { Matrix } from "../src/types.js";

const KEY_V1 = "ARGOS_SECRET_1_aaaaaa";
const manifest: SeedManifest = {
  markers: {},
  ids: {},
  secrets: [{ table: "vendors", column: "api_key", org: "v1", marker: KEY_V1 }],
};
const base = {
  version: 1,
  target: { start: "x" },
  personas: [
    { name: "vendor1", org: "v1", auth: { type: "bearer", token: "a" } },
    { name: "vendor2", org: "v2", auth: { type: "bearer", token: "b" } },
    { name: "anonymous", auth: { type: "none" } },
  ],
  resources: [{ id: "vendor-read", route: "GET /v/:id", owner: { table: "vendors", column: "id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } }],
};
const cell = (persona: string) => ({
  persona, resource: "vendor-read", expected: "allow" as const, observed: "allow" as const, verdict: "OK" as const,
  evidence: { request: "GET /v/v1", status: 200 },
});
const res = (body: string, headers: Record<string, string> = {}, status = 200): HttpResult => ({ request: "GET /v/v1", status, body, headers });
const matrix = (...p: string[]): Matrix => ({ personas: p, resources: ["vendor-read"], cells: p.map(cell) });

test("non-owner and anonymous leaks are red, owner is yellow", () => {
  const cfg = parseConfig(base);
  const f = secrets(cfg, matrix("vendor1", "vendor2", "anonymous"), [res(KEY_V1), res(KEY_V1), res(KEY_V1)], manifest);
  const by = Object.fromEntries(f.map((x) => [x.persona, x.verdict]));
  assert.deepEqual(by, { vendor1: "SUSPECTED", vendor2: "VULNERABLE", anonymous: "VULNERABLE" });
  assert.ok(f.every((x) => x.proof.marker === "ARGOS_" && x.column === "vendors.api_key"));
});

test("allowOwnerSecretRead silences the owner but not others", () => {
  const cfg = parseConfig({ ...base, secrets: { allowOwnerSecretRead: true } });
  const f = secrets(cfg, matrix("vendor1", "vendor2"), [res(KEY_V1), res(KEY_V1)], manifest);
  assert.deepEqual(f.map((x) => x.persona), ["vendor2"]);
});

test("leak in a response header is found", () => {
  const cfg = parseConfig(base);
  const f = secrets(cfg, matrix("vendor2"), [res("{}", { "x-debug": KEY_V1 })], manifest);
  assert.equal(f[0]!.verdict, "VULNERABLE");
});

test("leak on an error response still counts", () => {
  const cfg = parseConfig(base);
  const f = secrets(cfg, matrix("vendor2"), [res(`boom ${KEY_V1}`, {}, 500)], manifest);
  assert.equal(f[0]!.verdict, "VULNERABLE");
});

test("OK only when the resource answered 2xx; otherwise SKIPPED", () => {
  const cfg = parseConfig(base);
  assert.equal(secrets(cfg, matrix("vendor1"), [res("{}")], manifest)[0]!.verdict, "OK");
  // owner got 403 where allow was expected -> not conclusive
  const bad = matrix("vendor1");
  Object.assign(bad.cells[0]!, { observed: "deny", verdict: "SUSPECTED" });
  assert.equal(secrets(cfg, bad, [res("", {}, 403)], manifest)[0]!.verdict, "SKIPPED");
  // everyone denied exactly as expected -> nothing to leak
  const denied = matrix("vendor2");
  Object.assign(denied.cells[0]!, { expected: "deny", observed: "deny", verdict: "OK" });
  assert.equal(secrets(cfg, denied, [res("", {}, 403)], manifest)[0]!.verdict, "OK");
  assert.equal(secrets(cfg, matrix("vendor1"), [undefined], manifest)[0]!.verdict, "SKIPPED");
});

test("no seeded secrets -> SKIPPED, never a silent pass", () => {
  const cfg = parseConfig(base);
  const f = secrets(cfg, matrix("vendor1"), [res("{}")], { markers: {}, ids: {}, secrets: [] });
  assert.equal(f.length, 1);
  assert.equal(f[0]!.verdict, "SKIPPED");
});

test("env canaries: leaked value is red with env name, no leak is OK, nothing answered is SKIPPED", () => {
  const cfg = parseConfig(base);
  const withEnv: SeedManifest = { ...manifest, envCanaries: [{ name: "JWT_SECRET", marker: "ARGOS_ENV_JWT_SECRET_abcdef" }] };
  const leak = secrets(cfg, matrix("vendor1"), [res(JSON.stringify({ JWT_SECRET: "ARGOS_ENV_JWT_SECRET_abcdef" }))], withEnv).filter((f) => f.env);
  assert.equal(leak.length, 1);
  assert.equal(leak[0]!.verdict, "VULNERABLE");
  assert.equal(leak[0]!.env, "JWT_SECRET");
  assert.equal(leak[0]!.proof.marker, "ARGOS_");
  const clean = secrets(cfg, matrix("vendor1"), [res("{}")], withEnv).find((f) => f.resourceId === "(env)")!;
  assert.equal(clean.verdict, "OK");
  const dead = secrets(cfg, matrix("vendor1"), [undefined], withEnv).find((f) => f.resourceId === "(env)")!;
  assert.equal(dead.verdict, "SKIPPED");
});
