import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { fillPath, parseRoute, sendAs } from "../src/http.js";
import { observe, verdictFor, runMatrix, renderMatrixMarkdown } from "../src/matrix.js";
import { allMarkers } from "../src/seed.js";
import { Matrix } from "../src/types.js";

import { parseConfig } from "../src/config.js";
import { app, cfg, manifest, M1 } from "./helpers/fake-app.js";

test("observe: SPEC 6.4 rules", () => {
  const base = { markers: [M1], ownRequest: false };
  assert.equal(observe({ ...base, status: 200, body: `{"name":"${M1}"}` }), "allow");
  assert.equal(observe({ ...base, status: 200, body: "{}" }), "allow-empty");
  assert.equal(observe({ ...base, status: 201, body: M1 }), "allow");
  assert.equal(observe({ ...base, status: 401, body: "" }), "deny");
  assert.equal(observe({ ...base, status: 403, body: "" }), "deny");
  assert.equal(observe({ ...base, status: 404, body: "" }), "deny");
  assert.equal(observe({ ...base, ownRequest: true, status: 404, body: "" }), "error");
  assert.equal(observe({ ...base, status: 500, body: "" }), "error");
  assert.equal(observe({ ...base, status: 302, body: "" }), "error");
  assert.equal(observe({ ...base, status: null, body: "" }), "error");
  assert.equal(observe({ status: 200, body: "x", ownRequest: false }), "allow"); // no row/marker
});

test("observe: scoped list without the other org's marker is deny, not allow-empty", () => {
  const o = { status: 200, body: "[]", markers: [M1], ownRequest: false };
  assert.equal(observe({ ...o, scopedList: true }), "deny");
  assert.equal(observe({ ...o, scopedList: false }), "allow-empty");
  assert.equal(observe({ ...o, scopedList: true, body: `[{"n":"${M1}"}]` }), "allow"); // list leaked the other org's row
});

test("observe: any marker of the org counts (response may come from another table)", () => {
  assert.equal(observe({ status: 200, body: "task ARGOS_task_v1_cccccc", markers: [M1, "ARGOS_task_v1_cccccc"], ownRequest: true }), "allow");
});

test("verdictFor: never reports OK for ambiguous results", () => {
  assert.equal(verdictFor("deny", "allow"), "VULNERABLE");
  assert.equal(verdictFor("deny", "deny"), "OK");
  assert.equal(verdictFor("deny", "allow-empty"), "SUSPECTED");
  assert.equal(verdictFor("deny", "error"), "SKIPPED");
  assert.equal(verdictFor("allow", "allow"), "OK");
  assert.equal(verdictFor("allow", "deny"), "SUSPECTED");
  assert.equal(verdictFor("allow", "allow-empty"), "SUSPECTED");
  assert.equal(verdictFor("allow", "error"), "SKIPPED");
});

test("http helpers", () => {
  assert.deepEqual(parseRoute("GET /api/datasets/:id"), { method: "GET", path: "/api/datasets/:id", queryNames: [] });
  assert.deepEqual(parseRoute("GET /api/datasets?search="), { method: "GET", path: "/api/datasets", queryNames: ["search"] });
  assert.deepEqual(parseRoute("GET /x?a=1&b="), { method: "GET", path: "/x", queryNames: ["a", "b"] });
  assert.equal(fillPath("/api/datasets/:id", 7), "/api/datasets/7");
  assert.equal(fillPath("/a/:x/b/:y", "q r"), "/a/q%20r/b/q%20r");
});

const cell = (m: Matrix, persona: string, resource: string, target?: string) =>
  m.cells.find((c) => c.persona === persona && c.resource === resource && c.target === target)!;

test("vulnerable app: cross-vendor read and unauth export are red, controls stay green", async () => {
  const srv = await app({ checkOwner: false, exportNeedsAuth: false });
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const m = await runMatrix(cfg(), base, manifest);
    Matrix.parse(m); // matches the shared contract

    const own = cell(m, "vendor1", "dataset-read", "v1");
    assert.deepEqual([own.expected, own.observed, own.verdict], ["allow", "allow", "OK"]);

    const cross = cell(m, "vendor2", "dataset-read", "v1");
    assert.deepEqual([cross.expected, cross.observed, cross.verdict], ["deny", "allow", "VULNERABLE"]);
    assert.equal(cross.evidence.request, "GET /api/datasets/1");
    assert.equal(cross.evidence.marker, "ARGOS_");

    assert.equal(cell(m, "anonymous", "dataset-read", "v1").verdict, "OK"); // 401
    assert.equal(cell(m, "anonymous", "export").verdict, "VULNERABLE"); // no-row resource: 2xx on a denied cell is red
    assert.equal(cell(m, "vendor1", "export").verdict, "OK");
    assert.equal(cell(m, "anonymous", "health").verdict, "OK");
    assert.equal(cell(m, "vendor1", "danger").verdict, "SKIPPED"); // not safe: true
  } finally {
    srv.close();
  }
});

test("fixed app: no red cells", async () => {
  const srv = await app({ checkOwner: true, exportNeedsAuth: true });
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const m = await runMatrix(cfg(), base, manifest);
    assert.equal(m.cells.filter((c) => c.verdict === "VULNERABLE").length, 0);
    assert.equal(cell(m, "vendor2", "dataset-read", "v1").verdict, "OK");
    assert.equal(cell(m, "anonymous", "export").verdict, "OK");
  } finally {
    srv.close();
  }
});

test("unreachable target yields SKIPPED, never OK", async () => {
  const m = await runMatrix(cfg(), "http://127.0.0.1:1", manifest, { timeoutMs: 500 });
  const reqs = m.cells.filter((c) => c.resource !== "danger");
  assert.ok(reqs.every((c) => c.verdict === "SKIPPED" && c.observed === "error"));
});

test("evidence and rendered table never contain a full marker", async () => {
  const srv = await app({ checkOwner: false, exportNeedsAuth: true });
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    const m = await runMatrix(cfg(), base, manifest);
    const dump = JSON.stringify(m) + renderMatrixMarkdown(m);
    for (const marker of allMarkers(manifest)) assert.ok(!dump.includes(marker), `leaked ${marker}`);
    const md = renderMatrixMarkdown(m);
    assert.match(md, /\| vendor2 → v1 \| 🔴 deny\/allow \|/);
    assert.match(md, /dataset-read/);
  } finally {
    srv.close();
  }
});

test("sendAs reports connection errors instead of throwing", async () => {
  const r = await sendAs("http://127.0.0.1:1", { name: "a", auth: { type: "none" } }, "GET", "/x", { timeoutMs: 300 });
  assert.equal(r.status, null);
  assert.ok(r.error);
});

test("evidence withholds the body of a response that dumps the environment", async () => {
  const { createServer } = await import("node:http");
  const canary = "ARGOS_ENV_JWT_SECRET_abcdef";
  const srv = createServer((_req, res) => void res.end(JSON.stringify({ PATH: "/Users/someone/bin", JWT_SECRET: canary })));
  await new Promise<void>((ok) => srv.listen(0, "127.0.0.1", ok));
  try {
    const c = parseConfig({
      version: 1, target: { start: "x" },
      personas: [
        { name: "a", org: "o1", auth: { type: "bearer", token: "t1" } },
        { name: "b", org: "o2", auth: { type: "bearer", token: "t2" } },
        { name: "anon", auth: { type: "none" } },
      ],
      resources: [{ id: "debug-env", route: "GET /debug/env", expect: { owner: "deny", other: "deny", anonymous: "deny" } }],
      checks: ["unauth"],
    });
    const m = await runMatrix(c, `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, { markers: {}, secrets: [], ids: {}, envCanaries: [{ name: "JWT_SECRET", marker: canary }] });
    const dump = JSON.stringify(m);
    assert.ok(!dump.includes("/Users/someone"), "host path must not reach the matrix");
    assert.ok(!dump.includes(canary));
    assert.match(m.cells[0]!.evidence.note!, /body withheld/);
  } finally {
    srv.close();
  }
});
