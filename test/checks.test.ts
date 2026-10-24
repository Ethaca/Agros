import { test } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { runMatrix } from "../src/matrix.js";
import { bola } from "../src/checks/bola.js";
import { unauth } from "../src/checks/unauth.js";
import { runMatrixChecks } from "../src/checks/index.js";
import { allMarkers } from "../src/seed.js";
import { Finding, type Matrix } from "../src/types.js";
import { app, cfg, manifest } from "./helpers/fake-app.js";

async function scan(opts: { checkOwner: boolean; exportNeedsAuth: boolean }) {
  const srv = await app(opts);
  try {
    const matrix = await runMatrix(cfg(), `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, manifest);
    return matrix;
  } finally {
    srv.close();
  }
}

const f = (fs: ReturnType<typeof bola>, persona: string, resource: string) =>
  fs.find((x) => x.persona === persona && x.resourceId === resource);

test("bola: cross-vendor read is red, with controls proven", async () => {
  const m = await scan({ checkOwner: false, exportNeedsAuth: true });
  const fs = bola(cfg(), m);
  fs.forEach((x) => Finding.parse(x));
  assert.equal(fs.length, 2); // vendor1->v2 and vendor2->v1
  assert.ok(fs.every((x) => x.verdict === "VULNERABLE" && x.check === "bola"));
  assert.match(f(fs, "vendor2", "dataset-read")!.detail, /vendor2 read v1's data/);
});

test("bola: fixed app is OK on every cross cell, no extra findings", async () => {
  const m = await scan({ checkOwner: true, exportNeedsAuth: true });
  const fs = bola(cfg(), m);
  assert.equal(fs.length, 2);
  assert.ok(fs.every((x) => x.verdict === "OK"));
});

test("bola: only resources with seeded rows are in scope (export, health excluded)", async () => {
  const m = await scan({ checkOwner: false, exportNeedsAuth: true });
  assert.ok(bola(cfg(), m).every((x) => x.resourceId === "dataset-read"));
});

test("unauth: anonymous export is red; protected and public resources are not", async () => {
  const m = await scan({ checkOwner: true, exportNeedsAuth: false });
  const fs = unauth(cfg(), m);
  assert.equal(f(fs, "anonymous", "export")!.verdict, "VULNERABLE");
  assert.equal(f(fs, "anonymous", "dataset-read")!.verdict, "OK");
  assert.ok(!fs.some((x) => x.resourceId === "health"), "public: true is excluded");
});

test("unauth: fixed app is OK", async () => {
  const m = await scan({ checkOwner: true, exportNeedsAuth: true });
  const fs = unauth(cfg(), m);
  assert.ok(fs.filter((x) => x.resourceId !== "danger").every((x) => x.verdict === "OK"));
  assert.equal(f(fs, "anonymous", "danger")!.verdict, "SKIPPED"); // not marked safe: true
});

test("dead app: every finding is SKIPPED, never OK (control rule)", async () => {
  const m = await runMatrix(cfg(), "http://127.0.0.1:1", manifest, { timeoutMs: 400 });
  const fs = runMatrixChecks(cfg(), m);
  assert.ok(fs.length > 0);
  assert.ok(fs.every((x) => x.verdict === "SKIPPED"), JSON.stringify(fs.map((x) => x.verdict)));
});

test("bad attacker token: 401 must not read as 'secure'", async () => {
  const m = await scan({ checkOwner: false, exportNeedsAuth: true });
  // simulate vendor2's own-row control failing (e.g. expired token): cross cell looks denied
  const broken: Matrix = structuredClone(m);
  const own = broken.cells.find((c) => c.persona === "vendor2" && c.target === "v2" && c.resource === "dataset-read")!;
  Object.assign(own, { observed: "deny", verdict: "SUSPECTED" });
  const cross = broken.cells.find((c) => c.persona === "vendor2" && c.target === "v1" && c.resource === "dataset-read")!;
  Object.assign(cross, { observed: "deny", verdict: "OK" });

  const fs = bola(cfg(), broken);
  assert.equal(f(fs.filter((x) => /control failed/.test(x.detail)), "vendor2", "dataset-read")!.verdict, "SUSPECTED");
  const crossF = fs.find((x) => x.persona === "vendor2" && /did not succeed/.test(x.detail))!;
  assert.equal(crossF.verdict, "SKIPPED");
});

test("runMatrixChecks respects cfg.checks and findings carry no full markers", async () => {
  const m = await scan({ checkOwner: false, exportNeedsAuth: false });
  const only = { ...cfg(), checks: ["unauth" as const] };
  assert.ok(runMatrixChecks(only, m).every((x) => x.check === "unauth"));
  const dump = JSON.stringify(runMatrixChecks(cfg(), m));
  for (const marker of allMarkers(manifest)) assert.ok(!dump.includes(marker));
  assert.ok(runMatrixChecks(cfg(), m).some((x) => x.check === "bola"));
});

import { sqli } from "../src/checks/sqli.js";
import { createServer } from "node:http";

function sqliApp(mode: "vuln" | "safe" | "crash" | "down-control"): Promise<import("node:http").Server> {
  return new Promise((ok) => {
    const srv = createServer((req, res) => {
      const q = new URL(req.url!, "http://x").searchParams.get("search") ?? "";
      if (mode === "down-control") return void res.writeHead(503).end();
      if (mode === "crash") return void res.writeHead(500).end();
      if (mode === "vuln" && (q.match(/'/g) ?? []).length % 2 === 1) return void res.writeHead(500).end();
      res.end("[]");
    }).listen(0, "127.0.0.1", () => ok(srv));
  });
}
const sqliCfg = () => ({ ...cfg(), resources: [{ id: "search", route: "GET /api/search", params: ["search"], expect: { owner: "allow" as const, other: "deny" as const, anonymous: "deny" as const } }] });
async function runSqli(mode: Parameters<typeof sqliApp>[0]) {
  const srv = await sqliApp(mode);
  try {
    return await sqli(sqliCfg(), `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, manifest);
  } finally {
    srv.close();
  }
}

test("sqli: odd quote -> 500, escaped -> 200 is red", async () => {
  const f = (await runSqli("vuln"))[0]!;
  assert.equal(f.verdict, "VULNERABLE");
  assert.match(f.proof.note!, /control 200 \/ ' 500 \/ '' 200/);
});

test("sqli: app that handles quotes is OK", async () => {
  assert.equal((await runSqli("safe"))[0]!.verdict, "OK");
});

test("sqli: 500 on everything (even the control) is SKIPPED, not red", async () => {
  assert.equal((await runSqli("crash"))[0]!.verdict, "SKIPPED");
  assert.equal((await runSqli("down-control"))[0]!.verdict, "SKIPPED");
});

test("sqli: only resources with params are tested", async () => {
  const f = await sqli(cfg(), "http://127.0.0.1:1", manifest);
  assert.deepEqual(f, []);
});

test("a proven leak is reported red even without a working control (no legit access exists)", () => {
  const m: Matrix = {
    personas: ["anonymous"], resources: ["debug-env"],
    cells: [{ persona: "anonymous", resource: "debug-env", expected: "deny", observed: "allow", verdict: "VULNERABLE", evidence: { request: "GET /debug/env", status: 200 } }],
  };
  const c = { ...cfg(), resources: [{ id: "debug-env", route: "GET /debug/env", expect: { owner: "deny" as const, other: "deny" as const, anonymous: "deny" as const } }] };
  assert.equal(unauth(c, m)[0]!.verdict, "VULNERABLE");
});

test("sqli reads the parameter from the route's query string", async () => {
  const srv = await sqliApp("vuln");
  try {
    const c = { ...cfg(), resources: [{ id: "search", route: "GET /api/search?search=", expect: { owner: "allow" as const, other: "deny" as const, anonymous: "deny" as const } }] };
    const f = await sqli(c, `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, manifest);
    assert.equal(f[0]!.verdict, "VULNERABLE");
  } finally {
    srv.close();
  }
});
