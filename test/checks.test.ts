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
