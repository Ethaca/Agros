import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { Finding, Matrix, ScanMeta } from "../src/types.js";

const read = (f: string) => readFileSync(`examples/out/${f}`, "utf8");
const sha = (t: string) => createHash("sha256").update(t).digest("hex");

test("examples/out files satisfy the shared contracts", () => {
  const matrix = Matrix.parse(JSON.parse(read("matrix.json")));
  const findings = (JSON.parse(read("findings.json")) as unknown[]).map((f) => Finding.parse(f));
  const meta = ScanMeta.parse(JSON.parse(read("scan-meta.json")));
  assert.equal(meta.results.cells, matrix.cells.length);
  assert.equal(meta.results.findings, findings.length);
  for (const v of ["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"] as const) {
    assert.equal(meta.results.counts[v], findings.filter((f) => f.verdict === v).length, v);
  }
  assert.deepEqual(meta.personas.map((p) => p.name), matrix.personas);
  assert.deepEqual(meta.resources.map((r) => r.id), matrix.resources);
});

test("scan-meta hashes match the example files byte for byte", () => {
  const meta = ScanMeta.parse(JSON.parse(read("scan-meta.json")));
  assert.equal(meta.files.matrix.sha256, sha(read("matrix.json")));
  assert.equal(meta.files.findings.sha256, sha(read("findings.json")));
  assert.equal(meta.config.sha256, sha(readFileSync("demo/vendor-platform/argos.config.yaml", "utf8")), "example config hash is current");
  assert.equal(meta.seed?.schema.sha256, sha(readFileSync("demo/vendor-platform/schema.sql", "utf8")), "example schema hash is current");
});

test("examples carry no full marker, host path, or environment value", () => {
  const all = ["matrix.json", "findings.json", "scan-meta.json"].map(read).join("\n");
  assert.ok(!/ARGOS_SECRET_\d+_[0-9a-f]{6}/.test(all));
  assert.ok(!/ARGOS_ENV_[A-Z0-9_]+_[0-9a-f]{6}/.test(all));
  assert.ok(!/ARGOS_[A-Za-z0-9-]+_v\d_[0-9a-f]{6}/.test(all));
  assert.ok(!all.includes(homedir()), "no home directory path");
  assert.ok(!/"PATH"|\/Users\/|\/home\//.test(all), "no environment dump or absolute paths");
});
