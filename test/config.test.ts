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
