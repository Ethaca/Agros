import { test } from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";

for (const app of ["vendor-platform", "clean"]) {
  test(`demo/${app}/argos.config.yaml passes the Config schema`, () => {
    const cfg = loadConfig(`demo/${app}/argos.config.yaml`);
    assert.deepEqual(cfg.personas.map((p) => p.name), ["vendor1", "vendor2", "vendor3", "anonymous"]);
    assert.ok(cfg.resources.some((r) => r.id === "dataset-read"));
  });
}

test("both demo configs test the same resources", () => {
  const ids = (app: string) => loadConfig(`demo/${app}/argos.config.yaml`).resources.map((r) => r.id);
  assert.deepEqual(ids("vendor-platform"), ids("clean"));
});
