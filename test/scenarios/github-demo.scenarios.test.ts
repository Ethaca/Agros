/**
 * GitHub Actions demo (plugins/argos, the `/argos:demo` plugin): the template repo must stay clean, the Node demo PR (patches/node.patch) must
 * turn red on exactly its two planted flaws, and the verified fix must close both. Guards the story the demo tells.
 * The template has no dependencies, so this runs without `npm install`. Process isolation: the template is ours.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ROOT, cli, isRed, scan } from "./helpers.js";

const DEMO = join(ROOT, "plugins", "argos");

function template(): string {
  const dir = mkdtempSync(join(tmpdir(), "argos-scn-gh-demo-"));
  cpSync(join(DEMO, "template", "node"), dir, { recursive: true });
  return dir;
}

function demoPr(): string {
  const dir = template();
  const r = spawnSync("git", ["apply", join(DEMO, "patches", "node.patch")], { cwd: dir, encoding: "utf8" });
  assert.equal(r.status, 0, `patches/node.patch no longer applies to the template: ${r.stderr}`);
  return dir;
}

const PROC = ["--isolation", "process"];

describe("github actions demo", () => {
  it("the template (main) has no red, yellow or skipped finding", () => {
    const r = scan(join(template(), "argos.config.yaml"), PROC);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual([r.counts.VULNERABLE, r.counts.SUSPECTED, r.counts.SKIPPED], [0, 0, 0]);
  });

  it("the demo PR is red on exactly its two flaws: cross-vendor dataset read and the API key in the profile", () => {
    const r = scan(join(demoPr(), "argos.config.yaml"), PROC);
    assert.equal(r.status, 0, r.stderr);
    const red = r.findings.filter(isRed);
    assert.ok(red.some((f) => f.check === "bola" && f.resourceId === "dataset-read"), "BOLA on dataset-read");
    assert.ok(red.some((f) => f.check === "secrets" && f.resourceId === "vendor-profile" && f.column === "vendors.api_key"), "api_key leak");
    assert.deepEqual([...new Set(red.map((f) => f.resourceId))].sort(), ["dataset-read", "vendor-profile"]);
    assert.equal(r.counts.SKIPPED, 0);
  });

  it("the verified fix closes both flaws", () => {
    const dir = demoPr();
    const cfg = join(dir, "argos.config.yaml");
    const f = cli(["fix", "--config", cfg, "--out", join(dir, "o"), "--apply", ...PROC]);
    assert.equal(f.status, 0, f.stderr);
    const after = scan(cfg, PROC);
    assert.equal(after.counts.VULNERABLE, 0, after.findings.filter(isRed).map((x) => x.detail).join("\n"));
  });
});
