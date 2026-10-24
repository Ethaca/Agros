/**
 * The `argos` plugin (plugins/argos) bundles copies so it works outside this repository. Guard them against drift:
 *   template/spring + patches/spring.patch  ==  test/fixtures/spring/gradle-app  ->  demo/spring-workspace
 * (the Spring engine tests and `pnpm demo:spring` cover those originals with real Docker runs).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const PLUGIN = resolve("plugins/argos");
const diffTree = (a: string, b: string) => spawnSync("diff", ["-r", a, b], { encoding: "utf8" });

test("Spring template is the safe fixture app", () => {
  const r = diffTree(resolve("test/fixtures/spring/gradle-app"), join(PLUGIN, "template/spring"));
  assert.equal(r.status, 0, `plugins/argos/template/spring drifted from test/fixtures/spring/gradle-app:\n${r.stdout}`);
});

test("Spring demo PR turns the template into demo/spring-workspace (three planted flaws)", () => {
  const dir = mkdtempSync(join(tmpdir(), "argos-plugin-spring-"));
  cpSync(join(PLUGIN, "template/spring"), dir, { recursive: true });
  execFileSync("git", ["apply", join(PLUGIN, "patches/spring.patch")], { cwd: dir });
  const r = diffTree(resolve("demo/spring-workspace/src"), join(dir, "src"));
  assert.equal(r.status, 0, `patches/spring.patch no longer reproduces demo/spring-workspace:\n${r.stdout}`);
});

test("Spring template ships no Argos config (the demo shows zero-config CI)", () => {
  assert.throws(() => readFileSync(join(PLUGIN, "template/spring/argos.config.yaml")));
});

test("plugin manifest and marketplace entry agree", () => {
  const plugin = JSON.parse(readFileSync(join(PLUGIN, ".claude-plugin/plugin.json"), "utf8"));
  const market = JSON.parse(readFileSync(resolve(".claude-plugin/marketplace.json"), "utf8"));
  const entry = market.plugins.find((p: { name: string }) => p.name === plugin.name);
  assert.ok(entry, "marketplace lists the plugin");
  assert.equal(resolve(entry.source), PLUGIN);
});
