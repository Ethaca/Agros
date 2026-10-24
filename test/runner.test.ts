import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { parseConfig, type Config } from "../src/config.js";
import { startTarget, RunnerError } from "../src/runner.js";

const FIXTURE = resolve("test/fixtures/basic-app");

function cfg(env: Record<string, string> = {}, extra: Record<string, unknown> = {}): Config {
  return parseConfig({
    version: 1,
    target: { start: "node app.mjs", cwd: FIXTURE, readyPath: "/health", env, ...extra },
    personas: [
      { name: "a", org: "o1", auth: { type: "bearer", token: "t1" } },
      { name: "b", org: "o2", auth: { type: "bearer", token: "t2" } },
      { name: "anon", auth: { type: "none" } },
    ],
    resources: [{ id: "health", route: "GET /health", public: true }],
    checks: ["unauth"],
  });
}

test("boots target on a free port and waits until ready", async () => {
  const t = await startTarget(cfg(), { quiet: true });
  try {
    assert.match(t.baseUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.notEqual(t.port, 0);
    assert.equal((await fetch(t.baseUrl + "/health")).status, 200);
  } finally {
    await t.stop();
  }
});

test("waits through 503 until health returns 200", async () => {
  const t = await startTarget(cfg({ READY_DELAY_MS: "600" }), { quiet: true });
  try {
    assert.equal((await fetch(t.baseUrl + "/health")).status, 200);
  } finally {
    await t.stop();
  }
});

test("parent env is not forwarded; only PATH/HOME/PORT/target.env", async () => {
  process.env.ARGOS_PARENT_SECRET = "leak-me";
  const t = await startTarget(cfg({ CUSTOM: "yes" }), { quiet: true });
  try {
    const env = (await (await fetch(t.baseUrl + "/env")).json()) as Record<string, string>;
    assert.equal(env.ARGOS_PARENT_SECRET, undefined);
    assert.equal(env.CUSTOM, "yes");
    assert.equal(env.PORT, String(t.port));
    assert.notEqual(env.HOME, process.env.HOME);
  } finally {
    delete process.env.ARGOS_PARENT_SECRET;
    await t.stop();
  }
});

test("runs in a temp copy; original dir untouched", async () => {
  const t = await startTarget(cfg(), { quiet: true });
  try {
    await fetch(t.baseUrl + "/write");
    assert.ok(existsSync(resolve(t.workdir, "written.txt")));
    assert.ok(!existsSync(resolve(FIXTURE, "written.txt")));
  } finally {
    await t.stop();
  }
  assert.ok(!existsSync(t.workdir), "temp copy removed after stop");
});

test("boot failure throws RunnerError with log tail, not a silent pass", async () => {
  await assert.rejects(
    startTarget(cfg({ CRASH: "1" }), { quiet: true }),
    (e: Error) => e instanceof RunnerError && /exited with code 3/.test(e.message) && /boot failed: CRASH set/.test(e.message),
  );
});

test("never-ready target times out", async () => {
  await assert.rejects(
    startTarget(cfg({ READY_DELAY_MS: "60000" }), { quiet: true, readyTimeoutMs: 800 }),
    (e: Error) => e instanceof RunnerError && /not ready/.test(e.message),
  );
});

test("stop() terminates the process", async () => {
  const t = await startTarget(cfg(), { quiet: true });
  await t.stop();
  await assert.rejects(fetch(t.baseUrl + "/health", { signal: AbortSignal.timeout(1000) }));
});

test("extraEnv (env canaries) reaches the app and overrides nothing else", async () => {
  const t = await startTarget(cfg({ CUSTOM: "yes" }), { quiet: true, extraEnv: { JWT_SECRET: "ARGOS_ENV_JWT_SECRET_abcdef" } });
  try {
    const env = (await (await fetch(t.baseUrl + "/env")).json()) as Record<string, string>;
    assert.equal(env.JWT_SECRET, "ARGOS_ENV_JWT_SECRET_abcdef");
    assert.equal(env.CUSTOM, "yes");
  } finally {
    await t.stop();
  }
});
