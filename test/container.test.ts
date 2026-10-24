import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseConfig, type Config } from "../src/config.js";
import { containerSpec, defaultImage, dockerStatus, removeStrayContainers } from "../src/container.js";
import { RunnerError, startTarget } from "../src/runner.js";
import { runScan } from "../src/scan.js";
import { ScanMeta } from "../src/types.js";

const docker = dockerStatus();
const skip = docker.ok ? false : `docker not available: ${docker.ok ? "" : docker.reason}`;
const PROBE = resolve("test/fixtures/probe-app");

function cfg(env: Record<string, string> = {}, container: Record<string, unknown> = {}): Config {
  return parseConfig({
    version: 1,
    target: { start: "node app.mjs", cwd: PROBE, readyPath: "/health", env, isolation: "container", container },
    personas: [
      { name: "a", org: "o1", auth: { type: "bearer", token: "t1" } },
      { name: "b", org: "o2", auth: { type: "bearer", token: "t2" } },
      { name: "anon", auth: { type: "none" } },
    ],
    resources: [{ id: "health", route: "GET /health", public: true }],
    checks: ["unauth"],
  });
}

// Node-path containers only: JVM runs (label argos.run=<id>) from test files running in parallel are not ours to count.
const containersLeft = (): string =>
  spawnSync("docker", ["ps", "-a", "--filter", "label=argos=1", "--format", '{{.ID}} {{.Label "argos.run"}}'], { encoding: "utf8" })
    .stdout.split("\n")
    .filter((l) => l.trim() && !l.trim().includes(" "))
    .join("\n")
    .trim();

describe("container isolation", { skip }, () => {
  test("config: container is opt-in, with safe defaults", () => {
    const c = parseConfig({ ...JSON.parse(JSON.stringify({ version: 1, target: { start: "x" } })), personas: cfg().personas, resources: cfg().resources });
    assert.equal(c.target.isolation, "process");
    assert.deepEqual(c.target.container, { memory: "512m", cpus: "1", pids: 256 });
    assert.match(defaultImage(), /^node:\d+-slim$/);
  });

  test("boots in a container and answers through the loopback forwarder", async () => {
    const t = await startTarget(cfg(), { quiet: true });
    try {
      assert.equal(t.isolation, "container");
      assert.equal(t.image, defaultImage());
      assert.match(t.baseUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
      assert.equal((await fetch(t.baseUrl + "/health")).status, 200);
    } finally {
      await t.stop();
    }
  });

  test("the sandbox is real: no network, read-only root, non-root, no capabilities, no host paths, no host env", async () => {
    process.env.ARGOS_HOST_SECRET = "must-not-enter-the-container";
    const t = await startTarget(cfg({ CUSTOM: "yes" }), { quiet: true, extraEnv: { CANARY: "ARGOS_ENV_X_abcdef" } });
    try {
      const p = (await (await fetch(t.baseUrl + "/probe")).json()) as Record<string, any>;
      // network: loopback only, nothing can leave
      assert.deepEqual(p.interfaces, ["lo"]);
      // refused by the sandbox (no route / no resolver), not merely a slow or offline internet
      assert.equal(p.egressIp.ok, false);
      assert.match(p.egressIp.error, /ENETUNREACH|ENETDOWN/, JSON.stringify(p.egressIp));
      assert.equal(p.egressDns.ok, false);
      assert.match(p.egressDns.error, /EAI_AGAIN|ENOTFOUND/, JSON.stringify(p.egressDns));
      // filesystem: root is read-only, /tmp and the throwaway /app copy are writable
      assert.equal(p.writeRoot.ok, false);
      assert.match(p.writeRoot.error, /EROFS|EACCES/);
      assert.equal(p.writeUsr.ok, false);
      assert.equal(p.writeTmp.ok, true);
      assert.equal(p.writeApp.ok, true);
      assert.equal(p.hostPathVisible, false);
      // privileges
      assert.equal(p.uid, process.getuid!());
      assert.notEqual(p.uid, 0);
      assert.equal(p.capEff, "0000000000000000");
      assert.equal(p.noNewPrivs, "1");
      // environment: only what Argos passed, never the host's
      assert.equal(p.env.ARGOS_HOST_SECRET, undefined);
      assert.equal(p.env.CUSTOM, "yes");
      assert.equal(p.env.CANARY, "ARGOS_ENV_X_abcdef");
      assert.match(p.env.PORT, /^\d+$/);
      assert.equal(p.env.HOME, "/tmp");
      assert.ok(!JSON.stringify(p.env).includes(process.env.HOME!), "host home path must not appear");
    } finally {
      delete process.env.ARGOS_HOST_SECRET;
      await t.stop();
    }
  });

  test("runs on a temp copy: the original is untouched and everything is cleaned up", async () => {
    const t = await startTarget(cfg(), { quiet: true });
    await fetch(t.baseUrl + "/probe");
    assert.ok(existsSync(join(t.workdir, "argos-probe.txt")), "the app wrote into its copy");
    assert.ok(!existsSync(join(PROBE, "argos-probe.txt")), "original untouched");
    await t.stop();
    assert.ok(!existsSync(t.workdir), "temp copy removed");
    assert.equal(containersLeft(), "", "container removed");
  });

  test("boot failure reports the container's log tail, not a clean result", async () => {
    await assert.rejects(
      startTarget(cfg({ CRASH: "1" }), { quiet: true }),
      (e: Error) => e instanceof RunnerError && /exited with code 3/.test(e.message) && /boot failed: CRASH set/.test(e.message),
    );
    assert.equal(containersLeft(), "");
  });

  test("an unreachable docker daemon is an error, never a silent fall back to the host", async () => {
    const saved = process.env.DOCKER_HOST;
    process.env.DOCKER_HOST = "unix:///nonexistent/docker.sock";
    try {
      await assert.rejects(startTarget(cfg(), { quiet: true }), (e: Error) => e instanceof RunnerError && /docker is not available/.test(e.message));
    } finally {
      if (saved === undefined) delete process.env.DOCKER_HOST;
      else process.env.DOCKER_HOST = saved;
    }
  });

  test("image, memory and cpus are validated before they reach docker", () => {
    assert.throws(() => containerSpec(cfg({}, { image: "--privileged" })), /invalid image name/);
    assert.throws(() => containerSpec(cfg({}, { image: "node:25 --network host" })), /invalid image name/);
    assert.throws(() => containerSpec(cfg({}, { memory: "lots" })), /memory/);
    assert.throws(() => containerSpec(cfg({}, { cpus: "1; rm -rf /" })), /cpus/);
    assert.equal(containerSpec(cfg({}, { image: "node:25-slim", memory: "256m", cpus: "0.5" })).memory, "256m");
  });

  test("a missing image that cannot be pulled fails clearly", async () => {
    await assert.rejects(
      startTarget(cfg({}, { image: "argos-does-not-exist.invalid/nope:0" }), { quiet: true }),
      (e: Error) => e instanceof RunnerError && /cannot pull image/.test(e.message),
    );
  });

  test("scan gives the same matrix and findings in a container as on the host, and records the isolation", async () => {
    const FX = "test/fixtures/vuln-app";
    const run = (isolation: "process" | "container") =>
      runScan({ configPath: `${FX}/argos.config.yaml`, outDir: mkdtempSync(join(tmpdir(), "argos-iso-")), quiet: true, log: () => {}, isolation });
    const host = await run("process");
    const box = await run("container");
    assert.equal(readFileSync(box.files.matrix, "utf8"), readFileSync(host.files.matrix, "utf8"), "matrix.json");
    assert.equal(readFileSync(box.files.findings, "utf8"), readFileSync(host.files.findings, "utf8"), "findings.json");
    const hm = ScanMeta.parse(host.meta);
    const bm = ScanMeta.parse(box.meta);
    assert.deepEqual([hm.isolation, hm.image], ["process", null]);
    assert.deepEqual([bm.isolation, bm.image], ["container", defaultImage()]);
    assert.equal(containersLeft(), "");
  });

  test("removeStrayContainers cleans up labelled leftover containers and networks", () => {
    // narrowed to this test's label so concurrently running test files keep their stacks
    const label = "argos.stray-test=1";
    spawnSync("docker", ["run", "-d", "--label", "argos=1", "--label", label, "--name", "argos-stray-test", defaultImage(), "sleep", "60"]);
    spawnSync("docker", ["network", "create", "--internal", "--label", "argos=1", "--label", label, "argos-stray-test-net"]);
    assert.ok(containersLeft().length > 0);
    assert.ok(removeStrayContainers(label) >= 2);
    assert.equal(containersLeft(), "");
    assert.equal(spawnSync("docker", ["network", "ls", "-q", "--filter", `label=${label}`], { encoding: "utf8" }).stdout.trim(), "");
  });
});
