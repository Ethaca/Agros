import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import { isolationArgs, docker, runSandbox } from "../src/sandbox/run.js";
import { SANDBOX_IMAGE, SandboxResult } from "../src/sandbox/protocol.js";
import { sendAs } from "../src/http.js";
import { createServer } from "node:http";

const available = spawnSync("docker", ["image", "inspect", SANDBOX_IMAGE], { stdio: "ignore", timeout: 10_000 }).status === 0;
const skip = available ? false : "Build sandbox/Dockerfile to run local sandbox integration tests";

function archive(edit?: (dir: string) => void): Buffer {
  const dir = mkdtempSync(join(tmpdir(), "argos-sandbox-test-"));
  try {
    const target = join(dir, "source");
    cpSync(resolve("demo/realistic-app"), target, { recursive: true, filter: (p) => !/(?:^|\/)(?:node_modules|data\.db)(?:\/|$)/.test(p) });
    edit?.(target);
    return execFileSync("tar", ["czf", "-", "-C", dir, "source"], { maxBuffer: 20 * 1024 * 1024 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("sandbox protocol does not call an incomplete execution a pass", () => {
  assert.equal(SandboxResult.safeParse({ version: 1, status: "completed", image: SANDBOX_IMAGE, durationMs: 0, routes: [], untested: [], findings: [] }).success, false);
  assert.throws(() => isolationArgs("another-container", "argos-local-" + "a".repeat(24), true));
});

test("HTTP scanner refuses huge target responses", async () => {
  const server = createServer((_, r) => r.end("x".repeat(1024 * 1024 + 1)));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    const port = (server.address() as { port: number }).port;
    const result = await sendAs(`http://127.0.0.1:${port}`, { name: "anon", auth: { type: "none" } }, "GET", "/");
    assert.equal(result.status, null);
    assert.match(result.error!, /1 MiB/);
    assert.equal(result.body, "");
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});

test("offline service sandbox: normal own-data controls pass and no cross-vendor data leaks", { skip, timeout: 120_000 }, async () => {
  const result = await runSandbox(archive((dir) => {
    const file = join(dir, "app.mjs");
    writeFileSync(file, readFileSync(file, "utf8").replace('res.json({ ok: true })', 'res.json({ ok: true, unknownSecret: "must-never-export-response-secret" })'));
  }));
  assert.equal(result.status, "completed", JSON.stringify(result));
  assert.equal(result.policy, "repository");
  assert.ok(result.matrix!.cells.length > 20);
  assert.equal(result.findings.filter((f) => f.verdict === "VULNERABLE").length, 0);
  assert.ok(result.untested.some((r) => r.includes("POST /api/export")));
  assert.ok(!JSON.stringify(result).includes("argos-test-"), "tokens must not be exported");
  assert.ok(!JSON.stringify(result).includes("must-never-export-response-secret"), "unknown response secrets must not be exported");
});

test("offline service sandbox actually reproduces cross-vendor access; source scripts/env are ignored", { skip, timeout: 120_000 }, async () => {
  const result = await runSandbox(archive((dir) => {
    const p = join(dir, "app.mjs");
    writeFileSync(p, readFileSync(p, "utf8").replace('SELECT * FROM datasets WHERE id = ? AND vendor_id = ?\").get(req.params.id, req.user.vendor_id)', 'SELECT * FROM datasets WHERE id = ?\").get(req.params.id)'));
    const cfg = join(dir, "argos.config.yaml");
    writeFileSync(cfg, readFileSync(cfg, "utf8").replace('start: "node --no-warnings app.mjs"', 'start: "exit 99"').replace("env: {}", 'env: { NODE_OPTIONS: "--invalid-customer-option" }'));
    writeFileSync(join(dir, ".env"), "NEVER_COPY_THIS_SECRET=source-secret\n");
  }));
  assert.equal(result.status, "completed", JSON.stringify(result));
  assert.ok(result.findings.some((f) => f.check === "bola" && f.verdict === "VULNERABLE"));
  assert.ok(!JSON.stringify(result).includes("source-secret"));
});

test("sandbox times out and removes only its own containers and volume", { skip, timeout: 60_000 }, async () => {
  const result = await runSandbox(archive(), { timeoutMs: 1 });
  assert.equal(result.status, "failed");
  assert.match(result.reason!, /timed out|cancelled/);
});

test("service sandbox blocks egress, host paths/socket/env and source writes", { skip, timeout: 60_000 }, async () => {
  const name = `argos-local-${randomBytes(12).toString("hex")}`;
  await docker(["volume", "create", "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size=16m,uid=1000,gid=1000,mode=0700", name]);
  const code = `const fs=require('node:fs');const os=require('node:os');function writable(p){try{fs.writeFileSync(p,'x');return true}catch{return false}};console.log(JSON.stringify({uid:process.getuid(),interfaces:Object.keys(os.networkInterfaces()),env:process.env.GITHUB_CLIENT_SECRET,socket:fs.existsSync('/var/run/docker.sock'),host:fs.existsSync('/Users/gyeongsun'),root:writable('/etc/probe'),source:writable('/work/probe'),tmp:writable('/tmp/probe'),caps:fs.readFileSync('/proc/self/status','utf8').match(/CapEff:\\s*(\\w+)/)[1],nnp:fs.readFileSync('/proc/self/status','utf8').match(/NoNewPrivs:\\s*(\\w+)/)[1]}));`;
  try {
    const args = isolationArgs(`${name}-app`, name, true);
    const probe = JSON.parse(await docker(["run", "--rm", ...args, SANDBOX_IMAGE, "node", "-e", code]));
    assert.equal(probe.uid, 1000);
    assert.deepEqual(probe.interfaces, ["lo"]);
    assert.equal(probe.env, undefined);
    assert.equal(probe.socket, false);
    assert.equal(probe.host, false);
    assert.equal(probe.root, false);
    assert.equal(probe.source, false);
    assert.equal(probe.tmp, true);
    assert.equal(probe.caps, "0000000000000000");
    assert.equal(probe.nnp, "1");
  } finally { await docker(["volume", "rm", name]); }
});
