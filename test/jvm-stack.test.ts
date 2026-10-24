import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { parseConfig, type Config } from "../src/config.js";
import { dockerStatus } from "../src/container.js";
import { RunnerError, startTarget, type RunnerOptions, type RunningTarget } from "../src/runner.js";

/**
 * Docker-gated integration tests of the JVM stack (skipped, not failed, without docker).
 *   - always (with docker): a Spring-less Java stand-in (test/fixtures/jvm-probe) proves the sandbox from inside.
 *   - ARGOS_SPRING_IT=1: the real Spring fixtures (Maven and Gradle) — build, Flyway, JWT 200/401, isolation, cleanup.
 */

const docker = dockerStatus();
const skip = docker.ok ? false : `docker not available: ${docker.ok ? "" : docker.reason}`;
const springSkip = skip || (process.env.ARGOS_SPRING_IT === "1" ? false : "set ARGOS_SPRING_IT=1 to run the Spring fixture builds");
const LONG = 15 * 60_000;
const PROBE = resolve("test/fixtures/jvm-probe");

// direct = no proxy (must be blocked: internal network); allowed / denied = through the build proxy
const PROBE_BUILD =
  "mkdir -p out && javac -d out Server.java && { " +
  "curl -sS -m 8 --noproxy '*' -o /dev/null https://repo.maven.apache.org/maven2/ && echo direct=OPEN || echo direct=BLOCKED; " +
  "curl -sS -m 20 -o /dev/null -w 'allowed=%{http_code}\\n' https://repo.maven.apache.org/maven2/ || echo allowed=FAIL; " +
  "curl -sS -m 8 -o /dev/null https://example.com/ && echo denied=OPEN || echo denied=BLOCKED; " +
  "} > out/egress.txt 2>&1";

function cfg(target: Record<string, unknown> = {}, cwd = PROBE): Config {
  return parseConfig({
    version: 1,
    target: { start: "java -cp out Server", build: PROBE_BUILD, cwd, readyPath: "/health", isolation: "container", runtime: "jvm", ...target },
    db: { kind: "postgres", migrations: "none" },
    auth: { type: "jwt-issuer" },
    personas: [
      { name: "a", org: "o1", auth: { type: "jwt" } },
      { name: "b", org: "o2", auth: { type: "jwt" } },
      { name: "anon", auth: { type: "none" } },
    ],
    resources: [{ id: "health", route: "GET /health", public: true }],
    checks: ["unauth"],
  });
}

const left = (runId: string) => {
  const q = (args: string[]) => spawnSync("docker", args, { encoding: "utf8" }).stdout.trim();
  return { containers: q(["ps", "-aq", "--filter", `label=argos.run=${runId}`]), networks: q(["network", "ls", "-q", "--filter", `label=argos.run=${runId}`]) };
};
const runIdOf = (e: Error) => /\[argos run ([0-9a-f]{8})\]/.exec(e.message)?.[1];

async function rejectsClean(p: Promise<unknown>, re: RegExp): Promise<RunnerError> {
  let err: RunnerError | undefined;
  await assert.rejects(p, (e: Error) => {
    assert.ok(e instanceof RunnerError, e.message);
    assert.match(e.message, re);
    err = e;
    return true;
  });
  const id = runIdOf(err!);
  assert.ok(id, `run id in: ${err!.message}`);
  assert.deepEqual(left(id), { containers: "", networks: "" }, "everything of the run removed");
  return err!;
}

const internetFromHost = async () => {
  try {
    return (await fetch("https://repo.maven.apache.org/maven2/", { signal: AbortSignal.timeout(8000) })).ok;
  } catch {
    return false;
  }
};

describe("jvm stack (docker)", { skip, timeout: LONG }, () => {
  test("stand-in app: boots on SERVER_PORT, reaches only the run's db and issuer, sandbox holds", { timeout: LONG }, async () => {
    process.env.ARGOS_HOST_SECRET = "must-not-enter";
    const t = await startTarget(cfg({ env: { CUSTOM: "yes" } }), { quiet: true });
    try {
      assert.equal(t.runtime, "jvm");
      assert.equal(t.isolation, "container");
      assert.equal(t.image, "eclipse-temurin:21-jre");
      assert.equal((await fetch(t.baseUrl + "/health")).status, 200);
      const p = (await (await fetch(t.baseUrl + "/probe")).json()) as Record<string, string>;
      // the run's own services
      assert.match(p.jwks!, /^ok:200 \{"keys":\[\{.*"kty":"RSA"/);
      assert.match(p.oidc!, /^ok:200 .*"issuer":"http:\/\/argos-issuer:8081"/);
      assert.equal(p.db, "ok:connected");
      // nothing else: no route out, no resolver for the internet, no host
      assert.match(p.egressIp!, /^error:.*(unreachable|Network)/i);
      assert.match(p.egressDns!, /^error:UnknownHostException/);
      assert.match(p.hostDns!, /^error:/);
      // filesystem / privileges
      assert.match(p.writeRoot!, /^error:.*(Read-only|AccessDenied)/i);
      assert.match(p.writeTmp!, /^ok:/);
      assert.equal(p.dockerSock, "false");
      assert.match(p.status!, new RegExp(`Uid:\\s+${process.getuid!()}\\b`));
      assert.match(p.status!, /CapEff:\s+0000000000000000/);
      assert.match(p.status!, /NoNewPrivs:\s+1/);
      // environment: only what Argos injected + target.env
      const names = p.envNames!.split(",");
      assert.ok(!names.includes("ARGOS_HOST_SECRET") && !names.includes("PORT"));
      for (const k of t.injectedEnv!) assert.ok(names.includes(k), k);
      assert.equal(p.custom, "yes");
      // build: compiled in the build container; egress only through the allowlisting proxy
      assert.match(p.egressFile!, /direct=BLOCKED/);
      assert.match(p.egressFile!, /denied=BLOCKED/);
      if (await internetFromHost()) assert.match(p.egressFile!, /allowed=200/);
      // no published ports; the app is reachable only through the relay
      const app = `argos-${t.runId}-app`;
      assert.equal(spawnSync("docker", ["inspect", "-f", "{{json .NetworkSettings.Ports}}", app], { encoding: "utf8" }).stdout.trim(), "{}");
      const nets = spawnSync("docker", ["inspect", "-f", "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}", app], { encoding: "utf8" }).stdout.trim();
      assert.equal(nets, `argos-${t.runId}-net`);
      assert.equal(spawnSync("docker", ["network", "inspect", "-f", "{{.Internal}}", nets], { encoding: "utf8" }).stdout.trim(), "true");

      // DbHandle
      assert.deepEqual(await t.db!.query("select 1 as one, 'x' as s, null as n, true as b"), [{ one: 1, s: "x", n: null, b: true }]);
      assert.deepEqual(await t.db!.query("select 1 as t, 2 as u"), [{ t: 1, u: 2 }], "a column named t is still a whole row");
      await t.db!.exec("create table things (id serial primary key, name text not null); insert into things(name) values ('a');");
      assert.deepEqual(await t.db!.query("insert into things(name) values ('b') returning id, name"), [{ id: 2, name: "b" }]);
      assert.deepEqual(await t.db!.query("select name from things order by id"), [{ name: "a" }, { name: "b" }]);
      assert.deepEqual(await t.db!.query("update things set name = 'c' where id = 1"), []);
      await assert.rejects(t.db!.query("select * from nope"), /relation "nope" does not exist/);
      assert.ok(t.notes!.some((n) => /allowlisting CONNECT proxy/.test(n)));
    } finally {
      delete process.env.ARGOS_HOST_SECRET;
      await t.stop();
    }
    assert.ok(!existsSync(t.workdir), "temp copy removed");
    assert.deepEqual(left(t.runId!), { containers: "", networks: "" });
  });

  test("build failure: RunnerError with the build's log tail, everything cleaned up", { timeout: LONG }, async () => {
    const build = "echo compiling-step-1; curl -sS -m 5 -o /dev/null https://example.com/; exit 7";
    const e = await rejectsClean(startTarget(cfg({ build }), { quiet: true }), /build failed \(exit 7\)/);
    assert.match(e.message, /compiling-step-1/);
    assert.match(e.message, /argos-proxy deny example\.com:443/, "denied egress is part of the failure report");
  });

  test("boot failure: exit code + app log tail with the DB password redacted", { timeout: LONG }, async () => {
    const e = await rejectsClean(startTarget(cfg({ env: { CRASH: "1" } }), { quiet: true }), /exited with code 3/);
    assert.match(e.message, /boot failed: CRASH set, db password was <redacted>/);
  });

  test("not ready in time (secured readiness path with 200-only semantics) is an error, not a hang", { timeout: LONG }, async () => {
    await rejectsClean(startTarget(cfg({ readyPath: "/secured" }), { quiet: true, readyAnyStatus: false, readyTimeoutMs: 8_000 }), /did not return 200 within 8000ms/);
  });

  test("a secured readiness path (401) counts as ready by default for the jvm runtime", { timeout: LONG }, async () => {
    const t = await startTarget(cfg({ readyPath: "/secured" }), { quiet: true });
    await t.stop();
    assert.deepEqual(left(t.runId!), { containers: "", networks: "" });
  });

  test("build timeout and abort both clean up", { timeout: LONG }, async () => {
    const ids: string[] = [];
    const timedOut = await rejectsClean(startTarget(cfg({ build: "sleep 300" }), { quiet: true, prepareTimeoutMs: 5_000 }), /build timed out after 5000ms/);
    ids.push(runIdOf(timedOut)!);
    // abort at several points (before / around / after the build container is created)
    for (const ms of [2_000, 4_500, 6_000, 8_000]) {
      const ac = new AbortController();
      setTimeout(() => ac.abort(), ms);
      ids.push(runIdOf(await rejectsClean(startTarget(cfg({ build: "sleep 300" }), { quiet: true, signal: ac.signal }), /aborted/))!);
    }
    // nothing shows up late either (a killed `docker run` CLI can leave the daemon finishing a create)
    await new Promise((r) => setTimeout(r, 3_000));
    for (const id of ids) assert.deepEqual(left(id), { containers: "", networks: "" }, `run ${id}`);
  });

  test("afterReady runs against the live stack; a throw stops the target", { timeout: LONG }, async () => {
    let seen: RunningTarget | undefined;
    const opts: RunnerOptions = {
      quiet: true,
      afterReady: async (t) => {
        seen = t;
        await t.db!.exec("create table marker(x int)");
        throw new Error("seed failed");
      },
    };
    await assert.rejects(startTarget(cfg(), opts), /seed failed/);
    assert.ok(seen?.runId);
    assert.deepEqual(left(seen.runId), { containers: "", networks: "" });
  });
});

describe("jvm stack: Spring fixtures (docker, ARGOS_SPRING_IT=1)", { skip: springSkip, timeout: LONG }, () => {
  const ORG = "11111111-1111-1111-1111-111111111111";
  const USER = "22222222-2222-2222-2222-222222222222";
  for (const [tool, start] of [
    ["maven", "java -jar target/workspace.jar"],
    ["gradle", "java -jar build/libs/workspace.jar"],
  ] as const) {
    test(`${tool}: built in isolation, Flyway applied, JWT 200 / wrong key + expired 401, no egress, clean`, { timeout: LONG }, async () => {
      const c = cfg({ start, build: undefined, readyPath: "/healthz" }, resolve(`test/fixtures/spring/${tool}-app`));
      c.db!.migrations = "flyway";
      const t = await startTarget(c, {
        quiet: true,
        afterReady: (t) =>
          t.db!.exec(
            `insert into organizations(id,name,slug,api_key) values ('${ORG}','Org 1','org-1','k1');` +
              `insert into app_users(id,org_id,email,display_name,role) values ('${USER}','${ORG}','a@example.com','A','ADMIN');`,
          ),
      });
      try {
        assert.ok(t.notes!.some((n) => n.startsWith(`project: ${tool} (project wrapper), JDK 21`)), t.notes!.join("\n"));
        assert.deepEqual(await t.db!.query("select version, success from flyway_schema_history where version is not null order by installed_rank limit 1"), [{ version: "1", success: true }]);
        const me = (tok?: string) => fetch(t.baseUrl + "/api/me", { headers: tok ? { authorization: `Bearer ${tok}` } : {} });
        const ok = await me(t.issuer!.mint({ sub: USER, roles: ["ADMIN"] }));
        assert.equal(ok.status, 200);
        assert.equal(((await ok.json()) as { email: string }).email, "a@example.com");
        assert.equal((await me(t.issuer!.mint({ sub: USER }, { wrongKey: true }))).status, 401);
        assert.equal((await me(t.issuer!.mint({ sub: USER }, { expiresInSec: -3600 }))).status, 401);
        assert.equal((await me()).status, 401);
        const app = `argos-${t.runId}-app`;
        const sh = (cmd: string) => spawnSync("docker", ["exec", app, "sh", "-c", cmd], { encoding: "utf8", timeout: 30_000 });
        assert.notEqual(sh("timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/443'").status, 0, "no internet by IP");
        assert.notEqual(sh("getent hosts repo.maven.apache.org").status, 0, "no internet DNS");
        assert.notEqual(sh("getent hosts host.docker.internal").status, 0, "no host");
      } finally {
        await t.stop();
      }
      assert.deepEqual(left(t.runId!), { containers: "", networks: "" });
      const vols = spawnSync("docker", ["volume", "ls", "-q", "--filter", "label=argos-cache=1"], { encoding: "utf8" }).stdout;
      assert.match(vols, new RegExp(`argos-cache-${tool}`), "dependency cache volume is kept on purpose");
    });
  }
});
