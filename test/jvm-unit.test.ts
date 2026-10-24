import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseConfig } from "../src/config.js";
import { wrapForJson, psqlArgs } from "../src/jvm/db.js";
import { defaultAppImage, defaultBuildCommand, defaultBuildImage, detectJvmProject, normalizeJavaVersion } from "../src/jvm/detect.js";
import { appRunArgs, buildRunArgs, memBytes, networkCreateArgs, postgresRunArgs, sidecarRunArgs, HARDEN } from "../src/jvm/docker.js";
import { createIssuerKeys, issuerHandle, mintJwt } from "../src/jvm/jwt.js";
import { appEnv, buildContainerEnv, mavenSettingsXml, planBuild } from "../src/jvm/launch.js";
import { redact } from "../src/jvm/redact.js";
import { issuerScript, proxyScript } from "../src/jvm/sidecar.js";
import { jvmSettings } from "../src/jvm/settings.js";
import { RunnerError, startTarget } from "../src/runner.js";

function project(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), "argos-jvm-"));
  for (const [f, c] of Object.entries(files)) writeFileSync(join(d, f), c);
  return d;
}

function jvmCfg(extra: Record<string, unknown> = {}) {
  return parseConfig({
    version: 1,
    target: { start: "java -jar app.jar", isolation: "container", runtime: "jvm", readyPath: "/healthz" },
    db: { kind: "postgres", migrations: "flyway" },
    auth: { type: "jwt-issuer", audience: "workspace-api" },
    personas: [
      { name: "a", org: "o1", auth: { type: "jwt" } },
      { name: "b", org: "o2", auth: { type: "jwt" } },
      { name: "anon", auth: { type: "none" } },
    ],
    resources: [{ id: "health", route: "GET /healthz", public: true }],
    checks: ["unauth"],
    ...extra,
  });
}

describe("jvm: JDK and build tool detection", () => {
  test("normalizes Java versions", () => {
    assert.equal(normalizeJavaVersion("1.8"), 8);
    assert.equal(normalizeJavaVersion("17"), 17);
    assert.equal(normalizeJavaVersion("'21'"), 21);
    assert.equal(normalizeJavaVersion("21.0.2-tem"), 21);
    assert.equal(normalizeJavaVersion("VERSION_17"), 17);
    assert.equal(normalizeJavaVersion("VERSION_1_8"), 8);
    assert.equal(normalizeJavaVersion("${java.version}"), null);
    assert.equal(normalizeJavaVersion("latest"), null);
  });

  test("maven: java.version, compiler release (wins), ${property} indirection, wrapper", () => {
    const pom = (props: string, plugin = "") => `<project><properties>${props}</properties><build><plugins>${plugin}</plugins></build></project>`;
    assert.deepEqual(detectJvmProject(project({ "pom.xml": pom("<java.version>17</java.version>") })), { tool: "maven", wrapper: false, jdk: 17, jdkSource: "pom.xml <java.version>" });
    const rel = detectJvmProject(project({ "pom.xml": pom("<java.version>17</java.version><maven.compiler.release>21</maven.compiler.release>"), mvnw: "" }));
    assert.deepEqual([rel.tool, rel.wrapper, rel.jdk], ["maven", true, 21]);
    const ind = detectJvmProject(project({ "pom.xml": pom("<jdk>11</jdk><maven.compiler.source>${jdk}</maven.compiler.source>") }));
    assert.equal(ind.jdk, 11);
    const plug = detectJvmProject(project({ "pom.xml": pom("", "<plugin><artifactId>maven-compiler-plugin</artifactId><configuration><release>17</release></configuration></plugin>") }));
    assert.deepEqual([plug.jdk, plug.jdkSource], [17, "pom.xml compiler plugin <release>"]);
    const commented = detectJvmProject(project({ "pom.xml": pom("<!-- <java.version>8</java.version> -->") }));
    assert.deepEqual([commented.jdk, commented.jdkSource], [21, "default"]);
  });

  test("gradle: toolchain, jvmToolchain, sourceCompatibility; gradlew wins over pom.xml", () => {
    assert.deepEqual(
      detectJvmProject(project({ "build.gradle.kts": "java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }", gradlew: "" })),
      { tool: "gradle", wrapper: true, jdk: 17, jdkSource: "build.gradle.kts toolchain JavaLanguageVersion.of" },
    );
    assert.equal(detectJvmProject(project({ "build.gradle.kts": "kotlin { jvmToolchain(21) }" })).jdk, 21);
    assert.equal(detectJvmProject(project({ "build.gradle": "sourceCompatibility = JavaVersion.VERSION_11" })).jdk, 11);
    assert.equal(detectJvmProject(project({ "build.gradle": "sourceCompatibility = '1.8'" })).jdk, 8);
    assert.equal(detectJvmProject(project({ "build.gradle": "// sourceCompatibility = '11'\n" })).jdk, 21);
    assert.equal(detectJvmProject(project({ "pom.xml": "<project/>", gradlew: "", "build.gradle": "" })).tool, "gradle");
  });

  test("fallbacks: .java-version, .sdkmanrc, default 21, no build tool", () => {
    assert.deepEqual(detectJvmProject(project({ "pom.xml": "<project/>", ".java-version": "17\n" })).jdkSource, ".java-version");
    assert.equal(detectJvmProject(project({ "build.gradle": "", ".sdkmanrc": "java=11.0.22-tem\n" })).jdk, 11);
    assert.deepEqual(detectJvmProject(project({})), { tool: null, wrapper: false, jdk: 21, jdkSource: "default" });
  });

  test("the real fixtures", () => {
    const m = detectJvmProject("test/fixtures/spring/maven-app");
    assert.deepEqual([m.tool, m.wrapper, m.jdk], ["maven", true, 21]);
    const g = detectJvmProject("test/fixtures/spring/gradle-app");
    assert.deepEqual([g.tool, g.wrapper, g.jdk], ["gradle", true, 21]);
  });

  test("build command and images prefer the project wrapper", () => {
    const p = (tool: "maven" | "gradle" | null, wrapper: boolean, jdk = 17) => ({ tool, wrapper, jdk, jdkSource: "x" });
    assert.equal(defaultBuildCommand(p("maven", true)), "./mvnw -B -q -DskipTests package");
    assert.equal(defaultBuildCommand(p("maven", false)), "mvn -B -q -DskipTests package");
    assert.equal(defaultBuildCommand(p("gradle", true)), "./gradlew --no-daemon -q bootJar");
    assert.equal(defaultBuildCommand(p(null, false)), null);
    assert.equal(defaultBuildImage(p("maven", true)), "eclipse-temurin:17-jdk");
    assert.equal(defaultBuildImage(p("maven", false)), "maven:3-eclipse-temurin-17");
    assert.equal(defaultBuildImage(p("gradle", false)), "gradle:jdk17");
    assert.equal(defaultBuildImage(p("gradle", true)), "eclipse-temurin:17-jdk");
    assert.equal(defaultAppImage(p("maven", true)), "eclipse-temurin:17-jre");
  });

  test("planBuild: target.build and buildImage override detection; egress allowlist per tool", () => {
    const dir = project({ "pom.xml": "<project><properties><java.version>17</java.version></properties></project>" });
    const plan = planBuild(jvmSettings(jvmCfg()), dir);
    assert.deepEqual([plan.command, plan.image, plan.cacheVolume], ["mvn -B -q -DskipTests package", "maven:3-eclipse-temurin-17", "argos-cache-maven"]);
    assert.ok(plan.allowHosts.includes("repo.maven.apache.org") && !plan.allowHosts.includes("github.com"));
    const cfg = jvmCfg();
    cfg.target.build = "make jar";
    cfg.target.container.buildImage = "custom/jdk:1";
    const o = planBuild(jvmSettings(cfg), dir);
    assert.deepEqual([o.command, o.image], ["make jar", "custom/jdk:1"]);
  });
});

describe("jvm: docker arguments", () => {
  const limits = { memory: "1g", cpus: "1", pids: 512 };
  const hardened = (args: string[]) => {
    for (const f of HARDEN) assert.ok(args.includes(f), `missing ${f}`);
    assert.ok(!args.join(" ").includes("docker.sock"), "never the docker socket");
    assert.ok(!args.includes("--privileged") && !args.includes("host"), "never privileged / host network");
    assert.ok(args.includes("--label") && args.includes("argos=1") && args.includes("argos.run=r1"));
  };

  test("app: internal network alias, hardened, env by name only, no published port", () => {
    const env = { SERVER_PORT: "8080", SPRING_DATASOURCE_PASSWORD: "s3cr3t-value" };
    const a = appRunArgs({ name: "argos-r1-app", runId: "r1", network: "argos-r1-net", alias: "argos-app", image: "eclipse-temurin:21-jre", workdir: "/w", env, start: "java -jar x.jar", limits, user: "501:20" });
    hardened(a);
    assert.ok(!a.join(" ").includes("s3cr3t-value"), "secret values never on argv");
    assert.deepEqual(a.slice(a.indexOf("--network"), a.indexOf("--network") + 4), ["--network", "argos-r1-net", "--network-alias", "argos-app"]);
    assert.ok(!a.includes("-p") && !a.includes("--publish") && !a.includes("-P"));
    assert.deepEqual(a.slice(-4), ["eclipse-temurin:21-jre", "sh", "-c", "java -jar x.jar"]);
    assert.ok(a.includes("SPRING_DATASOURCE_PASSWORD") && a.includes("--user") && a.includes("501:20"));
    assert.ok(a.includes("--pids-limit") && a.includes("512") && a.includes("--memory") && a.includes("1g"));
  });

  test("build: hardened, internal build network, only workdir + home + cache volume mounted", () => {
    const b = buildRunArgs({ name: "argos-r1-build0", runId: "r1", network: "argos-r1-buildnet", image: "eclipse-temurin:21-jdk", workdir: "/w", home: "/h", cacheVolume: "argos-cache-maven", env: buildContainerEnv("argos-proxy", 3128), command: "./mvnw -q package", limits, user: "501:20" });
    hardened(b);
    const mounts = b.flatMap((x, i) => (x === "-v" ? [b[i + 1]] : []));
    assert.deepEqual(mounts, ["/w:/app:rw", "/h:/argos-home:rw", "argos-cache-maven:/cache:rw"]);
    assert.deepEqual(b.slice(-3), ["eclipse-temurin:21-jdk", "-c", "./mvnw -q package"]);
    assert.equal(b[b.indexOf("--entrypoint") + 1], "sh");
  });

  test("postgres and sidecar: hardened, non-root, alias on the run network", () => {
    const p = postgresRunArgs({ name: "argos-r1-db", runId: "r1", network: "n", alias: "argos-db", image: "postgres:16-alpine", env: { POSTGRES_PASSWORD: "pw-pw-pw-pw" } });
    hardened(p);
    assert.equal(p[p.indexOf("--user") + 1], "postgres");
    assert.ok(!p.join(" ").includes("pw-pw-pw-pw"));
    const s = sidecarRunArgs({ name: "argos-r1-issuer", runId: "r1", network: "n", alias: "argos-issuer", image: "node:25-slim", env: {}, script: issuerScript() });
    hardened(s);
    assert.equal(s[s.indexOf("--user") + 1], "1000:1000");
    assert.deepEqual(networkCreateArgs("argos-r1-net", "r1", true), ["network", "create", "--internal", "--label", "argos=1", "--label", "argos.run=r1", "argos-r1-net"]);
    assert.ok(!networkCreateArgs("e", "r1", false).includes("--internal"));
  });

  test("sidecar scripts are valid JavaScript", () => {
    for (const src of [issuerScript(), proxyScript()]) assert.doesNotThrow(() => new Function("require", "process", "console", src));
  });

  test("memBytes", () => {
    assert.equal(memBytes("512m"), 512 * 1024 ** 2);
    assert.equal(memBytes("1g"), 1024 ** 3);
    assert.ok(Number.isNaN(memBytes("lots")));
  });
});

describe("jvm: injected settings", () => {
  test("app env: Argos settings point at the run's aliases and cannot be overridden by target.env", () => {
    const s = jvmSettings(jvmCfg());
    const { env, injected } = appEnv({ s, targetEnv: { SERVER_PORT: "1", CUSTOM: "x" }, extraEnv: { CANARY: "c" }, dbPassword: "pw" });
    assert.equal(env.SERVER_PORT, "8080");
    assert.equal(env.PORT, undefined, "PORT is not what Spring reads");
    assert.equal(env.SPRING_DATASOURCE_URL, "jdbc:postgresql://argos-db:5432/argos");
    assert.equal(env.SPRING_DATASOURCE_USERNAME, "argos");
    assert.equal(env.SPRING_DATASOURCE_PASSWORD, "pw");
    assert.equal(env.SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI, "http://argos-issuer:8081/.well-known/jwks.json");
    assert.equal(env.SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI, "http://argos-issuer:8081");
    assert.deepEqual([env.CUSTOM, env.CANARY], ["x", "c"]);
    assert.ok(injected.includes("SPRING_DATASOURCE_PASSWORD") && !injected.includes("CUSTOM"));
    assert.deepEqual(Object.keys(env).sort(), [...injected, "CUSTOM", "CANARY"].sort(), "nothing from the host environment");
  });

  test("custom env names; no db/auth sections = nothing injected for them", () => {
    const cfg = jvmCfg({ db: { kind: "postgres", env: { url: "DB_URL", user: "DB_USER", password: "DB_PASS" } }, auth: { type: "jwt-issuer", env: { jwkSetUri: "JWKS" } } });
    const { env } = appEnv({ s: jvmSettings(cfg), targetEnv: {}, extraEnv: {}, dbPassword: "pw" });
    assert.deepEqual([env.DB_URL, env.DB_PASS, env.JWKS], ["jdbc:postgresql://argos-db:5432/argos", "pw", "http://argos-issuer:8081/.well-known/jwks.json"]);
    assert.equal(env.SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI, undefined, "issuer-uri only when configured");
    const bare = jvmCfg();
    delete (bare as { db?: unknown }).db;
    delete (bare as { auth?: unknown }).auth;
    assert.deepEqual(Object.keys(appEnv({ s: jvmSettings(bare), targetEnv: {}, extraEnv: {}, dbPassword: null }).env).sort(), ["HOME", "SERVER_PORT"]);
  });

  test("build env: proxy only, no host env or credentials; Maven settings point at the proxy and the cache", () => {
    const env = buildContainerEnv("argos-proxy", 3128);
    assert.match(env.JAVA_TOOL_OPTIONS!, /-Dhttps\.proxyHost=argos-proxy -Dhttps\.proxyPort=3128/);
    assert.equal(env.https_proxy, "http://argos-proxy:3128");
    assert.equal(env.GRADLE_USER_HOME, "/cache/gradle");
    for (const k of Object.keys(env)) assert.ok(!/TOKEN|SECRET|AWS|GITHUB|SSH/.test(k), k);
    const xml = mavenSettingsXml("argos-proxy", 3128);
    assert.match(xml, /<localRepository>\/cache\/m2\/repository<\/localRepository>/);
    assert.match(xml, /<protocol>https<\/protocol><host>argos-proxy<\/host><port>3128<\/port>/);
  });
});

describe("jvm: test issuer tokens", () => {
  const keys = createIssuerKeys();
  const pub = createPublicKey({ key: keys.jwks.keys[0] as never, format: "jwk" });
  const parts = (t: string) => t.split(".");
  const decode = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString()) as Record<string, unknown>;
  const valid = (t: string) => verify("sha256", Buffer.from(parts(t).slice(0, 2).join(".")), pub, Buffer.from(parts(t)[2]!, "base64url"));

  test("RS256 with kid; iss/iat/exp/aud set and not overridable by claims", () => {
    const h = issuerHandle(keys, "http://argos-issuer:8081", "api");
    const t = h.mint({ sub: "u1", roles: ["ADMIN"], iss: "evil", exp: 1, aud: "other" });
    const [hd, pl] = parts(t).map((p, i) => (i < 2 ? decode(p) : null));
    assert.deepEqual(hd, { alg: "RS256", typ: "JWT", kid: keys.kid });
    assert.equal(pl!.iss, "http://argos-issuer:8081");
    assert.equal(pl!.aud, "api");
    assert.equal(pl!.sub, "u1");
    assert.deepEqual(pl!.roles, ["ADMIN"]);
    const now = Date.now() / 1000;
    assert.ok((pl!.exp as number) > now + 200 && (pl!.exp as number) <= now + 301);
    assert.ok((pl!.iat as number) <= now + 1);
    assert.ok(valid(t), "verifies against the published JWKS");
  });

  test("wrongKey: same kid, signature does not verify against the JWKS; expired tokens are expired", () => {
    const bad = mintJwt(keys, "i", undefined, { sub: "u" }, { wrongKey: true });
    assert.equal(decode(parts(bad)[0]!).kid, keys.kid);
    assert.equal(valid(bad), false);
    const old = mintJwt(keys, "i", undefined, { sub: "u" }, { expiresInSec: -3600 });
    const p = decode(parts(old)[1]!);
    assert.ok((p.exp as number) < Date.now() / 1000 - 3000);
    assert.ok((p.iat as number) < (p.exp as number));
    assert.equal(p.aud, undefined);
    assert.ok(valid(old));
  });

  test("the JWKS has only public material", () => {
    const k = keys.jwks.keys[0]!;
    for (const priv of ["d", "p", "q", "dp", "dq", "qi"]) assert.equal(k[priv], undefined);
    assert.deepEqual([k.kty, k.alg, k.use], ["RSA", "RS256", "sig"]);
  });
});

describe("jvm: redaction and SQL", () => {
  test("redacts JWTs and run secrets", () => {
    const t = mintJwt(createIssuerKeys(), "i", undefined, { sub: "u" });
    const out = redact(`Bearer ${t} failed; password=Zx9_secretpw for jdbc`, ["Zx9_secretpw"]);
    assert.ok(!out.includes(t) && !out.includes("Zx9_secretpw"));
    assert.match(out, /Bearer <redacted-jwt> failed; password=<redacted> for jdbc/);
    assert.equal(redact("short ab", ["ab"]), "short ab", "very short values are not treated as secrets");
  });

  test("wrapForJson: selects and RETURNING produce JSON rows; other statements run as-is", () => {
    assert.equal(wrapForJson("select 1 as one;"), "select coalesce(json_agg(_argos_q), '[]'::json) from (select 1 as one) _argos_q");
    assert.match(wrapForJson("WITH x as (select 1) select * from x")!, /^select coalesce\(json_agg\(_argos_q\)/);
    assert.equal(wrapForJson("insert into a values (1) returning id"), "with _argos_q as (insert into a values (1) returning id) select coalesce(json_agg(_argos_q), '[]'::json) from _argos_q");
    // a column named t must not be what gets aggregated
    assert.ok(!/json_agg\(t\)|\) t$/.test(wrapForJson("select 1 as t, 2 as u")!));
    assert.equal(wrapForJson("insert into a values (1)"), null);
    assert.equal(wrapForJson("create table a(id int)"), null);
    assert.deepEqual(psqlArgs("c", "u", "d"), ["exec", "-i", "c", "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", "u", "-d", "d"]);
  });
});

test("jvm runtime refuses host execution", async () => {
  await assert.rejects(startTarget(jvmCfg(), { quiet: true, isolation: "process" }), (e: Error) => e instanceof RunnerError && /only with container isolation/.test(e.message));
});
