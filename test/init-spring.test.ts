import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parse } from "yaml";
import { loadConfig, parseConfig } from "../src/config.js";
import { runInit } from "../src/init/index.js";
import { detectSpring } from "../src/init/spring/detect.js";
import { buildSpringDraft, type SpringDraft } from "../src/init/spring/draft.js";
import { scanSpring } from "../src/init/spring/facts.js";
import { readJava } from "../src/init/spring/java.js";
import { maskSecrets, type LlmClient } from "../src/init/spring/llm.js";
import { parseCreateTables, readMigrations } from "../src/init/spring/sql.js";

const FIX = resolve("test/fixtures/spring");
const MAVEN = join(FIX, "maven-app");
const GRADLE = join(FIX, "gradle-app");

const tmp = (p: string) => mkdtempSync(join(tmpdir(), `argos-spring-${p}-`));
function copy(app: string, variant?: string): string {
  const d = join(tmp("app"), "repo");
  cpSync(app, d, { recursive: true });
  if (variant) {
    const r = spawnSync(process.execPath, [join(FIX, "apply-variant.mjs"), d, variant], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
  }
  return d;
}
const draftOf = (dir: string): SpringDraft => buildSpringDraft(scanSpring(dir)!, { cwd: ".", llmData: "none" });
const res = (d: SpringDraft, route: string): any => (d.config.resources as any[]).find((r) => r.route === route);
const write = (dir: string, rel: string, text: string) => {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), text);
};
const SEC = "src/main/java/com/acme/workspace/config/SecurityConfig.java";

// ---------------------------------------------------------------- detection
test("detect: Maven fixture (wrapper, Java 21, Boot 3.5 parent, finalName jar)", () => {
  const p = detectSpring(MAVEN)!;
  assert.equal(p.buildTool, "maven");
  assert.equal(p.wrapper, true);
  assert.equal(p.java?.version, "21");
  assert.equal(p.boot?.version, "3.5.16");
  assert.match(p.boot!.source, /pom\.xml:\d+ \(<parent>/);
  assert.equal(p.bootStatus, "supported");
  assert.equal(p.module, ".");
  assert.equal(p.app?.className, "WorkspaceApplication");
  assert.equal(p.jar.path, "target/workspace.jar");
  assert.equal(p.build, "./mvnw -B -DskipTests package");
  assert.equal(p.start, "java -jar target/workspace.jar");
  assert.deepEqual(p.unsupported, []);
});

test("detect: Gradle fixture (Kotlin DSL, toolchain 21, Boot plugin, bootJar archiveFileName)", () => {
  const p = detectSpring(GRADLE)!;
  assert.equal(p.buildTool, "gradle");
  assert.equal(p.wrapper, true);
  assert.equal(p.java?.version, "21");
  assert.equal(p.boot?.version, "3.5.16");
  assert.equal(p.bootStatus, "supported");
  assert.equal(p.jar.path, "build/libs/workspace.jar");
  assert.equal(p.build, "./gradlew --no-daemon bootJar -x test");
  assert.deepEqual(p.unsupported, []);
});

test("detect: Boot 2.x / 4.x are 'compatibility not verified', not a crash; non-Boot and WebFlux/MyBatis are 미지원 with evidence", () => {
  const d = tmp("detect");
  const pom = (parentVersion: string, extra = "") =>
    `<project><parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>${parentVersion}</version></parent><artifactId>x</artifactId><version>1</version><dependencies>${extra}</dependencies><build><plugins><plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`;
  const dep = (a: string, g = "org.springframework.boot") => `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId></dependency>`;
  write(d, "src/main/java/a/App.java", "@SpringBootApplication public class App {}");
  write(d, "pom.xml", pom("4.0.1", dep("spring-boot-starter-oauth2-resource-server")));
  let p = detectSpring(d)!;
  assert.equal(p.bootStatus, "unverified");
  assert.match(p.notes.join(), /4\.0\.1: 호환성 미검증/);
  assert.equal(p.jar.path, "target/x-1.jar");
  assert.equal(p.build, "mvn -B -DskipTests package"); // no wrapper

  write(d, "pom.xml", pom("2.7.18", dep("spring-boot-starter-webflux") + dep("mybatis-spring-boot-starter", "org.mybatis.spring.boot")));
  p = detectSpring(d)!;
  assert.equal(p.bootStatus, "unverified");
  const items = p.unsupported.map((u) => u.item).join("\n");
  assert.match(items, /WebFlux/);
  assert.match(items, /MyBatis/);
  assert.match(items, /OAuth2 Resource Server/);
  assert.ok(p.unsupported.every((u) => u.where.includes("pom.xml")));

  write(d, "pom.xml", pom("3.5.0", dep("spring-boot-starter-oauth2-resource-server")).replace("<dependencies>", "<repositories><repository><id>corp</id><url>https://nexus.corp.example/repo</url></repository></repositories><dependencies>"));
  p = detectSpring(d)!;
  assert.equal(p.bootStatus, "supported");
  assert.match(p.risks.map((r) => r.item).join(), /빌드 의존성 저장소 허용 목록 밖: https:\/\/nexus\.corp\.example\/repo/);
  assert.deepEqual(detectSpring(GRADLE)!.risks, []); // foojay + toolchain 21 = build image JDK: no download expected

  const plain = tmp("plain");
  write(plain, "pom.xml", "<project><artifactId>y</artifactId><version>1</version></project>");
  write(plain, "src/main/java/a/Main.java", "public class Main {}");
  p = detectSpring(plain)!;
  assert.equal(p.bootStatus, "none");
  assert.match(p.unsupported.map((u) => u.item).join(), /Spring Boot가 아님/);
  assert.equal(detectSpring(tmp("empty")), undefined);
});

// ---------------------------------------------------------------- Java facts
test("java facts: controllers, joined paths, methods, path variables, bodies, query params", () => {
  for (const app of [MAVEN, GRADLE]) {
    const j = readJava(app);
    const routes = j.endpoints.map((e) => `${e.method} ${e.path}`).sort();
    assert.deepEqual(routes, [
      "DELETE /api/projects/{projectId}/documents/{documentId}",
      "GET /api/admin/organization",
      "GET /api/admin/users",
      "GET /api/documents/export",
      "GET /api/documents/search",
      "GET /api/me",
      "GET /api/projects",
      "GET /api/projects/{projectId}",
      "GET /api/projects/{projectId}/documents",
      "GET /api/projects/{projectId}/documents/{documentId}",
      "GET /healthz",
      "POST /api/admin/users",
      "POST /api/projects",
      "POST /api/projects/{projectId}/documents",
      "PUT /api/projects/{projectId}",
      "PUT /api/projects/{projectId}/documents/{documentId}",
    ]);
    const ep = (r: string) => j.endpoints.find((e) => `${e.method} ${e.path}` === r)!;
    assert.deepEqual(ep("PUT /api/projects/{projectId}/documents/{documentId}").pathVars, ["projectId", "documentId"]);
    assert.equal(ep("POST /api/projects").bodyType, "ProjectRequest");
    assert.deepEqual(ep("GET /api/documents/search").queryParams.map((q) => [q.name, q.required]), [["q", false], ["page", false], ["size", false]]);
    assert.match(at(ep("GET /api/me").loc), /web\/MeController\.java:\d+$/);
    // controller -> service -> repository with ownership predicates
    const get = ep("GET /api/projects/{projectId}/documents/{documentId}");
    assert.deepEqual(get.access.map((a) => `${a.repository}.${a.method}:${a.predicates.join(",")}`), ["DocumentRepository.findByIdAndProjectIdAndOrgIdAndOwnerId:id,project_id,org_id,owner_id"]);
    assert.equal(get.usesPrincipal, true);
    assert.deepEqual(ep("GET /api/admin/users").access.map((a) => a.predicates), [["org_id"]]);
    assert.deepEqual(j.repositories.find((r) => r.name === "DocumentRepository")!.methods.find((m) => m.name === "search")!.predicates, ["org_id", "owner_id"]); // @Query JPQL
  }
});
const at = (l: { file: string; line: number }) => `${l.file}:${l.line}`;

test("java facts: DTO Bean Validation constraints, enums, entities with FK join columns", () => {
  const j = readJava(MAVEN);
  const cu = j.dtos.get("CreateUserRequest")!;
  assert.deepEqual(
    cu.fields.map((f) => [f.name, f.constraints.map((c) => c.name + (c.attrs.max ? `(${c.attrs.max})` : ""))]),
    [["email", ["NotBlank", "Email", "Size(254)"]], ["displayName", ["NotBlank", "Size(100)"]], ["role", ["NotNull"]]],
  );
  assert.deepEqual(j.enums.get("Role"), ["ADMIN", "MEMBER"]);
  const user = j.entities.find((e) => e.name === "AppUser")!;
  assert.equal(user.table, "app_users");
  assert.deepEqual(user.fields.find((f) => f.name === "organization"), { name: "organization", column: "org_id", type: "Organization", id: false, relation: { kind: "ManyToOne", target: "Organization" } });
  assert.equal(j.entities.find((e) => e.name === "Project")!.fields.find((f) => f.id)!.generated, "IDENTITY");
});

test("java facts: security matchers in order, JWT authority mapping, principal resolution, method security", () => {
  const j = readJava(MAVEN);
  const s = j.security;
  assert.equal(s.chains.length, 1);
  assert.equal(s.chains[0]!.resourceServer, "jwt");
  assert.deepEqual(
    s.chains[0]!.matchers.map((m) => `${m.method ?? "*"} ${m.anyRequest ? "anyRequest" : m.patterns.join(",")} ${m.rule}${m.args.length ? `(${m.args})` : ""}`),
    ["GET /healthz permitAll", "* /error permitAll", "* /api/admin/** hasRole(ADMIN)", "* /api/** authenticated", "* anyRequest denyAll"],
  );
  assert.equal(s.rolesClaim?.claim, "roles");
  assert.equal(s.rolePrefix?.prefix, "ROLE_");
  assert.equal(s.methodSecurity.enabled, true);
  assert.equal(s.methodSecurity.annotation, "@EnableMethodSecurity");
  assert.deepEqual(j.endpoints.find((e) => e.method === "POST" && e.path === "/api/projects")!.guards.map((g) => [g.kind, g.roles, g.simple]), [["PreAuthorize", ["ADMIN"], true]]);
  assert.equal(j.principal.subject, "id");
  assert.equal(j.principal.resolver, "CurrentUserService");
  assert.equal(j.principal.userEntity, "AppUser");
});

test("java facts: the method-security-disabled variant is detected statically (guards present, not enforced)", () => {
  const dir = copy(GRADLE, "method-security-disabled");
  assert.equal(readJava(dir).security.methodSecurity.enabled, false);
  const d = draftOf(dir);
  assert.deepEqual(d.inactiveGuards.map((g) => g.route).sort(), ["POST /api/projects", "PUT /api/projects/{projectId}"]);
  assert.match(d.inactiveGuards[0]!.what, /@EnableMethodSecurity가 없어 적용되지 않음/);
  // the declared intent stays the expectation (so the scan can show it), marked as an inactive guard
  assert.deepEqual(res(d, "POST /api/projects").roles, ["ADMIN"]);
  assert.ok(d.evidence.some((e) => e.field === "roles" && e.status === "비활성 가드"));
  assert.equal(draftOf(MAVEN).inactiveGuards.length, 0);
});

test("draft: the flawed variants show up as likely findings; the correct app has none", () => {
  assert.deepEqual(draftOf(MAVEN).likelyFindings, []);
  const org = draftOf(copy(GRADLE, "missing-org-check"));
  assert.ok(org.likelyFindings.some((f) => f.route === "GET /api/projects/{projectId}" && /ProjectRepository\.findById\(id\)에 org_id 조건이 없음/.test(f.what)));
  const owner = draftOf(copy(MAVEN, "missing-owner-check"));
  assert.deepEqual(owner.likelyFindings.map((f) => f.route).sort(), [
    "DELETE /api/projects/{projectId}/documents/{documentId}",
    "GET /api/projects/{projectId}/documents/{documentId}",
    "PUT /api/projects/{projectId}/documents/{documentId}",
  ]);
  // the expectation is the table's declared rule, not what the flawed handler does
  assert.equal(res(owner, "GET /api/projects/{projectId}/documents/{documentId}").expect.sameOrgOther, "deny");
  const role = draftOf(copy(MAVEN, "missing-role-check"));
  assert.deepEqual(res(role, "GET /api/admin/users").roles, ["ADMIN"]);
  assert.ok(role.policyQuestions.some((q) => q.route === "GET /api/admin/users"));
});

// ---------------------------------------------------------------- migrations
test("migrations: Flyway CREATE TABLE columns, types, PK, FK, NOT NULL, UNIQUE, CHECK IN, identity", () => {
  const m = readMigrations(MAVEN);
  assert.equal(m.tool, "flyway");
  assert.deepEqual(m.files, ["src/main/resources/db/migration/V1__init.sql"]);
  assert.deepEqual(m.tables.map((t) => t.name), ["organizations", "app_users", "projects", "documents"]);
  const col = (t: string, c: string) => m.tables.find((x) => x.name === t)!.columns.find((x) => x.name === c)!;
  assert.deepEqual(col("documents", "owner_id"), { name: "owner_id", type: "uuid", notNull: true, pk: false, unique: false, hasDefault: false, generated: false, references: { table: "app_users", column: "id" } });
  assert.equal(col("projects", "id").generated, true);
  assert.equal(col("projects", "id").pk, true);
  assert.deepEqual(col("app_users", "role").allowed, ["ADMIN", "MEMBER"]);
  assert.equal(col("organizations", "slug").unique, true);
  assert.equal(col("projects", "description").notNull, false);
  assert.deepEqual(m.tables.find((t) => t.name === "projects")!.uniques, [["org_id", "name"]]);

  const t = parseCreateTables(`-- comment (with parens)\nCREATE TABLE IF NOT EXISTS public."a" (id BIGSERIAL, b_id INT, CONSTRAINT pk PRIMARY KEY (id), FOREIGN KEY (b_id) REFERENCES b(id));\nALTER TABLE a ADD COLUMN note TEXT NOT NULL;`, "x.sql");
  assert.equal(t.tables[0]!.columns[0]!.pk, true);
  assert.equal(t.tables[0]!.columns[0]!.generated, true);
  assert.deepEqual(t.tables[0]!.columns[1]!.references, { table: "b", column: "id" });
});

// ---------------------------------------------------------------- draft -> config
test("draft: both fixtures produce a jvm config that parseConfig accepts, with evidence for every expectation", () => {
  for (const [app, build, jar] of [
    [MAVEN, "./mvnw -B -DskipTests package", "target/workspace.jar"],
    [GRADLE, "./gradlew --no-daemon bootJar -x test", "build/libs/workspace.jar"],
  ] as const) {
    const d = draftOf(app);
    const cfg = parseConfig(d.config);
    assert.equal(cfg.target.runtime, "jvm");
    assert.equal(cfg.target.isolation, "container");
    assert.equal(cfg.target.build, build);
    assert.equal(cfg.target.start, `java -jar ${jar}`);
    assert.equal(cfg.target.readyPath, "/healthz");
    assert.deepEqual(cfg.db, { kind: "postgres", migrations: "flyway", env: { url: "SPRING_DATASOURCE_URL", user: "SPRING_DATASOURCE_USERNAME", password: "SPRING_DATASOURCE_PASSWORD" } });
    assert.equal(cfg.auth?.claims.subject, "id");
    assert.deepEqual(cfg.auth?.claims.roles, { claim: "roles" } /* app adds ROLE_; tokens carry bare names */);
    assert.deepEqual(cfg.personas.map((p) => [p.name, p.org ?? "", (p.roles ?? []).join(), p.invalid ?? ""]), [
      ["orgA-admin", "orgA", "ADMIN", ""],
      ["orgA-member", "orgA", "MEMBER", ""],
      ["orgA-member2", "orgA", "MEMBER", ""],
      ["orgB-admin", "orgB", "ADMIN", ""],
      ["orgB-member", "orgB", "MEMBER", ""],
      ["invalid-signature", "orgA", "MEMBER", "wrong-signature"],
      ["expired", "orgA", "MEMBER", "expired"],
      ["anonymous", "", "", ""],
    ]);
    assert.equal(cfg.resources.length, 16);
    const r = (route: string) => cfg.resources.find((x) => x.route === route)!;
    assert.equal(r("GET /healthz").public, true);
    assert.deepEqual(r("GET /api/projects/{projectId}").owner, { table: "projects", column: "org_id", scope: "org" });
    assert.deepEqual(r("GET /api/projects/{projectId}/documents/{documentId}").owner, { table: "documents", column: "owner_id", scope: "user" });
    assert.deepEqual(r("GET /api/projects/{projectId}/documents/{documentId}").pathParams, { projectId: { table: "projects" }, documentId: { table: "documents" } });
    assert.deepEqual(r("GET /api/projects/{projectId}/documents/{documentId}").expect, { owner: "allow", other: "deny", anonymous: "deny", sameOrgOther: "deny" });
    assert.deepEqual(r("GET /api/admin/users").owner, { table: "app_users", column: "org_id", scope: "org" });
    assert.deepEqual(r("GET /api/admin/users").roles, ["ADMIN"]);
    const create = r("POST /api/projects");
    assert.deepEqual(create.roles, ["ADMIN"]);
    assert.equal(create.safe, true);
    assert.equal(create.action, "create");
    assert.deepEqual(create.body, { name: "$unique", description: "$marker" });
    assert.deepEqual(create.writeVerify, { table: "projects", column: "name", where: { org_id: "$orgId" } });
    assert.deepEqual(create.expect, { owner: "allow", other: "deny", anonymous: "deny", member: "deny" });
    assert.deepEqual(r("POST /api/admin/users").body, { email: "$unique@argos.test", displayName: "$marker", role: "MEMBER" });
    assert.deepEqual(r("POST /api/projects/{projectId}/documents").writeVerify, { table: "documents", column: "title", where: { project_id: "$id:projects" } });
    assert.deepEqual(r("DELETE /api/projects/{projectId}/documents/{documentId}").writeVerify, { table: "documents", column: "id" });
    // every inferred expectation is ai-draft with an evidence location
    for (const x of cfg.resources) {
      if (x.expect) assert.equal(cfg.provenance?.[`resources.${x.id}.expect`], "ai-draft");
      const ev = d.evidence.filter((e) => e.resource === x.id);
      assert.ok(ev.length > 0, x.id);
      assert.ok(ev.every((e) => /:\d+$|\.sql$|^\S+\.java:\d+/.test(e.where) || e.where.endsWith(".sql")), JSON.stringify(ev));
    }
    assert.ok(d.evidence.some((e) => e.resource === "get-projects-projectId" && e.field === "expect.other" && e.status === "코드 근거" && /ProjectService\.java:\d+/.test(e.where)));
    assert.deepEqual(d.untested, []);
    assert.deepEqual(d.unsupported, []);
  }
});

// ---------------------------------------------------------------- runInit
test("runInit on the Maven fixture (LLM disabled, --no-verify): deterministic config + Korean report, fixture untouched", async () => {
  const out = tmp("out");
  const configPath = join(out, "argos.config.yaml");
  const before = readFileSync(join(MAVEN, "pom.xml"), "utf8");
  const r = await runInit({ dir: MAVEN, out: configPath, reportDir: out, verify: false, llmData: "files", log: () => {} });
  assert.equal(r.adapter, "spring-boot");
  assert.equal(r.configWritten, true);
  assert.equal(r.exitCode, 0);
  const cfg = loadConfig(configPath);
  assert.equal(cfg.target.runtime, "jvm");
  assert.equal(resolve(out, cfg.target.cwd), MAVEN);
  const text = readFileSync(configPath, "utf8");
  assert.match(text, /owner: 코드 근거 · src\/main\/java\/com\/acme\/workspace\/repo\/DocumentRepository\.java:\d+/);
  const report = readFileSync(r.reportPath, "utf8");
  assert.match(report, /# argos init: 결과 \(Spring Boot\)/);
  assert.match(report, /\*\*미검증\*\*/);
  assert.match(report, /검증을 건너뜀 \(--no-verify\)/);
  assert.match(report, /## API 목록: 발견 16개 중 16개를 설정에 넣음/);
  assert.match(report, /\| Spring Boot \| 3\.5\.16 — 지원 \(3\.x\)/);
  assert.match(report, /## 기대 정책과 근거/);
  assert.doesNotMatch(report, /jdbc:postgresql|password: workspace/);
  // no uncertain items -> nothing sent even with --llm-data files
  const egress = JSON.parse(readFileSync(r.egressPath, "utf8"));
  assert.equal(egress.llm, false);
  assert.deepEqual(egress.sent, []);
  assert.equal(readFileSync(join(MAVEN, "pom.xml"), "utf8"), before);
});

test("runInit: verification result is reported; a failed or unavailable run is explicitly 미검증 (never claimed)", async () => {
  const out = tmp("out");
  const ok = await runInit({
    dir: GRADLE,
    out: join(out, "a.yaml"),
    reportDir: join(out, "a"),
    log: () => {},
    springVerifier: async () => ({ ran: true, ok: true, boot: true, problems: [], loggedIn: ["orgA-admin", "orgB-admin"], ms: 1 }),
  });
  assert.equal(ok.exitCode, 0);
  assert.match(readFileSync(ok.reportPath, "utf8"), /✅ 검증됨[\s\S]*✅ 격리 환경에서 빌드·기동했고 2개 페르소나/);

  const bad = await runInit({
    dir: GRADLE,
    out: join(out, "b.yaml"),
    reportDir: join(out, "b"),
    log: () => {},
    springVerifier: async () => ({ ran: false, ok: false, boot: false, problems: ["docker is not available (x)"], skipped: "docker", loggedIn: [], ms: 1 }),
  });
  assert.equal(bad.exitCode, 1);
  assert.equal(bad.configWritten, true);
  const report = readFileSync(bad.reportPath, "utf8");
  assert.match(report, /⚪ \*\*미검증\*\*/);
  assert.match(report, /docker is not available/);
  assert.doesNotMatch(report, /✅/);
});

test("runInit: unsupported structure (form login, custom JWT filter) still yields a config + report with evidence, and is not run", async () => {
  const dir = copy(MAVEN);
  const sec = readFileSync(join(dir, SEC), "utf8").replace(".csrf(AbstractHttpConfigurer::disable)", ".csrf(AbstractHttpConfigurer::disable).formLogin(Customizer.withDefaults())");
  writeFileSync(join(dir, SEC), sec);
  write(dir, "src/main/java/com/acme/workspace/config/TokenFilter.java", `package com.acme.workspace.config;
public class TokenFilter extends OncePerRequestFilter {
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {
    String h = req.getHeader("Authorization"); // Bearer ...
  }
}`);
  let called = false;
  const out = tmp("out");
  const r = await runInit({ dir, reportDir: out, log: () => {}, springVerifier: async () => ((called = true), { ran: true, ok: true, boot: true, problems: [], loggedIn: [], ms: 1 }) });
  assert.equal(called, false);
  assert.equal(r.exitCode, 1);
  assert.equal(r.configWritten, true);
  const report = readFileSync(r.reportPath, "utf8");
  assert.match(report, /## 미지원 \(2\)/);
  assert.match(report, /폼 로그인\(formLogin\)[^|]*\| `src\/main\/java\/com\/acme\/workspace\/config\/SecurityConfig\.java:\d+`/);
  assert.match(report, /커스텀 인증 필터 TokenFilter/);
  assert.match(report, /미지원 구성 2건이 있어 실행 검증을 하지 않음/);
});

test("runInit: nothing drafted (Kotlin-only) -> no config, but a report that says why", async () => {
  const d = tmp("kt");
  write(d, "build.gradle.kts", `plugins { kotlin("jvm") version "2.0.0"\n id("org.springframework.boot") version "3.5.0" }\ndependencies { implementation("org.springframework.boot:spring-boot-starter-web") }`);
  write(d, "src/main/kotlin/a/App.kt", "@SpringBootApplication class App");
  const out = tmp("out");
  const r = await runInit({ dir: d, reportDir: out, verify: false, log: () => {} });
  assert.equal(r.configWritten, false);
  assert.equal(r.exitCode, 1);
  const report = readFileSync(r.reportPath, "utf8");
  assert.match(report, /설정 파일 \| 만들지 못함/);
  assert.match(report, /Kotlin 전용 프로젝트/);
});

test("runInit --force never weakens a field a person confirmed", async () => {
  const dir = copy(MAVEN);
  const out = tmp("out");
  const configPath = join(dir, "argos.config.yaml");
  await runInit({ dir, reportDir: out, verify: false, log: () => {} });
  const raw = parse(readFileSync(configPath, "utf8"));
  const r0 = raw.resources.find((r: any) => r.id === "get-projects-projectId");
  r0.expect.other = "allow"; // a person decided projects are visible to other orgs
  raw.provenance["resources.get-projects-projectId.expect"] = "confirmed";
  writeFileSync(configPath, JSON.stringify(raw));
  await assert.rejects(runInit({ dir, reportDir: out, verify: false, log: () => {} }), /already exists/);
  const r = await runInit({ dir, reportDir: out, verify: false, force: true, log: () => {} });
  const cfg = loadConfig(configPath);
  assert.equal(cfg.resources.find((x) => x.id === "get-projects-projectId")!.expect!.other, "allow");
  assert.equal(cfg.provenance!["resources.get-projects-projectId.expect"], "confirmed");
  assert.match(readFileSync(r.reportPath, "utf8"), /기존 확인값 유지[\s\S]*resources\.get-projects-projectId\.expect/);
});

// ---------------------------------------------------------------- LLM egress
const FAKE_YML_SECRET = "Sup3rS3cretDbPassw0rd!";
const FAKE_JAVA_SECRET = "sk-live-0123456789abcdefghijklmnop";
const FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU";

function repoWithUncertainLink(): string {
  const dir = copy(MAVEN);
  write(dir, "src/main/resources/application.yml", readFileSync(join(dir, "src/main/resources/application.yml"), "utf8").replace("password: workspace", `password: ${FAKE_YML_SECRET}`));
  write(dir, "src/main/java/com/acme/workspace/web/ShareController.java", `package com.acme.workspace.web;
@RestController
@RequestMapping("/api/shares")
public class ShareController {
    private static final String WEBHOOK_SECRET = "${FAKE_JAVA_SECRET}";
    private static final String SAMPLE_TOKEN = "${FAKE_JWT}";
    private final DocumentService documents;
    @GetMapping("/{ref}")
    public DocumentResponse get(@PathVariable String ref) { return null; }
}`);
  return dir;
}

test("LLM: secrets in application.yml / Java never leave the machine; output is cross-checked against facts", async () => {
  const dir = repoWithUncertainLink();
  const d0 = draftOf(dir);
  assert.deepEqual(d0.uncertain.map((u) => `${u.route} ${u.param}`), ["GET /api/shares/{ref} ref"]);
  assert.ok(d0.untested.some((u) => u.route === "GET /api/shares/{ref}"));

  const prompts: string[] = [];
  const client: LlmClient = {
    model: "stub",
    async complete(prompt) {
      prompts.push(prompt);
      return JSON.stringify({
        links: [
          { route: "GET /api/shares/{ref}", param: "ref", table: "documents", column: "share_token", evidence: "src/main/java/com/acme/workspace/web/ShareController.java:9" },
          { route: "GET /api/shares/{ref}", param: "ref", table: "secrets_vault", evidence: "src/main/java/com/acme/workspace/web/ShareController.java:9" },
          { route: "GET /api/nope/{x}", param: "x", table: "documents", evidence: "src/main/java/com/acme/workspace/web/ShareController.java:9" },
          { route: "GET /api/shares/{ref}", param: "ref", table: "documents", column: "made_up", evidence: "src/main/java/com/acme/workspace/web/ShareController.java:9" },
        ],
      });
    },
  };
  const out = tmp("out");
  const r = await runInit({ dir, out: join(out, "c.yaml"), reportDir: out, verify: false, llmData: "files", llmClient: client, log: () => {} });
  assert.equal(prompts.length, 1);
  const egressText = readFileSync(r.egressPath, "utf8");
  for (const s of [FAKE_YML_SECRET, FAKE_JAVA_SECRET, FAKE_JWT]) {
    assert.ok(!prompts[0]!.includes(s), `prompt leaks ${s.slice(0, 6)}`);
    assert.ok(!egressText.includes(s));
    assert.ok(!readFileSync(r.reportPath, "utf8").includes(s));
  }
  assert.match(prompts[0]!, /spring\.datasource\.password/); // key names only
  assert.match(prompts[0]!, /ShareController\.java/);
  const egress = JSON.parse(egressText);
  assert.equal(egress.llm, true);
  assert.deepEqual(egress.sent.map((s: any) => s.file), ["src/main/java/com/acme/workspace/web/ShareController.java"]);
  assert.ok(egress.masked >= 2);
  assert.deepEqual(egress.discarded.map((x: any) => x.reason), ["table secrets_vault is not in the schema", "route/param is not one of the unlinked path variables", "column documents.made_up does not exist"]);
  const cfg = loadConfig(join(out, "c.yaml"));
  const share = cfg.resources.find((x) => x.route === "GET /api/shares/{ref}")!;
  assert.deepEqual(share.pathParams, { ref: { table: "documents", column: "share_token" } });
  assert.ok((r.draft as SpringDraft).evidence.some((e) => e.field === "pathParams.ref" && e.status === "LLM 제안"));
});

test("LLM disabled (--llm-data none, or no API key): no call, nothing sent, the deterministic draft is still usable", async () => {
  const dir = repoWithUncertainLink();
  const client: LlmClient = { model: "stub", complete: async () => assert.fail("must not be called") };
  const out = tmp("out");
  const saved = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    const a = await runInit({ dir, out: join(out, "a.yaml"), reportDir: join(out, "a"), verify: false, llmData: "none", llmClient: client, log: () => {} });
    const b = await runInit({ dir, out: join(out, "b.yaml"), reportDir: join(out, "b"), verify: false, llmData: "files", log: () => {} });
    for (const r of [a, b]) {
      const egress = JSON.parse(readFileSync(r.egressPath, "utf8"));
      assert.equal(egress.llm, false);
      assert.deepEqual(egress.sent, []);
      const cfg = loadConfig(r.configPath);
      assert.equal(cfg.resources.length, 16); // the unlinkable route is left out, everything else is drafted
      assert.match(readFileSync(r.reportPath, "utf8"), /`GET \/api\/shares\/\{ref\}` \|[^\n]*경로 변수 \{ref\}가 어떤 테이블의 값인지 알 수 없음/);
    }
    assert.match(JSON.parse(readFileSync(b.egressPath, "utf8")).note, /ANTHROPIC_API_KEY is not set/);
  } finally {
    if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
  }
});

test("maskSecrets: masks credential assignments, known key formats, JWTs and private keys; leaves code alone", () => {
  const src = `String password = "hunter2hunter2"; String apiKey = "${FAKE_JAVA_SECRET}"; var t = "${FAKE_JWT}";\n-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\nString name = "projects"; setPassword("p4ssw0rdValue");`;
  const m = maskSecrets(src);
  for (const s of ["hunter2hunter2", FAKE_JAVA_SECRET, FAKE_JWT, "MIIabc", "p4ssw0rdValue"]) assert.ok(!m.text.includes(s), s);
  assert.match(m.text, /String name = "projects"/);
  assert.ok(m.masked >= 5);
});
