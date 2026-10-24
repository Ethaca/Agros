import { readAppConfig, type AppConfigFacts } from "./appconfig.js";
import { detectSpring, type Evidence, type SpringProject } from "./detect.js";
import { readJava, type JavaFacts } from "./java.js";
import { readMigrations, type MigrationFacts, type SqlTable } from "./sql.js";

/** Everything the Spring adapter knows about a repository, before any drafting. Deterministic, read-only. */
export interface SpringFacts {
  project: SpringProject;
  java: JavaFacts;
  migrations: MigrationFacts;
  appConfig: AppConfigFacts;
  /** Tables as the run will see them: migrations when readable, otherwise JPA entities. */
  tables: SqlTable[];
  tablesFrom: "migrations" | "entities" | "none";
  /** Structures Argos cannot set up automatically, with evidence. Reported as 미지원, never a crash. */
  unsupported: Evidence[];
}

export function scanSpring(root: string): SpringFacts | undefined {
  const project = detectSpring(root);
  if (!project) return undefined;
  const java = readJava(root, project.module);
  const migrations = readMigrations(project.module === "." ? root : `${root}/${project.module}`);
  // migration file paths relative to the repository root
  if (project.module !== ".") {
    migrations.files = migrations.files.map((f) => `${project.module}/${f}`);
    for (const t of migrations.tables) t.file = `${project.module}/${t.file}`;
  }
  const appConfig = readAppConfig(project.module === "." ? root : `${root}/${project.module}`);
  const unsupported: Evidence[] = [...project.unsupported];

  let tables: SqlTable[] = migrations.tables;
  let tablesFrom: SpringFacts["tablesFrom"] = tables.length ? "migrations" : "none";
  if (!tables.length && java.entities.length) {
    tablesFrom = "entities";
    tables = java.entities.map((e) => ({
      name: e.table,
      columns: e.fields.map((f) => ({
        name: f.column,
        type: f.type.toLowerCase(),
        notNull: f.id,
        pk: f.id,
        unique: false,
        hasDefault: false,
        generated: !!f.generated,
        ...(f.relation ? { references: { table: java.entities.find((x) => x.name === f.relation!.target)?.table ?? f.relation.target.toLowerCase(), column: "id" } } : {}),
      })),
      uniques: [],
      file: e.loc.file,
      line: e.loc.line,
    }));
  }

  // ---- security structures the test issuer cannot stand in for
  const sec = java.security;
  if (sec.webflux) unsupported.push({ item: "WebFlux 보안 구성(SecurityWebFilterChain / @EnableWebFluxSecurity): Servlet MVC만 지원", where: `${sec.webflux.file}:${sec.webflux.line}` });
  for (const f of sec.jwtFilters) unsupported.push({ item: `토큰을 직접 읽는 커스텀 인증 필터 ${f.name}: 표준 Resource Server JWT 경로가 아니라 테스트 issuer로 같은 인증을 재현할 수 없음`, where: `${f.loc.file}:${f.loc.line}` });
  for (const d of sec.jwtDecoderBeans) unsupported.push({ item: "커스텀 JwtDecoder 빈: 검증 규칙이 코드에 있어 테스트 issuer 연결이 보장되지 않음", where: `${d.file}:${d.line}` });
  for (const c of sec.chains) {
    const where = (l: { file: string; line: number }) => `${l.file}:${l.line}`;
    if (c.formLogin) unsupported.push({ item: "폼 로그인(formLogin): 세션·CSRF 기반 로그인은 아직 지원하지 않음", where: where(c.formLogin) });
    if (c.httpBasic) unsupported.push({ item: "HTTP Basic 인증: 표준 JWT만 자동 구성 가능", where: where(c.httpBasic) });
    if (c.oauth2Login) unsupported.push({ item: "oauth2Login(외부 SSO 세션 로그인): 아직 지원하지 않음", where: where(c.oauth2Login) });
    if (c.resourceServer === "opaque") unsupported.push({ item: "opaque token(introspection) Resource Server: JWT만 지원", where: where(c.loc) });
    if (c.customDecoder) unsupported.push({ item: "oauth2ResourceServer.jwt(decoder(...)) 커스텀 디코더", where: where(c.customDecoder) });
    for (const f of c.customFilters) if (/jwt|token|auth/i.test(f.name)) unsupported.push({ item: `인증 체인에 추가된 커스텀 필터 ${f.name}`, where: where(f.loc) });
  }
  if (sec.chains.length && !sec.chains.some((c) => c.resourceServer === "jwt")) {
    unsupported.push({ item: "SecurityFilterChain에 oauth2ResourceServer().jwt()가 없음: 표준 JWT 인증이 아님", where: `${sec.chains[0]!.loc.file}:${sec.chains[0]!.loc.line}` });
  }
  if (appConfig.multipleDataSources) unsupported.push({ item: "여러 DataSource 설정: 단일 PostgreSQL만 지원", where: appConfig.files.join(", ") });
  if (appConfig.datasource && (appConfig.datasource.kind === "mysql" || appConfig.datasource.kind === "h2" || appConfig.datasource.kind === "other")) {
    unsupported.push({ item: `datasource 종류 ${appConfig.datasource.kind}: PostgreSQL만 지원`, where: appConfig.files.join(", ") });
  }
  for (const o of java.otherDataAccess) unsupported.push({ item: `${o.kind}: JPA 외 데이터 접근은 소유권 조건을 읽지 못함`, where: `${o.loc.file}:${o.loc.line}` });
  if (!java.endpoints.length && project.languages.java > 0) unsupported.push({ item: "@RestController/@Controller 엔드포인트를 찾지 못함", where: project.module === "." ? "src/main/java" : `${project.module}/src/main/java` });

  // de-duplicate (same item + place)
  const seen = new Set<string>();
  const uniq = unsupported.filter((u) => {
    const k = `${u.item}|${u.where}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { project, java, migrations, appConfig, tables, tablesFrom, unsupported: uniq };
}
