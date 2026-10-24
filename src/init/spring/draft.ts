import { isSensitiveColumn } from "../../seed.js";
import type { Draft, NeedsHuman } from "../draft.js";
import { at, snake, type DataAccess, type Dto, type Endpoint, type Guard, type HttpMethod, type Loc, type Matcher } from "./java.js";
import { simpleType, typeArgs } from "./javaparse.js";
import type { SpringFacts } from "./facts.js";
import type { SqlTable } from "./sql.js";

/**
 * Spring adapter, drafting step: FACTS -> argos.config.yaml (runtime jvm) with deterministic rules.
 *
 * Expected policy comes from what the code DECLARES (security matchers, guards, the ownership conditions the
 * repositories use for a table), never from whether one handler happens to enforce it: a handler that skips the
 * ownership condition other handlers of the same table use is reported as a likely finding, not learned as the rule.
 * When the code shows no ownership rule at all the conservative default applies and the report says
 * "정책 확인 필요" (policy to confirm) instead of calling it a vulnerability.
 */

export type EvidenceStatus = "코드 근거" | "기본값" | "정책 확인 필요" | "비활성 가드" | "LLM 제안";

export interface PolicyEvidence {
  resource: string;
  field: string;
  value: string;
  where: string;
  status: EvidenceStatus;
  note?: string;
}

export interface InventoryItem {
  route: string;
  where: string;
  /** Resource id when the endpoint is in the config. */
  resource?: string;
  reason?: string;
}

export interface Finding {
  route: string;
  what: string;
  where: string;
}

/** Something the static rules could not decide and the LLM may link (cross-checked against facts). */
export interface Uncertain {
  kind: "pathParam";
  route: string;
  param: string;
  where: string;
  /** Files worth showing (controller + reached classes). */
  files: string[];
}

/** A link proposed by the LLM that survived the cross-check against facts. */
export interface Link {
  route: string;
  param: string;
  table: string;
  column?: string;
  evidence: string;
}

export interface SpringDraft extends Draft {
  evidence: PolicyEvidence[];
  inventory: InventoryItem[];
  inactiveGuards: Finding[];
  likelyFindings: Finding[];
  policyQuestions: Finding[];
  uncertain: Uncertain[];
}

export interface SpringDraftOptions {
  /** target.cwd as seen from the config file. */
  cwd: string;
  llmData: "files" | "none";
  links?: Link[];
}

const HEALTH = /^\/(?:health|healthz|ping|ready|readyz|live|livez|status|actuator\/health(?:\/[\w-]+)?)$/i;
const ORG_COL = /^(?:org|organi[sz]ation|tenant|account|company|workspace|team|vendor|customer)_id$/;
const USER_COL = /^(?:owner|user|author|creator|created_by|app_user|member)(?:_id)?$/;
const ORG_TABLE = /^(?:organi[sz]ations?|orgs?|tenants?|workspaces?|compan(?:y|ies)|teams?|accounts?)$/;
const USER_TABLE = /^(?:app_)?users?$|^accounts?$|^members?$/;
const DEFAULT_SENSITIVE = ["api_key", "token", "secret", "password"];
const SECRETISH = /secret|token|key|password|passwd|credential/i;

const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

/** Ant-style request matcher -> RegExp (`/api/**`, `/a/*`, `/a/{id}`). */
export function antToRe(p: string): RegExp {
  let s = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (p.startsWith("/**", i) && i + 3 === p.length) {
      s += "(?:/.*)?";
      i += 2;
    } else if (p.startsWith("**", i)) {
      s += ".*";
      i++;
    } else if (c === "*") s += "[^/]*";
    else if (c === "{") {
      const end = p.indexOf("}", i);
      s += "[^/]+";
      i = end < 0 ? i : end;
    } else s += c.replace(/[.+?^$()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${s}/?$`);
}

const samplePath = (p: string): string => p.replace(/\{[^}]+\}/g, "1");

function resourceId(method: string, path: string, used: Set<string>): string {
  const parts = path
    .split("/")
    .filter((s) => s && s !== "api")
    .map((s) => s.replace(/^\{|\}$/g, ""));
  const base = `${method.toLowerCase()}-${parts.join("-") || "root"}`.replace(/[^a-zA-Z0-9-]/g, "-");
  let id = base;
  for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
  used.add(id);
  return id;
}

const ACTION: Record<HttpMethod, "read" | "create" | "update" | "delete"> = { GET: "read", POST: "create", PUT: "update", PATCH: "update", DELETE: "delete" };

export function buildSpringDraft(facts: SpringFacts, opts: SpringDraftOptions): SpringDraft {
  const { project, java, appConfig } = facts;
  const needsHuman: NeedsHuman[] = [];
  const found: string[] = [];
  const untested: Draft["untested"] = [];
  const provenance: Draft["provenance"] = {};
  const evidence: PolicyEvidence[] = [];
  const inventory: InventoryItem[] = [];
  const inactiveGuards: Finding[] = [];
  const likelyFindings: Finding[] = [];
  const policyQuestions: Finding[] = [];
  const uncertain: Uncertain[] = [];
  const unsupported = facts.unsupported.map((u) => `${u.item} (${u.where})`);
  const ask = (topic: NeedsHuman["topic"], message: string, where?: string) => needsHuman.push({ topic, message, ...(where ? { where } : {}) });

  // ---------------------------------------------------------------- schema helpers
  const tables = new Map<string, SqlTable>(facts.tables.map((t) => [t.name, t]));
  const entityTable = (name?: string): string | undefined => (name ? java.entities.find((e) => e.name === name)?.table : undefined);
  const entityOfTable = (table: string): string | undefined => java.entities.find((e) => e.table === table)?.name;
  const pkOf = (t: string): string => tables.get(t)?.columns.find((c) => c.pk)?.name ?? "id";
  const hasCol = (t: string, c: string): boolean => !!tables.get(t)?.columns.some((x) => x.name === c);

  const usersTable =
    entityTable(java.principal.userEntity) ?? [...tables.values()].find((t) => USER_TABLE.test(t.name) && t.columns.some((c) => c.name === "email"))?.name;
  const orgTable =
    (usersTable && tables.get(usersTable)?.columns.find((c) => c.references && ORG_COL.test(c.name))?.references?.table) ??
    [...tables.keys()].find((t) => ORG_TABLE.test(t) && t !== usersTable);
  const refTo = (t: string, c: string): string | undefined => tables.get(t)?.columns.find((x) => x.name === c)?.references?.table;
  const isOrgCol = (t: string, c: string): boolean => (orgTable !== undefined && refTo(t, c) === orgTable) || ORG_COL.test(c);
  const isUserCol = (t: string, c: string): boolean => t !== usersTable && ((usersTable !== undefined && refTo(t, c) === usersTable) || USER_COL.test(c));

  // ---- table-level ownership, from every repository query of the table (what the code declares as the rule)
  interface Scope {
    scope: "org" | "user";
    column: string;
    where: string;
    status: EvidenceStatus;
    why: string;
  }
  const tableScope = new Map<string, Scope>();
  for (const r of java.repositories) {
    const t = entityTable(r.entity);
    if (!t) continue;
    for (const m of r.methods) {
      const u = m.predicates.find((c) => isUserCol(t, c));
      const o = m.predicates.find((c) => isOrgCol(t, c));
      const cur = tableScope.get(t);
      if (u && cur?.scope !== "user") tableScope.set(t, { scope: "user", column: u, where: at(m.loc), status: "코드 근거", why: `${r.name}.${m.name}: ${u}로 조회 범위를 제한` });
      else if (o && !cur) tableScope.set(t, { scope: "org", column: o, where: at(m.loc), status: "코드 근거", why: `${r.name}.${m.name}: ${o}로 조회 범위를 제한` });
    }
  }
  if (orgTable && !tableScope.has(orgTable)) tableScope.set(orgTable, { scope: "org", column: pkOf(orgTable), where: tables.get(orgTable)!.file, status: "코드 근거", why: `${orgTable}는 조직 테이블(사용자 ${usersTable ?? "?"}의 조직 FK 대상)` });
  const scopeOf = (t: string): Scope | undefined => {
    const s = tableScope.get(t);
    if (s) return s;
    const tbl = tables.get(t);
    const org = tbl?.columns.find((c) => isOrgCol(t, c.name));
    if (org) return { scope: "org", column: org.name, where: `${tbl!.file}:${tbl!.line}`, status: "정책 확인 필요", why: `코드에서 ${t}의 소유권 조건을 찾지 못함: 스키마의 ${org.name} 기준 보수적 기본값` };
    return undefined;
  };

  // ---- path variable -> table
  const linkFor = (route: string, param: string) => opts.links?.find((l) => l.route === route && l.param === param);
  const tableForName = (stem: string): string | undefined => {
    const s = snake(stem);
    for (const c of [s, `${s}s`, `${s}es`, s.replace(/y$/, "ies")]) if (tables.has(c)) return c;
    const byEntity = java.entities.find((e) => e.name.toLowerCase() === stem.toLowerCase()) ?? java.entities.find((e) => stem.length >= 3 && e.name.endsWith(cap(stem)));
    if (byEntity && tables.has(byEntity.table)) return byEntity.table;
    return [...tables.keys()].find((t) => t.endsWith(`_${s}s`) || t.endsWith(`_${s}`));
  };
  const dtoTable = (returnType: string): string | undefined => {
    let t = returnType;
    for (let i = 0; i < 4 && typeArgs(t).length; i++) t = typeArgs(t).at(-1)!;
    const stem = simpleType(t).replace(/(?:Response|Dto|DTO|View|Resource|Summary|Details?|Result|Model|Item)$/, "");
    if (!stem || /^(?:String|Map|Object|Void|void|Integer|Long|Boolean|ResponseEntity)$/.test(stem)) return undefined;
    const e = java.entities.find((x) => x.name === stem) ?? java.entities.find((x) => stem.length >= 3 && x.name.endsWith(stem));
    return e && tables.has(e.table) ? e.table : undefined;
  };
  const controllerTable = (controller: string): string | undefined => {
    const stem = controller.replace(/(?:Rest)?Controller$|Resource$|Api$/, "");
    return stem ? tableForName(stem) : undefined;
  };
  const varTable = (ep: Endpoint, v: string): { table?: string; column?: string; status: EvidenceStatus; where: string } => {
    const route = `${ep.method} ${ep.path}`;
    const l = linkFor(route, v);
    if (l) return { table: l.table, ...(l.column ? { column: l.column } : {}), status: "LLM 제안", where: l.evidence };
    const stem = v.replace(/(?:Id|ID|_id|Uuid|UUID|Key|Code)$/, "");
    const t = stem && stem !== v ? tableForName(stem) : v === "id" ? (dtoTable(ep.returnType) ?? controllerTable(ep.controller)) : tableForName(v);
    if (!t) return { status: "정책 확인 필요", where: at(ep.loc) };
    const viaRepo = ep.access.some((a) => entityTable(a.entity) === t && a.predicates.includes(pkOf(t)));
    return { table: t, status: viaRepo ? "코드 근거" : "기본값", where: at(ep.loc) };
  };

  // ---- security rule for a route
  const chains = [...java.security.chains].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  const urlRule = (ep: Endpoint): Matcher | undefined => {
    const p = samplePath(ep.path);
    for (const c of chains) {
      if (c.securityMatcher.length && !c.securityMatcher.some((m) => antToRe(m).test(p))) continue;
      return c.matchers.find((m) => (!m.method || m.method === ep.method) && (m.anyRequest || m.patterns.some((x) => antToRe(x).test(p))));
    }
    return undefined;
  };
  const ms = java.security.methodSecurity;
  const guardActive = (g: Guard): boolean => (g.kind === "Secured" ? ms.secured : g.kind === "RolesAllowed" ? ms.jsr250 : ms.prePost);

  // ---------------------------------------------------------------- roles and personas
  const declaredRoles = new Set<string>();
  for (const c of chains) for (const m of c.matchers) if (/^has(?:Any)?(?:Role|Authority)$/.test(m.rule)) m.args.forEach((a) => declaredRoles.add(a.replace(/^ROLE_/, "")));
  for (const ep of java.endpoints) for (const g of ep.guards) g.roles.forEach((r) => declaredRoles.add(r));
  const adminRole = [...declaredRoles].find((r) => /ADMIN/i.test(r)) ?? [...declaredRoles][0];
  const roleEnum = adminRole ? [...java.enums.values()].find((cs) => cs.includes(adminRole)) : undefined;
  const roleColValues = usersTable ? tables.get(usersTable)?.columns.find((c) => /^role/.test(c.name))?.allowed : undefined;
  const memberRole = adminRole
    ? ([...(roleEnum ?? []), ...(roleColValues ?? [])].find((r) => r !== adminRole && /MEMBER|USER/i.test(r)) ?? [...(roleEnum ?? []), ...(roleColValues ?? [])].find((r) => r !== adminRole) ?? "USER")
    : undefined;

  const personas: Record<string, unknown>[] = [];
  if (adminRole && memberRole) {
    const p = (name: string, org: string, role: string) => ({ name, org, auth: { type: "jwt" }, roles: [role] });
    personas.push(p("orgA-admin", "orgA", adminRole), p("orgA-member", "orgA", memberRole), p("orgA-member2", "orgA", memberRole), p("orgB-admin", "orgB", adminRole), p("orgB-member", "orgB", memberRole));
    personas.push({ name: "invalid-signature", org: "orgA", user: "orgA-member", auth: { type: "jwt" }, roles: [memberRole], invalid: "wrong-signature" });
    personas.push({ name: "expired", org: "orgA", user: "orgA-member", auth: { type: "jwt" }, roles: [memberRole], invalid: "expired" });
    found.push(`역할: ${adminRole}(관리자), ${memberRole}(일반) — ${roleEnum ? "enum" : roleColValues ? "CHECK 제약" : "기본값"} 기준`);
  } else {
    const p = (name: string, org: string) => ({ name, org, auth: { type: "jwt" } });
    personas.push(p("orgA-user", "orgA"), p("orgA-user2", "orgA"), p("orgB-user", "orgB"));
    personas.push({ name: "invalid-signature", org: "orgA", user: "orgA-user", auth: { type: "jwt" }, invalid: "wrong-signature" });
    personas.push({ name: "expired", org: "orgA", user: "orgA-user", auth: { type: "jwt" }, invalid: "expired" });
    found.push("역할 조건을 코드에서 찾지 못함: 역할 없는 페르소나로 구성");
  }
  personas.push({ name: "anonymous", auth: { type: "none" } });
  provenance["personas"] = "ai-draft";

  // ---------------------------------------------------------------- request body templates
  const enumValue = (constants: string[]): string => (adminRole && constants.includes(adminRole) && memberRole && constants.includes(memberRole) ? memberRole : constants[0]!);
  const bodyFor = (dto: Dto, depth = 0): { body: Record<string, unknown>; notes: string[]; uniqueField?: string } => {
    const body: Record<string, unknown> = {};
    const notes: string[] = [];
    let uniqueField: string | undefined;
    for (const f of dto.fields) {
      const c = new Map(f.constraints.map((x) => [x.name, x.attrs]));
      const required = c.has("NotNull") || c.has("NotBlank") || c.has("NotEmpty");
      const max = Number(c.get("Size")?.max ?? c.get("Length")?.max ?? NaN);
      const min = Number(c.get("Size")?.min ?? c.get("Length")?.min ?? 0);
      const t = simpleType(f.type);
      const fits = (s: string): boolean => (Number.isNaN(max) || s.length <= max) && s.length >= min;
      if (t === "String" || t === "CharSequence") {
        let v: string;
        if (c.has("Email")) v = "$unique@argos.test";
        else if (!uniqueField) v = "$unique";
        else v = "$marker";
        const sampleLen = v === "$unique@argos.test" ? 27 : 16;
        if (!fits("x".repeat(sampleLen))) {
          v = "a".repeat(Math.max(min, Math.min(Number.isNaN(max) ? 8 : max, 8)));
          notes.push(`${dto.name}.${f.name}: 길이 제약(${min}..${Number.isNaN(max) ? "" : max}) 때문에 고정값 사용`);
        }
        if (c.has("Pattern")) notes.push(`${dto.name}.${f.name}: @Pattern(${c.get("Pattern")!.regexp ?? ""}) 형식을 만족하는지 확인 필요`);
        body[f.name] = v;
        if (v === "$unique" || v === "$unique@argos.test") uniqueField ??= f.name;
      } else if (java.enums.has(t)) {
        if (required) body[f.name] = enumValue(java.enums.get(t)!);
      } else if (/^(?:Long|long|Integer|int|Short|short|BigDecimal|Double|double|Float|float|BigInteger|Number)$/.test(t)) {
        const ref = /(?:Id|_id)$/.test(f.name) ? tableForName(f.name.replace(/(?:Id|_id)$/, "")) : undefined;
        if (ref) body[f.name] = `$id:${ref}`;
        else if (required || /^[a-z]/.test(t)) body[f.name] = Number(c.get("Min")?.value ?? c.get("DecimalMin")?.value ?? (c.has("Positive") ? 1 : 1));
      } else if (t === "UUID") {
        const ref = /(?:Id|_id)$/.test(f.name) ? tableForName(f.name.replace(/(?:Id|_id)$/, "")) : undefined;
        if (ref) body[f.name] = `$id:${ref}`;
        else if (required) notes.push(`${dto.name}.${f.name}: 필수 UUID인데 어떤 테이블의 id인지 알 수 없음`);
      } else if (t === "Boolean" || t === "boolean") {
        if (required || t === "boolean") body[f.name] = c.has("AssertTrue");
      } else if (/^(?:List|Set|Collection)$/.test(t)) {
        if (required) {
          body[f.name] = [];
          if (c.has("NotEmpty")) notes.push(`${dto.name}.${f.name}: 비어 있으면 안 되는 목록 — 값 확인 필요`);
        }
      } else if (/^(?:LocalDate|LocalDateTime|Instant|OffsetDateTime|ZonedDateTime)$/.test(t)) {
        if (required) body[f.name] = c.has("Past") || c.has("PastOrPresent") ? "2020-01-01" : t === "LocalDate" ? "2030-01-01" : "2030-01-01T00:00:00Z";
      } else if (java.dtos.has(t) && depth < 2) {
        if (required) body[f.name] = bodyFor(java.dtos.get(t)!, depth + 1).body;
      } else if (required) notes.push(`${dto.name}.${f.name}: 형식 ${f.type}의 값을 만들 수 없음`);
    }
    return { body, notes, ...(uniqueField ? { uniqueField } : {}) };
  };

  // ---------------------------------------------------------------- target, db, auth
  const health = java.endpoints.find((ep) => ep.method === "GET" && HEALTH.test(ep.path) && urlRule(ep)?.rule === "permitAll");
  let readyPath = "/actuator/health";
  if (health) {
    readyPath = health.path;
    found.push(`readiness: GET ${health.path} (익명 허용 ${at(urlRule(health)!.loc)}, ${at(health.loc)})`);
  } else if (project.deps.some((d) => /spring-boot-starter-actuator$/.test(d))) {
    ask("health", "익명 GET 헬스 엔드포인트를 찾지 못해 Actuator /actuator/health를 가정함. 익명 접근이 허용되는지 확인 필요", "target.readyPath");
  } else ask("health", "익명으로 열린 헬스 엔드포인트(예: /healthz)를 찾지 못함: target.readyPath를 직접 지정해야 함", "target.readyPath");
  const target: Record<string, unknown> = { start: project.start, cwd: opts.cwd, readyPath, isolation: "container", runtime: "jvm", build: project.build };
  found.push(`빌드: ${project.buildTool}${project.wrapper ? " (wrapper)" : ""} \`${project.build}\` → \`${project.jar.path}\` (${project.jar.source})`);
  provenance["target.readyPath"] = "ai-draft";
  for (const r of project.risks) ask("start", r.item, r.where);

  const migrations = facts.migrations.tool === "none" ? "app" : facts.migrations.tool;
  if (facts.migrations.tool === "none") ask("db", "Flyway/Liquibase migration을 찾지 못함: 앱(Hibernate ddl-auto 등)이 스키마를 만든다고 가정 (db.migrations: app). 원래 스키마 생성 방식 확인 필요", "db.migrations");
  const db = { kind: "postgres", migrations };
  found.push(`DB: PostgreSQL, migration ${migrations}${facts.migrations.files.length ? ` (${facts.migrations.files.join(", ")})` : ""}; 테이블 ${facts.tables.length}개 (${facts.tablesFrom === "entities" ? "JPA 엔티티 기준" : "migration 기준"})`);

  const rolesClaim = java.security.rolesClaim?.claim ?? "roles";
  const rolePrefix = java.security.rolePrefix?.prefix;
  if (!java.security.rolesClaim && adminRole) {
    ask("auth", `JWT의 권한 claim 매핑(JwtAuthenticationConverter)을 찾지 못함: 기본값 "${rolesClaim}" claim으로 가정. Spring 기본은 scope/scp → SCOPE_ 이므로 hasRole 규칙과 맞지 않을 수 있음`, "auth.claims.roles");
  }
  const auth: Record<string, unknown> = {
    type: "jwt-issuer",
    // The converter's authority prefix (e.g. ROLE_) is added by the app; the token carries bare role names, and
    // auth.claims.roles.prefix means "prefix inside the token value", so it is not emitted here.
    claims: { subject: java.principal.subject, roles: { claim: rolesClaim } },
  };
  provenance["auth.claims"] = "ai-draft";
  evidence.push({ resource: "(auth)", field: "claims.subject", value: java.principal.subject, where: java.principal.loc ? at(java.principal.loc) : "-", status: java.principal.loc ? "코드 근거" : "기본값", note: java.principal.why });
  if (java.security.rolesClaim) evidence.push({ resource: "(auth)", field: "claims.roles", value: `${rolesClaim}${rolePrefix ? ` → ${rolePrefix}*` : ""}`, where: at(java.security.rolesClaim.loc), status: "코드 근거" });
  if (appConfig.keys.some((k) => /resourceserver\.jwt\.audiences/.test(k))) ask("auth", "application 설정에 jwt.audiences가 있음: auth.audience를 앱이 기대하는 값으로 지정해야 함", "auth.audience");
  found.push(`인증: OAuth2 Resource Server JWT, sub = ${java.principal.subject} (${java.principal.why})`);
  if (ms.enabled) found.push(`메서드 보안: ${ms.annotation} 활성 (${at(ms.loc!)})`);
  else if (java.endpoints.some((e) => e.guards.length)) found.push("메서드 보안: 비활성 (@EnableMethodSecurity 없음) — @PreAuthorize 등은 적용되지 않음");

  // ---------------------------------------------------------------- resources
  const resources: Record<string, unknown>[] = [];
  const used = new Set<string>();
  for (const ep of java.endpoints) {
    const route = `${ep.method} ${ep.path}`;
    const where = at(ep.loc);
    if (ep.anyMethod) {
      inventory.push({ route: `* ${ep.path}`, where, reason: "HTTP 메서드가 지정되지 않은 @RequestMapping: 시험 대상 메서드를 정할 수 없음" });
      continue;
    }
    const rule = urlRule(ep);
    const id = resourceId(ep.method, ep.path, used);
    const ev = (field: string, value: string, w: string, status: EvidenceStatus, note?: string) => evidence.push({ resource: id, field, value, where: w, status, ...(note ? { note } : {}) });

    // public
    if (rule?.rule === "permitAll") {
      if (ep.method === "GET") {
        resources.push({ id, route, public: true });
        provenance[`resources.${id}.public`] = "ai-draft";
        ev("public", "true", at(rule.loc), "코드 근거", "requestMatchers(...).permitAll()");
        inventory.push({ route, where, resource: id });
      } else {
        used.delete(id);
        inventory.push({ route, where, reason: `익명 허용(permitAll, ${at(rule.loc)})된 쓰기 API: 의도인지 확인 필요` });
        policyQuestions.push({ route, what: "익명에게 열린 쓰기 API", where: at(rule.loc) });
      }
      continue;
    }

    // path params
    const pathParams: Record<string, { table: string; column?: string }> = {};
    let unmapped: string | undefined;
    for (const v of ep.pathVars) {
      const r = varTable(ep, v);
      if (r.table) {
        pathParams[v] = { table: r.table, ...(r.column ? { column: r.column } : {}) };
        ev(`pathParams.${v}`, r.column ? `${r.table}.${r.column}` : r.table, r.where, r.status, r.status === "기본값" ? "경로 변수 이름으로 연결" : r.status === "LLM 제안" ? "LLM이 연결, 정적 분석 결과와 대조해 통과" : undefined);
      } else unmapped ??= v;
    }
    if (unmapped) {
      used.delete(id);
      uncertain.push({ kind: "pathParam", route, param: unmapped, where, files: [...new Set([ep.loc.file, ...ep.access.map((a) => a.loc.file)])] });
      inventory.push({ route, where, reason: `경로 변수 {${unmapped}}가 어떤 테이블의 값인지 알 수 없음` });
      untested.push({ route, reason: `path variable {${unmapped}} could not be linked to a table (${where})` });
      continue;
    }

    // primary table and owner
    const lastVar = ep.pathVars.at(-1);
    const endsWithVar = /\}$/.test(ep.path);
    const dto = dtoTable(ep.returnType);
    const accessTables = ep.access.filter((a) => a.method !== "save").map((a) => entityTable(a.entity)).filter((t): t is string => !!t);
    let primary = endsWithVar && lastVar ? pathParams[lastVar]!.table : (dto ?? accessTables.at(-1));
    if (primary && primary === usersTable && !dto && !ep.access.some((a) => entityTable(a.entity) === usersTable)) primary = undefined;
    const write = ep.method !== "GET";
    // a create under a parent (POST /projects/{id}/documents): ownership is the parent's
    const ownerTable = ep.method === "POST" && !endsWithVar ? (lastVar ? pathParams[lastVar]!.table : undefined) : primary;
    const scope = ownerTable ? scopeOf(ownerTable) : undefined;
    const owner = scope && ownerTable ? { table: ownerTable, column: scope.column, scope: scope.scope } : undefined;

    if (ep.method === "GET" && ep.pathVars.length && !owner) {
      used.delete(id);
      inventory.push({ route, where, reason: `소유 테이블/컬럼을 찾지 못해 접근 기대값을 정할 수 없음 (${primary ?? "테이블 불명"})` });
      untested.push({ route, reason: `no owner column found for ${primary ?? "the returned data"} (${where})` });
      continue;
    }

    // roles
    let urlRoles: string[] | undefined;
    if (rule && /^has(?:Any)?Role$/.test(rule.rule)) urlRoles = rule.args.map((a) => a.replace(/^ROLE_/, ""));
    else if (rule && /^has(?:Any)?Authority$/.test(rule.rule)) {
      urlRoles = rule.args.filter((a) => a.startsWith("ROLE_")).map((a) => a.slice(5));
      if (rule.args.some((a) => !a.startsWith("ROLE_"))) policyQuestions.push({ route, what: `ROLE_ 접두사 없는 authority 조건 ${rule.args.join(", ")}: 토큰 claim으로 재현 가능한지 확인 필요`, where: at(rule.loc) });
    } else if (rule?.rule === "access") policyQuestions.push({ route, what: "access(...) 커스텀 인가 규칙: 자동 해석하지 않음", where: at(rule.loc) });
    let methodRoles: string[] | undefined;
    let inactiveRoles: string[] | undefined;
    let guardWhere: string | undefined;
    for (const g of ep.guards) {
      if (!g.simple) {
        policyQuestions.push({ route, what: `역할 외 조건이 있는 @${g.kind}("${g.expr}"): 자동 해석하지 않음${guardActive(g) ? "" : " (게다가 메서드 보안이 비활성이라 적용되지 않음)"}`, where: at(g.loc) });
        continue;
      }
      guardWhere = at(g.loc);
      if (guardActive(g)) methodRoles = g.roles;
      else {
        inactiveRoles = g.roles;
        const why = `@${g.kind}(${g.roles.join(", ")})가 있지만 ${g.kind === "Secured" ? "securedEnabled" : g.kind === "RolesAllowed" ? "jsr250Enabled" : "@EnableMethodSecurity"}가 없어 적용되지 않음`;
        inactiveGuards.push({ route, what: why, where: at(g.loc) });
        likelyFindings.push({ route, what: `비활성 가드: ${g.roles.join("/")} 아닌 사용자도 실행 가능할 가능성이 높음 (${why})`, where: at(g.loc) });
      }
    }
    let roles: string[] | undefined;
    if (urlRoles && methodRoles) roles = urlRoles.filter((r) => methodRoles!.includes(r));
    else roles = urlRoles ?? methodRoles ?? inactiveRoles;
    let roleStatus: EvidenceStatus = urlRoles || methodRoles ? "코드 근거" : "비활성 가드";
    let roleWhere = urlRoles ? at(rule!.loc) : (guardWhere ?? where);
    if (!roles?.length && adminRole && /\/admin(?:\/|$)/i.test(ep.path)) {
      roles = [adminRole];
      roleStatus = "정책 확인 필요";
      roleWhere = rule ? at(rule.loc) : where;
      policyQuestions.push({ route, what: `관리자 경로(/admin)인데 역할 조건이 없음: ${adminRole} 전용으로 가정 (아니라면 roles를 지울 것)`, where: roleWhere });
      likelyFindings.push({ route, what: `역할 검사 누락 의심: /admin 경로에 hasRole 등 역할 조건이 없음`, where: roleWhere });
    }

    const res: Record<string, unknown> = { id, route, action: ACTION[ep.method] };
    if (owner) {
      res.owner = owner;
      provenance[`resources.${id}.owner`] = "ai-draft";
      ev("owner", `${owner.table}.${owner.column} (${owner.scope === "user" ? "사용자 소유" : "조직 소유"})`, scope!.where, scope!.status, scope!.why);
    }
    if (Object.keys(pathParams).length) {
      res.pathParams = pathParams;
      provenance[`resources.${id}.pathParams`] = "ai-draft";
    }
    if (roles?.length) {
      res.roles = roles;
      provenance[`resources.${id}.roles`] = "ai-draft";
      ev("roles", roles.join(", "), roleWhere, roleStatus, roleStatus === "비활성 가드" ? "선언된 의도를 기대값으로 사용(실제로는 적용되지 않음)" : undefined);
    }

    // required query parameters
    const reqQuery = ep.queryParams.filter((q) => q.required);
    if (reqQuery.length) res.query = Object.fromEntries(reqQuery.map((q) => [q.name, /^(?:int|long|Integer|Long)$/.test(simpleType(q.type)) ? "1" : "$unique"]));

    // body + write verification
    if (write) {
      res.safe = true;
      provenance[`resources.${id}.safe`] = "ai-draft";
      ev("safe", "true", where, "기본값", "쓰기 요청은 실행별 일회성 DB에서만 보냄");
      let uniqueField: string | undefined;
      let bodyKeys: string[] = [];
      if (ep.bodyType) {
        const d = java.dtos.get(ep.bodyType);
        if (d) {
          const b = bodyFor(d);
          res.body = b.body;
          uniqueField = b.uniqueField;
          bodyKeys = Object.keys(b.body);
          provenance[`resources.${id}.body`] = "ai-draft";
          ev("body", JSON.stringify(b.body), at(d.loc), "코드 근거", `${d.name}의 Bean Validation 제약으로 만든 유효한 본문`);
          for (const n of b.notes) ask("route", n, at(d.loc));
        } else ask("route", `${route}: 요청 본문 형식 ${ep.bodyType}을(를) 찾지 못함 (본문 없이 보냄)`, where);
      }
      const wt = ep.method === "POST" && !endsWithVar ? primary : (endsWithVar && lastVar ? pathParams[lastVar]!.table : primary);
      if (wt && tables.has(wt)) {
        let column: string | undefined;
        if (ep.method === "DELETE") column = pkOf(wt);
        else {
          const cols = [uniqueField, ...bodyKeys].filter((k): k is string => !!k).map((k) => snake(k)).filter((c) => hasCol(wt, c));
          column = cols[0];
        }
        if (column) {
          const wv: Record<string, unknown> = { table: wt, column };
          if (ep.method === "POST" && !endsWithVar) {
            const parentT = lastVar ? pathParams[lastVar]!.table : undefined;
            const fk = parentT ? tables.get(wt)!.columns.find((c) => c.references?.table === parentT) : undefined;
            const orgC = tables.get(wt)!.columns.find((c) => isOrgCol(wt, c.name));
            if (fk && parentT) wv.where = { [fk.name]: `$id:${parentT}` };
            else if (orgC) wv.where = { [orgC.name]: "$orgId" };
          }
          res.writeVerify = wv;
          provenance[`resources.${id}.writeVerify`] = "ai-draft";
          ev("writeVerify", `${wt}.${column}${wv.where ? ` where ${JSON.stringify(wv.where)}` : ""}`, where, "기본값", "상태 코드가 아니라 DB 변화로 쓰기 성공 여부를 판단");
        } else ask("route", `${route}: 쓰기 결과를 DB에서 확인할 컬럼을 찾지 못함 (writeVerify 없음: 2xx만으로는 판정하지 않음)`, where);
      }
    }

    // expectations
    const denyAll = rule?.rule === "denyAll";
    const expect: Record<string, string> = denyAll
      ? { owner: "deny", other: "deny", anonymous: "deny" }
      : { owner: "allow", other: "deny", anonymous: "deny" };
    if (owner && !denyAll) expect.sameOrgOther = owner.scope === "user" ? "deny" : "allow";
    if (roles?.length && !denyAll) expect.member = "deny";
    res.expect = expect;
    provenance[`resources.${id}.expect`] = "ai-draft";
    ev("expect.anonymous", "deny", rule ? at(rule.loc) : where, rule && rule.rule !== "permitAll" ? "코드 근거" : "기본값", rule ? `requestMatchers → ${rule.rule}` : "일치하는 requestMatcher 없음");

    // ownership consistency: does THIS handler use the ownership condition the code declares for the table?
    if (owner) {
      const checked = ep.access.filter((a) => entityTable(a.entity) === owner.table);
      const enforcing = checked.find((a) => a.predicates.includes(owner.column));
      const singleRow = endsWithVar || (ep.method === "POST" && !!lastVar);
      if (enforcing) {
        ev("expect.other", "deny", at(enforcing.loc), "코드 근거", `${enforcing.repository}.${enforcing.method}가 ${owner.column} 조건으로 조회 (${enforcing.via})`);
      } else if (checked.length && singleRow && scope!.status === "코드 근거") {
        const a = checked.find((x) => x.method !== "save" && x.method !== "delete") ?? checked[0]!;
        ev("expect.other", "deny", scope!.where, "코드 근거", `${owner.table}의 소유권 규칙(${scope!.why})에 따른 기대값`);
        likelyFindings.push({ route, what: `소유권 조건 누락 의심: ${a.via} → ${a.repository}.${a.method}(${a.predicates.join(", ") || "조건 없음"})에 ${owner.column} 조건이 없음 (같은 테이블의 다른 쿼리는 ${owner.column}로 제한)`, where: at(a.loc) });
      } else {
        ev("expect.other", "deny", scope!.where, "정책 확인 필요", "이 경로에서 소유권 조건을 직접 확인하지 못함: 보수적 기본값");
        if (scope!.status !== "코드 근거") policyQuestions.push({ route, what: `다른 조직의 접근을 막아야 하는지 코드 근거가 없음 (${scope!.why})`, where: scope!.where });
      }
      if (owner.scope === "user") ev("expect.sameOrgOther", "deny", scope!.where, scope!.status, "같은 조직의 다른 사용자도 접근 불가 (사용자 소유)");
    } else if (!denyAll) {
      ev("expect.other", "deny", where, "기본값", "소유 데이터가 없는 API: 다른 조직 시험 대상 아님");
    }
    if (roles?.length && !denyAll) ev("expect.member", "deny", roleWhere, roleStatus);

    resources.push(res);
    inventory.push({ route, where, resource: id });
  }

  // ---------------------------------------------------------------- secrets, checks, assembly
  const allCols = [...new Set(facts.tables.flatMap((t) => t.columns.map((c) => c.name)))];
  const sensitiveExtra = allCols.filter((n) => SECRETISH.test(n) && !/_id$/i.test(n) && !isSensitiveColumn(n, DEFAULT_SENSITIVE)).sort();
  const secrets: Record<string, unknown> = {};
  if (sensitiveExtra.length) secrets.sensitiveColumns = [...DEFAULT_SENSITIVE, ...sensitiveExtra];
  const canaries = appConfig.envPlaceholders.filter((n) => /SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL/.test(n) && !/DATASOURCE|JWT_JWK|ISSUER/.test(n));
  if (canaries.length) secrets.envCanaries = canaries;

  const config: Record<string, unknown> = {
    version: 1,
    target,
    db,
    auth,
    personas,
    resources,
    checks: ["bola", "unauth", "secrets"],
    ...(Object.keys(secrets).length ? { secrets } : {}),
    mode: "report",
    llm: { provider: "anthropic", data: opts.llmData },
    provenance,
  };

  found.push(`API: ${java.endpoints.length}개 발견, ${resources.length}개를 설정에 넣음`);
  if (!ms.enabled && java.endpoints.some((e) => e.guards.length)) ask("expect", `메서드 보안이 꺼져 있어 @PreAuthorize/@Secured가 무시됨: ${inactiveGuards.length}개 API의 선언된 역할 제한이 실제로 적용되지 않음`, inactiveGuards[0]?.where);
  const draftCount = resources.filter((r) => r.expect).length;
  if (draftCount) ask("expect", `기대 규칙 ${draftCount}개(resources[].expect/roles/owner)는 코드에 선언된 정책과 보수적 기본값으로 만든 초안(ai-draft)이다. 확인 후 provenance를 confirmed로 바꿀 것`, "resources[].expect");
  for (const q of policyQuestions) ask("expect", `정책 확인 필요: ${q.route} — ${q.what}`, q.where);

  let blocker: string | undefined;
  if (!java.endpoints.length) blocker = "no Spring MVC endpoints (@RestController / @Controller with @GetMapping, ...) were found";
  else if (!resources.length) blocker = "no endpoint could be put into the config (see the report for the reason per endpoint)";
  return { config, provenance, needsHuman, unsupported, untested, found, evidence, inventory, inactiveGuards, likelyFindings, policyQuestions, uncertain, ...(blocker ? { blocker } : {}) };
}

/** Loc helper for callers. */
export type { Loc, DataAccess };
