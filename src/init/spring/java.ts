import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { walkFiles } from "./detect.js";
import { allTypes, ann, annAttrs, annIds, annStrings, parseJava, simpleType, tokText, typeArgs, type Annotation, type JFile, type JMethod, type JType, type Tok } from "./javaparse.js";

/**
 * Structured FACTS from a Spring Boot repository's Java sources (deterministic, no LLM):
 * controllers and endpoints, request DTOs with Bean Validation constraints, security configuration
 * (filter chains, request matchers, JWT authority mapping, method security), JPA entities, repositories with the
 * ownership predicates of their queries, and the data each endpoint reaches (controller -> service -> repository).
 */

export interface Loc {
  file: string;
  line: number;
}
export const at = (l: Loc): string => `${l.file}:${l.line}`;

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface Guard {
  kind: "PreAuthorize" | "PostAuthorize" | "Secured" | "RolesAllowed";
  expr: string;
  /** Roles the expression requires (any of). Empty when the expression is not a plain role check. */
  roles: string[];
  /** Only role checks (hasRole/hasAnyRole/hasAuthority('ROLE_..')), nothing else. */
  simple: boolean;
  loc: Loc;
}

export interface Endpoint {
  method: HttpMethod;
  /** RequestMapping without a method: every method is mapped. */
  anyMethod: boolean;
  path: string;
  controller: string;
  handler: string;
  loc: Loc;
  pathVars: string[];
  queryParams: { name: string; required: boolean; type: string }[];
  bodyType?: string;
  returnType: string;
  guards: Guard[];
  /** Repository calls reachable from the handler (controller -> services -> repositories). */
  access: DataAccess[];
  /** The handler resolves the caller (principal resolver or Jwt parameter). */
  usesPrincipal: boolean;
}

export interface Constraint {
  name: string;
  attrs: Record<string, string>;
}
export interface DtoField {
  name: string;
  type: string;
  constraints: Constraint[];
}
export interface Dto {
  name: string;
  loc: Loc;
  fields: DtoField[];
}

export interface EntityField {
  name: string;
  column: string;
  type: string;
  id: boolean;
  generated?: string;
  relation?: { kind: string; target: string };
}
export interface Entity {
  name: string;
  table: string;
  loc: Loc;
  fields: EntityField[];
}

export interface RepoMethod {
  name: string;
  /** Columns compared in the query's WHERE (derived name or @Query). */
  predicates: string[];
  loc: Loc;
}
export interface Repository {
  name: string;
  entity: string;
  loc: Loc;
  methods: RepoMethod[];
}

export interface DataAccess {
  repository: string;
  entity: string;
  method: string;
  predicates: string[];
  /** Call site. */
  loc: Loc;
  /** Class.method the call is in. */
  via: string;
}

export interface Matcher {
  /** HTTP method restriction (requestMatchers(HttpMethod.GET, ...)). */
  method?: string;
  patterns: string[];
  anyRequest: boolean;
  rule: string;
  args: string[];
  loc: Loc;
}

export interface SecurityChain {
  bean: string;
  loc: Loc;
  order?: number;
  securityMatcher: string[];
  matchers: Matcher[];
  resourceServer: "jwt" | "opaque" | "none";
  formLogin?: Loc;
  httpBasic?: Loc;
  oauth2Login?: Loc;
  stateless: boolean;
  customFilters: { name: string; loc: Loc }[];
  customDecoder?: Loc;
}

export interface SecurityFacts {
  chains: SecurityChain[];
  methodSecurity: { enabled: boolean; prePost: boolean; secured: boolean; jsr250: boolean; loc?: Loc; annotation?: string };
  rolesClaim?: { claim: string; loc: Loc };
  rolePrefix?: { prefix: string; loc: Loc };
  principalClaim?: { claim: string; loc: Loc };
  jwtDecoderBeans: Loc[];
  /** OncePerRequestFilter / GenericFilterBean subclasses that read tokens themselves. */
  jwtFilters: { name: string; loc: Loc }[];
  webflux?: Loc;
}

export interface PrincipalFacts {
  resolver?: string;
  subject: "id" | "email" | "username";
  /** How the subject was decided. */
  why: string;
  loc?: Loc;
  userEntity?: string;
}

export interface JavaFacts {
  files: string[];
  endpoints: Endpoint[];
  dtos: Map<string, Dto>;
  enums: Map<string, string[]>;
  entities: Entity[];
  repositories: Repository[];
  security: SecurityFacts;
  principal: PrincipalFacts;
  /** Classes annotated @Mapper (MyBatis) or using JdbcTemplate for data reads. */
  otherDataAccess: { kind: string; loc: Loc }[];
  problems: string[];
}

const MAPPINGS: Record<string, HttpMethod | undefined> = { GetMapping: "GET", PostMapping: "POST", PutMapping: "PUT", PatchMapping: "PATCH", DeleteMapping: "DELETE", RequestMapping: undefined };
const CONSTRAINTS = new Set(["NotNull", "NotBlank", "NotEmpty", "Email", "Size", "Min", "Max", "Pattern", "Positive", "PositiveOrZero", "Negative", "NegativeOrZero", "Past", "PastOrPresent", "Future", "FutureOrPresent", "Digits", "DecimalMin", "DecimalMax", "Length", "AssertTrue", "AssertFalse"]);
const REPO_BASES = /^(?:JpaRepository|CrudRepository|ListCrudRepository|PagingAndSortingRepository|ListPagingAndSortingRepository|Repository|JpaSpecificationExecutor)$/;

export const snake = (s: string): string =>
  s
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
    .toLowerCase();

const joinPath = (a: string, b: string): string => {
  const p = `/${a}/${b}`.replace(/\/+/g, "/");
  return p.length > 1 ? p.replace(/\/$/, "") : p;
};

/** `{id:\d+}` -> `{id}` */
const normPath = (p: string): string => p.replace(/\{([A-Za-z_]\w*)\s*:[^}]*\}/g, "{$1}");

function constraintsOf(as: Annotation[]): Constraint[] {
  return as
    .filter((a) => CONSTRAINTS.has(a.name))
    .map((a) => {
      const attrs: Record<string, string> = {};
      for (const [k, v] of annAttrs(a)) attrs[k] = v.map((x) => x.v).join("");
      return { name: a.name, attrs };
    });
}

/** Roles in a SpEL guard: hasRole('A') / hasAnyRole('A','B') / hasAuthority('ROLE_A'). */
export function rolesOfExpr(expr: string): { roles: string[]; simple: boolean } {
  const roles: string[] = [];
  const re = /\b(hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\(([^)]*)\)/g;
  for (const m of expr.matchAll(re)) {
    for (const s of m[2]!.matchAll(/['"]([^'"]+)['"]/g)) {
      const v = s[1]!;
      if (m[1]!.endsWith("Role")) roles.push(v.replace(/^ROLE_/, ""));
      else if (v.startsWith("ROLE_")) roles.push(v.slice(5));
      else roles.push(v);
    }
  }
  const rest = expr
    .replace(re, "")
    .replace(/\b(?:or)\b|\|\||[()\s]/g, "")
    .trim();
  return { roles: [...new Set(roles)], simple: roles.length > 0 && rest === "" };
}

const CRITERIA_SUFFIX =
  /(?:AllIgnoreCase|IgnoreCase|NotContaining|Containing|StartingWith|StartsWith|EndingWith|EndsWith|NotLike|Like|NotIn|In|Between|LessThanEqual|LessThan|GreaterThanEqual|GreaterThan|After|Before|IsNotNull|NotNull|IsNull|Null|IsTrue|True|IsFalse|False|IsNotEmpty|IsEmpty|Not|Is|Equals|Exists|Regex|Matches|Within|Near)$/;

/** Column of an entity property path (`orgId`, `organization.id`, `Organization_Id`, `OrganizationId`). */
function columnOf(e: Entity | undefined, prop: string): string | undefined {
  if (!e) return undefined;
  const parts = prop.includes("_") ? prop.split("_") : prop.split(".");
  const lc = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
  const first = lc(parts[0]!);
  const direct = e.fields.find((f) => f.name === first);
  if (direct && parts.length === 1) return direct.column;
  if (direct?.relation && parts.length > 1) return direct.column; // relation.id -> join column
  // OrganizationId: longest field prefix + remainder
  for (const f of e.fields) {
    const cap = f.name.charAt(0).toUpperCase() + f.name.slice(1);
    if (parts.length === 1 && parts[0]!.startsWith(cap) && parts[0] !== cap && f.relation) return f.column;
  }
  return undefined;
}

function derivedPredicates(name: string, e: Entity | undefined): string[] | undefined {
  const pk = e?.fields.find((f) => f.id)?.column;
  if (/^(?:findById|getById|getReferenceById|existsById|deleteById|findAllById)$/.test(name)) return pk ? [pk] : ["id"];
  if (/^(?:findAll|count|save|saveAll|saveAndFlush|delete|deleteAll|flush)$/.test(name)) return [];
  const m = /^(?:find|read|get|query|search|stream|count|exists|delete|remove)\w*?By(.+)$/.exec(name);
  if (!m) return undefined;
  const criteria = m[1]!.replace(/OrderBy.*$/, "");
  return criteria
    .split(/(?<=[a-z0-9_])(?:And|Or)(?=[A-Z])/)
    .map((p) => {
      let x = p;
      for (let i = 0; i < 3; i++) x = x.replace(CRITERIA_SUFFIX, "") || x;
      return columnOf(e, x) ?? snake(x.replace(/_/g, ""));
    })
    .filter(Boolean);
}

function queryPredicates(q: string, native: boolean, e: Entity | undefined): string[] {
  const out: string[] = [];
  if (native) {
    for (const m of q.matchAll(/(?:\b\w+\.)?(\w+)\s*=\s*(?::\w+|\?\d*)/g)) out.push(m[1]!.toLowerCase());
  } else {
    for (const m of q.matchAll(/\b\w+\.([\w.]+)\s*=\s*(?::\w+|\?\d*)/g)) out.push(columnOf(e, m[1]!) ?? snake(m[1]!.replace(/\./g, "_")));
  }
  return [...new Set(out)];
}

export function readJava(root: string, moduleDir = "."): JavaFacts {
  const base = join(root, moduleDir, "src", "main", "java");
  const files = walkFiles(base, (n) => n.endsWith(".java"));
  const problems: string[] = [];
  const parsed: JFile[] = [];
  for (const f of files) {
    try {
      parsed.push(parseJava(readFileSync(f, "utf8"), relative(root, f)));
    } catch (e) {
      problems.push(`${relative(root, f)}: could not be read (${(e as Error).message})`);
    }
  }
  const types = parsed.flatMap(allTypes);
  const byName = new Map<string, JType>();
  for (const t of types) if (!byName.has(t.name) || t.kind === "class") byName.set(t.name, t);

  // ---- constants (static final String X = "...")
  const consts = new Map<string, string>();
  for (const t of types) for (const f of t.fields) if (f.modifiers.includes("static") && f.modifiers.includes("final") && f.init.length === 1 && f.init[0]!.k === "str") consts.set(f.name, f.init[0]!.v);

  // ---- enums, DTOs
  const enums = new Map<string, string[]>();
  for (const t of types) if (t.kind === "enum") enums.set(t.name, t.enumConstants);
  const dtos = new Map<string, Dto>();
  for (const t of types) {
    if (t.kind === "record") dtos.set(t.name, { name: t.name, loc: { file: t.file, line: t.line }, fields: t.components.map((c) => ({ name: c.name, type: c.type, constraints: constraintsOf(c.annotations) })) });
    else if (t.kind === "class" && !ann(t.annotations, "Entity", "RestController", "Controller", "Service", "Component", "Configuration", "Repository")) {
      const fields = t.fields.filter((f) => !f.modifiers.includes("static")).map((f) => ({ name: f.name, type: f.type, constraints: constraintsOf(f.annotations) }));
      if (fields.length) dtos.set(t.name, { name: t.name, loc: { file: t.file, line: t.line }, fields });
    }
  }

  // ---- entities
  const entities: Entity[] = [];
  for (const t of types) {
    if (t.kind !== "class" || !ann(t.annotations, "Entity")) continue;
    const tableAnn = ann(t.annotations, "Table");
    const table = (tableAnn && annStrings(tableAnn, ["name", "value"], consts)[0]) || snake(t.name);
    const fields: EntityField[] = [];
    for (const f of t.fields) {
      if (f.modifiers.includes("static") || f.modifiers.includes("transient") || ann(f.annotations, "Transient")) continue;
      const rel = ann(f.annotations, "ManyToOne", "OneToOne", "OneToMany", "ManyToMany");
      if (rel && (rel.name === "OneToMany" || rel.name === "ManyToMany")) continue;
      const col = ann(f.annotations, "Column");
      const jc = ann(f.annotations, "JoinColumn");
      const colName = (jc && annStrings(jc, ["name"], consts)[0]) || (col && annStrings(col, ["name"], consts)[0]) || (rel ? `${snake(f.name)}_id` : snake(f.name));
      const gen = ann(f.annotations, "GeneratedValue");
      fields.push({
        name: f.name,
        column: colName.toLowerCase(),
        type: f.type,
        id: !!ann(f.annotations, "Id", "EmbeddedId"),
        ...(gen ? { generated: annIds(gen, "strategy").pop() ?? "AUTO" } : {}),
        ...(rel ? { relation: { kind: rel.name, target: simpleType(f.type) } } : {}),
      });
    }
    entities.push({ name: t.name, table: table.toLowerCase(), loc: { file: t.file, line: t.line }, fields });
  }
  const entityByName = new Map(entities.map((e) => [e.name, e]));

  // ---- repositories
  const repositories: Repository[] = [];
  for (const t of types) {
    if (t.kind !== "interface") continue;
    const baseName = simpleType(t.extends.split(/,(?![^<]*>)/)[0] ?? "");
    if (!REPO_BASES.test(baseName)) continue;
    const entity = simpleType(typeArgs(t.extends)[0] ?? "");
    const e = entityByName.get(entity);
    const methods: RepoMethod[] = t.methods.map((m) => {
      const q = ann(m.annotations, "Query");
      let predicates: string[];
      if (q) {
        const native = annAttrs(q).get("nativeQuery")?.some((x) => x.v === "true") ?? false;
        predicates = queryPredicates(annStrings(q, ["value"], consts).join(" "), native, e);
      } else predicates = derivedPredicates(m.name, e) ?? [];
      return { name: m.name, predicates, loc: { file: t.file, line: m.line } };
    });
    repositories.push({ name: t.name, entity, loc: { file: t.file, line: t.line }, methods });
  }
  const repoByName = new Map(repositories.map((r) => [r.name, r]));

  // ---- security
  const security = readSecurity(types, consts);

  // ---- principal resolution (sub -> user row)
  const principal = readPrincipal(types, repoByName, security);

  // ---- data access chains
  const implOf = (iface: string): JType | undefined => types.find((t) => t.kind === "class" && t.implements.split(",").some((x) => simpleType(x.trim()) === iface));
  const classOf = (name: string): JType | undefined => {
    const t = byName.get(name);
    if (t && t.kind === "interface" && !repoByName.has(name)) return implOf(name) ?? t;
    return t;
  };
  const fieldTypes = (t: JType): Map<string, string> => {
    const m = new Map<string, string>();
    for (const f of t.fields) m.set(f.name, simpleType(f.type));
    return m;
  };
  const accessCache = new Map<string, { access: DataAccess[]; principal: boolean }>();
  const reach = (t: JType, m: JMethod, depth: number, seen: Set<string>): { access: DataAccess[]; principal: boolean } => {
    const key = `${t.name}.${m.name}.${m.params.length}`;
    if (seen.has(key) || depth > 5) return { access: [], principal: false };
    seen.add(key);
    const cached = accessCache.get(key);
    if (cached) return cached;
    const access: DataAccess[] = [];
    let usesPrincipal = m.params.some((p) => ["Jwt", "Authentication", "JwtAuthenticationToken", "Principal"].includes(simpleType(p.type)) || !!ann(p.annotations, "AuthenticationPrincipal"));
    const fields = fieldTypes(t);
    const b = m.body;
    for (let i = 0; i < b.length; i++) {
      const x = b[i]!;
      if (x.k !== "id") continue;
      const prevDot = b[i - 1]?.v === "." && b[i - 2]?.v !== "this";
      // field.method(
      if (!prevDot && b[i + 1]?.v === "." && b[i + 2]?.k === "id" && b[i + 3]?.v === "(" && fields.has(x.v)) {
        const ft = fields.get(x.v)!;
        const callee = b[i + 2]!.v;
        const repo = repoByName.get(ft);
        if (repo) {
          const rm = repo.methods.find((y) => y.name === callee);
          const preds = rm?.predicates ?? derivedPredicates(callee, entityByName.get(repo.entity)) ?? [];
          access.push({ repository: repo.name, entity: repo.entity, method: callee, predicates: preds, loc: { file: t.file, line: x.line }, via: `${t.name}.${m.name}` });
        } else if (principal.resolver && ft === principal.resolver) {
          usesPrincipal = true;
        } else {
          const ct = classOf(ft);
          if (ct) for (const cm of ct.methods.filter((y) => y.name === callee && !y.constructor)) {
            const r = reach(ct, cm, depth + 1, seen);
            access.push(...r.access);
            usesPrincipal ||= r.principal;
          }
        }
        i += 2;
        continue;
      }
      // local call: method(
      if (!prevDot && b[i + 1]?.v === "(" && b[i - 1]?.v !== "new") {
        for (const cm of t.methods.filter((y) => y.name === x.v && !y.constructor && y !== m)) {
          const r = reach(t, cm, depth + 1, seen);
          access.push(...r.access);
          usesPrincipal ||= r.principal;
        }
      }
    }
    const r = { access, principal: usesPrincipal };
    accessCache.set(key, r);
    return r;
  };

  // ---- endpoints
  const endpoints: Endpoint[] = [];
  for (const t of types) {
    if (t.kind !== "class" || !ann(t.annotations, "RestController", "Controller")) continue;
    const cm = ann(t.annotations, "RequestMapping");
    const bases = cm ? annStrings(cm, ["value", "path"], consts) : [];
    const classGuards = guardsOf(t.annotations, { file: t.file, line: t.line });
    for (const m of t.methods) {
      const mapping = m.annotations.find((a) => a.name in MAPPINGS);
      if (!mapping) continue;
      let methods: HttpMethod[] = MAPPINGS[mapping.name] ? [MAPPINGS[mapping.name]!] : (annIds(mapping, "method").filter((v) => ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(v)) as HttpMethod[]);
      const anyMethod = !methods.length;
      if (anyMethod) methods = ["GET"];
      const paths = annStrings(mapping, ["value", "path"], consts);
      const guards = [...classGuards.filter((g) => !guardsOf(m.annotations, { file: t.file, line: m.line }).some((x) => x.kind === g.kind)), ...guardsOf(m.annotations, { file: t.file, line: m.line })];
      const pathVars: string[] = [];
      const queryParams: Endpoint["queryParams"] = [];
      let bodyType: string | undefined;
      for (const p of m.params) {
        const pv = ann(p.annotations, "PathVariable");
        const rp = ann(p.annotations, "RequestParam");
        const rb = ann(p.annotations, "RequestBody");
        if (pv) pathVars.push(annStrings(pv, ["value", "name"], consts)[0] ?? p.name);
        else if (rp) {
          const attrs = annAttrs(rp);
          const required = !(attrs.get("required")?.some((x) => x.v === "false") ?? false) && !attrs.has("defaultValue") && !/^Optional</.test(p.type);
          queryParams.push({ name: annStrings(rp, ["value", "name"], consts)[0] ?? p.name, required, type: p.type });
        } else if (rb) bodyType = simpleType(p.type);
      }
      const reached = reach(t, m, 0, new Set());
      for (const base of bases.length ? bases : [""]) {
        for (const sub of paths.length ? paths : [""]) {
          for (const method of methods) {
            endpoints.push({
              method,
              anyMethod,
              path: normPath(joinPath(base, sub)),
              controller: t.name,
              handler: m.name,
              loc: { file: t.file, line: m.line },
              pathVars,
              queryParams,
              ...(bodyType ? { bodyType } : {}),
              returnType: m.returnType,
              guards,
              access: reached.access,
              usesPrincipal: reached.principal,
            });
          }
        }
      }
    }
  }

  const otherDataAccess: JavaFacts["otherDataAccess"] = [];
  for (const t of types) {
    if (ann(t.annotations, "Mapper")) otherDataAccess.push({ kind: "MyBatis @Mapper", loc: { file: t.file, line: t.line } });
  }

  return { files: files.map((f) => relative(root, f)), endpoints, dtos, enums, entities, repositories, security, principal, otherDataAccess, problems };
}

function guardsOf(as: Annotation[], loc: Loc): Guard[] {
  const out: Guard[] = [];
  for (const a of as) {
    if (a.name === "PreAuthorize" || a.name === "PostAuthorize") {
      const expr = annStrings(a, ["value"]).join(" ");
      out.push({ kind: a.name, expr, ...rolesOfExpr(expr), loc: { file: loc.file, line: a.line } });
    } else if (a.name === "Secured" || a.name === "RolesAllowed") {
      const vals = annStrings(a, ["value"]);
      out.push({ kind: a.name, expr: vals.join(", "), roles: vals.map((v) => v.replace(/^ROLE_/, "")), simple: vals.length > 0, loc: { file: loc.file, line: a.line } });
    }
  }
  return out;
}

function stringsIn(ts: Tok[], consts: Map<string, string>): string[] {
  const out: string[] = [];
  ts.forEach((x, i) => {
    if (x.k === "str") out.push(x.v);
    else if (x.k === "id" && consts.has(x.v) && ts[i - 1]?.v !== ".") out.push(consts.get(x.v)!);
  });
  return out;
}

/** Index just past the `)` matching the `(` at `from`. */
function closeParen(b: Tok[], from: number): number {
  let d = 0;
  for (let j = from; j < b.length; j++) {
    if (b[j]!.k !== "op") continue;
    if (b[j]!.v === "(") d++;
    else if (b[j]!.v === ")" && --d === 0) return j + 1;
  }
  return b.length;
}

function readSecurity(types: JType[], consts: Map<string, string>): SecurityFacts {
  const chains: SecurityChain[] = [];
  const jwtDecoderBeans: Loc[] = [];
  const jwtFilters: SecurityFacts["jwtFilters"] = [];
  let methodSecurity: SecurityFacts["methodSecurity"] = { enabled: false, prePost: false, secured: false, jsr250: false };
  let rolesClaim: SecurityFacts["rolesClaim"];
  let rolePrefix: SecurityFacts["rolePrefix"];
  let principalClaim: SecurityFacts["principalClaim"];
  let webflux: Loc | undefined;

  for (const t of types) {
    const ems = ann(t.annotations, "EnableMethodSecurity");
    const egms = ann(t.annotations, "EnableGlobalMethodSecurity");
    if (ems || egms) {
      const a = (ems ?? egms)!;
      const attrs = annAttrs(a);
      const flag = (k: string, dflt: boolean) => (attrs.has(k) ? attrs.get(k)!.some((x) => x.v === "true") : dflt);
      const prePost = flag("prePostEnabled", !!ems);
      const secured = flag("securedEnabled", false);
      const jsr250 = flag("jsr250Enabled", false);
      methodSecurity = { enabled: prePost || secured || jsr250, prePost, secured, jsr250, loc: { file: t.file, line: a.line }, annotation: `@${a.name}` };
    }
    if (ann(t.annotations, "EnableWebFluxSecurity", "EnableReactiveMethodSecurity")) webflux = { file: t.file, line: t.line };
    if (t.kind === "class" && /^(?:OncePerRequestFilter|GenericFilterBean|AbstractAuthenticationProcessingFilter|BasicAuthenticationFilter)$/.test(simpleType(t.extends))) {
      const text = t.methods.flatMap((m) => m.body.map((x) => x.v)).join(" ");
      if (/Bearer|Authorization|Jwt|jwt|token/i.test(text + t.name)) jwtFilters.push({ name: t.name, loc: { file: t.file, line: t.line } });
    }

    for (const m of t.methods) {
      const b = m.body;
      const loc = (x: Tok): Loc => ({ file: t.file, line: x.line });
      if (ann(m.annotations, "Bean") && /^(?:JwtDecoder|ReactiveJwtDecoder|NimbusJwtDecoder)$/.test(simpleType(m.returnType))) jwtDecoderBeans.push({ file: t.file, line: m.line });
      if (simpleType(m.returnType) === "SecurityWebFilterChain") webflux ??= { file: t.file, line: m.line };
      // JWT authority / principal claim mapping
      for (let i = 0; i < b.length; i++) {
        const x = b[i]!;
        if (x.k !== "id" || b[i + 1]?.v !== "(") continue;
        const arg = b[i + 2];
        if (x.v === "setAuthoritiesClaimName" && arg?.k === "str") rolesClaim = { claim: arg.v, loc: loc(x) };
        if (x.v === "setAuthorityPrefix" && arg?.k === "str") rolePrefix = { prefix: arg.v, loc: loc(x) };
        if (x.v === "setPrincipalClaimName" && arg?.k === "str") principalClaim = { claim: arg.v, loc: loc(x) };
      }
      // hand-written Converter<Jwt, ...>: getClaimAsStringList("roles") + "ROLE_" + r
      if (/Converter<\s*Jwt/.test(t.implements) || (m.params.some((p) => simpleType(p.type) === "Jwt") && b.some((x) => x.k === "str" && x.v.startsWith("ROLE_")))) {
        for (let i = 0; i < b.length; i++) {
          const x = b[i]!;
          if (x.k === "id" && /^getClaim(?:AsStringList|AsString|AsMap)?$|^getClaim$/.test(x.v) && b[i + 2]?.k === "str" && !rolesClaim) rolesClaim = { claim: b[i + 2]!.v, loc: loc(x) };
          if (x.k === "str" && /^ROLE_$/.test(x.v) && !rolePrefix) rolePrefix = { prefix: "ROLE_", loc: loc(x) };
        }
      }

      const isChain = simpleType(m.returnType) === "SecurityFilterChain" || b.some((x) => x.v === "authorizeHttpRequests" || x.v === "authorizeRequests");
      if (!isChain || simpleType(m.returnType) === "SecurityWebFilterChain") continue;
      const orderAnn = ann(m.annotations, "Order");
      const chain: SecurityChain = {
        bean: m.name,
        loc: { file: t.file, line: m.line },
        ...(orderAnn ? { order: Number(orderAnn.args.find((x) => x.k === "num")?.v ?? NaN) } : {}),
        securityMatcher: [],
        matchers: [],
        resourceServer: "none",
        stateless: false,
        customFilters: [],
      };
      for (let i = 0; i < b.length; i++) {
        const x = b[i]!;
        if (x.k !== "id" || b[i + 1]?.v !== "(") continue;
        const end = closeParen(b, i + 1);
        const args = b.slice(i + 2, end - 1);
        switch (x.v) {
          case "securityMatcher":
          case "securityMatchers":
            chain.securityMatcher.push(...stringsIn(args, consts));
            break;
          case "requestMatchers":
          case "antMatchers":
          case "mvcMatchers":
          case "anyRequest": {
            // rule follows: ).rule(args)
            if (b[end]?.v === "." && b[end + 1]?.k === "id" && b[end + 2]?.v === "(") {
              const rEnd = closeParen(b, end + 2);
              const hm = args.findIndex((y) => y.v === "HttpMethod");
              const method = hm >= 0 && args[hm + 1]?.v === "." ? args[hm + 2]?.v : undefined;
              chain.matchers.push({
                ...(method ? { method } : {}),
                patterns: x.v === "anyRequest" ? [] : stringsIn(args, consts),
                anyRequest: x.v === "anyRequest",
                rule: b[end + 1]!.v,
                args: stringsIn(b.slice(end + 3, rEnd - 1), consts),
                loc: loc(x),
              });
              i = rEnd - 1;
            }
            break;
          }
          case "oauth2ResourceServer": {
            const inner = args.map((y) => y.v);
            chain.resourceServer = inner.includes("opaqueToken") ? "opaque" : "jwt";
            const dec = args.findIndex((y) => y.v === "decoder" || y.v === "jwkSetUri");
            if (dec >= 0 && args[dec]!.v === "decoder") chain.customDecoder = loc(args[dec]!);
            break;
          }
          case "formLogin":
            chain.formLogin = loc(x);
            break;
          case "httpBasic":
            if (!args.some((y) => y.v === "disable")) chain.httpBasic = loc(x);
            break;
          case "oauth2Login":
            chain.oauth2Login = loc(x);
            break;
          case "sessionCreationPolicy":
            if (args.some((y) => y.v === "STATELESS")) chain.stateless = true;
            break;
          case "addFilterBefore":
          case "addFilterAt":
          case "addFilterAfter": {
            const name = args[0]?.v === "new" ? args[1]?.v : args[0]?.v;
            if (name) chain.customFilters.push({ name, loc: loc(x) });
            break;
          }
        }
      }
      // a formLogin(...) customizer that only disables it is not a login
      if (chain.formLogin && b.some((y, j) => y.v === "formLogin" && b.slice(j, j + 6).some((z) => z.v === "disable"))) delete chain.formLogin;
      chains.push(chain);
    }
  }
  return { chains, methodSecurity, ...(rolesClaim ? { rolesClaim } : {}), ...(rolePrefix ? { rolePrefix } : {}), ...(principalClaim ? { principalClaim } : {}), jwtDecoderBeans, jwtFilters, ...(webflux ? { webflux } : {}) };
}

function readPrincipal(types: JType[], repos: Map<string, Repository>, sec: SecurityFacts): PrincipalFacts {
  if (sec.principalClaim) {
    const c = sec.principalClaim.claim;
    const subject = /mail/i.test(c) ? "email" : /user|login|name/i.test(c) ? "username" : "id";
    return { subject, why: `JwtAuthenticationConverter.setPrincipalClaimName("${c}")`, loc: sec.principalClaim.loc };
  }
  for (const t of types) {
    if (t.kind !== "class") continue;
    for (const m of t.methods) {
      const b = m.body;
      const subjIdx = b.findIndex((x) => x.v === "getSubject" || x.v === "getName");
      const claimIdx = b.findIndex((x, i) => x.v === "getClaim" || x.v === "getClaimAsString" ? b[i + 2]?.k === "str" : false);
      if (subjIdx < 0 && claimIdx < 0) continue;
      if (!b.some((x) => x.v === "Jwt" || x.v === "SecurityContextHolder" || x.v === "Authentication" || x.v === "JwtAuthenticationToken") && !m.params.some((p) => /Jwt|Authentication/.test(p.type))) continue;
      const fields = new Map(t.fields.map((f) => [f.name, simpleType(f.type)]));
      const repoOf = (name: string) => repos.get(fields.get(name) ?? "");
      // calls in this class, in source order (the subject may flow through a private helper)
      const calls: { method: string; repo: Repository; line: number }[] = [];
      for (const mm of t.methods) {
        mm.body.forEach((x, i) => {
          const r = x.k === "id" && mm.body[i + 1]?.v === "." && mm.body[i + 3]?.v === "(" ? repoOf(x.v) : undefined;
          if (r) calls.push({ method: mm.body[i + 2]!.v, repo: r, line: x.line });
        });
      }
      calls.sort((a, b2) => a.line - b2.line);
      if (claimIdx >= 0 && subjIdx < 0) {
        const c = b[claimIdx + 2]!.v;
        if (/mail/i.test(c)) return { resolver: t.name, subject: "email", why: `jwt.getClaim("${c}")`, loc: { file: t.file, line: b[claimIdx]!.line }, ...(calls[0] ? { userEntity: calls[0].repo.entity } : {}) };
      }
      const first = calls.find((c) => /^find|^get|^exists/.test(c.method));
      if (!first) continue;
      const subject = /Email/i.test(first.method) ? "email" : /Username|Login|Name/i.test(first.method) ? "username" : "id";
      return {
        resolver: t.name,
        subject,
        why: `${t.name}: jwt subject -> ${first.repo.name}.${first.method}(...)${calls.length > 1 ? ` (then ${calls.slice(1).map((c) => c.method).join(", ")})` : ""}`,
        loc: { file: t.file, line: first.line },
        userEntity: first.repo.entity,
      };
    }
  }
  return { subject: "id", why: "the code that maps the token to a user was not found: assumed sub = user id" };
}

/** Rendered guard text for reports. */
export const guardText = (g: Guard): string => `@${g.kind}(${JSON.stringify(g.expr)})`;
export { tokText };
