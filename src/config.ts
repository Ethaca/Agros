import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";
import { Access, CheckName, ReportLang } from "./types.js";

const Auth = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("bearer"), token: z.string().min(1) }),
  z.strictObject({ type: z.literal("none") }),
  /** Token minted at run time by the per-run test issuer (runtime jvm + auth section). Never stored in config. */
  z.strictObject({ type: z.literal("jwt") }),
]);

const Persona = z.strictObject({
  name: z.string().min(1),
  /** Owning org/vendor. Omit for anonymous personas. */
  org: z.string().min(1).optional(),
  auth: Auth,
  /** Seeded user key (jwt personas). Default: the persona name. Several personas may share an org. */
  user: z.string().min(1).optional(),
  /** Roles put into the token's roles claim. */
  roles: z.array(z.string().min(1)).optional(),
  /** Deliberately broken token: expected to be denied everywhere (except public resources). */
  invalid: z.enum(["wrong-signature", "expired"]).optional(),
});

const Action = z.enum(["read", "create", "update", "delete"]);

const PathParam = z.strictObject({ table: z.string().min(1), column: z.string().min(1).optional() });

const Route = z.string().regex(/^(GET|POST|PUT|PATCH|DELETE) \/\S*$/, 'expected "METHOD /path"');

const Resource = z.strictObject({
  id: z.string().min(1),
  route: Route,
  owner: z
    .strictObject({
      table: z.string(),
      column: z.string(),
      /** "org" (default): column holds the org. "user": the row belongs to one user inside an org; column holds the user's id. */
      scope: z.enum(["org", "user"]).optional(),
    })
    .optional(),
  expect: z
    .strictObject({
      owner: Access,
      other: Access,
      anonymous: Access,
      /** Another user of the same org. Default: owner for org-scoped rows, deny for user-scoped rows. */
      sameOrgOther: Access.optional(),
      /** A persona of the owning org whose roles do not include `roles`. Default: deny when `roles` is set. */
      member: Access.optional(),
    })
    .optional(),
  public: z.boolean().optional(),
  /** Non-read routes are only exercised when explicitly marked safe. */
  safe: z.boolean().optional(),
  /** Query-string parameters to test for SQL injection (sqli check). */
  params: z.array(z.string().min(1)).optional(),
  /** Roles allowed to use this resource; personas without one of them expect `expect.member`. */
  roles: z.array(z.string().min(1)).optional(),
  /** Default: read for GET, create for POST, update for PUT/PATCH, delete for DELETE. */
  action: Action.optional(),
  /** Which seeded table (and column, default the primary key) feeds each `:param` / `{param}`. */
  pathParams: z.record(z.string(), PathParam).optional(),
  /** Valid request body template. Placeholders: $org, $user, $marker, $unique, $id:<table>. */
  body: z.record(z.string(), z.unknown()).optional(),
  /** Query string sent with every request (same placeholders as body). */
  query: z.record(z.string(), z.string()).optional(),
  /** Write actions: the DB state that proves whether the write happened (runtime jvm with db only). */
  writeVerify: z
    .strictObject({
      table: z.string().min(1),
      column: z.string().min(1),
      /** Column -> value (placeholders allowed). Default: the target row's primary key. */
      where: z.record(z.string(), z.string()).optional(),
    })
    .optional(),
});

const DEFAULT_DB_ENV = { url: "SPRING_DATASOURCE_URL", user: "SPRING_DATASOURCE_USERNAME", password: "SPRING_DATASOURCE_PASSWORD" };
const DEFAULT_JWT_ENV = {
  jwkSetUri: "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI",
  issuerUri: "SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_ISSUER_URI",
};

const Db = z.strictObject({
  kind: z.literal("postgres"),
  /** PostgreSQL image. Default: target.container.dbImage, else DEFAULT_DB_IMAGE (see dbImageOf). */
  image: z.string().min(1).optional(),
  migrations: z.enum(["flyway", "liquibase", "app", "none"]).default("app"),
  /** Names of the environment variables the app reads the connection from (values are injected per run). */
  env: z
    .strictObject({ url: z.string().min(1), user: z.string().min(1), password: z.string().min(1) })
    .default(DEFAULT_DB_ENV),
});

const JwtAuth = z.strictObject({
  type: z.literal("jwt-issuer"),
  env: z
    .strictObject({ jwkSetUri: z.string().min(1), issuerUri: z.string().min(1).optional() })
    .default(DEFAULT_JWT_ENV),
  audience: z.string().min(1).optional(),
  claims: z
    .strictObject({
      /** What goes into `sub`: the seeded user's primary key ("id"), email or username. */
      subject: z.enum(["email", "id", "username"]).default("id"),
      /** prefix: written INTO each token role value (e.g. "ROLE_" when the claim must hold "ROLE_ADMIN").
       *  Leave it unset when the app's JwtAuthenticationConverter adds the prefix itself. */
      roles: z
        .strictObject({ claim: z.string().min(1).default("roles"), prefix: z.string().optional() })
        .default({ claim: "roles" }),
      extra: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
    })
    .default({ subject: "id", roles: { claim: "roles" } }),
});

export const Config = z
  .strictObject({
    version: z.literal(1),
    target: z.strictObject({
      start: z.string().min(1),
      cwd: z.string().default("."),
      baseUrl: z.string().default("http://127.0.0.1:0"),
      readyPath: z.string().default("/health"),
      env: z.record(z.string(), z.string()).default({}),
      /** process: run on the host (trusted code only). container: no network, read-only FS, non-root, limits. */
      isolation: z.enum(["process", "container"]).default("process"),
      /** node (default) or jvm (Spring Boot: built and run in containers with PostgreSQL and a test JWT issuer). */
      runtime: z.enum(["node", "jvm"]).default("node"),
      /** jvm: build command (default chosen by the runner from the Maven/Gradle wrapper). */
      build: z.string().min(1).optional(),
      container: z
        .strictObject({
          /** node: needs `node` inside (the host reaches the app through `docker exec`), default node:<host major>-slim.
           *  jvm: the app's runtime image (no node needed), default eclipse-temurin:<detected JDK>-jre. */
          image: z.string().min(1).optional(),
          memory: z.string().default("512m"),
          cpus: z.string().default("1"),
          pids: z.number().int().positive().default(256),
          /** jvm: image the Maven/Gradle build runs in. */
          buildImage: z.string().min(1).optional(),
          /** jvm: image of the in-network helper (relay / test issuer). */
          sidecarImage: z.string().min(1).optional(),
          /** jvm: PostgreSQL image (ignored when db.image is set). */
          dbImage: z.string().min(1).optional(),
        })
        .default({ memory: "512m", cpus: "1", pids: 256 }),
    }),
    seed: z
      .strictObject({
        schema: z.string(),
        dbPath: z.string(),
        rows: z.string().optional(),
      })
      .optional(),
    /** PostgreSQL for runtime jvm: seeded from the live schema after migrations. Replaces `seed`. */
    db: Db.optional(),
    /** How the app authenticates (runtime jvm). Personas with auth.type "jwt" get tokens from the run's test issuer. */
    auth: JwtAuth.optional(),
    personas: z.array(Persona).min(1),
    resources: z.array(Resource).min(1),
    checks: z.array(CheckName).default(["bola", "unauth", "sqli", "secrets"]),
    secrets: z
      .strictObject({
        sensitiveColumns: z.array(z.string()).default(["api_key", "token", "secret", "password"]),
        allowOwnerSecretRead: z.boolean().default(false),
        envCanaries: z
          .array(z.string())
          .default(["JWT_SECRET", "SECRET_KEY", "API_KEY", "STRIPE_SECRET_KEY"]),
        /** (c) look for hardcoded secrets in the target's source files. */
        staticScan: z.boolean().default(true),
        /** Extra path substrings to skip, on top of the defaults (seed*, tests, fixtures, examples, argos config). */
        staticExclude: z.array(z.string()).default([]),
      })
      .default({
        sensitiveColumns: ["api_key", "token", "secret", "password"],
        allowOwnerSecretRead: false,
        envCanaries: ["JWT_SECRET", "SECRET_KEY", "API_KEY", "STRIPE_SECRET_KEY"],
        staticScan: true,
        staticExclude: [],
      }),
    /** Hints for `argos fix`. Without `principal` only column limiting is applied automatically. */
    fix: z
      .strictObject({
        /** Source expression for the caller's org inside a handler, e.g. `req.user.vendor_id`. */
        principal: z.string().min(1).optional(),
      })
      .optional(),
    /**
     * Who vouches for a field: a person ("confirmed") or the drafting AI/heuristics ("ai-draft"). Keys look like
     * `resources.<id>.expect`. Unconfirmed expectations are listed in scan-meta.json and in the report, and
     * `argos init --update` never changes a confirmed field.
     */
    provenance: z.record(z.string(), z.enum(["confirmed", "ai-draft"])).optional(),
    mode: z.enum(["report", "block"]).default("report"),
    /** Evidence report / PR summary language. */
    report: z.strictObject({ lang: ReportLang.default("en") }).default({ lang: "en" }),
    llm: z
      .strictObject({
        provider: z.literal("anthropic"),
        data: z.enum(["files", "none"]),
      })
      .default({ provider: "anthropic", data: "files" }),
  })
  .superRefine((cfg, ctx) => {
    const dup = (names: string[], path: string) => {
      const seen = new Set<string>();
      names.forEach((n, i) => {
        if (seen.has(n)) ctx.addIssue({ code: "custom", path: [path, i], message: `duplicate "${n}"` });
        seen.add(n);
      });
    };
    dup(cfg.personas.map((p) => p.name), "personas");
    dup(cfg.resources.map((r) => r.id), "resources");

    if (!cfg.personas.some((p) => p.auth.type === "none")) {
      ctx.addIssue({ code: "custom", path: ["personas"], message: 'needs an anonymous persona (auth.type "none")' });
    }
    if (cfg.personas.filter(hasCredentials).length < 2) {
      ctx.addIssue({ code: "custom", path: ["personas"], message: "needs at least 2 authenticated personas to test cross-org access" });
    }
    const jvm = cfg.target.runtime === "jvm";
    cfg.personas.forEach((p, i) => {
      if (p.auth.type !== "none" && !p.invalid && !p.org) {
        ctx.addIssue({ code: "custom", path: ["personas", i, "org"], message: "authenticated persona requires org" });
      }
      if (p.auth.type === "jwt" && !cfg.auth) {
        ctx.addIssue({ code: "custom", path: ["personas", i, "auth"], message: 'auth.type "jwt" needs the top-level `auth` section (tokens are minted by the run\'s test issuer)' });
      }
      if (p.invalid && p.auth.type !== "jwt") {
        ctx.addIssue({ code: "custom", path: ["personas", i, "invalid"], message: 'only valid with auth.type "jwt"' });
      }
    });
    dup(cfg.personas.filter((p) => p.org && hasCredentials(p)).map((p) => `${p.org}/${userKey(p)}`), "personas");
    if (cfg.auth && !jvm) ctx.addIssue({ code: "custom", path: ["auth"], message: "requires target.runtime: jvm" });
    if (cfg.db && !jvm) ctx.addIssue({ code: "custom", path: ["db"], message: "requires target.runtime: jvm" });
    if (cfg.db && cfg.seed) ctx.addIssue({ code: "custom", path: ["seed"], message: "use either seed (SQLite) or db (PostgreSQL), not both" });
    if (jvm && cfg.target.isolation !== "container") {
      ctx.addIssue({ code: "custom", path: ["target", "isolation"], message: "runtime jvm runs only in containers (isolation: container)" });
    }
    cfg.resources.forEach((r, i) => {
      if (!r.public && !r.expect) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "expect"], message: "required unless public: true" });
      }
      const { path } = splitRoute(r.route);
      const params = routeParams(path);
      if (!r.public && cfg.checks.includes("bola") && !r.owner && r.route.startsWith("GET ") && params.length) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "owner"], message: "required for parameterized GET routes (bola needs the owning column)" });
      }
      for (const k of Object.keys(r.pathParams ?? {})) {
        if (!params.includes(k)) ctx.addIssue({ code: "custom", path: ["resources", i, "pathParams", k], message: `route has no :${k} / {${k}} parameter` });
      }
      if (r.writeVerify && !cfg.db) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "writeVerify"], message: "requires db (state is read from the run's PostgreSQL)" });
      }
      if (r.owner?.scope === "user" && !cfg.db) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "owner", "scope"], message: '"user" requires db (users are seeded in PostgreSQL)' });
      }
    });
  });

export type Config = z.infer<typeof Config>;

export const DEFAULT_DB_IMAGE = "postgres:16-alpine";

/** db.image wins over target.container.dbImage; both unset -> DEFAULT_DB_IMAGE. */
export const dbImageOf = (cfg: Config): string => cfg.db?.image ?? cfg.target.container.dbImage ?? DEFAULT_DB_IMAGE;
export type PersonaConfig = Config["personas"][number];
export type ResourceConfig = Config["resources"][number];

/** A persona that presents credentials the app should accept (bearer, or a correctly minted jwt). */
export function hasCredentials(p: { auth: { type: string }; invalid?: string }): boolean {
  return p.auth.type !== "none" && !p.invalid;
}

/** Seeded user key of a persona (default: its name). */
export const userKey = (p: { name: string; user?: string }): string => p.user ?? p.name;

/** "GET /a/:id?x=" -> method GET, path /a/:id */
function splitRoute(route: string): { method: string; path: string } {
  const [method, full = ""] = route.split(" ", 2);
  return { method: method!, path: full.split("?", 2)[0]! };
}

/** Parameter names in a path, in order: both `:id` and `{id}` forms. */
export function routeParams(path: string): string[] {
  return [...path.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map((m) => (m[1] ?? m[2])!);
}

export function actionOf(r: ResourceConfig): z.infer<typeof Action> {
  if (r.action) return r.action;
  const m = splitRoute(r.route).method;
  return m === "GET" ? "read" : m === "POST" ? "create" : m === "DELETE" ? "delete" : "update";
}

/** Single-line, location-first message: "personas.2.auth: ...". */
export function formatConfigError(err: z.ZodError): string {
  const i = err.issues[0]!;
  const loc = i.path.length ? i.path.join(".") : "(root)";
  const extra = err.issues.length > 1 ? ` (+${err.issues.length - 1} more)` : "";
  return `${loc}: ${i.message}${extra}`;
}

export class ConfigError extends Error {}

export function parseConfig(raw: unknown): Config {
  const r = Config.safeParse(raw);
  if (!r.success) throw new ConfigError(formatConfigError(r.error));
  return r.data;
}

export function loadConfig(path: string): Config {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new ConfigError(`${path}: cannot read file (${(e as Error).message})`);
  }
  let raw: unknown;
  try {
    raw = parse(text);
  } catch (e) {
    throw new ConfigError(`${path}: invalid YAML (${(e as Error).message.split("\n")[0]})`);
  }
  return parseConfig(raw);
}
