import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";
import { Access, CheckName, ReportLang } from "./types.js";

const Auth = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("bearer"), token: z.string().min(1) }),
  z.strictObject({ type: z.literal("none") }),
]);

const Persona = z.strictObject({
  name: z.string().min(1),
  /** Owning org/vendor. Omit for anonymous personas. */
  org: z.string().min(1).optional(),
  auth: Auth,
});

const Route = z.string().regex(/^(GET|POST|PUT|PATCH|DELETE) \/\S*$/, 'expected "METHOD /path"');

const Resource = z.strictObject({
  id: z.string().min(1),
  route: Route,
  owner: z.strictObject({ table: z.string(), column: z.string() }).optional(),
  expect: z.strictObject({ owner: Access, other: Access, anonymous: Access }).optional(),
  public: z.boolean().optional(),
  /** Non-read routes are only exercised when explicitly marked safe. */
  safe: z.boolean().optional(),
  /** Query-string parameters to test for SQL injection (sqli check). */
  params: z.array(z.string().min(1)).optional(),
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
      container: z
        .strictObject({
          /** Needs `node` inside (the host reaches the app through `docker exec`). Default: node:<host major>-slim. */
          image: z.string().min(1).optional(),
          memory: z.string().default("512m"),
          cpus: z.string().default("1"),
          pids: z.number().int().positive().default(256),
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
    if (cfg.personas.filter((p) => p.auth.type === "bearer").length < 2) {
      ctx.addIssue({ code: "custom", path: ["personas"], message: "needs at least 2 authenticated personas to test cross-org access" });
    }
    cfg.personas.forEach((p, i) => {
      if (p.auth.type === "bearer" && !p.org) {
        ctx.addIssue({ code: "custom", path: ["personas", i, "org"], message: "authenticated persona requires org" });
      }
    });
    cfg.resources.forEach((r, i) => {
      if (!r.public && !r.expect) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "expect"], message: "required unless public: true" });
      }
      if (!r.public && cfg.checks.includes("bola") && !r.owner && r.route.startsWith("GET ") && r.route.includes(":")) {
        ctx.addIssue({ code: "custom", path: ["resources", i, "owner"], message: "required for parameterized GET routes (bola needs the owning column)" });
      }
      if (!r.route.startsWith("GET ") && !r.safe && !r.public) {
        // allowed, but scan will skip it; surfaced at scan time, not a config error
      }
    });
  });

export type Config = z.infer<typeof Config>;

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
