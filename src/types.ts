import { z } from "zod";

/** Contract shared with A (report.ts). Change only after telling A. */

export const Verdict = z.enum(["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"]);
export type Verdict = z.infer<typeof Verdict>;

export const CheckName = z.enum(["bola", "unauth", "sqli", "secrets"]);
export type CheckName = z.infer<typeof CheckName>;

export const Access = z.enum(["allow", "deny"]);
export type Access = z.infer<typeof Access>;

/** allow-empty: 2xx without the owner's marker. error: unexpected response or owner 404. */
export const Observed = z.enum(["allow", "deny", "allow-empty", "error"]);
export type Observed = z.infer<typeof Observed>;

export const Evidence = z.strictObject({
  request: z.string(),
  status: z.number().int().optional(),
  /** First 6 chars of a marker or secret only. Never the full value. */
  marker: z.string().max(6).optional(),
  note: z.string().optional(),
});
export type Evidence = z.infer<typeof Evidence>;

export const MatrixCell = z.strictObject({
  persona: z.string(),
  resource: z.string(),
  /** Org whose data was requested (the persona's own org, or a foreign one). Absent for resources without rows. */
  target: z.string().optional(),
  expected: Access,
  observed: Observed,
  verdict: Verdict,
  evidence: Evidence,
});
export type MatrixCell = z.infer<typeof MatrixCell>;

export const Matrix = z.strictObject({
  personas: z.array(z.string()),
  resources: z.array(z.string()),
  cells: z.array(MatrixCell),
});
export type Matrix = z.infer<typeof Matrix>;

export const Finding = z.strictObject({
  check: CheckName,
  resourceId: z.string(),
  persona: z.string(),
  verdict: Verdict,
  proof: Evidence,
  detail: z.string(),
  /** secrets check only: sensitive column or env name that leaked */
  column: z.string().optional(),
  env: z.string().optional(),
});
export type Finding = z.infer<typeof Finding>;

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * out/scan-meta.json: raw material for the report's evidence header (SPEC V2).
 * Hashes pin files, they do not prevent tampering. No absolute paths, no secrets.
 */
export const ScanMeta = z.strictObject({
  tool: z.strictObject({ name: z.literal("argos"), version: z.string() }),
  startedAt: z.string(),
  finishedAt: z.string(),
  durationMs: z.number().int().nonnegative(),
  /** Name of the directory holding the config (identifies the target in a report). */
  target: z.string(),
  mode: z.enum(["report", "block"]),
  /** How the target ran. "process" = host process (trusted code only); "container" = no network, read-only FS, non-root. */
  isolation: z.enum(["process", "container"]),
  /** Container image (null for process isolation). */
  image: z.string().nullable(),
  config: z.strictObject({ file: z.string(), sha256: Sha256 }),
  /** Source files the DB was seeded from. rows is null until seed.rows is supported. */
  seed: z
    .strictObject({
      schema: z.strictObject({ file: z.string(), sha256: Sha256 }),
      rows: z.null(),
    })
    .nullable(),
  checks: z.array(CheckName),
  /** Config fields still marked `ai-draft` (no person has confirmed them), e.g. `resources.get-datasets-id.expect`. */
  unconfirmed: z.array(z.string()),
  personas: z.array(z.strictObject({ name: z.string(), org: z.string().nullable() })),
  /** Everything that was tested: a route not listed here was not tested (blackbox scope). */
  resources: z.array(z.strictObject({ id: z.string(), route: z.string(), public: z.boolean() })),
  results: z.strictObject({
    cells: z.number().int(),
    findings: z.number().int(),
    counts: z.strictObject({ VULNERABLE: z.number().int(), SUSPECTED: z.number().int(), OK: z.number().int(), SKIPPED: z.number().int() }),
  }),
  files: z.strictObject({
    matrix: z.strictObject({ file: z.literal("matrix.json"), sha256: Sha256 }),
    findings: z.strictObject({ file: z.literal("findings.json"), sha256: Sha256 }),
  }),
});
export type ScanMeta = z.infer<typeof ScanMeta>;
