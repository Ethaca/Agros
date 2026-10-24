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
