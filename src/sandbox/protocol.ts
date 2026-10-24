import { z } from "zod";
import { Finding, Matrix } from "../types.js";

export const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
export const MAX_RESULT_BYTES = 512 * 1024;
export const SANDBOX_IMAGE = "argos-local-runtime:dev";

export const SandboxJob = z.strictObject({
  id: z.number().int().positive(),
  lease: z.string().min(32).max(128),
  repo: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  pr: z.number().int().positive(),
  sha: z.string().regex(/^[a-f0-9]{40}$/),
});
export type SandboxJob = z.infer<typeof SandboxJob>;

export const SandboxResult = z.strictObject({
  version: z.literal(1),
  status: z.enum(["completed", "unsupported", "failed"]),
  image: z.string().max(256),
  durationMs: z.number().int().nonnegative(),
  reason: z.string().max(1000).optional(),
  policy: z.enum(["repository", "draft"]).optional(),
  routes: z.array(z.string().max(256)).max(60),
  untested: z.array(z.string().max(512)).max(100),
  matrix: Matrix.optional(),
  findings: z.array(Finding).max(1000),
}).superRefine((r, ctx) => {
  if (r.status === "completed" && (!r.matrix || !r.matrix.cells.length || !r.policy)) {
    ctx.addIssue({ code: "custom", message: "completed requires a nonempty matrix and policy source" });
  }
  if (r.matrix && r.matrix.cells.length > 1000) ctx.addIssue({ code: "custom", message: "too many matrix cells" });
  if (r.status !== "completed" && (r.matrix || r.findings.length)) {
    ctx.addIssue({ code: "custom", message: "incomplete execution cannot contain verdicts" });
  }
});
export type SandboxResult = z.infer<typeof SandboxResult>;

export const RUNTIME_LIMITS = [
  "BOLA, unauthenticated access, SQL error probes, response/environment secret markers only.",
  "SSRF exploitation, external APIs, roles, writes, and automatic fixes are not executed.",
  "Only configured/discovered routes are tested; absence of findings is not a security guarantee.",
];
