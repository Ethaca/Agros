import type { Config } from "../config.js";
import type { HttpResult } from "../http.js";
import type { SeedManifest } from "../seed.js";
import type { Finding, Matrix } from "../types.js";
import { bola } from "./bola.js";
import { secrets } from "./secrets.js";
import { sqli } from "./sqli.js";
import { unauth } from "./unauth.js";

export interface CheckContext {
  cfg: Config;
  baseUrl: string;
  matrix: Matrix;
  /** Raw responses aligned with matrix.cells (see runMatrixDetailed). */
  raw: (HttpResult | undefined)[];
  manifest: SeedManifest;
}

type CheckFn = (ctx: CheckContext) => Finding[] | Promise<Finding[]>;

export const CHECKS: Record<Finding["check"], CheckFn> = {
  bola: (c) => bola(c.cfg, c.matrix),
  unauth: (c) => unauth(c.cfg, c.matrix),
  sqli: (c) => sqli(c.cfg, c.baseUrl, c.manifest),
  secrets: (c) => secrets(c.cfg, c.matrix, c.raw, c.manifest),
};

export async function runChecks(ctx: CheckContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const name of ctx.cfg.checks) out.push(...(await CHECKS[name](ctx)));
  return out;
}

/** bola + unauth only: they need nothing but the matrix. */
export function runMatrixChecks(cfg: Config, m: Matrix): Finding[] {
  return cfg.checks.flatMap((name) => (name === "bola" ? bola(cfg, m) : name === "unauth" ? unauth(cfg, m) : []));
}

export { bola, unauth, sqli, secrets };
