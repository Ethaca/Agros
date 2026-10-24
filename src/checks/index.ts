import type { Config } from "../config.js";
import type { Finding, Matrix } from "../types.js";
import { bola } from "./bola.js";
import { unauth } from "./unauth.js";

type MatrixCheck = (cfg: Config, m: Matrix) => Finding[];

/** Checks that read the access matrix. sqli/secrets need their own requests and are added in step 6. */
export const MATRIX_CHECKS: Partial<Record<Finding["check"], MatrixCheck>> = { bola, unauth };

export function runMatrixChecks(cfg: Config, m: Matrix): Finding[] {
  return cfg.checks.flatMap((name) => MATRIX_CHECKS[name]?.(cfg, m) ?? []);
}

export { bola, unauth };
