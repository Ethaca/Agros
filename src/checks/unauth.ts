import type { Config } from "../config.js";
import type { Finding, Matrix } from "../types.js";
import { authedCells, describe, finding, isAnonymous, orgOf, ownCell } from "./common.js";

/**
 * unauth: does an anonymous request get through where auth is required? `public: true` is excluded.
 * An anonymous "denied" counts only if an authenticated control on the same resource succeeded,
 * so a dead app or broken route is SKIPPED instead of looking secure.
 */
export function unauth(cfg: Config, m: Matrix): Finding[] {
  const out: Finding[] = [];
  const resources = new Map(cfg.resources.filter((r) => !r.public).map((r) => [r.id, r]));

  for (const c of m.cells) {
    const res = resources.get(c.resource);
    if (!res || !isAnonymous(cfg, c.persona)) continue;

    const control = c.target
      ? ownCell(cfg, m, c.target, c.resource)?.verdict === "OK"
      : authedCells(cfg, m, c.resource).some((a) => a.verdict === "OK");
    if (!control && c.verdict !== "VULNERABLE") {
      out.push(finding("unauth", c, "SKIPPED", `no working authenticated control for ${c.resource}; cannot trust this result. ${describe(c)}`));
      continue;
    }
    const detail = c.verdict === "VULNERABLE" ? `anonymous request succeeded. ${describe(c)}` : describe(c);
    out.push(finding("unauth", c, c.verdict, detail));
  }
  return out;
}
