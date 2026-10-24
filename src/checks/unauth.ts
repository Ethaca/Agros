import type { Config } from "../config.js";
import type { Finding, Matrix } from "../types.js";
import { authedCells, describe, finding, isAnonymous, ownCell } from "./common.js";

/**
 * unauth: does an anonymous request (or one with a wrong-signature / expired token) get through where auth is
 * required? `public: true` is excluded.
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
      ? ownCell(cfg, m, c.target, c.resource, c.targetUser)?.verdict === "OK"
      : authedCells(cfg, m, c.resource).some((a) => a.verdict === "OK");
    if (!control && c.verdict !== "VULNERABLE") {
      out.push(finding("unauth", c, "SKIPPED", `no working authenticated control for ${c.resource}; cannot trust this result. ${describe(c)}`));
      continue;
    }
    const invalid = cfg.personas.find((p) => p.name === c.persona)?.invalid;
    const who = invalid ? `request with an invalid token (${invalid})` : "anonymous request";
    const detail = c.verdict === "VULNERABLE" ? `${who} succeeded. ${describe(c)}` : describe(c);
    out.push(finding("unauth", c, c.verdict, detail));
  }
  return out;
}
