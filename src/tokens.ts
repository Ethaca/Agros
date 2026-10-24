import { userKey, type Config } from "./config.js";
import type { PgSeedManifest } from "./seed-pg.js";
import type { IssuerHandle } from "./stack.js";

/** Valid tokens outlive any scan; "expired" ones are well past Spring's default 60s clock skew. */
const VALID_SEC = 3600;
const EXPIRED_SEC = -600;

/**
 * Mint one token per `auth.type: jwt` persona with the run's test issuer. `sub` follows auth.claims.subject
 * (the seeded user's id / email / username), roles go into auth.claims.roles.claim (dotted = nested, e.g.
 * `realm_access.roles`) with the optional prefix. `claims.extra` values may use $org, $orgId, $user, $userId,
 * $email, $username. Tokens live in memory only.
 */
export function mintPersonaTokens(cfg: Config, issuer: IssuerHandle, manifest?: PgSeedManifest): Record<string, string> {
  const out: Record<string, string> = {};
  const claimsCfg = cfg.auth?.claims ?? { subject: "id" as const, roles: { claim: "roles" } };
  for (const p of cfg.personas) {
    if (p.auth.type !== "jwt") continue;
    const key = p.org ? manifest?.personaUsers[p.name] ?? `${p.org}/${userKey(p)}` : undefined;
    const u = key ? manifest?.users[key] : undefined;
    const vars: Record<string, string> = {
      org: p.org ?? "",
      orgId: (p.org && manifest?.orgIds[p.org]) || p.org || "",
      user: p.org ? userKey(p) : "",
      userId: u?.id ?? "",
      email: u?.email ?? "",
      username: u?.username ?? "",
    };
    const claims: Record<string, unknown> = { sub: u?.subject || vars.user || p.name };
    const roles = (p.roles ?? []).map((r) => `${claimsCfg.roles.prefix ?? ""}${r}`);
    const path = claimsCfg.roles.claim.split(".");
    let node = claims;
    for (const part of path.slice(0, -1)) node = (node[part] ??= {}) as Record<string, unknown>;
    node[path[path.length - 1]!] = roles;
    for (const [k, v] of Object.entries(claimsCfg.extra ?? {})) {
      claims[k] = typeof v === "string" ? v.replace(/\$(orgId|org|userId|user|email|username)\b/g, (_m, n: string) => vars[n] ?? "") : v;
    }
    out[p.name] = issuer.mint(claims, p.invalid === "wrong-signature" ? { wrongKey: true, expiresInSec: VALID_SEC } : p.invalid === "expired" ? { expiresInSec: EXPIRED_SEC } : { expiresInSec: VALID_SEC });
  }
  return out;
}
