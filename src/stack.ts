/**
 * Contract between the JVM/Spring runner (container side) and the scan pipeline (config/seed/matrix side).
 * See docs/SPRING_SUPPORT_PLAN.md §2-§4. Both sides code against these types; change them only deliberately.
 */

export type SqlValue = string | number | boolean | null;
export type SqlRow = Record<string, SqlValue>;

/** Per-run PostgreSQL living on the run's internal network. Reached via `docker exec`, never a host port. */
export interface DbHandle {
  /** Run one statement; returns rows as objects (empty for statements without a result set). Throws on SQL error. */
  query(sql: string): Promise<SqlRow[]>;
  /** Run a multi-statement script (psql -f style, ON_ERROR_STOP). Throws on error. */
  exec(sql: string): Promise<void>;
}

export interface MintOptions {
  /** Seconds until exp (negative = already expired). Default 300. */
  expiresInSec?: number;
  /** Sign with a throwaway key the app does not trust (the token must be rejected). */
  wrongKey?: boolean;
}

/** Per-run test JWT issuer: the app trusts its JWKS (and issuer URI) via Argos-only environment settings. */
export interface IssuerHandle {
  /** Issuer URI the app was configured with (reachable only on the run's internal network). */
  issuer: string;
  /** Sign a JWT (RS256). `iss`, `iat`, `exp`, and `aud` (if configured) are filled in; `claims` may override nothing else. */
  mint(claims: Record<string, unknown>, opts?: MintOptions): string;
}

/** Optional pieces a started target can carry (JVM runtime only). */
export interface StackExtras {
  db?: DbHandle;
  issuer?: IssuerHandle;
  /** Human-readable record of environment settings Argos injected (names only, no values that are secrets). */
  injectedEnv?: string[];
  /** Ordered notes about what the run did (build tool + version, image names, etc.) for the report. */
  notes?: string[];
}
