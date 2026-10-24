import type { DbHandle, SqlRow, SqlValue } from "../stack.js";
import { dockerAsync } from "./docker.js";
import { redact } from "./redact.js";

/**
 * DbHandle over `docker exec -i <pg> psql` (local socket inside the DB container; no host port, no host psql).
 * SQL travels on stdin, never through a shell or argv.
 */

/** Wrap a statement so psql prints its rows as one JSON array; null = statement has no result set. */
export function wrapForJson(sql: string): string | null {
  const s = sql.trim().replace(/;\s*$/, "");
  // alias that no customer column will be named: json_agg(<alias>) must aggregate the row, not a same-named column
  if (/^(select|with|values|table)\b/i.test(s)) return `select coalesce(json_agg(_argos_q), '[]'::json) from (${s}) _argos_q`;
  if (/^(insert|update|delete)\b/i.test(s) && /\breturning\b/i.test(s)) return `with _argos_q as (${s}) select coalesce(json_agg(_argos_q), '[]'::json) from _argos_q`;
  return null;
}

const toRow = (o: Record<string, unknown>): SqlRow =>
  Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v === null || typeof v !== "object" ? (v as SqlValue) : JSON.stringify(v)]));

export function psqlArgs(container: string, user: string, db: string): string[] {
  return ["exec", "-i", container, "psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db];
}

export function dbHandle(container: string, user: string, db: string, secrets: () => string[]): DbHandle {
  const run = async (sql: string): Promise<string> => {
    const r = await dockerAsync(psqlArgs(container, user, db), { timeoutMs: 60_000, input: sql });
    if (r.status !== 0) {
      const why = r.timedOut ? "timed out" : (r.stderr.trim() || r.error?.message || `exit ${r.status}`);
      throw new Error(`postgres: ${redact(why, secrets())}`);
    }
    return r.stdout;
  };
  return {
    async query(sql) {
      const wrapped = wrapForJson(sql);
      if (!wrapped) {
        await run(sql);
        return [];
      }
      const out = (await run(wrapped)).trim();
      return (JSON.parse(out || "[]") as Record<string, unknown>[]).map(toRow);
    },
    async exec(sql) {
      await run(sql);
    },
  };
}
