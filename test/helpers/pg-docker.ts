import { spawnSync } from "node:child_process";
import type { DbHandle, SqlRow } from "../../src/stack.js";

/**
 * Test-only DbHandle backed by a throwaway `postgres:16-alpine` container, reached with `docker exec psql`
 * (no host port). Tests skip when docker is unavailable.
 */

export const PG_IMAGE = "postgres:16-alpine";

export function dockerAvailable(): boolean {
  const r = spawnSync("docker", ["info", "--format", "{{.ServerVersion}}"], { encoding: "utf8", timeout: 10_000 });
  if (r.status !== 0) return false;
  return spawnSync("docker", ["image", "inspect", PG_IMAGE], { encoding: "utf8" }).status === 0 ||
    spawnSync("docker", ["pull", PG_IMAGE], { encoding: "utf8", timeout: 120_000 }).status === 0;
}

function psql(id: string, sql: string): string {
  const r = spawnSync("docker", ["exec", "-i", id, "psql", "-U", "postgres", "-d", "postgres", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
    input: sql,
    encoding: "utf8",
    timeout: 30_000,
  });
  if (r.status !== 0) throw new Error((r.stderr || r.stdout || "psql failed").trim());
  return r.stdout;
}

export interface PgContainer extends DbHandle {
  id: string;
  stop(): void;
}

export async function startPg(): Promise<PgContainer> {
  const run = spawnSync("docker", ["run", "-d", "--rm", "--network", "none", "-e", "POSTGRES_PASSWORD=argos-test", PG_IMAGE], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(`docker run failed: ${run.stderr}`);
  const id = run.stdout.trim();
  const stop = () => void spawnSync("docker", ["rm", "-f", id], { encoding: "utf8" });
  const deadline = Date.now() + 60_000;
  for (;;) {
    // pg_isready alone is not enough: the image restarts the server once after initdb.
    try {
      if (psql(id, "SELECT 1;").trim() === "1") {
        await new Promise((r) => setTimeout(r, 300));
        if (psql(id, "SELECT 1;").trim() === "1") break;
      }
    } catch {
      /* starting */
    }
    if (Date.now() > deadline) {
      stop();
      throw new Error("postgres did not become ready");
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  return {
    id,
    stop,
    async query(sql: string): Promise<SqlRow[]> {
      // Same wrapping as the runner (src/jvm/db.ts), so result columns named `t` would break here too.
      const body = sql.trim().replace(/;$/, "");
      let wrapped: string;
      if (/^(SELECT|WITH)\b/i.test(body)) wrapped = `SELECT coalesce(json_agg(t), '[]'::json) FROM (${body}) t;`;
      else if (/\bRETURNING\b/i.test(body)) wrapped = `WITH t AS (${body}) SELECT coalesce(json_agg(t), '[]'::json) FROM t;`;
      else {
        psql(id, body + ";");
        return [];
      }
      return JSON.parse(psql(id, wrapped).trim() || "[]") as SqlRow[];
    },
    async exec(sql: string): Promise<void> {
      psql(id, sql);
    },
  };
}
