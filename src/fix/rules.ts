import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Config } from "../config.js";
import { isSensitiveColumn } from "../seed.js";
import type { Finding } from "../types.js";

/** An exact text replacement in one file (path relative to the target dir). */
export interface Edit {
  file: string;
  line: number;
  before: string;
  after: string;
}

export interface Proposal {
  kind: "select-star" | "guidance";
  /** Keys of the findings this proposal addresses (see findingKey). */
  addresses: string[];
  title: string;
  /** Present only when the change can be applied mechanically. */
  edits: Edit[];
  /** Human instructions. Always set; the only output for guidance proposals. */
  guidance: string;
}

export const findingKey = (f: Finding): string => [f.check, f.resourceId, f.persona, f.column ?? ""].join("|");

const SOURCE_EXT = /\.(?:[cm]?js|[jt]sx?)$/;
const SKIP_DIRS = new Set(["node_modules", ".git", "out", ".omc"]);
const MAX_FILE_BYTES = 1_000_000;

export function sourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (SOURCE_EXT.test(name) && st.size <= MAX_FILE_BYTES) out.push(p);
    }
  };
  walk(root);
  return out.sort();
}

/** Column names of `table` as declared by the schema file, in order. */
export function tableColumns(schemaPath: string, table: string): string[] {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(readFileSync(schemaPath, "utf8"));
    const rows = db.prepare(`PRAGMA table_info("${table.replace(/"/g, '""')}")`).all() as unknown as { name: string }[];
    return rows.map((r) => r.name);
  } finally {
    db.close();
  }
}

const ident = (n: string): string => (/^\w+$/.test(n) ? n : `"${n.replace(/"/g, '""')}"`);
const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** `SELECT * FROM <table>` -> explicit non-sensitive column list. Returns the edits found in the sources. */
function selectStarEdits(cfg: Config, srcDir: string, table: string): { edits: Edit[]; columns: string[] } {
  if (!cfg.seed) return { edits: [], columns: [] };
  const schemaPath = resolve(srcDir, cfg.seed.schema);
  if (!existsSync(schemaPath)) return { edits: [], columns: [] };
  const columns = tableColumns(schemaPath, table).filter((c) => !isSensitiveColumn(c, cfg.secrets.sensitiveColumns));
  if (!columns.length) return { edits: [], columns };

  const re = new RegExp(`SELECT\\s+\\*\\s+FROM\\s+["\`]?${escapeRe(table)}\\b["\`]?`, "gi");
  const edits: Edit[] = [];
  for (const file of sourceFiles(srcDir)) {
    const text = readFileSync(file, "utf8");
    const seen = new Set<string>();
    for (const m of text.matchAll(re)) {
      if (seen.has(m[0])) continue;
      seen.add(m[0]);
      edits.push({
        file: relative(srcDir, file),
        line: text.slice(0, m.index).split("\n").length,
        before: m[0],
        after: m[0].replace(/\*/, columns.map(ident).join(", ")),
      });
    }
  }
  return { edits, columns };
}

/**
 * Turn non-OK findings into proposals. Rule-based only: column-limiting is applied mechanically,
 * ownership / auth / parameterization depend on app code, so those come back as guidance.
 */
export function proposeFixes(cfg: Config, findings: Finding[], srcDir: string): Proposal[] {
  const bad = findings.filter((f) => f.verdict === "VULNERABLE" || f.verdict === "SUSPECTED");
  const out: Proposal[] = [];
  const handled = new Set<string>();

  // secrets: group by table
  const secretsByTable = new Map<string, Finding[]>();
  for (const f of bad.filter((x) => x.check === "secrets" && x.column)) {
    const table = f.column!.split(".")[0]!;
    secretsByTable.set(table, [...(secretsByTable.get(table) ?? []), f]);
  }
  for (const [table, fs] of secretsByTable) {
    const cols = [...new Set(fs.map((f) => f.column!.split(".")[1]!))];
    const { edits, columns } = selectStarEdits(cfg, srcDir, table);
    const addresses = fs.map(findingKey);
    addresses.forEach((a) => handled.add(a));
    out.push({
      kind: edits.length ? "select-star" : "guidance",
      addresses,
      title: `limit columns returned from ${table} (${cols.join(", ")} must not be selected)`,
      edits,
      guidance: edits.length
        ? `Select only non-sensitive columns from ${table}: ${columns.join(", ")}.`
        : `Do not return ${table}.${cols.join(", ")} in responses: replace SELECT * with an explicit column list that excludes it, or strip the field before responding. No "SELECT * FROM ${table}" was found in the sources to patch automatically.`,
    });
  }

  const guidance = (f: Finding): string => {
    const res = cfg.resources.find((r) => r.id === f.resourceId);
    switch (f.check) {
      case "bola":
        return `Route ${res?.route ?? f.resourceId}: add an ownership check so ${f.persona}'s org can only read its own rows` +
          (res?.owner ? ` (WHERE ${res.owner.column} = <caller's org>, e.g. AND ${res.owner.column} = ?).` : ".");
      case "unauth":
        return `Route ${res?.route ?? f.resourceId}: require authentication (reject anonymous requests with 401) before doing any work.`;
      case "sqli":
        return `Route ${res?.route ?? f.resourceId}: pass query parameter(s) ${(res?.params ?? []).join(", ")} as bound parameters (prepared statement), never by string concatenation.`;
      case "secrets":
        if (f.env) {
          return `Route ${res?.route ?? f.resourceId} returns the process environment (${f.env} leaked): remove or disable this debug route in production; never serialize process.env into a response.`;
        }
        return `Resolve: ${f.detail}`;
      default:
        return `Resolve: ${f.detail}`;
    }
  };
  for (const f of bad) {
    const k = findingKey(f);
    if (handled.has(k)) continue;
    handled.add(k);
    out.push({ kind: "guidance", addresses: [k], title: `${f.check} on ${f.resourceId} (${f.persona})`, edits: [], guidance: guidance(f) });
  }
  return out;
}

/** Apply edits under `root`. Throws if an expected snippet is missing, so a stale proposal never half-applies. */
export function applyEdits(root: string, edits: Edit[]): void {
  const byFile = new Map<string, Edit[]>();
  for (const e of edits) byFile.set(e.file, [...(byFile.get(e.file) ?? []), e]);
  const staged = new Map<string, string>();
  for (const [file, es] of byFile) {
    let text = readFileSync(join(root, file), "utf8");
    for (const e of es) {
      if (!text.includes(e.before)) throw new Error(`${file}: expected text not found: ${e.before}`);
      text = text.split(e.before).join(e.after);
    }
    staged.set(file, text);
  }
  for (const [file, text] of staged) writeFileSync(join(root, file), text);
}
