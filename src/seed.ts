import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { isAbsolute, relative, resolve } from "node:path";
import type { Config } from "./config.js";

/** Markers are planted in seed data; if one shows up in a response, that data leaked. */

export interface SecretMarker {
  table: string;
  column: string;
  org: string;
  marker: string;
}

export interface SeedManifest {
  /** resourceId -> org -> owner-data marker (full value; mask before printing). */
  markers: Record<string, Record<string, string>>;
  secrets: SecretMarker[];
}

export class SeedError extends Error {}

/** S4: only the first 6 chars may reach logs, reports and evidence. */
export const MASK_LEN = 6;
export const maskMarker = (m: string): string => m.slice(0, MASK_LEN);

export function hashConfigText(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/** Deterministic: same seedKey (config hash) + inputs always give the same marker. */
function hex6(seedKey: string, ...parts: (string | number)[]): string {
  return createHash("sha256").update([seedKey, ...parts].join("|")).digest("hex").slice(0, 6);
}

export const ownerMarker = (seedKey: string, resourceId: string, org: string): string =>
  `ARGOS_${resourceId}_${org}_${hex6(seedKey, "row", resourceId, org)}`;

export const secretMarker = (seedKey: string, n: number, table: string, column: string, org: string): string =>
  `ARGOS_SECRET_${n}_${hex6(seedKey, "secret", table, column, org)}`;

export function allMarkers(m: SeedManifest): string[] {
  return [...Object.values(m.markers).flatMap((o) => Object.values(o)), ...m.secrets.map((s) => s.marker)];
}

/** Replace any full marker in `text` with its masked form, so evidence never carries a full value. */
export function redact(text: string, m: SeedManifest): string {
  let out = text;
  for (const marker of allMarkers(m).sort((a, b) => b.length - a.length)) {
    out = out.split(marker).join(`${maskMarker(marker)}…`);
  }
  return out;
}

export function isSensitiveColumn(name: string, patterns: string[]): boolean {
  const n = name.toLowerCase();
  return patterns.some((p) => n.includes(p.toLowerCase()));
}

const q = (id: string): string => `"${id.replace(/"/g, '""')}"`;

interface ColumnInfo {
  name: string;
  type: string;
  notnull: number;
  dflt_value: unknown;
  pk: number;
}

export interface SeedOptions {
  /** Directory the app runs in (the temp copy). schema/dbPath resolve against it. */
  workdir: string;
  /** Usually hashConfigText(<config file text>), so markers are reproducible. */
  seedKey: string;
}

function inside(workdir: string, p: string, what: string): string {
  const abs = resolve(workdir, p);
  const rel = relative(workdir, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) throw new SeedError(`${what} escapes the working copy: ${p}`);
  return abs;
}

/**
 * Create the SQLite DB from schema.sql and insert one row per (owner table, org).
 * Owner column = org. Text columns get the owner marker; sensitive columns get a secret marker.
 * Must run against the temp copy from the runner, never the original repo (R4).
 */
export function seedDatabase(cfg: Config, opts: SeedOptions): SeedManifest {
  const seed = cfg.seed;
  if (!seed) throw new SeedError("config has no `seed` section; nothing to seed");
  if (seed.rows) throw new SeedError("seed.rows is not supported yet (omit it to auto-generate rows from resources)");

  const schemaPath = inside(opts.workdir, seed.schema, "seed.schema");
  const dbPath = inside(opts.workdir, seed.dbPath, "seed.dbPath");
  if (!existsSync(schemaPath)) throw new SeedError(`seed.schema not found: ${seed.schema}`);

  // Fresh DB every run so the manifest always matches what is in the file.
  for (const suffix of ["", "-wal", "-shm", "-journal"]) rmSync(dbPath + suffix, { force: true });

  const orgs = [...new Set(cfg.personas.map((p) => p.org).filter((o): o is string => !!o))];
  const manifest: SeedManifest = { markers: {}, secrets: [] };

  const db = new DatabaseSync(dbPath);
  try {
    db.exec(readFileSync(schemaPath, "utf8"));

    // table -> resources sharing it (the first one names the marker)
    const byTable = new Map<string, { column: string; resourceIds: string[] }>();
    for (const r of cfg.resources) {
      if (!r.owner) continue;
      const e = byTable.get(r.owner.table);
      if (e && e.column !== r.owner.column) {
        throw new SeedError(`table ${r.owner.table} has two owner columns: ${e.column}, ${r.owner.column}`);
      }
      if (e) e.resourceIds.push(r.id);
      else byTable.set(r.owner.table, { column: r.owner.column, resourceIds: [r.id] });
    }

    let n = 0;
    for (const [table, { column: ownerCol, resourceIds }] of byTable) {
      const cols = db.prepare(`PRAGMA table_info(${q(table)})`).all() as unknown as ColumnInfo[];
      if (!cols.length) throw new SeedError(`table "${table}" not found in ${seed.schema}`);
      if (!cols.some((c) => c.name === ownerCol)) {
        throw new SeedError(`owner column "${table}.${ownerCol}" not found in ${seed.schema}`);
      }
      const insertCols = cols.filter((c) => {
        if (c.name === ownerCol) return true;
        const text = !/INT|REAL|FLOA|DOUB|NUM|DEC|BOOL|BLOB/i.test(c.type);
        if (c.pk && /INT/i.test(c.type)) return false; // rowid alias: let SQLite assign
        return text || c.notnull === 1 && c.dflt_value === null;
      });

      for (const org of orgs) {
        const values: (string | number)[] = [];
        for (const c of insertCols) {
          if (c.name === ownerCol) values.push(org);
          else if (isSensitiveColumn(c.name, cfg.secrets.sensitiveColumns)) {
            const marker = secretMarker(opts.seedKey, ++n, table, c.name, org);
            manifest.secrets.push({ table, column: c.name, org, marker });
            values.push(marker);
          } else if (/INT|REAL|FLOA|DOUB|NUM|DEC|BOOL/i.test(c.type)) values.push(1);
          else values.push(ownerMarker(opts.seedKey, resourceIds[0]!, org));
        }
        db.prepare(
          `INSERT INTO ${q(table)} (${insertCols.map((c) => q(c.name)).join(", ")}) VALUES (${insertCols.map(() => "?").join(", ")})`,
        ).run(...values);
        for (const id of resourceIds) (manifest.markers[id] ??= {})[org] = ownerMarker(opts.seedKey, resourceIds[0]!, org);
      }
    }
  } catch (e) {
    if (e instanceof SeedError) throw e;
    throw new SeedError(`seeding failed: ${(e as Error).message}`);
  } finally {
    db.close();
  }
  return manifest;
}
