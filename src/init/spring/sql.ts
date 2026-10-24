import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * Migration facts for `argos init` (Spring): Flyway `db/migration/V*.sql` CREATE/ALTER TABLE statements are read
 * statically (PostgreSQL dialect, no database needed). Liquibase changelogs are only detected, not parsed.
 */

export interface SqlColumn {
  name: string;
  type: string;
  notNull: boolean;
  pk: boolean;
  unique: boolean;
  hasDefault: boolean;
  /** Identity / serial: the database generates it. */
  generated: boolean;
  references?: { table: string; column: string };
  /** CHECK (col IN ('A','B')) */
  allowed?: string[];
}

export interface SqlTable {
  name: string;
  columns: SqlColumn[];
  /** Multi-column UNIQUE constraints. */
  uniques: string[][];
  file: string;
  line: number;
}

export interface MigrationFacts {
  tool: "flyway" | "liquibase" | "none";
  files: string[];
  tables: SqlTable[];
  /** Statements that could not be read (reported, never guessed). */
  problems: string[];
}

const ident = (s: string): string => s.trim().replace(/^"|"$/g, "").replace(/^\w+\./, "").toLowerCase();

/** Split on commas at parenthesis depth 0 (strings respected). */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let d = 0;
  let cur = "";
  let q = false;
  for (const c of s) {
    if (c === "'") q = !q;
    if (!q && c === "(") d++;
    if (!q && c === ")") d--;
    if (!q && d === 0 && c === ",") {
      out.push(cur);
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

const stripComments = (sql: string): string => sql.replace(/--[^\n]*/g, (m) => " ".repeat(m.length)).replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));

function checkIn(expr: string): { col: string; values: string[] } | undefined {
  const m = /^\s*\(?\s*"?(\w+)"?\s+IN\s*\(([^)]*)\)/i.exec(expr);
  if (!m) return undefined;
  const values = [...m[2]!.matchAll(/'((?:[^']|'')*)'/g)].map((v) => v[1]!.replace(/''/g, "'"));
  return values.length ? { col: m[1]!.toLowerCase(), values } : undefined;
}

export function parseCreateTables(sqlText: string, file: string): { tables: SqlTable[]; alters: { table: string; body: string }[] } {
  const sql = stripComments(sqlText);
  const tables: SqlTable[] = [];
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w."]+)\s*\(/gi;
  for (let m = re.exec(sql); m; m = re.exec(sql)) {
    const open = m.index + m[0].length - 1;
    let d = 0;
    let end = open;
    for (let j = open; j < sql.length; j++) {
      if (sql[j] === "(") d++;
      if (sql[j] === ")" && --d === 0) {
        end = j;
        break;
      }
    }
    const body = sql.slice(open + 1, end);
    const table: SqlTable = { name: ident(m[1]!), columns: [], uniques: [], file, line: sql.slice(0, m.index).split("\n").length };
    const tableChecks: string[] = [];
    for (const raw of splitTop(body)) {
      const def = raw.trim().replace(/\s+/g, " ");
      if (!def) continue;
      const constraint = def.replace(/^CONSTRAINT\s+[\w"]+\s+/i, "");
      let cm: RegExpExecArray | null;
      if ((cm = /^PRIMARY KEY\s*\(([^)]*)\)/i.exec(constraint))) {
        for (const c of cm[1]!.split(",").map(ident)) {
          const col = table.columns.find((x) => x.name === c);
          if (col) col.pk = true;
        }
      } else if ((cm = /^UNIQUE\s*\(([^)]*)\)/i.exec(constraint))) {
        const cols = cm[1]!.split(",").map(ident);
        if (cols.length === 1) {
          const col = table.columns.find((x) => x.name === cols[0]);
          if (col) col.unique = true;
        } else table.uniques.push(cols);
      } else if ((cm = /^FOREIGN KEY\s*\(([^)]*)\)\s*REFERENCES\s+([\w."]+)\s*(?:\(([^)]*)\))?/i.exec(constraint))) {
        const col = table.columns.find((x) => x.name === ident(cm![1]!));
        if (col) col.references = { table: ident(cm[2]!), column: cm[3] ? ident(cm[3]) : "id" };
      } else if ((cm = /^CHECK\s*\((.*)\)\s*$/i.exec(constraint))) {
        tableChecks.push(cm[1]!);
      } else if (/^(?:EXCLUDE|LIKE)\b/i.test(constraint)) {
        continue;
      } else {
        const cd = /^("?[\w]+"?)\s+(.*)$/.exec(def);
        if (!cd) continue;
        const rest = cd[2]!;
        const type = (/^([\w ]+?(?:\([^)]*\))?(?:\[\])?)(?=\s+(?:NOT|NULL|PRIMARY|UNIQUE|REFERENCES|DEFAULT|CHECK|GENERATED|CONSTRAINT|COLLATE)\b|$)/i.exec(rest)?.[1] ?? rest.split(" ")[0]!).trim();
        const ref = /REFERENCES\s+([\w."]+)\s*(?:\(([^)]*)\))?/i.exec(rest);
        const chk = /CHECK\s*\((.*)\)/i.exec(rest);
        const col: SqlColumn = {
          name: ident(cd[1]!),
          type: type.toLowerCase(),
          notNull: /\bNOT NULL\b/i.test(rest) || /\bPRIMARY KEY\b/i.test(rest),
          pk: /\bPRIMARY KEY\b/i.test(rest),
          unique: /\bUNIQUE\b/i.test(rest),
          hasDefault: /\bDEFAULT\b/i.test(rest),
          generated: /\bGENERATED\b.*\bIDENTITY\b/i.test(rest) || /^(?:big|small)?serial\b/i.test(type),
          ...(ref ? { references: { table: ident(ref[1]!), column: ref[2] ? ident(ref[2]) : "id" } } : {}),
        };
        if (chk) {
          const ci = checkIn(chk[1]!);
          if (ci) col.allowed = ci.values;
        }
        table.columns.push(col);
      }
    }
    for (const c of tableChecks) {
      const ci = checkIn(c);
      const col = ci && table.columns.find((x) => x.name === ci.col);
      if (col && ci) col.allowed = ci.values;
    }
    tables.push(table);
    re.lastIndex = end;
  }
  const alters = [...sql.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([\w."]+)\s+([^;]*);/gi)].map((m) => ({ table: ident(m[1]!), body: m[2]! }));
  return { tables, alters };
}

function applyAlter(tables: Map<string, SqlTable>, a: { table: string; body: string }, file: string): void {
  const t = tables.get(a.table);
  if (!t) return;
  for (const part of splitTop(a.body)) {
    const p = part.trim().replace(/\s+/g, " ");
    let m: RegExpExecArray | null;
    if ((m = /^ADD (?:COLUMN )?(?:IF NOT EXISTS )?("?\w+"?) (.*)$/i.exec(p)) && !/^ADD (?:CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK)\b/i.test(p)) {
      const sub = parseCreateTables(`CREATE TABLE x (${m[1]} ${m[2]});`, file).tables[0]?.columns[0];
      if (sub && !t.columns.some((c) => c.name === sub.name)) t.columns.push(sub);
    } else if ((m = /^DROP (?:COLUMN )?(?:IF EXISTS )?("?\w+"?)/i.exec(p))) {
      const name = ident(m[1]!);
      t.columns = t.columns.filter((c) => c.name !== name);
    } else if ((m = /^ADD (?:CONSTRAINT [\w"]+ )?FOREIGN KEY\s*\(([^)]*)\)\s*REFERENCES\s+([\w."]+)\s*(?:\(([^)]*)\))?/i.exec(p))) {
      const col = t.columns.find((c) => c.name === ident(m![1]!));
      if (col) col.references = { table: ident(m[2]!), column: m[3] ? ident(m[3]) : "id" };
    } else if ((m = /^ALTER (?:COLUMN )?("?\w+"?) SET NOT NULL/i.exec(p))) {
      const col = t.columns.find((c) => c.name === ident(m![1]!));
      if (col) col.notNull = true;
    }
  }
}

/** Flyway version order: V1__a.sql < V1_1__b.sql < V2__c.sql. */
const flywayVersion = (f: string): number[] => (/^V([\d._]+)__/i.exec(f.split("/").pop()!)?.[1] ?? "0").split(/[._]/).map(Number);
const cmpVersion = (a: number[], b: number[]): number => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) - (b[i] ?? 0);
  return 0;
};

function findDirs(root: string, pick: (rel: string) => boolean, skip = new Set(["node_modules", ".git", "target", "build", "out", ".gradle", ".idea"])): string[] {
  const out: string[] = [];
  const visit = (d: string) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (!statSync(p).isDirectory() || skip.has(name)) continue;
      if (pick(relative(root, p))) out.push(p);
      visit(p);
    }
  };
  visit(root);
  return out;
}

export function readMigrations(root: string): MigrationFacts {
  const problems: string[] = [];
  const dirs = findDirs(root, (rel) => /(?:^|\/)src\/main\/resources\/db\/migration$/.test(rel));
  const files = dirs
    .flatMap((d) => readdirSync(d).filter((f) => /^V[\d._]+__.*\.sql$/i.test(f)).map((f) => join(d, f)))
    .sort((a, b) => cmpVersion(flywayVersion(a), flywayVersion(b)));
  if (files.length) {
    const tables = new Map<string, SqlTable>();
    for (const f of files) {
      const rel = relative(root, f);
      const { tables: ts, alters } = parseCreateTables(readFileSync(f, "utf8"), rel);
      for (const t of ts) tables.set(t.name, t);
      for (const a of alters) applyAlter(tables, a, rel);
      if (!ts.length && !alters.length && /\bCREATE\b/i.test(readFileSync(f, "utf8"))) problems.push(`${rel}: no CREATE TABLE statement could be read`);
    }
    return { tool: "flyway", files: files.map((f) => relative(root, f)), tables: [...tables.values()], problems };
  }
  const lq = findDirs(root, (rel) => /(?:^|\/)src\/main\/resources\/db$/.test(rel) || /(?:^|\/)src\/main\/resources$/.test(rel))
    .flatMap((d) => readdirSync(d).filter((f) => /^db\.changelog.*\.(?:ya?ml|xml|json|sql)$/i.test(f) || /changelog-master\.(?:ya?ml|xml)$/i.test(f)).map((f) => join(d, f)))
    .filter((f) => existsSync(f));
  if (lq.length) {
    problems.push(`Liquibase changelog found (${lq.map((f) => relative(root, f)).join(", ")}): its tables are not read statically; the schema is read from the database after migration`);
    return { tool: "liquibase", files: lq.map((f) => relative(root, f)), tables: [], problems };
  }
  return { tool: "none", files: [], tables: [], problems };
}
