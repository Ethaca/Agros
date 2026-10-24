// Bridge: Argos API (static PR analysis) -> Argos (dynamic attack proof).
//
// Argos API reads a PR diff and reports SUSPECTED findings it cannot execute
// ("verificationStatus: not_run"). The dynamic engine boots the app and attacks
// it, so a static SUSPECT can be turned into a proven VULNERABLE/OK. This module
// turns Argos API findings into Argos resources: it drafts an argos.config.yaml
// (like `argos init`) and annotates an existing config so the matrix shows which
// routes the static analysis independently flagged.
//
// Everything here is pure (no IO); the CLI does the reading/writing.

import type { CheckName } from "./types.js";
import type { Config } from "./config.js";

/** The subset of an Argos API finding we rely on. Parsed loosely from JSON. */
export interface ArgosApiFinding {
  id: string;
  category: string; // API1..API10 | INJECTION | SECRETS
  severity?: string;
  title?: string;
  file?: string;
  line?: number;
  evidence?: string;
  impact?: { steps?: { evidence?: { quote?: string }[] }[] };
}

/**
 * Argos API OWASP categories -> the Argos check that can prove them.
 * Argos only runs bola/unauth/sqli/secrets, so categories outside that surface
 * (SSRF, misconfig, inventory, rate limits, upstream APIs) map to null: still
 * reported, but Argos can't execute a proof for them yet.
 */
export const CATEGORY_TO_CHECK: Record<string, CheckName | null> = {
  API1: "bola", // Broken Object Level Authorization
  API2: "unauth", // Broken Authentication
  API3: "secrets", // Broken Object Property Level Authorization (over-exposed fields)
  API4: null, // Unrestricted Resource Consumption
  API5: "unauth", // Broken Function Level Authorization
  API6: null, // Unrestricted Access to Sensitive Business Flows
  API7: null, // SSRF
  API8: null, // Security Misconfiguration
  API9: "unauth", // Improper Inventory Management (e.g. /debug reachable without auth)
  API10: null, // Unsafe Consumption of APIs
  INJECTION: "sqli",
  SECRETS: "secrets",
};

const ROUTE_RE = /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/i;
const TABLE_RE = /\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)/i;

function quotesOf(f: ArgosApiFinding): string[] {
  const out: string[] = [];
  if (f.evidence) out.push(f.evidence);
  for (const s of f.impact?.steps ?? []) for (const e of s.evidence ?? []) if (e.quote) out.push(e.quote);
  return out;
}

/** "app.get("/api/x/:id", ...)" -> "GET /api/x/:id". Express `:param` is Argos-native. */
export function extractRoute(text: string): string | null {
  const m = ROUTE_RE.exec(text);
  if (!m) return null;
  return `${m[1]!.toUpperCase()} ${m[2]!.split("?")[0]}`;
}

/** "SELECT * FROM datasets WHERE ..." -> "datasets". A hint for `owner.table`. */
export function extractOwnerTable(text: string): string | null {
  const m = TABLE_RE.exec(text);
  return m ? m[1]!.toLowerCase() : null;
}

export interface DraftResource {
  id: string;
  route: string;
  check: CheckName;
  ownerTableHint?: string;
  /** Argos API finding ids that produced this resource. */
  from: string[];
  /** Highest Argos API severity among `from`. */
  severity?: string;
}

export interface BridgeResult {
  resources: DraftResource[];
  /** Union of checks the drafted resources need, in a stable order. */
  checks: CheckName[];
  /** Findings Argos cannot execute a proof for, kept for the report. */
  unmapped: { id: string; category: string; title?: string; reason: string }[];
}

const CHECK_ORDER: CheckName[] = ["bola", "unauth", "sqli", "secrets"];

function slug(route: string): string {
  return route
    .toLowerCase()
    .replace(/^[a-z]+ /, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "root";
}

/** SQL-sink findings carry the owner table but no route; attach within this many lines. */
const SINK_WINDOW = 20;

/** Group findings by the route they touch, pick the Argos check, keep the rest. */
export function bridgeFindings(findings: ArgosApiFinding[]): BridgeResult {
  const byRoute = new Map<string, DraftResource & { file?: string; line?: number }>();
  const unmapped: BridgeResult["unmapped"] = [];
  const rank = (s?: string) => ["critical", "high", "medium", "low", "info"].indexOf(s ?? "info");

  // Argos API emits a route handler and its SQL sink as separate findings a few
  // lines apart. Pass 1 builds a resource per route; pass 2 attaches the owner
  // table from a nearby sink finding in the same file.
  const sinks: { f: ArgosApiFinding; table: string; check: CheckName }[] = [];

  for (const f of findings) {
    const check = CATEGORY_TO_CHECK[f.category] ?? null;
    const quotes = quotesOf(f);
    const route = quotes.map(extractRoute).find((r): r is string => !!r) ?? null;
    const table = quotes.map(extractOwnerTable).find((t): t is string => !!t) ?? undefined;

    if (!check) {
      unmapped.push({ id: f.id, category: f.category, title: f.title, reason: "no Argos check for this category yet" });
      continue;
    }
    if (!route) {
      if (table) sinks.push({ f, table, check });
      else unmapped.push({ id: f.id, category: f.category, title: f.title, reason: "could not extract a route from the finding" });
      continue;
    }

    const existing = byRoute.get(route);
    if (existing) {
      existing.from.push(f.id);
      // BOLA/sqli are more specific proofs than a generic unauth; keep the stronger one.
      if (CHECK_ORDER.indexOf(check) < CHECK_ORDER.indexOf(existing.check)) existing.check = check;
      if (!existing.ownerTableHint && table) existing.ownerTableHint = table;
      if (rank(f.severity) < rank(existing.severity)) existing.severity = f.severity;
    } else {
      byRoute.set(route, { id: slug(route), route, check, ownerTableHint: table, from: [f.id], severity: f.severity, file: f.file, line: f.line });
    }
  }

  const routeResources = [...byRoute.values()];
  for (const { f, table } of sinks) {
    // Attach to the nearest route in the same file whose handler is just above the sink.
    const owner = routeResources
      .filter((r) => r.file && f.file && r.file === f.file && f.line != null && r.line != null && f.line >= r.line && f.line - r.line <= SINK_WINDOW)
      .sort((a, b) => (f.line! - a.line!) - (f.line! - b.line!))[0];
    if (owner) {
      owner.from.push(f.id);
      if (!owner.ownerTableHint) owner.ownerTableHint = table;
    } else {
      unmapped.push({ id: f.id, category: f.category, title: f.title, reason: "SQL sink with no nearby route handler" });
    }
  }

  const resources: DraftResource[] = routeResources.map(({ file: _f, line: _l, ...r }) => r);
  const checks = CHECK_ORDER.filter((c) => resources.some((r) => r.check === c));
  return { resources, checks, unmapped };
}

/**
 * Match Argos API findings against the resources already in an argos.config.yaml,
 * by route. The overlap is two independent tools agreeing on the same endpoint;
 * `argos scan` then proves or clears each one.
 */
export function annotateConfig(
  cfg: Pick<Config, "resources">,
  findings: ArgosApiFinding[],
): { matched: { resourceId: string; route: string; findingIds: string[] }[]; unmatchedFindings: string[] } {
  const routeToResource = new Map<string, { id: string; route: string }>();
  for (const r of cfg.resources) routeToResource.set(r.route, { id: r.id, route: r.route });

  const matched = new Map<string, { resourceId: string; route: string; findingIds: string[] }>();
  const unmatchedFindings: string[] = [];
  for (const f of findings) {
    const route = quotesOf(f).map(extractRoute).find((r): r is string => !!r);
    const hit = route ? routeToResource.get(route) : undefined;
    if (!hit) {
      unmatchedFindings.push(f.id);
      continue;
    }
    const e = matched.get(hit.id) ?? { resourceId: hit.id, route: hit.route, findingIds: [] };
    e.findingIds.push(f.id);
    matched.set(hit.id, e);
  }
  return { matched: [...matched.values()], unmatchedFindings };
}

/** Parse an Argos API JSON blob: either a bare array or `{ findings: [...] }`. */
export function parseArgosApiFindings(raw: unknown): ArgosApiFinding[] {
  const arr = Array.isArray(raw) ? raw : (raw as { findings?: unknown })?.findings;
  if (!Array.isArray(arr)) throw new Error("expected an array of findings or an object with a `findings` array");
  return arr.filter((f): f is ArgosApiFinding => !!f && typeof (f as ArgosApiFinding).category === "string");
}

/**
 * Render a draft argos.config.yaml from bridged findings. The target/seed/personas
 * blocks are scaffolding the user must complete (static analysis can't know the
 * start command or auth tokens) — mirrors how `argos init` emits a draft.
 */
export function renderDraftConfig(bridged: BridgeResult, opts: { target?: string } = {}): string {
  const L: string[] = [];
  L.push("# Draft generated by `argos import-findings` from Argos API findings.");
  L.push("# Routes and checks are inferred from static analysis; complete the");
  L.push("# TODO fields (start command, auth tokens, owner columns) before scanning.");
  L.push("version: 1");
  L.push("target:");
  L.push(`  start: "${opts.target ?? "TODO: command that boots the app (e.g. node app.mjs)"}"`);
  L.push('  cwd: "."');
  L.push('  readyPath: "/health"');
  L.push("seed:");
  L.push('  schema: "schema.sql"    # TODO: path to the DB schema to seed');
  L.push('  dbPath: "./data.db"');
  L.push("personas:");
  L.push("  # TODO: real auth tokens for two vendors + an anonymous persona.");
  L.push('  - { name: vendor1, org: v1, auth: { type: bearer, token: "TODO" } }');
  L.push('  - { name: vendor2, org: v2, auth: { type: bearer, token: "TODO" } }');
  L.push("  - { name: anonymous, auth: { type: none } }");
  L.push("resources:");
  for (const r of bridged.resources) {
    const from = r.from.join(", ");
    L.push(`  # ${r.check.toUpperCase()} candidate from Argos API [${from}]${r.severity ? ` (severity: ${r.severity})` : ""}`);
    L.push(`  - id: ${r.id}`);
    L.push(`    route: "${r.route}"`);
    if (r.route.includes(":")) {
      L.push(`    owner: { table: ${r.ownerTableHint ?? "TODO_table"}, column: TODO_column }`);
    }
    L.push("    expect: { owner: allow, other: deny, anonymous: deny }   # TODO: confirm");
  }
  L.push(`checks: [${bridged.checks.join(", ")}]`);
  if (bridged.unmapped.length) {
    L.push("# Not executable by Argos yet (reported by Argos API only):");
    for (const u of bridged.unmapped) L.push(`#   ${u.id} ${u.category}: ${u.title ?? ""} — ${u.reason}`);
  }
  return L.join("\n") + "\n";
}
