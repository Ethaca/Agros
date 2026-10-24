import type { Config } from "./config.js";
import { fillPath, parseRoute, sendAs, type HttpResult, type Persona } from "./http.js";
import { maskMarker, redact, type SeedManifest } from "./seed.js";
import type { Access, Evidence, Matrix, MatrixCell, Observed, Verdict } from "./types.js";

type Resource = Config["resources"][number];

export interface Obs {
  status: number | null;
  body: string;
  /** Marker of the row that was requested; undefined for resources without rows. */
  marker?: string;
  /** Persona is requesting its own row (a 404 then is an error, not hidden existence). */
  ownRequest: boolean;
}

/** SPEC 6.4: 2xx + requested row's marker -> allow; 401/403 -> deny; 404 -> deny (own request: error); 2xx w/o marker -> allow-empty. */
export function observe(o: Obs): Observed {
  const s = o.status;
  if (s === null) return "error";
  if (s >= 200 && s < 300) {
    if (o.marker === undefined) return "allow";
    return o.body.includes(o.marker) ? "allow" : "allow-empty";
  }
  if (s === 401 || s === 403) return "deny";
  if (s === 404) return o.ownRequest ? "error" : "deny";
  return "error";
}

/** expected deny + allow -> VULNERABLE. Contrast failures and ambiguous results are SUSPECTED/SKIPPED, never OK. */
export function verdictFor(expected: Access, observed: Observed): Verdict {
  if (observed === "error") return "SKIPPED";
  if (expected === "deny") {
    if (observed === "deny") return "OK";
    return observed === "allow" ? "VULNERABLE" : "SUSPECTED";
  }
  return observed === "allow" ? "OK" : "SUSPECTED";
}

interface Plan {
  persona: Persona;
  resource: Resource;
  target?: string;
  expected: Access;
}

function plan(cfg: Config): Plan[] {
  const orgs = [...new Set(cfg.personas.map((p) => p.org).filter((o): o is string => !!o))];
  const out: Plan[] = [];
  for (const persona of cfg.personas) {
    for (const resource of cfg.resources) {
      const exp = resource.expect;
      if (resource.public) {
        out.push({ persona, resource, expected: "allow" });
      } else if (!resource.owner) {
        out.push({ persona, resource, expected: persona.org ? exp!.owner : exp!.anonymous });
      } else if (!persona.org) {
        out.push({ persona, resource, target: orgs[0], expected: exp!.anonymous });
      } else {
        out.push({ persona, resource, target: persona.org, expected: exp!.owner });
        for (const o of orgs) if (o !== persona.org) out.push({ persona, resource, target: o, expected: exp!.other });
      }
    }
  }
  return out;
}

function skipped(p: Plan, request: string, note: string): MatrixCell {
  return {
    persona: p.persona.name,
    resource: p.resource.id,
    ...(p.target ? { target: p.target } : {}),
    expected: p.expected,
    observed: "error",
    verdict: "SKIPPED",
    evidence: { request, note },
  };
}

export interface MatrixOptions {
  timeoutMs?: number;
}

/** Build the full persona x resource matrix against a running target. Requests run sequentially. */
export async function runMatrix(
  cfg: Config,
  baseUrl: string,
  manifest: SeedManifest,
  opts: MatrixOptions = {},
): Promise<Matrix> {
  const cells: MatrixCell[] = [];
  for (const p of plan(cfg)) {
    const { method, path } = parseRoute(p.resource.route);
    if (method !== "GET" && !p.resource.safe) {
      cells.push(skipped(p, p.resource.route, "non-GET route not marked safe: true"));
      continue;
    }
    const marker = p.target ? manifest.markers[p.resource.id]?.[p.target] : undefined;
    const rowId = p.target ? manifest.ids[p.resource.id]?.[p.target] : undefined;
    if (p.target && (marker === undefined || rowId === undefined)) {
      cells.push(skipped(p, p.resource.route, `no seeded row for org "${p.target}"`));
      continue;
    }
    const res: HttpResult = await sendAs(baseUrl, p.persona, method, fillPath(path, rowId ?? 1), {
      timeoutMs: opts.timeoutMs,
      json: method === "GET" ? undefined : {},
    });
    const observed = observe({
      status: res.status,
      body: res.body,
      marker,
      ownRequest: !!p.target && p.target === p.persona.org,
    });
    cells.push({
      persona: p.persona.name,
      resource: p.resource.id,
      ...(p.target ? { target: p.target } : {}),
      expected: p.expected,
      observed,
      verdict: verdictFor(p.expected, observed),
      evidence: evidenceFor(res, marker, manifest),
    });
  }
  return {
    personas: cfg.personas.map((x) => x.name),
    resources: cfg.resources.map((r) => r.id),
    cells,
  };
}

/** M4: request line, status, and a short body excerpt with markers masked. */
function evidenceFor(res: HttpResult, marker: string | undefined, manifest: SeedManifest): Evidence {
  const ev: Evidence = { request: res.request };
  if (res.status !== null) ev.status = res.status;
  if (marker !== undefined && res.body.includes(marker)) ev.marker = maskMarker(marker);
  const note = res.error ?? redact(res.body.slice(0, 160), manifest);
  if (note) ev.note = note;
  return ev;
}

const ICON: Record<Verdict, string> = { VULNERABLE: "🔴", SUSPECTED: "🟡", OK: "🟢", SKIPPED: "⚪" };

/** Markdown table (also readable in a terminal): rows = persona → target, columns = resources. */
export function renderMatrixMarkdown(m: Matrix): string {
  const rowKeys: string[] = [];
  const grid = new Map<string, MatrixCell>();
  for (const c of m.cells) {
    const key = c.target ? `${c.persona} → ${c.target}` : c.persona;
    if (!rowKeys.includes(key)) rowKeys.push(key);
    grid.set(`${key}|${c.resource}`, c);
  }
  const head = `| persona → data | ${m.resources.join(" | ")} |`;
  const sep = `|---|${m.resources.map(() => "---").join("|")}|`;
  const rows = rowKeys.map((k) => {
    const cols = m.resources.map((r) => {
      const c = grid.get(`${k}|${r}`);
      return c ? `${ICON[c.verdict]} ${c.expected}/${c.observed}` : "–";
    });
    return `| ${k} | ${cols.join(" | ")} |`;
  });
  return [head, sep, ...rows, "", "cell = verdict expected/observed · 🔴 VULNERABLE 🟡 SUSPECTED 🟢 OK ⚪ SKIPPED"].join("\n");
}
