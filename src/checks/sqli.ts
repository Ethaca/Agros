import type { Config } from "../config.js";
import { fillPath, parseRoute, sendAs, type HttpResult, type Persona } from "../http.js";
import type { SeedManifest } from "../seed.js";
import type { Finding, Verdict } from "../types.js";

const is2xx = (r: HttpResult) => r.status !== null && r.status >= 200 && r.status < 300;
const is5xx = (r: HttpResult) => r.status !== null && r.status >= 500;
const show = (r: HttpResult) => (r.status === null ? `no response (${r.error})` : String(r.status));

export interface SqliOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
}

/**
 * sqli, three stages per query parameter: "1" (control) -> "'" (provoke an error) -> "''" (escaped, must be normal).
 * RED only when control is 2xx, `'` is a 5xx and `''` is 2xx again: the quote reached the SQL string.
 * A failing control is SKIPPED (the request path is not working), never "safe".
 */
export async function sqli(cfg: Config, baseUrl: string, manifest: SeedManifest, opts: SqliOptions = {}): Promise<Finding[]> {
  const out: Finding[] = [];
  const authed = cfg.personas.find((p) => p.auth.type === "bearer");
  const anon = cfg.personas.find((p) => p.auth.type === "none");

  for (const r of cfg.resources) {
    const { method, path, queryNames } = parseRoute(r.route);
    const params = [...new Set([...(r.params ?? []), ...queryNames])];
    if (!params.length) continue;
    const persona: Persona | undefined = r.public ? anon : authed;
    if (method !== "GET" || !persona) {
      out.push(skip(r.id, persona?.name ?? "-", r.route, method !== "GET" ? "sqli only tests GET routes" : "no persona available"));
      continue;
    }
    const rowId = (persona.org && manifest.ids[r.id]?.[persona.org]) || 1;
    const filled = fillPath(path, rowId);

    for (const param of params) {
      const send = (value: string) => sendAs(baseUrl, persona, method, filled, { query: { [param]: value }, timeoutMs: opts.timeoutMs, maxResponseBytes: opts.maxResponseBytes });
      const control = await send("1");
      if (!is2xx(control)) {
        out.push(skip(r.id, persona.name, control.request, `control request failed (${show(control)}); cannot judge injection on "${param}"`));
        continue;
      }
      const quote = await send("'");
      const escaped = await send("''");
      let verdict: Verdict;
      let detail: string;
      if (is5xx(quote) && is2xx(escaped)) {
        verdict = "VULNERABLE";
        detail = `"${param}" is concatenated into SQL: ' -> ${show(quote)}, '' -> ${show(escaped)}`;
      } else if (is5xx(quote)) {
        verdict = "SUSPECTED";
        detail = `"${param}": ' -> ${show(quote)} but '' -> ${show(escaped)} (server errors on quotes, injection not confirmed)`;
      } else if (quote.status === null) {
        out.push(skip(r.id, persona.name, quote.request, `no response to the quote request (${quote.error})`));
        continue;
      } else {
        verdict = "OK";
        detail = `"${param}" handled quotes safely: ' -> ${show(quote)}, '' -> ${show(escaped)}`;
      }
      out.push({
        check: "sqli",
        resourceId: r.id,
        persona: persona.name,
        verdict,
        proof: { request: quote.request, ...(quote.status !== null ? { status: quote.status } : {}), note: `control ${show(control)} / ' ${show(quote)} / '' ${show(escaped)}` },
        detail,
      });
    }
  }
  return out;
}

function skip(resourceId: string, persona: string, request: string, detail: string): Finding {
  return { check: "sqli", resourceId, persona, verdict: "SKIPPED", proof: { request }, detail };
}
