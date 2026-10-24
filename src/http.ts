import type { Config } from "./config.js";

export type Persona = Config["personas"][number];

export interface HttpResult {
  /** e.g. "GET /api/datasets/1" (no host, no credentials). */
  request: string;
  status: number | null;
  body: string;
  headers: Record<string, string>;
  /** Set when no HTTP response arrived (connection error, timeout). */
  error?: string;
}

export interface RequestOptions {
  timeoutMs?: number;
  /** JSON body for non-GET requests. */
  json?: unknown;
  query?: Record<string, string>;
}

export const REQUEST_TIMEOUT_MS = 5_000;

/** `GET /api/datasets?search=` -> path "/api/datasets", query names ["search"]. */
export function parseRoute(route: string): { method: string; path: string; queryNames: string[] } {
  const [method, full] = route.split(" ", 2);
  const [path, qs = ""] = full!.split("?", 2);
  const queryNames = qs.split("&").map((kv) => kv.split("=")[0]!).filter(Boolean);
  return { method: method!, path: path!, queryNames };
}

/** Fill `:name` params. All params get the same value (one id per request). */
export function fillPath(path: string, id: string | number): string {
  return path.replace(/:[A-Za-z_][A-Za-z0-9_]*/g, encodeURIComponent(String(id)));
}

export function authHeaders(persona: Persona): Record<string, string> {
  return persona.auth.type === "bearer" ? { authorization: `Bearer ${persona.auth.token}` } : {};
}

/** Never throws: network failures come back as `error` so callers can mark the cell SKIPPED, not "safe". */
export async function sendAs(
  baseUrl: string,
  persona: Persona,
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<HttpResult> {
  const qs = opts.query ? "?" + new URLSearchParams(opts.query).toString() : "";
  const request = `${method} ${path}${qs}`;
  const hasBody = opts.json !== undefined && method !== "GET";
  try {
    const res = await fetch(baseUrl + path + qs, {
      method,
      redirect: "manual",
      headers: { ...authHeaders(persona), ...(hasBody ? { "content-type": "application/json" } : {}) },
      body: hasBody ? JSON.stringify(opts.json) : undefined,
      signal: AbortSignal.timeout(opts.timeoutMs ?? REQUEST_TIMEOUT_MS),
    });
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    return { request, status: res.status, body, headers };
  } catch (e) {
    return { request, status: null, body: "", headers: {}, error: (e as Error).message };
  }
}
