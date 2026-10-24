import { createServer, type Server } from "node:http";
import { parseConfig, type Config } from "../../src/config.js";
import type { SeedManifest } from "../../src/seed.js";

export const M1 = "ARGOS_dataset-read_v1_aaaaaa";
export const M2 = "ARGOS_dataset-read_v2_bbbbbb";

const ROWS: Record<string, { org: string; marker: string }> = { "1": { org: "v1", marker: M1 }, "2": { org: "v2", marker: M2 } };
const TOKENS: Record<string, string> = { "tok-v1": "v1", "tok-v2": "v2" };

export function app(opts: { checkOwner: boolean; exportNeedsAuth: boolean }): Promise<Server> {
  return new Promise((ok) => {
    const srv = createServer((req, res) => {
      const org = TOKENS[(req.headers.authorization ?? "").replace("Bearer ", "")];
      const url = req.url!;
      const m = /^\/api\/datasets\/(\w+)$/.exec(url);
      if (m) {
        if (!org) return void res.writeHead(401).end();
        const row = ROWS[m[1]!];
        if (!row) return void res.writeHead(404).end();
        if (opts.checkOwner && row.org !== org) return void res.writeHead(403).end();
        return void res.end(JSON.stringify({ name: row.marker }));
      }
      if (url === "/api/export" && req.method === "POST") {
        if (opts.exportNeedsAuth && !org) return void res.writeHead(401).end();
        return void res.end("{}");
      }
      if (url === "/health") return void res.end("ok");
      res.writeHead(404).end();
    }).listen(0, "127.0.0.1", () => ok(srv));
  });
}

export const cfg = (): Config =>
  parseConfig({
    version: 1,
    target: { start: "x" },
    personas: [
      { name: "vendor1", org: "v1", auth: { type: "bearer", token: "tok-v1" } },
      { name: "vendor2", org: "v2", auth: { type: "bearer", token: "tok-v2" } },
      { name: "anonymous", auth: { type: "none" } },
    ],
    resources: [
      { id: "dataset-read", route: "GET /api/datasets/:id", owner: { table: "datasets", column: "vendor_id" }, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "export", route: "POST /api/export", safe: true, expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "danger", route: "DELETE /api/datasets/1", expect: { owner: "allow", other: "deny", anonymous: "deny" } },
      { id: "health", route: "GET /health", public: true },
    ],
    checks: ["bola", "unauth"],
  });

export const manifest: SeedManifest = {
  markers: { "dataset-read": { v1: M1, v2: M2 } },
  secrets: [],
  ids: { "dataset-read": { v1: 1, v2: 2 } },
};

