// Tiny intentionally-flawed app for Argos tests. FIXED=1 turns the flaws off.
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";

const fixed = process.env.FIXED === "1";
const db = new DatabaseSync("./data.db");
const tokens = { "tok-v1": "v1", "tok-v2": "v2" };

createServer((req, res) => {
  const org = tokens[(req.headers.authorization ?? "").replace("Bearer ", "")];
  const u = new URL(req.url, "http://x");
  const m = /^\/api\/datasets\/(\d+)$/.exec(u.pathname);
  const v = /^\/api\/vendors\/(\w+)$/.exec(u.pathname);
  if (m) {
    if (!org) return void res.writeHead(401).end();
    const row = db.prepare("SELECT * FROM datasets WHERE id = ?").get(Number(m[1]));
    if (!row) return void res.writeHead(404).end();
    if (fixed && row.vendor_id !== org) return void res.writeHead(403).end(); // flaw 1 when !fixed
    return void res.end(JSON.stringify(row));
  }
  if (v) {
    // flaw 4 when !fixed: no auth/owner check, SELECT * returns api_key
    if (fixed && v[1] !== org) return void res.writeHead(org ? 403 : 401).end();
    const row = db.prepare(fixed ? "SELECT id, name FROM vendors WHERE id = ?" : "SELECT * FROM vendors WHERE id = ?").get(v[1]);
    return row ? void res.end(JSON.stringify(row)) : void res.writeHead(404).end();
  }
  if (u.pathname === "/api/datasets") {
    if (!org) return void res.writeHead(401).end();
    const q = u.searchParams.get("search") ?? "";
    try {
      // flaw 3 when !fixed: string concatenation
      const rows = fixed
        ? db.prepare("SELECT id, name FROM datasets WHERE name LIKE ?").all(`%${q}%`)
        : db.prepare(`SELECT id, name FROM datasets WHERE name LIKE '%${q}%'`).all();
      return void res.end(JSON.stringify(rows));
    } catch (e) {
      return void res.writeHead(500).end("sql error");
    }
  }
  if (req.url === "/api/export" && req.method === "POST") {
    if (fixed && !org) return void res.writeHead(401).end(); // flaw 2 when !fixed
    return void res.end("{}");
  }
  if (u.pathname === "/debug/env" && !fixed) return void res.end(JSON.stringify(process.env)); // flaw 5
  if (req.url === "/health") return void res.end("ok");
  res.writeHead(404).end();
}).listen(Number(process.env.PORT), "127.0.0.1");
