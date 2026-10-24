// Tiny intentionally-flawed app for Argos tests. FIXED=1 turns the flaws off.
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";

const fixed = process.env.FIXED === "1";
const db = new DatabaseSync("./data.db");
const tokens = { "tok-v1": "v1", "tok-v2": "v2" };

createServer((req, res) => {
  const org = tokens[(req.headers.authorization ?? "").replace("Bearer ", "")];
  const m = /^\/api\/datasets\/(\d+)$/.exec(req.url);
  if (m) {
    if (!org) return void res.writeHead(401).end();
    const row = db.prepare("SELECT * FROM datasets WHERE id = ?").get(Number(m[1]));
    if (!row) return void res.writeHead(404).end();
    if (fixed && row.vendor_id !== org) return void res.writeHead(403).end(); // flaw 1 when !fixed
    return void res.end(JSON.stringify(row));
  }
  if (req.url === "/api/export" && req.method === "POST") {
    if (fixed && !org) return void res.writeHead(401).end(); // flaw 2 when !fixed
    return void res.end("{}");
  }
  if (req.url === "/health") return void res.end("ok");
  res.writeHead(404).end();
}).listen(Number(process.env.PORT), "127.0.0.1");
