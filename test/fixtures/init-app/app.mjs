// Dependency-free app with an Express-shaped router, used to test `argos init` end to end.
// Intentional flaw: GET /api/notes/:id has no owner check; GET /api/orgs/:id selects api_key; /debug/env dumps env.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(process.env.DB_PATH ?? "./data.db");
db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
const tokens = new Map((process.env.APP_TOKENS ?? "tk-a:orgA,tk-b:orgB").split(",").map((p) => p.split(":")));

const routes = [];
const app = {
  get: (path, ...h) => routes.push({ method: "GET", path, h }),
  post: (path, ...h) => routes.push({ method: "POST", path, h }),
};
function auth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  const org = m && tokens.get(m[1]);
  if (!org) return res.status(401).json({ error: "unauthorized" });
  req.user = { org_id: org };
  next();
}

app.get("/health", (req, res) => res.json({ ok: true }));
app.get("/api/tips", (req, res) => res.json(db.prepare("SELECT id, text FROM tips").all()));
app.get("/api/notes", auth, (req, res) => {
  const q = String(req.query.search ?? "");
  res.json(db.prepare("SELECT id, org_id, title FROM notes WHERE org_id = ? AND title LIKE ?").all(req.user.org_id, `%${q}%`));
});
app.get("/api/notes/:id", auth, (req, res) => {
  const row = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
  row ? res.json(row) : res.status(404).json({ error: "not found" });
});
app.get("/api/orgs/:id", auth, (req, res) => {
  const row = db.prepare("SELECT * FROM orgs WHERE id = ?").get(req.params.id);
  row ? res.json(row) : res.status(404).json({ error: "not found" });
});
app.post("/api/notes", auth, (req, res) => {
  db.prepare("INSERT INTO notes (org_id, title, body) VALUES (?, ?, ?)").run(req.user.org_id, req.body?.title, req.body?.body);
  res.json({ ok: true });
});
app.get("/debug/env", (req, res) => res.json(process.env));

createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  req.query = Object.fromEntries(url.searchParams);
  res.status = (c) => ((res.statusCode = c), res);
  res.json = (b) => (res.setHeader("content-type", "application/json"), res.end(JSON.stringify(b)));
  for (const r of routes) {
    if (r.method !== req.method) continue;
    const names = [];
    const re = new RegExp("^" + r.path.replace(/:(\w+)/g, (_, n) => (names.push(n), "([^/]+)")) + "$");
    const m = re.exec(url.pathname);
    if (!m) continue;
    req.params = Object.fromEntries(names.map((n, i) => [n, m[i + 1]]));
    let i = 0;
    const next = () => r.h[i++](req, res, next);
    return next();
  }
  res.status(404).json({ error: "not found" });
}).listen(Number(process.env.PORT ?? 3000), "127.0.0.1");
