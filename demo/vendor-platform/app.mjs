// Argos demo target: 3 vendors x datasets x tasks, with 5 PLANTED flaws (see "FLAW n").
// Intentionally insecure. Run only locally against throwaway data.
import express from "express";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";

const db = new DatabaseSync(process.env.DB_PATH ?? "./data.db");
db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));

// Bearer token -> vendor id. Matches the personas in argos.config.yaml.
const tokens = new Map(
  (process.env.DEMO_TOKENS ?? "tok-v1:v1,tok-v2:v2,tok-v3:v3").split(",").map((pair) => pair.split(":")),
);

function auth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get("authorization") ?? "");
  const vendorId = m && tokens.get(m[1]);
  if (!vendorId) return res.status(401).json({ error: "unauthorized" });
  req.user = { vendor_id: vendorId };
  next();
}

const app = express();
app.use(express.json());

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/products", (req, res) => {
  res.json(db.prepare("SELECT id, name, summary FROM products").all());
});

app.get("/api/me", auth, (req, res) => {
  res.json(db.prepare("SELECT id, name, contact_email FROM vendors WHERE id = ?").get(req.user.vendor_id) ?? { id: req.user.vendor_id });
});

app.get("/api/datasets", auth, (req, res) => {
  const search = String(req.query.search ?? "");
  // FLAW 3 (sqli): search is concatenated into the SQL string
  const rows = db
    .prepare(`SELECT id, vendor_id, name, description FROM datasets WHERE vendor_id = ? AND name LIKE '%${search}%'`)
    .all(req.user.vendor_id);
  res.json(rows);
});

app.get("/api/datasets/:id", auth, (req, res) => {
  // FLAW 1 (bola): no vendor check, any logged-in vendor can read any dataset
  const row = db.prepare("SELECT * FROM datasets WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

app.get("/api/datasets/:id/tasks", auth, (req, res) => {
  const ds = db.prepare("SELECT id FROM datasets WHERE id = ? AND vendor_id = ?").get(req.params.id, req.user.vendor_id);
  if (!ds) return res.status(404).json({ error: "not found" });
  res.json(
    db
      .prepare("SELECT id, dataset_id, vendor_id, title, instructions, status FROM tasks WHERE dataset_id = ? AND vendor_id = ?")
      .all(req.params.id, req.user.vendor_id),
  );
});

app.get("/api/tasks/:id", auth, (req, res) => {
  const row = db
    .prepare("SELECT id, dataset_id, vendor_id, title, instructions, status FROM tasks WHERE id = ? AND vendor_id = ?")
    .get(req.params.id, req.user.vendor_id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

// Vendor directory: logged-in vendors may see each other's public profile.
app.get("/api/vendors/:id", auth, (req, res) => {
  // FLAW 4 (secrets a): SELECT * also returns api_key to every logged-in vendor
  const row = db.prepare("SELECT * FROM vendors WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

// FLAW 2 (unauth): no auth middleware and no vendor scope, anyone can export any dataset
app.post("/api/export", (req, res) => {
  const id = req.body?.datasetId ?? req.query.datasetId;
  const datasets = id
    ? db.prepare("SELECT * FROM datasets WHERE id = ?").all(id)
    : db.prepare("SELECT * FROM datasets").all();
  const tasksOf = db.prepare("SELECT * FROM tasks WHERE dataset_id = ?");
  res.json({ datasets: datasets.map((d) => ({ ...d, tasks: tasksOf.all(d.id) })) });
});

// FLAW 5 (secrets b): debug endpoint left on, dumps the whole process environment
app.get("/debug/env", (req, res) => res.json(process.env));

app.use((err, req, res, next) => {
  res.status(500).json({ error: "internal error" });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, "127.0.0.1", () => console.log(`vendor-platform listening on http://127.0.0.1:${port}`));
