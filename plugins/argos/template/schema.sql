-- Applied by the app on start (idempotent) and by Argos before seeding.
-- Owner columns: datasets.vendor_id, tasks.vendor_id, vendors.id (values are persona orgs: v1, v2, v3).
-- No enforced foreign keys, so a seeder can insert rows table by table.

CREATE TABLE IF NOT EXISTS vendors (
  id            TEXT PRIMARY KEY,
  name          TEXT,
  contact_email TEXT,
  api_key       TEXT
);

CREATE TABLE IF NOT EXISTS datasets (
  id          INTEGER PRIMARY KEY,
  vendor_id   TEXT NOT NULL,
  name        TEXT,
  description TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
  id           INTEGER PRIMARY KEY,
  dataset_id   INTEGER NOT NULL,
  vendor_id    TEXT NOT NULL,
  title        TEXT,
  instructions TEXT,
  status       TEXT NOT NULL DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS products (
  id      INTEGER PRIMARY KEY,
  name    TEXT,
  summary TEXT
);
