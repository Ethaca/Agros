// Reset the DB to the manual fixture: node seed.mjs   (DB_PATH, default ./data.db)
import { DatabaseSync } from "node:sqlite";
import { readFileSync, rmSync } from "node:fs";

const dbPath = process.env.DB_PATH ?? "./data.db";
rmSync(dbPath, { force: true });
const db = new DatabaseSync(dbPath);
db.exec(readFileSync(new URL("./schema.sql", import.meta.url), "utf8"));
db.exec(readFileSync(new URL("./seed.sql", import.meta.url), "utf8"));
db.close();
console.log(`seeded ${dbPath}`);
