import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { Registry } from "./types.js";
import { keyBytes, keyId } from "./token.js";

export class CanaryError extends Error {}
export const sha256 = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
export function parseJson<T>(path: string, schema: { parse(data: unknown): T }): T {
  try { return schema.parse(JSON.parse(readFileSync(path, "utf8"))); }
  catch { throw new CanaryError(`cannot read or validate ${path}`); }
}
export function loadRegistry(path: string): { registry: Registry; registrySha256: string } {
  const registry = parseJson(path, Registry);
  if (process.env.ARGOS_CANARY_KEY && keyId(keyBytes()) !== registry.keyId) throw new CanaryError("canary key does not match registry");
  return { registry, registrySha256: sha256(readFileSync(path)) };
}
export function writeJson(path: string, value: unknown): void {
  // Exclusive create also prevents following an existing symlink or retaining permissive modes.
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600, flag: "wx" });
}
export function bind(registry: Registry, registrySha256: string) {
  return { version: 1 as const, datasetId: registry.datasetId, registrySha256 };
}
