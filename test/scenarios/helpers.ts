import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Finding, Matrix, Verdict } from "../../src/types.js";

export const ROOT = resolve(".");
export const APPS = ["vendor-platform", "realistic-app"] as const;
export type App = (typeof APPS)[number];

/** Scenarios run the real CLI against A's demo apps; they need `npm install` inside each demo dir. */
export const skipReason = (): string | false => {
  const missing = APPS.filter((a) => !existsSync(join(ROOT, "demo", a, "node_modules")));
  return missing.length ? `demo dependencies missing (run: cd demo/${missing[0]} && npm install)` : false;
};

export const hasCurl = (): boolean => spawnSync("curl", ["--version"]).status === 0;

/** Fresh temp copy so `fix --apply` and seeding never touch demo/. */
export function copyApp(app: App): string {
  const dir = mkdtempSync(join(tmpdir(), `argos-scn-${app}-`));
  cpSync(join(ROOT, "demo", app), dir, { recursive: true });
  return dir;
}

/** Copy of the config with text substitutions, written next to the original so relative paths still hold. */
export function variantConfig(dir: string, name: string, edit: (text: string) => string): string {
  const out = join(dir, name);
  writeFileSync(out, edit(readFileSync(join(dir, "argos.config.yaml"), "utf8")));
  return out;
}

export interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
  ms: number;
}

export function cli(args: string[]): CliResult {
  const t0 = Date.now();
  const r = spawnSync("node", ["--import", "tsx", "src/cli.ts", ...args], { cwd: ROOT, encoding: "utf8", timeout: 170_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, ms: Date.now() - t0 };
}

export interface ScanRun extends CliResult {
  out: string;
  matrix: Matrix;
  findings: Finding[];
  counts: Record<Verdict, number>;
}

export function scanConfig(config: string, extra: string[] = []): CliResult & { out: string } {
  const out = mkdtempSync(join(tmpdir(), "argos-scn-out-"));
  return { ...cli(["scan", "--config", config, "--out", out, ...extra]), out };
}

export function scan(config: string, extra: string[] = []): ScanRun {
  const r = scanConfig(config, extra);
  const matrix = JSON.parse(readFileSync(join(r.out, "matrix.json"), "utf8")) as Matrix;
  const findings = JSON.parse(readFileSync(join(r.out, "findings.json"), "utf8")) as Finding[];
  const counts = { VULNERABLE: 0, SUSPECTED: 0, OK: 0, SKIPPED: 0 } as Record<Verdict, number>;
  for (const f of findings) counts[f.verdict]++;
  return { ...r, matrix, findings, counts };
}

const memo = new Map<string, ScanRun>();
/** Pristine demo app scanned once and shared by read-only scenarios. */
export function pristineScan(app: App): ScanRun {
  if (!memo.has(app)) memo.set(app, scan(join(ROOT, "demo", app, "argos.config.yaml")));
  return memo.get(app)!;
}

/** `bash manual-exploit.sh <dir>`: curl-only reproduction, independent of Argos. Returns the flaw numbers it reproduced. */
export function manualExploit(appDir: string): { flaws: number[]; summary: string; status: number | null; raw: string } {
  const r = spawnSync("bash", [join(ROOT, "demo", "vendor-platform", "manual-exploit.sh"), appDir], { encoding: "utf8", timeout: 120_000 });
  const raw = r.stdout + r.stderr;
  const flaws = [...raw.matchAll(/\[VULN\]\s+(\d)/g)].map((m) => Number(m[1])).sort();
  return { flaws, summary: /summary: .*/.exec(raw)?.[0] ?? "", status: r.status, raw };
}

/** Every file under `dir` as text, for "no secret anywhere in the output" checks. */
export function readAll(dir: string): string {
  let out = "";
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    out += statSync(p).isDirectory() ? readAll(p) : readFileSync(p, "utf8");
  }
  return out;
}

export const isRed = (f: Finding): boolean => f.verdict === "VULNERABLE";
export const redOn = (fs: Finding[], check: Finding["check"], resource: string): Finding[] =>
  fs.filter((f) => f.check === check && f.resourceId === resource && isRed(f));
