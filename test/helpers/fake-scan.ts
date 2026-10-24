import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { stringify } from "yaml";
import type { PrepareDeps } from "../../src/ci-prepare.js";
import { loadConfig } from "../../src/config.js";
import type { FixReport } from "../../src/fix/index.js";
import type { Edit } from "../../src/fix/rules.js";
import type { InitResult } from "../../src/init/index.js";
import type { Finding, Matrix, MatrixCell, ScanMeta } from "../../src/types.js";
import { springRaw } from "./spring-config.js";

/** Stand-ins for the Docker-bound parts of `argos ci prepare` (init verification, JVM build, scan). */

const sha = (t: string) => createHash("sha256").update(t).digest("hex");

/** runInit stand-in: writes the hand-written Spring config as an ai-draft (what the Spring init path would produce). */
export function fakeSpringInit(opts: { untested?: { route: string; reason: string }[]; written?: boolean } = {}): PrepareDeps["runInit"] {
  return async (o) => {
    const raw = springRaw();
    raw.target.cwd = ".";
    raw.provenance = Object.fromEntries(raw.resources.filter((r: { expect?: unknown }) => r.expect).map((r: { id: string }) => [`resources.${r.id}.expect`, "ai-draft"]));
    const reportDir = o.reportDir!;
    mkdirSync(reportDir, { recursive: true });
    const reportPath = join(reportDir, "init-report.md");
    writeFileSync(reportPath, "# argos init: 결과\n\nSpring Boot 3.x (maven) 탐지\n");
    if (opts.written !== false) writeFileSync(o.out!, stringify(raw));
    return {
      configPath: o.out!,
      configWritten: opts.written !== false,
      reportPath,
      egressPath: join(reportDir, "init-egress.json"),
      draft: {
        config: raw,
        provenance: raw.provenance,
        needsHuman: [{ topic: "역할", message: "ADMIN만 /api/admin/users를 읽는다는 근거를 확인할 것" }],
        unsupported: opts.written === false ? ["커스텀 JWT 필터(SecurityConfig.java:40): 자동 세팅 미지원"] : [],
        untested: opts.untested ?? [{ route: "DELETE /api/projects/{projectId}", reason: "삭제 요청: 안전 표시 없음" }],
        found: ["Spring Boot 3.3 (maven)"],
      },
      facts: {},
      t1Seconds: 0.1,
      k: 1,
      exitCode: 0,
    } as unknown as InitResult;
  };
}

export interface FakeFixPlan {
  /** Resource ids with a red BOLA finding (persona bob-member). */
  red?: string[];
  /** Resource ids whose every cell is SKIPPED, with the reason. */
  skipped?: Record<string, string>;
  /** Edits of an adopted patch. */
  edits?: Edit[];
  /** Runs inside the fake fix (e.g. to observe the environment, or to tamper with the config). */
  during?: (configPath: string) => void;
  /** Runs after the outputs are written (e.g. a "fix" that relaxed the config). */
  afterward?: (configPath: string) => void;
  throws?: Error;
}

/** runFix stand-in: writes before/{matrix,findings,scan-meta}.json + fix.json in the real formats (hashes included). */
export function fakeFix(plan: FakeFixPlan = {}): PrepareDeps["runFix"] {
  return async (o) => {
    plan.during?.(o.configPath);
    if (plan.throws) throw plan.throws;
    const cfg = loadConfig(o.configPath);
    const red = new Set(plan.red ?? []);
    const skipped = plan.skipped ?? {};
    const cells: MatrixCell[] = [];
    const findings: Finding[] = [];
    for (const r of cfg.resources) {
      for (const p of ["alice-member", "bob-member"]) {
        const verdict = skipped[r.id] ? "SKIPPED" : red.has(r.id) && p === "bob-member" ? "VULNERABLE" : "OK";
        cells.push({ persona: p, resource: r.id, expected: p === "alice-member" ? "allow" : "deny", observed: verdict === "VULNERABLE" ? "allow" : "deny", verdict, evidence: { request: r.route, status: verdict === "VULNERABLE" ? 200 : 403, ...(skipped[r.id] ? { note: skipped[r.id] } : {}) } } as MatrixCell);
      }
      if (red.has(r.id)) findings.push({ check: "bola", resourceId: r.id, persona: "bob-member", verdict: "VULNERABLE", proof: { request: r.route.replace("{projectId}", "7"), status: 200, marker: "ARGOS_" }, detail: "other org's row returned" });
      else if (skipped[r.id]) findings.push({ check: "bola", resourceId: r.id, persona: "bob-member", verdict: "SKIPPED", proof: { request: r.route }, detail: skipped[r.id]! });
      else findings.push({ check: "bola", resourceId: r.id, persona: "bob-member", verdict: "OK", proof: { request: r.route, status: 403 }, detail: "denied" });
    }
    const matrix: Matrix = { personas: ["alice-member", "bob-member"], resources: cfg.resources.map((r) => r.id), cells };
    const counts = { VULNERABLE: 0, SUSPECTED: 0, OK: 0, SKIPPED: 0 };
    for (const f of findings) counts[f.verdict]++;
    const dir = join(o.outDir, "before");
    mkdirSync(dir, { recursive: true });
    const mt = JSON.stringify(matrix, null, 2) + "\n";
    const ft = JSON.stringify(findings, null, 2) + "\n";
    writeFileSync(join(dir, "matrix.json"), mt);
    writeFileSync(join(dir, "findings.json"), ft);
    const meta: ScanMeta = {
      tool: { name: "argos", version: "0.0.0" },
      startedAt: "2026-10-24T00:00:00.000Z",
      finishedAt: "2026-10-24T00:01:00.000Z",
      durationMs: 60000,
      target: "work",
      mode: cfg.mode,
      isolation: o.isolation ?? "container",
      image: "eclipse-temurin:21-jre",
      config: { file: "argos.config.yaml", sha256: sha("x") },
      seed: null,
      checks: cfg.checks,
      unconfirmed: Object.entries(cfg.provenance ?? {}).filter(([, v]) => v === "ai-draft").map(([k]) => k).sort(),
      personas: cfg.personas.map((p) => ({ name: p.name, org: p.org ?? null })),
      resources: cfg.resources.map((r) => ({ id: r.id, route: r.route, public: !!r.public })),
      results: { cells: cells.length, findings: findings.length, counts },
      runtime: "jvm",
      unverified: Object.entries(skipped).map(([id, reason]) => ({ scope: `resources.${id}`, reason })),
      notes: ["build: maven (wrapper)"],
      files: { matrix: { file: "matrix.json", sha256: sha(mt) }, findings: { file: "findings.json", sha256: sha(ft) } },
    };
    writeFileSync(join(dir, "scan-meta.json"), JSON.stringify(meta, null, 2) + "\n");
    const adopted = !!plan.edits?.length;
    const report: FixReport = {
      proposals: adopted ? [{ kind: "owner-check", title: "check the caller's org before returning the project", addresses: [], edits: plan.edits!, guidance: "", status: "adopted", reasons: [] } as unknown as FixReport["proposals"][number]] : [],
      tried: adopted,
      adopted,
      applied: false,
      reasons: [],
      before: counts,
      ...(adopted ? { after: { ...counts, VULNERABLE: 0, OK: counts.OK + counts.VULNERABLE } } : {}),
    };
    writeFileSync(join(o.outDir, "fix.json"), JSON.stringify(report, null, 2) + "\n");
    plan.afterward?.(o.configPath);
    return report;
  };
}
