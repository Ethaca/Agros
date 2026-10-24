import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { FixReport } from "./fix/index.js";
import { renderMatrixMarkdown } from "./matrix.js";
import { CheckName, Finding, Matrix, ScanMeta, type ReportLang, type Verdict } from "./types.js";

/**
 * Evidence report (SPEC 6.6, V1-V4). Reads only the files `argos scan` wrote (matrix.json, findings.json,
 * scan-meta.json) plus an optional fix.json, so it works standalone and in CI. It never sees raw responses:
 * everything printed here was already masked when it was written.
 */

export class ReportError extends Error {}

/** Every user-facing string of the report, per language (config `report.lang`, recorded in scan-meta.json). */
const TEXT = {
  en: {
    limits:
      "This document covers **the attacks that were run and the personas that were configured**. It does not guarantee security or prove compliance. " +
      "Hashes pin the files; they are not tamper-proofing. 🟢 means \"the attacks we ran did not get through\".",
    label: { VULNERABLE: "vulnerable", SUSPECTED: "suspected", OK: "ok", SKIPPED: "inconclusive" } as Record<Verdict, string>,
    title: (t: string) => `# Argos access-control evidence report — ${t}`,
    header: "## Evidence header", headerCols: "| Field | Value |",
    target: "Target", time: "Run time (UTC)", seconds: (s: string) => `${s}s`, tool: "Tool", isolation: "Isolation",
    container: (image: string) => `container (\`${image}\`: no network, read-only root, non-root)`,
    process: "process — **no isolation, use on trusted code only**",
    mode: "Mode", configFile: "Config file", seedSchema: "Seed schema", none: "none", checks: "Checks",
    confirmState: "Config confirmation",
    unconfirmedCount: (n: number) => `**${n} AI draft field${n === 1 ? "" : "s"} unconfirmed** (expectations, public flags or safe flags no person has confirmed yet)`,
    allConfirmed: "all confirmed by a person",
    runtime: "Runtime", jvm: (db: string) => `jvm${db ? ` · ${db}` : ""} · test JWT issuer (per-run keys)`,
    seedTables: (n: number) => `${n} seeded table${n === 1 ? "" : "s"}`,
    unverified: (n: number) => `## ⚪ Not verified (${n})`,
    unverifiedNote: "No conclusion was drawn for the items below. **This does not mean they are safe.**",
    unverifiedCols: "| Scope | Reason |",
    personas: "Personas",
    integrity: "**Integrity:**", match: "✅ match", mismatch: "❌ mismatch",
    integrityNote: "(header hashes compared with values recomputed from the files)",
    scope: "**Tested scope** — routes not listed below were not tested.",
    scopeCols: "| Resource | Route | Public |", yes: "yes", no: "no",
    unconfirmedWarn: (n: number) => `> ⚠️ **${n} unconfirmed expectation${n === 1 ? "" : "s"}.** The verdicts below use AI-drafted "who may see what" rules. Until a person confirms them, the rules themselves may be wrong.`,
    andMore: (n: number) => `… and ${n} more`,
    summary: "## Summary", check: "Check", total: "**Total**",
    red: (n: number) => `## 🔴 Vulnerable (${n})`, noneDot: "None.",
    redCols: "| Check | Resource | Persona | Description |",
    matrix: "## Access matrix",
    perCheck: "## Results by check",
    allOk: "All 🟢. The attacks we ran did not get through.",
    detailCols: "| Verdict | Resource | Persona | Evidence | Description |",
    skippedNote: "⚪ does not mean \"safe\": it means **we could not decide**. The reason is in the description column.",
    fix: "## Fix and re-verification", nothingToFix: "There was nothing to fix.",
    before: "Before", afterAll: "after applying every adopted patch", noneAdopted: " (no patch adopted)",
    fixMethod: "Each patch was applied to a temporary copy and **the same matrix was run again**. Only patches that resolved their finding, kept the control cells, added no new 🔴 and kept the app starting were adopted.",
    adopted: "✅ adopted", rejected: "⚠️ rejected", guidance: "📝 guidance", reason: "reason",
    limitsTitle: "## Limits",
    notInConfig: "- Routes not in the config and personas or permissions that were not tested are not covered.",
    masked: "- Full marker and secret values are never printed here (first 6 characters only).",
    hostRun: "- This run used a host process without isolation.",
    isolationShort: "isolation",
    verifiedFixes: (n: number, rb: number, ra: string, yb: number, ya: string) =>
      `**${n} verified fix${n === 1 ? "" : "es"}** (🔴 ${rb} → ${ra}, 🟡 ${yb} → ${ya}). Only patches that passed the same attacks on a re-run are included.`,
    remainingRed: (n: number) => `**${n} 🔴 remaining**`,
    moreFindings: (n: number) => `- … and ${n} more`,
    manual: (n: number) => `Needs manual action (no automatic fix, or fix rejected): ${n}. See the report for guidance.`,
    fullReport: (p: string) => `Full report: \`${p}\``,
  },
  ko: {
    limits:
      "이 문서는 **시험한 공격과 설정한 페르소나**에 대한 결과다. 보안을 보증하거나 규정 준수를 증명하지 않는다. " +
      "해시는 파일을 고정할 뿐 위·변조 방지가 아니다. 🟢은 \"시험한 공격으로는 뚫지 못했다\"는 뜻이다.",
    label: { VULNERABLE: "취약", SUSPECTED: "의심", OK: "정상", SKIPPED: "판단 불가" } as Record<Verdict, string>,
    title: (t: string) => `# Argos 접근 제어 증빙 리포트 — ${t}`,
    header: "## 증빙 헤더", headerCols: "| 항목 | 값 |",
    target: "대상", time: "실행 시각 (UTC)", seconds: (s: string) => `${s}초`, tool: "도구", isolation: "실행 격리",
    container: (image: string) => `container (\`${image}\`: 네트워크 없음, 읽기 전용 루트, 비root)`,
    process: "process — **격리 없음, 신뢰하는 코드에만 사용**",
    mode: "모드", configFile: "설정 파일", seedSchema: "시드 스키마", none: "없음", checks: "점검",
    confirmState: "설정 확인 상태",
    unconfirmedCount: (n: number) => `**AI 초안 ${n}개 미확인** (사람이 확인하기 전의 기대 규칙·공개 여부·안전 표시)`,
    allConfirmed: "모두 사람이 확인함",
    runtime: "런타임", jvm: (db: string) => `jvm${db ? ` · ${db}` : ""} · 테스트 JWT issuer (실행별 키)`,
    seedTables: (n: number) => `시드 테이블 ${n}개`,
    unverified: (n: number) => `## ⚪ 미검증 범위 (${n})`,
    unverifiedNote: "아래 항목은 결론을 내지 않았다. **안전하다는 뜻이 아니다.**",
    unverifiedCols: "| 범위 | 이유 |",
    personas: "페르소나",
    integrity: "**무결성:**", match: "✅ 일치", mismatch: "❌ 불일치",
    integrityNote: "(헤더의 해시를 파일에서 다시 계산한 값과 비교)",
    scope: "**시험한 범위** — 아래 목록에 없는 경로는 시험하지 않았다.",
    scopeCols: "| 리소스 | 경로 | 공개 |", yes: "예", no: "아니오",
    unconfirmedWarn: (n: number) => `> ⚠️ **미확인 기대 규칙 ${n}개.** 아래 판정은 AI가 초안으로 만든 "누가 무엇을 볼 수 있는가" 규칙을 기준으로 한다. 사람이 확인하기 전까지는 규칙 자체가 틀렸을 수 있다.`,
    andMore: (n: number) => `… 외 ${n}개`,
    summary: "## 요약", check: "점검", total: "**합계**",
    red: (n: number) => `## 🔴 취약 항목 (${n})`, noneDot: "없음.",
    redCols: "| 점검 | 리소스 | 페르소나 | 설명 |",
    matrix: "## 접근 매트릭스",
    perCheck: "## 점검별 결과",
    allOk: "모두 🟢. 시험한 공격으로는 뚫지 못했다.",
    detailCols: "| 판정 | 리소스 | 페르소나 | 증거 | 설명 |",
    skippedNote: "⚪은 \"안전\"이 아니라 **판단할 수 없었다**는 뜻이다. 이유는 설명 열에 있다.",
    fix: "## 수정과 재검증", nothingToFix: "수정할 항목이 없었다.",
    before: "수정 전", afterAll: "채택한 패치를 모두 적용한 뒤", noneAdopted: " (채택된 패치 없음)",
    fixMethod: "패치는 임시 복사본에 적용하고 **같은 매트릭스를 다시 실행**해, 대상 발견 해결·대조 칸 유지·새 🔴 없음·앱 기동을 모두 확인한 것만 채택했다.",
    adopted: "✅ 채택", rejected: "⚠️ 거부", guidance: "📝 지침", reason: "사유",
    limitsTitle: "## 한계",
    notInConfig: "- 설정에 없는 경로, 시험하지 않은 페르소나·권한은 결과에 포함되지 않는다.",
    masked: "- 마커·비밀의 전체 값은 이 문서에 싣지 않는다(앞 6자만).",
    hostRun: "- 이 실행은 격리 없이 호스트 프로세스로 수행되었다.",
    isolationShort: "격리",
    verifiedFixes: (n: number, rb: number, ra: string, yb: number, ya: string) =>
      `**검증된 수정 ${n}건** (🔴 ${rb} → ${ra}, 🟡 ${yb} → ${ya}). 각 패치는 같은 공격을 다시 실행해 통과한 것만 포함했다.`,
    remainingRed: (n: number) => `**남은 🔴 ${n}건**`,
    moreFindings: (n: number) => `- … 외 ${n}건`,
    manual: (n: number) => `수동 조치 필요(자동 수정 불가·거부): ${n}건. 자세한 지침은 리포트 참고.`,
    fullReport: (p: string) => `전체 리포트: \`${p}\``,
  },
} satisfies Record<ReportLang, unknown>;

/** Required wording (V3), per language. */
export const LIMITS: Record<ReportLang, string> = { en: TEXT.en.limits, ko: TEXT.ko.limits };
/** @deprecated language-specific: use LIMITS[lang]. Kept as the default-language statement. */
export const LIMITS_STATEMENT = LIMITS.en;

export interface RenderOptions {
  /** Overrides the language recorded in scan-meta.json. */
  lang?: ReportLang;
}
/** CLI flag > scan-meta.json (config `report.lang`) > English. */
export const reportLangOf = (scan: LoadedScan, opts: RenderOptions = {}): ReportLang => opts.lang ?? scan.meta.reportLang ?? "en";

const ICON: Record<Verdict, string> = { VULNERABLE: "🔴", SUSPECTED: "🟡", OK: "🟢", SKIPPED: "⚪" };
const VERDICTS: Verdict[] = ["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"];
const sha256 = (t: string): string => createHash("sha256").update(t).digest("hex");

export interface ReportInput {
  scanDir: string;
  /** Path to fix.json from `argos fix`/`argos ci`. Optional. */
  fixPath?: string;
}

export interface LoadedScan {
  matrix: Matrix;
  findings: Finding[];
  meta: ScanMeta;
  fix?: FixReport;
  /** Hash recomputed from the files on disk vs the value recorded in scan-meta.json. */
  integrity: { file: string; recorded: string; actual: string; ok: boolean }[];
}

function readJson(path: string, what: string): unknown {
  if (!existsSync(path)) throw new ReportError(`${what} not found: ${path} (run \`argos scan\` first)`);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new ReportError(`${what} is not valid JSON: ${(e as Error).message}`);
  }
}

function parse<T>(schema: { safeParse(v: unknown): { success: true; data: T } | { success: false; error: { issues: { path: PropertyKey[]; message: string }[] } } }, value: unknown, what: string): T {
  const r = schema.safeParse(value);
  if (r.success) return r.data;
  const i = r.error.issues[0]!;
  throw new ReportError(`${what}: ${i.path.map(String).join(".") || "(root)"}: ${i.message}`);
}

/** Load and validate the three scan files, and recompute the hashes the meta file recorded. */
export function loadScan(input: ReportInput): LoadedScan {
  const metaPath = join(input.scanDir, "scan-meta.json");
  const matrixPath = join(input.scanDir, "matrix.json");
  const findingsPath = join(input.scanDir, "findings.json");
  const meta = parse(ScanMeta, readJson(metaPath, "scan-meta.json"), "scan-meta.json");
  const matrix = parse(Matrix, readJson(matrixPath, "matrix.json"), "matrix.json");
  const rawFindings = readJson(findingsPath, "findings.json");
  if (!Array.isArray(rawFindings)) throw new ReportError("findings.json: expected an array");
  const findings = rawFindings.map((f, i) => parse(Finding, f, `findings.json[${i}]`));

  const integrity = [
    { file: "matrix.json", recorded: meta.files.matrix.sha256, actual: sha256(readFileSync(matrixPath, "utf8")) },
    { file: "findings.json", recorded: meta.files.findings.sha256, actual: sha256(readFileSync(findingsPath, "utf8")) },
  ].map((x) => ({ ...x, ok: x.recorded === x.actual }));
  const bad = integrity.find((x) => !x.ok);
  if (bad) throw new ReportError(`${bad.file} does not match the hash in scan-meta.json (recorded ${bad.recorded.slice(0, 12)}…, actual ${bad.actual.slice(0, 12)}…): the files changed after the scan`);

  const fix = input.fixPath && existsSync(input.fixPath) ? (readJson(input.fixPath, "fix.json") as FixReport) : undefined;
  return { matrix, findings, meta, fix, integrity };
}

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
const short = (h: string): string => `\`${h.slice(0, 16)}…\``;

function counts(findings: Finding[]): Record<Verdict, number> {
  const c = { VULNERABLE: 0, SUSPECTED: 0, OK: 0, SKIPPED: 0 } as Record<Verdict, number>;
  for (const f of findings) c[f.verdict]++;
  return c;
}

export function renderReport(scan: LoadedScan, opts: RenderOptions = {}): string {
  const T = TEXT[reportLangOf(scan, opts)];
  const { meta, matrix, findings, fix } = scan;
  const total = counts(findings);
  const out: string[] = [];
  const push = (...l: string[]) => out.push(...l);

  push(T.title(meta.target), "");
  push(`${VERDICTS.map((v) => `${ICON[v]} ${T.label[v]} ${total[v]}`).join(" · ")}`, "");

  // --- evidence header (V2)
  push(T.header, "", T.headerCols, "|---|---|");
  push(`| ${T.target} | ${cell(meta.target)} |`);
  push(`| ${T.time} | ${meta.startedAt} → ${meta.finishedAt} (${T.seconds((meta.durationMs / 1000).toFixed(1))}) |`);
  push(`| ${T.tool} | ${meta.tool.name} ${meta.tool.version} |`);
  push(`| ${T.isolation} | ${meta.isolation === "container" ? T.container(meta.image ?? "") : T.process} |`);
  if (meta.runtime === "jvm") push(`| ${T.runtime} | ${T.jvm(meta.db ? `${meta.db.kind} (\`${cell(meta.db.image)}\`, migrations: ${meta.db.migrations}, ${T.seedTables(meta.db.tables)})` : "")} |`);
  push(`| ${T.mode} | ${meta.mode} |`);
  push(`| ${T.configFile} | \`${cell(meta.config.file)}\` SHA-256 ${short(meta.config.sha256)} |`);
  push(`| ${T.seedSchema} | ${meta.seed ? `\`${cell(meta.seed.schema.file)}\` SHA-256 ${short(meta.seed.schema.sha256)}` : T.none} |`);
  push(`| matrix.json | SHA-256 ${short(meta.files.matrix.sha256)} |`);
  push(`| findings.json | SHA-256 ${short(meta.files.findings.sha256)} |`);
  push(`| ${T.checks} | ${meta.checks.join(", ")} |`);
  push(`| ${T.confirmState} | ${meta.unconfirmed.length ? T.unconfirmedCount(meta.unconfirmed.length) : T.allConfirmed} |`);
  push(`| ${T.personas} | ${meta.personas.map((p) => (p.org ? `${p.name} (${p.org})` : p.name)).join(", ")} |`, "");
  push(`${T.integrity} ${scan.integrity.map((i) => `${i.file} ${i.ok ? T.match : T.mismatch}`).join(" · ")} ${T.integrityNote}`, "");

  push(T.scope, "", T.scopeCols, "|---|---|---|");
  for (const r of meta.resources) push(`| ${cell(r.id)} | \`${cell(r.route)}\` | ${r.public ? T.yes : T.no} |`);
  push("");

  if (meta.unconfirmed.length) {
    push(T.unconfirmedWarn(meta.unconfirmed.length), "");
    for (const k of meta.unconfirmed.slice(0, 12)) push(`> - \`${cell(k)}\``);
    if (meta.unconfirmed.length > 12) push(`> - ${T.andMore(meta.unconfirmed.length - 12)}`);
    push("");
  }

  if (meta.unverified?.length) {
    push(T.unverified(meta.unverified.length), "", T.unverifiedNote, "", T.unverifiedCols, "|---|---|");
    for (const u of meta.unverified) push(`| \`${cell(u.scope)}\` | ${cell(u.reason)} |`);
    push("");
  }

  // --- summary
  push(T.summary, "", `| ${T.check} | ${VERDICTS.map((v) => `${ICON[v]} ${T.label[v]}`).join(" | ")} |`, `|---|${VERDICTS.map(() => "---:").join("|")}|`);
  for (const check of CheckName.options.filter((c) => findings.some((f) => f.check === c))) {
    const c = counts(findings.filter((f) => f.check === check));
    push(`| ${check} | ${VERDICTS.map((v) => c[v]).join(" | ")} |`);
  }
  push(`| ${T.total} | ${VERDICTS.map((v) => `**${total[v]}**`).join(" | ")} |`, "");

  // --- red findings
  const red = findings.filter((f) => f.verdict === "VULNERABLE");
  push(T.red(red.length), "");
  if (!red.length) push(T.noneDot, "");
  else {
    push(T.redCols, "|---|---|---|---|");
    for (const f of red) push(`| ${f.check} | ${cell(f.resourceId)} | ${cell(f.persona)} | ${cell(f.detail)} |`);
    push("");
  }

  // --- matrix
  push(T.matrix, "", renderMatrixMarkdown(matrix), "");

  // --- per check detail: everything that is not OK
  push(T.perCheck, "");
  for (const check of CheckName.options.filter((c) => findings.some((f) => f.check === c))) {
    const fs = findings.filter((f) => f.check === check);
    const c = counts(fs);
    push(`### ${check}`, "", `${VERDICTS.map((v) => `${ICON[v]} ${c[v]}`).join("  ")}`, "");
    const notOk = fs.filter((f) => f.verdict !== "OK");
    if (!notOk.length) push(T.allOk, "");
    else {
      push(T.detailCols, "|---|---|---|---|---|");
      for (const f of notOk) {
        const ev = [f.proof.request, f.proof.status ? `[${f.proof.status}]` : "", f.proof.marker ? `marker ${f.proof.marker}` : ""].filter(Boolean).join(" ");
        push(`| ${ICON[f.verdict]} | ${cell(f.resourceId)} | ${cell(f.persona)} | \`${cell(ev)}\` | ${cell(f.detail)} |`);
      }
      push("");
    }
    if (fs.some((f) => f.verdict === "SKIPPED")) push(T.skippedNote, "");
  }

  // --- fix
  if (fix) {
    push(T.fix, "");
    if (!fix.proposals.length) push(T.nothingToFix, "");
    else {
      push(`${T.before} ${ICON.VULNERABLE} ${fix.before.VULNERABLE} ${ICON.SUSPECTED} ${fix.before.SUSPECTED}` +
        (fix.after ? ` → ${T.afterAll} ${ICON.VULNERABLE} ${fix.after.VULNERABLE} ${ICON.SUSPECTED} ${fix.after.SUSPECTED}` : T.noneAdopted),
        "", T.fixMethod, "");
      for (const p of fix.proposals) {
        const mark = p.status === "adopted" ? T.adopted : p.status === "rejected" ? T.rejected : T.guidance;
        push(`- ${mark}: ${p.title}`);
        for (const e of p.edits) push(`  - \`${cell(e.file)}:${e.line}\``, `    - \`${cell(e.before)}\``, `    + \`${cell(e.after)}\``);
        for (const r of p.reasons) push(`  - ${T.reason}: ${cell(r)}`);
        if (p.status !== "adopted") push(`  - ${cell(p.guidance)}`);
      }
      push("");
    }
  }

  // --- limits (V3)
  push(T.limitsTitle, "", T.limits, "");
  push(T.notInConfig);
  push(T.masked);
  if (meta.isolation === "process") push(T.hostRun);
  return out.join("\n") + "\n";
}

export interface WriteReportResult {
  path: string;
  markdown: string;
  scan: LoadedScan;
}

export function writeReport(input: ReportInput & { outPath: string } & RenderOptions): WriteReportResult {
  const scan = loadScan(input);
  const markdown = renderReport(scan, { lang: input.lang });
  mkdirSync(dirname(input.outPath), { recursive: true });
  writeFileSync(input.outPath, markdown);
  return { path: input.outPath, markdown, scan };
}

/** Short Markdown for a PR description or comment (V5). Bounded length. */
export function renderSummary(scan: LoadedScan, opts: { reportPath?: string } & RenderOptions = {}): string {
  const lang = reportLangOf(scan, opts);
  const T = TEXT[lang];
  const { meta, findings, fix } = scan;
  const t = counts(findings);
  const red = findings.filter((f) => f.verdict === "VULNERABLE");
  const lines = [
    `### Argos — ${meta.target}`,
    "",
    `${VERDICTS.map((v) => `${ICON[v]} ${t[v]}`).join("  ")}  ·  ${T.isolationShort}: ${meta.isolation}${meta.image ? ` (${meta.image})` : ""}`,
    "",
  ];
  if (fix?.adopted) {
    lines.push(T.verifiedFixes(fix.proposals.filter((p) => p.status === "adopted").length, fix.before.VULNERABLE, String(fix.after?.VULNERABLE ?? "?"), fix.before.SUSPECTED, String(fix.after?.SUSPECTED ?? "?")), "");
    for (const p of fix.proposals.filter((x) => x.status === "adopted")) lines.push(`- ${p.title}`);
    lines.push("");
  }
  const rest = fix?.proposals.filter((p) => p.status !== "adopted") ?? [];
  if (red.length) {
    lines.push(T.remainingRed(red.length), "");
    for (const f of red.slice(0, 10)) lines.push(`- [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    if (red.length > 10) lines.push(T.moreFindings(red.length - 10));
    lines.push("");
  }
  if (rest.length) lines.push(T.manual(rest.length), "");
  if (opts.reportPath) lines.push(T.fullReport(opts.reportPath), "");
  lines.push(`> ${LIMITS[lang].replace(/\*\*/g, "")}`);
  return lines.join("\n") + "\n";
}
