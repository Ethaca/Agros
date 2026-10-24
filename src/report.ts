import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { FixReport } from "./fix/index.js";
import { renderMatrixMarkdown } from "./matrix.js";
import { CheckName, Finding, Matrix, ScanMeta, type Verdict } from "./types.js";

/**
 * Evidence report (SPEC 6.6, V1-V4). Reads only the files `argos scan` wrote (matrix.json, findings.json,
 * scan-meta.json) plus an optional fix.json, so it works standalone and in CI. It never sees raw responses:
 * everything printed here was already masked when it was written.
 */

export class ReportError extends Error {}

/** Required wording (V3). */
export const LIMITS_STATEMENT =
  "이 문서는 **시험한 공격과 설정한 페르소나**에 대한 결과다. 보안을 보증하거나 규정 준수를 증명하지 않는다. " +
  "해시는 파일을 고정할 뿐 위·변조 방지가 아니다. 🟢은 \"시험한 공격으로는 뚫지 못했다\"는 뜻이다.";

const ICON: Record<Verdict, string> = { VULNERABLE: "🔴", SUSPECTED: "🟡", OK: "🟢", SKIPPED: "⚪" };
const LABEL: Record<Verdict, string> = { VULNERABLE: "취약", SUSPECTED: "의심", OK: "정상", SKIPPED: "판단 불가" };
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

export function renderReport(scan: LoadedScan): string {
  const { meta, matrix, findings, fix } = scan;
  const total = counts(findings);
  const out: string[] = [];
  const push = (...l: string[]) => out.push(...l);

  push(`# Argos 접근 제어 증빙 리포트 — ${meta.target}`, "");
  push(`${VERDICTS.map((v) => `${ICON[v]} ${LABEL[v]} ${total[v]}`).join(" · ")}`, "");

  // --- evidence header (V2)
  push("## 증빙 헤더", "", "| 항목 | 값 |", "|---|---|");
  push(`| 대상 | ${cell(meta.target)} |`);
  push(`| 실행 시각 (UTC) | ${meta.startedAt} → ${meta.finishedAt} (${(meta.durationMs / 1000).toFixed(1)}초) |`);
  push(`| 도구 | ${meta.tool.name} ${meta.tool.version} |`);
  push(`| 실행 격리 | ${meta.isolation === "container" ? `container (\`${meta.image}\`: 네트워크 없음, 읽기 전용 루트, 비root)` : "process — **격리 없음, 신뢰하는 코드에만 사용**"} |`);
  push(`| 모드 | ${meta.mode} |`);
  push(`| 설정 파일 | \`${cell(meta.config.file)}\` SHA-256 ${short(meta.config.sha256)} |`);
  push(`| 시드 스키마 | ${meta.seed ? `\`${cell(meta.seed.schema.file)}\` SHA-256 ${short(meta.seed.schema.sha256)}` : "없음"} |`);
  push(`| matrix.json | SHA-256 ${short(meta.files.matrix.sha256)} |`);
  push(`| findings.json | SHA-256 ${short(meta.files.findings.sha256)} |`);
  push(`| 점검 | ${meta.checks.join(", ")} |`);
  push(`| 설정 확인 상태 | ${meta.unconfirmed.length ? `**AI 초안 ${meta.unconfirmed.length}개 미확인** (사람이 확인하기 전의 기대 규칙·공개 여부·안전 표시)` : "모두 사람이 확인함"} |`);
  push(`| 페르소나 | ${meta.personas.map((p) => (p.org ? `${p.name} (${p.org})` : p.name)).join(", ")} |`, "");
  push(`**무결성:** ${scan.integrity.map((i) => `${i.file} ${i.ok ? "✅ 일치" : "❌ 불일치"}`).join(" · ")} (헤더의 해시를 파일에서 다시 계산한 값과 비교)`, "");

  push("**시험한 범위** — 아래 목록에 없는 경로는 시험하지 않았다.", "", "| 리소스 | 경로 | 공개 |", "|---|---|---|");
  for (const r of meta.resources) push(`| ${cell(r.id)} | \`${cell(r.route)}\` | ${r.public ? "예" : "아니오"} |`);
  push("");

  if (meta.unconfirmed.length) {
    push(`> ⚠️ **미확인 기대 규칙 ${meta.unconfirmed.length}개.** 아래 판정은 AI가 초안으로 만든 "누가 무엇을 볼 수 있는가" 규칙을 기준으로 한다. 사람이 확인하기 전까지는 규칙 자체가 틀렸을 수 있다.`, "");
    for (const k of meta.unconfirmed.slice(0, 12)) push(`> - \`${cell(k)}\``);
    if (meta.unconfirmed.length > 12) push(`> - … 외 ${meta.unconfirmed.length - 12}개`);
    push("");
  }

  // --- summary
  push("## 요약", "", `| 점검 | ${VERDICTS.map((v) => `${ICON[v]} ${LABEL[v]}`).join(" | ")} |`, `|---|${VERDICTS.map(() => "---:").join("|")}|`);
  for (const check of CheckName.options.filter((c) => findings.some((f) => f.check === c))) {
    const c = counts(findings.filter((f) => f.check === check));
    push(`| ${check} | ${VERDICTS.map((v) => c[v]).join(" | ")} |`);
  }
  push(`| **합계** | ${VERDICTS.map((v) => `**${total[v]}**`).join(" | ")} |`, "");

  // --- red findings
  const red = findings.filter((f) => f.verdict === "VULNERABLE");
  push(`## 🔴 취약 항목 (${red.length})`, "");
  if (!red.length) push("없음.", "");
  else {
    push("| 점검 | 리소스 | 페르소나 | 설명 |", "|---|---|---|---|");
    for (const f of red) push(`| ${f.check} | ${cell(f.resourceId)} | ${cell(f.persona)} | ${cell(f.detail)} |`);
    push("");
  }

  // --- matrix
  push("## 접근 매트릭스", "", renderMatrixMarkdown(matrix), "");

  // --- per check detail: everything that is not OK
  push("## 점검별 결과", "");
  for (const check of CheckName.options.filter((c) => findings.some((f) => f.check === c))) {
    const fs = findings.filter((f) => f.check === check);
    const c = counts(fs);
    push(`### ${check}`, "", `${VERDICTS.map((v) => `${ICON[v]} ${c[v]}`).join("  ")}`, "");
    const notOk = fs.filter((f) => f.verdict !== "OK");
    if (!notOk.length) push("모두 🟢. 시험한 공격으로는 뚫지 못했다.", "");
    else {
      push("| 판정 | 리소스 | 페르소나 | 증거 | 설명 |", "|---|---|---|---|---|");
      for (const f of notOk) {
        const ev = [f.proof.request, f.proof.status ? `[${f.proof.status}]` : "", f.proof.marker ? `marker ${f.proof.marker}` : ""].filter(Boolean).join(" ");
        push(`| ${ICON[f.verdict]} | ${cell(f.resourceId)} | ${cell(f.persona)} | \`${cell(ev)}\` | ${cell(f.detail)} |`);
      }
      push("");
    }
    if (fs.some((f) => f.verdict === "SKIPPED")) push("⚪은 \"안전\"이 아니라 **판단할 수 없었다**는 뜻이다. 이유는 설명 열에 있다.", "");
  }

  // --- fix
  if (fix) {
    push("## 수정과 재검증", "");
    if (!fix.proposals.length) push("수정할 항목이 없었다.", "");
    else {
      push(`수정 전 ${ICON.VULNERABLE} ${fix.before.VULNERABLE} ${ICON.SUSPECTED} ${fix.before.SUSPECTED}` +
        (fix.after ? ` → 채택한 패치를 모두 적용한 뒤 ${ICON.VULNERABLE} ${fix.after.VULNERABLE} ${ICON.SUSPECTED} ${fix.after.SUSPECTED}` : " (채택된 패치 없음)"),
        "", "패치는 임시 복사본에 적용하고 **같은 매트릭스를 다시 실행**해, 대상 발견 해결·대조 칸 유지·새 🔴 없음·앱 기동을 모두 확인한 것만 채택했다.", "");
      for (const p of fix.proposals) {
        const mark = p.status === "adopted" ? "✅ 채택" : p.status === "rejected" ? "⚠️ 거부" : "📝 지침";
        push(`- ${mark}: ${p.title}`);
        for (const e of p.edits) push(`  - \`${cell(e.file)}:${e.line}\``, `    - \`${cell(e.before)}\``, `    + \`${cell(e.after)}\``);
        for (const r of p.reasons) push(`  - 사유: ${cell(r)}`);
        if (p.status !== "adopted") push(`  - ${cell(p.guidance)}`);
      }
      push("");
    }
  }

  // --- limits (V3)
  push("## 한계", "", LIMITS_STATEMENT, "");
  push("- 설정에 없는 경로, 시험하지 않은 페르소나·권한은 결과에 포함되지 않는다.");
  push("- 마커·비밀의 전체 값은 이 문서에 싣지 않는다(앞 6자만).");
  if (meta.isolation === "process") push("- 이 실행은 격리 없이 호스트 프로세스로 수행되었다.");
  return out.join("\n") + "\n";
}

export interface WriteReportResult {
  path: string;
  markdown: string;
  scan: LoadedScan;
}

export function writeReport(input: ReportInput & { outPath: string }): WriteReportResult {
  const scan = loadScan(input);
  const markdown = renderReport(scan);
  mkdirSync(dirname(input.outPath), { recursive: true });
  writeFileSync(input.outPath, markdown);
  return { path: input.outPath, markdown, scan };
}

/** Short Markdown for a PR description or comment (V5). Bounded length. */
export function renderSummary(scan: LoadedScan, opts: { reportPath?: string } = {}): string {
  const { meta, findings, fix } = scan;
  const t = counts(findings);
  const red = findings.filter((f) => f.verdict === "VULNERABLE");
  const lines = [
    `### Argos — ${meta.target}`,
    "",
    `${VERDICTS.map((v) => `${ICON[v]} ${t[v]}`).join("  ")}  ·  격리: ${meta.isolation}${meta.image ? ` (${meta.image})` : ""}`,
    "",
  ];
  if (fix?.adopted) {
    lines.push(`**검증된 수정 ${fix.proposals.filter((p) => p.status === "adopted").length}건** (🔴 ${fix.before.VULNERABLE} → ${fix.after?.VULNERABLE ?? "?"}, 🟡 ${fix.before.SUSPECTED} → ${fix.after?.SUSPECTED ?? "?"}). 각 패치는 같은 공격을 다시 실행해 통과한 것만 포함했다.`, "");
    for (const p of fix.proposals.filter((x) => x.status === "adopted")) lines.push(`- ${p.title}`);
    lines.push("");
  }
  const rest = fix?.proposals.filter((p) => p.status !== "adopted") ?? [];
  if (red.length) {
    lines.push(`**남은 🔴 ${red.length}건**`, "");
    for (const f of red.slice(0, 10)) lines.push(`- [${f.check}] ${f.resourceId} (${f.persona}): ${f.detail}`);
    if (red.length > 10) lines.push(`- … 외 ${red.length - 10}건`);
    lines.push("");
  }
  if (rest.length) lines.push(`수동 조치 필요(자동 수정 불가·거부): ${rest.length}건. 자세한 지침은 리포트 참고.`, "");
  if (opts.reportPath) lines.push(`전체 리포트: \`${opts.reportPath}\``, "");
  lines.push(`> ${LIMITS_STATEMENT.replace(/\*\*/g, "")}`);
  return lines.join("\n") + "\n";
}
