import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { z } from "zod";
import { bind, CanaryError, loadRegistry, parseJson, sha256 } from "./registry.js";
import { ProbeResult, ScanResult, StressResult, Sha256 } from "./types.js";

export const LIMITS = "미식별 또는 NO_EVIDENCE는 유출·학습 부재의 증거가 아니다. " +
  "이 표식은 삭제·재작성·카나리가 없는 부분 유출·사본 비교 공모에 취약하다. " +
  "NFKC는 모든 시각적 동형문자를 복원하지 않는다. 토큰 일치는 유출 책임을 확정하지 않는다. " +
  "mock 결과는 실제 모델의 탐지력을 검증하지 않는다. 확률은 이상화된 문자 분포 가정에 따른 값이며 실제 오염 확률이 아니다. " +
  "견고성 수치는 우리 시뮬레이션 공격에 대한 것이며 실제 공격자의 능력을 대표하지 않는다. " +
  "해시는 파일 무결성 비교용이며 서명이나 위·변조 방지가 아니다.";
const cell = (s: string): string => s.replace(/[\r\n]/g, " ").replace(/\|/g, "\\|").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/`/g, "'");
export interface ReportOptions { registry: string; scan?: string; probe?: string; stress?: string; argosScan?: string; out: string }
export function report(options: ReportOptions): string {
  const { registry, registrySha256 } = loadRegistry(options.registry);
  const binding = bind(registry, registrySha256);
  const bound = <T extends { datasetId: string; registrySha256: string }>(path: string | undefined, schema: { parse(v: unknown): T }): T | undefined => {
    if (!path) return undefined;
    const data = parseJson(path, schema);
    if (data.datasetId !== binding.datasetId || data.registrySha256 !== binding.registrySha256) throw new CanaryError("result belongs to a different registry");
    return data;
  };
  const scan = bound(options.scan, ScanResult), probe = bound(options.probe, ProbeResult), stress = bound(options.stress, StressResult);
  const lines = ["# Argos Canary 증빙 리포트", "", "## 발급 내역", "", "| 항목 | 값 |", "|---|---|",
    `| 데이터셋 | ${cell(registry.datasetId)} |`, `| 발급 시각 | ${registry.createdAt} |`,
    `| 도구 | ${cell(registry.toolVersion)} |`, `| keyId | ${registry.keyId} |`,
    `| 원본 SHA-256 | ${registry.inputSha256} |`, `| 레지스트리 SHA-256 | ${registrySha256} |`,
    `| 생성 방식 | ${registry.generation} |`, `| LLM으로 나간 데이터 범위 | ${registry.llmUsage.mode}; 호출 ${registry.llmUsage.calls}회 |`,
    "", "| 수신자 | 사본 SHA-256 | 파일 비교 |", "|---|---|---|"];
  for (const [name, copy] of Object.entries(registry.recipients)) {
    const path = join(dirname(options.registry), copy.copy);
    let integrity = "검증 불가 (사본 없음)";
    if (existsSync(path)) {
      if (sha256(readFileSync(path)) !== copy.sha256) throw new CanaryError("copy hash mismatch");
      integrity = "일치";
    }
    lines.push(`| ${cell(name)} | ${copy.sha256} | ${integrity} |`);
  }
  lines.push("", "## 유출 식별", "", scan ? scan.verdict : "미실행", "");
  if (scan) for (const r of scan.recipients) {
    lines.push(`- ${cell(r.recipient)}: 고유 토큰 ${r.matches}개 일치`);
    for (const e of r.evidence) lines.push(`  - ${cell(e.id)}: 원본 ${e.sourceLine}행 / 유출본 ${e.leakedLine}행, offset ${e.offset}${e.warnings.length ? " · CONTEXT_MISMATCH" : ""}`);
  }
  lines.push("", "## 모델 질의", "", probe ? `${probe.modelKind === "mock" ? "**MOCK 모의 모델**" : "외부 모델 (학습 여부 미검증)"} · ${probe.status}` : "미실행", "");
  if (probe) {
    lines.push(`비교 ${probe.comparisons}개 · 대조 항목 최대 일치 ${Math.max(...probe.controls.map((c) => c.matched), 0)}자`, "", "| 수신자 | 판정 | 최대 일치 | 수신자 내 보정 | 전체 비교 보정 |", "|---|---|---|---|---|");
    for (const r of probe.recipients) lines.push(`| ${cell(r.recipient)} | ${r.verdict ?? "판정 무효/미완료"} | ${r.maxMatched}/14 | ${r.pAdjusted.toExponential(3)} | ${r.pAdjustedGlobal.toExponential(3)} |`);
  }
  lines.push("", "## 견고성 (시뮬레이션)", "", "| 공격 | 기대 | 실측 성공률 | 시행 | 미식별 | 오귀속 |", "|---|---|---|---|---|---|");
  if (stress) for (const a of stress.attacks) lines.push(`| ${cell(a.id)} | ${cell(a.expected)} | ${a.executed ? `${((a.rate ?? 0) * 100).toFixed(1)}% (SE ${((a.standardError ?? 0) * 100).toFixed(1)}%p)` : "미실행"} | ${a.trials} | ${a.unidentified} | ${a.misattributed} |`);
  else lines.push("| S1~S9 | 미측정 | 미실행 | 0 | — | — |");
  lines.push("", "S9 성공률은 MIXED_SOURCES 검출률이며 나머지는 대상 수신자의 단일 출처 식별률이다. S2는 각 줄을 독립적으로 유지하는 표본이다. SE는 표본 비율의 근사 표준오차이며 신뢰구간이 아니다.");
  if (options.argosScan) {
    // File-only integration: deliberately no imports from the existing scanner or report modules.
    const meta = parseJson(join(options.argosScan, "scan-meta.json"), z.object({
      target: z.string(), files: z.object({
        matrix: z.object({ sha256: Sha256 }), findings: z.object({ sha256: Sha256 }),
      }),
    }));
    for (const file of ["matrix", "findings"] as const) {
      if (sha256(readFileSync(join(options.argosScan, `${file}.json`))) !== meta.files[file].sha256) throw new CanaryError("Argos attachment hash mismatch");
    }
    const findings = parseJson(join(options.argosScan, "findings.json"), z.array(z.object({ verdict: z.enum(["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"]) })));
    lines.push("", "## 별도 접근 제어 시험", "", `대상: ${cell(meta.target)}. Canary 데이터셋과의 연결 관계는 검증하지 않았다.`, "");
    for (const verdict of ["VULNERABLE", "SUSPECTED", "OK", "SKIPPED"]) lines.push(`- ${verdict}: ${findings.filter((f) => f.verdict === verdict).length}`);
  }
  lines.push("", "## 한계와 하지 않는 주장", "", LIMITS, "");
  const markdown = lines.join("\n");
  writeFileSync(options.out, markdown, { flag: "wx", mode: 0o600 });
  return markdown;
}
