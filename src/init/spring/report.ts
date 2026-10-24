import type { Verification } from "../verify.js";
import type { SpringDraft } from "./draft.js";
import type { SpringFacts } from "./facts.js";
import type { Egress } from "./llm.js";

const esc = (s: string): string => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export interface SpringReportInput {
  facts: SpringFacts;
  draft: SpringDraft;
  verification?: Verification;
  /** Why verification was not attempted (when `verification` is absent). */
  notVerifiedReason?: string;
  configPath?: string;
  t1Seconds: number;
  k: number;
  egress: Egress;
  preserved: string[];
}

/** init-report.md for a Spring Boot repository (Korean, plain language). */
export function renderSpringReport(o: SpringReportInput): string {
  const { facts, draft, verification: v } = o;
  const p = facts.project;
  const L: string[] = [];
  const verified = !!v?.ok;
  L.push("# argos init: 결과 (Spring Boot)", "");
  L.push(
    "| 항목 | 값 |",
    "|---|---|",
    `| 설정 파일 | ${o.configPath ? `\`${o.configPath.split("/").slice(-2).join("/")}\`` : "만들지 못함 (아래 '미지원' 참고)"} |`,
    `| 검증 상태 | ${verified ? "✅ 검증됨 (실제 빌드·기동·로그인)" : "⚪ **미검증**"} |`,
    `| T1 (초안 + 검증까지) | ${o.t1Seconds}초 |`,
    `| K (사람이 확인·입력할 항목) | ${o.k} |`,
    `| LLM 사용 | ${o.egress.llm ? `예 (${o.egress.model}, 파일 ${o.egress.sent.length}개, 마스킹 ${o.egress.masked}건)` : "아니오 (정적 분석만, 소스 전송 없음)"} |`,
    "",
  );

  L.push("## 찾은 스택", "");
  L.push("| 항목 | 값 | 근거 |", "|---|---|---|");
  L.push(`| 빌드 도구 | ${p.buildTool}${p.wrapper ? " (wrapper)" : " (wrapper 없음)"} | \`${p.buildFile}\` |`);
  L.push(`| Java | ${p.java?.version ?? "알 수 없음"} | ${p.java?.source ?? "-"} |`);
  const bootLabel = p.bootStatus === "supported" ? "지원 (3.x)" : p.bootStatus === "unverified" ? "**호환성 미검증**" : "Boot 아님";
  L.push(`| Spring Boot | ${p.boot?.version ?? "알 수 없음"} — ${bootLabel} | ${p.boot?.source ?? "-"} |`);
  L.push(`| 실행 모듈 | ${p.module} | ${p.app ? `@SpringBootApplication ${p.app.className} (\`${p.app.file}:${p.app.line}\`)` : "-"} |`);
  L.push(`| 빌드 명령 | \`${p.build}\` | 테스트 생략 |`);
  L.push(`| 실행 | \`${p.start}\` | ${p.jar.source} |`);
  const ds = facts.appConfig.datasource;
  L.push(`| DB | PostgreSQL${ds ? ` (설정: ${ds.kind})` : ""}, migration ${facts.migrations.tool} | ${facts.migrations.files.map((f) => `\`${f}\``).join(", ") || "-"} |`);
  const chain = facts.java.security.chains[0];
  L.push(`| 인증 | ${chain?.resourceServer === "jwt" ? "OAuth2 Resource Server JWT" : chain ? `JWT 아님 (${chain.resourceServer})` : "SecurityFilterChain 없음"} | ${chain ? `\`${chain.loc.file}:${chain.loc.line}\`` : "-"} |`);
  const ms = facts.java.security.methodSecurity;
  L.push(`| 메서드 보안 | ${ms.enabled ? `활성 (${ms.annotation})` : "**비활성**"} | ${ms.loc ? `\`${ms.loc.file}:${ms.loc.line}\`` : "@EnableMethodSecurity 없음"} |`);
  L.push(`| 사용자 식별 | sub = ${facts.java.principal.subject} | ${esc(facts.java.principal.why)} |`);
  L.push("");
  if (p.notes.length) L.push(...p.notes.map((n) => `- ${n}`), "");
  if (p.risks.length) L.push("### 빌드 위험", "", ...p.risks.map((r) => `- ${r.item} (\`${r.where}\`)`), "");
  if (facts.appConfig.keys.length) L.push(`설정 키(값은 읽지도 보내지도 않음): ${facts.appConfig.keys.map((k) => `\`${k}\``).join(", ")}`, "");

  L.push("## 검증", "");
  if (verified) {
    L.push(`✅ 격리 환경에서 빌드·기동했고 ${v!.loggedIn.length}개 페르소나(${v!.loggedIn.join(", ")})가 자기 데이터에 접근했다.`, "");
    if (v!.preview) L.push(`미리보기 스캔: 🔴 ${v!.preview.VULNERABLE} 🟡 ${v!.preview.SUSPECTED} 🟢 ${v!.preview.OK} ⚪ ${v!.preview.SKIPPED}. **확인되지 않은 규칙 기준이라 판정이 아니다.**`, "");
  } else {
    L.push("**미검증.** 이 설정으로 앱이 실제로 빌드·기동되고 로그인되는지는 확인되지 않았다. 아래 내용은 정적 분석 결과이며, 검증된 것으로 보지 말 것.", "");
    if (v) for (const x of v.problems) L.push(`- ${x}`);
    else if (o.notVerifiedReason) L.push(`- ${o.notVerifiedReason}`);
    L.push("");
  }

  const inConfig = draft.inventory.filter((i) => i.resource).length;
  L.push(`## API 목록: 발견 ${draft.inventory.length}개 중 ${inConfig}개를 설정에 넣음`, "");
  L.push("| API | 위치 | 설정 | 비고 |", "|---|---|---|---|");
  for (const i of draft.inventory) L.push(`| \`${i.route}\` | \`${i.where}\` | ${i.resource ? `\`${i.resource}\`` : "—"} | ${i.reason ? esc(i.reason) : ""} |`);
  L.push("");

  L.push("## 기대 정책과 근거", "", "확인 상태: **코드 근거**(코드에 선언됨) · **기본값**(근거 없이 보수적으로 둠) · **정책 확인 필요** · **비활성 가드**(선언됐지만 적용되지 않음) · **LLM 제안**(정적 분석 결과와 대조해 통과).", "");
  L.push("| 리소스 | 항목 | 값 | 근거 위치 | 확인 상태 | 설명 |", "|---|---|---|---|---|---|");
  for (const e of draft.evidence) L.push(`| \`${e.resource}\` | ${e.field} | ${esc(e.value)} | \`${e.where}\` | ${e.status} | ${esc(e.note ?? "")} |`);
  L.push("");

  if (draft.inactiveGuards.length) {
    L.push("## 비활성 가드", "", "권한 검사가 코드에 적혀 있지만 실제로는 적용되지 않는다. 선언된 의도를 기대 정책으로 두었으므로 스캔에서 위반으로 나올 가능성이 높다.", "");
    for (const g of draft.inactiveGuards) L.push(`- \`${g.route}\`: ${g.what} (\`${g.where}\`)`);
    L.push("");
  }
  if (draft.likelyFindings.length) {
    L.push("## 결함 의심 (정적 분석, 실행으로 확인되기 전)", "");
    for (const f of draft.likelyFindings) L.push(`- \`${f.route}\`: ${f.what} (\`${f.where}\`)`);
    L.push("");
  }
  if (draft.policyQuestions.length) {
    L.push("## 정책 확인 필요", "", "코드만으로는 의도를 알 수 없는 항목이다. 취약점으로 보고하지 않는다.", "");
    for (const q of draft.policyQuestions) L.push(`- \`${q.route}\`: ${q.what} (\`${q.where}\`)`);
    L.push("");
  }
  L.push(`## 미지원 (${facts.unsupported.length})`, "");
  if (!facts.unsupported.length) L.push("없음.", "");
  else {
    L.push("| 항목 | 근거 |", "|---|---|");
    for (const u of facts.unsupported) L.push(`| ${esc(u.item)} | \`${u.where}\` |`);
    L.push("");
  }
  L.push(`## 사람이 확인할 것 (${draft.needsHuman.length})`, "");
  if (!draft.needsHuman.length) L.push("없음.", "");
  else {
    L.push("| 주제 | 내용 | 위치 |", "|---|---|---|");
    for (const n of draft.needsHuman) L.push(`| ${n.topic} | ${esc(n.message)} | ${n.where ? `\`${n.where}\`` : ""} |`);
    L.push("");
  }
  if (o.preserved.length) L.push("## 기존 확인값 유지", "", "이전 설정에서 사람이 `confirmed`로 둔 항목은 새 초안으로 바꾸지 않았다:", "", ...o.preserved.map((x) => `- \`${x}\``), "");

  L.push("## 검증하지 않은 것", "");
  const nv: string[] = [];
  if (!verified) nv.push("앱 빌드·기동, 테스트 issuer 토큰으로의 로그인, 시드 가능 여부 (위 '검증' 참고)");
  nv.push("고객의 실제 외부 IdP(이 검증은 Argos 테스트 issuer 기준)");
  if (draft.untested.length) nv.push(`설정에 넣지 못한 API ${draft.untested.length}개 (API 목록의 비고 참고)`);
  if (facts.migrations.tool === "liquibase") nv.push("Liquibase changelog의 테이블 구조(정적으로 읽지 않음, 실행 시 DB에서 읽음)");
  if (facts.project.languages.kotlin) nv.push(`Kotlin 소스 ${facts.project.languages.kotlin}개`);
  nv.push("기대 정책 자체: 모두 `ai-draft`이며 사람이 확인하기 전까지 확정이 아니다");
  L.push(...nv.map((x) => `- ${x}`), "");
  return L.join("\n") + "\n";
}
