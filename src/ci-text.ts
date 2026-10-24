import type { Artifact } from "./ci-artifact.js";
import type { ReportLang } from "./types.js";

/**
 * Every user-facing string of `argos ci prepare` (plain report, PR body, title), per language. Same convention as
 * report.ts: config `report.lang` (default "en"), overridable with --lang. Sentences are templates over facts from
 * the scan files and the init result; nothing is inferred.
 */

type Status = Artifact["status"];
interface Text {
  status: Record<Status, string>;
  stackSpring: string;
  stackJvmOther: string;
  stackNode: string;
  stackUnknown: string;
  initNoConfig: string;
  configUnreadable: (e: string) => string;
  guardUnreadable: string;
  guardField: (k: string) => string;
  guardText: string;
  guardTree: string;
  guardPath: (rel: string, why: string) => string;
  outsideRepo: string;
  guardSummary: (r: string) => string;
  titleFix: (n: number, short: string) => string;
  titleReport: (generated: boolean, short: string) => string;
  impact: { bola: (p: string, r: string) => string; unauth: (r: string) => string; sqli: (r: string) => string; secrets: (r: string, what: string) => string; sensitiveField: string };
  cov: { ranNot: string; notSent: string; ran: string; notInConfig: string; scanNotRun: string; noRequest: string; allSkipped: string; partly: (w: string) => string };
  report: {
    title: (short: string) => string;
    item: string;
    value: string;
    stack: string;
    config: string;
    configGenerated: (rel: string) => string;
    configExisting: (rel: string) => string;
    configNone: string;
    isolation: string;
    result: string;
    counts: (c: Record<string, number>) => string;
    baseBranch: string;
    problems: string;
    noScan: string;
    nothingFound: string;
    evidence: string;
    suspected: string;
    fixHead: string;
    refused: string;
    fixIncluded: (n: number, files: string) => string;
    reverified: (b: number, a: string, bs: number, as: string) => string;
    fixNoneVerified: string;
    fixNothing: string;
    fixNotTried: string;
    coverage: (n: number, ran: number) => string;
    noApis: string;
    covHeader: string;
    unconfirmedHead: string;
    none: string;
    unconfirmedIntro: (n: number) => string;
    more: (n: number) => string;
    human: string;
    hints: string;
    envHead: string;
    envIntro: string;
    scopeHeader: string;
    unsupportedScope: string;
    todoHead: string;
    todoConfirm: (rel: string) => string;
    todoFix: (n: number, withPatch: boolean) => string;
    todoEnv: string;
    todoDetail: string;
    limitsHead: string;
  };
  body: {
    title: (short: string) => string;
    line: (c: Record<string, number>, iso: string, n: number, ran: number) => string;
    moreRed: (n: number) => string;
    fixIncluded: (b: number, a: string) => string;
    fixRefused: string;
    noFix: string;
    unverified: (n: number) => string;
    moreItems: (n: number) => string;
    draft: (rel: string) => string;
    fullReport: string;
  };
}

export const CI_TEXT: Record<ReportLang, Text> = {
  en: {
    status: {
      verified: "✅ The check ran to the end.",
      partial: "🔶 The check ran, but part of the scope could not be verified (see 'Test scope' and 'Not verified').",
      failed: "⚪ Preparation or the run failed, so there is no result or it is incomplete. This does not mean it is safe.",
      unsupported: "⚪ This repository setup is not supported for automatic checks yet. This does not mean it is safe.",
      skipped: "Skipped",
    },
    stackSpring: "Spring Boot (JVM)",
    stackJvmOther: "JVM (not Spring Boot: unsupported)",
    stackNode: "Node.js",
    stackUnknown: "unknown (unsupported)",
    initNoConfig: "no config draft could be made (see the init report for why)",
    configUnreadable: (e) => `the config could not be read: ${e}`,
    guardUnreadable: "the config became unreadable during the fix",
    guardField: (k) => `config \`${k}\` differs before and after the fix`,
    guardText: "the config file changed during the fix",
    guardTree: "tracked files in the checkout changed during the check",
    guardPath: (rel, why) => `the fix changes \`${rel}\` (${why})`,
    outsideRepo: "outside the repository",
    guardSummary: (r) => `verified fix left out of the PR: ${r}`,
    titleFix: (n, s) => `argos: ${n} verified fix(es) and check report (${s})`,
    titleReport: (g, s) => `argos: check report${g ? " and config draft" : ""} (${s})`,
    impact: {
      bola: (p, r) => `Account ‘${p}’ could access ‘${r}’ data of another organization or user. One customer's data can be seen or changed by another.`,
      unauth: (r) => `‘${r}’ could be accessed without logging in or with invalid credentials. Anyone can see this data.`,
      sqli: (r) => `The input of ‘${r}’ could manipulate the database query. Data outside the caller's rights can leak.`,
      secrets: (r, w) => `The response of ‘${r}’ contained a secret (${w}). Whoever sees the response gets that value.`,
      sensitiveField: "sensitive field",
    },
    cov: { ranNot: "⚪ not run", notSent: "⚪ no request", ran: "✅ ran", notInConfig: "➖ not in the config", scanNotRun: "the check did not run", noRequest: "no request was made to this route", allSkipped: "every request was inconclusive", partly: (w) => `partly not verified: ${w}` },
    report: {
      title: (s) => `# Argos check report (commit ${s})`,
      item: "Item",
      value: "Value",
      stack: "Stack",
      config: "Config",
      configGenerated: (rel) => `\`${rel}\` newly drafted **AI draft** (not confirmed by a person)`,
      configExisting: (rel) => `existing \`${rel}\` used (unchanged)`,
      configNone: "could not be made",
      isolation: "Isolation",
      result: "Result",
      counts: (c) => `🔴 vulnerable ${c.VULNERABLE} · 🟡 suspected ${c.SUSPECTED} · 🟢 ok ${c.OK} · ⚪ inconclusive ${c.SKIPPED}`,
      baseBranch: "Target branch",
      problems: "What was wrong",
      noScan: "The check did not run, so nothing can be concluded. See 'Environment errors / not verified' below.",
      nothingFound: "The attacks tried found no access-control violation. What was not tested is under 'Test scope'.",
      evidence: "Evidence",
      suspected: "Suspected",
      fixHead: "Fix and re-verification",
      refused: "A verified fix existed but was NOT put in this PR: a fix must not change the expected policy or the test scope.",
      fixIncluded: (n, f) => `${n} verified fix(es) are in a separate commit of this PR (${f}).`,
      reverified: (b, a, bs, as) => `The same config and the same attacks were run again on the fixed code: 🔴 ${b} → ${a}, 🟡 ${bs} → ${as}. Expectations and test scope are identical before and after.`,
      fixNoneVerified: "No fix could be verified automatically. What a person has to fix is in `.argos/evidence.md` (fix section).",
      fixNothing: "Nothing to fix.",
      fixNotTried: "The check did not run, so no fix was tried.",
      coverage: (n, r) => `Test scope: ${r} of ${n} discovered APIs run`,
      noApis: "No API was discovered (static analysis found no route, or no config could be made).",
      covHeader: "| API | State | Reason |",
      unconfirmedHead: "Unconfirmed policy (not a vulnerability)",
      none: "None.",
      unconfirmedIntro: (n) => `${n} expected rule(s) drafted by AI stay **unconfirmed** until a person confirms them. Verdicts rest on these rules: if a rule is wrong, so is the verdict.`,
      more: (n) => `- … and ${n} more`,
      human: "For a person to confirm or fill in:",
      hints: "Static analysis hints (not confirmed by running):",
      envHead: "Environment errors / not verified (not vulnerabilities)",
      envIntro: "No conclusion was reached for the scope below. **It means neither safe nor vulnerable.**",
      scopeHeader: "| Scope | Reason |",
      unsupportedScope: "unsupported",
      todoHead: "What to do",
      todoConfirm: (rel) => `- In \`${rel}\` change \`provenance\` from \`ai-draft\` to \`confirmed\` for the rules you checked, and commit. Argos never changes a confirmed rule.`,
      todoFix: (n, p) => `- Fix the ${n} 🔴 finding(s)${p ? " (review and merge the verified fix commit)" : ""}.`,
      todoEnv: "- Resolve the causes under 'Environment errors / not verified' and the next commit checks that scope too.",
      todoDetail: "- Technical detail: `.argos/evidence.md` (evidence), `.argos/init-report.md` (why the config draft looks as it does).",
      limitsHead: "Limits",
    },
    body: {
      title: (s) => `### Argos check result (commit ${s})`,
      line: (c, iso, n, r) => `🔴 ${c.VULNERABLE}  🟡 ${c.SUSPECTED}  🟢 ${c.OK}  ⚪ ${c.SKIPPED}  ·  isolation: ${iso}  ·  ${r} of ${n} discovered APIs run`,
      moreRed: (n) => `- … and ${n} more`,
      fixIncluded: (b, a) => `**Verified fix included**: re-run under the same policy and attacks, 🔴 ${b} → ${a}.`,
      fixRefused: "The verified fix changed the policy or test scope and was **left out** (see the report).",
      noFix: "This PR contains no code change.",
      unverified: (n) => `**${n} not verified** (not vulnerabilities, no conclusion):`,
      moreItems: (n) => `- … and ${n} more`,
      draft: (rel) => `The config \`${rel}\` is an **AI draft**. Please check the expected rules and set \`provenance\` to \`confirmed\`.`,
      fullReport: "Full report: `.argos/report.md` on this branch",
    },
  },
  ko: {
    status: {
      verified: "✅ 점검을 끝까지 실행했다.",
      partial: "🔶 점검을 실행했지만 일부 범위는 확인하지 못했다(아래 '시험 범위'와 '미검증').",
      failed: "⚪ 준비 또는 실행 단계에서 실패해 점검 결과가 없거나 불완전하다. 안전하다는 뜻이 아니다.",
      unsupported: "⚪ 이 저장소 구성은 아직 자동 점검을 지원하지 않는다. 안전하다는 뜻이 아니다.",
      skipped: "건너뜀",
    },
    stackSpring: "Spring Boot (JVM)",
    stackJvmOther: "JVM (Spring Boot 아님: 미지원)",
    stackNode: "Node.js",
    stackUnknown: "알 수 없음 (미지원)",
    initNoConfig: "설정 초안을 만들지 못했다 (자세한 이유는 init 보고서)",
    configUnreadable: (e) => `설정 파일을 읽지 못함: ${e}`,
    guardUnreadable: "설정 파일이 수정 과정에서 읽을 수 없게 바뀌었다",
    guardField: (k) => `설정의 \`${k}\`가 수정 전후로 달라졌다`,
    guardText: "설정 파일 내용이 수정 전후로 달라졌다",
    guardTree: "검사 중 작업 트리의 추적 파일이 바뀌었다",
    guardPath: (rel, why) => `수정이 \`${rel}\`를 바꾼다 (${why})`,
    outsideRepo: "저장소 밖",
    guardSummary: (r) => `검증된 수정을 PR에 넣지 않음: ${r}`,
    titleFix: (n, s) => `argos: 검증된 수정 ${n}건과 점검 보고서 (${s})`,
    titleReport: (g, s) => `argos: 점검 보고서${g ? "와 설정 초안" : ""} (${s})`,
    impact: {
      bola: (p, r) => `‘${p}’ 계정으로 다른 조직 또는 다른 사용자의 ‘${r}’ 데이터에 접근할 수 있었다. 한 고객의 데이터가 다른 고객에게 보이거나 바뀔 수 있다는 뜻이다.`,
      unauth: (r) => `로그인하지 않았거나 유효하지 않은 인증으로 ‘${r}’에 접근할 수 있었다. 누구나 이 데이터를 볼 수 있다는 뜻이다.`,
      sqli: (r) => `‘${r}’의 입력값으로 데이터베이스 질의를 조작할 수 있었다. 권한 밖의 데이터가 새어 나갈 수 있다.`,
      secrets: (r, w) => `‘${r}’ 응답에 비밀값(${w})이 들어 있었다. 응답을 본 사람이 그 값을 얻을 수 있다.`,
      sensitiveField: "민감 필드",
    },
    cov: { ranNot: "⚪ 실행 못함", notSent: "⚪ 실행 안 됨", ran: "✅ 실행함", notInConfig: "➖ 설정에 넣지 않음", scanNotRun: "점검을 실행하지 못함", noRequest: "이 경로에 대한 요청이 없었다", allSkipped: "모든 요청이 판단 불가", partly: (w) => `일부 미검증: ${w}` },
    report: {
      title: (s) => `# Argos 점검 보고서 (커밋 ${s})`,
      item: "항목",
      value: "값",
      stack: "기술 스택",
      config: "설정",
      configGenerated: (rel) => `\`${rel}\` 새로 만든 **AI 초안**(사람 확인 전)`,
      configExisting: (rel) => `기존 \`${rel}\` 사용(변경 안 함)`,
      configNone: "만들지 못함",
      isolation: "실행 격리",
      result: "결과",
      counts: (c) => `🔴 취약 ${c.VULNERABLE} · 🟡 의심 ${c.SUSPECTED} · 🟢 정상 ${c.OK} · ⚪ 판단 불가 ${c.SKIPPED}`,
      baseBranch: "대상 브랜치",
      problems: "무엇이 문제였나",
      noScan: "점검이 실행되지 않아 판단할 수 없다. 아래 '환경 오류·미검증'을 보라.",
      nothingFound: "시험한 공격으로는 권한 위반을 찾지 못했다. 시험하지 않은 범위는 아래 '시험 범위'에 있다.",
      evidence: "근거",
      suspected: "의심",
      fixHead: "수정과 재검증",
      refused: "검증된 수정이 있었지만 PR에 넣지 않았다. 수정이 기대 정책이나 시험 범위를 바꾸면 안 되기 때문이다:",
      fixIncluded: (n, f) => `검증된 수정 ${n}건을 이 PR의 별도 커밋으로 넣었다 (${f}).`,
      reverified: (b, a, bs, as) => `같은 설정·같은 공격을 수정한 코드에 다시 실행했다: 🔴 ${b} → ${a}, 🟡 ${bs} → ${as}. 기대 규칙과 시험 범위는 수정 전후 동일하다.`,
      fixNoneVerified: "자동으로 검증된 수정은 없다. 사람이 고쳐야 할 항목은 `.argos/evidence.md`의 수정 항목에 있다.",
      fixNothing: "고칠 항목이 없었다.",
      fixNotTried: "점검이 실행되지 않아 수정도 시도하지 않았다.",
      coverage: (n, r) => `시험 범위: 발견한 API ${n}개 중 ${r}개 실행`,
      noApis: "발견한 API가 없다(정적 분석이 경로를 찾지 못했거나 설정을 만들지 못함).",
      covHeader: "| API | 상태 | 이유 |",
      unconfirmedHead: "확인되지 않은 정책 (취약점 아님)",
      none: "없음.",
      unconfirmedIntro: (n) => `AI가 초안으로 정한 기대 규칙 ${n}개는 사람이 확인하기 전까지 **미확인**이다. 판정은 이 규칙을 기준으로 하므로 규칙이 틀렸다면 판정도 틀릴 수 있다.`,
      more: (n) => `- … 외 ${n}개`,
      human: "사람이 확인하거나 채울 것:",
      hints: "정적 분석 단서(실행으로 확인하지 않음):",
      envHead: "환경 오류·미검증 (취약점 아님)",
      envIntro: "아래는 결론을 내지 못한 범위다. **안전하다는 뜻도, 취약하다는 뜻도 아니다.**",
      scopeHeader: "| 범위 | 이유 |",
      unsupportedScope: "미지원",
      todoHead: "사람이 할 일",
      todoConfirm: (rel) => `- \`${rel}\`의 \`provenance\`에서 확인한 규칙을 \`ai-draft\` → \`confirmed\`로 바꿔 커밋한다. 확인된 규칙은 Argos가 다시 바꾸지 않는다.`,
      todoFix: (n, p) => `- 🔴 ${n}건을 고친다${p ? " (검증된 수정 커밋을 검토 후 머지)" : ""}.`,
      todoEnv: "- '환경 오류·미검증'의 원인을 해소하면 다음 커밋에서 그 범위도 점검된다.",
      todoDetail: "- 기술 상세: `.argos/evidence.md`(증빙), `.argos/init-report.md`(설정 초안 근거).",
      limitsHead: "한계",
    },
    body: {
      title: (s) => `### Argos 점검 결과 (커밋 ${s})`,
      line: (c, iso, n, r) => `🔴 ${c.VULNERABLE}  🟡 ${c.SUSPECTED}  🟢 ${c.OK}  ⚪ ${c.SKIPPED}  ·  격리: ${iso}  ·  발견한 API ${n}개 중 ${r}개 실행`,
      moreRed: (n) => `- … 외 ${n}건`,
      fixIncluded: (b, a) => `**검증된 수정 포함**: 같은 정책·같은 공격으로 다시 실행해 🔴 ${b} → ${a}.`,
      fixRefused: "검증된 수정은 정책·시험 범위를 바꿔 **제외했다**(보고서 참고).",
      noFix: "이 PR에는 코드 수정이 없다.",
      unverified: (n) => `**미검증 ${n}건** (취약점 아님, 결론 없음):`,
      moreItems: (n) => `- … 외 ${n}건`,
      draft: (rel) => `설정 \`${rel}\`는 **AI 초안**이다. 기대 규칙을 확인해 \`provenance\`를 \`confirmed\`로 바꿔 주세요.`,
      fullReport: "전체 보고서: 이 브랜치의 `.argos/report.md`",
    },
  },
};
