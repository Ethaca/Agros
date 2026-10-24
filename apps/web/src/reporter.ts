import { config } from './config.ts';
import type { ParsedPatch } from './diff.ts';
import { CATEGORY_NAMES, SEVERITY_ORDER, severityRank, type AnalysisResult, type Finding, type Severity } from './types.ts';
import { ANALYSIS_NOTICE, IMPACT_LABELS } from './impact.ts';
import { isLang, type Lang } from './i18n.ts';
import { learningGuide, learningSource, reviewPrompt } from './learning.ts';

export const REPORT_MARKER = '<!-- argos-report -->';

const ICON: Record<Severity | 'none', string> = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜', none: '✅' };

/** PR 코멘트·상태·인라인 리뷰에 쓰는 문구. 분석 결과의 언어(result.lang)를 따른다 */
const S = {
  en: {
    noIssues: 'No API security issues',
    confidence: (n: number) => `confidence ${n}%`,
    recommendation: 'Recommendation:',
    impactTitle: '🧭 Security impact map · not executed',
    ruleImpact: 'Generic risk path for this static detection. The actual call path still needs to be confirmed.',
    withEvidence: 'code evidence', possible: 'possible · needs confirmation',
    side: (before: boolean) => (before ? 'before change' : 'after change'),
    assumptions: 'Conditions to confirm',
    alternative: 'Safer alternative that keeps the purpose:',
    verification: 'How to verify yourself · not run yet',
    learnSummary: '🌱 What to learn',
    misconception: 'Easy to miss:', question: 'Think about it:', answer: 'Answer:',
    nextReview: 'Next time you review AI-written code',
    askAgain: 'Question to ask the AI next time',
    owasp: 'Learn more from OWASP',
    title: 'Argos security review',
    headline: (risk: string, n: number, fail: boolean) =>
      `Highest risk **${risk}** · ${n} finding${n === 1 ? '' : 's'} · ${fail ? '❌ Blocking merge recommended' : '⚠️ Review recommended'}`,
    clean: 'No API security issues were found in the scanned scope. This does not guarantee the safety of the whole service.',
    intent: 'Purpose of the change:',
    sevLabel: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } as Record<Severity, string>,
    howToRead: 'Each finding shows **what changed → what it exposes → how to fix it**, with code evidence where available. Start from the top — findings are ordered by severity.',
    table: '| Severity | Category | Location | What was found |',
    details: 'Details',
    moreOnDashboard: 'See the dashboard for the remaining details.',
    learnSection: '### 🌱 What to learn from this change',
    dismissed: (n: number) => `${n} static detection${n === 1 ? '' : 's'} dismissed by AI as false positive${n === 1 ? '' : 's'}`,
    filesScanned: (n: number) => `${n} file${n === 1 ? '' : 's'} scanned`,
    noLlm: 'No LLM (static rules)',
    dashboard: 'View on dashboard',
    llmError: 'LLM error:',
    inline: (sha: string, n: number) => `🔐 Argos flagged ${n} line${n === 1 ? '' : 's'} inline at \`${sha}\`.`,
    pending: 'API security scan in progress...',
    failed: 'Scan failed',
  },
  ko: {
    noIssues: 'API 보안 이슈 없음',
    confidence: (n: number) => `신뢰도 ${n}%`,
    recommendation: '권장 조치:',
    impactTitle: '🧭 보안 영향 지도 · 실행 미검증',
    ruleImpact: '정적 탐지에 따른 일반적인 위험 경로입니다. 실제 호출 경로는 확인이 필요합니다.',
    withEvidence: '코드 근거 포함', possible: '가능성 · 확인 필요',
    side: (before: boolean) => `변경 ${before ? '전' : '후'}`,
    assumptions: '추가 확인이 필요한 조건',
    alternative: '목적을 유지하는 안전한 대안:',
    verification: '직접 검증할 방법 · 아직 실행하지 않았습니다',
    learnSummary: '🌱 배울 점',
    misconception: '놓치기 쉬운 생각:', question: '생각해 보기:', answer: '해설:',
    nextReview: '다음에 AI 코드를 검토할 때',
    askAgain: 'AI에게 다시 요청할 때 쓸 질문',
    owasp: 'OWASP 공식 자료에서 더 알아보기',
    title: 'Argos 보안 리뷰',
    headline: (risk: string, n: number, fail: boolean) =>
      `최고 위험도 **${risk}** · 발견 ${n}건 · ${fail ? '❌ 머지 차단 권장' : '⚠️ 검토 권장'}`,
    clean: '검사 범위에서 API 보안 이슈가 발견되지 않았습니다. 전체 서비스의 안전을 보증하지는 않습니다.',
    intent: '변경 목적:',
    sevLabel: { critical: '심각', high: '높음', medium: '보통', low: '낮음', info: '정보' } as Record<Severity, string>,
    howToRead: '각 항목은 **무엇이 바뀌고 → 무엇이 열리고 → 어떻게 고치는지**를 코드 근거와 함께 보여줍니다. 위에서부터 보세요 — 심각도 순으로 정렬돼 있습니다.',
    table: '| 심각도 | 분류 | 위치 | 발견 내용 |',
    details: '상세 내용',
    moreOnDashboard: '추가 상세 결과는 대시보드에서 확인해 주세요.',
    learnSection: '### 🌱 이번 변경에서 배울 점',
    dismissed: (n: number) => `AI 가 오탐으로 판정한 정적 탐지 ${n}건`,
    filesScanned: (n: number) => `파일 ${n}개 검사`,
    noLlm: 'LLM 미사용 (정적 룰)',
    dashboard: '대시보드에서 보기',
    llmError: 'LLM 오류:',
    inline: (sha: string, n: number) => `🔐 Argos 이 \`${sha}\` 에서 ${n}건을 인라인으로 표시했습니다.`,
    pending: 'API 보안 검사 중...',
    failed: '검사 중 오류 발생',
  },
} satisfies Record<Lang, unknown>;

/** 결과에 언어가 없으면(이전 버전에서 저장된 결과) 서버 기본값 */
export const langOf = (result: Pick<AnalysisResult, 'lang'>): Lang => (isLang(result.lang) ? result.lang : config.lang);
export const reportText = (lang: Lang) => S[lang];

const loc = (f: Finding) => (f.line ? `${f.file}:${f.line}` : f.file);
const oneLine = (s: string) => s.replace(/\|/g, '\\|').replace(/\n+/g, ' ');

export function shouldFail(result: AnalysisResult, failOn = config.failOn): boolean {
  if (failOn === 'never' || result.risk === 'none') return false;
  return severityRank(result.risk) >= severityRank(failOn);
}

export function statusDescription(result: AnalysisResult): string {
  if (!result.findings.length) return S[langOf(result)].noIssues;
  const counts = new Map<Severity, number>();
  for (const f of result.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return [...counts].map(([s, n]) => `${s} ${n}`).join(', ').slice(0, 140);
}

export function renderFindingBody(f: Finding, includeLearning = true, lang: Lang = config.lang): string {
  const s = S[lang];
  const out = [
    `${ICON[f.severity]} **[${f.severity.toUpperCase()}] ${f.title}**`,
    `\`${CATEGORY_NAMES[f.category]}\`${f.source !== 'static' ? ' · 🤖 AI' : ''}${f.confidence ? ` · ${s.confidence(Math.round(f.confidence * 100))}` : ''}`,
    '',
    f.description,
    '',
    `**${s.recommendation}** ${f.recommendation}`,
  ];
  if (f.impact) {
    const impact = f.impact;
    out.push('', `**${s.impactTitle}**`, '', ANALYSIS_NOTICE[lang]);
    if (impact.source === 'rule') out.push('', s.ruleImpact);
    for (const [i, step] of impact.steps.entries()) {
      out.push('', `${i + 1}. **${IMPACT_LABELS[lang][step.kind]}** ${step.explanation} _(${step.evidence.length ? s.withEvidence : s.possible})_`);
      for (const ref of step.evidence) out.push(`   - \`${oneLine(ref.file)}:${ref.line}\` · ${s.side(ref.side === 'before')}`, `     > ${ref.quote.replace(/\n/g, ' ')}`);
    }
    out.push('', `**${s.assumptions}**`, ...impact.assumptions.map((a) => `- ${a}`),
      '', `**${s.alternative}** ${impact.saferAlternative}`,
      '', `**${s.verification}**`, ...impact.verification.map((v) => `- [ ] ${v}`));
  }
  if (includeLearning) out.push('', learningMarkdown(f, lang));
  return out.join('\n');
}

function learningMarkdown(f: Finding, lang: Lang): string {
  const s = S[lang];
  const guide = learningGuide(f.category, lang);
  return [
    `<details><summary>${s.learnSummary} · ${f.category}</summary>`, '',
    guide.concept, '', `**${s.misconception}** ${guide.misconception}`,
    '', `**${s.question}** ${guide.question}`, '', `**${s.answer}** ${guide.answer}`,
    '', `**${s.nextReview}**`, ...guide.checks.map((c) => `- [ ] ${c}`),
    '', `**${s.askAgain}**`, '', `> ${reviewPrompt(f.category, lang)}`,
    '', `[${s.owasp}](${learningSource(f.category)})`, '', '</details>',
  ].join('\n');
}

export function renderSummaryMarkdown(result: AnalysisResult, opts: { detailUrl?: string; sha?: string } = {}): string {
  const lang = langOf(result);
  const s = S[lang];
  const findings = [...result.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const out: string[] = [REPORT_MARKER, `## ${ICON[result.risk]} ${s.title}`];
  out.push(findings.length ? s.headline(result.risk.toUpperCase(), findings.length, shouldFail(result)) : s.clean);
  if (findings.length) {
    const counts = new Map<Severity, number>();
    for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    const breakdown = SEVERITY_ORDER.filter((sv) => counts.get(sv)).map((sv) => `${ICON[sv]} ${s.sevLabel[sv]} ${counts.get(sv)}`).join('  ·  ');
    out.push('', breakdown);
  }
  if (result.intent) out.push('', `**${s.intent}** ${oneLine(result.intent)}`);
  if (result.summary) out.push('', `> ${result.summary.replace(/\n/g, '\n> ')}`);

  if (findings.length) {
    out.push('', s.howToRead, '', s.table, '|---|---|---|---|');
    for (const f of findings) {
      out.push(`| ${ICON[f.severity]} ${s.sevLabel[f.severity]} | \`${f.category}\` | \`${oneLine(loc(f))}\` | ${oneLine(f.title)} |`);
    }
    out.push('', `<details><summary>${s.details}</summary>`, '');
    for (const f of findings) {
      if (out.join('\n').length > 45_000) {
        out.push('', s.moreOnDashboard);
        break;
      }
      out.push(`### ${f.id} · \`${loc(f)}\``, renderFindingBody(f, false, lang));
      if (f.evidence) out.push('', '```', f.evidence, '```');
      out.push('');
    }
    out.push('</details>');
    out.push('', s.learnSection, '');
    const learned = new Set<string>();
    for (const finding of findings) {
      if (learned.has(finding.category)) continue;
      learned.add(finding.category);
      out.push(learningMarkdown(finding, lang));
    }
  }

  if (result.dismissed.length) {
    out.push('', `<details><summary>${s.dismissed(result.dismissed.length)}</summary>`, '');
    for (const d of result.dismissed) out.push(`- \`${loc(d.finding)}\` ${d.finding.title} — ${d.reason}`);
    out.push('</details>');
  }

  const meta = [
    s.filesScanned(result.stats.filesScanned),
    result.llm.used ? `LLM: ${result.llm.model}` : s.noLlm,
    `${(result.stats.durationMs / 1000).toFixed(1)}s`,
    opts.sha ? `commit ${opts.sha.slice(0, 7)}` : '',
  ].filter(Boolean);
  out.push('', `<sub>${meta.join(' · ')}${opts.detailUrl ? ` · [${s.dashboard}](${opts.detailUrl})` : ''}</sub>`);
  if (result.llm.error) out.push(`<sub>⚠️ ${s.llmError} ${oneLine(result.llm.error).slice(0, 300)}</sub>`);
  return out.join('\n');
}

export interface ReviewComment { path: string; line: number; side: 'RIGHT'; body: string }

/** diff 범위 안에 있는 라인에만 인라인 코멘트를 단다 (범위 밖이면 GitHub 이 422 를 반환) */
export function buildReviewComments(result: AnalysisResult, patches: Map<string, ParsedPatch>, max = 30): ReviewComment[] {
  const lang = langOf(result);
  return [...result.findings]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .filter((f) => f.line && patches.get(f.file)?.commentable.has(f.line))
    .slice(0, max)
    .map((f) => ({ path: f.file, line: f.line!, side: 'RIGHT' as const, body: renderFindingBody(f, true, lang) }));
}
