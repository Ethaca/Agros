import { config } from './config.ts';
import type { ParsedPatch } from './diff.ts';
import { CATEGORY_NAMES, severityRank, type AnalysisResult, type Finding, type Severity } from './types.ts';
import { ANALYSIS_NOTICE, IMPACT_LABELS } from './impact.ts';
import { learningGuide, learningSource, reviewPrompt } from './learning.ts';

export const REPORT_MARKER = '<!-- argos-report -->';

const ICON: Record<Severity | 'none', string> = { critical: '🟥', high: '🟧', medium: '🟨', low: '🟦', info: '⬜', none: '✅' };

const loc = (f: Finding) => (f.line ? `${f.file}:${f.line}` : f.file);
const oneLine = (s: string) => s.replace(/\|/g, '\\|').replace(/\n+/g, ' ');

export function shouldFail(result: AnalysisResult, failOn = config.failOn): boolean {
  if (failOn === 'never' || result.risk === 'none') return false;
  return severityRank(result.risk) >= severityRank(failOn);
}

export function statusDescription(result: AnalysisResult): string {
  if (!result.findings.length) return 'API 보안 이슈 없음';
  const counts = new Map<Severity, number>();
  for (const f of result.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  return [...counts].map(([s, n]) => `${s} ${n}`).join(', ').slice(0, 140);
}

export function renderFindingBody(f: Finding, includeLearning = true): string {
  const out = [
    `${ICON[f.severity]} **[${f.severity.toUpperCase()}] ${f.title}**`,
    `\`${CATEGORY_NAMES[f.category]}\`${f.source !== 'static' ? ' · 🤖 AI' : ''}${f.confidence ? ` · 신뢰도 ${Math.round(f.confidence * 100)}%` : ''}`,
    '',
    f.description,
    '',
    `**권장 조치:** ${f.recommendation}`,
  ];
  if (f.impact) {
    const impact = f.impact;
    out.push('', '**🧭 보안 영향 지도 · 실행 미검증**', '', ANALYSIS_NOTICE);
    if (impact.source === 'rule') out.push('', '정적 탐지에 따른 일반적인 위험 경로입니다. 실제 호출 경로는 확인이 필요합니다.');
    for (const [i, step] of impact.steps.entries()) {
      out.push('', `${i + 1}. **${IMPACT_LABELS[step.kind]}** ${step.explanation} _(${step.evidence.length ? '코드 근거 포함' : '가능성 · 확인 필요'})_`);
      for (const ref of step.evidence) out.push(`   - \`${oneLine(ref.file)}:${ref.line}\` · 변경 ${ref.side === 'before' ? '전' : '후'}`, `     > ${ref.quote.replace(/\n/g, ' ')}`);
    }
    out.push('', '**추가 확인이 필요한 조건**', ...impact.assumptions.map((a) => `- ${a}`),
      '', `**목적을 유지하는 안전한 대안:** ${impact.saferAlternative}`,
      '', '**직접 검증할 방법 · 아직 실행하지 않았습니다**', ...impact.verification.map((v) => `- [ ] ${v}`));
  }
  if (includeLearning) out.push('', learningMarkdown(f));
  return out.join('\n');
}

function learningMarkdown(f: Finding): string {
  const guide = learningGuide(f.category);
  return [
    '<details><summary>🌱 배울 점 · ' + f.category + '</summary>', '',
    guide.concept, '', `**놓치기 쉬운 생각:** ${guide.misconception}`,
    '', `**생각해 보기:** ${guide.question}`, '', `**해설:** ${guide.answer}`,
    '', '**다음에 AI 코드를 검토할 때**', ...guide.checks.map((c) => `- [ ] ${c}`),
    '', '**AI에게 다시 요청할 때 쓸 질문**', '', `> ${reviewPrompt(f.category)}`,
    '', `[OWASP 공식 자료에서 더 알아보기](${learningSource(f.category)})`, '', '</details>',
  ].join('\n');
}

export function renderSummaryMarkdown(result: AnalysisResult, opts: { detailUrl?: string; sha?: string } = {}): string {
  const out: string[] = [REPORT_MARKER, `## ${ICON[result.risk]} Argos 보안 리뷰`];
  out.push(
    result.findings.length
      ? `최고 위험도 **${result.risk.toUpperCase()}** · 발견 ${result.findings.length}건 · ${shouldFail(result) ? '❌ 머지 차단 권장' : '⚠️ 검토 권장'}`
      : '검사 범위에서 API 보안 이슈가 발견되지 않았습니다. 전체 서비스의 안전을 보증하지는 않습니다.',
  );
  if (result.intent) out.push('', `**변경 목적:** ${oneLine(result.intent)}`);
  if (result.summary) out.push('', `> ${result.summary.replace(/\n/g, '\n> ')}`);

  if (result.findings.length) {
    out.push('', '| | 심각도 | 분류 | 위치 | 내용 |', '|---|---|---|---|---|');
    for (const f of result.findings) {
      out.push(`| ${ICON[f.severity]} | ${f.severity} | ${f.category} | \`${oneLine(loc(f))}\` | ${oneLine(f.title)} |`);
    }
    out.push('', '<details><summary>상세 내용</summary>', '');
    for (const f of result.findings) {
      if (out.join('\n').length > 45_000) {
        out.push('', '추가 상세 결과는 대시보드에서 확인해 주세요.');
        break;
      }
      out.push(`### ${f.id} · \`${loc(f)}\``, renderFindingBody(f, false));
      if (f.evidence) out.push('', '```', f.evidence, '```');
      out.push('');
    }
    out.push('</details>');
    out.push('', '### 🌱 이번 변경에서 배울 점', '');
    const learned = new Set<string>();
    for (const finding of result.findings) {
      if (learned.has(finding.category)) continue;
      learned.add(finding.category);
      out.push(learningMarkdown(finding));
    }
  }

  if (result.dismissed.length) {
    out.push('', `<details><summary>AI 가 오탐으로 판정한 정적 탐지 ${result.dismissed.length}건</summary>`, '');
    for (const d of result.dismissed) out.push(`- \`${loc(d.finding)}\` ${d.finding.title} — ${d.reason}`);
    out.push('</details>');
  }

  const meta = [
    `파일 ${result.stats.filesScanned}개 검사`,
    result.llm.used ? `LLM: ${result.llm.model}` : 'LLM 미사용 (정적 룰)',
    `${(result.stats.durationMs / 1000).toFixed(1)}s`,
    opts.sha ? `commit ${opts.sha.slice(0, 7)}` : '',
  ].filter(Boolean);
  out.push('', `<sub>${meta.join(' · ')}${opts.detailUrl ? ` · [대시보드에서 보기](${opts.detailUrl})` : ''}</sub>`);
  if (result.llm.error) out.push(`<sub>⚠️ LLM 오류: ${oneLine(result.llm.error).slice(0, 300)}</sub>`);
  return out.join('\n');
}

export interface ReviewComment { path: string; line: number; side: 'RIGHT'; body: string }

/** diff 범위 안에 있는 라인에만 인라인 코멘트를 단다 (범위 밖이면 GitHub 이 422 를 반환) */
export function buildReviewComments(result: AnalysisResult, patches: Map<string, ParsedPatch>, max = 30): ReviewComment[] {
  return result.findings
    .filter((f) => f.line && patches.get(f.file)?.commentable.has(f.line))
    .slice(0, max)
    .map((f) => ({ path: f.file, line: f.line!, side: 'RIGHT' as const, body: renderFindingBody(f) }));
}
