import { Accordion } from '@base-ui/react/accordion';
import { Button } from '@base-ui/react/button';
import { Checkbox } from '@base-ui/react/checkbox';
import { Collapsible } from '@base-ui/react/collapsible';
import { AcademicCapIcon, ArrowTopRightOnSquareIcon, CheckIcon, ChevronRightIcon, ExclamationTriangleIcon, PlusIcon } from '@heroicons/react/16/solid';
import { useEffect, useState, type ReactNode } from 'react';
import { ANALYSIS_NOTICE, IMPACT_LABELS } from '../impact.ts';
import { learningGuide, learningSource, reviewPrompt } from '../learning.ts';
import { CATEGORY_NAMES, type AnalysisResult, type Category, type Finding } from '../types.ts';
import { Badge, Card, cx, FOCUS, SeverityPill } from './kit.tsx';

/** 높이 애니메이션 패널. hiddenUntilFound: 닫혀 있어도 내용이 DOM 에 남아 브라우저 찾기와 서버 렌더에 보인다 */
const PANEL = 'h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-150 ease-out data-ending-style:h-0 data-starting-style:h-0';

/** 펼침 영역 (Base UI Collapsible) */
export function Fold({ summary, children, defaultOpen, className }: { summary: ReactNode; children: ReactNode; defaultOpen?: boolean; className?: string }) {
  return (
    <Collapsible.Root defaultOpen={defaultOpen} className={className}>
      <Collapsible.Trigger className={cx('group flex w-full items-center gap-1.5 rounded py-1 text-left text-sm text-gray-600 hover:text-gray-900', FOCUS)}>
        <ChevronRightIcon aria-hidden="true" className="size-4 flex-none text-gray-400 transition-transform group-data-panel-open:rotate-90" />
        <span className="min-w-0 flex-1">{summary}</span>
      </Collapsible.Trigger>
      <Collapsible.Panel hiddenUntilFound className={PANEL}>
        <div className="pt-1 pb-1.5 pl-5.5">{children}</div>
      </Collapsible.Panel>
    </Collapsible.Root>
  );
}

const SEVERITY_BAR: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-300', none: 'bg-green-500',
};

function Impact({ finding }: { finding: Finding }) {
  const impact = finding.impact;
  if (!impact) return null;
  return (
    <section aria-label="보안 영향 지도" className="mt-6">
      <div className="flex flex-wrap items-center gap-2">
        <h4 className="text-sm font-semibold text-gray-900">보안 영향 지도</h4>
        <Badge tone="yellow">실행 미검증</Badge>
      </div>
      <p className="mt-1 text-sm text-gray-600">{impact.source === 'ai' ? 'AI가 코드 문맥을 바탕으로 연결한 경로입니다.' : '정적 탐지에 따른 일반적인 위험 경로입니다. 실제 호출 경로는 확인이 필요합니다.'}</p>
      <ol className="mt-3 grid overflow-hidden rounded-md border border-gray-200 md:grid-cols-3 md:divide-x md:divide-gray-200 max-md:divide-y max-md:divide-gray-200">
        {impact.steps.map((step, i) => (
          <li key={i} className="p-4 [overflow-wrap:anywhere]">
            <div className="flex items-center gap-2 text-xs font-medium text-gray-500">
              <span className="grid size-5 place-items-center rounded-full bg-gray-900 text-[11px] text-white">{i + 1}</span>{IMPACT_LABELS[step.kind]}
            </div>
            <p className="mt-2 text-sm text-gray-800">{step.explanation}</p>
            <div className="mt-2"><Badge tone={step.evidence.length ? 'blue' : 'yellow'}>{step.evidence.length ? '코드 근거 포함' : '가능성 · 확인 필요'}</Badge></div>
            {step.evidence.map((ref, j) => (
              <Fold key={j} className="mt-1.5" summary={<span className="font-mono text-xs">{ref.file}:{ref.line} · 변경 {ref.side === 'before' ? '전' : '후'}</span>}>
                <pre className="whitespace-pre-wrap break-words">{ref.quote}</pre>
              </Fold>
            ))}
          </li>
        ))}
      </ol>
      <div className="mt-3 grid gap-0.5">
        <Fold summary="이 경로가 성립하려면 확인할 조건"><ul className="list-disc space-y-1 pl-5 text-sm text-gray-700">{impact.assumptions.map((a, i) => <li key={i}>{a}</li>)}</ul></Fold>
        <Fold summary="직접 검증할 방법 · 아직 실행하지 않았습니다"><ol className="list-decimal space-y-1 pl-5 text-sm text-gray-700">{impact.verification.map((v, i) => <li key={i}>{v}</li>)}</ol></Fold>
      </div>
      <div className="mt-3 rounded-md border border-gray-200 bg-gray-50 p-4">
        <h4 className="flex items-center gap-1.5 text-sm font-semibold text-gray-900"><CheckIcon aria-hidden="true" className="size-4 text-green-600" />목적을 유지하는 안전한 대안</h4>
        <p className="mt-1 text-sm text-gray-700">{impact.saferAlternative}</p>
      </div>
    </section>
  );
}

function FindingCard({ f }: { f: Finding }) {
  return (
    <Card className="relative overflow-hidden">
      <span aria-hidden="true" className={cx('absolute inset-y-0 left-0 w-0.75', SEVERITY_BAR[f.severity])} />
      <div className="px-5 py-5">
        <div className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
          <SeverityPill severity={f.severity} />
          <span>{CATEGORY_NAMES[f.category]}</span>
          <span aria-hidden="true">·</span>
          <span>{f.source === 'static' ? '정적 룰' : 'AI'}{f.confidence ? ` · 신뢰도 ${Math.round(f.confidence * 100)}%` : ''}</span>
        </div>
        <h3 className="mt-2.5 text-base font-semibold text-gray-900">{f.title}</h3>
        <p className="mt-0.5 font-mono text-xs text-gray-500">{f.file}{f.line ? `:${f.line}` : ''}</p>
        <p className="mt-3 text-sm leading-6 whitespace-pre-wrap text-gray-700">{f.description}</p>
        {f.evidence && <pre className="mt-3">{f.evidence}</pre>}
        <Impact finding={f} />
        <div className="mt-5 border-t border-gray-200 pt-4 text-sm">
          <p className="text-gray-700"><span className="font-medium text-gray-900">권장 조치 </span>{f.recommendation}</p>
          <a href={`#learn-${f.category}`} className="mt-2 inline-flex items-center gap-1.5 font-medium text-gray-900 underline decoration-gray-300 underline-offset-4 hover:decoration-gray-900">
            <AcademicCapIcon aria-hidden="true" className="size-4" />이 이슈에서 배울 점 · {learningGuide(f.category).question}
          </a>
        </div>
      </div>
    </Card>
  );
}

function CheckItem({ label }: { label: string }) {
  const [checked, setChecked] = useState(false);
  return (
    <label className="flex cursor-pointer items-start gap-2.5 py-1 text-sm">
      <Checkbox.Root checked={checked} onCheckedChange={setChecked}
        className={cx('mt-0.5 flex size-4 flex-none items-center justify-center rounded-sm border border-gray-300 bg-white data-checked:border-gray-900 data-checked:bg-gray-900', FOCUS)}>
        <Checkbox.Indicator className="flex text-white data-unchecked:hidden"><CheckIcon aria-hidden="true" className="size-3" /></Checkbox.Indicator>
      </Checkbox.Root>
      <span className={checked ? 'text-gray-400 line-through' : 'text-gray-700'}>{label}</span>
    </label>
  );
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<'idle' | 'done' | 'fail'>('idle');
  return (
    <Button onClick={() => navigator.clipboard.writeText(text).then(() => setState('done'), () => setState('fail'))}
      className={cx('h-7 rounded-md border border-gray-200 bg-gray-50 px-2.5 text-xs font-medium text-gray-900 hover:bg-gray-100', FOCUS)}>
      {state === 'done' ? '복사했습니다' : state === 'fail' ? '복사하지 못했습니다' : '복사'}
    </Button>
  );
}

function LearningPanel({ category }: { category: Category }) {
  const guide = learningGuide(category);
  return (
    <div className="grid gap-3 pb-5 text-sm leading-6 text-gray-700">
      <p>{guide.concept}</p>
      <p><span className="font-medium text-gray-900">놓치기 쉬운 생각 </span>{guide.misconception}</p>
      <p><span className="font-medium text-gray-900">생각해 보기 </span>{guide.question}</p>
      <Fold summary="해설 보기"><p>{guide.answer}</p></Fold>
      <div>
        <p className="font-medium text-gray-900">다음에 AI 코드를 검토할 때</p>
        <div className="mt-1">{guide.checks.map((check) => <CheckItem key={check} label={check} />)}</div>
      </div>
      <Fold summary="AI에게 다시 요청할 때 쓸 질문">
        <div className="flex justify-end pb-2"><CopyButton text={reviewPrompt(category)} /></div>
        <pre className="whitespace-pre-wrap [overflow-wrap:anywhere]">{reviewPrompt(category)}</pre>
      </Fold>
      <a href={learningSource(category)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 font-medium text-gray-900 underline decoration-gray-300 underline-offset-4 hover:decoration-gray-900">
        OWASP 공식 자료에서 더 알아보기 <ArrowTopRightOnSquareIcon aria-hidden="true" className="size-3.5" />
      </a>
    </div>
  );
}

/** 학습 자료 (Base UI Accordion). "이 이슈에서 배울 점" 링크로 들어오면 해당 항목을 연다 */
function Learning({ categories }: { categories: Category[] }) {
  const [open, setOpen] = useState<Category[]>([]);
  useEffect(() => {
    const sync = () => {
      const c = location.hash.replace('#learn-', '') as Category;
      if (categories.includes(c)) setOpen((prev) => (prev.includes(c) ? prev : [...prev, c]));
    };
    sync();
    addEventListener('hashchange', sync);
    return () => removeEventListener('hashchange', sync);
  }, [categories]);
  return (
    <Accordion.Root multiple value={open} onValueChange={(v) => setOpen(v as Category[])} className="mt-4 border-t border-gray-200">
      {categories.map((c) => (
        <Accordion.Item key={c} value={c} id={`learn-${c}`} className="scroll-mt-20 border-b border-gray-200">
          <Accordion.Header>
            <Accordion.Trigger className={cx('group flex w-full items-center justify-between gap-4 py-4 text-left text-sm font-semibold text-gray-900 hover:text-gray-600', FOCUS)}>
              {CATEGORY_NAMES[c]}
              <PlusIcon aria-hidden="true" className="size-4 flex-none transition-transform duration-150 group-data-panel-open:rotate-45" />
            </Accordion.Trigger>
          </Accordion.Header>
          <Accordion.Panel hiddenUntilFound className="h-(--accordion-panel-height) overflow-hidden transition-[height] duration-150 ease-out data-ending-style:h-0 data-starting-style:h-0">
            <LearningPanel category={c} />
          </Accordion.Panel>
        </Accordion.Item>
      ))}
    </Accordion.Root>
  );
}

export function Findings({ result }: { result: AnalysisResult }) {
  const categories = [...new Set(result.findings.map((f) => f.category))];
  const stats: { label: string; value: ReactNode; sub?: string }[] = [
    { label: '최고 위험도', value: <SeverityPill severity={result.risk} /> },
    { label: '발견', value: `${result.findings.length}건` },
    { label: '검사한 파일', value: `${result.stats.filesScanned}개` },
    { label: '분석', value: result.llm.used ? `LLM ${result.llm.model}` : '정적 룰만', sub: `${(result.stats.durationMs / 1000).toFixed(1)}s` },
  ];
  return (
    <div className="grid gap-4">
      <Card>
        <dl className="grid grid-cols-2 border-b border-gray-200 sm:grid-cols-4 sm:divide-x sm:divide-gray-200">
          {stats.map((s) => (
            <div key={s.label} className="px-5 py-4">
              <dt className="text-xs text-gray-500">{s.label}</dt>
              <dd className="mt-1 flex items-baseline gap-2 text-base font-semibold text-gray-900">{s.value}{s.sub && <span className="text-xs font-normal text-gray-400">{s.sub}</span>}</dd>
            </div>
          ))}
        </dl>
        <div className="grid gap-2 px-5 py-4 text-sm text-gray-700">
          {result.intent && <p><span className="font-medium text-gray-900">변경 목적 </span>{result.intent}</p>}
          {result.summary && <p>{result.summary}</p>}
          {result.llm.error && <p className="flex items-center gap-1.5 text-orange-700"><ExclamationTriangleIcon aria-hidden="true" className="size-4" />LLM 오류: {result.llm.error}</p>}
          <p className="text-xs text-gray-500">{ANALYSIS_NOTICE} diff와 수집된 파일 밖의 보호는 별도 확인이 필요합니다.</p>
        </div>
      </Card>

      {result.findings.length
        ? result.findings.map((f, i) => <FindingCard key={`${f.id}-${i}`} f={f} />)
        : <Card className="flex items-center gap-2 px-5 py-4 text-sm text-gray-700"><CheckIcon aria-hidden="true" className="size-4 text-green-600" />검사 범위에서 보안 이슈가 발견되지 않았습니다. 전체 서비스의 안전을 보증하는 결과는 아닙니다.</Card>}

      {result.dismissed.length > 0 && (
        <Card className="px-5 py-3">
          <Fold summary={`AI 가 오탐으로 판정한 정적 탐지 ${result.dismissed.length}건`}>
            <ul className="divide-y divide-gray-200">
              {result.dismissed.map((d, i) => (
                <li key={i} className="py-2 text-sm"><code className="text-xs text-gray-500">{d.finding.file}:{d.finding.line ?? ''}</code> <span className="text-gray-900">{d.finding.title}</span> <span className="text-gray-500">— {d.reason}</span></li>
              ))}
            </ul>
          </Fold>
        </Card>
      )}

      {categories.length > 0 && (
        <section aria-label="개발자를 위한 보안 학습" className="mt-6">
          <h2 className="text-lg font-semibold tracking-tight text-gray-900">이번 변경에서 배울 점</h2>
          <p className="mt-1 text-sm text-gray-600">AI가 만든 코드도 같은 기준으로 확인하세요. 개념을 이해하고, 직접 답해 본 뒤 검증 항목을 체크해 보세요.</p>
          <Learning categories={categories} />
        </section>
      )}
    </div>
  );
}
