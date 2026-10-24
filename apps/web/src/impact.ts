import { parsePatch, type ChangedFile } from './diff.ts';
import { learningGuide } from './learning.ts';
import type { Category, CodeEvidence, Finding, ImpactStep, SecurityImpact } from './types.ts';

export type EvidenceIndex = Map<string, CodeEvidence>;
export const IMPACT_LABELS: Record<ImpactStep['kind'], string> = {
  change: '무엇이 달라지나요?', access: '누가 무엇을 할 수 있나요?', consequence: '어떤 영향이 생길 수 있나요?',
};
export const ANALYSIS_NOTICE = '코드를 바탕으로 예상한 영향입니다. 코드 근거는 입력과 인용의 일치를 뜻하며, 실제 접근 가능성이나 공격 성공을 검증한 결과는 아닙니다.';
const key = (file: string, side: string, line: number) => `${file}\0${side}\0${line}`;
const text = (value: unknown, max = 1200): string => typeof value === 'string' ? value.trim().slice(0, max) : '';
const list = (value: unknown, max = 4): string[] => Array.isArray(value)
  ? value.map((v) => text(v, 600)).filter(Boolean).slice(0, max) : [];

export function evidenceIndex(files: ChangedFile[], contents?: Map<string, string>): EvidenceIndex {
  const index: EvidenceIndex = new Map();
  const add = (file: string, side: 'before' | 'after', line: number | undefined, quote: string) => {
    if (line && quote.trim()) index.set(key(file, side, line), { file, side, line, quote: quote.trim() });
  };
  for (const [file, content] of contents ?? []) {
    content.split('\n').forEach((quote, i) => add(file, 'after', i + 1, quote));
  }
  for (const file of files) {
    for (const line of parsePatch(file.patch).lines) {
      if (line.type !== 'add') add(file.filename, 'before', line.oldLine, line.content);
      if (line.type !== 'del') add(file.filename, 'after', line.newLine, line.content);
    }
  }
  return index;
}

function references(value: unknown, index: EvidenceIndex): CodeEvidence[] {
  if (!Array.isArray(value)) return [];
  const out: CodeEvidence[] = [];
  for (const item of value.slice(0, 3)) {
    if (!item || typeof item !== 'object') continue;
    const { file, side, line, quote } = item;
    if (typeof file !== 'string' || !['before', 'after'].includes(side) || !Number.isInteger(line)) continue;
    const actual = index.get(key(file, side, line));
    const snippet = text(quote, 400);
    // AI가 만든 파일·줄 번호·코드를 근거로 표시하지 않는다.
    if (!actual || snippet.length < 3 || !actual.quote.includes(snippet)) continue;
    out.push({ ...actual, quote: snippet });
  }
  return out;
}

const EFFECTS: Record<Category, [string, string]> = {
  API1: ['다른 사용자나 테넌트의 ID를 지정한 요청이 대상 객체의 처리에 도달할 수 있습니다.', '객체의 소유권이 다른 곳에서도 검사되지 않는다면, 타인의 데이터 조회·변경이 가능할 수 있습니다.'],
  API2: ['인증되지 않았거나 유효하지 않은 자격 증명을 가진 요청이 보호된 처리에 도달할 수 있습니다.', '인증 경계가 다른 곳에서도 유지되지 않는다면, 비인가 접근이나 사용자 사칭으로 이어질 수 있습니다.'],
  API3: ['클라이언트가 읽거나 수정할 수 있는 필드 범위가 의도보다 넓어질 수 있습니다.', '모델과 직렬화 설정에 따라 민감 필드 노출이나 권한 관련 속성 변경이 가능할 수 있습니다.'],
  API4: ['한 사용자가 서버 작업량이나 외부 호출량을 의도보다 크게 만들 수 있습니다.', '다른 제한이 없다면 응답 지연·자원 고갈·사용 비용 증가로 이어질 수 있습니다.'],
  API5: ['필요한 역할이 없는 사용자의 요청이 특권 기능에 도달할 수 있습니다.', '서버 측 기능 인가가 없다면 관리자 작업을 비인가 사용자가 실행할 수 있습니다.'],
  API6: ['업무상 제한되어야 하는 동작을 반복하거나 동시에 실행할 수 있습니다.', '별도 업무 규칙이 없다면 중복 처리나 서비스 정책 악용으로 이어질 수 있습니다.'],
  API7: ['사용자가 서버의 요청 목적지에 영향을 줄 수 있습니다.', '네트워크와 목적지 제한에 따라 내부 서비스 접근이나 의도하지 않은 외부 요청으로 이어질 수 있습니다.'],
  API8: ['설정 변경에 따라 외부에 공개되는 정보나 브라우저 접근 범위가 달라질 수 있습니다.', '배포·자격증명 설정에 따라 내부 정보 노출 또는 의도하지 않은 브라우저 접근이 가능할 수 있습니다.'],
  API9: ['기존 관리 범위 밖의 엔드포인트에 요청이 도달할 수 있습니다.', '배포 여부와 접근 제어에 따라 관리되지 않는 API가 노출될 수 있습니다.'],
  API10: ['검증되지 않은 통신 상대나 외부 응답이 서버 처리에 영향을 줄 수 있습니다.', '통신 경로와 응답 처리에 따라 위조된 데이터가 신뢰되는 결과로 이어질 수 있습니다.'],
  INJECTION: ['사용자 입력이 쿼리나 명령의 구조에 영향을 줄 수 있습니다.', '입력 경로와 실행 권한에 따라 의도하지 않은 데이터 접근·변경이 가능할 수 있습니다.'],
  SECRETS: ['코드 열람자가 자격 증명으로 보이는 값에 접근할 수 있습니다.', '실제로 유효한 키라면 해당 키의 권한 범위에서 비인가 사용이 가능할 수 있습니다.'],
};

export function fallbackImpact(finding: Finding, index: EvidenceIndex): SecurityImpact {
  const refs = [...index.values()].filter((ref) => ref.file === finding.file && finding.evidence
    && ref.quote.includes(finding.evidence.trim())).sort((a, b) =>
      Number(b.line === finding.line) - Number(a.line === finding.line));
  const [access, consequence] = EFFECTS[finding.category];
  return {
    source: 'rule', verificationStatus: 'not_run',
    steps: [
      { kind: 'change', explanation: finding.title, evidence: refs.slice(0, 1).map((r) => ({ ...r, quote: r.quote.slice(0, 400) })) },
      { kind: 'access', explanation: access, evidence: [] },
      { kind: 'consequence', explanation: consequence, evidence: [] },
    ],
    assumptions: ['탐지된 패턴은 검토 후보입니다. 상위 미들웨어·호출 경로·배포 설정의 보호 여부는 별도로 확인해야 합니다.'],
    saferAlternative: finding.recommendation,
    verification: learningGuide(finding.category).checks,
  };
}

export function normalizeImpact(value: unknown, finding: Finding, index: EvidenceIndex): SecurityImpact {
  const fallback = fallbackImpact(finding, index);
  if (!value || typeof value !== 'object') return fallback;
  const raw = value as Record<string, unknown>;
  const steps = Array.isArray(raw.steps) ? raw.steps : [];
  const normalized: ImpactStep[] = fallback.steps.map((base) => {
    const step = steps.find((s) => s && typeof s === 'object' && s.kind === base.kind);
    const explanation = text(step?.explanation);
    return explanation ? { kind: base.kind, explanation, evidence: references(step.evidence, index) } : base;
  });
  return {
    source: normalized.some((s, i) => s !== fallback.steps[i]) ? 'ai' : 'rule',
    verificationStatus: 'not_run',
    steps: normalized,
    assumptions: list(raw.assumptions).length ? list(raw.assumptions) : fallback.assumptions,
    saferAlternative: text(raw.saferAlternative) || fallback.saferAlternative,
    verification: list(raw.verification).length ? list(raw.verification) : fallback.verification,
  };
}
