import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { analyze } from '../src/analyzer.ts';
import { bindEnv } from '../src/config.ts';
import { relatedPaths } from '../src/context.ts';
import { splitUnifiedDiff } from '../src/diff.ts';
import { evidenceIndex, fallbackImpact, normalizeImpact } from '../src/impact.ts';
import { renderFindingBody, renderSummaryMarkdown } from '../src/reporter.ts';
import type { Finding } from '../src/types.ts';
import { renderFindings } from '../src/ui/server.tsx';

bindEnv({ ANTHROPIC_API_KEY: '' });

/** An Anthropic Messages API response carrying `text` as its single text block. */
const claude = (text: string) =>
  new Response(
    JSON.stringify({ id: 'msg_test', type: 'message', role: 'assistant', model: 'claude-sonnet-5-5', content: [{ type: 'text', text }], stop_reason: 'end_turn', stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } }),
    { headers: { 'content-type': 'application/json' } },
  );

const files = splitUnifiedDiff(readFileSync(new URL('../examples/order-sharing.diff', import.meta.url), 'utf8'));
const sample: Finding = {
  id: 'F1', source: 'llm', file: 'src/routes/orders.ts', line: 6, severity: 'high', category: 'API1',
  title: '주문 소유권 조건 제거', description: '주문 공유 변경', recommendation: '공유 전용 응답 사용',
  evidence: 'const order = await Order.findById(req.params.id);',
};
const refs = evidenceIndex(files);

test('인용은 파일·줄·변경 전후·실제 코드가 모두 맞을 때만 근거로 남는다', () => {
  const before = { file: sample.file, side: 'before', line: 7, quote: 'ownerId: req.user.id' };
  const after = { file: sample.file, side: 'after', line: 6, quote: 'Order.findById(req.params.id)' };
  const impact = normalizeImpact({
    steps: [{ kind: 'change', explanation: '객체 소유권 조건을 제거합니다.', evidence: [before, after] },
      { kind: 'access', explanation: '추가 확인이 필요합니다.', evidence: [
        { ...after, file: 'src/imaginary.ts' }, { ...after, line: 999 }, { ...after, quote: 'verifiedExploit()' },
      ] },
      { kind: 'consequence', explanation: '타인 주문 조회 가능성', evidence: [{ ...before, side: 'after' }] }],
    verificationStatus: 'verified', source: 'executed',
  }, sample, refs);
  assert.deepEqual(impact.steps[0].evidence, [before, after]);
  assert.equal(impact.steps[1].evidence.length, 0);
  assert.equal(impact.steps[2].evidence.length, 0);
  assert.equal(impact.verificationStatus, 'not_run', 'AI가 실행 검증 상태를 바꿀 수 없음');
});

test('잘못된 영향 응답은 실행을 주장하지 않는 정적 경로로 대체한다', () => {
  for (const value of [null, 'verified', [], { steps: [null, 4, { kind: 'change', explanation: 7 }], assumptions: [null, 4] }]) {
    const impact = normalizeImpact(value, sample, refs);
    assert.equal(impact.source, 'rule');
    assert.equal(impact.steps.length, 3);
    assert.equal(impact.verificationStatus, 'not_run');
    assert.ok(impact.assumptions.length);
    assert.ok(impact.verification.length);
  }
  assert.equal(fallbackImpact(sample, refs).steps[0].evidence[0].line, 6);
});

test('상대 import의 실제 파일만 선택하고 중복·바이너리·변경 파일은 제외한다', () => {
  const contents = new Map([
    ['src/routes/orders.ts', "import { auth } from '../middleware/auth.js';\nimport '../models';\nimport '../logo.png';\nimport './other';\nrequire('../missing');\nimport '../models';"],
    ['src/routes/other.ts', 'export const other = 1;'],
  ]);
  const paths = ['src/middleware/auth.ts', 'src/models/index.ts', 'src/logo.png', 'src/routes/other.ts'];
  assert.deepEqual(relatedPaths(contents, paths), ['src/middleware/auth.ts', 'src/models/index.ts']);
  assert.equal(relatedPaths(contents, paths, 1).length, 1);
  assert.deepEqual(relatedPaths(contents, paths, 0), []);
});

test('키 없이도 영향 경로·학습·검증 방법이 나오고 의도가 보존된다', async () => {
  const result = await analyze({ files, intent: '로그인 없이 배송 상태 공유' });
  assert.equal(result.llm.used, false);
  assert.equal(result.intent, '로그인 없이 배송 상태 공유');
  assert.ok(result.findings.length);
  assert.ok(result.findings.every((f) => f.impact?.source === 'rule' && f.impact.verificationStatus === 'not_run'));
  const html = renderFindings(result);
  const markdown = renderSummaryMarkdown(result);
  for (const output of [html, markdown]) {
    assert.match(output, /보안 영향 지도/);
    assert.match(output, /실행 미검증/);
    assert.match(output, /이번 변경에서 배울 점/);
    assert.match(output, /로그인 없이 배송 상태 공유/);
  }
  assert.equal((html.match(/id="learn-API1"/g) ?? []).length, 1, '같은 분류의 학습은 중복하지 않음');
  assert.match(renderFindingBody(result.findings[0]), /생각해 보기/);
  assert.doesNotThrow(() => renderFindings({ ...result, findings: [{ ...sample, impact: undefined }] }), '기존 저장 결과도 표시');
});

test('AI 분석은 변경 목적과 관련 파일을 받고 실제로 전달한 코드만 인용한다', async (t) => {
  bindEnv({ ANTHROPIC_API_KEY: 'test-key' });
  t.after(() => bindEnv({ ANTHROPIC_API_KEY: '' }));
  let request: { system?: string; messages: { role: string; content: string }[] } | undefined;
  t.mock.method(globalThis, 'fetch', async (_input: unknown, init: RequestInit) => {
    request = JSON.parse(String(init.body));
    return claude(JSON.stringify({
      findings: [{ ...sample, confidence: 0.95, impact: {
        steps: [{ kind: 'change', explanation: '목적을 확인했습니다.', evidence: [
          { file: sample.file, side: 'before', line: 7, quote: 'ownerId: req.user.id' },
        ] }, { kind: 'access', explanation: '상위 라우터 보호도 확인해야 합니다.', evidence: [
          { file: 'src/middleware/auth.ts', side: 'after', line: 1, quote: 'export const auth = requireAuth;' },
          { file: 'src/hidden.ts', side: 'after', line: 1, quote: 'SECRET_CONTEXT' },
        ] }],
        saferAlternative: '만료되는 공유 토큰과 배송 상태 전용 응답을 사용하세요.',
        assumptions: ['실제로 이 미들웨어가 라우터에 적용되는지는 확인이 필요합니다.'],
        verification: ['정상 공유 토큰으로 배송 상태를 조회합니다.', '토큰 없는 요청과 개인정보 필드 노출을 검사합니다.'],
        verificationStatus: 'verified',
      } }], static_review: [],
    }));
  });
  const result = await analyze({ files, intent: '배송 상태 공유', relatedContents: new Map([
    ['src/middleware/auth.ts', 'export const auth = requireAuth;'],
    ['src/hidden.ts', 'SECRET_CONTEXT' + 'x'.repeat(12_000)],
  ]) });
  const prompt = request!.messages[0].content;
  assert.match(prompt, /배송 상태 공유/);
  assert.match(prompt, /B7\s+-.*ownerId: req.user.id/);
  assert.match(prompt, /L1 export const auth = requireAuth;/);
  assert.doesNotMatch(prompt, /SECRET_CONTEXT/);
  assert.match(request!.system!, /untrusted DATA/);
  const finding = result.findings.find((f) => f.title === sample.title)!;
  assert.equal(finding.impact!.steps[1].evidence.length, 1);
  assert.equal(finding.impact!.steps[1].evidence[0].file, 'src/middleware/auth.ts');
  assert.equal(finding.impact!.verificationStatus, 'not_run');
  assert.match(finding.impact!.saferAlternative, /만료되는 공유 토큰/);
});

test('영향 설명·인용·의도의 HTML은 실행 가능한 태그로 출력하지 않는다', async () => {
  const result = await analyze({ files, intent: '"><script>alert(1)</script>' });
  result.findings[0].impact!.steps[0].explanation = '<img src=x onerror=alert(1)>';
  result.findings[0].impact!.saferAlternative = '<script>alert(2)</script>';
  const html = renderFindings(result);
  assert.doesNotMatch(html, /<script>|<img src=x/);
  assert.match(html, /&lt;img/);
});

test('AI 호출 실패 시 정적 탐지와 학습 자료가 유지된다', async (t) => {
  bindEnv({ ANTHROPIC_API_KEY: 'test-key' });
  t.after(() => bindEnv({ ANTHROPIC_API_KEY: '' }));
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'model unavailable' } }), { status: 400, headers: { 'content-type': 'application/json' } }));
  const result = await analyze({ files });
  assert.match(result.llm.error!, /400/);
  assert.ok(result.findings.length);
  assert.ok(result.findings.every((f) => f.impact?.source === 'rule'));
  assert.match(renderFindings(result), /이번 변경에서 배울 점/);
});

test('응답의 잘못된 분류와 변경되지 않은 파일은 학습 화면을 깨뜨리거나 새 이슈를 만들지 않는다', async (t) => {
  bindEnv({ ANTHROPIC_API_KEY: 'test-key' });
  t.after(() => bindEnv({ ANTHROPIC_API_KEY: '' }));
  const reply = { findings: [
    { ...sample, category: '__proto__', confidence: 0.9 },
    { ...sample, file: 'src/middleware/auth.ts', title: '변경되지 않은 파일', confidence: 0.9 },
  ] };
  t.mock.method(globalThis, 'fetch', async () => claude(JSON.stringify(reply)));
  const result = await analyze({ files, relatedContents: new Map([['src/middleware/auth.ts', 'export const auth = requireAuth;']]) });
  assert.equal(result.findings.some((f) => String(f.category) === '__proto__'), false);
  assert.equal(result.findings.some((f) => f.file === 'src/middleware/auth.ts'), false);
  assert.doesNotThrow(() => renderFindings(result));
});
