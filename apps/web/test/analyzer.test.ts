import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bindEnv } from '../src/config.ts';
import { parsePatch } from '../src/diff.ts';
import { extractJson } from '../src/llm.ts';
import { buildReviewComments, renderSummaryMarkdown, REPORT_MARKER, shouldFail } from '../src/reporter.ts';
import type { AnalysisResult } from '../src/types.ts';

bindEnv({ POE_API_KEY: '' });

test('extractJson: 코드펜스/앞뒤 텍스트 허용', () => {
  assert.deepEqual(extractJson('설명입니다\n```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(extractJson('prefix {"b":[1,2]} suffix'), { b: [1, 2] });
  assert.throws(() => extractJson('no json here'));
});

test('LLM 응답을 정적 결과와 병합하고 오탐을 제외한다', async (t) => {
  bindEnv({ POE_API_KEY: 'test-key' });
  t.after(() => bindEnv({ POE_API_KEY: '' }));
  const llmReply = {
    summary: 'BOLA 1건',
    findings: [
      { file: 'src/a.ts', line: 'L2', severity: 'critical', category: 'API1:2023', title: 'IDOR', description: 'd', recommendation: 'r', confidence: 0.9 },
      { file: 'src/a.ts', line: 3, severity: 'low', category: 'API8', title: '저신뢰', description: '', recommendation: '', confidence: 0.2 },
    ],
    static_review: [{ id: 'S2', verdict: 'false_positive', reason: '라우트 정의일 뿐' }],
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ choices: [{ message: { content: '```json\n' + JSON.stringify(llmReply) + '\n```' } }] })));

  const { analyze } = await import('../src/analyzer.ts');
  const patch = "@@ -0,0 +1,3 @@\n+router.get('/docs/:id', async (req, res) => {\n+  const d = await Doc.findById(req.params.id);\n+});";
  const result = await analyze({ files: [{ filename: 'src/a.ts', status: 'added', patch }] });

  assert.equal(result.llm.used, true);
  assert.equal(result.risk, 'critical');
  const bola = result.findings.find((f) => f.category === 'API1' && f.line === 2);
  assert.equal(bola?.source, 'static+llm');
  assert.equal(result.findings.some((f) => f.title === '저신뢰'), false, '신뢰도 낮은 결과는 버림');
  assert.equal(result.dismissed.length, 1);
});

test('reporter: diff 범위 밖 라인은 인라인 코멘트에서 제외, 실패 임계값', () => {
  const result: AnalysisResult = {
    risk: 'high', summary: '', dismissed: [], llm: { used: false }, stats: { filesScanned: 1, filesSkipped: 0, durationMs: 1 },
    findings: [
      { id: 'F1', source: 'static', file: 'a.ts', line: 2, severity: 'high', category: 'API1', title: 't', description: 'd', recommendation: 'r' },
      { id: 'F2', source: 'static', file: 'a.ts', line: 99, severity: 'low', category: 'API4', title: 't2', description: 'd', recommendation: 'r' },
    ],
  };
  const patches = new Map([['a.ts', parsePatch('@@ -1 +1,2 @@\n x\n+y')]]);
  assert.deepEqual(buildReviewComments(result, patches).map((c) => c.line), [2]);
  assert.equal(shouldFail(result, 'high'), true);
  assert.equal(shouldFail(result, 'critical'), false);
  assert.ok(renderSummaryMarkdown(result).startsWith(REPORT_MARKER));
});

test('LLM 결과 하나가 같은 이슈의 정적 결과 여러 개를 흡수한다', async (t) => {
  bindEnv({ POE_API_KEY: 'test-key' });
  t.after(() => bindEnv({ POE_API_KEY: '' }));
  const llmReply = {
    summary: '',
    findings: [
      { file: 'a.ts', line: 2, severity: 'high', category: 'API1', title: 'BOLA', description: '', recommendation: '', confidence: 0.9 },
      { file: 'a.ts', line: 4, severity: 'high', category: 'SECRETS', title: '시크릿', description: '', recommendation: '', confidence: 0.9 },
    ],
    static_review: [],
  };
  t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(llmReply) } }] })));
  const { analyze } = await import('../src/analyzer.ts');
  const patch = [
    '@@ -0,0 +1,4 @@',
    "+router.get('/docs/:id', async (req, res) => {", // 정적: 라우트 소유권 (API1, L1)
    '+  const d = await Doc.findById(req.params.id);', // 정적: BOLA (API1, L2)
    '+});',
    "+const JWT_SECRET = 'secret';", // 정적: weak-jwt-secret (API2, L4) ↔ LLM: SECRETS
  ].join('\n');
  const result = await analyze({ files: [{ filename: 'a.ts', status: 'added', patch }] });
  assert.deepEqual(result.findings.map((f) => [f.title, f.source]), [['BOLA', 'static+llm'], ['시크릿', 'static+llm']]);
});
