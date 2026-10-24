import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { splitUnifiedDiff } from '../src/diff.ts';
import { runStaticRules } from '../src/rules.ts';

const scan = (file: string, ...added: string[]) =>
  runStaticRules([{ filename: file, status: 'modified', patch: `@@ -1 +1,${added.length} @@\n` + added.map((l) => '+' + l).join('\n') }]);
const ids = (file: string, ...added: string[]) => scan(file, ...added).map((f) => f.ruleId);

test('예제 취약 PR 에서 핵심 위협을 모두 잡는다', () => {
  const findings = runStaticRules(splitUnifiedDiff(readFileSync('examples/vulnerable-pr.diff', 'utf8')));
  const rules = new Set(findings.map((f) => f.ruleId));
  for (const r of ['bola-direct-object-lookup', 'mass-assignment', 'auth-middleware-removed', 'bfla-role-from-request',
    'ssrf', 'jwt-decode-without-verify', 'weak-jwt-secret', 'tls-verification-disabled', 'verbose-error', 'unbounded-page-size']) {
    assert.ok(rules.has(r), `${r} 미탐지`);
  }
});

test('소유권 조건이 있는 안전한 PR 은 high 이상이 없다', () => {
  const findings = runStaticRules(splitUnifiedDiff(readFileSync('examples/safe-pr.diff', 'utf8')));
  assert.deepEqual(findings.filter((f) => f.severity === 'high' || f.severity === 'critical'), []);
});

test('BOLA: 여러 언어/프레임워크', () => {
  assert.ok(ids('a.ts', 'const doc = await Doc.findById(req.params.id);').includes('bola-direct-object-lookup'));
  assert.ok(ids('a.py', 'item = Item.objects.get(pk=request.GET["id"])').includes('bola-direct-object-lookup'));
  assert.deepEqual(ids('a.ts', 'const doc = await Doc.findOne({ _id: req.params.id, ownerId: req.user.id });'), []);
});

test('BOLA: 다른 핸들러의 소유권 체크를 근거로 삼지 않는다', () => {
  const r = ids('a.ts',
    "router.get('/a', async (req, res) => {", '  const x = await A.find({ ownerId: req.user.id });', '});',
    "router.get('/b/:id', async (req, res) => {", '  const y = await B.findById(req.params.id);', '});');
  assert.ok(r.includes('bola-direct-object-lookup'));
});

test('mass assignment 와 필드 선별 구분', () => {
  assert.ok(ids('a.ts', 'await User.update(req.body, { where: { id } });').includes('mass-assignment'));
  assert.ok(ids('a.ts', 'const u = { ...req.body };').includes('mass-assignment'));
  assert.ok(!ids('a.ts', 'await User.update({ name: req.body.name }, { where: { id } });').includes('mass-assignment'));
});

test('시크릿: 환경변수 참조는 무시', () => {
  assert.ok(ids('a.ts', "const apiKey = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';").includes('hardcoded-secret'));
  assert.ok(!ids('a.ts', 'const apiKey = process.env.OPENAI_API_KEY_ABCDEFGHIJKLMNOP;').includes('hardcoded-secret'));
});

test('SQL injection / NoSQL injection', () => {
  assert.ok(ids('a.ts', 'db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);').includes('sql-injection'));
  assert.ok(ids('a.py', 'cursor.execute(f"SELECT * FROM t WHERE id = {uid}")').includes('sql-injection'));
  assert.ok(!ids('a.ts', "db.query('SELECT * FROM users WHERE id = $1', [id]);").includes('sql-injection'));
  assert.ok(ids('a.ts', 'const u = await User.findOne(req.body);').includes('nosql-injection'));
});

test('BFLA: 역할 체크 없는 admin 라우트', () => {
  assert.ok(ids('a.ts', "app.delete('/api/admin/users/:id', async (req, res) => {").includes('bfla-admin-route-without-role-check'));
  assert.ok(!ids('a.ts', "app.delete('/api/admin/users/:id', requireRole('admin'), async (req, res) => {").includes('bfla-admin-route-without-role-check'));
});

test('삭제된 인증 미들웨어가 다른 곳에 다시 추가되면 무시', () => {
  const patch = "@@ -1,2 +1,2 @@\n-router.get('/x', requireAuth, h);\n+router.get('/x', requireAuth, h2);";
  assert.deepEqual(runStaticRules([{ filename: 'a.ts', status: 'modified', patch }]).map((f) => f.ruleId), []);
});

test('주석 라인은 무시', () => {
  assert.deepEqual(ids('a.ts', '// const x = await Doc.findById(req.params.id);'), []);
});
