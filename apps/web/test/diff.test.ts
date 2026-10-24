import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isScannable, parsePatch, splitUnifiedDiff } from '../src/diff.ts';

test('parsePatch: new-side 라인 번호와 commentable 범위', () => {
  const p = parsePatch('@@ -10,3 +20,4 @@ fn\n ctx\n-old\n+new1\n+new2\n ctx2');
  assert.deepEqual(p.lines.map((l) => [l.type, l.newLine ?? null]), [
    ['ctx', 20], ['del', null], ['add', 21], ['add', 22], ['ctx', 23],
  ]);
  assert.deepEqual([...p.commentable], [20, 21, 22, 23]);
});

test('splitUnifiedDiff: 파일 분리 및 상태 판별', () => {
  const diff = [
    'diff --git a/a.ts b/a.ts', '--- a/a.ts', '+++ b/a.ts', '@@ -1 +1 @@', '-x', '+y',
    'diff --git a/new.py b/new.py', 'new file mode 100644', '--- /dev/null', '+++ b/new.py', '@@ -0,0 +1 @@', '+print(1)',
    'diff --git a/gone.go b/gone.go', '--- a/gone.go', '+++ /dev/null', '@@ -1 +0,0 @@', '-package x',
  ].join('\n');
  const files = splitUnifiedDiff(diff);
  assert.deepEqual(files.map((f) => [f.filename, f.status]), [['a.ts', 'modified'], ['new.py', 'added'], ['gone.go', 'removed']]);
});

test('isScannable: lock 파일/이미지 제외', () => {
  assert.equal(isScannable({ filename: 'src/app.ts', status: 'modified', patch: '@@' }), true);
  assert.equal(isScannable({ filename: 'package-lock.json', status: 'modified', patch: '@@' }), false);
  assert.equal(isScannable({ filename: 'logo.png', status: 'added', patch: '@@' }), false);
  assert.equal(isScannable({ filename: 'src/app.ts', status: 'modified' }), false);
});
