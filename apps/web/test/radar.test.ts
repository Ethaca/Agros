import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { bindEnv } from '../src/config.ts';
import { encrypt } from '../src/crypto.ts';
import { exposures, ignored, initDb, inventories, repos, signals, threats, users, type D1Database } from '../src/db.ts';
import { normalizeGhAdvisory, normalizeOsv, type CommunityPost } from '../src/feeds.ts';
import { buildInventory, parseManifest, selectManifestPaths } from '../src/manifests.ts';
import {
  advisoryIgnoreReason, bumpLine, candidateTargets, computeLevel, postIgnoreReason, createIssueFor, createPrFor, ingestOfficial, ingestPost, issueMarkdown, matchComponents, normalizeVerdicts, RadarActionError,
} from '../src/radar.ts';
import { radarPage } from '../src/ui/server.tsx';
import { judgeVersion, lowestOf, parseRangeExpression } from '../src/versions.ts';

bindEnv({ ANTHROPIC_API_KEY: '', ENCRYPTION_KEY: 'a'.repeat(64), SESSION_SECRET: 'b'.repeat(64), PUBLIC_URL: 'https://sentinel.test' });

test('버전 범위: GHSA 표기, 브랜치별 패치 목록, 범위 표기의 하한', () => {
  assert.deepEqual(parseRangeExpression('>= 16.3.0, < 16.3.4'), { introduced: '16.3.0', fixed: '16.3.4' });
  assert.equal(parseRangeExpression('16.3.x 이하'), null, '해석할 수 없으면 추측하지 않음');
  const ranges = [parseRangeExpression('>= 16.3.0, < 16.3.4')!];
  assert.deepEqual(judgeVersion('16.3.2', ranges, []), { affected: true, fix: '16.3.4' });
  assert.deepEqual(judgeVersion('16.3.4', ranges, []), { affected: false });
  const php = ['8.2.35', '8.3.36', '8.4.27', '8.5.12'];
  assert.deepEqual(judgeVersion('8.3.35', [], php), { affected: true, fix: '8.3.36' });
  assert.deepEqual(judgeVersion('8.4.27', [], php), { affected: false });
  assert.deepEqual(judgeVersion('8.1.30', [], php), { affected: true }, '패치 없는 오래된 브랜치');
  assert.deepEqual(judgeVersion('8.3.35', [], []), { affected: null });
  assert.equal(lowestOf('^8.3'), '8.3.0');
  assert.equal(lowestOf('lts/*'), null);
});

const LOCK = `{
  "name": "shop",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "shop",
      "version": "1.0.0",
      "dependencies": { "next": "^16.3.0" }
    },
    "node_modules/next": {
      "version": "16.3.2",
      "resolved": "https://registry.npmjs.org/next/-/next-16.3.2.tgz"
    },
    "node_modules/next/node_modules/@swc/helpers": {
      "version": "0.5.15"
    }
  }
}`;

test('매니페스트: lock 파일, Dockerfile, 런타임 선언, CI 설정을 줄 번호와 함께 읽는다', () => {
  const lock = parseManifest('package-lock.json', LOCK);
  assert.deepEqual(lock.map((c) => [c.target, c.spec, c.line, c.context]), [['npm:next', '16.3.2', 11, 'lock'], ['npm:@swc/helpers', '0.5.15', 15, 'lock']]);

  const docker = parseManifest('docker/Dockerfile', 'ARG X=1\nFROM php:8.3.35-fpm AS base\nFROM node:20-alpine\nFROM ${IMAGE}\n');
  assert.deepEqual(docker.map((c) => [c.target, c.spec, c.exact, c.line]), [['runtime:php', '8.3.35', true, 2], ['runtime:node', '20', false, 3]]);

  const composer = parseManifest('composer.json', '{\n  "require": {\n    "php": "^8.3",\n    "ext-json": "*",\n    "guzzlehttp/guzzle": "^7.9"\n  }\n}');
  assert.deepEqual(composer.map((c) => [c.target, c.spec, c.line]), [['runtime:php', '^8.3', 3], ['composer:guzzlehttp/guzzle', '^7.9', 5]]);

  const lockC = parseManifest('composer.lock', '{\n "packages": [\n  {\n   "name": "guzzlehttp/guzzle",\n   "version": "7.9.3",\n   "authors": [{ "name": "Michael Dowling" }]\n  }\n ]\n}');
  assert.deepEqual(lockC.map((c) => [c.target, c.spec]), [['composer:guzzlehttp/guzzle', '7.9.3']]);

  const ci = parseManifest('.github/workflows/ci.yml', "jobs:\n  t:\n    steps:\n      - uses: shivammathur/setup-php@v2\n        with:\n          php-version: '8.4'\n");
  assert.deepEqual(ci.map((c) => [c.target, c.spec, c.context]), [['runtime:php', '8.4', 'ci']]);

  const pnpm = parseManifest('pnpm-lock.yaml', "lockfileVersion: '9.0'\n\npackages:\n\n  next@16.3.2:\n    resolution: {}\n\n  '@types/node@22.20.5':\n    resolution: {}\n");
  assert.deepEqual(pnpm.map((c) => [c.target, c.spec]), [['npm:next', '16.3.2'], ['npm:@types/node', '22.20.5']]);

  // lock 이 있는 디렉터리의 package.json 범위 표기는 버린다
  const inv = buildInventory([{ path: 'package.json', content: '{"dependencies":{"next":"^16.3.0"},"engines":{"node":">=20"}}' }, { path: 'package-lock.json', content: LOCK }]);
  assert.deepEqual(inv.map((c) => `${c.target}@${c.spec}`).sort(), ['npm:@swc/helpers@0.5.15', 'npm:next@16.3.2', 'runtime:node@>=20']);

  assert.deepEqual(selectManifestPaths(['src/a.ts', 'node_modules/x/package.json', 'apps/web/package-lock.json', 'Dockerfile', '.github/workflows/ci.yml', 'deploy/prod.Dockerfile']),
    ['Dockerfile', 'deploy/prod.Dockerfile', 'apps/web/package-lock.json', '.github/workflows/ci.yml'], '얕은 경로 우선, CI 는 뒤로');
});

const sig = (o: Partial<{ official: number; trusted: number; exploited: number; domain: string | null; source: string }>) =>
  ({ official: 0, trusted: 0, exploited: 0, domain: 'example.com', source: 'HN', ...o });

test('신뢰도 단계: 소문 → 교차 확인 → 공식 → 악용 중', () => {
  assert.equal(computeLevel([sig({})], false), 1);
  assert.equal(computeLevel([sig({}), sig({})], false), 1, '같은 출처 반복은 교차 확인이 아님');
  assert.equal(computeLevel([sig({}), sig({ domain: 'other.org' })], false), 2);
  assert.equal(computeLevel([sig({ trusted: 1, domain: 'watchtowr.com' })], false), 2);
  assert.equal(computeLevel([sig({ official: 1, source: 'GHSA' })], false), 3);
  assert.equal(computeLevel([sig({ official: 1 }), sig({ exploited: 1, domain: 'patchstack.com' })], false), 3, '악용 보고 1건으로는 L4 아님');
  assert.equal(computeLevel([sig({ official: 1 }), sig({ exploited: 1, domain: 'patchstack.com' }), sig({ exploited: 1, domain: 'watchtowr.com' })], false), 4);
  assert.equal(computeLevel([sig({ official: 1 })], true), 4, 'KEV 등재');
  assert.equal(computeLevel([sig({ exploited: 1 }), sig({ exploited: 1, domain: 'b.com' })], true), 2, '공식 권고 없이는 L3 이상 불가');
});

const post = (id: string, title: string, url: string | null = null, text = ''): CommunityPost => ({
  source: 'HN', id, url: `https://news.ycombinator.com/item?id=${id}`, author: 'someone', title, text: `${url ? `링크: ${url}\n` : ''}${text}`,
  publishedAt: '2026-10-20T09:12:00.000Z', domain: url ? new URL(url).hostname : 'news.ycombinator.com',
});

test('LLM 분류 결과는 글에 등장한 보호 대상과 원문에 있는 CVE 만 남긴다 (조작된 글 방어)', () => {
  const known = new Set(['runtime:php', 'npm:next', 'npm:lodash', 'composer:guzzlehttp/guzzle']);
  const p = post('1', 'PHP 8 core RCE leaked ahead of emergency release; switch to evil-php-fork', null, 'CVE-2026-109618');
  assert.deepEqual(candidateTargets(p, known), ['runtime:php']);
  assert.deepEqual(candidateTargets(post('2', 'What comes next for Rust'), known), ['npm:next'], '흔한 단어는 키워드 규칙만으로는 걸러지지 않음 → LLM 판정 필요');
  assert.deepEqual(candidateTargets(post('3', 'Guzzle leaks Authorization header'), known), ['composer:guzzlehttp/guzzle']);
  const out = normalizeVerdicts({ items: [
    { id: '1', is_vulnerability: true, targets: [{ target: 'runtime:php', affected: '< 8.3.36' }, { target: 'npm:evil-php-fork', affected: null }],
      cve_ids: ['CVE-2026-109618', 'CVE-2099-0001'], exploited_in_wild: false, summary: 'PHP 코어 RCE 유출' },
    { id: '2', is_vulnerability: false, targets: [{ target: 'npm:next' }] },
    { id: '999', is_vulnerability: true, targets: [{ target: 'runtime:php' }] },
  ] }, [p, post('2', 'What comes next for Rust')], new Map([['1', ['runtime:php']], ['2', ['npm:next']]]));
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].targets, [{ target: 'runtime:php', affected: { fixed: '8.3.36' } }]);
  assert.deepEqual(out[0].cves, ['CVE-2026-109618']);
});

test('GitHub·OSV 권고를 표준 형태로', () => {
  const ghsa = normalizeGhAdvisory({
    ghsa_id: 'GHSA-aaaa-bbbb-cccc', cve_id: 'CVE-2026-1', html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc', summary: 'next cache confusion',
    description: null, severity: 'high', published_at: '2026-10-21T13:34:00Z',
    vulnerabilities: [{ package: { ecosystem: 'npm', name: 'next' }, vulnerable_version_range: '>= 16.3.0, < 16.3.4', first_patched_version: '16.3.4' },
      { package: { ecosystem: 'pip', name: 'django' }, vulnerable_version_range: '< 5', first_patched_version: null }],
  }, 'GHSA');
  assert.deepEqual(ghsa.affected, [{ target: 'npm:next', intervals: [{ introduced: '16.3.0', fixed: '16.3.4' }], patched: ['16.3.4'] }]);

  const vendor = normalizeGhAdvisory({
    ghsa_id: 'GHSA-php1', cve_id: 'CVE-2026-109618', html_url: 'https://github.com/php/php-src/security/advisories/GHSA-php1', summary: 'RCE in PHP core',
    description: 'see CVE-2026-109619', severity: 'critical', published_at: '2026-10-21T13:34:00Z',
    vulnerabilities: [{ package: { ecosystem: 'other', name: 'php-src' }, vulnerable_version_range: null, patched_versions: '8.2.35, 8.3.36, 8.4.27, 8.5.12' }],
  }, 'VENDOR', 'runtime:php');
  assert.deepEqual(vendor.affected, [{ target: 'runtime:php', intervals: [], patched: ['8.2.35', '8.3.36', '8.4.27', '8.5.12'] }]);
  assert.deepEqual(vendor.cves, ['CVE-2026-109618', 'CVE-2026-109619']);

  // 실제 php-src 권고 모양: 브랜치마다 하한 없는 "< x" 범위
  const branches = normalizeGhAdvisory({
    ghsa_id: 'GHSA-w8hw-w9fx-j79w', cve_id: null, html_url: 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w', summary: 'RCE via OOM corruption',
    description: '', severity: 'high', published_at: '2026-10-21T13:34:00Z',
    vulnerabilities: ['8.2.35', '8.3.36', '8.4.27', '8.5.12'].map((v) => ({ package: { ecosystem: 'other', name: 'php' }, vulnerable_version_range: `< ${v}`, patched_versions: v })),
  }, 'VENDOR', 'runtime:php');
  const { intervals, patched } = branches.affected[0];
  assert.deepEqual(judgeVersion('8.3.36', intervals, patched), { affected: false }, '패치된 8.3.36 은 "< 8.4.27" 에 걸리지 않음');
  assert.deepEqual(judgeVersion('8.3.35', intervals, patched), { affected: true, fix: '8.3.36' });
  assert.deepEqual(judgeVersion('8.1.20', intervals, patched), { affected: true, fix: '8.2.35' }, '가장 오래된 브랜치 아래는 계속 영향');

  const osv = normalizeOsv({ id: 'GHSA-x', aliases: ['CVE-2026-2'], published: '2026-10-22T00:00:00Z', summary: 's',
    affected: [{ package: { ecosystem: 'Packagist', name: 'guzzlehttp/guzzle' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '7.10.2' }] }] }] });
  assert.deepEqual(osv.affected, [{ target: 'composer:guzzlehttp/guzzle', intervals: [{ introduced: '0', fixed: '7.10.2' }], patched: ['7.10.2'] }]);
});

test('매칭: 공식 패치 버전만 PR 근거가 되고, 범위 표기·lock 파일은 PR 대상이 아니다', () => {
  const comps = buildInventory([
    { path: 'Dockerfile', content: 'FROM php:8.3.35-fpm\n' },
    { path: 'composer.json', content: '{"require":{"php":"^8.3"}}' },
    { path: '.github/workflows/ci.yml', content: "php-version: '8.5'\n" },
  ]);
  const rumor = matchComponents({ id: 1, target: 'runtime:php', ranges: [], patched: [], hintRanges: [{ fixed: '8.3.36' }] }, 'acme/api', comps);
  assert.deepEqual(rumor.map((e) => [e.file, e.status, e.fix_version]), [['Dockerfile', 'hit', null], ['composer.json', 'maybe', null]],
    'L1 의 SNS 범위로 영향은 표시하되 PR 근거(fix_version)는 만들지 않음');
  const official = matchComponents({ id: 1, target: 'runtime:php', ranges: [], patched: ['8.3.36', '8.4.27', '8.5.12'], hintRanges: [] }, 'acme/api', comps);
  assert.deepEqual(official.map((e) => [e.file, e.status, e.fix_version]),
    [['Dockerfile', 'hit', '8.3.36'], ['composer.json', 'maybe', null], ['.github/workflows/ci.yml', 'maybe', null]], "CI 의 '8.5' 는 8.5.0 일 수도 있음");
  assert.match(official[2].reason, /CI 설정입니다/);
  const lock = matchComponents({ id: 2, target: 'npm:next', ranges: [{ introduced: '16.3.0', fixed: '16.3.4' }], patched: ['16.3.4'], hintRanges: [] }, 'acme/web', parseManifest('package-lock.json', LOCK));
  assert.equal(lock[0].status, 'hit');
  assert.match(lock[0].reason, /lock 파일은 패키지 매니저로 갱신/);
});

test('숨긴 이유: 매칭하지 않는 생태계, 레포에 없는 대상, 이름은 나오지만 취약점 글이 아님', () => {
  const known = new Set(['runtime:php', 'npm:next']);
  const adv = (affected: { target: string }[], ecosystems: string[]) => ({
    source: 'GHSA' as const, id: 'GHSA-x', url: 'u', title: 't', text: '', publishedAt: '', cves: [], severity: null, ecosystems,
    affected: affected.map((a) => ({ ...a, intervals: [], patched: [] })),
  });
  assert.equal(advisoryIgnoreReason(adv([{ target: 'runtime:php' }], ['other']), known), null, '관련 있으면 숨기지 않음');
  assert.match(advisoryIgnoreReason(adv([], ['pip', 'Go']), known)!, /매칭하지 않는 생태계입니다: pip, Go/);
  assert.match(advisoryIgnoreReason(adv(['a', 'b', 'c', 'd'].map((n) => ({ target: `npm:${n}` })), ['npm']), known)!, /없는 대상입니다: npm:a, npm:b, npm:c 외 1개/);
  assert.match(postIgnoreReason(post('9', 'What comes next for Rust'), known), /npm:next 이 언급되지만 취약점 관련 글로 판정되지 않았습니다/);
  assert.match(postIgnoreReason(post('10', 'Linux kernel CVE'), known), /이름이 나오지 않습니다/);
});

test('PR 초안은 원래 줄이 그대로일 때만 버전 표기를 바꾼다', () => {
  assert.equal(bumpLine('# base\nFROM php:8.3.35-fpm\n', 2, 'FROM php:8.3.35-fpm', '8.3.35', '8.3.36'), '# base\nFROM php:8.3.36-fpm\n');
  assert.equal(bumpLine('FROM php:8.4.1-fpm\n', 1, 'FROM php:8.3.35-fpm', '8.3.35', '8.3.36'), null);
});

// ---------- D1 (node:sqlite) 위에서 전체 흐름 ----------

function sqliteD1(): D1Database {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  const stmt = (sql: string, values: unknown[] = []): any => ({
    bind: (...v: unknown[]) => stmt(sql, v),
    first: async () => db.prepare(sql).get(...(values as never[])) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...(values as never[])) }),
    run: async () => { const r = db.prepare(sql).run(...(values as never[])); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } }; },
  });
  return { prepare: (sql) => stmt(sql), batch: async (list) => { const out = []; for (const s of list as any[]) out.push(await s.run()); return out; } };
}

test('PHP2Shell 흐름: HN 소문 L1 → 공신력 출처 L2 → php-src 권고 L3 → 악용 보고 L4, Issue·PR 은 단계에 따라 열린다', async () => {
  await initDb(sqliteD1());
  const user = await users.upsert({ github_id: 1, login: 'octo', avatar_url: '', token_enc: encrypt('gho_test') });
  await repos.enable(user.id, 'acme/billing-api', 1, encrypt('s'));
  const comps = buildInventory([{ path: 'Dockerfile', content: 'FROM php:8.3.35-fpm\n' }, { path: 'composer.json', content: '{"require":{"php":"^8.3"}}' }]);
  await inventories.upsert('acme/billing-api', JSON.stringify(comps), 2, null);
  const known = new Set(comps.map((c) => c.target));
  const verdict = (id: string, exploited = false) => ({ id, relevant: true, targets: [{ target: 'runtime:php', affected: null }], cves: [], exploited, summary: 'PHP 코어 RCE' });

  const [tid] = await ingestPost(post('100', 'PHP core RCE patch leaked before emergency release'), verdict('100'));
  assert.equal((await threats.get(tid))!.level, 1);
  const listed = await threats.listForUser(user.id);
  assert.equal(listed.length, 0, '매칭은 수집 루프가 하므로 아직 노출 없음');
  await expectAction(() => createIssueFor(user.id, 1, 'https://x'), 'notfound');

  await ingestPost(post('101', 'watchTowr: PHP2Shell is real', 'https://labs.watchtowr.com/php2shell'), verdict('101'));
  assert.equal((await threats.get(tid))!.level, 2);

  const adv = normalizeGhAdvisory({
    ghsa_id: 'GHSA-php1', cve_id: 'CVE-2026-109618', html_url: 'https://github.com/php/php-src/security/advisories/GHSA-php1', summary: 'Unauthenticated RCE in PHP core',
    description: '', severity: 'critical', published_at: '2026-10-21T13:34:00Z',
    vulnerabilities: [{ package: null, vulnerable_version_range: null, patched_versions: '8.3.36, 8.4.27' }],
  }, 'VENDOR', 'runtime:php');
  assert.deepEqual(await ingestOfficial(adv, known), [tid], '공식 권고는 소문 위협에 합쳐진다');
  assert.deepEqual(await ingestOfficial(adv, known), [], '같은 권고는 한 번만');
  let t = (await threats.get(tid))!;
  assert.equal(t.level, 3);
  assert.equal(t.title, 'Unauthenticated RCE in PHP core');

  // 공식 권고 72시간 안의 글은 CVE 없이도 같은 위협으로
  await ingestPost(post('102', 'PHP2Shell exploited in the wild', 'https://patchstack.com/x'), verdict('102', true));
  await ingestPost(post('103', 'Honeypots see PHP2Shell attacks', 'https://watchtowr.com/y'), verdict('103', true));
  t = (await threats.get(tid))!;
  assert.equal(t.level, 4);
  const late = { ...post('104', 'Another PHP bug', 'https://example.org/z'), publishedAt: '2026-11-20T00:00:00.000Z' };
  const [other] = await ingestPost(late, verdict('104'));
  assert.notEqual(other, tid, '한 달 뒤 CVE 없는 글은 이 권고에 붙이지 않음');

  // 수집 루프가 하는 매칭
  const { matchComponents: match, threatSpec } = await import('../src/radar.ts');
  await exposures.replaceFor({ threatId: tid }, match(threatSpec(t), 'acme/billing-api', comps));
  const rows = await exposures.forUserThreat(user.id, tid);
  assert.deepEqual(rows.map((e) => [e.file, e.status, e.fix_version]), [['Dockerfile', 'hit', '8.3.36'], ['composer.json', 'maybe', null]]);
  assert.equal((await exposures.forUserThreat(user.id + 1, tid)).length, 0, '다른 사용자는 볼 수 없음');
  assert.equal(await exposures.getForUser(rows[0].id, user.id + 1), null);

  const { body } = issueMarkdown(t, 'acme/billing-api', rows, await signals.forThreat(tid), 'https://sentinel.test/radar?t=1');
  assert.match(body, /L4 악용 중/);
  assert.match(body, /`Dockerfile:1`/);
  assert.match(body, /8\.3\.36/);

  // GitHub API 를 가로채 PR 초안이 실제로 어떤 요청을 보내는지 확인
  const calls: { method: string; url: string; body?: any }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    calls.push({ method, url, body: init.body ? JSON.parse(String(init.body)) : undefined });
    const ok = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
    if (url.endsWith('/repos/acme/billing-api')) return ok({ full_name: 'acme/billing-api', default_branch: 'main', private: true, html_url: '', pushed_at: '' });
    if (url.includes('/contents/Dockerfile?')) return ok({ sha: 'blob1', encoding: 'base64', content: Buffer.from('FROM php:8.3.35-fpm\n').toString('base64') });
    if (url.includes('/git/ref/heads/main')) return ok({ object: { sha: 'base1' } });
    if (url.endsWith('/git/refs')) return ok({}, 201);
    if (method === 'PUT') return ok({}, 200);
    if (url.endsWith('/pulls')) return ok({ number: 128, html_url: 'https://github.com/acme/billing-api/pull/128' }, 201);
    if (url.endsWith('/issues')) return ok({ number: 141, html_url: 'https://github.com/acme/billing-api/issues/141' }, 201);
    return ok({ message: 'unexpected' }, 500);
  }) as typeof fetch;
  try {
    assert.equal(await createPrFor(user.id, rows[0].id, 'https://sentinel.test'), 'https://github.com/acme/billing-api/pull/128');
    const put = calls.find((c) => c.method === 'PUT')!;
    assert.equal(Buffer.from(put.body.content, 'base64').toString(), 'FROM php:8.3.36-fpm\n');
    assert.equal(put.body.sha, 'blob1');
    const pr = calls.find((c) => c.url.endsWith('/pulls'))!;
    assert.equal(pr.body.draft, true);
    assert.equal(pr.body.base, 'main');
    await expectAction(() => createPrFor(user.id, rows[1].id, 'https://sentinel.test'), 'notfixable');

    assert.equal(await createIssueFor(user.id, rows[1].id, 'https://sentinel.test'), 'https://github.com/acme/billing-api/issues/141');
    const issue = calls.find((c) => c.url.endsWith('/issues'))!;
    assert.deepEqual(issue.body.labels, ['security', 'urgent']);
    const after = await exposures.forUserThreat(user.id, tid);
    assert.ok(after.every((e) => e.issue_number === 141), '같은 위협은 레포당 Issue 1개');
  } finally {
    globalThis.fetch = realFetch;
  }

  // 숨긴 항목은 같은 출처·ID 로 한 번만 기록하고 오늘 목록으로 볼 수 있다
  const row = { source: 'HN', external_id: '555', title: 'Unrelated <b>post</b>', url: 'https://news.ycombinator.com/item?id=555', reason: '이름이 나오지 않습니다', published_at: null };
  assert.equal(await ignored.addMany([row, { ...row, external_id: '556' }]), 2);
  assert.equal(await ignored.addMany([row]), 0);
  assert.equal(await ignored.countToday(), 2);
  assert.deepEqual((await ignored.today()).map((r) => r.external_id).sort(), ['555', '556']);

  const html = radarPage({
    user, csrf: 'tok', list: await threats.listForUser(user.id), inventories: await inventories.forUser(user.id), lv: 0, confirmPr: false, version: 'v',
    selected: { threat: t, signals: await signals.forThreat(tid), exposures: await exposures.forUserThreat(user.id, tid), prefs: null },
    state: { lastRun: { at: '2026-10-23T10:00:00Z', collected: 120, relevant: 1, errors: [] }, today: { collected: 120, relevant: 1, ignored: 119 } },
  });
  const text = html.replaceAll('<!-- -->', '');
  assert.match(text, /L4 악용 중/);
  assert.match(text, /PR #128 초안/);
  assert.match(text, /Issue #141/);
  assert.match(text, /레포와 무관해서 숨김 <b[^>]*>119<\/b>/);
  assert.doesNotMatch(html, /gho_|token_enc|hook_secret/, '브라우저로 보내는 props 에 토큰을 넣지 않음');
  assert.ok(!html.includes('<script>alert'), '원문은 이스케이프');
});

async function expectAction(fn: () => Promise<unknown>, code: string) {
  await assert.rejects(fn, (err: unknown) => err instanceof RadarActionError && err.code === code);
}
