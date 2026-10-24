import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bindEnv } from '../src/config.ts';
import { renderSandboxReport, sandboxAllowed, workerAuthorized } from '../src/sandbox.ts';
import { DatabaseSync } from 'node:sqlite';
import { initDb, sandboxJobs, scans, type D1Database } from '../src/db.ts';
import { GitHub } from '../src/github.ts';

test('sandbox worker auth refuses absent/short/wrong credentials and repositories are opt-in', () => {
  const token = 'x'.repeat(64);
  assert.equal(workerAuthorized(undefined, token), false);
  assert.equal(workerAuthorized('Bearer short', 'short'), false);
  assert.equal(workerAuthorized(`Bearer ${'y'.repeat(64)}`, token), false);
  assert.equal(workerAuthorized(`Bearer ${token}`, token), true);
  bindEnv({ SANDBOX_ENABLED: 'true', SANDBOX_WORKER_TOKEN: token, SANDBOX_REPOS: 'gngsn/argos-realistic-app' });
  assert.equal(sandboxAllowed('gngsn/argos-realistic-app'), true);
  assert.equal(sandboxAllowed('someone/other'), false);
  bindEnv({ SANDBOX_ENABLED: 'false' });
  assert.equal(sandboxAllowed('gngsn/argos-realistic-app'), false);
});

test('incomplete sandbox runs do not render success or a vulnerability verdict', () => {
  bindEnv({ REPORT_LANG: 'en' });
  const text = renderSandboxReport({ version: 1, status: 'unsupported', image: 'argos-local-runtime:dev', durationMs: 10, reason: 'Unsupported database', routes: [], untested: [], findings: [] }, 'a'.repeat(40));
  assert.match(text, /NOT VERIFIED/);
  assert.match(text, /not a security pass/);
  assert.doesNotMatch(text, /Authenticated own-data control requests succeeded/);
});

test('source download supports Workers redirect mode and strips OAuth authorization on codeload', async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (input, init) => {
    calls++;
    assert.equal(init?.redirect, 'manual');
    if (calls === 1) {
      assert.ok(String(input).startsWith('https://api.github.com/repos/owner/demo/tarball/'));
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer private-oauth-value');
      return new Response(null, { status: 302, headers: { location: 'https://codeload.github.com/owner/demo/archive.tar.gz' } });
    }
    assert.ok(String(input).startsWith('https://codeload.github.com/'));
    assert.equal(new Headers(init?.headers).get('authorization'), null);
    return new Response('compressed-archive');
  };
  try {
    const r = await new GitHub('private-oauth-value').sourceArchive('owner/demo', 'a'.repeat(40));
    assert.equal(await r.text(), 'compressed-archive');
    assert.equal(calls, 2);
  } finally { globalThis.fetch = original; }
});

test('persistent jobs lease atomically, hide other users, reject stale/revoked leases, and preserve publication', async () => {
  const db = new DatabaseSync(':memory:');
  const database: D1Database = {
    prepare(sql: string) {
      const statement = () => db.prepare(sql);
      return { bind(...values: unknown[]) {
        const params = values as (string | number | null)[];
        return {
          async first<T>() { return (statement().get(...params) as T) ?? null; },
          async all<T>() { return { results: statement().all(...params) as T[] }; },
          async run() { const r = statement().run(...params); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } }; },
        };
      }, async run() { const r = statement().run(); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } }; } } as ReturnType<D1Database['prepare']>;
    },
    async batch(statements) { return Promise.all(statements.map((s) => s.run())); },
  };
  try {
    await initDb(database);
    db.exec("INSERT INTO users (id, github_id, login, token_enc) VALUES (1, 1, 'owner', 'encrypted'); INSERT INTO repos (user_id, full_name, enabled) VALUES (1, 'owner/demo', 1);");
    const scan = await scans.create({ user_id: 1, repo_full_name: 'owner/demo', pr_number: 1, pr_title: 'demo', head_sha: 'a'.repeat(40) });
    await scans.finish(scan, 'high', '{}');
    await sandboxJobs.enqueue(scan, 1, 'owner/demo', 1, 'a'.repeat(40));
    const now = Date.now();
    const first = await sandboxJobs.claim(['owner/demo'], 'a'.repeat(64), now);
    assert.ok(first);
    const second = await scans.create({ user_id: 1, repo_full_name: 'owner/demo', pr_number: 2, pr_title: 'other queued job', head_sha: 'b'.repeat(40) });
    await scans.finish(second, 'none', '{}');
    await sandboxJobs.enqueue(second, 1, 'owner/demo', 2, 'b'.repeat(40));
    // Even a second worker must not claim another queued job while the laptop is busy.
    assert.equal(await sandboxJobs.claim(['owner/demo'], 'b'.repeat(64), now), null);
    assert.equal(await sandboxJobs.forScan(scan, 2), null);
    assert.equal(await sandboxJobs.active(first.id, 'b'.repeat(64)), null);
    assert.ok(await sandboxJobs.active(first.id, first.lease!));
    assert.equal(await sandboxJobs.save(first.id, first.lease!, '{"persisted":true}'), 1);
    const retried = await sandboxJobs.claim(['owner/demo'], 'c'.repeat(64), now + 240_001);
    assert.equal(retried?.result_json, '{"persisted":true}');
    assert.equal(retried?.status, 'publishing');
    assert.equal(await sandboxJobs.active(first.id, first.lease!), null);
    db.exec("UPDATE repos SET enabled = 0");
    assert.equal(await sandboxJobs.active(first.id, retried!.lease!), null);
    assert.equal(await sandboxJobs.claim(['owner/demo'], 'd'.repeat(64), now + 480_002), null);
  } finally { db.close(); }
});
