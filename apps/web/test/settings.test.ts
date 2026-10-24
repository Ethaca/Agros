import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { addColumns, initDb, repos, users, type D1Database } from '../src/db.ts';
import { encrypt } from '../src/crypto.ts';
import { bindEnv } from '../src/config.ts';

bindEnv({ ENCRYPTION_KEY: 'test-encryption-key' });

function sqliteD1(db = new DatabaseSync(':memory:')): D1Database {
  const stmt = (sql: string, values: unknown[] = []): any => ({
    bind: (...v: unknown[]) => stmt(sql, v),
    first: async () => db.prepare(sql).get(...(values as never[])) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...(values as never[])) }),
    run: async () => { const r = db.prepare(sql).run(...(values as never[])); return { meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } }; },
  });
  return { prepare: (sql) => stmt(sql), batch: async (list) => { const out = []; for (const s of list as any[]) out.push(await s.run()); return out; } };
}

test('기존 repos 테이블에 리포트 설정 컬럼이 추가되고, 다시 실행해도 오류가 없으며, 레포별로 저장된다', async () => {
  const db = new DatabaseSync(':memory:');
  // 리포트 설정 컬럼이 없던 이전 배포의 스키마
  db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, github_id INTEGER NOT NULL UNIQUE, login TEXT NOT NULL,
    avatar_url TEXT, token_enc TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  db.exec(`CREATE TABLE repos (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL UNIQUE, hook_id INTEGER, hook_secret_enc TEXT, enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  const d1 = sqliteD1(db);
  await initDb(d1);
  await addColumns(d1); // 컬럼이 이미 있어도 통과

  const user = await users.upsert({ github_id: 1, login: 'octo', avatar_url: '', token_enc: encrypt('gho_test') });
  await repos.enable(user.id, 'acme/api', 1, encrypt('s'));
  await repos.enable(user.id, 'acme/web', 2, encrypt('s'));
  const api = (await repos.byName('acme/api'))!;
  assert.equal(api.report_lang, null, '설정 전에는 서버 기본값을 따른다');
  assert.equal(api.report_simple, 0, '쉬운 설명은 기본으로 꺼져 있다');

  await repos.setReportSettings(api.id, { lang: 'ko', simple: true });
  assert.equal((await repos.byName('acme/api'))!.report_lang, 'ko');
  assert.equal((await repos.byName('acme/api'))!.report_simple, 1);
  assert.equal((await repos.byName('acme/web'))!.report_lang, null, '다른 레포에는 영향이 없다');

  // 보호를 껐다 켜도 설정은 남는다
  await repos.disable(api.id);
  await repos.enable(user.id, 'acme/api', 3, encrypt('s'));
  assert.equal((await repos.byName('acme/api'))!.report_lang, 'ko');

  await repos.setReportSettings(api.id, { lang: 'en', simple: false });
  assert.equal((await repos.byName('acme/api'))!.report_lang, 'en');
  assert.equal((await repos.byName('acme/api'))!.report_simple, 0);
});
