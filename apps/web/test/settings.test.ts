import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { addColumns, initDb, users, type D1Database } from '../src/db.ts';
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

test('기존 users 테이블에 report_lang 이 추가되고, 다시 실행해도 오류가 없으며, 설정이 저장된다', async () => {
  const db = new DatabaseSync(':memory:');
  // report_lang 이 없던 이전 배포의 스키마
  db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, github_id INTEGER NOT NULL UNIQUE, login TEXT NOT NULL,
    avatar_url TEXT, token_enc TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  const d1 = sqliteD1(db);
  await initDb(d1);
  await addColumns(d1); // 컬럼이 이미 있어도 통과

  const user = await users.upsert({ github_id: 1, login: 'octo', avatar_url: '', token_enc: encrypt('gho_test') });
  assert.equal(user.report_lang, null, '설정 전에는 서버 기본값을 따른다');
  await users.setReportLang(user.id, 'ko');
  assert.equal((await users.get(user.id))!.report_lang, 'ko');
  await users.setReportLang(user.id, 'en');
  assert.equal((await users.get(user.id))!.report_lang, 'en');

  assert.equal(user.report_simple, 0, '쉬운 설명은 기본으로 꺼져 있다');
  await users.setReportSimple(user.id, true);
  assert.equal((await users.get(user.id))!.report_simple, 1);
  await users.setReportSimple(user.id, false);
  assert.equal((await users.get(user.id))!.report_simple, 0);
});
