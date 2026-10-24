/** Cloudflare D1 (필요한 만큼만 최소 타입 정의) */
export interface D1Database {
  prepare(sql: string): D1Statement;
  batch(statements: D1Statement[]): Promise<unknown>;
}
interface D1Statement {
  bind(...values: unknown[]): D1Statement;
  first<T>(): Promise<T | null>;
  all<T>(): Promise<{ results: T[] }>;
  run(): Promise<{ meta: { last_row_id: number; changes: number } }>;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    github_id INTEGER NOT NULL UNIQUE,
    login TEXT NOT NULL,
    avatar_url TEXT,
    token_enc TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL UNIQUE,
    hook_id INTEGER,
    hook_secret_enc TEXT,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_full_name TEXT NOT NULL,
    pr_number INTEGER NOT NULL,
    pr_title TEXT,
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    risk TEXT,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS scans_user ON scans(user_id, id DESC)`,
  // ---- Threat Radar ----
  // 같은 대상(패키지·런타임)을 가리키는 신호의 묶음. ranges/patched 는 공식 권고에서만 채운다 (PR 근거)
  `CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    cve_ids TEXT NOT NULL DEFAULT '[]',
    advisory_ids TEXT NOT NULL DEFAULT '[]',
    ranges_json TEXT NOT NULL DEFAULT '[]',
    patched_json TEXT NOT NULL DEFAULT '[]',
    hint_ranges_json TEXT NOT NULL DEFAULT '[]',
    severity TEXT,
    level INTEGER NOT NULL DEFAULT 1,
    kev INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    official_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE INDEX IF NOT EXISTS threats_target ON threats(target, updated_at DESC)`,
  `CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY,
    threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    url TEXT NOT NULL,
    author TEXT,
    domain TEXT,
    title TEXT NOT NULL,
    verdict TEXT,
    official INTEGER NOT NULL DEFAULT 0,
    trusted INTEGER NOT NULL DEFAULT 0,
    exploited INTEGER NOT NULL DEFAULT 0,
    published_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source, external_id)
  )`,
  `CREATE INDEX IF NOT EXISTS signals_threat ON signals(threat_id, published_at)`,
  // 보호 중인 레포에서 읽은 의존성·런타임 목록 (매칭 때 GitHub 을 다시 부르지 않도록 캐시)
  `CREATE TABLE IF NOT EXISTS inventories (
    repo_full_name TEXT PRIMARY KEY,
    components_json TEXT NOT NULL,
    files_read INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS exposures (
    id INTEGER PRIMARY KEY,
    threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    repo_full_name TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    snippet TEXT NOT NULL,
    spec TEXT NOT NULL,
    context TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    fix_version TEXT,
    issue_number INTEGER,
    issue_url TEXT,
    pr_number INTEGER,
    pr_url TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(threat_id, repo_full_name, file, line)
  )`,
  `CREATE INDEX IF NOT EXISTS exposures_repo ON exposures(repo_full_name, threat_id)`,
  `CREATE TABLE IF NOT EXISTS threat_prefs (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    threat_id INTEGER NOT NULL REFERENCES threats(id) ON DELETE CASCADE,
    muted_until TEXT,
    assigned INTEGER NOT NULL DEFAULT 0,
    dismissed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(user_id, threat_id)
  )`,
  `CREATE TABLE IF NOT EXISTS radar_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  // 수집했지만 보호 중인 레포와 무관해서 숨긴 항목 (화면에서 이유와 함께 볼 수 있게 며칠만 보관)
  `CREATE TABLE IF NOT EXISTS radar_ignored (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    reason TEXT NOT NULL,
    published_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(source, external_id)
  )`,
  `CREATE INDEX IF NOT EXISTS radar_ignored_created ON radar_ignored(created_at DESC)`,
];

let d1: D1Database | undefined;
let migrated: Promise<unknown> | undefined;

/** isolate 당 한 번 스키마를 보장한다 (D1 은 배포 시 자동 생성되므로 별도 마이그레이션 단계 없이 동작) */
export async function initDb(database: D1Database) {
  d1 = database;
  migrated ??= database.batch(SCHEMA.map((s) => database.prepare(s))).catch((err) => {
    migrated = undefined;
    throw err;
  });
  await migrated;
}

const q = (sql: string, ...values: unknown[]) => {
  if (!d1) throw new Error('DB 가 초기화되지 않았습니다');
  return d1.prepare(sql).bind(...values);
};

export interface UserRow { id: number; github_id: number; login: string; avatar_url: string | null; token_enc: string }
export interface RepoRow { id: number; user_id: number; full_name: string; hook_id: number | null; hook_secret_enc: string | null; enabled: number }
export interface ScanRow {
  id: number; user_id: number; repo_full_name: string; pr_number: number; pr_title: string | null; head_sha: string;
  status: 'running' | 'done' | 'error'; risk: string | null; result_json: string | null; error: string | null;
  created_at: string; finished_at: string | null;
}

export const users = {
  async upsert(u: { github_id: number; login: string; avatar_url: string; token_enc: string }): Promise<UserRow> {
    await q(`INSERT INTO users (github_id, login, avatar_url, token_enc) VALUES (?, ?, ?, ?)
      ON CONFLICT(github_id) DO UPDATE SET login = excluded.login, avatar_url = excluded.avatar_url, token_enc = excluded.token_enc`,
    u.github_id, u.login, u.avatar_url, u.token_enc).run();
    return (await q('SELECT * FROM users WHERE github_id = ?', u.github_id).first<UserRow>())!;
  },
  get: (id: number) => q('SELECT * FROM users WHERE id = ?', id).first<UserRow>(),
};

export const repos = {
  byName: (fullName: string) => q('SELECT * FROM repos WHERE full_name = ?', fullName).first<RepoRow>(),
  async listForUser(userId: number): Promise<RepoRow[]> {
    return (await q('SELECT * FROM repos WHERE user_id = ?', userId).all<RepoRow>()).results;
  },
  async enable(userId: number, fullName: string, hookId: number, hookSecretEnc: string) {
    await q(`INSERT INTO repos (user_id, full_name, hook_id, hook_secret_enc, enabled) VALUES (?, ?, ?, ?, 1)
      ON CONFLICT(full_name) DO UPDATE SET user_id = excluded.user_id, hook_id = excluded.hook_id,
        hook_secret_enc = excluded.hook_secret_enc, enabled = 1`, userId, fullName, hookId, hookSecretEnc).run();
  },
  async disable(id: number) {
    await q('UPDATE repos SET enabled = 0, hook_id = NULL, hook_secret_enc = NULL WHERE id = ?', id).run();
  },
};

export const scans = {
  async create(s: { user_id: number; repo_full_name: string; pr_number: number; pr_title: string; head_sha: string }): Promise<number> {
    const r = await q(`INSERT INTO scans (user_id, repo_full_name, pr_number, pr_title, head_sha, status)
      VALUES (?, ?, ?, ?, ?, 'running')`, s.user_id, s.repo_full_name, s.pr_number, s.pr_title, s.head_sha).run();
    return r.meta.last_row_id;
  },
  async finish(id: number, risk: string, resultJson: string) {
    await q(`UPDATE scans SET status = 'done', risk = ?, result_json = ?, finished_at = datetime('now') WHERE id = ?`, risk, resultJson, id).run();
  },
  async fail(id: number, error: string) {
    await q(`UPDATE scans SET status = 'error', error = ?, finished_at = datetime('now') WHERE id = ?`, error, id).run();
  },
  /** user_id 조건을 반드시 함께 건다 (이 도구 자체의 BOLA 방지) */
  getForUser: (id: number, userId: number) => q('SELECT * FROM scans WHERE id = ? AND user_id = ?', id, userId).first<ScanRow>(),
  async recentForUser(userId: number, limit = 30): Promise<ScanRow[]> {
    return (await q('SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC LIMIT ?', userId, limit).all<ScanRow>()).results;
  },
  async existsForSha(repoFullName: string, prNumber: number, sha: string): Promise<boolean> {
    return !!(await q(`SELECT 1 AS x FROM scans WHERE repo_full_name = ? AND pr_number = ? AND head_sha = ? AND status != 'error'`,
      repoFullName, prNumber, sha).first());
  },
};

// ---------- Threat Radar ----------

export interface ThreatRow {
  id: number; target: string; title: string; summary: string | null; cve_ids: string; advisory_ids: string;
  ranges_json: string; patched_json: string; hint_ranges_json: string; severity: string | null;
  level: number; kev: number; first_seen_at: string; official_at: string | null; updated_at: string;
}
export interface ThreatListRow extends ThreatRow {
  hits: number; maybes: number; fixed: number; repos: number; signal_count: number; sources: string | null;
  muted_until: string | null; assigned: number | null; dismissed: number | null;
}
export interface SignalRow {
  id: number; threat_id: number; source: string; external_id: string; url: string; author: string | null; domain: string | null;
  title: string; verdict: string | null; official: number; trusted: number; exploited: number; published_at: string; created_at: string;
}
export interface ExposureRow {
  id: number; threat_id: number; repo_full_name: string; file: string; line: number; snippet: string; spec: string;
  context: string; status: 'hit' | 'maybe' | 'fixed'; reason: string; fix_version: string | null;
  issue_number: number | null; issue_url: string | null; pr_number: number | null; pr_url: string | null; updated_at: string;
}
export interface InventoryRow { repo_full_name: string; components_json: string; files_read: number; error: string | null; fetched_at: string }

export const radarState = {
  async get(key: string): Promise<string | null> {
    return (await q('SELECT value FROM radar_state WHERE key = ?', key).first<{ value: string }>())?.value ?? null;
  },
  async set(key: string, value: string) {
    await q('INSERT INTO radar_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, value).run();
  },
  async all(): Promise<Record<string, string>> {
    const rows = (await q('SELECT key, value FROM radar_state').all<{ key: string; value: string }>()).results;
    return Object.fromEntries(rows.map((r) => [r.key, r.value]));
  },
};

export const threats = {
  get: (id: number) => q('SELECT * FROM threats WHERE id = ?', id).first<ThreatRow>(),
  /** 같은 대상에 최근 갱신된 위협 (신호를 묶을 후보) */
  async openForTarget(target: string, days = 14): Promise<ThreatRow[]> {
    return (await q(`SELECT * FROM threats WHERE target = ? AND updated_at > datetime('now', ?) ORDER BY updated_at DESC`,
      target, `-${days} days`).all<ThreatRow>()).results;
  },
  async create(t: { target: string; title: string; summary: string | null }): Promise<number> {
    return (await q('INSERT INTO threats (target, title, summary) VALUES (?, ?, ?)', t.target, t.title, t.summary).run()).meta.last_row_id;
  },
  async update(id: number, fields: Partial<Omit<ThreatRow, 'id' | 'target' | 'first_seen_at'>>) {
    const keys = Object.keys(fields);
    if (!keys.length) return;
    await q(`UPDATE threats SET ${keys.map((k) => `${k} = ?`).join(', ')}, updated_at = datetime('now') WHERE id = ?`,
      ...keys.map((k) => (fields as Record<string, unknown>)[k]), id).run();
  },
  async withCvesNotInKev(): Promise<ThreatRow[]> {
    return (await q(`SELECT * FROM threats WHERE kev = 0 AND cve_ids != '[]' AND updated_at > datetime('now', '-60 days')`).all<ThreatRow>()).results;
  },
  async recent(days = 60): Promise<ThreatRow[]> {
    return (await q(`SELECT * FROM threats WHERE updated_at > datetime('now', ?)`, `-${days} days`).all<ThreatRow>()).results;
  },
  /** 사용자의 보호 중인 레포와 매칭된 위협만 (연결된 레포와 무관한 신호는 보여주지 않는다) */
  async listForUser(userId: number): Promise<ThreatListRow[]> {
    return (await q(`SELECT t.*,
        SUM(e.status = 'hit') AS hits, SUM(e.status = 'maybe') AS maybes, SUM(e.status = 'fixed') AS fixed,
        COUNT(DISTINCT e.repo_full_name) AS repos,
        (SELECT COUNT(*) FROM signals s WHERE s.threat_id = t.id) AS signal_count,
        (SELECT GROUP_CONCAT(DISTINCT s.source) FROM signals s WHERE s.threat_id = t.id) AS sources,
        p.muted_until, p.assigned, p.dismissed
      FROM threats t
      JOIN exposures e ON e.threat_id = t.id
      JOIN repos r ON r.full_name = e.repo_full_name AND r.user_id = ? AND r.enabled = 1
      LEFT JOIN threat_prefs p ON p.threat_id = t.id AND p.user_id = ?
      GROUP BY t.id ORDER BY t.level DESC, SUM(e.status = 'hit') > 0 DESC, t.updated_at DESC LIMIT 200`, userId, userId).all<ThreatListRow>()).results;
  },
};

export const signals = {
  /** 이미 있으면 false (출처 + 외부 ID 로 중복 제거) */
  async insert(s: Omit<SignalRow, 'id' | 'created_at'>): Promise<boolean> {
    const r = await q(`INSERT INTO signals (threat_id, source, external_id, url, author, domain, title, verdict, official, trusted, exploited, published_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source, external_id) DO NOTHING`,
    s.threat_id, s.source, s.external_id, s.url, s.author, s.domain, s.title, s.verdict, s.official, s.trusted, s.exploited, s.published_at).run();
    return r.meta.changes > 0;
  },
  async exists(source: string, externalId: string): Promise<boolean> {
    return !!(await q('SELECT 1 AS x FROM signals WHERE source = ? AND external_id = ?', source, externalId).first());
  },
  /** 공식 권고 ID 를 이미 받은 적이 있는가 (GHSA 피드와 OSV 가 같은 권고를 줄 때 중복 방지) */
  async knownAdvisory(id: string): Promise<boolean> {
    return !!(await q(`SELECT 1 AS x FROM signals WHERE official = 1 AND substr(external_id, 1, ?) = ?`, id.length + 1, `${id}|`).first());
  },
  async forThreat(threatId: number): Promise<SignalRow[]> {
    return (await q('SELECT * FROM signals WHERE threat_id = ? ORDER BY published_at, id', threatId).all<SignalRow>()).results;
  },
};

export const inventories = {
  async upsert(repo: string, componentsJson: string, filesRead: number, error: string | null) {
    await q(`INSERT INTO inventories (repo_full_name, components_json, files_read, error, fetched_at) VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(repo_full_name) DO UPDATE SET components_json = excluded.components_json, files_read = excluded.files_read,
        error = excluded.error, fetched_at = excluded.fetched_at`, repo, componentsJson, filesRead, error).run();
  },
  /** 보호 중인 레포의 목록만 (보호를 끈 레포는 매칭하지 않는다) */
  async allEnabled(): Promise<InventoryRow[]> {
    return (await q(`SELECT i.* FROM inventories i JOIN repos r ON r.full_name = i.repo_full_name AND r.enabled = 1`).all<InventoryRow>()).results;
  },
  get: (repo: string) => q('SELECT * FROM inventories WHERE repo_full_name = ?', repo).first<InventoryRow>(),
  async forUser(userId: number): Promise<(InventoryRow & { full_name: string })[]> {
    return (await q(`SELECT r.full_name, i.* FROM repos r LEFT JOIN inventories i ON i.repo_full_name = r.full_name
      WHERE r.user_id = ? AND r.enabled = 1 ORDER BY r.full_name`, userId).all<InventoryRow & { full_name: string }>()).results;
  },
  async stale(hours = 6, limit = 10): Promise<string[]> {
    return (await q(`SELECT r.full_name FROM repos r LEFT JOIN inventories i ON i.repo_full_name = r.full_name
      WHERE r.enabled = 1 AND (i.fetched_at IS NULL OR i.fetched_at < datetime('now', ?)) LIMIT ?`, `-${hours} hours`, limit)
      .all<{ full_name: string }>()).results.map((r) => r.full_name);
  },
};

export type ExposureInput = Pick<ExposureRow, 'threat_id' | 'repo_full_name' | 'file' | 'line' | 'snippet' | 'spec' | 'context' | 'status' | 'reason' | 'fix_version'>;

export const exposures = {
  /** 매칭 결과를 반영. 이번에 매칭되지 않은 이전 영향 항목은 '해결됨' 으로 바꾼다 (버전업 후 다시 읽었을 때) */
  async replaceFor(scope: { threatId?: number; repo?: string }, rows: ExposureInput[]) {
    const stmts = rows.map((e) => q(`INSERT INTO exposures (threat_id, repo_full_name, file, line, snippet, spec, context, status, reason, fix_version)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(threat_id, repo_full_name, file, line) DO UPDATE SET
        snippet = excluded.snippet, spec = excluded.spec, context = excluded.context, status = excluded.status,
        reason = excluded.reason, fix_version = excluded.fix_version, updated_at = datetime('now')`,
    e.threat_id, e.repo_full_name, e.file, e.line, e.snippet, e.spec, e.context, e.status, e.reason, e.fix_version));
    const keep = new Set(rows.map((e) => `${e.threat_id}|${e.repo_full_name}|${e.file}|${e.line}`));
    const where = scope.threatId ? 'threat_id = ?' : 'repo_full_name = ?';
    const current = (await q(`SELECT * FROM exposures WHERE ${where} AND status != 'fixed'`, scope.threatId ?? scope.repo).all<ExposureRow>()).results;
    for (const e of current) {
      if (!keep.has(`${e.threat_id}|${e.repo_full_name}|${e.file}|${e.line}`)) {
        stmts.push(q(`UPDATE exposures SET status = 'fixed', reason = '다시 읽은 파일에서 영향 버전이 더 이상 보이지 않습니다', updated_at = datetime('now') WHERE id = ?`, e.id));
      }
    }
    for (let i = 0; i < stmts.length; i += 50) await d1!.batch(stmts.slice(i, i + 50));
  },
  async forUserThreat(userId: number, threatId: number): Promise<ExposureRow[]> {
    return (await q(`SELECT e.* FROM exposures e JOIN repos r ON r.full_name = e.repo_full_name AND r.user_id = ? AND r.enabled = 1
      WHERE e.threat_id = ? ORDER BY e.status = 'fixed', e.status = 'maybe', e.repo_full_name, e.file`, userId, threatId).all<ExposureRow>()).results;
  },
  /** 소유자 확인을 SQL 에 함께 건다 (이 도구 자체의 BOLA 방지) */
  getForUser: (id: number, userId: number) => q(`SELECT e.* FROM exposures e JOIN repos r ON r.full_name = e.repo_full_name AND r.user_id = ? AND r.enabled = 1
    WHERE e.id = ?`, userId, id).first<ExposureRow>(),
  async setIssue(threatId: number, repo: string, number: number, url: string) {
    await q('UPDATE exposures SET issue_number = ?, issue_url = ? WHERE threat_id = ? AND repo_full_name = ?', number, url, threatId, repo).run();
  },
  async setPr(id: number, number: number, url: string) {
    await q('UPDATE exposures SET pr_number = ?, pr_url = ? WHERE id = ?', number, url, id).run();
  },
};

export const threatPrefs = {
  async set(userId: number, threatId: number, fields: { muted_until?: string | null; assigned?: number; dismissed?: number }) {
    await q('INSERT INTO threat_prefs (user_id, threat_id) VALUES (?, ?) ON CONFLICT DO NOTHING', userId, threatId).run();
    const keys = Object.keys(fields);
    await q(`UPDATE threat_prefs SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE user_id = ? AND threat_id = ?`,
      ...keys.map((k) => (fields as Record<string, unknown>)[k]), userId, threatId).run();
  },
  get: (userId: number, threatId: number) =>
    q('SELECT * FROM threat_prefs WHERE user_id = ? AND threat_id = ?', userId, threatId).first<{ muted_until: string | null; assigned: number; dismissed: number }>(),
};

export interface IgnoredRow { id: number; source: string; external_id: string; title: string; url: string; reason: string; published_at: string | null; created_at: string }
export type IgnoredInput = Pick<IgnoredRow, 'source' | 'external_id' | 'title' | 'url' | 'reason' | 'published_at'>;

export const ignored = {
  /** 이미 기록한 항목은 건너뛴다. 새로 기록한 수를 돌려준다 */
  async addMany(rows: IgnoredInput[]): Promise<number> {
    let added = 0;
    for (let i = 0; i < rows.length; i += 50) {
      const res = await d1!.batch(rows.slice(i, i + 50).map((r) => q(`INSERT INTO radar_ignored (source, external_id, title, url, reason, published_at)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(source, external_id) DO NOTHING`, r.source, r.external_id, r.title.slice(0, 300), r.url, r.reason, r.published_at))) as { meta?: { changes?: number } }[] | undefined;
      added += (res ?? []).reduce((n, r) => n + (r?.meta?.changes ?? 0), 0);
    }
    return added;
  },
  /** 오늘(UTC) 숨긴 항목 */
  async today(limit = 500): Promise<IgnoredRow[]> {
    return (await q(`SELECT * FROM radar_ignored WHERE created_at >= date('now') ORDER BY created_at DESC, id DESC LIMIT ?`, limit).all<IgnoredRow>()).results;
  },
  async countToday(): Promise<number> {
    return (await q(`SELECT COUNT(*) AS n FROM radar_ignored WHERE created_at >= date('now')`).first<{ n: number }>())?.n ?? 0;
  },
  async prune(days = 3) {
    await q(`DELETE FROM radar_ignored WHERE created_at < datetime('now', ?)`, `-${days} days`).run();
  },
};
