import { Buffer } from 'node:buffer';
import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { bindEnv, config } from './config.ts';
import { decrypt, encrypt, randomToken, signPayload, verifyPayload, verifyWebhookSignature } from './crypto.ts';
import { exposures, ignored, initDb, inventories, radarState, repos, scans, signals, threatPrefs, threats, users, type D1Database, type UserRow } from './db.ts';
import { exchangeOAuthCode, GitHub, GitHubError, type GhRepo } from './github.ts';
import { collect, createIssueFor, createPrFor, RadarActionError, refreshInventory } from './radar.ts';
import { scanPullRequest, type ScanJob } from './scanner.ts';
import { dashboardPage, landingPage, messagePage, radarPage, scanPage } from './ui/server.tsx';

/** 큐 하나로 PR 스캔과 Threat Radar 작업을 함께 처리한다 */
type QueueJob = ({ kind?: undefined } & ScanJob) | { kind: 'inventory'; repo: string } | { kind: 'collect' };
type QueueBody = QueueJob & { publicUrl?: string };

interface Bindings {
  DB: D1Database;
  SCAN_QUEUE: { send(body: QueueBody): Promise<void> };
  [key: string]: unknown;
}
type AppEnv = { Bindings: Bindings; Variables: { user?: UserRow; csrf: string } };
type Ctx = Context<AppEnv>;

const SESSION_TTL_S = 7 * 24 * 3600;
const PR_ACTIONS = new Set(['opened', 'synchronize', 'reopened', 'ready_for_review']);
const REPO_NAME = /^[\w.-]+$/;
const FLASH: Record<string, { msg: string; err?: boolean }> = {
  enabled: { msg: '보호를 켰습니다. 이제 이 레포의 PR 이 자동으로 검사됩니다.' },
  disabled: { msg: '보호를 껐고 webhook 을 삭제했습니다.' },
  queued: { msg: '검사를 시작했습니다. 잠시 후 PR 코멘트와 아래 목록에서 결과를 확인하세요.' },
  noadmin: { msg: '이 레포의 관리자 권한이 없어 webhook 을 만들 수 없습니다.', err: true },
  taken: { msg: '다른 사용자가 이미 이 레포를 보호 중입니다.', err: true },
  notfound: { msg: '대상을 찾을 수 없습니다.', err: true },
  ghfail: { msg: 'GitHub API 호출에 실패했습니다. 토큰 권한을 확인하고 다시 로그인해 주세요.', err: true },
  collecting: { msg: '수집을 시작했습니다. 1분 안에 새 신호가 반영됩니다.' },
  busy: { msg: '방금 수집했습니다. 1분 뒤에 다시 시도하세요.', err: true },
  refreshing: { msg: '보호 중인 레포의 의존성과 런타임 버전을 다시 읽고 있습니다.' },
  issue_done: { msg: 'GitHub Issue 를 만들었습니다.' },
  pr_done: { msg: '버전업 PR 초안을 만들었습니다. 머지 전에 스테이징에서 확인하세요.' },
  locked: { msg: '현재 신뢰도 단계에서는 이 조치를 할 수 없습니다.', err: true },
  notfixable: { msg: '공식 패치 버전으로 바꿀 수 있는 위치가 아닙니다. Issue 안내대로 직접 갱신하세요.', err: true },
  changed: { msg: '파일이 수집 이후 바뀌었습니다. "레포 다시 읽기" 후 다시 시도하세요.', err: true },
  pref: { msg: '설정을 바꿨습니다.' },
};

const app = new Hono<AppEnv>();

const cookie = (c: Ctx, name: string, value: string, maxAge: number) =>
  setCookie(c, name, value, { httpOnly: true, sameSite: 'Lax', secure: config.publicUrl.startsWith('https://'), maxAge, path: '/' });

app.use('*', async (c, next) => {
  // PUBLIC_URL 을 따로 설정하지 않으면 접속한 origin 을 사용
  bindEnv({ PUBLIC_URL: new URL(c.req.url).origin, ...c.env });
  await initDb(c.env.DB);

  const session = verifyPayload<{ uid: number; exp: number }>(getCookie(c, 'sid'));
  if (session) c.set('user', (await users.get(session.uid)) ?? undefined);
  let csrf = getCookie(c, 'csrf');
  if (!csrf) {
    csrf = randomToken(16);
    cookie(c, 'csrf', csrf, SESSION_TTL_S);
  }
  c.set('csrf', csrf);
  await next();
});

const requireUser: MiddlewareHandler<AppEnv> = async (c, next) => (c.get('user') ? next() : c.redirect('/'));

/** double-submit CSRF 토큰 + SameSite=Lax 쿠키. 파싱한 form 을 이후 핸들러에 넘긴다 */
async function form(c: Ctx): Promise<Record<string, string> | null> {
  const body = await c.req.parseBody();
  const data = Object.fromEntries(Object.entries(body).map(([k, v]) => [k, typeof v === 'string' ? v : '']));
  return data.csrf && data.csrf === getCookie(c, 'csrf') ? data : null;
}
const csrfFail = (c: Ctx) => c.text('CSRF 토큰이 유효하지 않습니다', 403);

const ghFor = (user: UserRow) => new GitHub(decrypt(user.token_enc));
const enqueue = (c: Ctx, job: QueueJob) => c.env.SCAN_QUEUE.send({ ...job, publicUrl: config.publicUrl });

// ---------- webhook ----------
app.post('/webhooks/github', async (c) => {
  const raw = Buffer.from(await c.req.arrayBuffer());
  let payload: any;
  try {
    payload = JSON.parse(raw.toString('utf8'));
  } catch {
    return c.text('invalid json', 400);
  }
  const fullName: string | undefined = payload?.repository?.full_name;
  const row = fullName ? await repos.byName(fullName) : null;
  if (!row?.enabled || !row.hook_secret_enc) return c.text('repo not registered', 404);
  if (!verifyWebhookSignature(decrypt(row.hook_secret_enc), raw, c.req.header('x-hub-signature-256'))) {
    return c.text('bad signature', 401);
  }

  const event = c.req.header('x-github-event');
  if (event === 'ping') return c.text('pong');
  if (event === 'pull_request' && PR_ACTIONS.has(payload.action) && !payload.pull_request?.draft) {
    await enqueue(c, { userId: row.user_id, repo: fullName!, number: payload.pull_request.number });
    return c.text('scan queued', 202);
  }
  return c.body(null, 204);
});

// ---------- OAuth ----------
app.get('/auth/github', (c) => {
  const state = randomToken(16);
  cookie(c, 'oauth_state', state, 600);
  const params = new URLSearchParams({
    client_id: config.githubClientId,
    redirect_uri: `${config.publicUrl}/auth/github/callback`,
    // repo: PR/파일 읽기, 코멘트, commit status / admin:repo_hook: webhook 등록·삭제
    scope: 'repo admin:repo_hook read:user',
    state,
  });
  return c.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get('/auth/github/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const expected = getCookie(c, 'oauth_state');
  deleteCookie(c, 'oauth_state', { path: '/' });
  if (!code || !state || state !== expected) {
    return c.html(messagePage('로그인 실패', 'OAuth state 가 일치하지 않습니다.', { link: { href: '/', label: '다시 시도' } }), 400);
  }
  try {
    const token = await exchangeOAuthCode(code);
    const me = await new GitHub(token).getUser();
    const user = await users.upsert({ github_id: me.id, login: me.login, avatar_url: me.avatar_url, token_enc: encrypt(token) });
    cookie(c, 'sid', signPayload({ uid: user.id, exp: Date.now() + SESSION_TTL_S * 1000 }), SESSION_TTL_S);
    return c.redirect('/');
  } catch (err) {
    console.error('[oauth]', err);
    return c.html(messagePage('로그인 실패', 'GitHub 로그인에 실패했습니다.', { link: { href: '/', label: '다시 시도' } }), 500);
  }
});

app.post('/logout', (c) => {
  deleteCookie(c, 'sid', { path: '/' });
  return c.redirect('/');
});

// ---------- dashboard ----------
app.get('/', async (c) => {
  const user = c.get('user');
  if (!user) return c.html(landingPage());
  let ghRepos: GhRepo[];
  try {
    ghRepos = await ghFor(user).listAdminRepos();
  } catch (err) {
    if (err instanceof GitHubError && err.status === 401) {
      deleteCookie(c, 'sid', { path: '/' });
      return c.redirect('/');
    }
    throw err;
  }
  const [rows, recent] = await Promise.all([repos.listForUser(user.id), scans.recentForUser(user.id)]);
  return c.html(dashboardPage(user, ghRepos, rows, recent, c.get('csrf'), FLASH[c.req.query('m') ?? '']));
});

app.post('/repos/:owner/:name/enable', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const { owner, name } = c.req.param();
  if (!REPO_NAME.test(owner) || !REPO_NAME.test(name)) return c.redirect('/?m=notfound');
  const fullName = `${owner}/${name}`;
  const user = c.get('user')!;
  const gh = ghFor(user);
  try {
    // 서버 측에서 GitHub 에 직접 관리자 권한을 재확인 (클라이언트 입력을 믿지 않음)
    const repo = await gh.getRepo(fullName);
    if (!repo.permissions?.admin) return c.redirect('/?m=noadmin');
    const existing = await repos.byName(fullName);
    if (existing?.enabled && existing.user_id !== user.id) return c.redirect('/?m=taken');
    if (existing?.enabled && existing.hook_id) await gh.deleteHook(fullName, existing.hook_id).catch(() => {});

    const secret = randomToken(32);
    const hook = await gh.createHook(repo.full_name, `${config.publicUrl}/webhooks/github`, secret);
    await repos.enable(user.id, repo.full_name, hook.id, encrypt(secret));
    await enqueue(c, { kind: 'inventory', repo: repo.full_name });
    return c.redirect('/?m=enabled');
  } catch (err) {
    console.error('[enable]', err);
    return c.redirect('/?m=ghfail');
  }
});

app.post('/repos/:owner/:name/disable', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const { owner, name } = c.req.param();
  const user = c.get('user')!;
  const row = await repos.byName(`${owner}/${name}`);
  // 소유자 확인 — 남의 레포 설정을 끌 수 없게
  if (!row || row.user_id !== user.id) return c.redirect('/?m=notfound');
  if (row.hook_id) {
    await ghFor(user).deleteHook(row.full_name, row.hook_id).catch((err) => {
      if (!(err instanceof GitHubError && err.status === 404)) console.warn('[disable]', err.message);
    });
  }
  await repos.disable(row.id);
  return c.redirect('/?m=disabled');
});

app.post('/scan', requireUser, async (c) => {
  const data = await form(c);
  if (!data) return csrfFail(c);
  const user = c.get('user')!;
  const repo = data.repo ?? '';
  const number = Number(data.number);
  const row = await repos.byName(repo);
  if (!row?.enabled || row.user_id !== user.id || !Number.isInteger(number) || number <= 0) return c.redirect('/?m=notfound');
  await enqueue(c, { userId: user.id, repo, number, force: true });
  return c.redirect('/?m=queued');
});

app.get('/scans/:id', requireUser, async (c) => {
  const user = c.get('user')!;
  const scan = await scans.getForUser(Number(c.req.param('id')), user.id);
  if (!scan) return c.html(messagePage('없음', '검사 결과를 찾을 수 없습니다.', { user, link: { href: '/', label: '대시보드로' } }), 404);
  return c.html(scanPage(user, scan, c.get('csrf')));
});


// ---------- Threat Radar ----------
const radarBack = (c: Ctx, threatId: number | string | undefined, m: string) =>
  c.redirect(`/radar?${new URLSearchParams({ ...(threatId ? { t: String(threatId) } : {}), m })}`);

async function radarVersion(userId: number): Promise<string> {
  const list = await threats.listForUser(userId);
  return `${list.length}:${list.map((t) => `${t.id}.${t.level}.${t.updated_at}`).sort().at(-1) ?? ''}`;
}

app.get('/radar', requireUser, async (c) => {
  const user = c.get('user')!;
  const tid = Number(c.req.query('t'));
  const lv = Number(c.req.query('lv')) || 0;
  const [list, invs, state] = await Promise.all([threats.listForUser(user.id), inventories.forUser(user.id), radarState.all()]);
  const visible = list.find((t) => t.id === tid) ?? (tid ? undefined : list.find((t) => !t.dismissed && !(t.muted_until && t.muted_until > new Date().toISOString())));
  const selected = visible ? {
    threat: visible,
    signals: await signals.forThreat(visible.id),
    exposures: await exposures.forUserThreat(user.id, visible.id),
    prefs: await threatPrefs.get(user.id, visible.id),
  } : null;
  const parse = <T>(s: string | undefined, f: T): T => { try { return s ? JSON.parse(s) : f; } catch { return f; } };
  return c.html(radarPage({
    user, csrf: c.get('csrf'), list, selected, inventories: invs, lv,
    confirmPr: c.req.query('confirm') === 'pr',
    state: {
      lastRun: parse(state.last_run, null),
      today: { ...parse(state[`stats:${new Date().toISOString().slice(0, 10)}`], { collected: 0, relevant: 0 }), ignored: await ignored.countToday() },
    },
    version: `${await radarVersion(user.id)}`,
    flash: FLASH[c.req.query('m') ?? ''],
  }));
});

app.get('/radar/live', requireUser, async (c) => c.json({ version: await radarVersion(c.get('user')!.id) }));

/** 오늘 수집했지만 보호 중인 레포와 무관해서 숨긴 항목 (공개 피드 내용과 숨긴 이유만 담는다) */
app.get('/radar/ignored', requireUser, async (c) => c.json({
  items: (await ignored.today()).map((r) => ({ id: r.id, source: r.source, title: r.title, url: r.url, reason: r.reason, publishedAt: r.published_at, createdAt: r.created_at })),
}));

app.post('/radar/collect', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const last = Number(await radarState.get('manual_collect_at'));
  if (Date.now() - last < 60_000) return radarBack(c, undefined, 'busy');
  await radarState.set('manual_collect_at', String(Date.now()));
  await enqueue(c, { kind: 'collect' });
  return radarBack(c, undefined, 'collecting');
});

app.post('/radar/refresh', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  for (const r of await repos.listForUser(c.get('user')!.id)) if (r.enabled) await enqueue(c, { kind: 'inventory', repo: r.full_name });
  return radarBack(c, undefined, 'refreshing');
});

/** 이 사용자의 레포와 매칭된 위협인가 (보이지 않는 위협에 설정을 걸 수 없게) */
const userSeesThreat = async (userId: number, threatId: number) => (await exposures.forUserThreat(userId, threatId)).length > 0;

const radarAction = async (c: Ctx, threatId: number | undefined, run: () => Promise<unknown>, done: string) => {
  try {
    await run();
    return radarBack(c, threatId, done);
  } catch (err) {
    if (err instanceof RadarActionError) return radarBack(c, threatId, err.code);
    console.error('[radar]', err);
    return radarBack(c, threatId, 'ghfail');
  }
};

app.post('/radar/exposures/:id/issue', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const user = c.get('user')!;
  const e = await exposures.getForUser(Number(c.req.param('id')), user.id);
  if (!e) return radarBack(c, undefined, 'notfound');
  return radarAction(c, e.threat_id, () => createIssueFor(user.id, e.id, config.publicUrl), 'issue_done');
});

app.post('/radar/exposures/:id/pr', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const user = c.get('user')!;
  const e = await exposures.getForUser(Number(c.req.param('id')), user.id);
  if (!e) return radarBack(c, undefined, 'notfound');
  return radarAction(c, e.threat_id, () => createPrFor(user.id, e.id, config.publicUrl), 'pr_done');
});

app.post('/radar/threats/:id/issues', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const user = c.get('user')!;
  const tid = Number(c.req.param('id'));
  const rows = (await exposures.forUserThreat(user.id, tid)).filter((e) => e.status !== 'fixed' && !e.issue_url);
  if (!rows.length) return radarBack(c, tid, 'notfound');
  const firstPerRepo = [...new Map(rows.map((e) => [e.repo_full_name, e])).values()];
  return radarAction(c, tid, async () => { for (const e of firstPerRepo) await createIssueFor(user.id, e.id, config.publicUrl); }, 'issue_done');
});

app.post('/radar/threats/:id/prs', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const user = c.get('user')!;
  const tid = Number(c.req.param('id'));
  const rows = (await exposures.forUserThreat(user.id, tid)).filter((e) => e.status === 'hit' && e.fix_version && e.context !== 'lock' && !e.pr_url);
  if (!rows.length) return radarBack(c, tid, 'notfixable');
  return radarAction(c, tid, async () => { for (const e of rows) await createPrFor(user.id, e.id, config.publicUrl); }, 'pr_done');
});

const PREF_ACTIONS: Record<string, Parameters<typeof threatPrefs.set>[2] | (() => Parameters<typeof threatPrefs.set>[2])> = {
  assign: { assigned: 1 }, unassign: { assigned: 0 },
  mute: () => ({ muted_until: new Date(Date.now() + 24 * 3600_000).toISOString() }), unmute: { muted_until: null },
  dismiss: { dismissed: 1 }, undismiss: { dismissed: 0 },
};

app.post('/radar/threats/:id/pref', requireUser, async (c) => {
  if (!(await form(c))) return csrfFail(c);
  const user = c.get('user')!;
  const tid = Number(c.req.param('id'));
  const action = PREF_ACTIONS[c.req.query('do') ?? ''];
  if (!action || !(await userSeesThreat(user.id, tid))) return radarBack(c, undefined, 'notfound');
  await threatPrefs.set(user.id, tid, typeof action === 'function' ? action() : action);
  return radarBack(c, tid, 'pref');
});

app.get('/healthz', (c) => c.json({ ok: true, llm: !!config.claude.apiKey, model: config.claude.model }));

app.onError((err, c) => {
  console.error('[http]', err);
  return c.html(messagePage('오류', '서버 오류가 발생했습니다.', { hint: /환경변수/.test(err.message) ? err.message : undefined }), 500);
});

// ---------- queue consumer: PR 스캔, Threat Radar 수집·레포 읽기 (오래 걸리는 작업을 HTTP 응답과 분리) ----------
interface QueueMessage { body: QueueBody; ack(): void }

/** 수집 후 오래된 레포 목록은 레포마다 별도 메시지로 (실행당 서브리퀘스트 한도) */
async function runCollect(env: Bindings, publicUrl?: string) {
  const result = await collect();
  console.log(`[radar] 수집 ${result.collected}건, 관련 ${result.relevant}건${result.errors.length ? `, 오류: ${result.errors.join(' / ')}` : ''}`);
  for (const repo of result.staleRepos) await env.SCAN_QUEUE.send({ kind: 'inventory', repo, publicUrl });
}

export default {
  fetch: app.fetch,
  async queue(batch: { messages: QueueMessage[] }, env: Bindings) {
    for (const msg of batch.messages) {
      const body = msg.body;
      bindEnv({ ...(body.publicUrl ? { PUBLIC_URL: body.publicUrl } : {}), ...env });
      await initDb(env.DB);
      try {
        if (body.kind === 'collect') await runCollect(env, body.publicUrl);
        else if (body.kind === 'inventory') await refreshInventory(body.repo);
        else await scanPullRequest(body);
      } catch (err) {
        // 스캔 실패 상태는 scans 테이블과 commit status 에 이미 기록됨. 재시도하면 PR 코멘트가 중복되므로 ack
        console.error(`[queue] ${body.kind ?? 'scan'} 실패:`, err);
      }
      msg.ack();
    }
  },
  /** Cron Trigger: 10분마다 위협 신호 수집 */
  async scheduled(_event: unknown, env: Bindings) {
    bindEnv(env);
    await initDb(env.DB);
    await runCollect(env);
  },
};
