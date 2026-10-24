import { renderToString } from 'react-dom/server';
import type { ExposureRow, InventoryRow, RepoRow, SandboxJobRow, ScanRow, SignalRow, ThreatListRow, ThreatRow, UserRow } from '../db.ts';
import type { GhRepo } from '../github.ts';
import type { Level } from '../levels.ts';
import type { AnalysisResult, SandboxView } from '../types.ts';
import { App, type PageName, type PageProps } from './app.tsx';
import { Findings } from './findings.tsx';
import type { BaseProps, FlashMessage, Viewer } from './kit.tsx';
import type { ScanSummary } from './pages.tsx';
import type { RadarDetail, RadarThreat, WatchedRepo } from './radar.tsx';

/**
 * Worker 가 부르는 화면 진입점. DB 행을 화면 props 로 옮기고, React(Headless UI) 로 HTML 을 그린다.
 * props 는 그대로 브라우저로 내려가므로(hydrate) 토큰·시크릿 같은 서버 전용 필드는 절대 넣지 않는다.
 */

const escapeHtml = (s: string) => s.replace(/[&\x3c\x3e"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** props 는 <script type="application/json"> 에 들어간다. </script> 로 빠져나오지 못하게 < 를 이스케이프 */
const serialize = (value: unknown) => {
  let out = JSON.stringify(value);
  for (const [ch, esc] of [['\x3c', '\\u003c'], ['\u2028', '\\u2028'], ['\u2029', '\\u2029']]) out = out.split(ch).join(esc);
  return out;
};

/** React 로 그린 HTML + 브라우저에서 같은 컴포넌트를 hydrate 할 데이터 */
function renderPage<K extends PageName>(name: K, props: PageProps<K>, title: string): string {
  const html = renderToString(<App name={name} props={props} />);
  return `<!doctype html><html lang="ko" class="h-full bg-gray-50"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} · Argos</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css">
<link rel="stylesheet" href="/assets/app.css"></head>
<body class="h-full"><div id="root">${html}</div><script type="application/json" id="page-data">${serialize({ name, props })}</script>
<script type="module" src="/assets/client.js"></script></body></html>`;
}

const viewer = (user?: UserRow | null): Viewer | null => (user ? { login: user.login, avatarUrl: user.avatar_url } : null);
const base = (user: UserRow | null | undefined, csrf = '', flash?: FlashMessage): BaseProps => ({ viewer: viewer(user), csrf, ...(flash ? { flash } : {}) });
const json = <T,>(s: string | null | undefined, fallback: T): T => { try { return s ? (JSON.parse(s) as T) : fallback; } catch { return fallback; } };

const scanSummary = (s: ScanRow): ScanSummary => ({
  id: s.id, repo: s.repo_full_name, prNumber: s.pr_number, prTitle: s.pr_title, headSha: s.head_sha, status: s.status, risk: s.risk, createdAt: s.created_at,
});

export function landingPage(): string {
  return renderPage('landing', base(null), 'AI 보안 내비게이터');
}

export function dashboardPage(user: UserRow, ghRepos: GhRepo[], rows: RepoRow[], recent: ScanRow[], csrf: string, flash?: FlashMessage): string {
  const enabled = new Set(rows.filter((r) => r.enabled).map((r) => r.full_name));
  const repos = [...ghRepos]
    .sort((a, b) => Number(enabled.has(b.full_name)) - Number(enabled.has(a.full_name)))
    .map((r) => ({ fullName: r.full_name, private: r.private, htmlUrl: r.html_url, enabled: enabled.has(r.full_name) }));
  return renderPage('dashboard', { ...base(user, csrf, flash), repos, recent: recent.map(scanSummary) }, '대시보드');
}

export function scanPage(user: UserRow, scan: ScanRow, csrf = '', sandbox?: SandboxJobRow | null): string {
  return renderPage('scan', {
    ...base(user, csrf), scan: { ...scanSummary(scan), error: scan.error }, result: json<AnalysisResult | null>(scan.result_json, null),
    sandbox: sandbox ? { status: sandbox.status, result: json<SandboxView['result']>(sandbox.result_json, null) } : null,
  }, `검사 #${scan.id}`);
}

export function messagePage(title: string, text: string, opts: { user?: UserRow | null; hint?: string; link?: { href: string; label: string } } = {}): string {
  return renderPage('message', { ...base(opts.user), title, text, hint: opts.hint, link: opts.link }, title);
}

/** PR 검사 결과만 HTML 로 (테스트·미리보기) */
export const renderFindings = (result: AnalysisResult) => renderToString(<Findings result={result} />);

export interface RadarSelectionRows {
  threat: ThreatRow; signals: SignalRow[]; exposures: ExposureRow[];
  prefs: { muted_until: string | null; assigned: number; dismissed: number } | null;
}

export function radarPage(opts: {
  user: UserRow; csrf: string; list: ThreatListRow[]; selected: RadarSelectionRows | null; inventories: (InventoryRow & { full_name: string })[];
  state: { lastRun: { at: string; collected: number; relevant: number; errors: string[] } | null; today: { collected: number; relevant: number; ignored: number } };
  lv: number; confirmPr: boolean; version: string; flash?: FlashMessage; now?: string;
}): string {
  const now = opts.now ?? new Date().toISOString();
  const muted = (until: string | null | undefined) => !!until && until > now;
  const threats: RadarThreat[] = opts.list.map((t) => ({
    id: t.id, target: t.target, title: t.title, level: t.level as Level, updatedAt: t.updated_at, cves: json(t.cve_ids, []),
    hits: t.hits ?? 0, maybes: t.maybes ?? 0, fixed: t.fixed ?? 0, sources: (t.sources ?? '').split(',').filter(Boolean),
    assigned: !!t.assigned, muted: muted(t.muted_until), dismissed: !!t.dismissed,
  }));
  const sel = opts.selected;
  const selected: RadarDetail | null = sel && {
    id: sel.threat.id, target: sel.threat.target, title: sel.threat.title, summary: sel.threat.summary, level: sel.threat.level as Level,
    kev: !!sel.threat.kev, severity: sel.threat.severity, cves: json(sel.threat.cve_ids, []), patched: json(sel.threat.patched_json, []),
    firstSeenAt: sel.threat.first_seen_at, officialAt: sel.threat.official_at,
    signals: sel.signals.map((s) => ({
      id: s.id, source: s.source, author: s.author, domain: s.domain, title: s.title, url: s.url, verdict: s.verdict,
      official: s.official, trusted: s.trusted, exploited: s.exploited, publishedAt: s.published_at,
    })),
    exposures: sel.exposures.map((e) => ({
      id: e.id, repo: e.repo_full_name, file: e.file, line: e.line, snippet: e.snippet, spec: e.spec, context: e.context, status: e.status,
      reason: e.reason, fixVersion: e.fix_version, issueNumber: e.issue_number, issueUrl: e.issue_url, prNumber: e.pr_number, prUrl: e.pr_url,
    })),
    prefs: { mutedUntil: sel.prefs?.muted_until ?? null, muted: muted(sel.prefs?.muted_until), assigned: !!sel.prefs?.assigned, dismissed: !!sel.prefs?.dismissed },
  };
  const repos: WatchedRepo[] = opts.inventories.map((i) => ({
    name: i.full_name, components: i.components_json ? json<unknown[]>(i.components_json, []).length : null, fetchedAt: i.fetched_at, error: i.error,
  }));
  return renderPage('radar', {
    ...base(opts.user, opts.csrf, opts.flash), threats, selected, repos, lastRun: opts.state.lastRun, today: opts.state.today,
    initialLevel: opts.lv, openPrDialog: opts.confirmPr, version: opts.version,
  }, 'Threat Radar');
}
