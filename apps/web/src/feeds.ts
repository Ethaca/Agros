import { config } from './config.ts';
import { compareVersions, parseRangeExpression, parseVersion, parseVersionList, type Interval } from './versions.ts';

/**
 * Threat Radar 수집기. 공식 API 와 공개 피드만 쓴다 (스크래핑하지 않음).
 * 공식 권고는 구조화 데이터로, 커뮤니티 글은 원문 그대로 가져와 이후 LLM 이 "데이터로만" 분류한다.
 */

export interface AffectedTarget { target: string; intervals: Interval[]; patched: string[] }

/** GHSA, OSV, 벤더 레포 권고처럼 패치 버전을 근거로 쓸 수 있는 출처 */
export interface OfficialAdvisory {
  source: 'GHSA' | 'OSV' | 'VENDOR';
  id: string;
  url: string;
  title: string;
  text: string;
  publishedAt: string;
  cves: string[];
  severity: string | null;
  affected: AffectedTarget[];
  /** 권고에 적힌 원래 생태계 이름 (pip, go 등). 매칭하지 않는 생태계라 숨겼을 때 이유로 보여준다 */
  ecosystems: string[];
}

/** 커뮤니티 글 (Hacker News) */
export interface CommunityPost {
  source: 'HN';
  id: string;
  url: string;
  author: string;
  title: string;
  text: string;
  publishedAt: string;
  /** 글이 가리키는 원 출처 도메인. 서로 다른 출처 수와 공신력 판단에 쓴다 */
  domain: string;
}

/** 공식 권고를 내는 벤더 레포. 패키지 레지스트리에 없는 런타임 자체의 취약점을 잡는다 */
export const VENDOR_REPOS: { repo: string; target: string }[] = [
  { repo: 'php/php-src', target: 'runtime:php' },
  { repo: 'nodejs/node', target: 'runtime:node' },
  { repo: 'python/cpython', target: 'runtime:python' },
];

const ECOSYSTEMS: Record<string, string> = { npm: 'npm', composer: 'composer', packagist: 'composer' };
const CVE = /CVE-\d{4}-\d{4,}/g;
const UA = { 'User-Agent': 'argos-threat-radar' };

export const cvesIn = (text: string) => [...new Set(text.match(CVE) ?? [])];

async function getJson<T>(url: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(url, { ...init, headers: { ...UA, ...init.headers }, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`${new URL(url).host} ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return (await res.json()) as T;
}

const ghHeaders = () => ({
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
  ...(config.radarGithubToken ? { Authorization: `Bearer ${config.radarGithubToken}` } : {}),
});

interface GhAdvisory {
  ghsa_id: string; cve_id: string | null; html_url: string; summary: string; description: string | null;
  severity: string | null; published_at: string;
  vulnerabilities: {
    package: { ecosystem: string; name: string } | null;
    vulnerable_version_range: string | null;
    first_patched_version?: string | { identifier: string } | null;
    patched_versions?: string | null;
  }[] | null;
}

/** GitHub 권고(전역 DB, 레포 권고 공통)를 표준 형태로. forceTarget 이 있으면 패키지 이름 대신 그 대상으로 본다 (런타임) */
export function normalizeGhAdvisory(a: GhAdvisory, source: 'GHSA' | 'VENDOR', forceTarget?: string): OfficialAdvisory {
  const byTarget = new Map<string, AffectedTarget>();
  for (const v of a.vulnerabilities ?? []) {
    const eco = ECOSYSTEMS[v.package?.ecosystem?.toLowerCase() ?? ''];
    const target = forceTarget ?? (eco && v.package?.name ? `${eco}:${v.package.name.toLowerCase()}` : null);
    if (!target) continue;
    const entry = byTarget.get(target) ?? { target, intervals: [], patched: [] };
    const first = typeof v.first_patched_version === 'string' ? v.first_patched_version : v.first_patched_version?.identifier;
    const patched = parseVersionList([first, v.patched_versions].filter(Boolean).join(','));
    entry.patched.push(...patched.filter((p) => !entry.patched.includes(p)));
    const iv = parseRangeExpression(v.vulnerable_version_range);
    if (iv) entry.intervals.push(!iv.fixed && !iv.lastAffected && patched.length === 1 ? { ...iv, fixed: patched[0] } : iv);
    byTarget.set(target, entry);
  }
  for (const entry of byTarget.values()) entry.intervals = splitBranches(entry.intervals);
  if (forceTarget && !byTarget.size) byTarget.set(forceTarget, { target: forceTarget, intervals: [], patched: [] });
  const text = `${a.summary}\n\n${a.description ?? ''}`.slice(0, 4000);
  return {
    source, id: a.ghsa_id, url: a.html_url, title: a.summary, text, publishedAt: a.published_at,
    cves: [...new Set([a.cve_id, ...cvesIn(text)].filter((c): c is string => !!c))],
    severity: a.severity, affected: [...byTarget.values()],
    ecosystems: [...new Set((a.vulnerabilities ?? []).map((v) => v.package?.ecosystem).filter((e): e is string => !!e))],
  };
}

/**
 * 런타임 권고는 브랜치마다 "< 8.2.35", "< 8.3.36" 처럼 하한 없는 범위를 따로 적는다.
 * 그대로 두면 이미 패치된 8.3.36 도 "< 8.4.27" 에 걸리므로, 가장 낮은 브랜치를 뺀 나머지는 그 브랜치의 .0 부터로 좁힌다
 */
export function splitBranches(intervals: Interval[]): Interval[] {
  const open = intervals.filter((iv) => !iv.introduced && iv.fixed && !iv.lastAffected);
  if (open.length < 2) return intervals;
  const sorted = open.map((iv) => ({ iv, v: parseVersion(iv.fixed!) })).filter((x) => x.v).sort((a, b) => compareVersions(a.v!, b.v!));
  const lowest = sorted[0].iv;
  return intervals.map((iv) => (open.includes(iv) && iv !== lowest ? { introduced: `${parseVersion(iv.fixed!)!.slice(0, 2).join('.')}.0`, ...iv } : iv));
}

/** GitHub Advisory Database 에서 since 이후 게시된 검토 완료 권고 */
export async function fetchGhsa(since: string): Promise<OfficialAdvisory[]> {
  const params = new URLSearchParams({ type: 'reviewed', sort: 'published', direction: 'desc', per_page: '100', published: `>=${since.slice(0, 10)}` });
  const list = await getJson<GhAdvisory[]>(`https://api.github.com/advisories?${params}`, { headers: ghHeaders() });
  return list.filter((a) => a.published_at > since).map((a) => normalizeGhAdvisory(a, 'GHSA'));
}

/** 벤더 레포의 공개 보안 권고 (예: php/php-src). 패치 버전이 범위 대신 브랜치별 목록으로 오는 경우가 많다 */
export async function fetchVendorAdvisories(since: string): Promise<OfficialAdvisory[]> {
  const results = await Promise.allSettled(VENDOR_REPOS.map(async ({ repo, target }) => {
    const list = await getJson<GhAdvisory[]>(`https://api.github.com/repos/${repo}/security-advisories?state=published&sort=published&direction=desc&per_page=20`, { headers: ghHeaders() });
    return list.filter((a) => a.published_at > since).map((a) => normalizeGhAdvisory(a, 'VENDOR', target));
  }));
  results.filter((r) => r.status === 'rejected').forEach((r) => console.warn('[radar] 벤더 권고 수집 실패:', (r as PromiseRejectedResult).reason?.message));
  return results.flatMap((r) => (r.status === 'fulfilled' ? r.value : []));
}

interface OsvVuln {
  id: string; summary?: string; details?: string; aliases?: string[]; published: string;
  affected?: { package?: { ecosystem: string; name: string }; ranges?: { type: string; events: Record<string, string>[] }[] }[];
  database_specific?: { severity?: string };
}

export function normalizeOsv(v: OsvVuln): OfficialAdvisory {
  const byTarget = new Map<string, AffectedTarget>();
  for (const a of v.affected ?? []) {
    const eco = ECOSYSTEMS[a.package?.ecosystem?.toLowerCase() ?? ''];
    if (!eco || !a.package) continue;
    const target = `${eco}:${a.package.name.toLowerCase()}`;
    const entry = byTarget.get(target) ?? { target, intervals: [], patched: [] };
    for (const r of a.ranges ?? []) {
      if (r.type === 'GIT') continue;
      let cur: Interval | null = null;
      for (const e of r.events) {
        if (e.introduced !== undefined) cur = { introduced: e.introduced };
        else if (cur && (e.fixed || e.last_affected)) {
          entry.intervals.push(e.fixed ? { ...cur, fixed: e.fixed } : { ...cur, lastAffected: e.last_affected });
          if (e.fixed && !entry.patched.includes(e.fixed)) entry.patched.push(e.fixed);
          cur = null;
        }
      }
      if (cur) entry.intervals.push(cur);
    }
    byTarget.set(target, entry);
  }
  const ghsa = [v.id, ...(v.aliases ?? [])].find((x) => x.startsWith('GHSA-'));
  const text = `${v.summary ?? ''}\n\n${v.details ?? ''}`.slice(0, 4000);
  return {
    source: 'OSV', id: ghsa ?? v.id, url: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`, title: v.summary ?? v.id, text,
    publishedAt: v.published, cves: [...new Set([...(v.aliases ?? []), v.id].filter((x) => /^CVE-/.test(x)))],
    severity: v.database_specific?.severity?.toLowerCase() ?? null, affected: [...byTarget.values()],
    ecosystems: [...new Set((v.affected ?? []).map((a) => a.package?.ecosystem).filter((e): e is string => !!e))],
  };
}

/** 레포가 쓰는 정확한 패키지 버전을 OSV 에 일괄 조회 → 알려진 취약점 ID */
export async function osvQueryBatch(packages: { target: string; version: string }[]): Promise<string[]> {
  const queries = packages.slice(0, 1000).map(({ target, version }) => {
    const [eco, name] = [target.slice(0, target.indexOf(':')), target.slice(target.indexOf(':') + 1)];
    return { package: { ecosystem: eco === 'composer' ? 'Packagist' : 'npm', name }, version };
  });
  if (!queries.length) return [];
  const data = await getJson<{ results: { vulns?: { id: string }[] }[] }>('https://api.osv.dev/v1/querybatch', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries }),
  });
  return [...new Set(data.results.flatMap((r) => r.vulns?.map((v) => v.id) ?? []))];
}

export const fetchOsvVuln = (id: string) => getJson<OsvVuln>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`).then(normalizeOsv);

/** CISA KEV. CVE 가 들어 있는지만 보면 되므로 JSON 을 파싱하지 않고 문자열로 찾는다 (Workers CPU 한도) */
export async function fetchKevText(): Promise<string> {
  const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { headers: UA, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`KEV ${res.status}`);
  return res.text();
}
export const kevHas = (kev: string, cve: string) => kev.includes(`"${cve}"`);

interface HnHit { objectID: string; title?: string; url?: string | null; author: string; created_at_i: number; story_text?: string | null }

const domainOf = (url: string | null | undefined) => {
  try { return url ? new URL(url).hostname.replace(/^www\./, '') : 'news.ycombinator.com'; } catch { return 'news.ycombinator.com'; }
};
const stripHtml = (s: string) => s.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/\s+/g, ' ').trim();

const hnPost = (id: string, title: string, url: string | null | undefined, author: string, time: number, text: string | null | undefined): CommunityPost => ({
  source: 'HN', id, url: `https://news.ycombinator.com/item?id=${id}`, author, title: title.slice(0, 300),
  text: stripHtml(`${url ? `링크: ${url}\n` : ''}${text ?? ''}`).slice(0, 1500), publishedAt: new Date(time * 1000).toISOString(), domain: domainOf(url),
});

/** 보안 관련 키워드가 하나라도 들어간 HN 글 (Algolia HN Search API) */
export const SECURITY_WORDS = /\b(cve-\d|rce|remote code|vulnerab|exploit|zero[- ]?day|0day|security (fix|release|advisory|patch|update)|backdoor|compromis|malicious|supply[- ]chain|poc\b)/i;

export async function fetchHackerNews(sinceUnix: number): Promise<CommunityPost[]> {
  const words = 'CVE vulnerability RCE exploit zero-day security backdoor compromised malicious';
  const params = new URLSearchParams({ tags: 'story', query: words, optionalWords: words, numericFilters: `created_at_i>${sinceUnix}`, hitsPerPage: '100' });
  const data = await getJson<{ hits: HnHit[] }>(`https://hn.algolia.com/api/v1/search_by_date?${params}`);
  return data.hits
    .filter((h) => h.title && SECURITY_WORDS.test(`${h.title} ${h.story_text ?? ''}`))
    .map((h) => hnPost(h.objectID, h.title!, h.url, h.author, h.created_at_i, h.story_text));
}
