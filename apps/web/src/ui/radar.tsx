import { AlertDialog } from '@base-ui/react/alert-dialog';
import { Combobox } from '@base-ui/react/combobox';
import { Dialog } from '@base-ui/react/dialog';
import { Field } from '@base-ui/react/field';
import { Menu } from '@base-ui/react/menu';
import { Radio } from '@base-ui/react/radio';
import { RadioGroup } from '@base-ui/react/radio-group';
import { Separator } from '@base-ui/react/separator';
import { Tabs } from '@base-ui/react/tabs';
import { Toast } from '@base-ui/react/toast';
import { Toggle } from '@base-ui/react/toggle';
import { ToggleGroup } from '@base-ui/react/toggle-group';
import {
  ArrowPathIcon, ArrowUpCircleIcon, BellSlashIcon, BugAntIcon, BuildingOffice2Icon, CircleStackIcon, ChatBubbleLeftEllipsisIcon, CheckIcon, EllipsisHorizontalIcon, FireIcon,
  LockClosedIcon, MagnifyingGlassIcon, ShieldCheckIcon, SignalIcon, UserCircleIcon, XMarkIcon,
} from '@heroicons/react/16/solid';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { ACTION_MIN_LEVEL, computeLevel, LEVELS, type Level } from '../levels.ts';
import { Fold } from './findings.tsx';
import { BACKDROP, Badge, Btn, btnClass, Card, CardHeader, cx, DIALOG, FOCUS, Hint, INPUT, ITEM, POPUP, PostForm, Shell, submitForm, type BaseProps, type Tone } from './kit.tsx';

export interface RadarThreat {
  id: number; target: string; title: string; level: Level; updatedAt: string; cves: string[];
  hits: number; maybes: number; fixed: number; sources: string[]; assigned: boolean; muted: boolean; dismissed: boolean;
}
export interface RadarSignal {
  id: number; source: string; author: string | null; domain: string | null; title: string; url: string; verdict: string | null;
  official: number; trusted: number; exploited: number; publishedAt: string;
}
export interface RadarExposure {
  id: number; repo: string; file: string; line: number; snippet: string; spec: string; context: string; status: 'hit' | 'maybe' | 'fixed';
  reason: string; fixVersion: string | null; issueNumber: number | null; issueUrl: string | null; prNumber: number | null; prUrl: string | null;
}
export interface RadarDetail {
  id: number; target: string; title: string; summary: string | null; level: Level; kev: boolean; severity: string | null; cves: string[];
  patched: string[]; firstSeenAt: string; officialAt: string | null; signals: RadarSignal[]; exposures: RadarExposure[];
  prefs: { mutedUntil: string | null; muted: boolean; assigned: boolean; dismissed: boolean };
}
export interface WatchedRepo { name: string; components: number | null; fetchedAt: string | null; error: string | null }
export interface RadarProps extends BaseProps {
  threats: RadarThreat[]; selected: RadarDetail | null; repos: WatchedRepo[];
  lastRun: { at: string; collected: number; relevant: number; errors: string[] } | null; today: { collected: number; relevant: number; ignored: number };
  initialLevel: number; openPrDialog: boolean; version: string;
}

const LV_TONE: Record<Level, Tone> = { 1: 'yellow', 2: 'orange', 3: 'green', 4: 'red' };
const LV_TEXT: Record<Level, string> = { 1: 'text-yellow-600', 2: 'text-orange-600', 3: 'text-green-600', 4: 'text-red-600' };
const LV_BAR: Record<Level, string> = { 1: 'bg-yellow-500', 2: 'bg-orange-500', 3: 'bg-green-500', 4: 'bg-red-500' };
const SHORT: Record<number, string> = { 0: '전체', 1: 'L1 소문', 2: 'L2 교차', 3: 'L3 공식', 4: 'L4 악용' };
const STATUS: Record<RadarExposure['status'], { label: string; tone: Tone }> = {
  hit: { label: '영향', tone: 'red' }, maybe: { label: '영향 가능', tone: 'yellow' }, fixed: { label: '해결됨', tone: 'green' },
};

const fmt = (s: string | null | undefined) => (s ?? '').slice(0, 16).replace('T', ' ');
const targetName = (t: string) => {
  const [eco, name] = [t.slice(0, t.indexOf(':')), t.slice(t.indexOf(':') + 1)];
  return eco === 'runtime' ? `${name} 런타임` : `${name} (${eco})`;
};

export function LevelPill({ level }: { level: Level }) {
  return <Badge tone={LV_TONE[level]}>{LEVELS[level].name}</Badge>;
}

// ---------- 숨긴 항목 ----------

interface IgnoredItem { id: number; source: string; title: string; url: string; reason: string; publishedAt: string | null; createdAt: string }

const SOURCE_NAME: Record<string, string> = { GHSA: 'GitHub Advisory', VENDOR: '벤더 권고', OSV: 'OSV', HN: 'Hacker News' };

const GitHubMark = ({ className }: { className?: string }) => (
  <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className={className}>
    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
  </svg>
);

/** 출처별 작은 아이콘. 이름은 title 과 스크린리더용 텍스트로 남긴다 */
export function SourceIcon({ source, className }: { source: string; className?: string }) {
  const box = cx('inline-grid size-4 flex-none place-items-center rounded-sm', className);
  const name = SOURCE_NAME[source] ?? source;
  const inner = source === 'HN' ? <span aria-hidden="true" className="text-[10px] leading-none font-bold">Y</span>
    : source === 'GHSA' ? <GitHubMark className="size-3" />
      : source === 'VENDOR' ? <BuildingOffice2Icon aria-hidden="true" className="size-3" />
        : source === 'OSV' ? <CircleStackIcon aria-hidden="true" className="size-3" />
          : <span aria-hidden="true" className="text-[9px] leading-none font-bold">{source.slice(0, 1)}</span>;
  const tone = source === 'HN' ? 'bg-orange-500 text-white' : source === 'GHSA' ? 'bg-gray-900 text-white'
    : source === 'OSV' ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700';
  return <span title={name} className={cx(box, tone)}>{inner}<span className="sr-only">{name}</span></span>;
}

/** "레포와 무관해서 숨김" 을 누르면 오늘 숨긴 항목과 이유를 보여준다. 목록은 열 때 불러온다 */
function IgnoredDialog({ count }: { count: number }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<IgnoredItem[] | null>(null);
  const [failed, setFailed] = useState(false);
  const [source, setSource] = useState<string[]>([]);
  const [query, setQuery] = useState('');
  useEffect(() => {
    if (!open || items) return;
    setFailed(false);
    fetch('/radar/ignored', { headers: { accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((d: { items: IgnoredItem[] }) => setItems(d.items))
      .catch(() => setFailed(true));
  }, [open, items]);
  const sources = useMemo(() => {
    const n = new Map<string, number>();
    (items ?? []).forEach((i) => n.set(i.source, (n.get(i.source) ?? 0) + 1));
    return [...n.entries()];
  }, [items]);
  const shown = (items ?? []).filter((i) => (!source.length || source.includes(i.source))
    && (!query.trim() || `${i.title} ${i.reason}`.toLowerCase().includes(query.trim().toLowerCase())));
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger className={cx('rounded text-sm text-gray-500 underline decoration-gray-300 decoration-dotted underline-offset-4 hover:text-gray-900 hover:decoration-gray-900', FOCUS)}>
        레포와 무관해서 숨김 <b className="font-medium text-gray-900 tabular-nums">{count.toLocaleString('en-US')}</b>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Backdrop className={BACKDROP} />
        <Dialog.Popup className={cx(DIALOG, 'flex max-h-[min(44rem,calc(100dvh-4rem))] w-[min(48rem,calc(100vw-2rem))] flex-col p-0!')}>
          <div className="flex items-start justify-between gap-4 border-b border-gray-200 px-6 py-5">
            <div>
              <Dialog.Title className="text-base font-semibold">오늘 숨긴 항목</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm leading-6 text-gray-600">수집했지만 보호 중인 레포의 패키지·런타임과 맞지 않아 위협으로 만들지 않은 항목입니다. 3일 동안 보관합니다.</Dialog.Description>
            </div>
            <Dialog.Close aria-label="닫기" className={cx('-m-1 rounded-md p-1.5 text-gray-500 hover:bg-gray-100 hover:text-gray-900', FOCUS)}>
              <XMarkIcon aria-hidden="true" className="size-4" />
            </Dialog.Close>
          </div>
          {items && items.length > 0 && (
            <div className="flex flex-wrap items-center gap-3 border-b border-gray-200 px-6 py-3">
              <ToggleGroup value={source} onValueChange={setSource} multiple aria-label="출처로 거르기" className="flex flex-wrap gap-1">
                {sources.map(([s, n]) => (
                  <Toggle key={s} value={s} className={cx('h-7 rounded-md border border-gray-200 px-2.5 text-xs text-gray-700 select-none hover:bg-gray-50 data-pressed:border-gray-900 data-pressed:bg-gray-900 data-pressed:text-white', FOCUS)}>
                    <span className="inline-flex items-center gap-1.5"><SourceIcon source={s} />{SOURCE_NAME[s] ?? s} <span className="tabular-nums opacity-70">{n}</span></span>
                  </Toggle>
                ))}
              </ToggleGroup>
              <Field.Root className="relative ml-auto w-full sm:w-56">
                <Field.Label className="sr-only">숨긴 항목 검색</Field.Label>
                <MagnifyingGlassIcon aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-gray-400" />
                <Field.Control value={query} onChange={(e) => setQuery(e.target.value)} placeholder="제목·이유로 찾기" className={cx(INPUT, 'h-8 pl-8')} />
              </Field.Root>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-y-auto">
            {failed ? <p className="px-6 py-10 text-center text-sm text-red-600">목록을 불러오지 못했습니다. 다시 열어 주세요.</p>
              : !items ? <p className="flex items-center justify-center gap-2 px-6 py-10 text-sm text-gray-500"><ArrowPathIcon aria-hidden="true" className="size-3.5 animate-spin" />불러오는 중…</p>
                : !shown.length ? <p className="px-6 py-10 text-center text-sm text-gray-500">{items.length ? '조건에 맞는 항목이 없습니다.' : '오늘 숨긴 항목이 없습니다.'}</p>
                  : (
                    <ul className="divide-y divide-gray-200">
                      {shown.map((i) => (
                        <li key={i.id} className="px-6 py-3">
                          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
                            <span className="inline-flex items-center gap-1.5 font-medium text-gray-900"><SourceIcon source={i.source} />{SOURCE_NAME[i.source] ?? i.source}</span>
                            <time className="ml-auto tabular-nums">{fmt(i.publishedAt ?? i.createdAt)}</time>
                          </div>
                          <a href={i.url} target="_blank" rel="noopener noreferrer" className="mt-1 block text-sm text-gray-900 underline decoration-gray-300 underline-offset-4 hover:decoration-gray-900 [overflow-wrap:anywhere]">{i.title}</a>
                          <p className="mt-1 text-xs text-gray-600">{i.reason}</p>
                        </li>
                      ))}
                    </ul>
                  )}
          </div>
          {items && items.length > 0 && <p className="border-t border-gray-200 px-6 py-3 text-xs text-gray-500">{shown.length} / {items.length}건 표시</p>}
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ---------- 상단 실시간 상태줄 ----------

function useCountdown() {
  const [left, setLeft] = useState<number | null>(null);
  useEffect(() => {
    const tick = () => setLeft(600 - (Math.floor(Date.now() / 1000) % 600));
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);
  return left === null ? '--:--' : `${String(Math.floor(left / 60)).padStart(2, '0')}:${String(left % 60).padStart(2, '0')}`;
}

/** 30초마다 새 신호가 있는지 확인하고, 있으면 토스트로 새로고침을 권한다 (화면을 갈아엎지 않음) */
function useFreshness(version: string) {
  const toast = Toast.useToastManager();
  useEffect(() => {
    let notified = false;
    const t = setInterval(async () => {
      if (notified) return;
      try {
        const r = await fetch('/radar/live', { headers: { accept: 'application/json' } });
        if (r.ok && (await r.json()).version !== version) {
          notified = true;
          toast.add({ title: '새 신호가 들어왔습니다', description: '새로고침하면 최신 위협을 볼 수 있습니다.', timeout: 0, actionProps: { children: '새로고침', onClick: () => location.reload() } });
        }
      } catch { /* 다음 주기에 다시 */ }
    }, 30_000);
    return () => clearInterval(t);
  }, [version, toast]);
}

function LiveStrip({ lastRun, today, version }: Pick<RadarProps, 'lastRun' | 'today' | 'version'>) {
  const next = useCountdown();
  useFreshness(version);
  const errors = lastRun?.errors ?? [];
  const stat = (label: string, value: ReactNode) => (
    <span className="text-sm text-gray-500">{label} <b className="font-medium text-gray-900 tabular-nums">{value}</b></span>
  );
  return (
    <div className="mb-6 flex flex-wrap items-center gap-x-6 gap-y-3 border-y border-gray-200 py-3">
      <span title={errors.join('\n')} className="inline-flex items-center gap-2 text-sm font-medium text-gray-900">
        <span className="relative flex size-2">
          <span className={cx('absolute inline-flex size-full rounded-full opacity-75 motion-safe:animate-ping', errors.length ? 'bg-yellow-400' : 'bg-green-400')} />
          <span className={cx('relative inline-flex size-2 rounded-full', errors.length ? 'bg-yellow-500' : 'bg-green-500')} />
        </span>
        {errors.length ? `실시간 · 출처 ${errors.length}곳 오류` : '실시간 감시 중'}
      </span>
      {stat('마지막 수집', lastRun ? `${fmt(lastRun.at)} UTC` : '아직 없음')}
      {stat('다음 수집', next)}
      {stat('오늘 수집', today.collected.toLocaleString('en-US'))}
      <IgnoredDialog count={today.ignored} />
      <div className="ml-auto flex flex-wrap gap-2">
        <PostForm action="/radar/collect"><Btn type="submit" variant="primary"><ArrowPathIcon aria-hidden="true" className="size-3.5" />지금 수집</Btn></PostForm>
      </div>
    </div>
  );
}

// ---------- 왼쪽: 필터, 찾기, 위협 목록 ----------

function LevelFilter({ value, onChange, counts }: { value: number; onChange: (v: number) => void; counts: Record<number, number> }) {
  return (
    <RadioGroup value={value} onValueChange={(v) => onChange(v as number)} aria-label="신뢰도 단계로 거르기" className="grid grid-cols-5 gap-1.5">
      {[0, 4, 3, 2, 1].map((l) => (
        <Radio.Root key={l} value={l}
          className={cx('rounded-md border border-gray-200 bg-white px-2 py-1.5 text-center hover:bg-gray-50 data-checked:border-gray-900 data-checked:bg-gray-50', FOCUS)}>
          <span className={cx('block text-lg font-semibold tabular-nums', l ? LV_TEXT[l as Level] : 'text-gray-900')}>{l ? counts[l] ?? 0 : Object.values(counts).reduce((a, b) => a + b, 0)}</span>
          <span className="block truncate text-[11px] text-gray-500" title={l ? LEVELS[l as Level].name : undefined}>{SHORT[l]}</span>
        </Radio.Root>
      ))}
    </RadioGroup>
  );
}

function ThreatFinder({ threats }: { threats: RadarThreat[] }) {
  return (
    <Combobox.Root items={threats} itemToStringLabel={(t: RadarThreat) => `${t.title} ${t.target} ${t.cves.join(' ')}`}
      onValueChange={(t) => { if (t) location.href = `/radar?t=${(t as RadarThreat).id}`; }}>
      <div className="relative">
        <MagnifyingGlassIcon aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-gray-400" />
        <Combobox.Input aria-label="위협 찾기" placeholder="패키지, CVE, 제목으로 찾기" className={cx(INPUT, 'pl-8')} />
      </div>
      <Combobox.Portal>
        <Combobox.Positioner sideOffset={6} className="z-50 outline-none">
          <Combobox.Popup className={cx(POPUP, 'max-h-80 w-(--anchor-width) overflow-y-auto py-1')}>
            <Combobox.Empty className="px-4 py-2 text-sm text-gray-500 empty:m-0 empty:p-0">찾는 위협이 없습니다.</Combobox.Empty>
            <Combobox.List>
              {(t: RadarThreat) => (
                <Combobox.Item key={t.id} value={t} className={cx(ITEM, 'pr-4')}>
                  <LevelPill level={t.level} /><span className="truncate">{t.title}</span>
                </Combobox.Item>
              )}
            </Combobox.List>
          </Combobox.Popup>
        </Combobox.Positioner>
      </Combobox.Portal>
    </Combobox.Root>
  );
}

function ThreatCard({ t, selected }: { t: RadarThreat; selected: boolean }) {
  const quiet = t.muted || t.dismissed;
  return (
    <a href={`/radar?t=${t.id}`} aria-current={selected ? 'true' : undefined}
      className={cx('relative block overflow-hidden rounded-md border bg-white py-3 pr-3.5 pl-4', FOCUS,
        selected ? 'border-gray-900' : 'border-gray-200 hover:bg-gray-50', quiet && 'opacity-55')}>
      <span aria-hidden="true" className={cx('absolute inset-y-0 left-0 w-0.75', LV_BAR[t.level])} />
      <div className="flex flex-wrap items-center gap-1.5">
        <LevelPill level={t.level} />
        {t.level === 4 && <Badge tone="red">고정</Badge>}
        {t.assigned && <Badge tone="blue">내 담당</Badge>}
        {quiet && <Badge>{t.dismissed ? '오탐' : '음소거'}</Badge>}
        <time className="ml-auto text-xs text-gray-400 tabular-nums">{fmt(t.updatedAt)}</time>
      </div>
      <p className="mt-2 text-sm leading-5 font-medium text-gray-900 [overflow-wrap:anywhere]">{t.title}</p>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
        <span>{targetName(t.target)}</span>
        {t.hits > 0 && <span className="font-medium text-red-600">영향 {t.hits}</span>}
        {t.maybes > 0 && <span>영향 가능 {t.maybes}</span>}
        {!t.hits && !t.maybes && t.fixed > 0 && <span className="text-green-600">모두 해결됨</span>}
        <span className="ml-auto flex items-center gap-1">{t.sources.map((src) => <SourceIcon key={src} source={src} />)}</span>
      </div>
    </a>
  );
}

function WatchedRepos({ repos }: { repos: WatchedRepo[] }) {
  if (!repos.length) return null;
  return (
    <Card className="px-4 py-2.5">
      <Fold defaultOpen summary={<span className="font-medium text-gray-900">감시 중인 레포 {repos.length}</span>}>
        <ul className="divide-y divide-gray-200">
          {repos.map((r) => (
            <li key={r.name} className="flex items-center gap-2 py-2 text-sm">
              <span className="min-w-0 flex-1 truncate text-gray-900">{r.name}</span>
              {r.error ? <Hint label={r.error}><Badge tone="red">읽기 실패</Badge></Hint>
                : r.fetchedAt ? <span className="text-xs text-gray-500">{r.components}개 · {fmt(r.fetchedAt).slice(5)}</span>
                  : <Badge tone="blue">읽는 중</Badge>}
            </li>
          ))}
        </ul>
        <PostForm action="/radar/refresh" className="mt-2"><Btn type="submit" size="sm"><ArrowPathIcon aria-hidden="true" className="size-3" />레포 다시 읽기</Btn></PostForm>
      </Fold>
    </Card>
  );
}

// ---------- 오른쪽: 선택한 위협 ----------

const NEXT_HINT: Record<Level, string> = {
  1: '다른 출처나 공신력 있는 출처에서 같은 대상이 확인되면 L2 로 올라갑니다.',
  2: '공식 권고(GHSA, OSV, 벤더)가 게시되면 L3 로 올라가 PR 초안을 만들 수 있습니다.',
  3: 'CISA KEV 등재나 독립된 악용 보고 2건이 확인되면 L4 로 올라갑니다.',
  4: '가장 높은 단계입니다. 영향받는 레포부터 대응하세요.',
};

function Ladder({ level }: { level: Level }) {
  return (
    <Card>
      <CardHeader title="신뢰도" description={NEXT_HINT[level]} />
      <ol aria-label="신뢰도 단계" className="grid gap-px overflow-hidden rounded-b-lg bg-gray-200 md:grid-cols-4">
        {([1, 2, 3, 4] as Level[]).map((n) => (
          <li key={n} aria-current={n === level ? 'step' : undefined} className={cx('grid content-start gap-1 bg-white px-5 py-4', n > level && 'text-gray-400')}>
            <span className="flex items-center gap-2">
              <span className={cx('grid size-5 place-items-center rounded-full text-[11px] font-semibold',
                n < level ? 'bg-gray-900 text-white' : n === level ? 'bg-gray-900 text-white ring-4 ring-gray-200' : 'border border-gray-300 text-gray-400')}>
                {n < level ? <CheckIcon aria-hidden="true" className="size-3" /> : n}
              </span>
              <span className={cx('text-sm font-medium', n <= level ? 'text-gray-900' : 'text-gray-400')}>{LEVELS[n].name}</span>
            </span>
            <span className={cx('text-xs leading-5', n <= level ? 'text-gray-600' : 'text-gray-400')}>{LEVELS[n].cond}</span>
            <span className={cx('text-xs font-medium', n <= level ? 'text-gray-900' : 'text-gray-400')}>{LEVELS[n].unlocks}</span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function ActionTile({ icon: Icon, title, sub, locked, done, hot, onClick }: {
  icon: typeof BugAntIcon; title: string; sub: string; locked?: number; done?: boolean; hot?: boolean; onClick?: () => void;
}) {
  const disabled = !!locked || !!done;
  const ShownIcon = locked ? LockClosedIcon : done ? CheckIcon : Icon;
  const tile = (
    <button type="button" onClick={onClick} disabled={disabled}
      className={cx('flex w-full items-start gap-3 rounded-md border border-gray-200 bg-white p-3.5 text-left hover:bg-gray-50 disabled:cursor-not-allowed disabled:hover:bg-white', FOCUS)}>
      <span className={cx('grid size-8 flex-none place-items-center rounded-md',
        locked ? 'bg-gray-100 text-gray-400' : done ? 'bg-green-50 text-green-600' : hot ? 'bg-red-50 text-red-600' : 'bg-gray-900 text-white')}>
        <ShownIcon aria-hidden="true" className="size-4" />
      </span>
      <span className="min-w-0">
        <span className={cx('block text-sm font-medium', disabled ? 'text-gray-500' : 'text-gray-900')}>{title}</span>
        <span className="mt-0.5 block text-xs leading-5 text-gray-500">{sub}</span>
      </span>
    </button>
  );
  return locked ? <Hint label={`${LEVELS[locked as Level].name} 부터 가능합니다`}>{tile}</Hint> : tile;
}

function PrDialog({ open, onOpenChange, threatId, rows }: { open: boolean; onOpenChange: (o: boolean) => void; threatId: number; rows: RadarExposure[] }) {
  const [pending, setPending] = useState(false);
  return (
    <AlertDialog.Root open={open} onOpenChange={(o) => { if (!pending) onOpenChange(o); }}>
      <AlertDialog.Portal>
        <AlertDialog.Backdrop className={BACKDROP} />
        <AlertDialog.Popup className={cx(DIALOG, 'w-[min(40rem,calc(100vw-2rem))]')}>
          <AlertDialog.Title className="flex items-center gap-2 text-base font-semibold"><ArrowUpCircleIcon aria-hidden="true" className="size-4" />버전업 PR 초안 {rows.length}건을 만들까요?</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm leading-6 text-gray-600">변경은 공식 권고의 패치 버전에서만 가져오고, 머지는 하지 않습니다. 머지 전에 스테이징에서 확인하세요.</AlertDialog.Description>
          <div className="mt-4 grid max-h-[50vh] gap-3 overflow-y-auto">
            {rows.map((e) => (
              <div key={e.id}>
                <div className="mb-1 text-xs text-gray-600">{e.repo} · <span className="font-mono">{e.file}:{e.line}</span></div>
                <pre className="m-0"><span className="block bg-red-50 text-red-800">- {e.snippet}</span><span className="block bg-green-50 text-green-800">+ {e.snippet.replace(e.spec, e.fixVersion!)}</span></pre>
              </div>
            ))}
          </div>
          <PostForm action={`/radar/threats/${threatId}/prs`} onSubmit={() => setPending(true)} className="mt-6 flex justify-end gap-2">
            <AlertDialog.Close className={btnClass()} disabled={pending}>취소</AlertDialog.Close>
            <Btn type="submit" variant="primary" disabled={pending}>
              {pending && <ArrowPathIcon aria-hidden="true" className="size-3.5 animate-spin" />}{pending ? '만드는 중…' : 'PR 초안 만들기'}
            </Btn>
          </PostForm>
        </AlertDialog.Popup>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}

const TD = 'px-5 py-3.5 align-top';

function ExposureTable({ rows, level }: { rows: RadarExposure[]; level: Level }) {
  if (!rows.length) return <p className="px-5 py-10 text-center text-sm text-gray-500">보호 중인 레포에서 영향받는 위치가 없습니다.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50"><tr>
          {['레포 · 위치', '상태', '판단 근거', '조치'].map((h) => <th key={h} className="px-5 py-2.5 text-left text-xs font-medium whitespace-nowrap text-gray-500">{h}</th>)}
        </tr></thead>
        <tbody className="divide-y divide-gray-200">
          {rows.map((e) => {
            const prOk = level >= ACTION_MIN_LEVEL.pr && e.status === 'hit' && !!e.fixVersion && e.context !== 'lock';
            const prWhy = level < ACTION_MIN_LEVEL.pr ? 'L3 공식부터 가능합니다' : e.context === 'lock' ? 'lock 파일은 패키지 매니저로 갱신해야 합니다' : '공식 패치 버전이 없거나 버전을 확정할 수 없습니다';
            return (
              <tr key={e.id}>
                <td className={TD}>
                  <div className="font-medium text-gray-900 [overflow-wrap:anywhere]">{e.repo}</div>
                  <a href={`https://github.com/${e.repo}/blob/HEAD/${e.file}#L${e.line}`} target="_blank" rel="noopener" className="text-xs text-gray-600 underline decoration-gray-300 underline-offset-2 hover:decoration-gray-900">{e.file}:{e.line}</a>
                  <div className="mt-1 font-mono text-xs text-gray-500 [overflow-wrap:anywhere]">{e.snippet}</div>
                </td>
                <td className={TD}><Badge tone={STATUS[e.status].tone}>{STATUS[e.status].label}</Badge></td>
                <td className={cx(TD, 'max-w-md text-gray-600')}>{e.reason}</td>
                <td className={TD}>
                  {e.status === 'fixed' ? <span className="text-xs text-gray-400">조치 불필요</span> : (
                    <div className="flex flex-col items-start gap-1.5">
                      {e.issueUrl
                        ? <a href={e.issueUrl} target="_blank" rel="noopener"><Badge tone="green">Issue #{e.issueNumber}</Badge></a>
                        : <Hint label={level < ACTION_MIN_LEVEL.issue ? 'L2 교차 확인부터 가능합니다' : undefined}>
                          <PostForm action={`/radar/exposures/${e.id}/issue`}><Btn type="submit" size="sm" disabled={level < ACTION_MIN_LEVEL.issue}>Issue</Btn></PostForm>
                        </Hint>}
                      {e.prUrl
                        ? <a href={e.prUrl} target="_blank" rel="noopener"><Badge tone="green">PR #{e.prNumber} 초안</Badge></a>
                        : <Hint label={prOk ? undefined : prWhy}>
                          <PostForm action={`/radar/exposures/${e.id}/pr`}><Btn type="submit" size="sm" disabled={!prOk}>PR 초안</Btn></PostForm>
                        </Hint>}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Timeline({ signals, kev }: { signals: RadarSignal[]; kev: boolean }) {
  // 신호가 하나씩 쌓일 때 단계가 어떻게 올라갔는지 표시
  const levels = signals.map((_, i) => computeLevel(signals.slice(0, i + 1), false));
  const items = signals.map((s, i) => ({ s, level: levels[i], raised: !i || levels[i] > levels[i - 1] })).reverse();
  const Icon = ({ s }: { s: RadarSignal }) => {
    const [I, cls] = s.exploited ? [FireIcon, 'text-red-600'] : s.official ? [ShieldCheckIcon, 'text-green-600'] : [ChatBubbleLeftEllipsisIcon, 'text-gray-500'];
    return <span className="relative z-10 grid size-7 flex-none place-items-center rounded-full border border-gray-200 bg-white"><I aria-hidden="true" className={cx('size-3.5', cls)} /></span>;
  };
  return (
    <ol className="relative px-5 py-5 before:absolute before:top-8 before:bottom-8 before:left-[2.05rem] before:w-px before:bg-gray-200">
      {kev && (
        <li className="relative flex gap-3 pb-6">
          <span className="relative z-10 grid size-7 flex-none place-items-center rounded-full bg-red-600"><FireIcon aria-hidden="true" className="size-3.5 text-white" /></span>
          <div className="pt-1 text-sm"><span className="font-medium">CISA</span> Known Exploited Vulnerabilities 카탈로그에 등재됨 <Badge tone="red" className="ml-1">→ {LEVELS[4].name}</Badge></div>
        </li>
      )}
      {items.map(({ s, level, raised }) => (
        <li key={s.id} className="relative flex gap-3 pb-6 last:pb-0">
          <Icon s={s} />
          <div className="min-w-0 flex-1 pt-0.5">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
              <span className="inline-flex items-center gap-1.5 font-medium text-gray-900"><SourceIcon source={s.source} />{SOURCE_NAME[s.source] ?? s.source}</span>
              <span>{s.author ?? s.domain}</span>
              {raised && <Badge tone={LV_TONE[level]}>→ {LEVELS[level].name}</Badge>}
              {s.trusted && !s.official ? <Badge tone="blue">공신력</Badge> : null}
              {s.exploited ? <Badge tone="red">악용 보고</Badge> : null}
              <time className="ml-auto whitespace-nowrap tabular-nums">{fmt(s.publishedAt).slice(5)}</time>
            </div>
            <a href={s.url} target="_blank" rel="noopener noreferrer" className="mt-1 block text-sm text-gray-900 underline decoration-gray-300 underline-offset-4 hover:decoration-gray-900 [overflow-wrap:anywhere]">{s.title}</a>
            {s.verdict && <p className="mt-1 text-xs text-gray-500">{s.official ? '공식' : 'LLM 판정'} · {s.verdict}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}

function ThreatDetail({ t, openPrDialog }: { t: RadarDetail; openPrDialog: boolean }) {
  const open = t.exposures.filter((e) => e.status !== 'fixed');
  const needIssue = [...new Set(open.filter((e) => !e.issueUrl).map((e) => e.repo))];
  const prable = open.filter((e) => e.status === 'hit' && e.fixVersion && e.context !== 'lock' && !e.prUrl);
  const [prOpen, setPrOpen] = useState(openPrDialog && prable.length > 0 && t.level >= ACTION_MIN_LEVEL.pr);
  const base = `/radar/threats/${t.id}`;
  const pref = (action: string) => `${base}/pref?do=${action}`;
  const forms = {
    assign: pref(t.prefs.assigned ? 'unassign' : 'assign'),
    mute: pref(t.prefs.muted ? 'unmute' : 'mute'),
    dismiss: pref(t.prefs.dismissed ? 'undismiss' : 'dismiss'),
  };
  const facts: [string, ReactNode][] = [
    ['대상', targetName(t.target)],
    ['식별자', t.cves.length ? t.cves.join(', ') : '없음'],
    ['심각도', t.severity ?? '미정'],
    ['패치 버전', t.patched.length ? t.patched.join(' / ') : '미확인'],
    ['첫 감지', `${fmt(t.firstSeenAt)} UTC`],
    ['공식 확인', t.officialAt ? `${fmt(t.officialAt)} UTC` : '아직 없음'],
  ];
  const TAB = cx('relative z-10 flex h-10 items-center gap-2 px-1 text-sm font-medium text-gray-500 select-none hover:text-gray-900 data-active:text-gray-900', FOCUS);
  const count = (n: number) => <span className="rounded-full bg-gray-100 px-1.5 text-xs text-gray-700 tabular-nums">{n}</span>;
  return (
    <div className="grid min-w-0 gap-5">
      {/* 메뉴·버튼이 제출하는 폼 (메뉴 팝업은 닫히면서 사라지므로 바깥에 둔다) */}
      {Object.entries(forms).map(([k, action]) => <PostForm key={k} id={`pref-${k}`} action={action} className="hidden" />)}
      <PostForm id="issues-form" action={`${base}/issues`} className="hidden" />

      <Card>
        <div className="px-5 pt-5 pb-4">
          <div className="flex items-start justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <LevelPill level={t.level} />
              {t.kev && <Badge tone="red">CISA KEV 등재</Badge>}
              {t.prefs.assigned && <Badge tone="blue">내 담당</Badge>}
              {t.prefs.muted && <Badge>음소거 중</Badge>}
            </div>
            <Menu.Root>
              <Menu.Trigger aria-label="더 보기" className={cx('-m-1 grid size-8 place-items-center rounded-md text-gray-500 hover:bg-gray-100 hover:text-gray-900 data-popup-open:bg-gray-100', FOCUS)}>
                <EllipsisHorizontalIcon aria-hidden="true" className="size-4" />
              </Menu.Trigger>
              <Menu.Portal>
                <Menu.Positioner sideOffset={6} align="end" className="z-50 outline-none">
                  <Menu.Popup className={cx(POPUP, 'min-w-48 py-1')}>
                    <Menu.Item onClick={() => submitForm('pref-assign')} className={ITEM}>{t.prefs.assigned ? '할당 해제' : '나에게 할당'}</Menu.Item>
                    <Menu.Item onClick={() => submitForm('pref-mute')} className={ITEM}>{t.prefs.muted ? '음소거 해제' : '24시간 음소거'}</Menu.Item>
                    <Separator className="mx-4 my-1 h-px bg-gray-200" />
                    <Menu.Item onClick={() => submitForm('pref-dismiss')} className={cx(ITEM, 'text-red-600')}>{t.prefs.dismissed ? '오탐 표시 취소' : '오탐으로 표시'}</Menu.Item>
                  </Menu.Popup>
                </Menu.Positioner>
              </Menu.Portal>
            </Menu.Root>
          </div>
          <h1 className="mt-3 text-xl font-semibold tracking-tight text-balance text-gray-900">{t.title}</h1>
          {t.summary && t.summary !== t.title && (
            <Fold className="mt-2" summary="권고 요약"><p className="text-sm leading-6 whitespace-pre-wrap text-gray-600">{t.summary.slice(0, 600)}</p></Fold>
          )}
        </div>
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-b-lg border-t border-gray-200 bg-gray-200 sm:grid-cols-3">
          {facts.map(([k, v]) => (
            <div key={k} className="bg-white px-5 py-3">
              <dt className="text-xs text-gray-500">{k}</dt>
              <dd className="mt-0.5 text-sm text-gray-900 [overflow-wrap:anywhere]">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Ladder level={t.level} />

      <Card>
        <CardHeader title="대응" description="신뢰도 단계가 허용하는 조치만 열립니다. 서버에서도 다시 확인합니다." />
        <div className="grid gap-2.5 p-5 sm:grid-cols-2 xl:grid-cols-4">
          <ActionTile icon={BugAntIcon} title={needIssue.length ? `Issue 만들기 (${needIssue.length}개 레포)` : open.length ? 'Issue 모두 생성됨' : '영향 레포 없음'}
            sub={t.level < 3 ? '완화책 중심 · 영향 레포에만' : `패치 버전과 근거 링크 포함${t.level === 4 ? ' · 긴급 라벨' : ''}`}
            locked={t.level < ACTION_MIN_LEVEL.issue ? ACTION_MIN_LEVEL.issue : undefined} done={!needIssue.length} hot={t.level === 4} onClick={() => submitForm('issues-form')} />
          <ActionTile icon={ArrowUpCircleIcon} title={prable.length ? `버전업 PR 초안 ${prable.length}건` : open.some((e) => e.prUrl) ? 'PR 초안 생성됨' : 'PR 초안 대상 없음'}
            sub="공식 패치 버전으로만 · 머지는 사람이" locked={t.level < ACTION_MIN_LEVEL.pr ? ACTION_MIN_LEVEL.pr : undefined} done={!prable.length} onClick={() => setPrOpen(true)} />
          <ActionTile icon={UserCircleIcon} title={t.prefs.assigned ? '내가 담당 중' : '나에게 할당'} sub={t.prefs.assigned ? '누르면 할당 해제' : '목록에 "내 담당" 표시'} onClick={() => submitForm('pref-assign')} />
          <ActionTile icon={BellSlashIcon} title={t.prefs.muted ? '음소거 중' : '24시간 음소거'} sub={t.prefs.muted ? `${fmt(t.prefs.mutedUntil)} UTC 까지 · 누르면 해제` : '새 신호는 계속 기록합니다'} onClick={() => submitForm('pref-mute')} />
        </div>
      </Card>
      <PrDialog open={prOpen} onOpenChange={setPrOpen} threatId={t.id} rows={prable} />

      <Card className="overflow-hidden">
        <Tabs.Root defaultValue="exposures">
          <Tabs.List className="relative z-0 flex gap-6 border-b border-gray-200 px-5">
            <Tabs.Tab value="exposures" className={TAB}>영향받는 레포{count(open.length)}</Tabs.Tab>
            <Tabs.Tab value="signals" className={TAB}>신호 타임라인{count(t.signals.length + (t.kev ? 1 : 0))}</Tabs.Tab>
            <Tabs.Indicator className="absolute bottom-0 left-0 h-0.5 w-(--active-tab-width) translate-x-(--active-tab-left) bg-gray-900 transition-all duration-200 ease-in-out" />
          </Tabs.List>
          <Tabs.Panel value="exposures" keepMounted className="outline-none"><ExposureTable rows={t.exposures} level={t.level} /></Tabs.Panel>
          <Tabs.Panel value="signals" keepMounted className="outline-none">
            <Timeline signals={t.signals} kev={t.kev} />
            <p className="mx-5 mb-5 flex gap-2 rounded-md bg-gray-50 p-3 text-xs leading-5 text-gray-600">
              <ShieldCheckIcon aria-hidden="true" className="mt-0.5 size-3.5 flex-none text-gray-400" />SNS·커뮤니티 원문은 데이터로만 다룹니다. PoC 는 내려받거나 실행하지 않고, 코드 변경은 공식 권고의 패치 버전으로만 만듭니다.
            </p>
          </Tabs.Panel>
        </Tabs.Root>
      </Card>
    </div>
  );
}

// ---------- 페이지 ----------

export function Radar({ threats, selected, repos, lastRun, today, initialLevel, openPrDialog, version, ...base }: RadarProps) {
  const [level, setLevel] = useState(initialLevel);
  const counts: Record<number, number> = {};
  threats.forEach((t) => { if (!t.muted && !t.dismissed) counts[t.level] = (counts[t.level] ?? 0) + 1; });
  const shown = threats.filter((t) => !level || t.level === level).sort((a, b) => Number(a.muted || a.dismissed) - Number(b.muted || b.dismissed));
  return (
    <Shell {...base} active="radar" wide>
      <div className="mb-5">
        <h1 className="text-2xl font-semibold tracking-tight text-gray-900">Threat Radar</h1>
        <p className="mt-1 text-sm text-gray-600">공식 권고보다 먼저 퍼지는 위협을 모아, 보호 중인 레포에 영향이 있는 것만 보여줍니다.</p>
      </div>
      <LiveStrip lastRun={lastRun} today={today} version={version} />
      <div className="grid items-start gap-6 lg:grid-cols-[360px_minmax(0,1fr)]">
        <aside className="grid min-w-0 gap-3">
          <LevelFilter value={level} onChange={setLevel} counts={counts} />
          {threats.length > 0 && <ThreatFinder threats={threats} />}
          <div className="grid gap-2">
            {shown.map((t) => <ThreatCard key={t.id} t={t} selected={selected?.id === t.id} />)}
            {!shown.length && <Card className="px-4 py-6 text-center text-sm text-gray-500">{threats.length ? '이 단계의 위협이 없습니다.' : '보호 중인 레포와 관련된 위협이 아직 없습니다.'}</Card>}
          </div>
          <WatchedRepos repos={repos} />
        </aside>
        {selected ? <ThreatDetail key={selected.id} t={selected} openPrDialog={openPrDialog} /> : (
          <Card className="px-6 py-16 text-center">
            <SignalIcon aria-hidden="true" className="mx-auto size-6 text-gray-300" />
            <h2 className="mt-3 text-sm font-semibold text-gray-900">{threats.length ? '왼쪽에서 위협을 고르세요' : '감시 중입니다'}</h2>
            <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-gray-600">GitHub Advisory, PHP·Node·Python 벤더 권고, OSV, CISA KEV, Hacker News 를 10분마다 확인해 보호 중인 레포의 lock 파일, Dockerfile, 런타임 버전과 맞는 위협만 이곳에 보여줍니다.</p>
            {!repos.length && <div className="mt-6"><Btn href="/" variant="primary">레포 보호 켜기</Btn></div>}
          </Card>
        )}
      </div>
    </Shell>
  );
}
