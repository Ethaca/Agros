import { AlertDialog } from '@base-ui/react/alert-dialog';
import { Checkbox } from '@base-ui/react/checkbox';
import { Field } from '@base-ui/react/field';
import { Select } from '@base-ui/react/select';
import { Switch } from '@base-ui/react/switch';
import {
  AcademicCapIcon, ArrowPathIcon, ChatBubbleLeftRightIcon, CheckIcon, ChevronRightIcon, ChevronUpDownIcon,
  ExclamationTriangleIcon, LockClosedIcon, MagnifyingGlassIcon, MapIcon, SignalIcon,
} from '@heroicons/react/16/solid';
import { useEffect, useMemo, useState } from 'react';
import type { AnalysisResult } from '../types.ts';
import { LANG_NAMES, LANGS, type Lang } from '../i18n.ts';
import { Findings } from './findings.tsx';
import { BACKDROP, Btn, btnClass, Card, CardHeader, cx, DIALOG, FOCUS, INPUT, ITEM, LABEL, PageHeader, POPUP, PostForm, SeverityPill, Shell, submitForm, type BaseProps } from './kit.tsx';


// ---------- 랜딩 ----------

const FEATURES = [
  { icon: MapIcon, title: '보안 영향 지도', body: '변경 → 가능한 접근 → 데이터와 기능에 미치는 영향을 연결합니다. 코드 근거와 추정을 구분해 보여줍니다.' },
  { icon: SignalIcon, title: 'Threat Radar', body: 'SNS·커뮤니티에 먼저 퍼지는 위협을 공식 권고와 묶어, 내 레포의 lock 파일과 Dockerfile 에 영향이 있는지 알려줍니다.' },
  { icon: ChatBubbleLeftRightIcon, title: 'PR 에 바로 표시', body: '요약 코멘트, 인라인 리뷰, commit status 로 머지 전에 차단합니다.' },
  { icon: AcademicCapIcon, title: '고치면서 배우는 보안', body: 'AI 코드에서 놓치기 쉬운 개념, 생각해 볼 질문, 직접 검증할 체크리스트를 제공합니다.' },
];

export function Landing(props: BaseProps) {
  return (
    <Shell {...props}>
      <section className="py-16 sm:py-24">
        <a href="/auth/github" className="inline-flex items-center gap-1.5 rounded-full border border-gray-200 px-3 py-1 text-xs text-gray-700 hover:bg-gray-50">
          <span className="size-1.5 rounded-full bg-green-500" />새 기능 · Threat Radar 로 실시간 위협 대응<ChevronRightIcon aria-hidden="true" className="size-3.5 text-gray-400" />
        </a>
        <h1 className="mt-6 max-w-3xl text-4xl font-semibold tracking-tight text-balance text-gray-900 sm:text-5xl">이 변경, 누구에게 어떤 권한을 열어줄까요?</h1>
        <p className="mt-5 max-w-2xl text-lg leading-8 text-gray-600">PR의 보안 영향을 코드 근거와 함께 따라가 보세요. 무엇이 달라지고, 어떤 접근이 가능해지고, 어떻게 안전하게 구현할지 이해하며 배웁니다.</p>
        <div className="mt-8 flex flex-wrap items-center gap-3">
          <Btn href="/auth/github" variant="primary" size="lg">GitHub 로 시작하기</Btn>
        </div>
      </section>
      <dl className="grid border-t border-gray-200 sm:grid-cols-2 lg:grid-cols-4 lg:divide-x lg:divide-gray-200">
        {FEATURES.map((f) => (
          <div key={f.title} className="py-8 lg:px-6 lg:first:pl-0">
            <dt className="flex items-center gap-2 text-sm font-semibold text-gray-900"><f.icon aria-hidden="true" className="size-4" />{f.title}</dt>
            <dd className="mt-2 text-sm leading-6 text-gray-600">{f.body}</dd>
          </div>
        ))}
      </dl>
    </Shell>
  );
}

// ---------- 대시보드 ----------

export interface RepoItem { fullName: string; private: boolean; htmlUrl: string; enabled: boolean }
export interface ScanSummary { id: number; repo: string; prNumber: number; prTitle: string | null; headSha: string; status: 'running' | 'done' | 'error'; risk: string | null; createdAt: string }

const TH = 'px-5 py-2.5 text-left text-xs font-medium text-gray-500';

function ScanTable({ scans }: { scans: ScanSummary[] }) {
  if (!scans.length) return null;
  return (
    <Card className="overflow-hidden">
      <CardHeader title="최근 검사" description="보호 중인 레포의 PR 검사 결과입니다." />
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead className="bg-gray-50"><tr>
            <th className={TH}>PR</th><th className={TH}>위험도</th>
            <th className={cx(TH, 'hidden sm:table-cell')}>커밋</th><th className={cx(TH, 'hidden sm:table-cell')}>시각 (UTC)</th>
          </tr></thead>
          <tbody className="divide-y divide-gray-200">
            {scans.map((s) => (
              <tr key={s.id} className="hover:bg-gray-50">
                <td className="px-5 py-3">
                  <a href={`/scans/${s.id}`} className="font-medium text-gray-900 underline decoration-gray-300 underline-offset-4 hover:decoration-gray-900">{s.repo}#{s.prNumber}</a>
                  <div className="text-gray-500">{s.prTitle}</div>
                </td>
                <td className="px-5 py-3">
                  {s.status === 'running' ? <span className="inline-flex items-center gap-1.5 text-gray-500"><ArrowPathIcon aria-hidden="true" className="size-3.5 animate-spin" />검사 중</span>
                    : s.status === 'error' ? <span className="font-medium text-red-600">오류</span> : <SeverityPill severity={s.risk} />}
                </td>
                <td className="hidden px-5 py-3 font-mono text-xs text-gray-500 sm:table-cell">{s.headSha.slice(0, 7)}</td>
                <td className="hidden px-5 py-3 text-gray-500 sm:table-cell">{s.createdAt}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

const repoPath = (fullName: string) => fullName.split('/').map(encodeURIComponent).join('/');

/** Base UI 문서의 스위치 모양: 켜지면 진한 회색이 밀려 들어온다 */
const SWITCH = 'relative flex h-6 w-10 flex-none rounded-full bg-gradient-to-r from-gray-700 from-35% to-gray-200 to-65% bg-[length:6.5rem_100%] bg-[100%_0%] bg-no-repeat p-px shadow-[inset_0_1.5px_2px] shadow-gray-200 outline-1 -outline-offset-1 outline-gray-200 transition-[background-position,box-shadow] duration-[125ms] ease-[cubic-bezier(0.26,0.75,0.38,0.45)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-800 data-checked:bg-[0%_0%] data-checked:active:bg-gray-500 data-disabled:opacity-60';
const THUMB = 'aspect-square h-full rounded-full bg-white shadow-[0_0_1px_1px,0_1px_1px,1px_2px_4px_-1px] shadow-gray-100 transition-transform duration-150 data-checked:translate-x-4';

function RepoRow({ repo, index, onAskDisable }: { repo: RepoItem; index: number; onAskDisable: (r: RepoItem, formId: string) => void }) {
  const [pending, setPending] = useState(false);
  const onId = `repo-${index}-enable`;
  const offId = `repo-${index}-disable`;
  return (
    <li className="flex items-center justify-between gap-6 px-5 py-3.5">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <a href={repo.htmlUrl} target="_blank" rel="noopener" className="truncate text-sm font-medium text-gray-900 hover:underline">{repo.fullName}</a>
          {repo.private && <LockClosedIcon aria-label="비공개 레포" className="size-3.5 flex-none text-gray-400" />}
        </div>
        <p className="mt-0.5 text-xs text-gray-500">{pending ? '바꾸는 중…' : repo.enabled ? '보호 중 · PR 검사와 Threat Radar 감시' : '꺼짐'}</p>
      </div>
      <Switch.Root checked={repo.enabled} disabled={pending} aria-label={`${repo.fullName} 보호`} className={SWITCH}
        onCheckedChange={(on) => { if (on) { setPending(true); submitForm(onId); } else onAskDisable(repo, offId); }}>
        <Switch.Thumb className={THUMB} />
      </Switch.Root>
      <PostForm id={onId} action={`/repos/${repoPath(repo.fullName)}/enable`} className="hidden" />
      <PostForm id={offId} action={`/repos/${repoPath(repo.fullName)}/disable`} className="hidden" />
    </li>
  );
}

function LangSelect({ value }: { value: Lang }) {
  return (
    <Select.Root name="lang" items={LANGS.map((l) => ({ value: l, label: LANG_NAMES[l] }))} defaultValue={value}>
      <Select.Label className={LABEL}>리포트 언어</Select.Label>
      <Select.Trigger className={cx('flex h-9 min-w-40 items-center justify-between gap-3 rounded-md border border-gray-200 bg-white pr-2.5 pl-3 text-sm text-gray-900 select-none hover:bg-gray-50 data-popup-open:bg-gray-50', FOCUS)}>
        <Select.Value />
        <Select.Icon className="flex text-gray-500"><ChevronUpDownIcon aria-hidden="true" className="size-4" /></Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Positioner sideOffset={8} className="z-50 outline-none select-none">
          <Select.Popup className={cx(POPUP, 'min-w-(--anchor-width) py-1')}>
            <Select.List>
              {LANGS.map((l) => (
                <Select.Item key={l} value={l} className={cx(ITEM, 'grid grid-cols-[0.75rem_1fr] pl-2.5')}>
                  <Select.ItemIndicator className="col-start-1"><CheckIcon aria-hidden="true" className="size-3" /></Select.ItemIndicator>
                  <Select.ItemText className="col-start-2">{LANG_NAMES[l]}</Select.ItemText>
                </Select.Item>
              ))}
            </Select.List>
          </Select.Popup>
        </Select.Positioner>
      </Select.Portal>
    </Select.Root>
  );
}

function SimpleCheckbox({ defaultChecked }: { defaultChecked: boolean }) {
  return (
    <label className="flex h-9 cursor-pointer items-center gap-2.5 text-sm text-gray-900">
      <Checkbox.Root name="simple" value="1" defaultChecked={defaultChecked}
        className={cx('flex size-4 flex-none items-center justify-center rounded-sm border border-gray-300 bg-white data-checked:border-gray-900 data-checked:bg-gray-900', FOCUS)}>
        <Checkbox.Indicator className="flex text-white data-unchecked:hidden"><CheckIcon aria-hidden="true" className="size-3" /></Checkbox.Indicator>
      </Checkbox.Root>
      초등학교 5학년 수준으로 설명하기
    </label>
  );
}

function RepoSelect({ names }: { names: string[] }) {
  return (
    <Select.Root name="repo" items={names.map((n) => ({ value: n, label: n }))} defaultValue={names[0]}>
      <Select.Label className={LABEL}>레포</Select.Label>
      <Select.Trigger className={cx('flex h-9 min-w-60 items-center justify-between gap-3 rounded-md border border-gray-200 bg-white pr-2.5 pl-3 text-sm text-gray-900 select-none hover:bg-gray-50 data-popup-open:bg-gray-50', FOCUS)}>
        <Select.Value />
        <Select.Icon className="flex text-gray-500"><ChevronUpDownIcon aria-hidden="true" className="size-4" /></Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Positioner sideOffset={8} className="z-50 outline-none select-none">
          <Select.Popup className={cx(POPUP, 'min-w-(--anchor-width) py-1')}>
            <Select.List>
              {names.map((n) => (
                <Select.Item key={n} value={n} className={cx(ITEM, 'grid grid-cols-[0.75rem_1fr] pl-2.5')}>
                  <Select.ItemIndicator className="col-start-1"><CheckIcon aria-hidden="true" className="size-3" /></Select.ItemIndicator>
                  <Select.ItemText className="col-start-2">{n}</Select.ItemText>
                </Select.Item>
              ))}
            </Select.List>
          </Select.Popup>
        </Select.Positioner>
      </Select.Portal>
    </Select.Root>
  );
}

export interface DashboardProps extends BaseProps { repos: RepoItem[]; recent: ScanSummary[]; reportLang: Lang; reportSimple: boolean }

export function Dashboard({ repos, recent, reportLang, reportSimple, ...base }: DashboardProps) {
  const [filter, setFilter] = useState('');
  const [confirm, setConfirm] = useState<{ repo: RepoItem; formId: string } | null>(null);
  const shown = useMemo(() => repos.filter((r) => r.fullName.toLowerCase().includes(filter.trim().toLowerCase())), [repos, filter]);
  const enabled = repos.filter((r) => r.enabled).map((r) => r.fullName);
  return (
    <Shell {...base} active="repos">
      <PageHeader title="레포지토리" description="보호를 켜면 해당 레포에 webhook 이 등록되고, PR 이 열리거나 커밋이 푸시될 때마다 자동으로 검사합니다. Threat Radar 도 이 레포의 의존성과 런타임 버전을 감시합니다." />
      <div className="grid gap-6">
        <ScanTable scans={recent} />

        <Card className="overflow-hidden">
          <CardHeader title={`내 레포 (${repos.length})`} description="관리자 권한이 있는 레포만 표시합니다."
            actions={repos.length > 6 && (
              <Field.Root className="relative w-full sm:w-64">
                <Field.Label className="sr-only">레포 검색</Field.Label>
                <MagnifyingGlassIcon aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-gray-400" />
                <Field.Control value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="레포 이름으로 찾기" className={cx(INPUT, 'pl-8')} />
              </Field.Root>
            )} />
          {shown.length
            ? <ul className="divide-y divide-gray-200">{shown.map((r) => <RepoRow key={r.fullName} repo={r} index={repos.indexOf(r)} onAskDisable={(repo, formId) => setConfirm({ repo, formId })} />)}</ul>
            : <p className="px-5 py-10 text-center text-sm text-gray-500">{repos.length ? '찾는 레포가 없습니다.' : '관리자 권한이 있는 레포가 없습니다.'}</p>}
        </Card>

        {enabled.length > 0 && (
          <Card>
            <CardHeader title="수동 검사" description="열려 있는 PR 을 지금 바로 다시 검사합니다." />
            <PostForm action="/scan" className="flex flex-wrap items-end gap-4 px-5 py-4">
              <div className="grid gap-1.5"><RepoSelect names={enabled} /></div>
              <Field.Root className="grid gap-1.5">
                <Field.Label className={LABEL}>PR 번호</Field.Label>
                <Field.Control name="number" inputMode="numeric" pattern="[0-9]+" required placeholder="예: 42" className={cx(INPUT, 'w-32')} />
              </Field.Root>
              <Btn type="submit" variant="primary">지금 검사</Btn>
            </PostForm>
          </Card>
        )}

        <Card>
          <CardHeader title="PR 리포트 설정" description="PR 코멘트·인라인 리뷰·커밋 상태에 적용됩니다. 다음 검사부터 반영됩니다." />
          <PostForm action="/settings/report" className="flex flex-wrap items-end gap-x-6 gap-y-4 px-5 py-4">
            <div className="grid gap-1.5"><LangSelect value={reportLang} /></div>
            <SimpleCheckbox defaultChecked={reportSimple} />
            <Btn type="submit">저장</Btn>
          </PostForm>
        </Card>
      </div>

      <AlertDialog.Root open={!!confirm} onOpenChange={(o) => { if (!o) setConfirm(null); }}>
        <AlertDialog.Portal>
          <AlertDialog.Backdrop className={BACKDROP} />
          <AlertDialog.Popup className={DIALOG}>
            <AlertDialog.Title className="text-base font-semibold">{confirm?.repo.fullName} 보호를 끌까요?</AlertDialog.Title>
            <AlertDialog.Description className="mt-2 text-sm leading-6 text-gray-600">이 레포의 webhook 을 삭제합니다. 이후 PR 은 자동으로 검사되지 않고, Threat Radar 도 이 레포를 더 이상 감시하지 않습니다.</AlertDialog.Description>
            <div className="mt-6 flex justify-end gap-2">
              <AlertDialog.Close className={btnClass()}>취소</AlertDialog.Close>
              <Btn variant="danger" onClick={() => { if (confirm) submitForm(confirm.formId); }}>보호 끄기</Btn>
            </div>
          </AlertDialog.Popup>
        </AlertDialog.Portal>
      </AlertDialog.Root>
    </Shell>
  );
}

// ---------- 검사 결과 ----------

export interface ScanPageProps extends BaseProps { scan: ScanSummary & { error: string | null }; result: AnalysisResult | null }

export function ScanPage({ scan, result, ...base }: ScanPageProps) {
  // 검사 중이면 5초마다 새로 고친다
  useEffect(() => {
    if (scan.status !== 'running') return;
    const t = setTimeout(() => location.reload(), 5000);
    return () => clearTimeout(t);
  }, [scan.status]);
  const prUrl = `https://github.com/${scan.repo}/pull/${scan.prNumber}`;
  return (
    <Shell {...base} active="repos">
      <PageHeader
        eyebrow={<nav aria-label="경로" className="flex items-center gap-1"><a href="/" className="hover:text-gray-900">레포지토리</a><ChevronRightIcon aria-hidden="true" className="size-3.5 text-gray-400" /><span>검사 #{scan.id}</span></nav>}
        title={`${scan.repo}#${scan.prNumber}`}
        description={<>{scan.prTitle} · commit <code className="text-xs">{scan.headSha.slice(0, 7)}</code> · {scan.createdAt} UTC</>}
        actions={<Btn href={prUrl}>GitHub 에서 PR 보기</Btn>} />
      {scan.status === 'running' && (
        <Card className="mb-4 flex items-center gap-2 px-5 py-4 text-sm text-gray-700"><ArrowPathIcon aria-hidden="true" className="size-4 animate-spin text-gray-400" />검사 중입니다. 끝나면 자동으로 새로 고칩니다.</Card>
      )}
      {scan.status === 'error' && (
        <Card className="mb-4 flex items-center gap-2 px-5 py-4 text-sm text-red-700"><ExclamationTriangleIcon aria-hidden="true" className="size-4" />오류: {scan.error}</Card>
      )}
      {result && <Findings result={result} />}
    </Shell>
  );
}

// ---------- 안내 (오류, 없음) ----------

export interface MessageProps extends BaseProps { title: string; text: string; hint?: string; link?: { href: string; label: string } }

export function Message({ title, text, hint, link, ...base }: MessageProps) {
  return (
    <Shell {...base}>
      <div className="py-24">
        <h1 className="text-3xl font-semibold tracking-tight text-gray-900">{title}</h1>
        <p className="mt-3 text-gray-600">{text}</p>
        {hint && <p className="mt-2 text-sm text-gray-500">{hint}</p>}
        {link && <div className="mt-8"><Btn href={link.href} variant="primary">{link.label}</Btn></div>}
      </div>
    </Shell>
  );
}
