import { Avatar } from '@base-ui/react/avatar';
import { Button } from '@base-ui/react/button';
import { Menu } from '@base-ui/react/menu';
import { Separator } from '@base-ui/react/separator';
import { Toast } from '@base-ui/react/toast';
import { Tooltip } from '@base-ui/react/tooltip';
import { Bars3Icon, CheckCircleIcon, ExclamationCircleIcon, ShieldCheckIcon, XMarkIcon } from '@heroicons/react/16/solid';
import { createContext, useContext, useEffect, type ButtonHTMLAttributes, type ReactElement, type ReactNode } from 'react';

/** 모든 페이지가 받는 공통 props. 사용자 정보는 화면에 필요한 것만 (토큰 등은 절대 넣지 않는다) */
export interface Viewer { login: string; avatarUrl: string | null }
export interface FlashMessage { msg: string; err?: boolean }
export interface BaseProps { viewer: Viewer | null; csrf: string; flash?: FlashMessage }

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ');

const CsrfContext = createContext('');

/** 상태를 바꾸는 POST 폼. double-submit CSRF 토큰을 자동으로 넣는다 */
export function PostForm({ action, id, className, children, onSubmit }: { action: string; id?: string; className?: string; children?: ReactNode; onSubmit?: () => void }) {
  const csrf = useContext(CsrfContext);
  return (
    <form method="post" action={action} id={id} className={className} onSubmit={onSubmit}>
      <input type="hidden" name="csrf" value={csrf} />
      {children}
    </form>
  );
}

/** 메뉴처럼 클릭 직후 사라지는 요소 안에서는 폼을 밖에 두고 id 로 제출한다 */
export const submitForm = (id: string) => (document.getElementById(id) as HTMLFormElement | null)?.requestSubmit();

// ---------- Base UI 공통 스타일 ----------

/** 팝업(메뉴·셀렉트·팝오버): 열리는 원점에서 커지고 작아진다 */
export const POPUP = 'origin-(--transform-origin) rounded-lg bg-white text-gray-900 shadow-lg shadow-gray-200 outline-1 outline-gray-200 transition-[transform,scale,opacity] duration-150 data-ending-style:scale-90 data-ending-style:opacity-0 data-starting-style:scale-90 data-starting-style:opacity-0';
/** 메뉴·셀렉트 항목: 강조되면 검은 배경 */
export const ITEM = 'flex cursor-default items-center gap-2 py-2 pr-8 pl-4 text-sm leading-4 outline-none select-none data-highlighted:relative data-highlighted:z-0 data-highlighted:text-gray-50 data-highlighted:before:absolute data-highlighted:before:inset-x-1 data-highlighted:before:inset-y-0 data-highlighted:before:z-[-1] data-highlighted:before:rounded-sm data-highlighted:before:bg-gray-900';
/** 대화 상자: 바탕은 흐리게, 패널은 살짝 커지며 나타난다 */
export const BACKDROP = 'fixed inset-0 min-h-dvh bg-black opacity-20 supports-[-webkit-touch-callout:none]:absolute transition-all duration-150 data-ending-style:opacity-0 data-starting-style:opacity-0';
export const DIALOG = 'fixed top-1/2 left-1/2 -mt-8 w-[min(28rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 rounded-lg bg-white p-6 text-gray-900 outline-1 outline-gray-200 shadow-xl transition-all duration-150 data-ending-style:scale-90 data-ending-style:opacity-0 data-starting-style:scale-90 data-starting-style:opacity-0';
export const INPUT = 'h-9 w-full rounded-md border border-gray-200 bg-white px-3 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-2 focus:-outline-offset-1 focus:outline-blue-800';
export const LABEL = 'text-sm font-medium text-gray-900';
export const FOCUS = 'focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-blue-800';

const BTN = {
  base: `inline-flex items-center justify-center gap-1.5 rounded-md font-medium whitespace-nowrap select-none ${FOCUS} data-disabled:cursor-not-allowed data-disabled:opacity-50`,
  variant: {
    secondary: 'border border-gray-200 bg-gray-50 text-gray-900 hover:bg-gray-100 active:bg-gray-100 data-disabled:hover:bg-gray-50',
    primary: 'bg-gray-900 text-white hover:bg-gray-800 active:bg-gray-700 data-disabled:hover:bg-gray-900',
    danger: 'bg-red-600 text-white hover:bg-red-500',
    ghost: 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
  },
  size: { sm: 'h-7 px-2.5 text-xs', md: 'h-9 px-3.5 text-sm', lg: 'h-10 px-4 text-sm' },
};

type BtnProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
  variant?: keyof typeof BTN.variant; size?: keyof typeof BTN.size; className?: string; href?: string;
};

/** Base UI 부품(Close 등)에 버튼 모양만 입힐 때 */
export const btnClass = (variant: keyof typeof BTN.variant = 'secondary', size: keyof typeof BTN.size = 'md') => cx(BTN.base, BTN.variant[variant], BTN.size[size]);

export function Btn({ variant = 'secondary', size = 'md', className, href, children, ...rest }: BtnProps) {
  const cls = cx(btnClass(variant, size), className);
  if (href) return <Button nativeButton={false} render={<a href={href} />} className={cls}>{children}</Button>;
  return <Button className={cls} {...rest}>{children}</Button>;
}

export function Card({ className, children, id }: { className?: string; children: ReactNode; id?: string }) {
  return <div id={id} className={cx('rounded-lg border border-gray-200 bg-white', className)}>{children}</div>;
}

export function CardHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-200 px-5 py-4">
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        {description && <p className="mt-0.5 text-sm text-gray-600">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

/** 상태 표시: 색 점 + 글자. 색은 상태에만 쓴다 */
export type Tone = 'gray' | 'red' | 'orange' | 'yellow' | 'green' | 'blue';
const DOT: Record<Tone, string> = { gray: 'bg-gray-400', red: 'bg-red-500', orange: 'bg-orange-500', yellow: 'bg-yellow-500', green: 'bg-green-500', blue: 'bg-blue-500' };

export function Badge({ tone = 'gray', children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cx('inline-flex items-center gap-1.5 rounded-full border border-gray-200 bg-white px-2 py-0.5 text-xs font-medium whitespace-nowrap text-gray-700', className)}>
      <span aria-hidden="true" className={cx('size-1.5 rounded-full', DOT[tone])} />{children}
    </span>
  );
}

export const SEVERITY_TONE: Record<string, Tone> = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue', info: 'gray', none: 'green' };

export function SeverityPill({ severity }: { severity: string | null }) {
  return <Badge tone={SEVERITY_TONE[severity ?? 'info'] ?? 'gray'}>{(severity ?? '-').toUpperCase()}</Badge>;
}

/** 비활성 버튼에 이유를 보여주는 툴팁 */
export function Hint({ label, children }: { label?: string; children: ReactElement }) {
  if (!label) return children;
  return (
    <Tooltip.Root>
      <Tooltip.Trigger render={<span className="inline-flex" />}>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Positioner sideOffset={6}>
          <Tooltip.Popup className="origin-(--transform-origin) rounded-md bg-gray-900 px-2 py-1 text-xs text-white shadow-lg transition-[transform,scale,opacity] data-ending-style:scale-90 data-ending-style:opacity-0 data-starting-style:scale-90 data-starting-style:opacity-0">{label}</Tooltip.Popup>
        </Tooltip.Positioner>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0 flex-1">
        {eyebrow && <div className="mb-2 text-sm text-gray-500">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold tracking-tight text-gray-900">{title}</h1>
        {description && <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-600">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

// ---------- 알림 (Toast) ----------

/** 서버가 넘긴 결과 알림을 토스트로 띄운다 */
function FlashToast({ flash }: { flash?: FlashMessage }) {
  const toast = Toast.useToastManager();
  useEffect(() => {
    if (flash) toast.add({ title: flash.msg, type: flash.err ? 'error' : 'success', timeout: flash.err ? 8000 : 5000 });
    // 첫 화면에서 한 번만
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return null;
}

function ToastList() {
  const { toasts } = Toast.useToastManager();
  return (
    <Toast.Portal>
      <Toast.Viewport className="fixed right-4 bottom-4 z-50 flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2">
        {toasts.map((t) => (
          <Toast.Root key={t.id} toast={t}
            className="flex items-start gap-3 rounded-lg border border-gray-200 bg-white p-4 shadow-lg shadow-gray-200 transition-all duration-200 data-ending-style:translate-y-2 data-ending-style:opacity-0 data-starting-style:translate-y-2 data-starting-style:opacity-0">
            {t.type === 'error'
              ? <ExclamationCircleIcon aria-hidden="true" className="mt-0.5 size-4 flex-none text-red-600" />
              : <CheckCircleIcon aria-hidden="true" className="mt-0.5 size-4 flex-none text-green-600" />}
            <Toast.Content className="min-w-0 flex-1">
              <Toast.Title className="text-sm font-medium text-gray-900" />
              <Toast.Description className="text-sm text-gray-600" />
              {t.actionProps && <Toast.Action className={cx(btnClass('primary', 'sm'), 'mt-2')} />}
            </Toast.Content>
            <Toast.Close aria-label="알림 닫기" className={cx('-m-1 rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-900', FOCUS)}>
              <XMarkIcon aria-hidden="true" className="size-4" />
            </Toast.Close>
          </Toast.Root>
        ))}
      </Toast.Viewport>
    </Toast.Portal>
  );
}

// ---------- 앱 레이아웃 ----------

const NAV = [
  { href: '/', label: '레포지토리', key: 'repos' },
  { href: '/radar', label: 'Threat Radar', key: 'radar' },
] as const;
type NavKey = (typeof NAV)[number]['key'];

function UserAvatar({ viewer }: { viewer: Viewer }) {
  return (
    <Avatar.Root className="inline-flex size-7 items-center justify-center overflow-hidden rounded-full bg-gray-100 align-middle text-xs font-medium text-gray-900 select-none">
      {viewer.avatarUrl && <Avatar.Image src={viewer.avatarUrl} width="28" height="28" className="size-full object-cover" />}
      <Avatar.Fallback className="flex size-full items-center justify-center">{viewer.login.slice(0, 2).toUpperCase()}</Avatar.Fallback>
    </Avatar.Root>
  );
}

function AppMenu({ viewer, trigger, label, side }: { viewer: Viewer; trigger: ReactNode; label: string; side: 'nav' | 'profile' }) {
  return (
    <Menu.Root>
      <Menu.Trigger aria-label={label} className={cx('flex items-center gap-2 rounded-md px-1.5 py-1 text-sm text-gray-700 select-none hover:bg-gray-100 data-popup-open:bg-gray-100', FOCUS)}>
        {trigger}
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Positioner sideOffset={8} align="end" className="z-50 outline-none">
          <Menu.Popup className={cx(POPUP, 'min-w-52 py-1')}>
            <div className="px-4 py-2 text-xs text-gray-500">{viewer.login} 으로 로그인됨</div>
            <Separator className="mx-4 my-1 h-px bg-gray-200" />
            {NAV.map((n) => <Menu.LinkItem key={n.key} href={n.href} className={ITEM}>{n.label}</Menu.LinkItem>)}
            <Separator className="mx-4 my-1 h-px bg-gray-200" />
            <Menu.Item onClick={() => submitForm('logout-form')} className={ITEM}>로그아웃</Menu.Item>
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  );
}

export function Shell({ viewer, csrf, flash, active, wide, children }: BaseProps & { active?: NavKey; wide?: boolean; children: ReactNode }) {
  const width = wide ? 'max-w-[1440px]' : 'max-w-5xl';
  return (
    <CsrfContext.Provider value={csrf}>
      <Toast.Provider>
        <Tooltip.Provider delay={200}>
          {/* 팝업이 페이지 위에 쌓이도록 별도 쌓임 맥락 (Base UI 권장 설정) */}
          <div className="isolate min-h-full">
            <header className="sticky top-0 z-30 border-b border-gray-200 bg-white/90 backdrop-blur">
              <div className={cx('mx-auto flex h-14 items-center gap-6 px-4 sm:px-6', width)}>
                <a href="/" className="flex items-center gap-2 text-sm font-semibold text-gray-900">
                  <ShieldCheckIcon aria-hidden="true" className="size-5" />Argos
                </a>
                {viewer && (
                  <nav aria-label="주 메뉴" className="hidden items-center gap-1 sm:flex">
                    {NAV.map((n) => (
                      <a key={n.key} href={n.href} aria-current={active === n.key ? 'page' : undefined}
                        className={cx('rounded-md px-2.5 py-1.5 text-sm', FOCUS, active === n.key ? 'bg-gray-100 font-medium text-gray-900' : 'text-gray-600 hover:text-gray-900')}>
                        {n.label}
                      </a>
                    ))}
                  </nav>
                )}
                <div className="ml-auto flex items-center gap-1">
                  {viewer ? (
                    <>
                      <div className="hidden sm:block"><AppMenu viewer={viewer} side="profile" label="사용자 메뉴" trigger={<><UserAvatar viewer={viewer} /><span>{viewer.login}</span></>} /></div>
                      <div className="sm:hidden"><AppMenu viewer={viewer} side="nav" label="메뉴" trigger={<Bars3Icon aria-hidden="true" className="size-5" />} /></div>
                    </>
                  ) : <Btn href="/auth/github" variant="primary" size="sm">GitHub 로 로그인</Btn>}
                </div>
              </div>
            </header>
            {viewer && <form id="logout-form" method="post" action="/logout" hidden />}
            <main className={cx('mx-auto px-4 py-10 sm:px-6', width)}>{children}</main>
          </div>
          <FlashToast flash={flash} />
          <ToastList />
        </Tooltip.Provider>
      </Toast.Provider>
    </CsrfContext.Provider>
  );
}
