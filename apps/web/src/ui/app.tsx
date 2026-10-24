import type { ComponentProps } from 'react';
import { Dashboard, Landing, Message, ScanPage } from './pages.tsx';
import { Radar } from './radar.tsx';

/** 서버 렌더와 브라우저 hydrate 가 같은 표를 본다 */
export const PAGES = { landing: Landing, dashboard: Dashboard, scan: ScanPage, radar: Radar, message: Message };
export type PageName = keyof typeof PAGES;
export type PageProps<K extends PageName> = ComponentProps<(typeof PAGES)[K]>;

export function App<K extends PageName>({ name, props }: { name: K; props: PageProps<K> }) {
  // name 과 props 의 짝은 PageProps<K> 가 보장한다
  const Page = PAGES[name] as React.ComponentType<PageProps<K>>;
  return <Page {...(props as PageProps<K> & React.JSX.IntrinsicAttributes)} />;
}
