import type { SignalRow } from './db.ts';

/** 신뢰도 단계. 서버(조치 허용)와 화면(단계 표시)이 같은 규칙을 쓴다 */
export type Level = 1 | 2 | 3 | 4;
export const LEVELS: Record<Level, { name: string; cond: string; unlocks: string }> = {
  1: { name: 'L1 소문', cond: 'SNS·커뮤니티 글 1건, 취약점 관련으로 판정', unlocks: '대시보드 알림' },
  2: { name: 'L2 교차 확인', cond: '서로 다른 출처 2곳 이상 또는 공신력 있는 출처', unlocks: '+ GitHub Issue (완화책 중심)' },
  3: { name: 'L3 공식', cond: 'GHSA · OSV · 벤더 권고 등재, 패치 버전 확인', unlocks: '+ 버전업 PR 초안' },
  4: { name: 'L4 악용 중', cond: 'L3 + CISA KEV 등재 또는 독립된 악용 보고 2건', unlocks: '+ 최상단 고정 · 긴급 라벨' },
};
/** 조치별 최소 신뢰도. 서버에서 다시 확인한다 (UI 의 비활성 버튼만 믿지 않음) */
export const ACTION_MIN_LEVEL = { issue: 2, pr: 3 } as const;

export function computeLevel(sigs: Pick<SignalRow, 'official' | 'trusted' | 'exploited' | 'domain' | 'source'>[], kev: boolean): Level {
  const official = sigs.some((s) => s.official);
  const exploitOrigins = new Set(sigs.filter((s) => s.exploited).map((s) => s.domain ?? s.source));
  if (official) return kev || exploitOrigins.size >= 2 ? 4 : 3;
  const origins = new Set(sigs.map((s) => s.domain ?? s.source));
  return sigs.some((s) => s.trusted) || origins.size >= 2 ? 2 : 1;
}

