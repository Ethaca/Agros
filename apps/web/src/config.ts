import { DEFAULT_LANG, isLang, type Lang } from './i18n.ts';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Workers 에서는 요청/큐 진입 시 bindEnv(env) 로 바인딩을 주입하고,
 * Node(CLI/테스트) 에서는 process.env 를 그대로 쓴다.
 */
let source: Record<string, unknown> = typeof process !== 'undefined' ? { ...process.env } : {};

export function bindEnv(env: object) {
  source = { ...source, ...env };
}

const env = (name: string, fallback = ''): string => {
  const v = source[name];
  return (typeof v === 'string' && v.trim()) || fallback;
};

function required(name: string): string {
  const value = env(name);
  if (!value) throw new Error(`환경변수 ${name} 가 설정되지 않았습니다 (README 의 배포 섹션 참고)`);
  return value;
}

export const config = {
  get publicUrl() { return required('PUBLIC_URL').replace(/\/$/, ''); },
  get failOn() { return env('FAIL_ON', 'high') as Severity | 'never'; },
  get minConfidence() { return Number(env('MIN_CONFIDENCE', '0.5')); },
  /** 사용자가 설정하지 않았을 때의 PR 리포트 언어 */
  get lang(): Lang { const v = env('REPORT_LANG', DEFAULT_LANG); return isLang(v) ? v : DEFAULT_LANG; },
  claude: {
    get apiKey() { return env('ANTHROPIC_API_KEY'); },
    get model() { return env('ANTHROPIC_MODEL', 'claude-sonnet-5-5'); },
  },
  /** 선택: GitHub 권고 수집용 토큰. 없으면 비인증 한도(시간당 60회) 안에서 동작 */
  get radarGithubToken() { return env('RADAR_GITHUB_TOKEN'); },
  get githubClientId() { return required('GITHUB_CLIENT_ID'); },
  get githubClientSecret() { return required('GITHUB_CLIENT_SECRET'); },
  get sessionSecret() { return required('SESSION_SECRET'); },
  get encryptionKey() { return required('ENCRYPTION_KEY'); },
};
