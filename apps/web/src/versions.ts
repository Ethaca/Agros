/**
 * 권고의 영향 범위와 레포에 적힌 버전을 비교한다.
 * semver 전체가 아니라 숫자 버전 비교만 한다 (프리릴리스 꼬리표는 무시하고 정식 버전과 같게 본다).
 */

/** 영향 구간. introduced 이상, fixed 미만 또는 lastAffected 이하 */
export interface Interval { introduced?: string; fixed?: string; lastAffected?: string }

export type Version = number[];

export function parseVersion(s: string): Version | null {
  const m = /^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?/.exec(s);
  if (!m) return null;
  return m.slice(1).filter((x) => x !== undefined).map(Number);
}

export function compareVersions(a: Version, b: Version): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d) return Math.sign(d);
  }
  return 0;
}

const cmp = (a: string, b: string) => {
  const va = parseVersion(a), vb = parseVersion(b);
  return va && vb ? compareVersions(va, vb) : NaN;
};

/** 정확히 x.y.z 로 적힌 버전인가 */
export const isExactVersion = (s: string) => /^v?\d+\.\d+\.\d+(?:[-+.][\w.-]*)?$/.test(s.trim());

export function inInterval(version: string, iv: Interval): boolean {
  if (iv.introduced && iv.introduced !== '0' && !(cmp(version, iv.introduced) >= 0)) return false;
  if (iv.fixed && !(cmp(version, iv.fixed) < 0)) return false;
  if (iv.lastAffected && !(cmp(version, iv.lastAffected) <= 0)) return false;
  return !!parseVersion(version);
}

/**
 * GitHub Advisory 의 vulnerable_version_range (예: ">= 16.3.0, < 16.3.4", "< 8.3.36", "= 1.2.3") 를 구간으로 바꾼다.
 * 해석할 수 없는 토큰이 하나라도 있으면 null (잘못 해석하느니 범위 미확인으로 둔다)
 */
export function parseRangeExpression(expr: string | null | undefined): Interval | null {
  if (!expr?.trim()) return null;
  const iv: Interval = {};
  for (const token of expr.split(',').map((t) => t.trim()).filter(Boolean)) {
    const m = /^(>=|>|<=|<|=)\s*v?(\d+(?:\.\d+){0,3}[\w.-]*)$/.exec(token);
    if (!m) return null;
    const [, op, v] = m;
    if (op === '>=' || op === '>') iv.introduced = v;
    else if (op === '<') iv.fixed = v;
    else if (op === '<=') iv.lastAffected = v;
    else { iv.introduced = v; iv.lastAffected = v; }
  }
  return iv;
}

/** 패치 버전 목록 문자열 ("8.2.35, 8.3.36") 에서 버전만 꺼낸다 */
export const parseVersionList = (s: string | null | undefined): string[] =>
  (s ?? '').split(/[\s,;|]+/).map((v) => v.replace(/^v/, '')).filter((v) => /^\d+\.\d+(?:\.\d+)*$/.test(v));

const sameBranch = (a: Version, b: Version) => a[0] === b[0] && (a[1] ?? 0) === (b[1] ?? 0);

export interface RangeVerdict {
  affected: boolean | null; // null: 판단 근거 없음
  /** 같은 브랜치에서 올릴 수 있는 공식 패치 버전 */
  fix?: string;
}

/**
 * 버전 하나가 영향받는지 판정한다.
 * 1) 구간이 있으면 구간으로, 2) 구간 없이 브랜치별 패치 목록만 있으면(런타임 권고에 흔함) 같은 브랜치 패치보다 낮은지로 판정
 */
export function judgeVersion(version: string, intervals: Interval[], patched: string[]): RangeVerdict {
  const v = parseVersion(version);
  if (!v) return { affected: null };
  if (intervals.length) {
    const hit = intervals.find((iv) => inInterval(version, iv));
    if (!hit) return { affected: false };
    const fix = hit.fixed ?? branchFix(v, patched);
    return { affected: true, fix };
  }
  if (patched.length) {
    const pv = patched.map((p) => [p, parseVersion(p)] as const).filter((x): x is readonly [string, Version] => !!x[1]);
    const same = pv.find(([, p]) => sameBranch(p, v));
    if (same) return compareVersions(v, same[1]) < 0 ? { affected: true, fix: same[0] } : { affected: false };
    const lowest = pv.sort((a, b) => compareVersions(a[1], b[1]))[0];
    // 패치가 나오지 않은 더 오래된 브랜치는 지원 종료로 보고 영향받는 쪽으로 판단
    if (lowest && compareVersions(v, lowest[1]) < 0) return { affected: true };
    return { affected: false };
  }
  return { affected: null };
}

function branchFix(v: Version, patched: string[]): string | undefined {
  return patched.find((p) => { const pv = parseVersion(p); return pv && sameBranch(pv, v) && compareVersions(v, pv) < 0; });
}

/** "^8.3", "8", ">=20", "~1.2" 처럼 범위로 적힌 표기에서 가장 낮은 구체 버전 (8.3.0 등) */
export function lowestOf(spec: string): string | null {
  const m = /(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(spec);
  if (!m || /^\s*[<]/.test(spec)) return null;
  return [m[1], m[2] ?? '0', m[3] ?? '0'].join('.');
}
