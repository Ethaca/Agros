import { parsePatch, type ChangedFile, type DiffLine } from './diff.ts';
import type { Category, Finding, Severity } from './types.ts';

/**
 * 빠르고 결정적인 1차 필터. 오탐 가능성이 있는 패턴도 일부러 넓게 잡고,
 * LLM 단계에서 문맥을 보고 confirmed / false_positive 를 판정하게 한다.
 */
export interface Rule {
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  pattern: RegExp;
  /** 'removed' 면 삭제된 라인을 본다 (인증/레이트리밋 제거 탐지) */
  target?: 'added' | 'removed';
  /** 주변 window 줄 안에 이 패턴이 있으면 안전한 것으로 보고 건너뛴다 */
  unless?: RegExp;
  window?: number;
  /** 'handler' 면 window 를 현재 라우트 핸들러 안으로 제한 (옆 핸들러의 소유권 체크를 잘못 참조하지 않도록) */
  scope?: 'handler';
  files?: RegExp;
}

// 요청에서 들어오는 사용자 입력
const REQ = String.raw`(?:\b(?:req|request|ctx|c)\.(?:params|query|body|args|GET|POST|form|json|data|view_args|path_params|query_params)\b|\bparams\[:?\w+\]|@PathVariable|@RequestParam|\bc\.(?:Param|Query)\(|\$_(?:GET|POST|REQUEST)|r\.URL\.Query\(\)|mux\.Vars\()`;
// 소유권 / 테넌트 / 인가 체크의 흔적
const OWNERSHIP = /\b(user_?id|userId|owner(_?id|Id)?|tenant(_?id|Id)?|org(anization)?_?[iI]d|account_?[iI]d|current_?user|currentUser|req\.user|request\.user|ctx\.state\.user|session\.user|authorize|ability|can\(|policy|permission|checkAccess|assertOwn\w*|belongsTo|createdBy|created_by)\b/i;
const ROUTE = String.raw`(?:\.(?:get|post|put|patch|delete|all)\s*\(\s*['"\`]|@(?:Get|Post|Put|Patch|Delete|Request)Mapping\(|@(?:app|router|bp|api)\.(?:get|post|put|patch|delete|route)\()`;
const JS = /\.(m?[jt]sx?|cjs)$/i;
const ROUTE_START = new RegExp(ROUTE + '|^\\s*(?:async\\s+)?def\\s+\\w+\\(|^\\s*func\\s');

export const RULES: Rule[] = [
  {
    id: 'bola-direct-object-lookup',
    category: 'API1',
    severity: 'high',
    title: '요청 파라미터의 ID 로 객체를 직접 조회/수정',
    description: '클라이언트가 보낸 ID 로 DB 객체를 조회·수정·삭제하면서 현재 사용자의 소유권(owner/tenant) 조건이 보이지 않습니다. 다른 사용자의 ID 를 넣으면 남의 데이터에 접근할 수 있습니다 (BOLA/IDOR).',
    recommendation: '조회 조건에 `ownerId: req.user.id` (또는 tenantId) 를 함께 걸거나, 조회 후 소유권을 검증하고 실패 시 404/403 을 반환하세요.',
    pattern: new RegExp(String.raw`\b(?:find\w*|get(?:ById)?|get_object_or_404|objects\.(?:get|filter)|delete\w*|update\w*|destroy|remove|select|query)\s*\(.*` + REQ, 'i'),
    unless: OWNERSHIP,
    window: 8,
    scope: 'handler',
  },
  {
    id: 'bola-id-route-without-ownership',
    category: 'API1',
    severity: 'medium',
    title: '객체 ID 를 받는 신규 엔드포인트에 소유권 검증 흔적 없음',
    description: '경로에 객체 식별자(`:id`, `{id}`, `<int:pk>` 등)를 받는 라우트가 추가되었지만 근처에 소유권/권한 체크가 보이지 않습니다.',
    recommendation: '핸들러에서 리소스의 소유자와 인증된 사용자가 일치하는지 검증하세요. 정책 미들웨어(예: `authorizeResource`)로 일괄 적용하는 것을 권장합니다.',
    pattern: /(\.(get|put|patch|delete)\s*\(\s*['"`][^'"`]*\/:\w*(id|Id|ID)\b|@(Get|Put|Patch|Delete)Mapping\([^)]*\{\w*[iI]d\}|@(app|router|api)\.(get|put|patch|delete)\([^)]*\{\w*id\}|path\(\s*['"][^'"]*<(int:|uuid:)?\w*(id|pk)>)/,
    unless: OWNERSHIP,
    window: 15,
    scope: 'handler',
  },
  {
    id: 'bola-client-supplied-user-id',
    category: 'API1',
    severity: 'medium',
    title: '사용자 식별자를 클라이언트 입력에서 가져옴',
    description: '`userId`/`ownerId` 같은 주체 식별자를 body·query·header 에서 읽고 있습니다. 인증 토큰이 아닌 클라이언트 값을 믿으면 다른 사용자로 행세할 수 있습니다.',
    recommendation: '주체 식별자는 검증된 세션/토큰(`req.user.id`)에서만 가져오세요.',
    pattern: /\b(req|request|ctx\.request)\.(body|query|headers|params)\.?\[?['"]?(user_?id|userId|owner_?id|ownerId|account_?id|accountId|x-user-id)\b/i,
  },
  {
    id: 'bfla-admin-route-without-role-check',
    category: 'API5',
    severity: 'high',
    title: '관리자/내부용 라우트에 역할 검사 없음',
    description: '`/admin`, `/internal`, `/debug` 등 특권 기능 라우트가 추가되었지만 역할(role) 기반 인가 체크가 보이지 않습니다.',
    recommendation: '`requireRole("admin")`, `@PreAuthorize("hasRole(\'ADMIN\')")`, `Depends(require_admin)` 같은 함수 수준 인가를 적용하세요.',
    pattern: new RegExp(ROUTE.slice(0, -1) + String.raw`)[^)]*\/(?:admin|internal|debug|manage|ops)\b`, 'i'),
    unless: /(isAdmin|requireAdmin|require_admin|admin_required|requireRole|hasRole|hasAuthority|roles?\b|authorize|permission|@PreAuthorize|@Secured|@RolesAllowed|@UseGuards|staff_member_required|superuser)/i,
    window: 4,
  },
  {
    id: 'bfla-role-from-request',
    category: 'API5',
    severity: 'high',
    title: '권한/역할 값을 클라이언트 입력에서 신뢰',
    description: '`role`, `isAdmin`, `permissions` 등을 요청 body/query/header 에서 읽고 있습니다. 공격자가 자신의 권한을 올릴 수 있습니다.',
    recommendation: '권한 정보는 서버 측 사용자 레코드나 검증된 토큰 클레임에서만 가져오세요.',
    pattern: /\b(req|request|ctx\.request)\.(body|query|headers|json|data|form)\.?\[?['"]?(role|roles|is_?admin|isAdmin|admin|permissions?|x-role|x-admin)\b/i,
  },
  {
    id: 'auth-middleware-removed',
    category: 'API2',
    severity: 'high',
    title: '인증/인가 미들웨어가 제거됨',
    description: '이 PR 에서 인증·인가 미들웨어/데코레이터가 삭제되었습니다. 해당 엔드포인트가 비인증 상태로 노출될 수 있습니다.',
    recommendation: '의도된 변경인지 확인하고, 다른 위치(라우터 레벨 등)에서 동일한 보호가 적용되는지 검증하세요.',
    target: 'removed',
    pattern: /(authenticate\w*|requireAuth|isAuthenticated|ensureAuth\w*|ensureLoggedIn|verifyToken|authMiddleware|passport\.authenticate|checkJwt|jwtAuth|@login_required|@permission_required|@PreAuthorize|@Secured|@RolesAllowed|@UseGuards|@Authorized|Depends\(\s*get_current_\w+|before_action\s+:authenticate\w*|requireRole|authorize\w*)/,
  },
  {
    id: 'rate-limit-removed',
    category: 'API4',
    severity: 'medium',
    title: '레이트 리밋/스로틀링이 제거됨',
    description: '요청 횟수 제한 로직이 삭제되었습니다. 브루트포스나 리소스 고갈 공격에 노출될 수 있습니다.',
    recommendation: '엔드포인트별 레이트 리밋(특히 로그인, OTP, 결제 등 민감 흐름)을 유지하세요.',
    target: 'removed',
    pattern: /(rateLimit\w*|RateLimit\w*|rate_limit\w*|[tT]hrottle\w*|limiter|slowDown)/,
  },
  {
    id: 'mass-assignment',
    category: 'API3',
    severity: 'high',
    title: '요청 body 전체를 모델에 바인딩 (Mass Assignment)',
    description: '요청 body 를 필드 선별 없이 그대로 생성/수정에 사용합니다. `role`, `isAdmin`, `balance`, `ownerId` 같은 민감 속성을 클라이언트가 덮어쓸 수 있습니다.',
    recommendation: '허용 필드만 명시적으로 골라내세요 (`pick(req.body, ["name","bio"])`, DTO/스키마 검증, Rails strong params `permit(:name)`).',
    pattern: /(\.(create|update|insert|save|build|updateOne|updateMany|findByIdAndUpdate|findOneAndUpdate|upsert|merge|assign_attributes|update_attributes)\s*\([^)]*\b(req|request|ctx\.request)\.body\b(?!\s*[.\[])|Object\.assign\([^)]*\b(req|request)\.body\b(?!\s*[.\[])|\.\.\.\s*(req|request)\.body\b(?!\s*[.\[])|\*\*\s*request\.(json|data|form|get_json\(\))|params\.permit!|\.update\(\s*params\[:\w+\]\s*\))/,
  },
  {
    id: 'excessive-data-exposure',
    category: 'API3',
    severity: 'medium',
    title: '사용자 객체 전체를 응답으로 반환',
    description: 'DB 사용자 객체를 그대로 직렬화해 반환합니다. 비밀번호 해시, 토큰, 내부 플래그 등이 노출될 수 있습니다.',
    recommendation: '응답 DTO/serializer 로 필요한 필드만 반환하세요.',
    pattern: /((res|reply)\.(json|send)\(\s*(user|users|account|accounts|member|profile)\s*\)|jsonify\(\s*(user|users)\.__dict__|return\s+(user|account)\.__dict__)/,
    unless: /(select\(|omit|exclude|toJSON|serialize|Serializer|DTO|password\s*:\s*0|-password|sanitize|toPublic)/i,
    window: 6,
  },
  {
    id: 'jwt-verification-disabled',
    category: 'API2',
    severity: 'critical',
    title: 'JWT 서명/만료 검증 비활성화',
    description: '`none` 알고리즘 허용, 서명 검증 끄기, 만료 무시 등으로 토큰 위조가 가능합니다.',
    recommendation: '알고리즘을 명시적으로 고정(`algorithms: ["RS256"]`)하고 서명·만료 검증을 항상 켜세요.',
    pattern: /(algorithms?\s*[:=]\s*\[?\s*['"]none['"]|verify_signature['"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|parseUnsecuredClaims|parseClaimsJwt\(|setSigningKey\(\s*""\s*\))/i,
  },
  {
    id: 'jwt-decode-without-verify',
    category: 'API2',
    severity: 'medium',
    title: 'jwt.decode() 사용 (서명 검증 없음)',
    description: '`jsonwebtoken` 의 `decode()` 는 서명을 검증하지 않습니다. 이 결과로 인증/인가 결정을 하면 토큰 위조가 가능합니다.',
    recommendation: '인증 판단에는 반드시 `jwt.verify(token, key, { algorithms: [...] })` 를 사용하세요.',
    pattern: /\bjwt\.decode\(/,
    files: JS,
  },
  {
    id: 'weak-jwt-secret',
    category: 'API2',
    severity: 'high',
    title: '추측 가능한 JWT/세션 시크릿',
    description: '`secret`, `changeme` 같은 약한 하드코딩 키로 토큰을 서명합니다. 키를 추측하면 임의 토큰을 발급할 수 있습니다.',
    recommendation: '충분히 긴 랜덤 키를 비밀 저장소/환경변수에서 주입하세요.',
    pattern: /(jwt\.(sign|verify)\([^)]*|secretOrKey\s*:\s*|SECRET_KEY\s*=\s*|JWT_SECRET\w*\s*[:=]\s*|session\(\s*\{[^}]*secret\s*:\s*)['"](secret|changeme|change-me|password|123456|test|dev|default|mysecret|keyboard cat)['"]/i,
  },
  {
    id: 'hardcoded-secret',
    category: 'SECRETS',
    severity: 'high',
    title: '하드코딩된 자격 증명/토큰',
    description: '소스 코드에 API 키나 비밀번호로 보이는 값이 포함되었습니다. 저장소 접근자 누구나 사용할 수 있고 git 히스토리에 영구히 남습니다.',
    recommendation: '키를 즉시 폐기(rotate)하고 환경변수/시크릿 매니저로 옮기세요.',
    pattern: /((api[_-]?key|secret|passwd|password|token|private[_-]?key|access[_-]?key|client[_-]?secret)\w*['"]?\s*[:=]\s*['"][A-Za-z0-9_\-\/+=.]{12,}['"]|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)/i,
    unless: /(process\.env|os\.environ|getenv|System\.getenv|ENV\[|example|placeholder|dummy|xxxx|your[_-]|<.*>|\$\{)/i,
    window: 0,
  },
  {
    id: 'sql-injection',
    category: 'INJECTION',
    severity: 'high',
    title: '문자열 결합으로 SQL 쿼리 생성',
    description: '쿼리 문자열을 템플릿/결합/포맷팅으로 만들고 있습니다. 사용자 입력이 섞이면 SQL Injection 이 가능합니다.',
    recommendation: '바인딩 파라미터(`?`, `$1`, `:name`)나 ORM 쿼리 빌더를 사용하세요.',
    pattern: /(\.(query|execute|raw|exec|executeQuery|executeUpdate|createQuery|createNativeQuery|\$queryRawUnsafe|\$executeRawUnsafe)|cursor\.execute|db\.(Exec|Query|QueryRow))\s*\(\s*(`[^`]*\$\{|f['"]|['"][^'"]*['"]\s*(\+|%)|['"][^'"]*['"]\.format\(|\w+\s*\+\s*\w)/,
  },
  {
    id: 'nosql-injection',
    category: 'INJECTION',
    severity: 'high',
    title: '요청 객체를 그대로 NoSQL 쿼리 조건으로 사용',
    description: '`req.body`/`req.query` 를 쿼리 필터로 그대로 넘기면 `{"$ne": null}` 같은 연산자 주입으로 인증 우회·데이터 유출이 가능합니다.',
    recommendation: '필드를 명시적으로 추출하고 타입(string 등)을 검증한 뒤 쿼리에 사용하세요. `mongo-sanitize` 같은 필터도 고려하세요.',
    pattern: /(\.(find|findOne|where|count\w*|update\w*|delete\w*)\(\s*(req|request)\.(body|query)\s*[,)]|\$where\s*:)/,
  },
  {
    id: 'ssrf',
    category: 'API7',
    severity: 'high',
    title: '사용자 입력 URL 로 서버가 직접 요청 (SSRF)',
    description: '요청 파라미터로 받은 URL 로 서버가 HTTP 요청을 보냅니다. 내부망(169.254.169.254 메타데이터, 내부 관리 API 등)에 접근하는 데 악용될 수 있습니다.',
    recommendation: '허용 도메인 allowlist 를 적용하고, DNS 해석 후 사설/링크로컬 IP 를 차단하며, 리다이렉트를 제한하세요.',
    pattern: new RegExp(String.raw`\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|needle|superagent\.get|requests\.(?:get|post|put|request)|urlopen|httpx\.(?:get|post)|http\.(?:Get|Post)|\w*[rR]estTemplate\.\w+|request)\s*\(\s*[^)]*` + REQ),
    unless: /(allow_?list|whitelist|ALLOWED_(HOSTS|DOMAINS)|isAllowedUrl|validateUrl|isSafeUrl|ssrf)/i,
    window: 5,
  },
  {
    id: 'cors-wildcard',
    category: 'API8',
    severity: 'medium',
    title: 'CORS 전체 허용',
    description: '모든 Origin 을 허용하는 CORS 설정입니다. 쿠키/자격증명과 함께 쓰이면 타 사이트에서 사용자 데이터를 읽을 수 있습니다.',
    recommendation: '신뢰할 Origin 만 명시적으로 허용하세요.',
    pattern: /(Access-Control-Allow-Origin['"]?\s*,\s*['"]\*|origin\s*:\s*(['"]\*['"]|true)\s*[,}]|allow_origins\s*=\s*\[\s*['"]\*['"]|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|AllowAllOrigins\s*:\s*true|allowedOrigins\(\s*"\*"\)|cors\(\s*\)\s*\))/i,
  },
  {
    id: 'verbose-error',
    category: 'API8',
    severity: 'medium',
    title: '스택 트레이스/디버그 정보 노출',
    description: '에러 스택이나 디버그 모드를 외부 응답에 노출합니다. 내부 구조, 경로, 라이브러리 버전이 공격자에게 유출됩니다.',
    recommendation: '클라이언트에는 일반화된 에러 메시지와 요청 ID 만 반환하고 상세 내용은 서버 로그에 남기세요.',
    pattern: /(\.(json|send)\([^)]*\b(err|error|e|ex)\.stack\b|traceback\.format_exc\(\)|^\s*DEBUG\s*=\s*True|\.run\([^)]*debug\s*=\s*True|printStackTrace\(\))/,
  },
  {
    id: 'tls-verification-disabled',
    category: 'API10',
    severity: 'high',
    title: 'TLS 인증서 검증 비활성화',
    description: '외부 API 호출 시 인증서 검증을 끄면 중간자 공격으로 응답을 위조당할 수 있습니다.',
    recommendation: '인증서 검증을 켜고, 사설 CA 가 필요하면 해당 CA 만 신뢰하도록 설정하세요.',
    pattern: /(rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|_create_unverified_context|TrustAll\w*|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)/,
    unless: /jwt/i,
    window: 0,
  },
  {
    id: 'unbounded-page-size',
    category: 'API4',
    severity: 'low',
    title: '페이지 크기 상한 없음',
    description: '클라이언트가 지정한 limit/size 값을 상한 없이 사용합니다. 한 번에 대량 데이터를 요청해 DB/메모리를 고갈시킬 수 있습니다.',
    recommendation: '`Math.min(limit, 100)` 처럼 최대값을 강제하세요.',
    pattern: new RegExp(String.raw`\b(?:limit|take|per_?page|page_?size|pageSize|size|count)\w*\s*[:=]\s*(?:parseInt\(|Number\(|int\(|\+)?\s*` + REQ, 'i'),
    unless: /(Math\.min|\bmin\(|clamp|MAX_\w+|max_\w+|\ble\s*=|\blte\b|<=|\.max\()/i,
    window: 3,
  },
  {
    id: 'debug-or-legacy-endpoint',
    category: 'API9',
    severity: 'low',
    title: '디버그/레거시 엔드포인트 추가',
    description: '`/debug`, `/test`, `/v0`, `/legacy` 같은 엔드포인트는 운영 환경에 남아 관리되지 않는 공격 표면이 되기 쉽습니다.',
    recommendation: '운영 빌드에서 제외하거나 인증 뒤로 숨기고, API 인벤토리에 등록하세요.',
    pattern: new RegExp(ROUTE.slice(0, -1) + String.raw`)[^)]*\/(?:v0|beta|test|debug|old|legacy|tmp|dev|graphiql|actuator)\b`, 'i'),
  },
];

const isComment = (s: string) => /^\s*(\/\/|\/\*|\*|#(?![\[!])|--\s)/.test(s);

interface Located { file: string; line?: number; evidence: string }

export function runStaticRules(files: ChangedFile[], rules: Rule[] = RULES): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    const { lines } = parsePatch(file.patch);
    const addedText = lines.filter((l) => l.type === 'add').map((l) => l.content).join('\n');

    for (const rule of rules) {
      if (rule.files && !rule.files.test(file.filename)) continue;
      const wantType: DiffLine['type'] = rule.target === 'removed' ? 'del' : 'add';

      lines.forEach((dl, idx) => {
        if (dl.type !== wantType || isComment(dl.content)) return;
        const match = rule.pattern.exec(dl.content);
        if (!match) return;

        if (rule.target === 'removed') {
          // 같은 토큰이 다시 추가됐다면 이동/리팩터링으로 간주
          if (addedText.includes(match[0])) return;
        } else if (rule.unless) {
          const around = windowText(lines, idx, rule.window ?? 0, rule.scope === 'handler');
          if (rule.unless.test(around)) return;
        }

        const loc: Located = {
          file: file.filename,
          // 삭제 라인은 new-side 번호가 없으므로 바로 앞의 new-side 라인에 붙인다
          line: dl.newLine ?? nearestNewLine(lines, idx),
          evidence: dl.content.trim().slice(0, 200),
        };
        const key = `${rule.id}:${loc.file}:${loc.line}`;
        if (seen.has(key)) return;
        seen.add(key);
        out.push({
          id: `S${out.length + 1}`,
          source: 'static',
          ruleId: rule.id,
          ...loc,
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          description: rule.description,
          recommendation: rule.recommendation,
        });
      });
    }
  }
  return out;
}

function windowText(lines: DiffLine[], idx: number, w: number, handlerScoped: boolean): string {
  let from = Math.max(0, idx - w);
  let to = Math.min(lines.length - 1, idx + w);
  if (handlerScoped) {
    // 위쪽: 가장 가까운 라우트 시작까지 / 아래쪽: 다음 라우트 시작 직전까지
    for (let i = idx; i >= from; i--) if (lines[i].type !== 'del' && ROUTE_START.test(lines[i].content)) { from = i; break; }
    for (let i = idx + 1; i <= to; i++) if (lines[i].type !== 'del' && ROUTE_START.test(lines[i].content)) { to = i - 1; break; }
  }
  return lines.slice(from, to + 1).filter((l) => l.type !== 'del').map((l) => l.content).join('\n');
}

function nearestNewLine(lines: DiffLine[], idx: number): number | undefined {
  for (let i = idx; i >= 0; i--) if (lines[i].newLine) return lines[i].newLine;
  for (let i = idx; i < lines.length; i++) if (lines[i].newLine) return lines[i].newLine;
  return undefined;
}
