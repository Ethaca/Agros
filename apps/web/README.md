# 🔐 Argos

GitHub OAuth 로 로그인하고 레포에서 **보호 켜기**만 누르면, 이후 올라오는 PR 을 자동으로 검사해
**BOLA(IDOR)** 를 비롯한 **OWASP API Security Top 10 (2023)** 위협을 PR 코멘트로 알려주는 보안 도구입니다.

이제 발견한 문제를 **변경 → 새롭게 가능한 접근 → 발생 가능한 영향**으로 설명하는 **AI 보안 내비게이터**를 제공합니다.
바이브코더와 AI를 사용하는 개발자가 경고를 이해하고 직접 검증할 수 있도록, 분류별 핵심 개념·흔한 오해·생각해 볼 질문·검토 체크리스트도 함께 보여줍니다.

## 보안 영향 지도와 학습

- **PR 자동 분석:** PR 제목·본문을 문맥으로 활용합니다. 최대 10개 변경 파일과 상대 import로 찾은 최대 5개 관련 JS/TS 파일을 같은 head 커밋에서 수집해 분석합니다.
- **근거 구분:** AI가 인용한 파일·줄 번호·변경 전후·코드 조각이 실제로 전달한 입력과 맞는 경우에만 “코드 근거 포함”으로 표시합니다. 인용이 맞는다는 것은 그 해석이나 공격 성공을 증명하는 것이 아닙니다.
- **조건과 대안:** 누락된 상위 미들웨어나 배포 설정 등 확인할 조건, 목적을 유지하는 구현 대안, 정상·거부 동작을 확인할 방법을 보여줍니다.
- **고치면서 학습:** 같은 보안 분류의 학습 자료를 모아서 제공합니다. 예를 들어 BOLA에서는 “로그인 성공과 객체 소유권 확인은 다르다”는 개념을 질문·해설·직접 체크할 항목으로 배웁니다. 웹 결과와 GitHub 리뷰 모두에서 볼 수 있습니다.

현재는 **코드 기반 영향 분석**이며 애플리케이션이나 공격 요청을 실행하지 않습니다. 모든 경로는 “실행 미검증”으로 표시됩니다.
키가 없거나 AI 호출에 실패해도 정적 탐지에 따른 일반적인 위험 경로와 학습 자료를 제공합니다.
관련 파일은 직접적인 상대 import만 수집하므로 경로 별칭·다단계 호출·전체 배포 환경은 확인 범위 밖입니다.

```
PR opened/synchronize ──webhook──▶ Argos
                                    ├─ 1. 변경 파일 + diff + (head 기준) 전체 파일 내용 수집
                                    ├─ 2. 정적 룰 엔진: 후보를 넓게 탐지 (21개 룰, 다국어)
                                    ├─ 3. Claude LLM: 문맥 분석 + 정적 결과 오탐 판정 + 추가 탐지
                                    └─ 4. PR 에 게시
                                         ├─ 요약 코멘트 (푸시할 때마다 같은 코멘트를 갱신)
                                         ├─ 인라인 리뷰 코멘트 (해당 라인에)
                                         └─ commit status `argos/security` (FAIL_ON 이상이면 failure → 브랜치 보호로 머지 차단)
```

## Threat Radar: 실시간 위협 대응

`/radar` 에서 보호 중인 레포에 영향을 주는 위협을 공식 권고보다 먼저 확인하고 대응합니다.

- **수집 (Cron, 10분마다):** GitHub Advisory DB, 벤더 레포 권고(`php/php-src`, `nodejs/node`, `python/cpython`), Hacker News(Algolia API), CISA KEV. 레포를 읽을 때 OSV 로 이미 알려진 취약 버전도 조회합니다. 화면의 **지금 수집**(1분에 한 번)으로 바로 수집할 수도 있습니다.
- **매칭:** lock 파일(`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`), `package.json`/`composer.json`, `Dockerfile`·compose 이미지, `.nvmrc`·`.python-version`·`.tool-versions`, GitHub Actions 의 `*-version`. 범위로만 적힌 버전은 "영향 가능"으로 표시합니다.
- **신뢰도와 조치:** 보호 중인 레포와 매칭된 위협만 보여주고, 단계에 따라 조치가 열립니다. 서버에서도 다시 확인합니다.

| 단계 | 조건 | 열리는 조치 |
|---|---|---|
| L1 소문 | 커뮤니티 글 1건, 취약점 관련으로 판정 | 대시보드 알림 |
| L2 교차 확인 | 서로 다른 출처 2곳 또는 공신력 있는 도메인 | + GitHub Issue (완화책 중심) |
| L3 공식 | GHSA · OSV · 벤더 권고 | + 버전업 PR 초안 (Dockerfile, 런타임 선언 등 한 줄 치환이 가능한 위치) |
| L4 악용 중 | L3 + KEV 등재 또는 독립된 악용 보고 2건 | + 최상단 고정, `urgent` 라벨 |

- **안전장치:** 커뮤니티 원문은 LLM 에 데이터로만 전달하고, LLM 이 지목한 대상은 글에 실제로 이름이 나온 보호 대상일 때만, CVE 는 원문에 있을 때만 받아들입니다. PR 의 패치 버전은 공식 권고에서만 가져오고, 파일이 수집 이후 바뀌었으면 만들지 않습니다. PoC 는 내려받거나 실행하지 않습니다. `ANTHROPIC_API_KEY` 가 없으면 키워드 규칙으로 L1 신호만 만듭니다.
- 비인증 GitHub API 한도(시간당 60회) 안에서 동작하며, `RADAR_GITHUB_TOKEN` 을 넣으면 한도가 늘어납니다.

## 탐지 항목

| 분류 | 예시 |
|---|---|
| **API1 BOLA** | `Order.findById(req.params.id)` 처럼 소유권 조건 없이 ID 로 조회·수정, `:id` 라우트에 소유권 체크 없음, `userId` 를 body/header 에서 받음 |
| API2 인증 | 인증 미들웨어 삭제, `jwt.decode()` 로 인증, `algorithms: ['none']`, 약한 JWT 시크릿 |
| API3 속성 인가 | `update(req.body)` mass assignment, 사용자 객체 통째로 응답 |
| API4 리소스 | 레이트 리밋 삭제, 페이지 크기 상한 없음 |
| API5 기능 인가 | 역할 검사 없는 `/admin` 라우트, `req.headers['x-role']` 신뢰 |
| API7 SSRF | `fetch(req.body.url)` |
| API8 설정 | CORS `*`, 스택 트레이스 노출, `DEBUG=True` |
| API9 인벤토리 | `/debug`, `/v0`, `/legacy` 엔드포인트 추가 |
| API10 외부 API | `rejectUnauthorized: false`, `verify=False` |
| Injection / Secrets | 문자열 결합 SQL, NoSQL 연산자 주입, 하드코딩된 키 |

정적 룰은 일부러 넓게 잡습니다. LLM 은 라우터와 미들웨어 구성까지 보고 각 후보를 `confirmed` 또는 `false_positive` 로 판정하고, 정적 룰이 놓친 문맥 의존 BOLA 도 찾아냅니다.
`ANTHROPIC_API_KEY` 가 없으면 정적 룰만으로 동작합니다.

## 배포 (Cloudflare Workers)

구성: **Workers**(Hono) + **D1**(사용자, 레포, 검사 결과, 위협 신호) + **Queues**(PR 검사, 위협 수집, 레포 읽기. 오래 걸리는 작업을 HTTP 응답과 분리) + **Cron Trigger**(Threat Radar 수집, 10분마다).
D1 데이터베이스와 큐는 첫 `wrangler deploy` 때 자동으로 생성되고, 테이블은 첫 요청 때 자동으로 만들어집니다.

1. **배포**: Cloudflare 대시보드에서 Git 연동을 쓰거나(빌드 명령 없음, 배포 명령 `npx wrangler deploy`) 로컬에서 `npm run deploy` 를 실행합니다.
2. **GitHub OAuth App 생성**: Settings → Developer settings → OAuth Apps
   - Homepage URL: `https://argos.<계정>.workers.dev`
   - Authorization callback URL: `https://argos.<계정>.workers.dev/auth/github/callback`
3. **Secret 등록**: 대시보드 → Workers → argos → Settings → Variables and Secrets, 또는 아래 명령으로 등록합니다.
   ```bash
   npx wrangler secret put GITHUB_CLIENT_ID
   npx wrangler secret put GITHUB_CLIENT_SECRET
   npx wrangler secret put ANTHROPIC_API_KEY    # https://console.anthropic.com/settings/keys
   npx wrangler secret put SESSION_SECRET       # openssl rand -hex 32
   npx wrangler secret put ENCRYPTION_KEY       # openssl rand -hex 32 (바꾸면 저장된 토큰을 복호화할 수 없음)
   ```
4. 접속 → GitHub 로그인 → 레포 **보호 켜기** → PR 을 올리면 자동으로 검사됩니다.

모델, 실패 기준 등 민감하지 않은 설정은 `wrangler.jsonc` 의 `vars` 에 있습니다 (기본 모델 `claude-sonnet-5.5`).
`PUBLIC_URL` 은 생략하면 접속한 origin 을 쓰고, 커스텀 도메인을 쓸 때만 지정하면 됩니다.

요청하는 OAuth 권한은 `repo`(PR 읽기, 코멘트, status), `admin:repo_hook`(webhook 등록·삭제), `read:user` 입니다.

> **플랜 참고**: 외부 API 호출량을 제한하기 위해 검사 한 번에 전체 내용을 가져오는 파일은 최대 15개(변경 파일 10개 + 관련 파일 5개)로 제한했습니다. 큰 PR과 AI 호출이 많은 경우 현재 Workers 플랜의 제한을 확인하세요.

### 화면 (React + Base UI)

화면은 `src/ui` 의 React 컴포넌트로, [Base UI](https://base-ui.com) 의 Menu·AlertDialog·Switch·Select·Combobox·Popover·Tooltip·Toast·Tabs·Accordion·Collapsible·RadioGroup·Checkbox·Field·Avatar 를 씁니다.
Worker 가 `renderToString` 으로 HTML 을 그려 보내고, 브라우저는 같은 컴포넌트를 hydrate 합니다. 상태를 바꾸는 동작은 모두 CSRF 토큰이 든 POST 폼입니다.
`npm run build:ui` 가 Tailwind CSS 와 브라우저 번들을 `public/assets/` 에 만들며, `wrangler dev`·`wrangler deploy` 가 실행 전에 자동으로 돌립니다.

### 로컬 개발

```bash
npm install
cp .dev.vars.example .dev.vars   # 값 채우기
npm run dev                      # wrangler dev (로컬 D1/Queue 사용)
```

로컬에서 webhook 까지 받아보려면 `cloudflared tunnel --url http://localhost:8787` 로 얻은 주소를 `.dev.vars` 의 `PUBLIC_URL` 과 OAuth App 콜백에 넣습니다.

### GitHub 없이 써보기

```bash
npm run scan -- examples/vulnerable-pr.diff            # LLM 포함 (키가 있을 때)
npm run scan -- examples/vulnerable-pr.diff --no-llm   # 정적 룰만
git diff main | npm run scan -- -                      # 내 브랜치 검사 (high 이상이면 exit 1 → CI 에서 사용 가능)
npm run scan -- examples/order-sharing.diff --intent "로그인 없이 배송 상태를 공유하고 싶어요"
npm run scan -- examples/order-sharing.diff --no-llm --json  # 영향 경로를 포함한 JSON
```


## 구조

| 파일 | 역할 |
|---|---|
| `src/worker.ts` | Workers 진입점 (Hono): OAuth, 대시보드, 레포 on/off, webhook 수신 + Queue consumer |
| `src/scanner.ts` | PR 단위 스캔 파이프라인 (같은 커밋은 중복 검사 생략) |
| `src/analyzer.ts` | 정적 룰과 LLM 결과 병합, 오탐 제거, 위험도 산정 |
| `src/impact.ts` | 영향 경로 정규화, 코드 인용 검증, 정적 분석용 기본 경로 |
| `src/learning.ts` | 보안 분류별 핵심 개념, 오해, 질문과 해설, 검토 항목 |
| `src/context.ts` | 저장소 파일 목록을 기준으로 상대 import의 실제 경로 해석 |
| `src/rules.ts` | 정적 룰 정의 |
| `src/llm.ts` | Anthropic Claude Messages API 클라이언트 (공식 SDK, JSON 추출) |
| `src/reporter.ts` | PR 코멘트 마크다운, 인라인 코멘트, status |
| `src/github.ts` | GitHub REST 클라이언트 |
| `src/db.ts` | D1 쿼리 + 스키마 자동 생성 |
| `src/radar.ts` | Threat Radar: 신호 묶기, 신뢰도 단계, 레포 매칭, Issue·PR 초안 |
| `src/feeds.ts` | GHSA, 벤더 권고, OSV, KEV, Hacker News 수집기 |
| `src/manifests.ts` | lock 파일, Dockerfile, 런타임·CI 버전 선언 파서 |
| `src/versions.ts` | 권고 범위와 버전 비교 |
| `src/ui/server.tsx` | Worker 가 부르는 화면 진입점: DB 행을 화면 props 로 옮겨 서버에서 렌더 (토큰 등 서버 전용 필드는 넣지 않음) |
| `src/ui/` | 화면: React + [Base UI](https://base-ui.com) + Tailwind. 서버에서 그리고 브라우저에서 hydrate |
| `src/levels.ts` | 신뢰도 단계 정의 (서버와 화면이 함께 씀) |

## 도구 자체의 보안

- OAuth 토큰과 webhook 시크릿은 AES-256-GCM 으로 암호화해 저장합니다.
- webhook 은 레포마다 랜덤 시크릿을 두고 `X-Hub-Signature-256` 을 검증합니다.
- 레포를 켤 때 GitHub API 로 관리자 권한을 서버에서 다시 확인하고, 스캔 결과 조회와 레포 끄기는 모두 `user_id` 조건으로 소유자를 확인합니다 (이 도구 자체의 BOLA 방지).
- 세션은 HMAC 으로 서명한 쿠키(HttpOnly, SameSite=Lax)를 쓰고, 상태를 바꾸는 POST 는 double-submit CSRF 토큰을 확인합니다.
- PR 요약 코멘트는 **도구 계정이 직접 쓴** 코멘트만 갱신합니다 (다른 사람이 마커를 흉내 낸 코멘트를 덮어쓰지 않음).
- Threat Radar 의 위협·영향 조회와 Issue/PR 생성은 모두 `repos.user_id` 를 조인해 자기 레포의 항목만 다룹니다.

## 한계와 다음 단계

- OAuth App 방식이라 코멘트가 **로그인한 사용자 명의**로 달립니다. 봇 명의와 Check Run UI 가 필요하면 GitHub App 으로 전환해야 합니다.
- 큰 PR 은 최대 6개 배치(배치당 약 60k 자)까지만 LLM 으로 분석합니다.

```bash
npm test
npm run typecheck
```
