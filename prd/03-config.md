# 03. 설정 (`argos.config.yaml`)

검증은 Zod 스키마(`src/config.ts`)로 한다. 알 수 없는 키·누락 필드는 오류이며, 첫 줄에 위치와 이유를 내고 나머지 개수를 덧붙인다(실제 출력: `argos: target.start: Invalid input: expected string, received undefined (+2 more)`). 전체 예시는 `examples/argos.config.yaml`, 실제 사용 예는 `demo/*/argos.config.yaml`.

## 주요 섹션
| 키 | 뜻 | 기본값 |
|---|---|---|
| `target.start` | 앱 기동 명령(필수) | - |
| `target.cwd`, `baseUrl`, `readyPath`, `env` | 작업 디렉터리, `:0`은 빈 포트로 대체, 200을 기다릴 경로, 앱 환경변수(비밀 금지) | `.`, `http://127.0.0.1:0`, `/health`, `{}` |
| `target.isolation` | `process` \| `container` | `process` |
| `target.container` | `image`, `memory`, `cpus`, `pids` | node:<호스트 major>-slim, 512m, 1, 256 |
| `seed.schema`, `dbPath` | 시드할 SQLite 스키마와 DB 경로 | - |
| `personas[]` | `name`, `org`, `auth`(`bearer` 토큰 또는 `none`) | - |
| `resources[]` | `id`, `route`, `owner{table,column}`, `expect{owner,other,anonymous}`, `public`, `safe`, `params` | - |
| `checks` | 실행할 점검 | 4종 전부 |
| `secrets` | `sensitiveColumns`, `allowOwnerSecretRead`, `envCanaries`, `staticScan`, `staticExclude` | 아래 참고 |
| `fix.principal` | 핸들러 안에서 호출자 조직을 가리키는 식. 예: `req.user.vendor_id` | 없음 |
| `mode` | `report` \| `block` | `report` |
| `llm` | `init`의 LLM 전송 범위(`files` \| `none`) | `files` |

`secrets` 기본값: `sensitiveColumns: [api_key, token, secret, password]`(이름에 포함되면 민감), `allowOwnerSecretRead: false`, `envCanaries: [JWT_SECRET, SECRET_KEY, API_KEY, STRIPE_SECRET_KEY]`, `staticScan: true`.

## 검증 규칙 (스키마가 강제)
- 페르소나·리소스 이름은 중복 불가.
- **익명 페르소나 1개 이상**, **인증된 페르소나 2개 이상**(벤더 간 접근을 시험하려면 필요). 인증된 페르소나는 `org` 필수.
- `public`이 아닌 리소스는 `expect` 필수.
- `:id`가 있는 GET 리소스는 `owner` 필수(소유 컬럼을 알아야 마커로 판정).
- 비밀(토큰 값)은 **시험용 값**만. 운영 토큰을 넣으라고 안내하지 않는다. v1은 Bearer/없음만 지원.

## 라우트 표기
- `"METHOD /path/:id"`. `:param`은 시드된 행의 id로 채운다.
- `"GET /api/datasets?search="`처럼 **쿼리 파라미터를 라우트에 적으면 sqli가 그 파라미터를 시험**한다. 요청 자체는 쿼리 없이 보낸다. 별도 지정은 `params: [search]`.
- GET이 아닌 라우트는 `safe: true`일 때만 호출한다. 아니면 칸이 ⚪(건너뜀).
- `public: true`: 의도된 공개(오탐 방지). 모든 페르소나에 `allow`를 기대한다.

## `expect`와 소유자
`owner`(자기 조직의 행), `other`(다른 조직의 행), `anonymous`. 소유 행이 없는 리소스(예: `POST /api/export`, `/debug/env`)는 인증된 페르소나를 `owner`, 익명을 `anonymous`로 본다.
