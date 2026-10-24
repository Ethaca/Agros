# 03. 설정 (`argos.config.yaml`)

검증은 Zod 스키마(`src/config.ts`)로 한다. 알 수 없는 키·누락 필드는 오류이며, 첫 줄에 위치와 이유를 내고 나머지 개수를 덧붙인다(실제 출력: `argos: target.start: Invalid input: expected string, received undefined (+2 more)`). 전체 예시는 `examples/argos.config.yaml`, 실제 사용 예는 `demo/*/argos.config.yaml`.

## 주요 섹션
| 키 | 뜻 | 기본값 |
|---|---|---|
| `target.start` | 앱 기동 명령(필수) | - |
| `target.cwd`, `baseUrl`, `readyPath`, `env` | 작업 디렉터리, `:0`은 빈 포트로 대체, 200을 기다릴 경로, 앱 환경변수(비밀 금지) | `.`, `http://127.0.0.1:0`, `/health`, `{}` |
| `target.isolation` | `process` \| `container` | `process` |
| `target.container` | `image`, `memory`, `cpus`, `pids` (jvm: `buildImage`, `sidecarImage`, `dbImage`도) | node:<호스트 major>-slim, 512m, 1, 256 |
| `target.runtime` | `node` \| `jvm`(Spring Boot: 격리 빌드 + PostgreSQL + 테스트 JWT issuer, `isolation: container` 필수) | `node` |
| `target.build` | jvm 빌드 명령(없으면 Maven/Gradle wrapper로 결정) | 없음 |
| `seed.schema`, `dbPath` | 시드할 SQLite 스키마와 DB 경로 | - |
| `db` | jvm 전용 `{kind: postgres, image, migrations: flyway\|liquibase\|app\|none, env{url,user,password}}`. `seed`와 함께 쓸 수 없다 | `postgres:16-alpine`, `app`, `SPRING_DATASOURCE_URL/USERNAME/PASSWORD` |
| `auth` | jvm 전용 `{type: jwt-issuer, env{jwkSetUri, issuerUri}, audience, claims{subject: id\|email\|username, roles{claim, prefix}, extra}}` | `SPRING_SECURITY_OAUTH2_RESOURCESERVER_JWT_JWK_SET_URI`/`_ISSUER_URI`, `id`, `roles` |
| `personas[]` | `name`, `org`, `auth`(`bearer` 토큰 \| `none` \| `jwt`), `user`(시드 사용자 키, 기본=name), `roles`, `invalid`(`wrong-signature`\|`expired`) | - |
| `resources[]` | `id`, `route`, `owner{table,column,scope: org\|user}`, `expect{owner,other,anonymous,sameOrgOther?,member?}`, `public`, `safe`, `params`, `roles`, `action`, `pathParams`, `body`, `query`, `writeVerify` | - |
| `checks` | 실행할 점검 | 4종 전부 |
| `secrets` | `sensitiveColumns`, `allowOwnerSecretRead`, `envCanaries`, `staticScan`, `staticExclude` | 아래 참고 |
| `fix.principal` | 핸들러 안에서 호출자 조직을 가리키는 식. 예: `req.user.vendor_id` | 없음 |
| `provenance` | 필드별 출처: `confirmed`(사람) \| `ai-draft`. 키는 `resources.<id>.expect`/`.public`/`.safe`, `personas`, `fix.principal`. `argos init`이 채우고, 미확인 항목은 `scan-meta.json`과 보고서에 표시된다 | 없음 |
| `mode` | `report` \| `block` | `report` |
| `llm` | `init`의 LLM 전송 범위(`files` \| `none`) | `files` |

`secrets` 기본값: `sensitiveColumns: [api_key, token, secret, password]`(이름에 포함되면 민감), `allowOwnerSecretRead: false`, `envCanaries: [JWT_SECRET, SECRET_KEY, API_KEY, STRIPE_SECRET_KEY]`, `staticScan: true`.

## 검증 규칙 (스키마가 강제)
- 페르소나·리소스 이름은 중복 불가.
- **익명 페르소나 1개 이상**, **인증된 페르소나 2개 이상**(벤더 간 접근을 시험하려면 필요). 인증된 페르소나는 `org` 필수.
- `public`이 아닌 리소스는 `expect` 필수.
- `:id`가 있는 GET 리소스는 `owner` 필수(소유 컬럼을 알아야 마커로 판정).
- 비밀(토큰 값)은 **시험용 값**만. 운영 토큰을 넣으라고 안내하지 않는다. `jwt` 페르소나는 설정에 토큰이 없다(실행마다 테스트 issuer가 발급).
- `jwt` 페르소나는 최상위 `auth`가 필요하고, `auth`·`db`는 `runtime: jvm`에서만, jvm은 `isolation: container`에서만 허용. `invalid`는 `jwt` 페르소나에만.
- 같은 조직의 페르소나는 사용자 키(`user` 또는 name)가 달라야 한다. `pathParams`의 키는 라우트에 있는 파라미터여야 한다. `writeVerify`·`owner.scope: user`는 `db` 필요.

## 라우트 표기
- `"METHOD /path/:id"` 또는 `"METHOD /path/{id}"`. 파라미터는 시드된 행의 id로 채운다. `pathParams: {projectId: {table: projects}, documentId: {table: documents, column?}}`로 파라미터마다 다른 테이블의 id를 쓸 수 있다(없으면 마지막 파라미터=소유 행, 앞 파라미터는 이름으로 테이블 추정).
- `body`/`query` 템플릿 자리표시자: `$org`, `$orgId`, `$user`, `$userId`, `$marker`, `$unique`, `$id:<table>`. `body`가 없으면 `{}`.
- `action`(`read|create|update|delete`)은 기본값이 메서드에서 정해진다(GET=read, POST=create, PUT/PATCH=update, DELETE=delete).
- `"GET /api/datasets?search="`처럼 **쿼리 파라미터를 라우트에 적으면 sqli가 그 파라미터를 시험**한다. 요청 자체는 쿼리 없이 보낸다. 별도 지정은 `params: [search]`.
- GET이 아닌 라우트는 `safe: true`일 때만 호출한다. 아니면 칸이 ⚪(건너뜀).
- `public: true`: 의도된 공개(오탐 방지). 모든 페르소나에 `allow`를 기대한다.

## `expect`와 소유자
`owner`(자기 조직의 행), `other`(다른 조직의 행), `anonymous`. 소유 행이 없는 리소스(예: `POST /api/export`, `/debug/env`)는 인증된 페르소나를 `owner`, 익명을 `anonymous`로 본다.
- `owner.scope: user`: 행이 조직 안의 한 사용자 소유(`owner.column` = 사용자 FK). `sameOrgOther`(같은 조직 다른 사용자, 기본 `deny`)가 추가된다. org 범위 행에는 같은 조직 칸이 없다(조직 공용 데이터).
- `roles`: 허용 역할. 역할이 없는 페르소나는 `member`(기본 `deny`)를 기대한다. 역할은 `ROLE_` 접두사·대소문자를 무시하고 비교.
- `invalid` 페르소나와 익명은 공개가 아닌 모든 리소스에 `anonymous`(보통 `deny`)를 기대한다.
- `writeVerify{table, column, where?}`: 쓰기 전후 DB의 `column` 값(행 수 + 해시)을 비교한다. `where` 기본값은 대상 행의 PK. 쓰기는 jvm에서 `safe: true` + `db` + 컨테이너일 때만 실행한다.

## jvm 시드 (PostgreSQL)
앱의 migration이 끝난 뒤 실제 스키마(information_schema·pg_catalog)를 읽어 FK 순서·PK(UUID/identity/sequence)·NOT NULL·unique·enum·CHECK IN 목록을 만족하는 행을 만든다. 조직 테이블은 `owner`의 FK 대상(없으면 `org_id`류 컬럼·이름 휴리스틱), 사용자 테이블은 `scope: user` FK 대상 또는 email/username을 가진 `users`류 테이블. 페르소나의 (조직, 사용자)마다 사용자 행(역할 컬럼 = 페르소나 역할), 조직별·사용자별 리소스 행을 만든다. 토큰의 `sub`는 `claims.subject`에 따라 사용자 PK·email·username. 마커는 title/name/description/body 등 응답에 나올 법한 텍스트 컬럼에, 비밀 마커는 `sensitiveColumns`에 심는다. 구조를 판단할 수 없으면 `SeedError` → 실행 전체가 **미검증(unsupported)**.
