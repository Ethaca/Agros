# 12. `argos init` 설계

> **상태: v1 구현됨 (LLM 없는 경로, express-sqlite 어댑터). LLM 초안과 `--update`/`--check`는 아직 없다.** 아래 "구현 상태" 표가 실제 상태다. 목적: 저장소를 읽어 `argos.config.yaml` 초안을 만들고, 그 초안으로 앱이 실제로 뜨고 로그인되는지 확인한 뒤, 사람이 확인할 목록을 남긴다.

```
argos init <저장소|openapi.json> [--update|--check] [--llm-data none|files] [--out argos.config.yaml] [--isolation process|container] [--no-verify] [--force]
```

## 단계
```
 ① 정적 스캔      LLM 없음, 결정적        → 사실 수집
 ② 근거 수집      코드 밖에서도            → 기대 규칙(expect)의 근거
 ③ LLM 초안       선택 파일만, 선택 사항   → 설정 JSON + 필드별 근거·확신도
 ④ 시험 환경 구성  토큰·시드·페르소나       → 결정적 규칙 (LLM이 만들지 않음)
 ⑤ 검증           스키마 → 기동 → 로그인    → 실패하면 어디가 문제인지
 ⑥ 출력           설정 + 확인할 목록 + 지표
```
LLM은 ③에서만, 선택적으로 쓴다. ①②④⑤⑥은 LLM 없이 동작해야 한다(키가 없거나 `--llm-data none`이면 템플릿 초안).

## ① 정적 스캔: 무엇을 어떻게 찾나
| 찾는 것 | 규칙 |
|---|---|
| 기동 명령 | `package.json`의 `scripts.start`가 `node …`이면 그대로, 아니면 `npm start`; 없으면 `main` → `node <main>`; 없으면 `app/server/index` 파일. 못 찾으면 "탐지 불가" |
| 포트 | 소스에 `process.env.PORT` 사용 여부(Argos는 `PORT`를 넘긴다). 없으면 하드코딩 가능성을 확인 목록에 올림 |
| 라우트 | `app/router.get|post|put|patch|delete("/경로", …)`. 경로의 `:param`, 핸들러 안의 `req.query.X`/구조분해, `req.body.X`, 참조 테이블(`FROM/JOIN/INTO/UPDATE`), 쓰기 여부(INSERT/UPDATE/DELETE) |
| 라우트별 인증 | 경로 뒤 미들웨어 이름이 `auth/jwt/session/passport/protect/guard/login/verify`류이거나, 앞선 `app.use(<auth>)`(경로 한정 포함)가 있으면 인증 있음 |
| 헬스 경로 | `/health`, `/healthz`, `/ping`, `/ready`, `/live`, `/status` 라우트. 없으면 `/health` + 확인 목록 |
| 스키마 | `*.sql`(시드·테스트 제외)을 메모리 SQLite에 실행해 테이블·컬럼을 읽는다. 실행 실패(다른 방언)면 "지원 안 함" |
| 소유 컬럼 | 컬럼명 우선순위 `vendor_id`, `org_id`, `organization_id`, `tenant_id`, `account_id`, `company_id`, `customer_id`, `owner_id`, `user_id`. 테이블 이름이 `vendors/orgs/tenants/accounts/companies/customers`류면 기본키 |
| 민감 컬럼 | 기본 목록(`api_key`, `token`, `secret`, `password`) + 이름에 `secret/token/key/password/credential`이 든 추가 컬럼 |
| DB | `node:sqlite`/`better-sqlite3`/`sqlite3` → SQLite. `pg`, `mysql2`, `mongoose`, `prisma` 등 → 지원 안 함. 경로는 `new DatabaseSync(process.env.X ?? "./data.db")`에서 환경변수명과 기본값 |
| 호출자 식(`fix.principal`) | 소유 컬럼 이름과 같은 속성의 `req.user.<속성>`(`req.user.vendor_id`) |
| 환경 카나리 후보 | 소스의 `process.env.X`와 `.env.example` 키 중 `SECRET/KEY/TOKEN/PASSWORD/CREDENTIAL`이 든 것 |

**환경 카나리에서 제외해야 하는 것:** 토큰을 읽는 환경변수(예: `DEMO_TOKENS`), DB 경로 변수, `PORT`, `target.env`에 이미 있는 키. 이 변수에 카나리를 주입하면 앱의 인증·DB가 깨져서 시험 자체가 무너진다(4b 부작용).

## ② 기대 규칙(`expect`)은 코드에서 추정하지 않는다
순환 논리(코드의 버그를 규칙으로 학습) 방지가 이 설계의 핵심이다.
- 근거 우선순위: 사람이 확인한 이전 설정 → OpenAPI 보안 정의·README·역할 문서 → **보수적 기본값**(소유자 `allow`, 다른 조직 `deny`, 익명 `deny`).
- `public: true`는 **데이터로 판단**하고 사람이 확인한다: 헬스 계열이거나, 인증이 없는 GET이면서 참조하는 테이블이 **모두 소유 컬럼도 민감 컬럼도 없는** 경우만 후보. 참조 테이블이 없는 라우트(예: `/debug/env`)나 소유 테이블을 참조하는 라우트는 공개로 보지 않는다(인증 없는 `export` 같은 결함이 규칙으로 굳는 것을 막는다).
- 경로가 `/debug`, `/admin`, `/internal`, `/env`, `/metrics`, `/_`류면 소유자도 `deny`.
- GET이 아닌 라우트는 핸들러가 SELECT만 하면 `safe: true` 후보(확인 필요), 쓰기가 있으면 제외하고 "시험하지 않음"으로 기록.
- 소유 테이블을 찾지 못한 `:id` GET 라우트는 설정 스키마상 표현할 수 없으므로 리소스로 넣지 않고 **시험 못 한 경로 목록**에 이유와 함께 남긴다.

**출처 표시:** 설정에 `provenance`(필드 → `confirmed` | `ai-draft`)를 둔다. init이 만든 `expect`/`public`/`safe`는 모두 `ai-draft`이고, `scan-meta.json`에 미확인 항목이 기록되며 보고서가 **"미확인 기대 규칙 N개"**로 표시한다. 사람이 확인한 값(`confirmed`)은 `--update`가 바꾸지 못한다.

## ③ LLM 초안 (`--llm-data files`, 선택)
- 하는 일: 라우트 → 리소스 id·소유 테이블 매핑 보정, 쿼리 파라미터 후보, 페르소나·조직 이름, 모호한 단서 해석.
- **하지 않는 일:** 판정, `confirmed` 필드 변경, 토큰 값 생성, `expect`를 코드 동작에 맞추기.
- 출력은 JSON이고 필드마다 `근거(파일:줄)`와 `확신도`. `Config` 스키마로 검증하고 실패하면 오류를 넣어 1회 재시도, 그래도 실패하면 ①②④의 템플릿으로 대체.
- 키는 `ANTHROPIC_API_KEY` 환경변수로만, 모델은 `ARGOS_MODEL`(기본 `claude-sonnet-5-5`).
- **전송 정책:** 선택한 파일만. `.env`, 키 파일, `node_modules`, 락 파일, 큰 파일은 제외. 비밀 패턴(`sk-…`, 토큰 값)은 마스킹. 보낸 파일 목록을 출력하고 `out/init-egress.json`에 기록(LLM을 쓰지 않았으면 빈 목록).

## ④ 시험 환경 구성 (결정적 규칙)
| 인증 방식 | 처리 |
|---|---|
| 토큰이 환경변수에서 오고 **기본값 `token:org,…`이 코드에 있음** | 코드에 있는 시험 토큰을 그대로 페르소나로 사용(`target.env` 주입 없음) |
| 토큰 환경변수는 있으나 기본값 없음 | 시험용 토큰을 생성해 `target.env`와 페르소나에 넣음(결정적: 저장소 이름 해시 기반). 형식은 `token:org`로 가정하고 확인 목록에 올림 |
| JWT / 세션·쿠키 / 알 수 없음 | **v1 미지원.** "사람이 필요"로 남기고 이유와 안내를 출력 |
| 인증 없음 | 자리표시 페르소나 + "인증이 발견되지 않음" 경고 |
- 페르소나: 인증된 2개(서로 다른 조직) + 익명. 토큰은 **시험용 값만**, 운영 토큰처럼 보이면(`sk-…`, 긴 JWT) 거부·경고.
- 격리: 초안은 `isolation: container`. 도커가 없으면 검증을 건너뛰지 않고 오류로 알리며 `--isolation process`(신뢰하는 코드만)를 안내.

## ⑤ 검증 (실제로 해 본다)
1. `Config` 스키마 통과
2. **기동:** 초안으로 앱을 띄워 `readyPath`가 200 (실패하면 로그 끝 50줄)
3. **로그인 대조:** 각 페르소나가 소유 데이터를 읽을 수 있는지(토큰 설정이 맞는지) — 초안으로 `scan`을 한 번 돌려 대조 칸이 🟢인지로 확인
4. **시드 가능성:** 소유 테이블·컬럼이 실제로 존재하는지

## ⑥ 출력
- `argos.config.yaml`: 필드마다 주석(`ai-draft · 근거 파일:줄`, 확인 필요 표시).
- `out/init-report.md`: 찾은 것, 가정, **사람이 확인할 목록**, 지원 안 되는 것, 시험 못 한 경로, 검증 결과.
- 지표: **T1**(시작 → 기동 검증된 설정까지 초), **K**(사람이 확인·입력해야 한 항목 수). **R**(자동 구성 성공률)은 샘플 앱으로 측정하기 전에는 숫자로 약속하지 않는다.
- `out/init-egress.json`.
- 소스는 읽기 전용. 쓰는 것은 설정 파일과 `out/`뿐. 이미 설정이 있으면 `--force` 없이는 덮어쓰지 않는다.

## `--update` / `--check`
- `--update`: 기존 설정을 입력으로 **`confirmed` 필드를 보존**하고 바뀐 부분의 차이만 제안. 근거: 시드 스키마 해시가 `scan-meta`와 다름, 소스에는 있는데 설정에 없는 라우트(시험 범위 공백), 지난 스캔에서 404였던 리소스, 지난 스캔의 ⚪ 사유.
- `--check`: CI에서 설정이 낡았는지만 확인("소스에 라우트 N개, 시험 M개"). 기본은 경고, 차단하지 않음.
- 기준선: 지난 결과의 발견 키(`check|resource|persona|column`)를 작은 파일로 커밋해 "기존 🔴" 대 "새로 생긴 🔴"을 구분.

## 어댑터 구조 (프레임워크 확장)
`init`은 **공통 파이프라인 + 스택별 어댑터**로 만든다. 어댑터가 ①(사실 수집)과 ④(시험 환경)의 스택별 부분을 맡고, ②③⑤⑥과 출력 형식·`provenance`·전송 정책은 공통이다.
| 어댑터 | 상태 | 맡는 것 |
|---|---|---|
| `express-sqlite` | 🔶 v1 | 라우트·스키마(SQLite)·Bearer 시험 토큰 |
| `spring-boot` | ⬜ 계획 (`docs/SPRING_SUPPORT_PLAN.md`) | Maven/Gradle 격리 빌드, SecurityFilterChain·JWT, JPA·PostgreSQL·Flyway, 시험 JWT issuer |

Spring 계획과의 접점(해당 문서는 다른 작업이며 이 문서는 그것을 대체하지 않는다):
- 공통 원칙은 이미 같다: 기대 정책의 근거 위치·확인 상태 기록(= `provenance`), 기존에 검토된 정책을 새 코드에 맞춰 자동 완화하지 않기, 정상 대조가 실패하면 차단을 안전 근거로 쓰지 않기, 관측할 수 없는 리소스는 "검증 불충분".
- **설정·보고서 PR은 검증된 코드 수정이 없어도 만든다.** CI에서 `init`(또는 `--update`)이 만든 설정 초안은 PR로 올려 사람이 확인하게 한다. 이 PR이 `ai-draft` → `confirmed`로 바꾸는 확인 절차다.
- **PR 쓰기 자격증명은 고객 코드·빌드·LLM에 전달하지 않는다.** 앱 프로세스 환경은 비우고(`PATH/HOME/PORT/target.env`만), 컨테이너에는 호스트 환경을 아예 전달하지 않는다. PR 게시는 고객 코드 실행이 모두 끝난 뒤 Argos 프로세스가 수행한다. 어댑터가 빌드 단계를 추가해도 이 분리를 유지해야 한다.
- 현재 한계(Spring 지원에 필요한 변경): SQLite 시드와 Bearer/익명 인증, `owner/other/anonymous` 기대값만 지원하고, 컨테이너 포워더가 이미지 안의 `node`에 의존한다. Postgres, 실제 서명된 JWT, 역할·행동 단위 정책, Java 이미지에서의 포워더는 별도 설계가 필요하다.

## v1 범위
Express + SQLite + 환경변수·시드 기반 Bearer 토큰(데모 앱 형태). 나중: JWT·DB 사용자·쿠키 인증, Postgres, 다른 프레임워크의 라우트 탐지. 못 찾은 것은 추정으로 채우지 않고 **"탐지 불가"로 명시**한다.

## 테스트 계획
- 데모 앱 2종: 초안이 스키마를 통과하고 기동·로그인까지 되며, 그 초안으로 `scan`한 🔴 집합이 손으로 쓴 설정과 같다.
- 스텁 LLM으로 `.env` 값이 요청 본문에 없음, 키 없음/`--llm-data none`이면 템플릿만 쓰고 소스를 보내지 않음.
- 인증 방식별(JWT 등) 미지원 안내, 토큰 환경변수에 카나리가 주입되지 않음, 이미 설정이 있을 때 덮어쓰지 않음.

## 구현 상태
| 단계 | 상태 |
|---|---|
| ① 정적 스캔, ④ 시험 환경 구성, ⑤ 검증, ⑥ 출력 (LLM 없이, `express-sqlite`) | ✅ `src/init/` |
| `provenance`(설정), `scan-meta.json`의 `unconfirmed`, 보고서의 "미확인 기대 규칙" 경고 | ✅ |
| ② 코드 밖 근거(OpenAPI 보안 정의, README, 역할 문서) | ⬜ 지금은 보수적 기본값만 |
| ③ LLM 초안 + 전송 정책(`--llm-data files`) | ⬜ (`--llm-data none`만 동작, `init-egress.json`은 항상 빈 목록) |
| `--update`, `--check`, 기준선 비교 | ⬜ |
| `spring-boot` 어댑터 | ⬜ (`docs/SPRING_SUPPORT_PLAN.md`) |

## 실측 (데모 앱, 설정 파일을 지운 저장소에서)
- `argos init`: **T1 0.6초, K 5**(vendor-platform) / 3(realistic-app). 앱 기동과 3개 페르소나 로그인까지 검증됨.
- 초안으로 `scan`한 🔴 집합이 A의 수기 설정과 **하나만 빼고 일치**한다(리소스 이름 차이는 매핑해 비교). 차이는 `GET /api/vendors/:id`의 다른 벤더 읽기(bola 6건): 이 앱은 "벤더 프로필은 다른 벤더에게 공개"가 의도인데, 이 업무 규칙은 코드에서 알 수 없어 보수적 기본값이 `deny`로 잡은 것이다.
- 사람이 그 한 줄(`other: allow`)을 바꾸고 `provenance`를 `confirmed`로 두면 realistic-app은 🔴 0건이 된다. 나머지 규칙은 계속 "미확인"으로 표시된다.
- 이것이 이 설계의 의도된 동작이다: 오탐은 사람이 확인할 곳을 정확히 가리키고, 취약한 코드가 규칙으로 굳는 일은 없다.

## 구현 메모
- 정적 스캔은 SQL을 **문자열 리터럴 안에서만** 찾는다(주석의 "... into the SQL"을 테이블로 읽는 오류를 시험으로 고정).
- `POST /api/export?datasetId=`처럼 쓰기 라우트에 쿼리를 붙이지 않는다(sqli는 GET만 시험).
- 검증은 초안으로 `scan`을 한 번 돌려 대조 칸(소유자 본인 접근)이 🟢인지로 로그인을 확인한다. 그때 나오는 🔴/🟡 숫자는 **미리보기**이며 확인되지 않은 규칙 기준이라 판정이 아니다.
- 이미 설정이 있으면 덮어쓰지 않는다(`--force`). 설정 파일 외에는 `--report` 디렉터리에만 쓴다(소스 불변).
- 기본 격리는 `container`. 도커가 없으면 설정은 쓰되 검증은 실행하지 않고 종료 코드 1과 `--isolation process`/`--no-verify` 안내.
