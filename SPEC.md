# Argos SPEC (Rebuild, 5시간)

> 기존 `hackathon/argos/` 코드를 **재사용하지 않고 새로 만든다.** 이 문서는 새 빌드의 명세다.
> `ARCHITECTURE.md`, `DEV_PLAN.md`, `ROLE.md`는 기존 코드를 전제한 부분이 있어, **구현 기준은 이 SPEC이 우선**한다(정리는 별도).
> 우선순위: **PROVE + VOUCH + PLUG** 메인, TRACE 후순위, PDF 최하위.
> 확정된 결정: 기본 모드 `report`(비차단) · `argos init`의 LLM 전송 기본 `files` · "API 키 유출" = 응답 속 노출 / 환경 비밀 노출 / 하드코딩 · 개발 시간 5시간 · 개발자 2명(A: 데모·리포트·init, B: 코어·점검).
> 표기: **MUST**(5시간 안), **SHOULD**(시간이 남으면), **LATER**(5시간 밖).

## 1. 목적과 한 줄 정의

> Hand sensitive data and tasks to external vendors, with permissions that are attack-tested and proven, not just configured.

Argos는 실행 중인 API(또는 저장소)를 **여러 페르소나로 실제 공격**해서 "누가 무엇을 볼 수 있는가"를 **기대 vs 실제 접근 매트릭스**로 증명하고, 그 결과를 **증빙 문서**로 내며, 설정은 **AI가 초안**을 쓴다.

## 2. 범위

| 구분 | 내용 |
|---|---|
| **In (MUST)** | 설정 기반 블랙박스 동적 시험, 접근 매트릭스, 점검 4종(`bola`, `unauth`, `sqli`, `secrets`), 증빙 리포트(Markdown + JSON), `argos init`(AI 설정 초안), 데모 대상 앱, CLI |
| **SHOULD** | 자동 수정 제안 + 같은 매트릭스로 재검증, PR 코멘트용 Markdown, GitHub Actions 예시 워크플로, (c) 하드코딩 비밀 정적 패턴 |
| **LATER** | 컨테이너 격리 실행, GitHub App/웹훅 서버, 코드 정적 분석(라우트·싱크 추적), 인증 어댑터(쿠키·SSO), 작업 단위 권한, PDF 내보내기·전송, TRACE(카나리 추적·오염 탐지) |

**설계 결정:** 재빌드는 5시간이므로 기존의 "코드에서 경로 추적(Access Path IR)" 방식을 버리고 **블랙박스**로 간다. 시험 대상 라우트와 기대 접근은 **설정 파일**(`argos.config.yaml`)에서 온다. 설정 초안은 `argos init`이 OpenAPI 또는 소스에서 AI로 만든다. 장점은 구현이 작고 어떤 언어의 앱에도 적용된다는 것이고, 한계는 설정에 없는 경로는 시험하지 않는다는 것이다.

## 3. 용어

| 용어 | 뜻 |
|---|---|
| Target | 시험 대상 앱(실행 중인 HTTP API) |
| Persona | 시험에서 쓰는 주체: 이름, 소유 조직(벤더), 인증 정보. 예: `vendor1`, `vendor2`, `anonymous` |
| Resource | 시험할 엔드포인트와 그 소유자. 예: `GET /datasets/{id}`, 소유 `vendor1` |
| Expectation | 페르소나 × 리소스의 기대: `allow` / `deny` |
| Cell | 매트릭스의 한 칸: 기대, 실제, 판정, 증거 |
| Marker | 시드 데이터에 심는 고유 문자열. 응답에 나타나면 데이터가 노출된 것 |
| Verdict | `VULNERABLE`(🔴) · `SUSPECTED`(🟡) · `OK`(🟢) · `SKIPPED`(⚪) |

## 4. 사용자 흐름

```
 1 argos init <target-dir | openapi.json>     → argos.config.yaml draft (validated, boot-checked)
 2 argos scan                                  → out/matrix.json, out/findings.json
 3 argos fix        (SHOULD)                   → patch proposals, re-verified with the same matrix
 4 argos report                                → out/report.md  (+ evidence header)
 5 CI (SHOULD): workflow runs 2 and 4, posts report.md as a PR comment (non-blocking)
```

## 5. 설정 스키마 (`argos.config.yaml`)

```yaml
version: 1
target:
  start: "node app.mjs"          # 앱 기동 명령 (argos가 자식 프로세스로 실행)
  cwd: "."
  baseUrl: "http://127.0.0.1:0"  # 0 = argos가 빈 포트를 골라 PORT 환경변수로 전달
  readyPath: "/health"
  env: { }                       # 앱에 줄 환경변수 (비밀 금지)
seed:
  schema: "schema.sql"           # 시드할 DB 스키마 (SQLite)
  dbPath: "./data.db"
  rows: "seed.json"              # 선택. 없으면 resources의 owner로 자동 생성
personas:
  - name: vendor1
    org: v1
    auth: { type: bearer, token: "tok-v1" }
  - name: vendor2
    org: v2
    auth: { type: bearer, token: "tok-v2" }
  - name: anonymous
    auth: { type: none }
resources:
  - id: dataset-read
    route: "GET /api/datasets/:id"
    owner: { table: datasets, column: vendor_id }     # 소유 컬럼
    expect: { owner: allow, other: deny, anonymous: deny }
  - id: export
    route: "POST /api/export"
    expect: { owner: allow, other: deny, anonymous: deny }
  - id: health
    route: "GET /health"
    public: true                  # 의도된 공개: 오탐 방지
checks: [bola, unauth, sqli, secrets]
secrets:
  sensitiveColumns: ["api_key", "token", "secret", "password"]   # 이름 패턴 기본값
  allowOwnerSecretRead: false
  envCanaries: ["JWT_SECRET", "SECRET_KEY", "API_KEY", "STRIPE_SECRET_KEY"]
mode: report                      # report(기본, 비차단) | block
llm: { provider: anthropic, data: files }   # files | none
```

- 검증은 Zod 스키마로 한다. 알 수 없는 키·누락 필드는 오류로 처음 한 줄에 위치와 이유를 낸다.
- 비밀(토큰 값)은 **시험용 값**만 허용한다. 실제 운영 토큰을 넣으라고 안내하지 않는다.
- v1은 **Bearer 토큰/없음**만 지원한다. 쿠키·SSO는 LATER.

## 6. 기능 요구사항

### 6.1 Runner (FR-R)

| ID | 요구 | 우선 |
|---|---|---|
| R1 | `target.start`를 자식 프로세스로 기동하고 `readyPath`가 200이 될 때까지 대기(타임아웃 30초, 실패 시 로그 끝 50줄 출력) | MUST |
| R2 | 빈 포트를 골라 `PORT`로 전달, 앱 종료는 SIGTERM 후 5초 뒤 SIGKILL | MUST |
| R3 | **환경 정리**: 부모 환경변수를 넘기지 않는다. `PATH`, `HOME`(임시 디렉터리), `PORT`, 설정의 `target.env`만 전달 | MUST |
| R4 | 시험은 **임시 복사본**에서 실행(원본 저장소와 DB를 수정하지 않음) | MUST |
| R5 | 요청 타임아웃 5초, 전체 시험 타임아웃 설정 가능(기본 5분) | MUST |
| R6 | 컨테이너 격리(네트워크 없음, 읽기 전용, 비root) | LATER |

> ⚠️ R6이 없으므로 **신뢰할 수 없는 코드에는 사용하면 안 된다.** 데모는 우리가 만든 앱만 대상으로 한다. CLI는 시작 시 "격리 없음: 신뢰하는 코드에만 실행" 경고를 출력한다.

### 6.2 시드와 마커 (FR-S)

| ID | 요구 | 우선 |
|---|---|---|
| S1 | SQLite 스키마를 적용하고, 소유자(org)별로 리소스 행을 시드한다 | MUST |
| S2 | 행마다 고유 **마커**(`ARGOS_<resourceId>_<org>_<hex6>`)를 텍스트 컬럼에 넣는다 | MUST |
| S3 | `sensitiveColumns`에 해당하는 컬럼에는 **비밀 마커**(`ARGOS_SECRET_<n>_<hex6>`)를 넣는다 | MUST |
| S4 | 마커는 로그·리포트에 **앞 6자만** 기록한다(전체 값 금지) | MUST |
| S5 | SQLite 외 DB(Postgres 등) | LATER |

### 6.3 점검 (FR-C)

모든 점검은 `Finding { check, resourceId, persona, verdict, proof, detail }`을 낸다. **판정은 실행 증거로만** 한다.

| ID | 점검 | 방법 | 판정 | 우선 |
|---|---|---|---|---|
| C1 | `bola` (소유권·접근 매트릭스) | 모든 페르소나로 모든 리소스(소유 행의 id 포함)를 요청. 응답 상태와 **다른 조직의 마커 포함 여부**로 allow/deny 판단 | 기대 `deny`인데 마커 포함 → 🔴. 기대 `allow`인데 거부 → 🟡(기능 손상) | MUST |
| C2 | `unauth` | `anonymous`로 인증이 필요한 모든 리소스 요청. `public: true`는 제외 | 2xx이고 데이터 마커 포함 → 🔴, 2xx이나 마커 없음 → 🟡 | MUST |
| C3 | `sqli` | 문자열 파라미터에 `"1"`, `"'"`, `"''"` 3단계 시험(대조 → 오류 유도 → 이스케이프 정상 확인) | 대조는 정상, `'`는 오류, `''`는 정상이면 🔴 | MUST |
| C4a | `secrets` (a) 민감 필드 | 시드한 **비밀 마커**가 비소유자·익명 응답에 포함되는지 | 비소유자·익명 → 🔴, 소유자 재노출 → 🟡(`allowOwnerSecretRead`로 허용) | MUST |
| C4b | `secrets` (b) 환경 비밀 | 앱 환경에 고유 값 `ARGOS_ENV_<name>_<hex6>`를 주입하고, 모든 리소스에 정상·오류 유도 요청을 보내 응답 본문과 헤더에서 검색 | 포함되면 🔴 | SHOULD |
| C4c | `secrets` (c) 하드코딩 | 소스 파일에서 비밀 패턴 정규식(`sk-`, `AKIA`, `-----BEGIN`, `*_secret = "..."`) 검색 | 🟡, 값은 마스킹(앞 4자 + 길이) | SHOULD |

**공통 규칙**
- **대조 요청**: 소유자 본인의 정상 접근이 성공해야 한다. 실패하면 해당 점검은 `SKIPPED`로 하고 이유를 낸다(앱이 안 떠서 "안전"으로 보이는 것 방지).
- **4b 부작용 방어**: 환경 주입 후 로그인(대조) 요청이 실패하면 판정을 보류하고 주입 없이 재시험한다.
- **AI는 판정을 낮추지 않는다.** AI는 설명 문구와 수정 제안에만 쓴다.

### 6.4 접근 매트릭스 (FR-M)

| ID | 요구 | 우선 |
|---|---|---|
| M1 | 페르소나 × 리소스 전체 칸을 만든다. 칸: `{persona, resource, expected, observed, verdict, evidence}` | MUST |
| M2 | `expected`는 설정의 `expect`에서 계산한다(`owner`/`other`/`anonymous`) | MUST |
| M3 | `observed`는 `allow`(2xx + 자기/타인 마커 규칙) 또는 `deny`(401/403/404) 또는 `error` | MUST |
| M4 | `evidence`는 요청 줄, 상태 코드, 응답의 일부(마커는 앞 6자)만 담는다 | MUST |
| M5 | 매트릭스 JSON과 사람이 읽는 표(터미널·Markdown) 두 가지 출력 | MUST |

**`observed` 판정 규칙:** 2xx이고 **요청한 리소스 소유자의 마커**가 응답에 있으면 `allow`. 401/403이면 `deny`. 404는 `deny`(존재 은닉, 단 소유자 요청의 404는 `error`). 2xx인데 마커가 없으면 `allow-empty`로 기록하고 🟡.

```json
{
  "personas": ["vendor1", "vendor2", "anonymous"],
  "resources": ["dataset-read", "export"],
  "cells": [
    { "persona": "vendor2", "resource": "dataset-read",
      "expected": "deny", "observed": "allow", "verdict": "VULNERABLE",
      "evidence": { "request": "GET /api/datasets/d1", "status": 200, "marker": "ARGOS_" } }
  ]
}
```

### 6.5 수정과 재검증 (FR-F) — SHOULD

| ID | 요구 |
|---|---|
| F1 | 🔴 칸마다 수정 제안을 만든다. 규칙 기반(`WHERE ... AND <owner_col> = ?`, `SELECT *` → 비민감 컬럼 목록)이 먼저, 안 되면 LLM(`llm.data: files`)으로 제안 |
| F2 | 수정은 **임시 복사본**에 적용하고 **같은 매트릭스를 다시 실행**한다 |
| F3 | 채택 조건: 문제 칸이 ✅, 대조 칸 유지, **새 🔴 없음**, 앱이 기동 |
| F4 | 채택하지 못하면 "수정 지침"만 출력하고 파일은 바꾸지 않는다 |
| F5 | 원본 저장소를 자동으로 바꾸지 않는다. `--apply`를 줄 때만 쓴다 |

### 6.6 증빙 리포트 (FR-V)

| ID | 요구 | 우선 |
|---|---|---|
| V1 | `out/report.md`: 요약, 매트릭스 표, 점검별 결과, 증거, 수정 결과, **한계 문구** | MUST |
| V2 | **증빙 헤더**: 대상 이름, 설정 파일 SHA-256, 시드 파일 SHA-256, 실행 시각(UTC), 도구 버전, 점검 목록, 페르소나 목록, 범위·한계 | MUST |
| V3 | 한계 문구(필수): "이 문서는 **시험한 공격과 설정한 페르소나**에 대한 결과다. 보안을 보증하거나 규정 준수를 증명하지 않는다. 해시는 파일을 고정할 뿐 위·변조 방지가 아니다." | MUST |
| V4 | 비밀·마커 전체 값은 싣지 않는다(앞 6자) | MUST |
| V5 | PR 코멘트용 요약(마크다운, 길이 제한) | SHOULD |
| V6 | PDF 내보내기, 전송(허용 목록, 확인, 기록) | LATER, 최하위 |

### 6.7 `argos init` (FR-I) — PLUG

| ID | 요구 | 우선 |
|---|---|---|
| I1 | 입력: 소스 디렉터리 또는 `openapi.json`. 출력: `argos.config.yaml` 초안 | MUST |
| I2 | **정적 스캔(LLM 없음)**: `package.json`, 진입 파일, 라우트 파일, `schema.sql`/`schema.prisma`, `.env.example`로 기동 명령·포트·health 후보·테이블·소유 컬럼 후보 추출 | MUST |
| I3 | **템플릿 초안**: I2의 힌트로 채운다. 키가 없거나 `--llm-data none`일 때의 기본 경로 | MUST |
| I4 | **LLM 초안**(기본 `files`): 선택 파일만 전송 → JSON → `Config` 스키마(Zod)로 검증, 실패하면 오류를 넣어 1회 재시도 후 템플릿으로 폴백 | SHOULD |
| I5 | **전송 정책**: `.env`·키 파일·`node_modules`는 보내지 않는다. 비밀 패턴(`sk-...`, 토큰 값)은 마스킹 후 전송. 보낸 파일 목록을 출력하고 `out/init-egress.json`에 기록 | MUST (I4를 할 때) |
| I6 | **기동 검증**: 초안으로 실제로 앱을 띄워 `readyPath` 확인, 로그인(대조) 확인 | MUST |
| I7 | **편의 지표 출력**: T1(시작→기동 검증된 설정까지 초), K(사용자가 채워야 한 항목 수), 성공/실패 | MUST |
| I8 | 지표 R(자동 구성 성공률)은 샘플 앱 3종으로 측정해 문서에 기록. **측정 전에는 숫자로 약속하지 않는다** | SHOULD |

LLM 호출은 `@anthropic-ai/sdk`를 쓰고 모델 ID는 `ARGOS_MODEL` 환경변수로 받는다(기본 `claude-sonnet-5-5`). 키는 `ANTHROPIC_API_KEY` 환경변수로만 받는다.

### 6.8 CLI (FR-L)

```
argos init   <dir|openapi.json> [--llm-data none|files] [--out argos.config.yaml]
argos scan   [--config argos.config.yaml] [--checks bola,unauth,sqli,secrets] [--out out/]
argos fix    [--config ...] [--apply]                       # SHOULD
argos report [--scan out/] [--format md] [--out out/report.md]
```

- 종료 코드: `0` 정상(🔴 없음 또는 `mode: report`), `1` 오류, `2` `mode: block`이고 🔴가 있을 때. **기본 모드가 `report`이므로 기본은 🔴가 있어도 0.**
- 모든 출력에서 비밀·마커는 앞 6자만 보인다.

### 6.9 PR 연동 (FR-G) — SHOULD

- v1은 **GitHub Actions 워크플로 예시**(`examples/argos.yml`)만 제공한다: 체크아웃 → `argos scan` → `argos report` → `gh pr comment`로 `report.md` 게시.
- 웹훅 서버·GitHub App은 LATER.
- 코멘트 게시는 **워크플로가 하는 것**이고 CLI는 외부로 아무것도 보내지 않는다.

## 7. 데모 대상 (`demo/vendor-platform`)

- Express + `node:sqlite`, 벤더 3곳 × 데이터셋 × 작업.
- 의도적 결함(각각 점검 하나와 대응):

| # | 결함 | 점검 |
|---|---|---|
| 1 | `GET /api/datasets/:id`가 소유자 확인을 안 함(벤더 간 읽기) | `bola` |
| 2 | `POST /api/export`가 인증 없이 동작 | `unauth` |
| 3 | `GET /api/datasets?search=`가 문자열을 이어 붙임 | `sqli` |
| 4 | `GET /api/vendors/:id`가 `SELECT *`로 `api_key`를 반환 | `secrets` (a) |
| 5 | `GET /debug/env`가 환경을 덤프 | `secrets` (b) |

- 정상 대조: 소유 벤더 본인의 접근, 공개 엔드포인트(`/health`, `/api/products`).
- 수동 재현 스크립트(`manual-exploit.sh`)를 함께 둔다. **Argos 결과와 수동 재현이 일치**하는지가 데모의 신뢰 근거다.

## 8. 비기능 요구사항

| 항목 | 요구 |
|---|---|
| 안전 | 대상에게 **읽기 중심** 요청만. `POST /export` 등 쓰기는 설정에 `safe: true`로 명시한 경우만 시험 |
| 비밀 | LLM 키·시험 토큰은 환경변수/설정 파일로만. 저장소에 커밋하지 않고 리포트·로그에 전체를 싣지 않는다 |
| 재현성 | 같은 설정·시드·앱이면 같은 매트릭스(마커의 `hex6`은 설정 파일 해시로 시드해 결정적) |
| 성능 | 샘플 앱 기준 `scan` 60초 이내(목표, 측정해서 기록) |
| 오류 | 앱 기동 실패, 대조 실패, 설정 오류는 **"안전"이 아니라 `SKIPPED`/오류**로 낸다 |
| 호환 | Node 25, pnpm, macOS/Linux |

## 9. 기술 스택과 디렉터리

- **TypeScript(ESM) + Node 25 + pnpm**, 실행은 `tsx`. 검증은 **Zod**, CLI는 가벼운 라이브러리(`commander` 등), HTTP 클라이언트는 내장 `fetch`.
- 새 디렉터리: `hackathon/1024/argos/` (기존 `hackathon/argos/`와 분리).

```
argos/
├─ src/
│  ├─ cli.ts                 # (B) command wiring
│  ├─ config.ts              # (B) Zod schema + loader
│  ├─ runner.ts              # (B) spawn target, ports, ready check, scrubbed env
│  ├─ seed.ts                # (B) sqlite schema + markers
│  ├─ http.ts                # (B) persona requests
│  ├─ matrix.ts              # (B) cells + expected/observed rules
│  ├─ checks/{bola,unauth,sqli,secrets}.ts   # (B)
│  ├─ fix/                   # (B, SHOULD)
│  ├─ report.ts              # (A) report.md + evidence header
│  └─ init/{scan,template,llm,egress,verify}.ts   # (A)
├─ demo/vendor-platform/     # (A)
├─ examples/argos.yml        # (A, SHOULD)
├─ test/                     # unit + e2e against demo
└─ package.json
```

## 10. 인수 기준 (5시간 종료 시)

1. `argos scan`이 데모 앱에서 **결함 1~3과 4(a)**를 🔴로, 정상 대조 칸을 ✅로 낸다(5(b)는 SHOULD). 수동 재현 스크립트와 결과가 일치한다.
2. 매트릭스에서 **소유 벤더의 정상 접근은 허용 유지**다. 오탐: 공개 엔드포인트에 🔴 0건.
3. `argos report`가 증빙 헤더(해시, 시각, 범위, 한계)를 낸다. **헤더의 해시가 파일에서 다시 계산한 값과 일치**한다.
4. `argos init`이 샘플 앱 3종 중 데모 앱에서 **스키마를 통과하는 설정 초안**을 만들고 기동 검증까지 한다. T1·K를 출력한다. `.env` 값이 LLM 요청 본문에 없다(스텁 클라이언트 테스트).
5. 앱 기동 실패·대조 실패 시 "안전"이 아니라 `SKIPPED`/오류가 난다.
6. 데모 3분 안에 `init → scan → (fix) → report`가 재생된다.

## 11. 테스트 계획

| 구분 | 테스트 | 기대 |
|---|---|---|
| unit | `config` 스키마: 필수 누락, 알 수 없는 키, 잘못된 enum | 위치·이유 포함 오류 |
| unit | `matrix` expected/observed 규칙(2xx+마커, 401/403, 404, allow-empty) | 표대로 판정 |
| unit | 마커·마스킹: 출력에 앞 6자만 | 전체 값이 로그·리포트에 없음 |
| unit | `sqli` 3단계 판정(대조 정상/오류 유도/이스케이프 정상) | 🔴/🟢 구분 |
| e2e | 데모 앱 scan | 결함 칸 🔴, 정상 칸 ✅, 수동 재현과 일치 |
| e2e | 결함 없는 앱(`demo/clean`) | 🔴 0건 |
| e2e | 앱 기동 실패 | `SKIPPED` + 로그 끝 |
| e2e | 대조 실패(토큰 오류) | `SKIPPED`, "안전" 아님 |
| e2e | secrets(a) 열 제한 수정 후 재검증 (SHOULD) | ✅ 유지, 새 🔴 없음 |
| report | 증빙 헤더 해시 재계산 | 일치 |
| init | `.env`가 있는 저장소, 스텁 LLM 클라이언트 | 요청 본문에 `.env` 값 없음 |
| init | 키 없음 / `--llm-data none` | 템플릿 초안, 소스 미전송 |

## 12. 5시간 일정과 역할 (재빌드 기준)

| 시간 | B — 코어·점검 | A — 데모·리포트·init |
|---|---|---|
| 0:00–0:30 | 함께: 프로젝트 골격(`pnpm`, TS, Zod), **config 스키마·매트릭스 JSON·Finding 형식 확정** | 같음 |
| 0:30–2:00 | `runner`, `seed`, `http`, `matrix`, **bola + unauth** | **데모 앱**(결함 5종, 정상 대조), `manual-exploit.sh` |
| 2:00–3:00 | `sqli`, **secrets (a)** (+ (b) SHOULD) | **report.ts**(매트릭스, 증빙 헤더, 한계) |
| 3:00–4:00 | (SHOULD) 규칙 기반 수정 + 매트릭스 재검증 | **`argos init`**(정적 스캔, 템플릿, 기동 검증, T1·K) → (SHOULD) LLM 초안·송신 정책 |
| 4:00–5:00 | 통합, e2e, **리허설 2회**, 동결 | 같음 |

- **크리티컬 패스:** B의 0:30–2:00(`runner` → `matrix` → `bola`). 2:00에 매트릭스가 데모에서 나오지 않으면 **bola를 페르소나 쌍 순차 실행 + 표 출력으로 단순화**하고 문서에 밝힌다.
- **자르는 순서:** ① init의 LLM 경로(템플릿만) → ② secrets (b) → ③ 자동 수정(수정 지침만) → ④ PR 워크플로 예시 → ⑤ 리포트 서식. **bola 매트릭스, secrets (a), 증빙 헤더, init 템플릿 + 기동 검증은 끝까지 지킨다.**
- 파일 소유: A = `src/report.ts`, `src/init/`, `demo/`, `examples/`; B = 나머지 `src/`. 계약(config 스키마, 매트릭스 JSON, Finding)을 바꾸면 바로 알린다.

## 13. 위험과 열린 질문

| 위험 | 대응 |
|---|---|
| 설정을 사용자가(또는 AI가) 잘못 쓰면 거짓 안전/거짓 위험 | 대조 칸 필수, 기동·로그인 검증, 대조 실패는 SKIPPED |
| 블랙박스는 설정에 없는 경로를 못 본다 | 리포트의 범위 문구에 시험한 리소스 목록을 명시. 라우트 자동 발견은 LATER |
| 격리가 없다(R6) | 경고 출력, 데모는 자체 앱만, 컨테이너는 LATER |
| 5시간 안에 처음부터 만든다 | 위의 자르는 순서, 코어 크리티컬 패스 점검 |
| 소스 일부가 LLM으로 나간다 | `files` 기본, 마스킹, 제외 목록, 전송 목록 기록, `--llm-data none` |
| 이 영역에 이미 경쟁 제품이 있다 | 차별점(공격 증명 + 증빙 문서 + 쉬운 세팅)은 미검증 가설로 둔다 |

**열린 질문**
1. 새 코드 위치를 `hackathon/1024/argos/`로 해도 되는가(기존 `hackathon/argos/`는 그대로 둠)?
2. 격리 없이 프로세스로 실행하는 v1을 받아들이는가(데모는 자체 앱만)?
3. 블랙박스 + 설정 기반(경로 자동 추적 포기)으로 가는 것에 동의하는가?
4. PR 연동은 v1에서 Actions 예시까지만으로 충분한가?
5. 5시간에 작업하는 인원과 시연 청중.
