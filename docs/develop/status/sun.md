# B 진행 현황 (코어·점검)

> 담당: 개발자 B. 기준: `docs/SPEC.md` 6절·10절·12절. 갱신: 2026-10-24.
> 표기: ✅ 완료 · 🔶 진행 · ⬜ 대기 · SHOULD = 시간이 남으면.

## 도식

```
 [계약]     ✅ config.ts   설정 스키마 (Zod) + loader
            ✅ types.ts    Finding / Matrix / Verdict 계약
               │
 [Step 1]   ✅ runner.ts   앱 기동 · 빈 포트 · ready 체크 · 환경 정리 · 임시 복사본
 [Step 2]   ✅ seed.ts     SQLite 시드 · 마커/비밀 마커 · 마스킹(앞 6자) · 결정적 hex6
 [Step 3]   ✅ http.ts + matrix.ts   페르소나 요청 · expected/observed 판정 · 매트릭스 JSON·표
 [Step 4]   ✅ checks/bola.ts, unauth.ts        ← 크리티컬 패스 끝
 [Step 5]   ✅ scan.ts + cli.ts scan   (out/matrix.json, findings.json)
 [Step 6]   ✅ checks/sqli.ts, secrets.ts  (a) 민감 필드 + (b) 환경 카나리
 [Step 7]   ✅ fix/  (SHOULD)  규칙 기반 수정 + 같은 매트릭스 재검증
 [데모 실측] ✅ A의 demo/ 앱에서 scan 동작 확인, 오탐·대조 문제 수정
               │
 [Step 8]   🔶 통합 · 시나리오 기반 테스트 · 동결
               ├─ ✅ 8-1 시나리오 테스트 (test/scenarios/, 데모 앱 기준, 15개)
               ├─ ✅ 8-2 성능 측정 (scan 0.8초, scan+fix+재scan 3.1초 — S10에서 매번 측정)
               └─ ⬜ 8-3 A의 report / init 연결 (A push 이후)
```

## 요약

| 상태 | 항목 | 파일 | 테스트 |
|---|---|---|---|
| ✅ | 계약 + config | `src/config.ts`, `src/types.ts` | 8개 |
| ✅ | runner | `src/runner.ts` | 8개 |
| ✅ | seed | `src/seed.ts` | 9개 |
| ✅ | http + matrix | `src/http.ts`, `src/matrix.ts` | 10개 |
| ✅ | bola + unauth + sqli | `src/checks/*` | 14개 |
| ✅ | secrets (a)(b) | `src/checks/secrets.ts` | 7개 |
| ✅ | scan 명령 (fixture e2e) | `src/scan.ts`, `src/cli.ts` | 11개 |
| ✅ | fix (규칙 기반 + 재검증) | `src/fix/*` | 8개 |
| ✅ | 시나리오 (데모 앱, 실제 CLI) | `test/scenarios/*` | 16개 |
| ✅ | 출력 예시 + `scan-meta.json` | `examples/out/*`, `src/types.ts`(`ScanMeta`) | 3개 |

단위 테스트 82개 + 시나리오 16개 모두 통과.

## 완료 내용

- **계약:** 설정 스키마(알 수 없는 키 거부, 위치를 앞에 둔 한 줄 오류), `Finding`/`Matrix` 타입. 증거의 `marker`는 6자까지만 허용.
- **runner:** `target.start` 실행, `readyPath` 200 대기(30초), 부모 환경변수 차단(`PATH`/`HOME`/`PORT`/`target.env`만), 임시 복사본 실행, SIGTERM 후 5초 뒤 SIGKILL, 기동 실패 시 로그 끝 50줄, `beforeStart` 훅(시드), `extraEnv`(환경 카나리).
- **seed:** 소유 테이블 × 조직별 한 행, 소유자 마커·비밀 마커, `<x>_id` 컬럼을 같은 조직의 행에 연결, `maskMarker`/`redact`, 설정 해시 기반 결정적 마커.
- **http / matrix:** 페르소나별 요청(5초 타임아웃, 연결 오류는 SKIPPED), 페르소나 × 리소스 × 대상 조직 매트릭스, SPEC 6.4 observed 규칙, 마스킹된 증거, Markdown 표. 조직 마커는 어느 테이블 것이든 인정, 호출자 범위로 응답하는 목록은 `deny`.
- **bola / unauth:** 매트릭스 칸에서 Finding 생성. 공격자·소유자 대조 요청이 성공하지 않으면 SKIPPED(죽은 앱·만료 토큰이 "안전"으로 보이지 않게). 증명된 유출(🔴)은 대조 없이도 보고.
- **sqli:** 리소스의 `params`와 라우트의 `?search=`에서 파라미터를 읽어 `"1"`(대조) → `"'"` → `"''"` 3단계. 대조 2xx + `'` 5xx + `''` 2xx면 🔴, 대조 실패는 SKIPPED.
- **secrets:** (a) 매트릭스 요청의 원본 응답(본문·헤더)에서 비밀 마커 검색. 비소유자·익명 🔴, 소유자 재노출 🟡(`allowOwnerSecretRead`로 허용). (b) 앱 환경에 `ARGOS_ENV_<NAME>_<hex6>`를 주입하고 응답에서 검색. "유출 없음"은 2xx가 있거나 모두 기대대로 거부된 리소스에만 인정.
- **scan:** `argos scan [--config] [--checks] [--out] [--timeout]`. 임시 복사본 → 시드 → 앱 기동 → 매트릭스 → 점검 → `out/matrix.json`, `out/findings.json`. 종료 코드 0/1/2, 전체 타임아웃 기본 5분.
- **scan-meta.json:** `scan`이 `out/scan-meta.json`도 쓴다(`ScanMeta` 계약). 증빙 헤더 재료: 설정·시드 스키마·`matrix.json`·`findings.json`의 SHA-256, 실행 시각(UTC), 도구 버전, 점검·페르소나·시험 리소스 목록, 판정별 개수. 절대 경로·비밀 없음. A의 `report`는 해시를 직접 계산하지 않고 이 파일을 읽으면 된다.
- **출력 예시:** `examples/out/`(`matrix.json`, `findings.json`, `scan-meta.json`, `README.md`). `vendor-platform` 실제 스캔 결과이고 필드 설명이 README에 있다. 테스트가 스키마·해시·최신 여부를 지킨다.
- **fix:** `argos fix [--config] [--out] [--apply]`. 기계적으로 고치는 건 `SELECT * FROM <table>` → 비민감 컬럼 목록뿐, 소유자 검사·인증·파라미터화·환경 노출은 수정 지침만 출력. 패치는 임시 복사본에 적용해 **같은 매트릭스를 다시 실행**하고, ① 대상 Finding 해결 ② 대조 칸 유지 ③ 새 🔴 없음 ④ 앱 기동일 때만 채택. 원본은 `--apply`일 때만 수정. 결과는 `out/before/`, `out/after/`, `out/fix.json`.

## 데모 앱 실측 (A의 `demo/`)

| 앱 | 🔴 | 🟡 | ⚪ | 비고 |
|---|---|---|---|---|
| `vendor-platform` | 25 | 3 | 0 | 결함 1~5 모두 🔴. 🟡은 소유자의 `api_key` 재노출(의도) |
| `realistic-app` | 0 | 0 | 0 | 오탐 0 (구 `clean`) |

- `manual-exploit.sh`와 일치(`vendor-platform` 5/5 재현, 안전한 앱 0/5).
- `fix`: `SELECT * FROM vendors` → `SELECT id, name, contact_email FROM vendors`(안전한 앱의 수정과 동일). 🔴 25→19, 🟡 3→0, 원본 불변.
- 데모에서 발견해 고친 것: `?search=`에서 sqli 파라미터 읽기 / 목록 라우트 오탐 / 다른 테이블 마커 인정 / `<x>_id` 시드 연결 / 증명된 유출은 대조 없이 보고 / secrets (b) 구현 / 모두 거부된 리소스는 유출 없음으로 판정.

## Step 8: 시나리오 기반 테스트 (구현됨)

`rehearse.sh` 대신 **시나리오 테스트**로 간다. 합격·불합격이 자동으로 갈리고, 동결 뒤 A가 계약을 바꿔도 `pnpm test`에서 바로 드러나며, SPEC 10절 인수 기준을 실행 가능한 형태로 남긴다. 리허설(시연 연습)은 사람이 하고, "시연이 깨지지 않는다"는 보장만 테스트로 가져간다.

위치: `test/scenarios/`. A의 실제 데모 앱(`demo/`) 기준으로만 작성하고, 기존 `test/scan.test.ts`(작은 fixture 앱)와 겹치지 않게 한다. 실제 CLI를 띄워 종료 코드, 출력 파일, 원본 파일 변화를 확인한다. 데모 앱은 임시 복사본에서 돌려 `fix --apply`가 `demo/`를 건드리지 않게 한다. `demo/*/node_modules`가 없으면 건너뛰고 이유를 출력한다.

| # | 시나리오 | 확인하는 것 (SPEC 10절) |
|---|---|---|
| S1 | 고객이 결함 앱을 스캔한다 | 결함 1~5가 🔴, 정상 대조 칸 🟢, 공개 엔드포인트 오탐 0 (기준 1·2) |
| S2 | 안전한 앱을 스캔한다 | `realistic-app`에서 🔴 0건, ⚪ 0건 (기준 2) |
| S3 | 수동 재현과 맞춰 본다 | `manual-exploit.sh` 결과와 Argos 🔴이 같은 결함을 가리킨다 (기준 1) |
| S4 | 수정하고 다시 검증한다 | `fix`가 열 제한 패치를 검증, `--apply` 없이 원본 불변, 적용 후 재스캔에서 해당 🔴 소멸·새 🔴 없음 |
| S5 | 앱이 안 뜬다 | 종료 코드 1 + 로그 끝, "안전"으로 나오지 않는다 (기준 5) |
| S6 | 토큰이 틀렸다 | 대조 실패가 ⚪, 🟢이 없다 (기준 5) |
| S7 | 모드와 종료 코드 | `mode: report`는 🔴이 있어도 0, `mode: block`은 2 |
| S8 | 같은 설정으로 두 번 돌린다 | 두 매트릭스가 같다 (재현성) |
| S9 | 결과 파일이 안전하다 | `matrix.json`, `findings.json`, `fix.json`에 마커·비밀·카나리 전체 값이 없다 |
| S12 | 출력 예시가 최신이다 | `examples/out/`가 새로 스캔한 결과와 일치(시각 제외) |
| S10 | 시연 3분 흐름 | `scan` → `fix` → 재스캔의 총 시간을 재서 기록 (목표 60초/scan, 기준 6) |
| S0, S11 | (A 구현 후 추가) | `init` 초안이 스키마를 통과하고 기동 검증까지, `report` 증빙 헤더 해시가 재계산 값과 일치 (기준 3·4) |

실행: `pnpm run test:scenarios`(시나리오만), `pnpm run test:unit`(단위만), `pnpm test`(둘 다).
파일: `test/scenarios/demo.scenarios.test.ts`(시나리오), `test/scenarios/helpers.ts`(앱 복사·CLI 실행·수동 재현 파싱). `demo/*/node_modules`가 없으면 시나리오 전체를 건너뛰고 설치 명령을 출력한다.

구현하며 확인한 점:
- S3는 `manual-exploit.sh`의 `[VULN] <번호>`를 파싱해 Argos의 🔴(결함 1~5)과 번호 단위로 대조한다. `fix --apply` 뒤에는 curl 결과도 결함 4만 사라진다(`[1,2,3,5]`).
- S6: 토큰이 틀려도 `export`는 로그인이 필요 없는 결함이라 다른 조직 데이터가 나오므로 🔴이 유지된다(증명된 유출). 로그인이 필요한 리소스는 전부 ⚪/🟡이고 🟢·🔴이 없다.
- S10 실측: `scan` 0.8초(두 앱 모두), `scan` + `fix --apply` + 재`scan` 3.1초.

## 테스트 방법

저장소 루트에서 실행한다. 필요: Node 25+, pnpm.

```bash
pnpm install                 # 최초 1회
(cd demo/vendor-platform && npm install)   # 데모 앱 의존성 (realistic-app도 동일)
pnpm run typecheck           # 타입 검사
pnpm test                    # 단위 82개 + 시나리오 16개
pnpm run examples:update     # examples/out 재생성 (출력 형식·데모 앱이 바뀌었을 때)
pnpm run test:scenarios      # 시나리오만 (데모 앱 실제 CLI)

# 파일 하나만
node --import tsx --test test/scan.test.ts

# 데모 앱 스캔
pnpm argos scan --config demo/vendor-platform/argos.config.yaml --out /tmp/demo-vp
pnpm argos scan --config demo/realistic-app/argos.config.yaml --out /tmp/demo-ra

# fix (원본을 수정하는 --apply는 반드시 복사본에서)
cp -r demo/vendor-platform /tmp/vp-copy
pnpm argos fix --config /tmp/vp-copy/argos.config.yaml --out /tmp/vp-fix            # 검증만
pnpm argos fix --config /tmp/vp-copy/argos.config.yaml --out /tmp/vp-fix --apply    # 복사본에 적용

# 작은 테스트용 결함 앱 (test/fixtures/vuln-app)
pnpm argos scan --config test/fixtures/vuln-app/argos.config.yaml --out /tmp/argos-out
pnpm argos scan --config test/fixtures/vuln-app/block.config.yaml; echo $?          # 종료 코드 2
```

| 테스트 파일 | 확인하는 것 |
|---|---|
| `test/config.test.ts` | 설정 스키마 오류, 페르소나 규칙, 매트릭스 스키마 |
| `test/runner.test.ts` | 기동·대기·환경 차단·임시 복사본·기동 실패·타임아웃·종료·`extraEnv` |
| `test/seed.test.ts` | 행·마커 시드, 비밀 마커, FK 연결, 결정성, 마스킹·redact, 오류 |
| `test/matrix.test.ts` | observe/verdict 규칙, 목록 라우트, 매트릭스 계약, 마커 노출 방지 |
| `test/checks.test.ts` | bola·unauth·sqli 판정, 대조 규칙(죽은 앱·잘못된 토큰) |
| `test/secrets.test.ts` | 컬럼 유출, 헤더·에러 응답 유출, 환경 카나리, OK/SKIPPED 조건 |
| `test/scan.test.ts` | `scan` e2e(fixture 앱), 종료 코드, `--checks`, 타임아웃, CLI |
| `test/fix.test.ts` | 제안 생성, 패치 적용·거부, `--apply`, 환경 노출 지침 |
| `test/demo-config.test.ts` | (A) 데모 설정이 스키마를 통과 |
| `test/scenarios/demo.scenarios.test.ts` | S1~S10: 데모 앱 기준 인수 기준 |

## 알아둘 것

- **A에게 알릴 계약 추가:** `MatrixCell.target`, `SeedManifest.ids`/`envCanaries`, 라우트의 `?search=`를 sqli가 읽는 것(리소스 `params`도 가능), `ScanMeta`. `report`는 `out/matrix.json`, `out/findings.json`, `out/scan-meta.json`을 읽는다(예시: `examples/out/`).
- **환경을 덤프하는 응답(`/debug/env`)은 증거에 본문을 싣지 않는다**(`body withheld`). 실제 스캔 출력에 호스트의 `PATH`/홈 경로가 섞이는 문제를 예시를 만들다 발견해 고쳤다.
- 소유 행이 없는 리소스는 거부 기대 칸의 2xx를 🔴로 판정한다(`POST /api/export`, `/debug/env`).
- secrets (b)는 매트릭스 요청의 응답만 검색한다(오류 유도 요청은 아직 없음). (c) 정적 스캔은 없다(SHOULD).
- 자동 수정은 `SELECT *` 열 제한만 지원한다. `req.user.vendor_id` 기반 소유자 검사 자동 수정은 없다.
- `seed.rows`는 지원하지 않는다(지정하면 오류). 조직당 한 행만 시드한다.
- 마스킹이 앞 6자(`ARGOS_`)만 남겨 마커끼리 구분이 안 된다. 리포트에서 필요하면 A와 논의.
- `node:sqlite`가 ExperimentalWarning을 출력한다(동작에는 문제 없음).

## 막힌 것 / 의존

- 8-1, 8-2 완료. 남은 것은 8-3.
- 8-3은 A의 `src/report.ts`, `src/init/` push 이후. `cli.ts` 연결은 B 소유(ROLE.md 경계 규칙).
- 작업 트리에 `demo/clean` → `demo/realistic-app` 이름 변경이 미커밋 상태로 있다(다른 쪽 작업). 시나리오는 `realistic-app` 기준.

## git

- `feature/sun`, `main`: `2a90f55`까지 push (데모 앱 대응 수정·secrets (b) 포함).
- `feature/sun`, `main`: `99ee2e3`까지 push (시나리오 테스트, `demo/realistic-app` 이름 변경 포함).
- 미커밋: `scan-meta.json`, `examples/out/`, 환경 덤프 증거 처리 수정, 이 문서.
- (이전 기록) `demo/` 이름 변경(`clean` → `realistic-app`), `docs/SPEC.md`·`test/demo-config.test.ts`의 이름 반영.
