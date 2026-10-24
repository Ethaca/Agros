# B 진행 현황 (코어·점검)

> 담당: 개발자 B. 기준: `docs/SPEC.md` 6절·12절. 갱신: 2026-10-24.
> 표기: ✅ 완료 · ⬜ 대기 · SHOULD = 시간이 남으면.

## 도식

```
 [계약]     ✅ config.ts   설정 스키마 (Zod) + loader
            ✅ types.ts    Finding / Matrix / Verdict 계약
               │
 [Step 1]   ✅ runner.ts   앱 기동 · 빈 포트 · ready 체크 · 환경 정리 · 임시 복사본
               │
 [Step 2]   ✅ seed.ts     SQLite 시드 · 마커/비밀 마커 · 마스킹(앞 6자) · 결정적 hex6
               │
 [Step 3]   ✅ http.ts     페르소나 요청
            ✅ matrix.ts   expected / observed 판정 → 매트릭스 JSON·표
               │
 [Step 4]   ✅ checks/bola.ts, unauth.ts        ← 크리티컬 패스 끝
               │
 [Step 5]   ✅ scan.ts + cli.ts scan 연결  (out/matrix.json, findings.json)
               │
 [Step 6]   ✅ checks/sqli.ts, secrets.ts (a)
 [Step 7]   ✅ fix/  (SHOULD)  규칙 기반 수정 + 같은 매트릭스 재검증
 [Step 8]   ⬜ 통합 · e2e · 리허설
```

## 요약

| 상태 | 항목 | 파일 | 테스트 |
|---|---|---|---|
| ✅ | 계약 + config | `src/config.ts`, `src/types.ts` | 8개 |
| ✅ | runner | `src/runner.ts` | 7개 |
| ✅ | seed | `src/seed.ts` | 7개 |
| ✅ | http + matrix | `src/http.ts`, `src/matrix.ts` | 8개 |
| ✅ | bola + unauth | `src/checks/*` | 8개 |
| ✅ | scan 명령 (e2e) | `src/scan.ts`, `src/cli.ts` | 8개 |
| ✅ | sqli + secrets (a) | `src/checks/sqli.ts`, `secrets.ts` | 12개 |
| ✅ | fix (규칙 기반 + 재검증) | `src/fix/*` | 7개 |
| ⬜ | Step 8 | - | - |

## 완료 내용

- **계약:** 설정 스키마(알 수 없는 키 거부, 위치를 앞에 둔 한 줄 오류), `Finding`/`Matrix` 타입. 증거의 `marker`는 6자까지만 허용.
- **runner:** `target.start` 실행, `readyPath` 200 대기(30초), 부모 환경변수 차단(`PATH`/`HOME`/`PORT`/`target.env`만), 임시 복사본 실행, SIGTERM 후 5초 뒤 SIGKILL, 기동 실패 시 로그 끝 50줄.
- **seed:** 소유 테이블 × 조직별 한 행, 비민감 텍스트 컬럼에 소유자 마커, 민감 컬럼에 비밀 마커, `maskMarker`/`redact`, 설정 해시 기반 결정적 마커.

## 테스트 방법

저장소 루트에서 실행한다. 필요: Node 25+, pnpm.

```bash
pnpm install                 # 최초 1회 (esbuild 빌드는 pnpm-workspace.yaml에서 허용됨)
pnpm run typecheck           # 타입 검사
pnpm test                    # 전체 단위 테스트 (현재 65개)

# 파일 하나만
node --import tsx --test test/config.test.ts
node --import tsx --test test/runner.test.ts
node --import tsx --test test/seed.test.ts

# fix 직접 실행 (fixture를 복사해서 시험할 것: --apply가 원본을 수정함)
cp -r test/fixtures/vuln-app /tmp/fixdemo
pnpm argos fix --config /tmp/fixdemo/argos.config.yaml --out /tmp/fixdemo-out            # 검증만
pnpm argos fix --config /tmp/fixdemo/argos.config.yaml --out /tmp/fixdemo-out --apply    # 원본에 적용

# scan 직접 실행 (테스트용 결함 앱: test/fixtures/vuln-app)
pnpm argos scan --config test/fixtures/vuln-app/argos.config.yaml --out /tmp/argos-out
pnpm argos scan --config test/fixtures/vuln-app/fixed.config.yaml --out /tmp/argos-out   # 🔴 없음
pnpm argos scan --config test/fixtures/vuln-app/block.config.yaml; echo $?                # 종료 코드 2
pnpm argos --help
```

| 테스트 파일 | 확인하는 것 |
|---|---|
| `test/config.test.ts` | 필수 누락·알 수 없는 키·잘못된 enum 오류, 페르소나 규칙, 매트릭스 스키마 |
| `test/runner.test.ts` | 기동·대기·환경 차단·임시 복사본·기동 실패·타임아웃·종료 (`test/fixtures/basic-app` 사용) |
| `test/seed.test.ts` | 행·마커 시드, 비밀 마커, 결정성, 재시드, 마스킹·redact, 오류 (`test/fixtures/seed-app` 사용) |

**수동 확인 (runner + seed 흐름)**
- `pnpm test` 통과가 기본 확인이다. runner 테스트는 실제로 `node app.mjs`를 띄우고 `/health`, `/env`로 환경 차단을 검증한다.
- 시드 결과를 직접 보려면 `seedDatabase()`를 호출한 뒤 `data.db`를 `sqlite3`로 열어 `SELECT * FROM datasets;`를 본다.

- **http / matrix:** 페르소나별 요청(5초 타임아웃, 연결 오류는 SKIPPED), 페르소나 × 리소스 × 대상 조직 매트릭스, SPEC 6.4 observed 규칙, 마커 마스킹된 증거, Markdown 표.
- **scan:** `argos scan [--config] [--checks] [--out] [--timeout]`. 임시 복사본 → 시드 → 앱 기동 → 매트릭스 → 점검 → `out/matrix.json`, `out/findings.json`. 종료 코드 0/1/2, 전체 타임아웃 기본 5분, 구현 전 점검(sqli, secrets)은 "not run"으로 표시. runner에 `beforeStart` 훅 추가(시드를 앱 기동 전에 실행).
- **sqli:** `resources[].params`에 적은 쿼리 파라미터마다 `"1"`(대조) → `"'"` → `"''"` 3단계. 대조 2xx + `'` 5xx + `''` 2xx면 🔴, 대조 실패는 SKIPPED.
- **secrets (a):** 매트릭스 요청의 원본 응답(본문·헤더)에서 비밀 마커 검색. 비소유자·익명 🔴, 소유자 재노출 🟡(`allowOwnerSecretRead`로 허용), 2xx 응답이 있는 리소스만 OK.
- **fix:** `argos fix [--config] [--out] [--apply]`. 🔴/🟡 Finding마다 제안 생성. 기계적으로 고치는 건 `SELECT * FROM <table>` → 비민감 컬럼 목록뿐, 소유자 검사·인증·파라미터화는 수정 지침만 출력. 패치는 임시 복사본에 적용해 **같은 매트릭스를 다시 실행**하고, ① 대상 Finding 해결 ② 대조 칸 유지 ③ 새 🔴 없음 ④ 앱 기동일 때만 채택. 원본은 `--apply`일 때만 수정, 채택 실패 시 지침만. 결과는 `out/before/`, `out/after/`, `out/fix.json`.
- **bola / unauth:** 매트릭스 칸에서 Finding 생성. 공격자·소유자 대조 요청이 성공하지 않으면 SKIPPED(죽은 앱·만료 토큰이 "안전"으로 보이지 않게).

## 알아둘 것

- 계약 추가(A에게 알릴 것): `MatrixCell.target`, `SeedManifest.ids`, 리소스 설정 `params`(sqli 대상 쿼리 파라미터).
- 자동 수정은 `SELECT *` 열 제한만 지원한다(그 외는 지침). secrets (b) 환경 카나리와 (c) 정적 스캔은 아직 없다(SHOULD).
- 소유 행이 없는 리소스는 거부 기대 칸의 2xx를 🔴로 판정한다(오탐 여부는 데모 앱으로 재확인).

- `seed.rows`는 아직 지원하지 않는다(지정하면 오류).
- 조직당 한 행만 시드한다.
- 마스킹이 앞 6자(`ARGOS_`)만 남겨 마커끼리 구분이 안 된다. 리포트에서 필요하면 A와 논의.
- `node:sqlite`가 ExperimentalWarning을 출력한다(동작에는 문제 없음).

## 막힌 것 / 의존

- 막힌 것 없음. Step 3까지는 단독 진행 가능.
- Step 4 e2e부터 A의 `demo/vendor-platform`이 필요하다(그 전에는 테스트용 앱으로 대체).

## git

- `feature/sun`, `main`: Step 5(scan)까지 push. Step 6~7은 미커밋.
- `main`: `9590e30`(계약 단계).
