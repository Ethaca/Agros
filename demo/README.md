# Demo targets

Argos가 시험할 앱 두 개. 둘 다 Express 5 + `node:sqlite`, 같은 스키마·라우트·시드를 쓴다.

| 앱 | 용도 | 기대 결과 |
|---|---|---|
| `vendor-platform/` | 결함 5종을 심은 시연 대상 | 결함 칸 🔴, 대조 칸 ✅ |
| `clean/` | 같은 앱에서 결함만 고친 오탐 기준선 | 🔴 0건 |

```bash
cd demo/vendor-platform && npm install
npm run exploit                      # = bash manual-exploit.sh           → 5/5 flaws reproduced
bash manual-exploit.sh ../clean      # (clean도 npm install 후)            → 0/5 flaws reproduced
```

`manual-exploit.sh`는 Argos 없이 curl만으로 결함을 재현한다. **Argos 결과와 이 스크립트의 결과가 일치하는지**가 시연의 신뢰 근거다(SPEC 7절).

## 심은 결함 (`vendor-platform/app.mjs`의 `FLAW n` 주석)

| # | 라우트 | 결함 | 점검 | `clean`의 수정 |
|---|---|---|---|---|
| 1 | `GET /api/datasets/:id` | 소유 벤더 확인 없음 | `bola` | `WHERE id = ? AND vendor_id = ?` |
| 2 | `POST /api/export` | 인증 없음 + 벤더 범위 없음. body `{"datasetId": n}`, 없으면 전체 | `unauth` (+`bola`) | `auth` + `vendor_id` 범위 |
| 3 | `GET /api/datasets?search=` | `search`를 SQL에 이어 붙임. `x`→200, `'`→500, `''`→200 | `sqli` | 파라미터 바인딩 |
| 4 | `GET /api/vendors/:id` | `SELECT *`가 `api_key`까지 반환. 프로필 자체는 다른 벤더에게 공개가 의도 | `secrets` (a) | 명시 열 `id, name, contact_email` |
| 5 | `GET /debug/env` | `process.env` 전체 덤프 | `secrets` (b) | 라우트 제거(404) |

**대조(정상) 라우트:** `GET /health`, `GET /api/products`(공개), `GET /api/me`(로그인 확인용), `GET /api/datasets/:id/tasks`, `GET /api/tasks/:id`(벤더 범위가 올바름).

## Argos와의 계약 (B 확인 필요)

| 항목 | 값 |
|---|---|
| 기동 | `node --no-warnings app.mjs`, `PORT` 환경변수, `127.0.0.1`에 바인딩, `/health` → 200 |
| DB | `DB_PATH`(기본 `./data.db`, cwd 기준). 앱이 시작할 때 `schema.sql`을 적용(`IF NOT EXISTS`)하고, **행은 시드하지 않는다** → Argos가 시드 |
| 소유 컬럼 | `datasets.vendor_id`, `tasks.vendor_id`, `vendors.id`. 값은 페르소나 `org`(`v1`, `v2`, `v3`) |
| 주체 속성 | `req.user.vendor_id` (수정 규칙에서 사용) |
| 인증 | `Authorization: Bearer <token>`. 토큰→벤더 매핑은 `DEMO_TOKENS`(기본 `tok-v1:v1,tok-v2:v2,tok-v3:v3`). 없거나 틀리면 401 |
| 거부 응답 | 인증 없음 401, 다른 벤더 리소스 404(존재 은닉) |
| PK | `datasets.id`, `tasks.id`는 `INTEGER PRIMARY KEY`(자동 할당), `vendors.id`는 TEXT(= org) |
| 외래키 | 강제하지 않음(테이블 단위로 시드 가능) |
| 앱이 읽는 env | `PORT`, `DB_PATH`, `DEMO_TOKENS`뿐. 환경 카나리를 주입해도 동작이 바뀌지 않음(4b 부작용 없음) |

`seed.sql`은 수동 재현용 고정 데이터다(`V1-CONFIDENTIAL`, `vk_live_v1_...`). Argos는 쓰지 않는다.

**B가 판단할 점**
- `dataset-search`는 목록이라 다른 벤더 요청도 200(자기 행)이 나온다. SPEC M3 규칙상 `allow-empty`(🟡)가 될 수 있으니 목록 리소스 처리 규칙이 필요하다.
- 라우트에 쿼리 파라미터를 `GET /api/datasets?search=`로 적었다. sqli가 시험할 파라미터를 이렇게 읽을지 정해야 한다.
- `POST /api/export`는 경로에 id가 없고 body로 받는다. 소유자 마커 비교 방식을 정해야 한다.
- `debug-env`는 소유자가 없는 리소스라 `expect`를 모두 `deny`로 적었다.
