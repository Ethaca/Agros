# `argos scan` 출력 예시

`demo/vendor-platform`(결함 5종)을 실제로 스캔한 결과다. A의 `report.ts`와 CI 연동이 읽는 입력 형식의 기준이다.

```bash
pnpm run examples:update     # = argos scan --config demo/vendor-platform/argos.config.yaml --out examples/out
```

| 파일 | 내용 | 계약(Zod) |
|---|---|---|
| `matrix.json` | 페르소나 × 리소스 × 대상 조직의 칸마다 기대·실제·판정·증거 | `Matrix` (`src/types.ts`) |
| `findings.json` | 점검(`bola`, `unauth`, `sqli`, `secrets`)별 발견. 🟢·⚪도 포함 | `Finding[]` |
| `scan-meta.json` | 증빙 헤더 재료: 해시, 시각, 도구 버전, 범위 | `ScanMeta` |

예시는 테스트가 지킨다. 스키마 검증은 `test/examples.test.ts`, 새로 스캔한 결과와의 일치는 `test/scenarios/`의 S12. 데모 앱이나 출력 형식이 바뀌면 위 명령으로 다시 만든다.

## `matrix.json`

```json
{
  "persona": "vendor1", "resource": "dataset-read", "target": "v2",
  "expected": "deny", "observed": "allow", "verdict": "VULNERABLE",
  "evidence": { "request": "GET /api/datasets/2", "status": 200, "marker": "ARGOS_", "note": "{\"id\":2,\"vendor_id\":\"v2\",\"name\":\"ARGOS_…\"}" }
}
```

- 칸 하나 = "`persona`가 `target` 조직의 데이터를 요청했을 때". `target`이 없으면 소유 행이 없는 리소스(`export`, `debug-env`, 공개 경로)다.
- `persona`의 조직과 `target`이 같으면 **대조 칸**(소유자 본인 접근), 다르면 **공격 칸**.
- `expected`: `allow` | `deny` (설정의 `expect`에서 계산). `observed`: `allow` | `deny` | `allow-empty`(2xx인데 대상 조직 마커 없음) | `error`.
- `verdict`: `VULNERABLE`(🔴) · `SUSPECTED`(🟡) · `OK`(🟢) · `SKIPPED`(⚪).
- `evidence.marker`는 항상 앞 6자(`ARGOS_`). `note`는 응답 본문 발췌로, 마커는 `ARGOS_…`로 가려져 있고, 환경 변수를 덤프하는 응답은 본문을 싣지 않는다(`body withheld`).

## `findings.json`

```json
{ "check": "secrets", "resourceId": "debug-env", "persona": "vendor1", "verdict": "VULNERABLE",
  "proof": { "request": "GET /debug/env", "status": 200, "marker": "ARGOS_" },
  "detail": "environment variable JWT_SECRET is exposed in the response of GET /debug/env", "env": "JWT_SECRET" }
```

- `secrets`만 세부 필드가 있다: 응답 속 민감 컬럼은 `column`(`vendors.api_key`), 환경 변수 노출은 `env`(`JWT_SECRET`).
- `persona`/`resourceId`가 `(all)`인 항목은 "모든 응답에서 못 찾았다"는 음성 결과(🟢) 또는 판단 불가(⚪)다.
- 🟢은 "시험한 공격으로는 못 뚫었다"는 뜻이지 보증이 아니다. 한계 문구는 리포트가 싣는다.
- `SKIPPED`의 `detail`에 이유가 있다(대조 실패, 앱 미기동 등). "안전"으로 읽으면 안 된다.

## `scan-meta.json`

증빙 헤더(SPEC V2)에 쓸 재료다. 해시는 파일을 **고정**할 뿐 위·변조를 막지 않는다.

| 필드 | 뜻 |
|---|---|
| `tool.version`, `startedAt`, `finishedAt`, `durationMs` | 도구 버전과 실행 시각(UTC) |
| `target` | 설정이 있는 디렉터리 이름 |
| `config.sha256`, `seed.schema.sha256` | 설정 파일, 시드 스키마 파일의 SHA-256 (파일 내용 기준) |
| `checks`, `personas`, `resources` | 시험 범위. **여기 없는 라우트는 시험하지 않았다** |
| `results` | 칸 수, 발견 수, 판정별 개수 |
| `files.matrix.sha256`, `files.findings.sha256` | 같은 디렉터리의 두 파일 SHA-256. 리포트가 다시 계산한 값과 비교할 수 있다 |

절대 경로, 토큰, 마커·비밀 전체 값은 어느 파일에도 없다.
