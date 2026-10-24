# Argos 전체 아키텍처 (1024, 5시간 범위)

> 기준: `PLAN.md`(기획), `DEV_PLAN.md`(개발), `ROLE.md`(역할). 우선순위는 **PROVE + VOUCH + PLUG가 메인**, TRACE는 후순위, PDF는 최하위.
> 표기: ✅ 구현됨 · 🆕 5시간 안에 만듦 · ░ 후순위. 다이어그램은 Notion에서 깨지지 않도록 영어 라벨의 ASCII로 그렸다.
> 담당: **A** = 데모·리포트·설정, **B** = 코어·점검.

## 1. 한눈에: 고객 액션부터 증빙까지

```
 Customer (data company / vendor platform team)
 │
 │ 1. argos init <repo>            ← PLUG   (A) 🆕  AI drafts config, boots app, prints T1/K/R
 │ 2. argos scan --matrix          ← PROVE  (B) 🆕  personas attack every resource, secrets check
 │ 3. argos fix                    ← FIX    (B) 🆕  vendor-level patch, then re-run same attacks
 │ 4. argos report                 ← VOUCH  (A) 🆕  evidence doc: matrix + scope + hashes + limits
 │ 5. (later) report --format pdf  ← lowest priority, explicit send only
 ▼
 Argos CLI  ──(same core runs in CI: GitHub App webhook / workflow trigger)✅
```

## 2. 시스템 구성도 (층별)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ① ENTRY                                                                              │
│   CLI (cli.ts)  ✅        GitHub App + /trigger (github/*)  ✅        argos init 🆕 (A) │
└───────────────┬──────────────────────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ② PROVE CORE (B)                                                                     │
│                                                                                      │
│  config (personas 🆕, expected access) ─► routes ─► sinks ─► trace (heuristic / LLM) │
│                                                  │                                   │
│                                                  ▼                                   │
│                                         Access Path IR (ir.ts)                       │
│                                                  │                                   │
│            schema + ownership (vendor-level 🆕) ─┤                                   │
│                                                  ▼                                   │
│                          scenario (persona × resource 🆕) ─► pipeline                │
└───────────────┬──────────────────────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ③ CHECKS (B)                                                                         │
│   bac ✅   unauth ✅   sqli ✅   secrets 🆕: (a) sensitive field  (b) env canary  (c) static│
└───────────────┬──────────────────────────────────────────────────────────────────────┘
                ▼  every request runs inside ④
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ④ EXECUTION / ISOLATION (B, existing code, minimal change)                           │
│                                                                                      │
│   install container (network ON, no secrets)                                         │
│          │ deps only                                                                 │
│          ▼                                                                           │
│   scan container: --network none, read-only FS, non-root, cap-drop, pids/mem limits  │
│     └─ app + temp sqlite + personas 🆕 (N logins) + injected env canaries 🆕          │
│     └─ result JSON validated by Zod, no host fallback                                │
└───────────────┬──────────────────────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ⑤ VERDICT & FIX (B)                                                                  │
│   verify + triage:  🔴 VULNERABLE  🟡 SUSPECTED  🟢 OK  ⚪ SKIPPED                    │
│   rule: AI may raise a verdict, never lower it                                       │
│   fix: vendor-level patch (AND vendor_id = ?)  +  SELECT * → explicit safe columns 🆕 │
│   re-verify: same matrix, same attacks → problem cell must turn ✅, no new 🔴        │
└───────────────┬──────────────────────────────────────────────────────────────────────┘
                ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ⑥ VOUCH / REPORT (A) 🆕                                                              │
│   access matrix (expected vs actual) + per-check summary                             │
│   evidence header: scope, time, tool version, SHA-256 of inputs, limits statement    │
│   output: Markdown / PR comment  (PDF export & send: lowest priority, later)         │
└──────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────┐
│ ⑦ DEMO TARGET (A) 🆕  demo/vendor-platform                                           │
│   3 vendors × datasets × tasks; planted flaws: cross-vendor read, export without auth,│
│   list without scope, api_key in response, env dump debug endpoint                   │
└──────────────────────────────────────────────────────────────────────────────────────┘

 ░ TRACE (later): canary issue / scan / probe, registry — outside the 5 hours
```

## 3. 접근 매트릭스: 핵심 개념

페르소나(벤더 A, 벤더 B, 익명)로 모든 리소스를 시도하고, **기대**와 **실제**를 칸마다 비교한다.

```
                 dataset:d1(owner V1)   dataset:d2(owner V2)   export-api    /debug
 vendor1         allow / allow  ✅      deny / deny   ✅       allow / allow  ✅   deny / deny ✅
 vendor2         deny  / ALLOW  🔴      allow / allow ✅       allow / allow  ✅   deny / deny ✅
 anonymous       deny  / deny   ✅      deny / deny   ✅       deny  / ALLOW  🔴   deny / ALLOW 🔴
                 (expected / observed)
```

- 🔴 칸은 요청·응답 증거(상태 코드, 마커)를 함께 저장한다.
- 정상 접근(대조 칸)이 유지되는지도 확인해서 "전부 막아서 통과"하는 가짜 수정을 걸러낸다.

## 4. 데이터 흐름 (한 번의 scan → fix → report)

```
 repo ─► routes/sinks/trace ─► Access Path IR ─► scenario(persona × resource)
                                                      │
                          ┌───────────────────────────┘
                          ▼
              scan container (network none)
              ├─ seed rows (owners, sensitive columns with markers 🆕)
              ├─ inject env canaries 🆕
              └─ send requests as each persona
                          │ findings.json + matrix.json
                          ▼
              verify / triage ─► 🔴🟡🟢⚪
                          │
              fix ─► patch ─► re-run same matrix ─► accept only if problem cell ✅ and no new 🔴
                          │
                          ▼
              report: matrix + summary + evidence header (hashes of inputs, not tamper-proof)
```

## 5. 신뢰 경계와 보안 속성

| 경계 | 규칙 |
|---|---|
| 고객 코드 실행 | 항상 일회용 컨테이너. 스캔 단계는 네트워크 없음, 읽기 전용, 비root, 자원 제한 |
| 비밀 | LLM 키·`ARGOS_*` 비밀은 환경변수로만. 커밋하지 않고 스캔 컨테이너에 넘기지 않음 |
| 시험용 비밀 | 환경 카나리는 샌드박스 안의 시험 값이며 실제 비밀이 아님. 로그·리포트에는 앞 6자만 |
| `argos init`의 LLM 전송 | 기본 `files`: 선택한 파일만, 비밀 패턴 마스킹, `.env`·키 파일 제외. `--llm-data none`으로 끔. 전송 목록을 출력·기록 |
| 판정 | 실행 증거로만. AI는 올리기만 하고 낮추지 않음 |
| 기본 모드 | `report`(비차단) |
| 보고서 언어 | 영어가 기본(`en`)이며, `argos report --lang ko`로 한국어 보고서를 생성할 수 있다. JSON 판정 값은 언어와 무관하게 고정한다. |
| 외부 전송 | PDF·리포트 전송은 명시적·허용 목록·확인·기록 (최하위, 후순위) |

## 6. 층별 담당·파일·상태

| # | 층 | 담당 | 파일 | 상태 |
|---|---|---|---|---|
| ① | CLI, GitHub 연동 | B(기존), A(`init`) | `cli.ts`, `github/*`, `src/init/*` | ✅ / 🆕 |
| ② | PROVE 코어 | B | `config.ts`, `routes.ts`, `sinks.ts`, `trace-*.ts`, `ir.ts`, `schema.ts`, `policy.ts`, `scenario.ts`, `pipeline.ts` | ✅ 기반 / 🆕 페르소나·벤더 소유권·매트릭스 |
| ③ | 점검 | B | `checks/*` | ✅ bac, unauth, sqli / 🆕 secrets |
| ④ | 실행·격리 | B | `executor.ts`, `executors.ts`, `container-executor.ts`, `sandbox-runner.ts`, `install-policy.ts` | ✅ / 🆕 페르소나 N개·환경 주입 |
| ⑤ | 판정·수정 | B | `verify.ts`, `triage.ts`, `fix/*` | ✅ / 🆕 벤더 단위·열 제한·매트릭스 재검증 |
| ⑥ | 리포트(VOUCH) | A | `report.ts`, `github/report-md.ts`(기존 재사용) | 🆕 |
| ⑦ | 데모 대상 | A | `demo/vendor-platform/` | 🆕 |
| ░ | TRACE | 미정 | `src/canary/*` | 후순위 |

## 7. 이미 있는 것과 새로 만드는 것

| 구분 | 내용 |
|---|---|
| ✅ 있음 | 사용자 단위 소유권 점검, 인증 누락, SQLi, 수정 + 재검증, 컨테이너 샌드박스, GitHub 연동(모의 E2E), 평가 스위트(`eval`, `eval:mutation`, `eval:sandbox`, `github-e2e`) |
| 🆕 새로 | 페르소나 N개와 벤더 단위 소유권, 접근 매트릭스, 비밀 유출 점검(민감 필드·환경 카나리), 벤더 단위 수정과 열 제한, 증빙 리포트, `argos init`, 데모 플랫폼 |
| ⚠️ 미검증 | 실제 GitHub 환경 리허설, AI 경로 정확도, 여러 서비스에 대한 일반화, 오탐률 |

## 8. 알려진 한계

- 매트릭스는 **설정한 페르소나와 시험한 공격**에 대한 결과다. 보안을 보증하지 않는다.
- 증빙의 해시는 파일을 고정할 뿐 위·변조 방지가 아니다.
- 데모와 샘플은 Node + sqlite 위주라 `argos init`의 성공률(R)은 일반화할 수 없다.
- 이 영역(공격 기반 접근 제어 시험)에는 이미 경쟁 제품이 있다. 차별점(공격 증명 + 증빙 문서 + 쉬운 세팅)의 구매 의사는 미검증이다.
