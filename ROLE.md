# 역할 분담 (1024) — 5시간 범위

> 최신 기획은 `PLAN.md`(영어 `PLAN.en.md`). 이 문서는 **5시간** 개발 시간 기준의 역할과 일정이다. `../final/ROLE.md`, `../final/ROLE2.md`는 이전 방향(API 보안 올인원) 기준이라 대체되었다.
> 표기: **A** = 프론트엔드 개발자(백엔드 조금), **B** = 메인 개발자(풀스택·AI). 한 명이 둘을 맡는 경우에는 아래 순서대로 위에서부터 한다.
> 개발 시간 5시간, LLM 키 보유, 모델 오염 탐지는 모의 모델로 시연, 구현 먼저.

## 1. 한눈에 보기

**우선순위 (재확정):** Argos 메인 = 공격 증명(PROVE) + 증빙(VOUCH) + 편한 세팅(PLUG). 원천 추적(TRACE)은 **후순위**(5시간 밖), PDF는 최하위.

| | A — 데모·리포트·설정 | B — 코어·점검 |
|---|---|---|
| 중심 작업 | **데모 플랫폼**(벤더 3곳 × 데이터셋 × 작업, 결함 심기), **증빙 리포트**, **`argos init`**(AI 설정 초안, 편의 지표 T1·K·R), 시연 스크립트·리허설 | **PROVE 코어**(페르소나 N개, 벤더 단위 소유권, 접근 매트릭스), **비밀 유출 점검**(민감 필드, 환경 카나리), 벤더 단위 수정·재검증 |
| 건드리는 곳 | `demo/`, `report.ts`, `src/init/` | `config.ts`, `executor.ts`, `schema.ts`, `policy.ts`, `scenario.ts`, `pipeline.ts`, `checks/secrets.ts`, `fix/` |
| 막히면 | B에게 매트릭스·점검 형식 질문 | A에게 데모 앱 요구 확인 |

### 1.1 아키텍처별 역할 분담

**A** = 데모·리포트·설정, **B** = 코어·점검. 5시간 안에 만드는 층만 표시했고 `░`는 후순위(TRACE)다.

```
 Customer / CI
      │  argos init · scan · fix · report
      ▼
 ┌─ ① CLI & Setup ───────────────────────────────  A  (src/init/, CLI 연결은 B 협의)
 │   argos init: repo scan → AI draft config → boot check → T1/K/R
 ├─ ② PROVE core ────────────────────────────────  B
 │   config(personas) → schema/ownership → scenario → pipeline → matrix verdict
 ├─ ③ Checks ────────────────────────────────────  B
 │   bac · unauth · sqli (exists)   secrets: (a) sensitive field (b) env canary
 ├─ ④ Execution / isolation ─────────────────────  B  (executor, 컨테이너: 기존 코드, 변경 최소)
 │   disposable container, network none, personas run here
 ├─ ⑤ Fix & re-verify ───────────────────────────  B
 │   vendor-level patch, SELECT * column limit, matrix re-run
 ├─ ⑥ VOUCH / Report ────────────────────────────  A  (입력 형식은 B와 합의)
 │   matrix + per-check summary + evidence header (scope, time, hashes, limits)
 ├─ ⑦ Demo target ───────────────────────────────  A  (demo/vendor-platform)
 │   3 vendors × datasets × tasks, planted flaws, seed, manual repro script
 └─ ░ TRACE (canary issue / scan / probe) ───────  후순위, 담당 미정
```

| # | 아키텍처 층 | 담당 | 파일 | 상대에게 주는 것 / 받는 것 |
|---|---|---|---|---|
| ① | CLI·설정(`argos init`) | **A** | `src/init/*` | 받음: `Config` 스키마(B). 줌: 초안 `argos.config.yaml` |
| ② | PROVE 코어 | **B** | `config.ts`, `schema.ts`, `policy.ts`, `scenario.ts`, `pipeline.ts` | 줌: 매트릭스 JSON(A의 리포트 입력) |
| ③ | 점검 | **B** | `checks/*`, `checks/secrets.ts` | 받음: 데모 앱의 민감 컬럼·환경 덤프 위치(A) |
| ④ | 실행·격리 | **B** | `executor.ts`, `container-executor.ts` | 페르소나 N개 지원만 추가, 보안 속성은 유지 |
| ⑤ | 수정·재검증 | **B** | `fix/*` | 받음: 데모 앱의 주체 속성 `req.user.vendor_id`(A) |
| ⑥ | 리포트(VOUCH) | **A** | `report.ts` | 받음: 매트릭스·Finding JSON(B). 한계 문구는 A가 책임 |
| ⑦ | 데모 대상 | **A** | `demo/vendor-platform/` | 줌: 소유 컬럼명, 주체 속성, 결함 목록 |
| - | 머지 게이트 | 변경한 쪽 | `typecheck`, `eval`, `eval:mutation`, `github-e2e` | B 영역을 건드리면 그 쪽이 실행 |

**경계 규칙:** ①의 CLI 서브커맨드 등록(`cli.ts`)은 B 소유 파일이므로 A는 `init`을 한 줄 연결하는 변경만 하고 B에게 알린다. ②↔⑥은 매트릭스 JSON, ③↔⑥은 Finding 형식이 계약이며 바꾸면 바로 알린다.

## 2. 5시간 일정 (최신)

| 시간 | B | A |
|---|---|---|
| **0:00–0:30** | 함께: 계약 합의 (아래 3절) | |
| **0:30–2:00** | **[PROVE 코어]** 페르소나 N개, 벤더 단위 소유권, 시나리오, 매트릭스 판정 | **[데모 플랫폼]** 벤더 3곳 × 데이터셋 × 작업 + 결함, 설정·시드 |
| **2:00–3:00** | **[비밀 유출]** (a) 민감 필드 노출, (b) 환경 카나리 | **[증빙 리포트]** 매트릭스 + 점검별 요약 + 증빙 헤더 |
| **3:00–4:00** | 벤더 단위 수정 + `SELECT *` 열 제한 + 매트릭스 재검증 | **[PLUG]** `argos init` + T1·K·R 측정 |
| **4:00–5:00** | 통합 점검, **리허설 2회**, 동결 | 동일 |

**자르는 순서:** ① `init`의 AI 설정 → ② (b) 환경 카나리 → ③ 벤더 단위 자동 수정 → ④ 리포트 서식. **매트릭스, (a) 민감 필드 노출, 증빙 헤더는 끝까지 지킨다.**
**위험:** V1(PROVE 코어)이 크리티컬 패스이고 추정보다 길어질 수 있다. 2:00에 매트릭스가 없으면 **matrix-lite**로 대체한다. 상세는 `DEV_PLAN.md` 5.2.

## 3. 먼저 합의할 계약 (0:00–0:30)

> 아래 표의 **카나리(`argos canary ...`)·등록부** 행은 후순위 기능(TRACE)이라 이번 5시간에 구현하지 않는다.

| 항목 | 제안 (합의 후 확정) |
|---|---|
| (후순위) 입력 | `eval.jsonl` (줄마다 JSON 한 개) |
| (후순위) 발급 | `argos canary issue --input eval.jsonl --recipients vendorA,vendorB --out out/` → 수신자별 사본 + `registry.json` |
| (후순위) 식별 | `argos canary scan <leaked-file> --registry registry.json` → 일치한 표식, 수신자, 신뢰도 |
| (후순위) 오염 질의 | `argos canary probe --model <endpoint> --registry registry.json` → 표식별 이어 쓰기 결과, 통계 판정 |
| (후순위) 등록부 `registry.json` | 표식 ID ↔ 수신자 ↔ 삽입 위치 ↔ 발급 시각 (표식 원문은 해시와 함께 보관) |
| 설정 | `argos.config.yaml`의 `personas`(이름, 소유 조직/벤더, 인증 방식), 기대 접근표 `resources`. 기존 A·B 설정과 호환 |
| 매트릭스 | JSON: `personas`, `resources`, `cells[{persona, resource, expected, observed, verdict, evidence}]` (`DEV_PLAN.md` 5.2) |
| 증빙 헤더 | 데이터셋 ID, 수신자, 발급 시각, 레지스트리 `keyId`, 사본·레지스트리 SHA-256, 도구 버전, 범위·한계 문장 |
| 비밀 유출 점검 | Finding `check: "secrets"`, 세부 `column` 또는 `env`. 마커·비밀은 출력에 전체를 싣지 않고 앞 6자만 표시 |
| `argos init` | 입력: 저장소 경로. 출력: `argos.config.yaml` 초안 + 검증 결과(스키마 통과, 앱 기동 여부) + T1·K·R. LLM 전송 기본값은 선택한 파일만(비밀 마스킹), `--llm-data none`으로 끔 |
| 리포트 | 증빙 헤더, 매트릭스, 점검별 요약, **한계 문구** ("시험한 공격의 결과이며 보안을 보증하지 않는다") |

**규칙:** 판정은 실행 증거로만 한다. AI는 설정 초안과 설명에만 쓰고 판정을 낮추지 않는다. 인터페이스를 바꾸면 바로 상대에게 알린다.

## 4. 머지 게이트

기존 `argos/` 코드를 건드릴 때만 적용한다. 새 모듈(secrets 점검, init, report)은 자체 테스트를 같이 둔다.

```bash
cd hackathon/argos
pnpm run typecheck
pnpm run eval
pnpm run eval:mutation
npx tsx eval/github-e2e.ts
```

## 5. 이번 5시간에 하지 않는 것

**TRACE 전체**(카나리 발급·식별·오염 탐지·견고성 시험), 증빙 리포트의 **PDF 내보내기·전송(최하위)**, 인증 어댑터(쿠키·API 키·SSO), 작업 단위 권한, 쓰기·목록 시나리오, Postgres·Python, 실제 GitHub 리허설, (c) 정적 비밀 스캔(시간이 남을 때만), 사용자 판정 제거의 코드 반영, 인터뷰. (이유는 `PLAN.md` 9.1)

## 6. 주의할 점

- **`argos init`은 소스 일부를 LLM API로 보낸다.** 전송 범위를 출력하고 `.env`·키 파일은 보내지 않는다.
- **"오염 없음"을 증명한다고 말하지 않는다.** 음성은 증거가 아니다.
- **LLM 키는 서버/로컬 환경변수로만** 쓴다. 저장소에 커밋하지 않고, 스캔 컨테이너에는 넘기지 않는다.
- **구매 의사는 미검증이다.** 시연에서도 "가설"임을 숨기지 않는다.
- 커밋과 push는 팀이 정한 시점에만 한다.
