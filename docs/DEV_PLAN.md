# 개발 플랜 (1024) — `argos canary` 5시간 구현

> 기준 문서: `PLAN.md`(기획), `ROLE.md`(역할·일정). 이 문서는 **무엇을 어떤 구조로, 어떤 순서로, 어떤 기준으로 만들지**를 정한다.
> 전제: 개발 시간 **5시간**, LLM 키 보유, 모델 오염 탐지(1C)는 **모의 모델**로 시연, 구현 먼저, 모든 변경은 로컬(커밋·push는 지시가 있을 때만).
> 표기: ✅ 이미 있음 · ⬜ 이번에 만듦 · ⚠️ 위험/주의. 도식 안의 글자는 영어(정렬 유지용).

> **우선순위 재확정 (2026-10-24):** **Argos 메인 = 공격 증명(PROVE) + 증빙(VOUCH) + 편한 세팅(PLUG).** 원천 추적(TRACE, `argos canary`)은 **후순위**이고 이번 5시간에 만들지 않는다. PDF 내보내기·전송은 최하위.
> **읽는 법:** 5시간 안의 개발은 **5.2(일정) · 5.4(비밀 유출 점검) · 5.5(`argos init`) · 5.6(CLI·테스트·시연)** 이 최신이다. **1~4절, 7~8절, 6절의 연결 설계는 후순위 기능 TRACE의 설계**이며 참고용으로 유지한다.

## 1. 무엇을 만드는가

세 줄로 요약하면 이렇다.

1. **발급(issue):** 평가 세트 한 개 → 수신자별로 **고유 카나리가 든 사본**을 만든다.
2. **식별(scan):** 유출된 샘플을 주면 **어느 수신자 사본인지** 찾는다.
3. **오염 질의(probe):** 모델에 카나리 앞부분을 주고, **카나리를 이어 쓰는지**로 학습 여부를 통계적으로 판정한다. (모의 모델로 시연)

이 셋의 결과를 `report`가 한 문서(**신뢰 증빙 리포트**)로 묶고, 기존 Argos 접근 제어 스캔 결과(기둥 2)를 첨부한다.

## 2. 전체 아키텍처

### 2.1 시스템 맥락 (누가 무엇을 주고받는가)

```
 +----------------+    eval.jsonl     +--------------------------------------------------+
 |  Data owner    | ----------------> |                  argos canary (CLI)              |
 |  (eval team)   |                   |                                                  |
 +----------------+                   |   issue  ----> out/<recipient>.jsonl  (copies)   |
        ^                             |            \-> out/registry.json      (SECRET)   |
        |  report.md                  |   scan   <---- leaked sample                     |
        +-----------------------------|   probe  ----> model endpoint                    |
                                      |   report ----> out/report.md                     |
                                      +--------+-------------------+---------------------+
                                               |                   |
                      per-recipient copies     v                   v
                   +------------------------+  +-------------+   +----------------------+
                   | Recipients             |  | Claude API  |   | Suspect model        |
                   | (vendors / labs)       |  | (LLM key)   |   | (MOCK in the demo)   |
                   +------------------------+  +-------------+   +----------------------+
                                                 canary item        canary prefix ->
                                                 generation only    completion
```

### 2.2 모듈 구조 (저장소 안의 위치)

```
 hackathon/argos/
 |
 +-- src/cli.ts ------------ argv[2]=="canary" ? --yes--> src/canary/cli.ts      (NEW, ~5 lines changed)
 |                                    |
 |                                    no -> existing scan / fix  (pillar 2, unchanged)
 |
 +-- src/canary/                      (ALL NEW)
 |     cli.ts        subcommand router: issue | scan | probe | report
 |     types.ts      Zod schemas: Row, Canary, Registry, ScanResult, ProbeResult
 |     token.ts      HMAC-based token derivation  (ARGOS_CANARY_KEY)
 |     registry.ts   read / write / validate registry.json
 |     generate.ts   canary item generation  (template first, LLM optional)
 |     llm.ts        Anthropic SDK wrapper + usage log + validation
 |     issue.ts      insert canaries, write per-recipient copies
 |     scan.ts       normalize + match + rank recipients
 |     stats.ts      match length -> p-value, verdict thresholds
 |     probe.ts      send prefixes, compare completions, include control tokens
 |     model-client.ts   HTTP adapter  (mock now, real endpoints later)
 |     report.ts     markdown evidence report
|     attacks.ts    simulated attacks on a copy  (subset, scrub, diff, paraphrase-lite, frame ...)
|     stress.ts     runs attacks x trials -> identification rate table  (out/stress.json)
 |
 +-- fixtures/eval-set/eval.jsonl        sample eval set (40 items)
 +-- fixtures/mock-model/server.ts       mock model: --memorize / --clean
 +-- eval/canary.ts                      tests  (pnpm run eval:canary)
 +-- demo/canary-demo.sh                 end-to-end demo script
 |
 +-- (existing) src/pipeline.ts, src/checks/*, src/fix/*  ----> run on ../demo/shop-api
                                                                 result JSON is attached to the report
```

### 2.3 데이터 흐름 (파일이 어디서 어디로)

```
 eval.jsonl --+
              |   ARGOS_CANARY_KEY (env, never written to disk)
              v          |
        +-----------+    v
        |   issue   |--> token.ts (HMAC) --> tokens per (dataset, recipient, index)
        +-----+-----+
              |   generate.ts --(optional)--> llm.ts --> Claude API
              v
   out/vendorA.jsonl   out/vendorB.jsonl   out/vendorC.jsonl      -> sent to recipients
   out/registry.json   (tokens, positions, recipients, keyId)     -> keep SECRET
              |
   ...later...|
              v
 leaked.jsonl --> scan  --(reads registry)--> scan.json   {recipient, matched tokens, evidence}
 model URL ----> probe  --(reads registry)--> probe.json  {per canary: match length, p, verdict}
              |
              v
   report <-- scan.json + probe.json + (optional) argos-scan.json  -->  out/report.md
```

### 2.4 신뢰 경계와 비밀

```
 NEVER leaves your machine / never committed         MAY be shared
 ---------------------------------------------       ----------------------------------
 ARGOS_CANARY_KEY      (derives every token)          out/vendorX.jsonl  -> its own recipient only
 ANTHROPIC_API_KEY     (LLM calls)                    out/report.md      -> after review
 out/registry.json     (lists every token)
```

- **LLM API로는 스키마와 합성 예시만 나간다**(기본값). 실제 문항은 보내지 않는다. 정책은 3.6의 "데이터 반출 정책".
- 레지스트리가 새면 카나리 위치가 드러나 추적이 무력해진다. **파일 권한 600**으로 쓰고 출력에 경고한다.
- 키가 없으면 CLI는 **실행을 거부**한다(조용히 임의 키를 만들지 않는다). 데모용 키는 `.env.example`에 가짜 값으로만 둔다.

### 2.5 고객 행동 기준 흐름

고객이 하는 행동 순서로 본 시스템 전체. (도식 안은 정렬을 위해 영어)

```
 CUSTOMER ACTION                    ARGOS (what runs)                           OUTPUT                       STATUS
 ---------------------------------  ------------------------------------------  ---------------------------  --------------
 1 Point Argos at a data file       PLUG   reads the file format                 ready to run                 5h: CLI only
   (and later: a code repo)                AI drafts config for the API repo     config PR                    later
          |
          v
 2 Send the eval set to vendors     TRACE  issue                                 vendorA.jsonl, vendorB...    5h
   (upload to a bucket, etc.)              per-recipient copies + hidden marks   registry.json (SECRET)
          |
          v
 3 Open a PR on the platform that   PROVE  disposable sandbox                    findings + proof             done (user level)
   serves the data                         log in as users, try to read others'  verified fix PR
                                           data, reproduce, fix, retest
                                    VOUCH  personas x datasets x tasks           access matrix                later
          |
          v
 4 "Can I show this to a customer?" VOUCH  evidence report                       report.md                    5h: header only
                                           (scope, date, hash, limits)
 4b (lowest priority) PDF       VOUCH  export report.pdf; send only on request  report.pdf                   lowest priority
          |
   ........ time passes ........
          |
          v
 5 A file shows up outside          TRACE  scan(leaked file, registry)           "vendorB's copy" + evidence  5h
          |
          v
 6 A model looks suspicious         TRACE  probe(model, registry)                SUSPECTED / NO_EVIDENCE      5h (MOCK model)
          |
          v
 7 A lab asks for proof             VOUCH  hand over the report                  contract attachment          unvalidated
```

```
 +---------------- Customer side ----------------+        +------------- Outside -------------+
 |                                               |        |                                    |
 |  eval.jsonl --> [ argos CLI ] --> copies ------+--------+--> Vendors / labs (just files)     |
 |                      |                         |        |                                    |
 |                      +--> registry.json (SECRET, stays here)                                 |
 |                      |                         |        |                                    |
 |  platform repo --> [ disposable container ]    |        |                                    |
 |   (PR)               runs the app, attacks it  |        |                                    |
 |                      (no network, read-only)   |        |                                    |
 |                      |                         |        |                                    |
 |                      +--> report.md -----------+--------+--> Lab / customer (proof)          |
 |                      |                         |        |                                    |
 |                      +-- schema + synthetic samples ----+--> LLM API (canary text, AI config)|
 +-----------------------------------------------+        +------------------------------------+
```

- Argos는 고객 쪽에서 도는 CLI다. 전달(업로드, 서명 URL, 이메일)은 고객의 일이다.
- 평가 세트를 호스팅 채점으로만 운영하는 고객에게는 사본이 없어 카나리의 적용 범위가 줄어든다(`PLAN.md` 5.6).

## 3. 핵심 설계 결정

### 3.1 토큰: HMAC으로 결정적으로 만든다

```
token(dataset, recipient, i) = tag2 + "-" + hex12
  digest = HMAC-SHA256(ARGOS_CANARY_KEY, dataset + "|" + recipient + "|" + i)
  tag2   = two letters picked from digest      (no constant prefix to filter on)
  hex12  = first 12 hex chars of digest        (48 bits)
```

- 같은 키·같은 입력이면 같은 토큰이다 → 재현 가능, 테스트가 쉽다.
- 접두 문자가 고정되어 있지 않아 "ARG-"를 걸러 내는 단순 필터가 통하지 않는다. (정규식이 아니라 **레지스트리의 토큰 목록**으로 찾기 때문에 가능)
- 추측해서 맞출 확률 약 2^-48. 통계 기준은 3.4절.

### 3.2 카나리 문항: 눈에 띄지 않게

- 토큰을 "Reference code" 같은 **라벨 없이 자연스러운 식별자**(제품 코드, 모델 번호 등)로 문항 안에 넣는다.
- **수신자마다 문항 줄기(stem)가 달라야 한다.** 같은 줄기에 토큰만 다르면 사본을 비교(diff)해서 카나리를 찾아 지울 수 있다(공모). 그래서 수신자 × 카나리 개수만큼 서로 다른 문항을 만든다.
- 삽입 위치는 HMAC에서 파생해 수신자별로 다르게 하되, 레지스트리에 기록한다.

### 3.3 식별(scan): 정규화 후 일치

1. 유출 샘플의 텍스트를 읽는다(jsonl, csv, 일반 텍스트 모두 문자열로 처리).
2. 비교용 정규화: **유니코드 NFKC 정규화 → 제로폭 문자 제거 → 영숫자만 남기고 소문자로**(토큰 쪽도 같은 규칙). 동형문자·제로폭 삽입 같은 값싼 변형을 막는다.
3. 모든 수신자의 모든 토큰을 검색해 **수신자별 일치 개수**를 센다.
4. 결과: 일치가 1개 이상이면 그 수신자(들)를 증거(토큰 ID, 위치)와 함께 보고. 일치가 없으면 **"식별 불가"** (유출이 없었다는 뜻이 아니다).
5. **모함 방어:** 한 유출본에 **둘 이상의 수신자 토큰**이 있으면 단정하지 않고 `MIXED_SOURCES`(공모 또는 혼합 출처)로 표시하며 수신자별 일치 개수를 함께 보여 준다. 일치한 토큰은 레지스트리에 기록된 **줄 번호·앞뒤 문맥**과도 맞는지 확인하고, 안 맞으면 "위치 불일치" 경고를 붙인다.

⚠️ **알려진 한계:** 카나리 문항을 포함하지 않은 일부만 유출되면 식별 불가, 재작성(paraphrase)하면 토큰이 지워질 수 있음, 수신자 간 사본 비교로 제거 가능. 리포트에 반드시 적는다.

### 3.4 오염 질의(probe)와 통계

```
token (normalized) = 2 letters + 12 hex chars = 14 chars
for each canary item i (recipient R) and each CONTROL item c (never issued to anyone):
    prefix  = item text up to the token
    ask model: complete(prefix)  -> completion
    matched = length of the longest common prefix between normalize(completion) and normalize(token)   (0..14)
    p_i     = (1/26)^min(matched,2) * (1/16)^max(matched-2,0)        (null: random letters, then random hex)
decision (per recipient R's canary set, n canaries):
    p_adj     = min(1, n * min_i p_i)                                  (Bonferroni over n canaries)
    SUSPECTED  if max matched >= 10 chars   (2 letters + 8 hex: p ~ 3.4e-13, p_adj ~ n * 3.4e-13)
               AND no control item reaches matched >= 4
    NO_EVIDENCE otherwise
```

- **"오염 없음"이라는 판정은 만들지 않는다.** 가능한 출력은 `SUSPECTED`(오염 의심)와 `NO_EVIDENCE`(증거 없음) 둘뿐이다.
- **대조 항목(control)** 은 누구에게도 발급하지 않은 토큰이다. 모델이 이것을 맞히면 방법 자체가 오염/우연에 취약하다는 뜻이라 판정을 무효로 표시한다.
- 임계값(10자, 대조 4자)은 5시간 안에 정한 초안이며 **실제 모델로 검증하지 않았다.** (확률 계산은 영문자 2자 + 16진수 12자 구조를 반영한다.)

### 3.5 모의 모델: 무엇을 시연하는가

```
 mock-model server (node:http)
   POST /complete  { "prompt": "<prefix>" }  ->  { "completion": "..." }

   --clean                       always returns random hex-like text
   --memorize registry.json      for canaries issued to RECIPIENT: returns the correct token
       --recipient vendorB       with probability RECALL (default 0.8, seeded -> deterministic)
       --recall 0.8              for every other prompt: random text
```

- 시연 문장: **"모의 모델이 vendorB 사본을 학습했다고 가정했을 때 파이프라인이 그것을 잡는다."** 실제 모델에서의 탐지력을 보여 주는 것이 아니다.
- `model-client.ts`는 `complete(prefix) -> string` 인터페이스 하나만 노출해서, 나중에 실제 모델 엔드포인트 어댑터를 같은 자리에 꽂을 수 있게 한다.

### 3.6 LLM은 어디에 쓰고, 어디에 쓰지 않나

| 쓴다 | 쓰지 않는다 |
|---|---|
| 데이터 형식을 보고 **그럴듯한 카나리 문항 줄기** 생성 (수신자별 서로 다르게) | 식별·오염 **판정** (표식 일치와 통계로만) |
| 리포트의 설명 문장(선택) | 토큰 생성 (HMAC으로만) |

```
 generate.ts
   try LLM:  1 call per recipient -> N stems as JSON
             validate (Zod + checks):  same keys as dataset rows,
                                       token appears exactly once and only where we insert it,
                                       no meta words ("canary", "fake", "test", "example"),
                                       length within 0.5x-2x of dataset median
             retry up to 2 times
   fallback: template generator  (fill a stem template from vocabulary lists)  + notice
   log:      out/llm-usage.json  { calls, latencyMs, inputTokens, outputTokens, model }
```

**데이터 반출 정책 (LLM 호출)**

| `--llm-data` | 무엇이 LLM으로 나가나 | 기본 |
|---|---|---|
| `none` | 아무것도. LLM을 쓰지 않고 템플릿 생성기만 사용 | |
| `schema` | **필드 이름·형식·길이 통계와 AI가 만든 합성 예시**만. 실제 문항은 보내지 않음 | ✅ 기본값 |
| `samples` | 실제 문항 일부(최대 5개). **명시적으로 켠 경우에만** | |

- 어떤 값으로 호출했는지는 `llm-usage.json`에 기록하고, 리포트에 "LLM으로 나간 데이터 범위"를 한 줄 적는다.
- `schema` 모드에서도 합성 예시가 실제 문항을 베끼지 않도록 프롬프트에서 금지하고, 검증 단계에서 **원본 문항과의 문자열 겹침**(공통 부분 20자 이상)이 있으면 폐기한다.
- 모델은 환경변수 `ARGOS_MODEL`(기본 코드값), 키는 `ANTHROPIC_API_KEY`. 키가 없으면 템플릿으로 자동 대체하고 알린다.
- 샘플링 파라미터(temperature 등)는 지정하지 않는다. 응답은 텍스트 JSON으로 받아 **스키마로 검증**한다.
- **비용은 미측정.** 첫 실행에서 기록하고, 호출 상한(`--max-llm-calls`, 기본 수신자 수 × 2)을 둔다.

## 4. CLI 계약 (0:00–0:30에 확정)

```
argos canary issue  --input eval.jsonl --recipients vendorA,vendorB,vendorC \
                    --out out/ [--canaries 5] [--generate llm|template] [--llm-data none|schema|samples] [--dataset-id eval-q4]
argos canary scan   <leaked-file> --registry out/registry.json [--json out/scan.json]
argos canary probe  --model http://127.0.0.1:8787 --registry out/registry.json \
                    [--recipient vendorB] [--controls 5] [--json out/probe.json]
argos canary stress --input eval.jsonl --recipients vendorA,vendorB,vendorC \
                    [--trials 20] [--seed 7] [--llm-rewrite] [--json out/stress.json]
argos canary report --registry out/registry.json [--scan out/scan.json] [--probe out/probe.json] \
                    [--argos-scan out/argos-scan.json] --out out/report.md
```

| 항목 | 규칙 |
|---|---|
| 환경변수 | `ARGOS_CANARY_KEY`(필수, 16바이트 이상 hex), `ANTHROPIC_API_KEY`(선택), `ARGOS_MODEL`(선택) |
| 종료 코드 | 0 정상, 1 판정 결과가 의심(`scan` 식별됨 / `probe` SUSPECTED), 2 사용법/설정 오류 |
| 출력 | 사람이 읽는 요약 + `--json` 파일. 비밀(키, 레지스트리 내용)은 로그에 찍지 않는다 |

레지스트리 스키마(초안):

```json
{
  "version": 1,
  "datasetId": "eval-q4",
  "keyId": "<first 8 hex of sha256(key)>",      // key mismatch detection, not the key
  "createdAt": "2026-10-24T12:00:00Z",
  "recipients": {
    "vendorB": { "copy": "vendorB.jsonl",
                 "canaries": [ { "i": 0, "token": "QK-3F9A2C1B7D04", "line": 17, "prefix": "..." } ] }
  },
  "controls": [ { "i": 0, "token": "MZ-A81C09E2F5B7", "prefix": "..." } ]   // never issued
}
```

## 5. 작업 분해 (WBS)

A = 프론트엔드·백엔드 조금, B = 메인(풀스택·AI). 한 명이 둘을 맡으면 위에서부터 순서대로.

| ID | 시간 | 담당 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|---|---|
| **T0** | 0:00–0:30 | A+B | 계약 확정, `src/canary/` 뼈대, `src/cli.ts` 분기, 타입(Zod) | `types.ts`, `cli.ts`, 스텁 | `argos canary --help` 동작, `pnpm run typecheck` 통과 |
| **B1** | 0:30–1:15 | B | `token.ts`, `registry.ts`, 템플릿 생성기, **issue** | `issue.ts`, `generate.ts`(템플릿) | 수신자별 사본 생성, 수신자마다 토큰·문항이 다름, 같은 키로 재실행 시 동일 결과, 레지스트리 권한 600 |
| **A1** | 0:30–2:00 | A | 샘플 평가 세트 40문항, **유출 샘플 시나리오**(전체/일부/섞기), **공격 함수 `attacks.ts`**, **모의 모델 서버** | `eval.jsonl`, 시나리오 스크립트, `server.ts` | 서버 `--clean` / `--memorize`가 결정적으로 동작 |
| **B2** | 1:15–2:00 | B | **scan**: 정규화·검색·수신자 순위·증거 | `scan.ts` | 아래 7절의 scan 테스트 통과 |
| **B3** | 2:00–3:15 | B | **probe**, `stats.ts`, `model-client.ts`, 대조 항목 | `probe.ts`, `stats.ts` | 모의 memorize → SUSPECTED, 모의 clean → NO_EVIDENCE, 대조 항목은 일치하지 않음 |
| **A2** | 2:00–3:15 | A | **report** 생성기(견고성 표 포함), **`stress` 러너**, CLI 출력·오류 메시지 다듬기 | `report.ts`, `stress.ts` | 리포트에 발급 내역·식별 결과·오염 판정·**한계 문구**가 항상 포함 |
| **B4** | 3:15–4:00 | B | **LLM 생성**(`llm.ts`), 검증·재시도·폴백, 사용량 로그, **첫 실행** | `llm.ts`, `llm-usage.json` | `--generate llm`이 검증을 통과하는 문항 생성, 키 없으면 템플릿으로 대체, 호출당 비용·시간 기록 |
| **A3** | 3:15–4:00 | A | **시연 스크립트**, 기존 `shop-api` 스캔 결과를 리포트에 첨부 | `demo/canary-demo.sh` | 스크립트 한 번으로 전체 흐름 재생 |
| **I1** | 4:00–4:45 | A+B | 통합, 버그 수정, **리허설 2회** | - | 3분 안에 전체 시연, 실패 시 대체 화면 |
| **F** | 4:45–5:00 | A+B | 동결, 문서 정리 | `PLAN`/`ROLE` 갱신 | 테스트 통과, 한계 문구 확인 |

### 5.1 의존 관계 (크리티컬 패스)

```
 T0 ---> B1 (issue) ---> B2 (scan) ---+
  |                                   |
  |                                   +--> B3 (probe) --> A2 (report) --> A3 (demo) --> I1 --> F
  +---> A1 (data, mock model) --------+          ^
                                                 |
        B4 (LLM)  can start after B1, replaces the template generator at any time (not on the critical path)
```

- 크리티컬 패스: T0 → B1 → B2 → B3 → A2 → A3 → I1. **B4(LLM)는 경로 밖**이라 늦어지면 먼저 자른다.
- A1은 B1과 병렬이고, B3 시작(2:00) 전에 모의 서버가 필요하다.

### 5.2 5시간 일정 (최신: PROVE + VOUCH + PLUG)

| ID | 시간 | 담당 | 작업 | 산출물 | 완료 기준 |
|---|---|---|---|---|---|
| **T0** | 0:00–0:30 | A+B | 계약: 페르소나·벤더 소유권 설정, 매트릭스 JSON, 비밀 유출 점검 형식, 증빙 헤더, `argos init` 입출력 | 타입, 스텁 | 형식이 문서에 고정, `typecheck` 통과 |
| **V1** | 0:30–2:00 | B | **PROVE 코어:** 페르소나 N개(`config.ts`, `executor.ts`), 벤더 단위 소유권 감지(`schema.ts`, `policy.ts`), 페르소나 × 리소스 시나리오(`scenario.ts`, `pipeline.ts`), 매트릭스 판정 | 매트릭스 JSON | 데모 앱에서 기대 vs 실제가 칸마다 나오고 결함 칸은 🔴 + 증거, 정상 칸은 ✅. **기존 `eval`, `eval:mutation`, `github-e2e` 통과(회귀 없음)** |
| **V2** | 0:30–2:00 | A | **데모 플랫폼:** 벤더 3곳 × 데이터셋 × 작업, 결함(벤더 간 읽기, 내보내기 인증 누락, 목록 범위 누락, 민감 필드 `api_key` 노출, 환경을 노출하는 디버그 엔드포인트), 설정, 시드, 수동 재현 스크립트 | `demo/vendor-platform/` | 수동 스크립트로 결함이 실제로 재현됨 |
| **K1** | 2:00–3:00 | B | **비밀 유출 점검** (a) 민감 필드 노출 (b) 환경 카나리 — 5.4 | `checks/secrets.ts` | 5.6의 secrets 테스트 통과 |
| **V3** | 2:00–3:00 | A | **증빙 리포트:** 매트릭스 + 점검별 요약 + 증빙 헤더(범위·시각·해시·한계) | `report.ts` | 헤더 해시가 파일에서 다시 계산한 값과 일치, 한계 문구 포함 |
| **V4** | 3:00–4:00 | B | 벤더 단위 **수정**(`AND vendor_id = ?`, 주체 속성) + `SELECT *` 열 제한 + **매트릭스 단위 재검증** | `fix/` 확장 | 수정 후 같은 매트릭스에서 문제 칸이 ✅, 대조 칸 유지, 새 🔴 없음 |
| **P1** | 3:00–4:00 | A | **`argos init`** (AI 설정 초안) + 편의 지표 T1·K·R 측정 — 5.5 | `src/init/*` | 샘플 앱 3종에서 초안이 스키마를 통과하고 기동 여부·T1·K·R이 기록됨 |
| **I1** | 4:00–5:00 | A+B | 통합, **리허설 2회**, 동결 | - | 3분 안에 전체 시연 |
| **V6** | 5시간 밖 | A | PDF 내보내기 → (별도) 전송, **최하위** (5.3) | `report --format pdf` | 5.3 |
| **C1** | 5시간 밖 | B | **후순위:** TRACE(카나리 발급·식별·오염 탐지), 설계는 3~4절 | `src/canary/*` | 7절 |

**의존 관계:** T0 → V1 → (K1, V3, V4) / T0 → V2 → (K1, V4) / T0 → P1. **V1이 크리티컬 패스**다.

**자르는 순서:** ① P1의 AI 설정(템플릿 초안으로 대체) → ② K1의 (b) 환경 카나리 → ③ V4의 벤더 단위 자동 수정(수정 제안만) → ④ V3의 서식. **V1 매트릭스, K1의 (a), 증빙 헤더는 끝까지 지킨다.**

**matrix-lite (V1 대체안):** 2:00에 매트릭스가 안 나오면 기존 소유권 점검을 페르소나 쌍마다 실행해 결과를 표로 모으는 스크립트로 대체하고, 문서와 시연에서 "matrix-lite"임을 밝힌다.

**매트릭스 JSON (제안)**

```json
{
  "personas": ["vendor1", "vendor2", "anonymous"],
  "resources": ["dataset:d1", "dataset:d2", "export-api"],
  "cells": [
    { "persona": "vendor2", "resource": "dataset:d1", "expected": "deny", "observed": "allow",
      "verdict": "VULNERABLE", "evidence": { "request": "GET /api/datasets/d1", "status": 200, "marker": "..." } }
  ]
}
```

**벤더 단위 수정의 주의:** 기존 규칙 기반 패처는 주체를 `req.user.id`로 추정한다. 벤더 단위에서는 소유 컬럼 이름(`vendor_id`)에 맞춰 `req.user.vendor_id`를 쓰도록 확장한다. 데모 앱이 이 속성을 제공하도록 설계한다(제공하지 않으면 자동 수정은 거부하고 수정 지침만 낸다).

### 5.3 PDF 내보내기·전송 (최하위 우선순위)

**위치:** 마지막 단계("검증 결과·테스트 결과" = 증빙 리포트) 뒤. 5시간 일정에 넣지 않는다. 리허설까지 끝나고 시간이 남을 때만 **생성**부터 하고, **전송은 그다음**이다.

| 단계 | 내용 | 크기 (추정) |
|---|---|---|
| **a. 생성** | `argos canary report ... --format pdf --out out/report.pdf` | 작음~중간 |
| **b. 전송** | 사용자가 명시한 수신자에게 이메일·웹훅 등으로 보냄 | 중간. 자격 증명·동의 필요 |

**생성 방식 후보 (시작 전에 환경에서 확인할 것)**

| 방식 | 장점 | 단점 |
|---|---|---|
| Markdown → HTML → **헤드리스 브라우저로 PDF 출력** | 표·서식이 가장 자연스러움 | 브라우저 설치가 필요(용량 큼), 샌드박스 환경에서 동작 확인 필요 |
| `pandoc` | 설정이 단순 | PDF 엔진(LaTeX 등) 필요, 한글 폰트 설정이 까다로움 |
| JS PDF 라이브러리(`pdfkit` 등) | 브라우저 불필요 | 표를 직접 그려야 함, 한글 폰트를 직접 포함 |

- 어느 쪽이든 **한글이 깨지지 않는지**(폰트 포함)와 **영어 리포트 옵션**(해외 연구소에 보낼 때)을 확인한다.
- PDF 본문에 **증빙 헤더**(범위·시각·`keyId`·사본/레지스트리 해시)와 **한계 문구**가 반드시 들어간다.
- 생성 후 **PDF 자체의 SHA-256**을 출력해 "어느 파일이 전달됐는지"를 고정한다. 서명은 5시간 밖.

**전송 안전 규칙 (외부로 나가는 행동이므로)**

| 규칙 | 내용 |
|---|---|
| 자동 전송 금지 | 리포트를 만들어도 **보내지 않는다.** `argos canary report send ...`처럼 **명시적 명령**일 때만 |
| 수신자 허용 목록 | 설정에 허용한 주소·도메인 밖으로는 거부 |
| 확인 단계 | 수신자와 첨부 해시를 출력하고 확인(`--yes` 없이는 대화형 확인) |
| 자격 증명 | 환경변수로만. 로그·리포트에 출력하지 않음 |
| 민감도 경고 | 리포트에는 샌 데이터의 증거(표식 위치 등)가 들어갈 수 있어, 내용을 검토하라는 경고를 출력 |
| 기록 | 누가·언제·어디로·어떤 해시를 보냈는지 로컬 로그에 남김 |

**완료 기준 (할 때만)**

1. 생성된 PDF가 열리고, 증빙 헤더·매트릭스 표·한계 문구가 있다. 한글이 깨지지 않는다.
2. PDF의 해시가 출력되고, 같은 입력으로 다시 만들어도 **본문 해시(증빙 헤더)는 같다**. (PDF 파일 자체는 생성 시각 때문에 달라질 수 있음을 문서에 적는다.)
3. 전송 단계(구현하는 경우): 허용 목록 밖은 거부, 확인 없이는 보내지 않음, 로그 기록.

### 5.4 비밀 유출 점검 설계 (K1) — `check: "secrets"`

**입력:** 스키마(SQL DDL, Prisma), 라우트 인벤토리, 페르소나. **출력:** Finding(`check: "secrets"`, `proof`, `detail: {column | env}`).

**(a) 민감 필드 노출**

1. 민감 컬럼 탐지: 이름이 `/(api[_-]?key|secret|token|password|passwd|private[_-]?key|hash)/i`이고 텍스트형인 컬럼.
2. 시드: 해당 행의 민감 컬럼에 고유 마커 `ARGOS_SECRET_<n>_<hex6>`를 넣는다(**새 시드 로직**: 기존은 소유권 시나리오의 리소스 행만 시드).
3. 시도: 모든 GET 라우트(상세 경로는 시드된 id)를 **비소유자·익명·소유자** 페르소나로 호출한다.
4. 판정: 비소유자·익명의 응답에 마커 → 🔴. 소유자 응답에 마커 → 🟡("재노출", 설정 `allowOwnerSecretRead`로 허용 가능).
5. 수정: `SELECT *`를 **민감 컬럼을 뺀 명시 열 목록**으로 바꾸고(스키마에서 열 목록을 가져옴), 같은 마커 검사로 재검증한다. 실패하면 수정 지침만 낸다.

**(b) 서버 비밀 유출**

1. 앱 프로세스 환경에 `JWT_SECRET`, `SECRET_KEY`, `APP_SECRET`, `API_KEY`, `STRIPE_SECRET_KEY`를 각각 고유 값 `ARGOS_ENV_<name>_<hex6>`로 주입한다(샌드박스 안의 시험용 값이며 실제 비밀이 아니다).
2. 모든 라우트에 정상 요청과 **오류 유도 요청**(없는 경로, 잘못된 JSON 본문, 매우 긴 파라미터)을 보내고 응답 **본문과 헤더**에서 마커를 찾는다.
3. 판정: 마커가 나오면 🔴. 자동 수정 없음(지침만).
4. **부작용 방어:** 주입한 환경변수가 앱 동작을 바꿀 수 있어(예: 토큰 서명), 로그인 **대조 요청**이 실패하면 판정을 보류하고 주입 없이 다시 시험한다.

**(c) 정적 패턴** — 시간이 남을 때만. 값은 **마스킹**(앞 4자 + 길이)해서 출력한다.

**마커·비밀은 로그와 리포트에 전체를 싣지 않는다**(앞 6자만).

### 5.5 `argos init` 설계 (P1) — 편한 세팅

**목표:** 저장소 경로만 주면 `argos.config.yaml` 초안을 만들고 **실제로 앱이 기동되는지 검증**한다.

```
argos init <repo-dir> [--llm-data none|files] [--out argos.config.yaml]

 1 scan the repo (no LLM):  package.json / pyproject, lockfile, entry file, framework hints,
                            route files, schema files (*.sql, schema.prisma), .env.example
 2 draft config:
     LLM path   -> send ONLY selected files (see data policy) -> JSON -> validate with Config (Zod)
     template   -> fill from detected hints (fallback, also used when no key / --llm-data none)
 3 verify:       start the app in the disposable container, wait for readyPath, try login
 4 print:        T1 (seconds from start to a runnable config), K (fields the user had to fill), pass/fail
```

**LLM 데이터 반출 정책 (`argos init`)**

| `--llm-data` | 무엇이 LLM으로 나가나 |
|---|---|
| `none` | 아무것도. 템플릿 초안만 |
| `files` (기본) | **선택한 파일만**: `package.json`, 진입 파일, 라우트 파일, 스키마 파일의 일부. **비밀 패턴(키, 토큰, `.env`의 값)은 마스킹 후 전송**하고 `.env`·키 파일은 아예 보내지 않음 |

- ⚠️ **소스 코드 일부가 외부 API로 나간다.** 이는 고객 코드를 밖으로 내보내지 않는다는 메시지와 충돌할 수 있으므로 **전송 범위를 출력에 표시하고 `none`으로 끌 수 있게** 한다. 기본값 `files`는 **확정**(2026-10-24).
- 출력과 리포트에 "LLM으로 나간 파일 목록"을 남긴다.

**편의 지표 (측정해서만 말한다)**

| 지표 | 정의 | 측정 |
|---|---|---|
| T1 | `init` 시작부터 기동이 검증된 설정까지의 시간 | 샘플 앱 3종(`orders-node`, `shop-api`, `vendor-platform`) |
| K | 사용자가 직접 채워야 한 항목 수 | 같음 |
| R | 3종 중 사용자 수정 없이 통과한 비율 | 같음 |

한계: 샘플이 모두 Node + sqlite라서 R이 높게 나와도 **일반화할 수 없다.**

### 5.6 메인 CLI·테스트·완료 정의·시연 (5시간 안)

**CLI (기존 `scan`/`fix` 확장 + 신규)**

```
argos init  <repo-dir> [--llm-data none|files]
argos scan  <repo-dir> --checks bac,unauth,sqli,secrets [--matrix] [--personas <file>] --out out/
argos fix   <repo-dir> --checks ... [--apply]
argos report --scan out/findings.json [--matrix out/matrix.json] --out out/report.md
```

**테스트 (`eval/` 에 추가)**

| 구분 | 테스트 | 기대 |
|---|---|---|
| matrix | 데모 앱(벤더 3곳) | 칸마다 기대 vs 실제, 결함 칸 🔴 + 증거, 정상 칸 ✅ |
| matrix | 소유 벤더의 정상 접근 | 허용 유지 (대조) |
| matrix | 기존 A·B 두 사용자 설정 | 기존 `eval`, `eval:mutation`, `github-e2e` 통과 (회귀 없음) |
| secrets(a) | 민감 필드를 노출하는 앱 | 비소유자·익명 🔴, 소유자 재노출 🟡 |
| secrets(a) | 열 제한 수정 후 | ✅, 정상 기능 유지 |
| secrets(b) | 환경을 덤프하는 디버그 엔드포인트 | 🔴 |
| secrets(b) | 환경을 쓰지 않는 앱 | 오탐 0 |
| secrets(b) | 주입 후 로그인 실패 | 판정 보류 + 주입 없이 재시험 |
| evidence | 증빙 헤더 | 필드 존재, 해시 재계산 일치, 한계 문구 |
| init | 샘플 앱 3종 | 초안이 `Config` 스키마 통과, 기동 여부·T1·K·R 기록 |
| init | LLM 키 없음 / `--llm-data none` | 템플릿 초안 + 안내, 소스 미전송 |
| init | `.env`가 있는 저장소 | `.env` 값이 요청 본문에 포함되지 않음(스텁 클라이언트로 검사) |

**전체 완료 정의 (5시간 종료 시)**

1. 시연 스크립트 한 번으로 **init → scan(매트릭스 + secrets) → fix → 재검증 → report**가 3분 안에 재생된다.
2. `typecheck`와 기존 `eval`, `eval:mutation`, `github-e2e`가 통과한다.
3. 리포트에 한계가 빠지지 않는다(예: "시험한 공격에 대한 결과이며 보안을 보증하지 않는다").
4. T1·K·R이 측정값 또는 "미측정"으로 기록된다.

**시연 스크립트 (제안)**

```
argos init  demo/vendor-platform                      # AI draft config, prints T1 / K
argos scan  demo/vendor-platform --checks bac,unauth,sqli,secrets --matrix --out out/
#   -> matrix: mismatched cells in red; secrets: api_key exposed to vendor2, env secret via /debug
argos fix   demo/vendor-platform --checks bac,secrets --apply
argos scan  demo/vendor-platform --checks bac,unauth,sqli,secrets --matrix --out out/after/
argos report --scan out/after/findings.json --matrix out/after/matrix.json --out out/report.md
```

### 5.7 개발자별 작업 분담 (5시간)

표기: **A** = 프론트엔드(백엔드 조금), **B** = 메인(풀스택·AI). ID는 5.2의 작업 ID. 한 명이 둘을 맡으면 크리티컬 패스(B의 V1)를 먼저 한다.

#### 개발자 A — 데모 플랫폼 · 증빙 리포트 · `argos init`

| 순서 | ID | 시간 | 작업 | 건드리는 곳 | 완료 기준 |
|---|---|---|---|---|---|
| 1 | T0 | 0:00–0:30 | B와 계약 합의(매트릭스 JSON, 증빙 헤더, init 입출력) | 문서 | `typecheck` 통과 |
| 2 | V2 | 0:30–2:00 | 데모 플랫폼: 벤더 3곳 × 데이터셋 × 작업, 결함 5종(벤더 간 읽기, 내보내기 인증 누락, 목록 범위 누락, `api_key` 노출, 환경 덤프 디버그), 설정·시드, 수동 재현 스크립트 | `demo/vendor-platform/` | 수동 스크립트로 결함 재현 |
| 3 | V3 | 2:00–3:00 | 증빙 리포트: 매트릭스 + 점검별 요약 + 증빙 헤더(범위·시각·해시·한계) | `report.ts` | 헤더 해시가 재계산 값과 일치, 한계 문구 포함 |
| 4 | P1 | 3:00–4:00 | `argos init`(AI 설정 초안, `files` 기본) + T1·K·R 측정 | `src/init/*` | 샘플 3종에서 초안이 `Config` 통과, 기동 여부·T1·K·R 기록, `.env` 값 미전송 테스트 |
| 5 | I1 | 4:00–5:00 | 시연 스크립트, 리허설 2회 | `demo/`, 문서 | 3분 안에 재생 |

**A가 B에게 받는 것:** 매트릭스 JSON 형식(T0), `scan --matrix` 출력(V1 이후, V3 입력). **A가 B에게 주는 것:** 데모 앱의 소유 컬럼명(`vendor_id`)과 주체 속성(`req.user.vendor_id`), 환경 덤프 엔드포인트 위치(K1 시험용).

#### 개발자 B — PROVE 코어 · 비밀 유출 점검 · 수정·재검증

| 순서 | ID | 시간 | 작업 | 건드리는 곳 | 완료 기준 |
|---|---|---|---|---|---|
| 1 | T0 | 0:00–0:30 | A와 계약 합의 | 문서 | 형식 고정 |
| 2 | V1 | 0:30–2:00 | 페르소나 N개, 벤더 단위 소유권, 시나리오, 매트릭스 판정 (**크리티컬 패스**) | `config.ts`, `executor.ts`, `schema.ts`, `policy.ts`, `scenario.ts`, `pipeline.ts` | 칸마다 기대 vs 실제, 결함 칸 🔴 + 증거. 기존 `eval`, `eval:mutation`, `github-e2e` 통과 |
| 3 | K1 | 2:00–3:00 | 비밀 유출 점검 (a) 민감 필드 (b) 환경 카나리 (5.4) | `checks/secrets.ts` | 5.6 secrets 테스트 통과 |
| 4 | V4 | 3:00–4:00 | 벤더 단위 수정 + `SELECT *` 열 제한 + 매트릭스 재검증 | `fix/` | 수정 후 문제 칸 ✅, 대조 칸 유지, 새 🔴 없음 |
| 5 | I1 | 4:00–5:00 | 통합 점검, 리허설 2회, 동결 | - | 머지 게이트 통과 |

**B의 2:00 점검:** 매트릭스가 안 나오면 matrix-lite로 대체하고 A에게 알린다.

#### 교차 지점과 규칙

```
 T0  ── contract ──┬─► A: V2 demo platform ─────────────┐
                   └─► B: V1 matrix core ──┬─► K1 secrets ─┬─► V4 fix + re-verify ─┐
                                           └──────────────►V3 report (A) ──────────┼─► I1
                                      P1 init (A, independent of B) ───────────────┘
```

- 겹치지 않게 **파일 소유**를 나눈다: A = `demo/`, `report.ts`, `src/init/`, B = 나머지 `src/`. 상대 영역을 고쳐야 하면 먼저 알린다.
- 인터페이스(매트릭스 JSON, Finding, 증빙 헤더)를 바꾸면 바로 알린다.
- 머지 게이트(`typecheck`, `eval`, `eval:mutation`, `github-e2e`)는 B의 영역을 건드린 쪽이 돌린다.
- 자르는 순서는 5.2를 따른다: ① init의 AI 설정 → ② (b) 환경 카나리 → ③ 자동 수정 → ④ 리포트 서식.

## 6. 기존 Argos(기둥 2)와의 연결

> ※ 이 절은 **TRACE 리포트에 기둥 2 결과를 붙이는** 설계다. 메인에서는 리포트가 PROVE 결과(매트릭스, 비밀 유출)를 직접 렌더링하므로 이 연결이 필요 없다.

변경 없이 **결과 파일만 첨부**한다.

```
 cd hackathon/argos
 npx tsx src/cli.ts scan ../demo/shop-api --approve-all --json > out/argos-scan.json
   -> report.ts reads it:  verdict counts, the reproduced findings (route, check, proof lines)
```

- 필요 조건: `demo/shop-api`에서 `npm install` 완료(컨테이너 모드를 쓰지 않으면 호스트 실행).
- 리포트에는 "접근 제어 증명은 별도 도메인의 예제 앱(`shop-api`) 결과이며, 카나리 데모 데이터셋을 서빙하는 시스템의 결과가 아니다"를 명시한다.
- ⚠️ 현재 Argos 코드에는 정책 승인 흐름이 남아 있어 `--approve-all`이 필요하다.

## 7. 테스트와 완료 정의

`eval/canary.ts` (`pnpm run eval:canary`, 머지 게이트에 추가):

| 구분 | 테스트 | 기대 |
|---|---|---|
| issue | 같은 키·입력으로 두 번 발급 | 결과 동일 (결정적) |
| issue | 수신자 3명 | 사본 3개, 서로 다른 토큰, 서로 다른 문항 줄기, 원본 문항은 모두 보존 |
| issue | 키 없음 | 종료 코드 2, 비밀 미출력 |
| scan | 사본 전체를 그대로 유출 | 해당 수신자 식별, 다른 수신자는 0 |
| scan | 사본의 20%를 유출(카나리 포함) | 식별 |
| scan | 카나리를 포함하지 않은 일부만 유출 | **식별 불가** (오탐 아님) |
| scan | 대소문자·구분자를 바꾼 토큰 | 정규화로 식별 |
| scan | 관련 없는 텍스트 | 식별 불가, 오탐 0 |
| scan | 재작성한 샘플 | **식별 불가임을 확인** (알려진 한계로 문서화) |
| probe | 모의 `--memorize vendorB` | vendorB `SUSPECTED`, 나머지 `NO_EVIDENCE` |
| probe | 모의 `--clean` | 전원 `NO_EVIDENCE`, 대조 항목 일치 없음 |
| probe | 대조 항목을 맞히는 모델 | 판정 무효로 표시 |
| llm | 키 없음 | 템플릿 대체 + 안내 |
| llm | `--llm-data schema`(기본) | 프롬프트에 **실제 문항 문자열이 포함되지 않음**(스텁 클라이언트로 요청 본문 검사) |
| llm | 생성 문항이 원본과 20자 이상 겹침 | 폐기 후 재시도·폴백 |
| llm | 생성 문항이 검증 실패 | 재시도 후 폴백 |
| report | 모든 경우 | **한계 문구 포함**, "오염 없음" 표현 없음, "LLM으로 나간 데이터 범위" 한 줄 |
| pdf | (할 때만) 생성 | 파일이 열리고 증빙 헤더·표·한계 문구 포함, 한글이 깨지지 않음 |
| send | (할 때만) 허용 목록 밖 수신자 | 거부, 확인 없이는 전송하지 않음 |
| report | 증빙 헤더 | 데이터셋 ID·수신자·시각·`keyId`·도구 버전·사본별 SHA-256·레지스트리 SHA-256이 있고, **파일에서 해시를 다시 계산하면 일치** |

### 7.1 견고성 실험 (공격 시뮬레이션)

**목적:** "지울 수 있다"를 말로 끝내지 않고 **공격별 식별률**로 보여 준다. 결과는 리포트의 **견고성 표**가 된다.

**방법:** `attacks.ts`의 공격 함수를 발급된 사본에 적용하고, `scan`이 올바른 수신자를 식별하는지 **시행 횟수(`--trials`, 시드 고정)** 만큼 반복해 비율을 낸다.

```
 issue (3 recipients) --> for each attack A, for each trial t:  leaked = A(copy of vendorB, seed t)
                                                                result  = scan(leaked)
                          identification rate(A) = (# trials where result == vendorB) / trials
                          --> out/stress.json --> report "Robustness" table
```

| ID | 공격 | 기대 결과 (구현 전 예상, **실측 아님**) | 비고 |
|---|---|---|---|
| S1 | 사본 전체 그대로 | 100% | 기준선 |
| S2 | 무작위 줄 일부만 유출 (10% / 25% / 50%) | 이론값: 카나리 k=5개, 유지 비율 f일 때 `1-(1-f)^k` → **10% ≈ 41%, 25% ≈ 76%, 50% ≈ 97%** | **이론값과 실측을 비교**해 코드 점검 |
| S3 | 카나리 줄을 알고 **제외**하고 유출 | 0% | 위치를 아는 공격자는 방어 불가. 한계로 기록 |
| S4 | 대소문자·하이픈·공백·**제로폭 삽입·동형문자** 변경 | 높음 (정규화로 대부분 복원) | 정규화 규칙 검증용 |
| S5 | 공격자가 **토큰 형식을 학습**해 정규식으로 삭제 | 0% | 형식 유출 시 무력. 한계로 기록 |
| S6 | **이상치 필터**(문장 길이·어휘가 튀는 줄 제거) | 템플릿 카나리 vs LLM 카나리를 **비교**해 차이를 숫자로 | **LLM 생성의 가치를 입증하는 실험** |
| S7 | **사본 비교(공모)**: 두 사본에서 서로 다른 줄을 제거 | 낮음 (수신자별 줄기가 달라 카나리가 제거됨) | 현재 설계의 약점. 진짜 문제에 섞는 지문이 필요하다는 근거 |
| S8 | **LLM 재작성**(선택, `--llm-rewrite`) | ~0% | 비용 큼 → 10줄 표본만. 첫 번째로 자른다 |
| S9 | **모함**: vendorC의 토큰을 vendorA 유출본에 삽입 | `MIXED_SOURCES`로 표시, 단정하지 않음 | 모함 방어 로직 검증 |

**규칙**

- 표에는 **"기대"와 "실측"을 따로** 적는다. 실측이 없으면 비워 두고, 기대를 결과처럼 쓰지 않는다.
- S2는 **수식과 실측이 크게 어긋나면 버그**로 본다(허용 오차는 시행 횟수에 맞춰 정한다).
- S3·S5·S7처럼 **지는 항목을 숨기지 않는다.** 이 표가 "무엇을 주장하지 않는가"의 근거다.
- 한계 문구에 "표 안의 수치는 우리 시뮬레이션 공격에 대한 것이며 실제 공격자의 능력을 대표하지 않는다"를 넣는다.

**시간 배분 (5시간 안에 흡수):** 공격 함수 S1~S5·S7·S9는 A1(0:30–2:00)에서 순수 함수로 만든다. `stress` 러너와 리포트 표는 A2(2:00–3:15)에 넣는다. S6은 B4에서 LLM 카나리가 생기면 비교한다. **S8은 시간이 남을 때만.**

**전체 완료 정의 (5시간 종료 시)**

1. `demo/canary-demo.sh` 한 번으로 **발급 → 유출 식별 → 모의 모델 오염 판정 → 리포트**가 3분 안에 재생된다.
2. `pnpm run typecheck`, `pnpm run eval:canary`, 기존 `eval`, `eval:mutation`이 통과한다.
3. 리포트와 CLI 출력에 한계(음성은 증거가 아님, 모의 모델, 재작성에 약함)가 빠지지 않고, **견고성 표(S1~S9)** 가 실측 또는 "미실행"으로 채워져 있다.
4. LLM 첫 실행의 호출 수·지연·토큰 사용량이 `llm-usage.json`에 기록되어 있다(또는 키 문제로 못 했다면 그 사실이 기록).

## 8. 시연 스크립트와 기대 출력

```
# 0. setup
export ARGOS_CANARY_KEY=<demo key>             # fake value from .env.example
# 1. issue per-recipient copies
argos canary issue --input fixtures/eval-set/eval.jsonl --recipients vendorA,vendorB,vendorC --out out/
#    -> out/vendorA.jsonl vendorB.jsonl vendorC.jsonl, out/registry.json (mode 600)
# 2. a leak appears (simulated): 25% of vendorB's copy
bash demo/make-leak.sh out/vendorB.jsonl > out/leaked.jsonl
argos canary scan out/leaked.jsonl --registry out/registry.json
#    -> IDENTIFIED vendorB  (3 of 5 canaries matched; evidence: tokens QK-..., lines 4, 17, 29)
# 3. a model that seems to know the data (MOCK, trained on vendorB's copy)
tsx fixtures/mock-model/server.ts --memorize out/registry.json --recipient vendorB &
argos canary probe --model http://127.0.0.1:8787 --registry out/registry.json
#    -> vendorB SUSPECTED (matched 14/14 chars on 4 of 5 canaries; controls: no match)
#       vendorA, vendorC NO_EVIDENCE   [mock model: not a result on a real model]
# 4. evidence report (+ Argos access-control scan attached)
argos canary report --registry out/registry.json --scan out/scan.json --probe out/probe.json \
                    --argos-scan out/argos-scan.json --out out/report.md
```

리포트 목차: ① 발급 내역 ② 유출 식별 결과와 증거 ③ 오염 질의 결과(모의 표시) ④ **견고성 표(시뮬레이션 공격별 식별률)** ⑤ 접근 제어 시험 요약(기둥 2) ⑥ **한계와 하지 않는 주장**.

## 9. 위험과 자르는 순서

| 위험 | 대응 |
|---|---|
| 5시간이 빠듯함 | 크리티컬 패스(T0→B1→B2→B3→A2→A3)만 지키고 B4를 먼저 자름 |
| LLM 첫 실행이 실패하거나 비쌈 | 템플릿 생성기가 기본 경로. LLM은 선택. 호출 상한 |
| 카나리가 쉽게 걸러짐(공모, 재작성) | 수신자별 서로 다른 문항으로 diff 공격 완화. 한계는 리포트에 명시 |
| 통계 임계값이 근거 없음 | 초안임을 명시, 대조 항목으로 최소한의 자체 점검, 실제 모델 검증은 로드맵 |
| 모의 모델이 실제처럼 읽힘 | 출력·리포트·시연 문구 모두에 "mock" 표기 |
| **LLM 호출로 평가 세트가 외부 API에 노출** | 기본 `schema` 모드(실제 문항 미전송), `none`으로 끌 수 있음, 전송 범위를 리포트에 기록, 원본 겹침 검사 |
| **PDF 전송으로 민감한 증거가 외부로 나감** | 자동 전송 금지, 수신자 허용 목록, 전송 전 확인·해시 표시, 로컬 기록 (5.3) |
| **`argos init`이 소스 코드 일부를 LLM API로 보냄** | 선택한 파일만, 비밀 패턴 마스킹, `.env`·키 파일은 제외, `--llm-data none`, 전송 목록 기록 (5.5) |
| **비밀 유출 점검의 부작용·오탐** | 마커 기반이라 오탐은 적지만, 환경 주입이 앱 동작을 바꿀 수 있어 로그인 대조 후 보류·재시험 (5.4) |
| 비밀 유출(키, 레지스트리) | 환경변수만 사용, 레지스트리 권한 600, 로그에 미출력, 커밋 금지(`.gitignore`에 `out/`) |
| 기존 코드와 충돌 | `src/cli.ts`는 분기 몇 줄만 수정, 나머지는 새 디렉터리 |

**자르는 순서:** ① S8(LLM 재작성) → ② LLM 생성(템플릿만, S6 비교도 생략) → ③ 수신자별 문항 줄기 차별화를 단순화 → ④ 리포트 서식 → ⑤ 기둥 2 첨부. **issue·scan·probe(모의) 세 가지는 끝까지 지킨다.**

## 10. 5시간 밖의 다음 단계 (참고)

- 실제 모델 엔드포인트 어댑터(OpenAI 호환 등)와 임계값 실측
- 재작성·일부 유출·공모에 대한 내성 실험, 백도어형 통계 표식
- **증빙 리포트의 PDF 내보내기·전송**(최하위 우선순위, 5.3)
- 공개 웹·저장소 스캔(1B)
- 사용자 판정 제거의 코드 반영, 벤더 단위 소유권·접근 매트릭스
- 기둥 2용 AI 설정 초안, Postgres·Python 지원, 실제 GitHub 리허설
- 구매자 인터뷰(구현 먼저 결정으로 미뤘으며, 구매 의사 미검증 상태)

### 10.1 5시간 밖 설계 메모 — 기둥 4 (VOUCH)

잊지 않기 위한 메모. **5시간 안에는 만들지 않는다**(증빙 헤더만 예외).

**페르소나 설정 (제안)**

```yaml
personas:
  vendor1_annotator: { org: vendor1, role: annotator, auth: { mode: jwt, claims: { org: vendor1, role: annotator } } }
  vendor2_annotator: { org: vendor2, role: annotator, auth: { mode: jwt, claims: { org: vendor2, role: annotator } } }
  admin:             { role: admin, auth: { mode: login } }
  anonymous:         {}
resources:                         # 기대 접근 (설정으로 선언, 사용자 판정이 아님)
  dataset:d1:        { allow: [vendor1_annotator, admin] }
  dataset:d1/task:t1:{ allow: [vendor1_annotator, admin] }      # 작업 단위
  export-api:        { allow: [admin] }
```

**접근 매트릭스 출력 (예)**

```
                  dataset:d1   dataset:d2   task:d1/t1   export-api
 vendor1            allow OK     deny  OK     allow OK     deny  OK
 vendor2            deny  OK     allow OK     deny  FAIL   deny  OK     FAIL = expected deny, observed allow -> red + evidence
 anonymous          deny  OK     deny  OK     deny  OK     deny  FAIL
```

**인증 어댑터 (우선순위)**

| 모드 | 방법 | 비고 |
|---|---|---|
| login(토큰) | 현재 구현 | ✅ |
| cookie | 로그인 응답의 쿠키를 보관해 재사용 | 작음 |
| apiKey | 시드로 키를 심고 헤더로 전송 | 작음 |
| jwt | 시험용 서명 키로 임의 클레임의 토큰 발급 | 중간 |
| oidc | 샌드박스 안의 시험용 IdP, 앱이 issuer/JWKS를 환경변수로 가리킬 때 | 중간~큼. 업체 SDK에 코드가 고정된 앱은 불가 |

**전제 작업:** 소유자 추정을 `users` 외래키에서 `vendor_id`/`org_id`까지 확장, 쓰기·목록·내보내기 시나리오, Postgres 서비스 컨테이너, 조직 단위 수정 규칙.

## 11. 아직 열려 있는 것

1. 기본 차단 모드는 `report`(비차단)로 **확정**. 이번 범위의 `canary`는 차단과 무관.
2. 5시간 동안 작업하는 인원과 실제 역할 분담.
3. 시연 청중과 시연 시간(스크립트는 3분 분량으로 가정).
4. 우선순위는 **Argos 메인 = 공격 증명 + 증빙 + 편한 세팅, 원천 추적은 후순위**로 **재확정됨**(2026-10-24).
   - "API 키 유출"은 응답 속 노출·환경 비밀 노출·하드코딩 세 가지로 **확정**.
   - `argos init`의 LLM 전송 기본값 `files`(선택 파일만, 비밀 마스킹)로 **확정**.
5. LLM 데이터 반출 기본값(`schema`)에 동의하는가. 실제 문항을 LLM에 보내야만 품질이 나온다면 `samples`를 켤지(고객 동의 필요).
6. 샘플 평가 세트의 도메인(문항 형식)은 A가 정한다. 형식은 `{id, question, choices[], answer}` 같은 객관식을 제안.
