# 02. 아키텍처

## 층 구조 (구현 상태)
```
 Customer / CI
      │  argos init · scan · fix · report
      ▼
 ① CLI & Setup        scan ✅  fix ✅  report ✅  ci ✅  init ⬜(A)   src/cli.ts (B 소유)
 ② PROVE core         config → seed → runner → matrix → scan        ✅
 ③ Checks             bola ✅ unauth ✅ sqli ✅ secrets (a)(b)(c) ✅
 ④ Execution          process ✅ · container ✅ (네트워크 없음·읽기 전용·비root)
 ⑤ Fix & re-verify    열 제한 ✅ · 소유자 검사 ✅ · 그 외 지침         ✅
 ⑥ VOUCH / report     ✅  입력: scan-meta.json, matrix.json, findings.json (+fix.json)   src/report.ts
 ⑦ Demo target        demo/vendor-platform(결함 5종), demo/realistic-app(안전)   ✅(A)
```

## `scan` 실행 흐름
```
loadConfig ─► 임시 복사본 만들기 ─► DB 시드(마커) ─► 앱 기동 ─► ready 확인
   (Zod)       (원본 불변)          (beforeStart)   process|container
                                                         │
   out/*.json ◄─ 점검(bola,unauth,sqli,secrets) ◄─ 매트릭스(페르소나×리소스×대상 조직)
                                                         │
                                          앱 종료 + 임시 복사본 삭제 (항상)
```
- 시드는 **앱이 뜨기 전에** 복사본에 넣는다(`beforeStart` 훅).
- 환경 카나리(`ARGOS_ENV_*`)는 앱 환경에 주입한다(`extraEnv`).
- 전체 시한(기본 300초)이 지나면 기동 중이어도 앱을 정리한다.

## 모듈 지도 (`src/`)
| 파일 | 역할 |
|---|---|
| `config.ts` | 설정 Zod 스키마·로더. 위치를 앞에 둔 한 줄 오류 |
| `types.ts` | 공유 계약: `Verdict`, `Finding`, `Matrix`, `ScanMeta` |
| `runner.ts`, `container.ts`, `errors.ts` | 앱 기동(프로세스/컨테이너), ready 확인, 정리 |
| `seed.ts` | SQLite 시드, 마커·비밀 마커·환경 카나리, 마스킹 |
| `http.ts` | 페르소나 요청(5초 타임아웃, 연결 오류는 결과로 반환) |
| `matrix.ts` | observed/verdict 규칙, 매트릭스 생성, Markdown 표 |
| `checks/*` | 점검 4종 + 정적 스캔 |
| `fix/*` | 제안 생성, 제안별 누적 재검증 |
| `scan.ts` | 전체 파이프라인, 출력 파일, 종료 코드 |
| `report.ts` | 증빙 리포트·PR 요약. 해시를 다시 계산해 파일이 바뀌었으면 거부 |
| `ci.ts` | `argos ci`: scan + fix 검증 + 리포트 + (선택) 적용/PR |
| `pr.ts` | 수정 브랜치·커밋·push·`gh pr create`. 더러운 작업 트리 거부, 끝나면 원래 브랜치로 복귀 |
| `cli.ts` | 명령 연결 |

## 담당 분리
- **B(코어·점검):** `src/` 중 `report.ts`, `init/`을 뺀 전부, `fix/`.
- **A(데모·리포트·init):** `demo/`, `examples/`, `src/init/`. `src/report.ts`는 A 몫이었지만 `ci`에 필요해 B가 첫 버전을 만들었다(입력 계약만 지키면 교체 가능).
- 경계: `cli.ts`는 B 소유(A는 `init`/`report`를 한 줄 연결만). **계약(config 스키마, 매트릭스 JSON, Finding, ScanMeta)을 바꾸면 상대에게 바로 알린다.**
