# Argos PRD 모음

지금까지의 논의와 구현에서 **나중에도 필요한 결정과 사실**만 주제별로 정리한 문서다. 코드로 알 수 있는 것은 줄이고, 왜 그렇게 했는지와 한계를 남겼다. 기준 시점: 2026-10-24.

| 파일 | 내용 |
|---|---|
| [01-product.md](01-product.md) | 무엇을 만드는가, 누구를 위한 것인가, 범위·비범위, 확정된 결정 |
| [02-architecture.md](02-architecture.md) | 층 구조, 모듈 지도, `scan` 실행 흐름, 담당 분리(A/B) |
| [03-config.md](03-config.md) | `argos.config.yaml` 스키마, 검증 규칙, 라우트 표기 |
| [04-checks-and-verdicts.md](04-checks-and-verdicts.md) | 점검 4종, 매트릭스 판정 규칙, "안전으로 보이지 않게" 하는 규칙 |
| [05-isolation.md](05-isolation.md) | 프로세스/컨테이너 격리, 위협 모델, 네트워크 설계, 한계 |
| [06-output-contracts.md](06-output-contracts.md) | `matrix.json`, `findings.json`, `scan-meta.json`, 마스킹 규칙 |
| [07-fix.md](07-fix.md) | 수정 제안과 재검증 방식, 채택 기준 |
| [08-testing.md](08-testing.md) | 테스트 전략, 시나리오, 실행 방법, 수치 |
| [09-decisions.md](09-decisions.md) | 결정 기록(왜 그렇게 했나) |
| [10-status-and-roadmap.md](10-status-and-roadmap.md) | 구현 현황, 남은 일, 위험·열린 질문 |
| [12-init.md](12-init.md) | `argos init` 설계: 단계, 탐지 규칙, 기대 규칙을 코드에서 추정하지 않는 이유, 시험 환경 구성, 검증, 전송 정책, `--update`/`--check`, 구현 상태 |
| [11-ci-flow.md](11-ci-flow.md) | CI 목표 흐름(정적→LLM 설정→동적→수정→PR→보고서), 현재 구현, 순환 논리 위험, 비개발자용 PR 메시지 |

관련 문서: 명세 `docs/SPEC.md`(구현 기준), 역할 `docs/ROLE.md`, 진행 현황 `docs/develop/status/sun.md`, 출력 예시 `examples/out/`.

설치형 제품의 진입점과 구현 순서는 [GitHub App 구현 계획](../docs/GITHUB_APP_PLAN.md)을 따른다. 고객은 App 설치와 저장소 선택만 수행하고, Argos 서비스가 자동 설정·격리 검사·별도 결과 PR 생성을 담당한다.
