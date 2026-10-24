# Demo apps

Argos가 동일한 멀티테넌트 API를 두 상태로 검사한다. `vendor-platform`은 결함을 재현하는 대상이고, `realistic-app`은 동일한 업무 흐름을 안전하게 구현한 기준 앱이다.

| 앱 | 결과 |
|---|---|
| `vendor-platform/` | 의도적으로 심은 취약점이 🔴로 발견됨 |
| `realistic-app/` | 정상 접근만 허용되며 🔴 0건 |

```bash
cd demo/vendor-platform && npm install
npm run exploit
bash manual-exploit.sh ../realistic-app
```

## Argos가 확인하는 취약점

- [x] **BOLA** — 다른 벤더의 데이터셋·작업을 ID로 조회할 수 있는지
- [x] **미인증 접근** — 로그인 없이 내보내기 API를 실행할 수 있는지
- [x] **SQL injection** — 검색어가 SQL 구문으로 실행되는지
- [x] **응답 내 비밀값 노출** — 공개 프로필에 API 키가 포함되는지
- [x] **환경변수 노출** — 디버그 엔드포인트가 비밀 환경변수를 반환하는지

`realistic-app`은 세 벤더, 데이터셋, 작업, 공개 제품 목록, 벤더 프로필, 내보내기 흐름을 가진 안전한 기준 앱이다. 다른 벤더의 데이터는 404, 미인증 요청은 401로 처리하며 민감 필드는 응답에 포함하지 않는다.

## Spring Boot 데모 — 설정 0줄, 명령 1개

`spring-workspace/`는 Spring Boot 3.5 + Security JWT + JPA + PostgreSQL + Flyway(Gradle) 앱이고, 권한 결함 세 개(다른 조직 접근, 동료 문서 접근, 멤버의 관리자 기능 사용)가 들어 있다. Argos 설정 파일은 넣지 않았다: `argos init`이 코드에서 만든다.

```bash
pnpm demo:spring              # Docker만 필요 (Java 불필요)
pnpm demo:spring --baseline   # 정상 앱도 검사해 오탐이 없음을 비교
```

심사위원용 안내: [SPRING_DEMO.md](SPRING_DEMO.md)
