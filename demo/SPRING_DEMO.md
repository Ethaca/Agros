# Spring Boot 데모: 설정 0줄, 명령 1개

Argos는 Spring Boot 저장소를 받으면 **설정 파일, 테스트 계정, DB 시드 없이** 권한 결함을 실제 HTTP 요청으로 증명한다.
심사위원은 아래 명령 하나만 실행하면 된다.

## 1. 준비물 (Java 불필요)

- Node.js 22 이상, pnpm
- Docker Desktop 실행 중

Java, Maven, Gradle, PostgreSQL은 설치하지 않아도 된다. 빌드와 실행은 전부 격리된 컨테이너 안에서 일어난다.

## 2. 실행

```bash
git clone https://github.com/Ethaca/Agros.git && cd Agros
pnpm install
pnpm demo:spring
```

끝이다. 첫 실행은 의존성 다운로드 때문에 몇 분 걸리고, 이후 실행은 약 1분이다.
결함 없는 정상 앱과 비교하려면 `pnpm demo:spring --baseline`을 실행한다 (약 2분).

터미널에는 이렇게 나온다:

```
━━━ 결함이 있는 데모 앱 (demo/spring-workspace) ━━━
① argos init   코드를 읽고 설정 초안 작성 (몇 초)
   found: API: 16개 발견, 16개를 설정에 넣음
   likely finding: GET /api/projects/{projectId}: 소유권 조건 누락 의심: ProjectService.get → ProjectRepository.findById(id)에 org_id 조건이 없음 ...
② argos scan   샌드박스에서 빌드·실행 후 권한 공격
   결과: 🔴 취약 45 · 🟡 의심 0 · 🟢 정상 141 · ⚪ 판단 불가 0
   🔴 다른 조직의 데이터를 읽거나 바꿈: 12건 (예: orgA-admin → GET /api/projects/2 → 200)
   🔴 같은 조직 동료의 데이터를 읽거나 바꿈: 24건 (예: orgA-admin → GET /api/projects/1/documents/… → 200)
   🔴 권한 없는 사용자가 관리자 기능을 씀: 9건 (예: orgA-member → GET /api/admin/organization → 200)
```

①은 코드만 읽고 의심 지점을 찾고, ②는 그 의심을 실제 요청으로 증명한다.

## 3. 결과 보기

터미널에 요약이 나오고, 자세한 내용은 `out/spring-demo/spring-workspace/`에 있다.

| 파일 | 내용 |
|---|---|
| `report.md` | 검증 보고서: 무엇이 뚫렸는지, 요청·응답 증거, 미검증 범위 |
| `init-report.md` | 코드 분석 보고서: 찾은 API, 각 권한 규칙의 코드 근거(파일:줄) |
| `argos.config.yaml` | Argos가 코드에서 자동으로 만든 설정 (사람이 쓴 줄 0) |

## 무엇이 일어나나

```
pnpm demo:spring
 ├─ ① argos init  : Java 코드·Security 설정·Flyway migration을 읽고 API 16개와 권한 규칙을 추출
 ├─ ② argos scan  : 샌드박스에서 빌드 → PostgreSQL·테스트 JWT 발급자 준비 → 두 조직의 관리자·멤버 데이터 생성
 │                  → 실제 서명된 JWT로 "다른 조직 / 같은 조직 다른 사람 / 관리자 전용 / 로그인 없음" 공격
 └─ ③ argos report: 결과를 쉬운 한국어 보고서로 작성
```

데모 앱(`demo/spring-workspace`)은 Spring Boot 3.5 + Spring Security(JWT) + JPA + PostgreSQL + Flyway로 만든 협업 문서 서비스이고, 흔한 권한 실수 세 개가 들어 있다.

| 심어 둔 결함 | 코드 위치 | Argos가 보여 주는 증거 |
|---|---|---|
| 다른 조직 데이터 접근 | `ProjectService.get`: `findById`만 쓰고 조직 확인 없음 | 다른 조직 프로젝트 조회·수정 성공 |
| 같은 조직 동료의 문서 접근 | `DocumentService.get`: 소유자 확인 없음 | 동료 문서 조회·수정·삭제 성공 (DB 변경으로 확인) |
| 일반 멤버의 관리자 기능 사용 | `SecurityConfig`: `/api/admin/**` 역할 규칙 없음 | 멤버가 관리자 API 실행 성공 |

`--baseline`으로 실행하면 같은 앱의 정상 버전도 같은 방식으로 검사한다. 결과는 🔴 0 · 🟡 0 · 🟢 186 · ⚪ 0: 오탐이 없다.

## 직접 해 보기 (선택)

스크립트 없이 명령 세 개로도 같다. 어떤 Spring Boot 저장소에도 그대로 쓸 수 있다.

```bash
cp -R demo/spring-workspace /tmp/my-app
pnpm argos init /tmp/my-app                                              # 설정 자동 작성 + 실제 기동 확인
pnpm argos scan --config /tmp/my-app/argos.config.yaml --out out/my-app   # 공격 실행
pnpm argos report --scan out/my-app --lang ko                            # 보고서
```

## 안전장치

- 고객 코드는 네트워크가 막힌 컨테이너에서만 실행된다. 빌드는 허용된 Maven/Gradle 저장소에만 접근할 수 있다.
- DB, 키, 토큰은 실행마다 새로 만들고 끝나면 지운다. 보고서에는 토큰·비밀값이 남지 않는다.
- 판단할 수 없는 항목은 "안전"이 아니라 ⚪(판단 불가)로 표시한다.

## 문제가 생기면

| 증상 | 해결 |
|---|---|
| `Docker is not running` | Docker Desktop을 켜고 다시 실행 |
| 첫 실행이 오래 걸림 | 정상. Gradle·의존성을 컨테이너 안에서 내려받는 중 (이후 캐시됨) |
| `scan failed` | `out/spring-demo/spring-workspace/scan.log` 마지막 줄 확인 |
