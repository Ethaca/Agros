# 노트북 Docker 검사 연결

GitHub OAuth 웹앱에 들어온 PR을 이 노트북의 Docker에서 실제 HTTP 요청으로 검사한다. 기존 코드 리뷰와 별도의 `argos/sandbox` 상태·댓글·웹 상세 패널을 제공한다. GitHub App 설치형 서비스 전체를 구현한 것은 아니다.

```text
GitHub PR → 웹앱의 코드 분석 → D1에 실행 작업 저장
                            ↓
                  노트북 Worker가 작업 한 개 받기
                            ↓
              서버가 정확한 PR SHA의 소스만 전달
                            ↓
       준비 컨테이너: 소스 정리·SQL 분석·합성 DB 생성
                            ↓
       앱 컨테이너: 읽기 전용 소스 + /tmp의 테스트 DB
                            ↓
       호스트의 신뢰된 검사기: loopback 중계로 HTTP 검사
                            ↓
              결과 JSON → 서버 → PR 댓글·상태
```

## 처음 한 번

Docker Desktop을 켜고 저장소 루트에서 실행한다.

```bash
pnpm sandbox:build
node apps/web/scripts/setup-demo.mjs --sandbox-repos gngsn/argos-realistic-app
```

이미 설정한 GitHub Client ID·Secret·세션/암호화 키는 유지한다. Worker 전용 키는 `.dev.vars`에 생성되고, Git에는 올라가지 않는다. 실행 저장소는 `SANDBOX_REPOS` 허용 목록과 사용자가 웹앱에서 보호를 켠 목록에 **모두** 있어야 한다. 기본값은 실행 비활성이다.

## 데모 실행

세 터미널에서 각각 실행한다.

```bash
# 1. 웹 서버: 변경된 .dev.vars를 반영하려면 기존 서버를 재시작
node apps/web/scripts/start-demo.mjs

# 2. GitHub가 이 노트북에 알림을 보내는 통로
cloudflared tunnel --url http://127.0.0.1:8787 --no-autoupdate

# 3. 실제 Docker 작업을 처리하는 Worker (한 번에 한 작업)
pnpm sandbox:worker
```

터널 주소가 바뀌면 [데모 설정](../apps/web/DEMO.md)에 따라 PUBLIC_URL, OAuth Callback, 저장소 Webhook을 갱신한다. 웹앱에서 로그인 → 테스트 저장소 보호 켜기 → PR 생성 또는 수동 검사를 진행한다. 활성화 시 이미 분석된 PR의 최신 기록도 한 번 검사한다.

Worker만 한 작업 처리하고 종료하려면 `pnpm sandbox:worker --once`를 사용한다.

## 무엇을 검사하나

첫 어댑터는 루트 `app.mjs/app.js/server.mjs/server.js`로 시작하는 Express + `node:sqlite` 앱이다. `PORT`, DB 경로, Bearer `token:org` 목록을 환경변수로 설정할 수 있어야 한다. 이미지에는 신뢰된 고정 Express 의존성이 들어 있으며 고객의 npm install·빌드·start 스크립트는 실행하지 않는다. Express 외 의존성이 필요한 앱은 미지원으로 남긴다.

- `bola`: 다른 조직의 시험용 데이터가 실제 응답에 나타나는지 확인.
- `unauth`: 익명 접근 확인.
- `sqli`: 지원하는 쿼리 파라미터의 오류 대조 요청.
- `secrets`: 합성 비밀 컬럼과 주입한 환경 카나리의 응답 노출 확인.

GET만 실행한다. SSRF 공격, 외부 API, 역할/쓰기 검사, 자동 수정·재검증은 이 어댑터에 연결하지 않았다. 구성된 경로 목록과 건너뛴 경로를 보고서에 남긴다. 정상 사용자의 자기 데이터 접근 대조가 실패하면 실행 전체를 미검증으로 처리한다.

저장소의 `argos.config.yaml`이 있으면 기대 접근 규칙에 사용하고, 없으면 자동 초안을 만든다. 실행 명령·환경·이미지·기존 토큰은 그대로 사용하지 않는다. 어느 경우든 업무상 기대 권한이 검토·확정됐다는 의미는 아니며 결과에 정책 출처를 표시한다.

## 격리 경계

| 항목 | 실제 적용 |
|---|---|
| 고객 코드·SQL | 준비와 실행을 각각 Docker 안에서만 수행 |
| 소스 전달 | GitHub의 정확한 SHA 아카이브를 컨테이너 안에서만 해제 |
| 파일 | `.env`, 키 파일, `.git`, `node_modules`, DB 제외; 링크·특수 파일 거부 |
| 앱 소스 | 읽기 전용 Docker 볼륨; 호스트 폴더 바인드 마운트 없음 |
| 쓰기 영역 | 실행별 tmpfs 볼륨 256 MiB, 앱 `/tmp` 64 MiB |
| 권한 | UID/GID 1000, capability 전체 제거, no-new-privileges |
| 네트워크 | 준비·앱·볼륨 유지 컨테이너 모두 `--network none`; 공개 포트 없음 |
| 통신 | 노트북 loopback의 제한된 TCP 중계 → `docker exec` → 앱의 3000 포트 |
| 비밀 | GitHub/LLM/Worker 토큰·호스트 환경을 고객 컨테이너에 전달하지 않음 |
| Docker | 고객 컨테이너에 Docker 소켓·CLI 제어권을 주지 않음 |
| 실행 제한 | 컨테이너별 CPU 1, 메모리 512 MiB, PID 128; 검사 3분·앱 준비 30초 |
| 입력·출력 | 압축 소스 20 MiB, 소스 파일/크기 제한, 서비스 HTTP 응답 64 KiB, 결과 512 KiB |
| 정리 | 해당 실행의 컨테이너·볼륨만 삭제; Worker가 5분 만료 자원도 회수 |

tmpfs는 마지막 마운트가 닫히면 지워지므로, 신뢰된 볼륨 유지 컨테이너 하나가 준비와 앱 실행 사이에만 볼륨을 유지한다. 이 컨테이너에는 고객 코드를 실행하지 않는다.

Docker 커널 격리는 절대적인 보안 보증이 아니다. 현재는 허용 목록의 데모 프로젝트로 운용하며 공개 다중 고객 서비스·microVM 수준 격리·Spring 자동 준비는 별도 작업이다. 기존 CLI의 `process` 모드나 호스트 준비 코드는 이 서비스 경로에서 호출하지 않는다.

## 작업과 결과

작업은 D1에 저장하고 원자적 lease로 가져간다. Worker 인증·작업별 lease·저장소 소유/활성 상태를 각각 확인한다. 만료 lease는 상한 내에서 재시도하고, 게시 전 결과를 저장해 GitHub 게시 실패 시 재실행 없이 재게시할 수 있다. 완료 게시 전에 PR SHA를 다시 확인해 오래된 커밋 결과는 `superseded`로 남긴다.

원본 응답·DB·전체 토큰·소스 로그를 반출하지 않는다. 검사표·마스킹된 Finding만 검증된 JSON으로 반환한다. 별도 PR 댓글에 4종 검사별 발견/의심/미탐지/미실행 개수와 접근표를 표시하고 웹 상세 화면에는 전체 접근표를 제공한다. 미지원·실패는 통과가 아니라 `argos/sandbox`의 오류로 표시한다.

## 종료와 다시 시작

Worker와 웹 서버는 각각 `Ctrl+C`로 종료한다. Worker 종료 신호는 실행 중 검사에 전달되며 해당 실행의 컨테이너와 볼륨을 정리한다. 컴퓨터 강제 종료 등으로 남은 자원은 Worker 재시작 후 만료 확인을 거쳐 회수한다. 다른 Docker 프로젝트를 지우는 전역 정리 명령은 사용하지 않는다.

검사를 끄려면 `.dev.vars`에 `SANDBOX_ENABLED=false`를 설정하고 웹 서버·Worker를 재시작한다. 코드 리뷰만 계속 사용할 수 있다.

## 검증

```bash
node --import tsx --test --test-timeout=180000 test/sandbox.test.ts
pnpm --dir apps/web exec tsx --test test/sandbox.test.ts
```

정상 앱 대조, 실제 교차 조직 데이터 접근, 소스의 실행 명령·환경 무시, 읽기 전용 소스, 비root·무권한·네트워크 차단, 호스트/소켓 비노출, 결과 크기와 토큰 반출 제한, 시간 초과 정리, 작업 lease·소유권·접근 철회를 검증한다.

### 2026-10-24 연결 확인

- `gngsn/argos-realistic-app` PR #1, SHA `7214cc5`를 GitHub에서 받아 준비·실행·결과 게시까지 완료했다.
- 8개 경로의 접근표 62칸을 실행했고, 소유권 조건이 제거된 데이터 조회에서 교차 조직 접근 6건을 재현했다. SSRF 엔드포인트와 비GET 요청 등은 미검증으로 보고했다.
- [실제 Docker 결과 댓글](https://github.com/gngsn/argos-realistic-app/pull/1#issuecomment-6380940028)에 `argos/sandbox` 상태와 별도 결과가 게시됐다.
- 웹 테스트 41개, 관련 HTTP·매트릭스·Docker 서비스 테스트 31개, 웹/루트 타입 검사를 통과했다. 컨테이너 자원은 실행 후 남지 않았다.
- 전체 루트 테스트 실행은 기존 `test/container.test.ts`의 전역 `argos=1` 자원 정리/빈 목록 검사 4건에서 동시에 돌아가는 다른 Docker 작업과 충돌했다. 해당 파일만 단독 실행하면 10건 모두 통과했다. 새 서비스는 별도 `argos.local-sandbox=1` 라벨과 실행별 이름을 사용한다.
