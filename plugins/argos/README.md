# Argos demo plugin

**English** · [한국어](#argos-데모-플러그인--pr-하나로-argos-체험)

Try Argos on your own GitHub account in about 5 minutes. You open a harmless-looking PR; Argos in GitHub Actions starts the app in Docker, actually attacks it, and opens a PR with the report (and, for Node, a fix proven by the same attacks).

```
/plugin install argos --marketplace Ethaca/Agros     # older Claude Code: /plugin marketplace add Ethaca/Agros, then /plugin install argos@argos
/argos:demo
```

You need Claude Code, `git` and the [GitHub CLI](https://cli.github.com) (`gh`). No Node or Docker locally. The tutorial asks for **English or 한국어** first; the report and the demo PR use the same language. Then pick a demo app: **Node.js** (about 1 minute, verified fix) or **Spring Boot** (about 4 minutes, zero config).

Without Claude: `bash demo.sh check | create --stack node|spring --lang en | pr | watch | report | cleanup` from the plugin folder.

---

# Argos 데모 플러그인 — PR 하나로 Argos 체험

내 GitHub 계정에 데모 레포를 만들고, 겉보기엔 무해한 PR을 올리면 GitHub Actions의 Argos가 앱을 Docker에서 실제로 공격해 보고 **리포트와 재검증된 수정이 담긴 PR**을 열어 준다. 5분 정도 걸린다.

```text
GitHub 로그인 → 데모 앱 받기 → 취약 PR → Argos (Actions) → 리포트 PR 받기 → 정리
```

## 설치

필요한 것: [Claude Code](https://claude.com/claude-code), `git`, [GitHub CLI](https://cli.github.com)(`gh`). 로컬에 Node·Docker는 필요 없다.

Claude Code에서:

```
/plugin install argos --marketplace Ethaca/Agros
```

이전 버전의 Claude Code라면 두 단계로:

```
/plugin marketplace add Ethaca/Agros
/plugin install argos@argos
```

## 사용

```
/argos:demo
```

또는 "Argos 데모 해줘"라고 말한다. 6단계 튜토리얼로(처음에 English / 한국어 선택), 단계마다 목표·결과·핵심 한 줄만 보여 주고 확인을 받은 뒤 명령을 대신 실행한다. GitHub 로그인이 필요하면 `! gh auth login -h github.com -s workflow`를 입력하라고 안내한다.

| 단계 | 하는 일 |
|---|---|
| 1. 준비 확인 | `gh` 설치·로그인·`workflow` 권한 확인 |
| 2. 데모 앱 받기 | Node.js 또는 Spring Boot 중 선택, 내 계정에 `argos-demo` 레포 생성(기본 비공개), Actions가 PR을 만들 수 있게 레포 설정 켜기 |
| 3. PR 올리기 | 정리처럼 보이지만 권한 검사를 깨뜨리는 PR |
| 4. Argos 실행 | Actions에서 앱을 Docker(네트워크 없음, 쓰기 토큰 없음)로 띄워 실제로 공격 |
| 5. 리포트 받기 | 리포트 PR 요약, 보고서를 `./argos-demo-report.md`로 저장 |
| 6. 정리 | 데모 레포 삭제(`delete_repo` 권한 필요) |

## Claude 없이 직접 하기

플러그인 폴더(이 저장소에서는 `plugins/argos/`)에서:

```bash
bash demo.sh check
bash demo.sh create --stack node --lang ko   # 또는 --stack spring. <내 계정>/argos-demo, --public 이면 공개
bash demo.sh pr
bash demo.sh watch
bash demo.sh report --save argos-demo-report.md
bash demo.sh cleanup
```

모든 명령은 `--repo <owner/name>`으로 레포 이름을 바꿀 수 있다.

## 무엇이 들어 있나

| 파일 | 내용 |
|---|---|
| `skills/demo/SKILL.md` | `/argos:demo` 안내 절차 |
| `demo.sh` | 각 단계를 실행하는 스크립트 (`git`, `gh`만 사용) |
| `template/node/` | 데이터 라벨링 멀티테넌트 API(벤더는 자기 데이터만 본다). 의존성 없음(Argos CI는 검사 대상의 `npm install`을 실행하지 않는다). `argos.config.yaml`은 사람이 확인한 규칙 |
| `patches/node.patch` | Node 데모 PR. ① 데이터셋 조회에서 vendor 조건 제거(BOLA) ② 벤더 프로필을 `SELECT *`로 반환(API 키 노출) |
| `template/spring/` | 협업 문서 서비스: Spring Boot 3.5 + Security(JWT) + JPA + PostgreSQL + Flyway(Gradle). Argos 설정 없음: Argos가 코드에서 초안을 만든다. `test/fixtures/spring/gradle-app`의 복사본 |
| `patches/spring.patch` | Spring 데모 PR. ① 프로젝트 조회에서 조직 조건 제거 ② 문서 조회에서 작성자 조건 제거 ③ `/api/admin/**` 관리자 규칙 제거. 적용 결과는 `demo/spring-workspace`와 같다 |

데모 레포의 `.github/workflows/argos.yml`은 `create`가 Argos 저장소의 `examples/github-workflow.yml`을 **고정된 커밋**(`demo.sh`의 `ARGOS_TOOL_REF`)에서 받아 만든다. 워크플로와 Argos 도구 버전이 항상 같다. 복사본(`template/spring`, `patches/spring.patch`)이 원본과 달라지면 `test/demo-plugin.test.ts`가 실패한다.

## 결과

| 스택 | `main` (안전한 기준) | 데모 PR | 리포트 PR |
|---|---|---|---|
| Node | 🔴 0 · 🟢 45 | 🔴 12 (다른 벤더 데이터셋 읽기 6, 프로필의 API 키 노출 6) | 검증된 수정 포함, 🔴 12 → 0 (실제 GitHub, 약 1분) |
| Spring | 🔴 0 · 🟢 186 | 🔴 45 (다른 조직 접근, 동료 문서 접근, 멤버의 관리자 기능 사용) | 리포트 + 설정 초안, 자동 수정 없음 (실제 GitHub, 약 4분) |

리포트 PR(`argos/report-<PR 브랜치>` → PR 브랜치)에는 `.argos/report.md`(쉬운 설명), `.argos/evidence.md`(기술 증빙)가 들어 있다. Node는 수정 커밋, Spring은 Argos가 만든 `argos.config.yaml` 초안도 함께 들어 있다.

## 참고

- `create`는 레포 설정 **Actions → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**를 켠다. 꺼져 있으면 리포트 PR을 만들 수 없다.
- 비공개 레포는 계정의 Actions 사용 시간을 쓴다(한 번에 몇 분).
- 데모 앱의 비밀값·토큰은 모두 테스트용이다. 배포하지 않는다.
