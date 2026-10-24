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

또는 "Argos 데모 해줘"라고 말한다. Claude가 단계마다 확인을 받고 명령을 대신 실행한다. GitHub 로그인이 필요하면 `! gh auth login -h github.com -s workflow`를 입력하라고 안내한다.

| 단계 | 하는 일 |
|---|---|
| 1. 준비 확인 | `gh` 설치·로그인·`workflow` 권한 확인 |
| 2. 데모 앱 받기 | 내 계정에 `argos-demo` 레포 생성(기본 비공개), Actions가 PR을 만들 수 있게 레포 설정 켜기 |
| 3. PR 올리기 | 정리처럼 보이지만 다른 벤더 데이터를 읽을 수 있게 하고 API 키를 노출하는 PR |
| 4. Argos 실행 | Actions에서 앱을 Docker(네트워크 없음, 쓰기 토큰 없음)로 띄워 실제로 공격 (1~3분) |
| 5. 리포트 받기 | 리포트 PR 요약, 보고서를 `./argos-demo-report.md`로 저장 |
| 6. 정리 | 데모 레포 삭제(`delete_repo` 권한 필요) |

## Claude 없이 직접 하기

플러그인 폴더(이 저장소에서는 `plugins/argos/`)에서:

```bash
bash demo.sh check
bash demo.sh create --lang ko          # <내 계정>/argos-demo, --public 이면 공개
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
| `template/` | 데모 레포 내용. 멀티테넌트 API(벤더는 자기 데이터만 본다), 의존성 없음. `argos.config.yaml`은 사람이 확인한 규칙(누가 무엇을 읽을 수 있나) |
| `vulnerable.patch` | 데모 PR. ① 데이터셋 조회에서 vendor 조건 제거(BOLA) ② 벤더 프로필을 `SELECT *`로 반환(API 키 노출) |

데모 레포의 `.github/workflows/argos.yml`은 `create`가 Argos 저장소의 `examples/github-workflow.yml`을 **고정된 커밋**(`demo.sh`의 `ARGOS_TOOL_REF`)에서 받아 만든다. 워크플로와 Argos 도구 버전이 항상 같다.

## 결과 (실제 GitHub에서 실행)

| 대상 | 결과 |
|---|---|
| `main` (안전한 기준) | 🔴 0 · 🟢 45 |
| 데모 PR | 🔴 12 (다른 벤더 데이터셋 읽기 6, 프로필의 API 키 노출 6) → 검증된 수정 후 🔴 0 |

리포트 PR(`argos/report-feature-vendor-dashboard` → `feature/vendor-dashboard`)에는 `.argos/report.md`(쉬운 설명), `.argos/evidence.md`(기술 증빙), 수정 커밋이 들어 있다.

## 참고

- `create`는 레포 설정 **Actions → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**를 켠다. 꺼져 있으면 리포트 PR을 만들 수 없다.
- 비공개 레포는 계정의 Actions 사용 시간을 쓴다(한 번에 몇 분).
- 데모 앱의 비밀값·토큰은 모두 테스트용이다. 배포하지 않는다.
