# Argos 사용 안내

## CI: 설정 없이 보고 PR 받기

`argos.config.yaml`을 직접 쓰지 않아도 됩니다. 워크플로 하나를 넣으면 커밋마다 Argos가 저장소를 분석하고, 격리된 컨테이너에서 앱을 실제로 띄워 권한을 시험한 뒤, 결과를 **전용 브랜치 `argos/report-<브랜치>`의 PR 하나**로 남깁니다.

### 설치
1. [`examples/github-workflow.yml`](../examples/github-workflow.yml)을 `.github/workflows/argos.yml`로 복사하고 `ARGOS_TOOL_REPO`/`ARGOS_TOOL_REF`를 Argos 저장소와 고정 커밋으로 바꿉니다.
2. 저장소(또는 조직) **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**를 켭니다. 꺼져 있으면 브랜치는 push되지만 PR은 만들어지지 않습니다. 이 요건과 포크 PR·트리거 제약은 [prd/11-ci-flow.md "GitHub Actions에서 PR 권한"](../prd/11-ci-flow.md)에 정리된 기존 CI PR 권한 그대로입니다.
3. 러너에 Docker가 있어야 합니다(`ubuntu-latest`에는 있음).

### PR에 들어가는 것
| 파일 | 내용 |
|---|---|
| `argos.config.yaml` | 설정이 없을 때만. AI 초안이며 `provenance`가 `ai-draft`입니다. 확인한 규칙을 `confirmed`로 바꿔 커밋하면 Argos는 그 규칙을 다시 바꾸지 않습니다. |
| `.argos/report.md` | 쉬운 보고서: 무엇이 문제였나와 근거, 수정·재검증 결과, 발견한 API 전체 대비 실행/미실행, 확인되지 않은 정책, 환경 오류·미검증. 미검증·미확인 항목은 취약점으로 세지 않습니다. |
| `.argos/evidence.md`, `.argos/init-report.md`, `.argos/result.json` | 기술 증빙, 설정 초안의 근거, 기계용 요약 |
| 별도 커밋: 코드 수정 | 같은 설정·같은 공격으로 다시 실행해 통과한 수정만. 기대 규칙·시험 범위·테스트·migration·CI 파일을 바꾸는 수정은 넣지 않습니다. |

지원하지 않는 구성이거나 빌드·기동이 실패해도 PR은 만들어지고, 무엇을 확인하지 못했는지와 이유가 적힙니다. 보고서 언어는 설정의 `report.lang`(기본 `en`)을 따르며 `argos ci prepare --lang ko`로 바꿀 수 있습니다.

### 같은 PR이 갱신됩니다
- 새 커밋마다 같은 브랜치를 다시 만들고 **기존 Argos PR의 제목·본문을 수정**합니다(PR이 계속 늘어나지 않음).
- 같은 커밋에 대해 이미 결과가 있으면 push하지 않습니다.
- Argos 브랜치·Argos 커밋에서는 실행하지 않습니다(재귀 방지).
- Argos 브랜치에 사람이 커밋을 push했다면 덮어쓰지 않고 경고만 남깁니다. 설정 확인은 원래 브랜치에 커밋하는 것을 권합니다.

### 권한은 두 단계로 나뉩니다
| job | 하는 일 | 권한 |
|---|---|---|
| `prepare` | 고객 코드 빌드·실행(컨테이너), 설정 초안, 점검, 수정 검증 → artifact | `contents: read`, 자격증명 미보관, 토큰 없음(있으면 지움) |
| `publish` | artifact 검증 후 브랜치 push·PR 생성/수정 | `contents: write`, `pull-requests: write`, `GH_TOKEN` |

`publish`는 고객 저장소를 체크아웃하거나 빌드하지 않습니다. git 객체만 받아 작업 트리 없이 커밋을 만들고, artifact가 `.github/` 수정·비밀값·전체 마커·위조된 PR 마커를 담고 있으면 거부합니다.

### 로컬에서 시험하기
```sh
argos ci prepare --dir . --artifact argos-artifact --isolation container
argos ci publish --artifact argos-artifact --remote <git-url> --repo <owner/name>
```
