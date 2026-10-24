# 11. CI 흐름 (목표와 현재)

## 목표 흐름
```
사용자가 코드를 커밋 → CI 실행
  ① 정적 탐지        소스에서 라우트·스키마·역할 규칙·시험 환경을 찾는다
  ② 설정 정의        ①을 근거로 가장 유력한 설정을 만든다 (LLM 판단 + 이전 확정 설정 참고)
  ③ 동적 탐지        설정대로 실제 공격 (scan, 컨테이너 격리)
  ④ 수정 건 탐지     고칠 수 있는 항목을 찾고 같은 공격으로 재검증 (fix)
  ⑤ 수정이 있으면    비개발자도 읽을 수 있는 설명의 PR 생성
  ⑥ 항상            증빙 보고서 생성
```
설정은 매번 바뀌므로 ②는 이전 설정·이전 결과를 입력으로 **차이만 갱신**한다(`init --update`, 기준선 비교).

## 현재 구현
| 단계 | 상태 | 비고 |
|---|---|---|
| CI 트리거 / 워크플로 예시 | ✅ | `examples/github-workflow.yml`: prepare(읽기 전용) / publish(쓰기) 두 job. 실제 GitHub에서는 아직 실행해 보지 않음 |
| ① 정적 탐지 | 🔶 | `init`의 라우트·스키마·인증·소유 컬럼 탐지(express-sqlite)와 하드코딩 비밀 스캔. 역할 규칙(코드 밖 근거)은 아직 |
| ② 설정 정의 | 🔶 | `argos init` v1(정적 규칙)으로 설정 초안·기동 검증 가능. LLM 판단과 `--update`는 아직(설계: `12-init.md`) |
| ③ 동적 탐지 | ✅ | 점검 4종, 프로세스/컨테이너 격리 |
| ④ 수정 건 탐지 | ✅ | 열 제한·소유자 검사 자동 수정, 나머지는 지침 |
| ⑤ PR 생성 | 🔶 | 설정 있는 저장소: `argos ci --pr`(수정 PR). 설정 없는 저장소: `argos ci prepare` → `argos ci publish`(설정 초안·쉬운 보고서·검증된 수정을 `argos/report-<브랜치>` 한 PR로, 아래). 본문 문장은 템플릿(LLM 다듬기 없음) |
| ⑥ 보고서 | ✅ | `argos report`, `ci`가 `out/report.md`를 만든다. 첫 버전은 B가 작성(A 구현이 들어오면 교체 가능, 입력 계약은 `out/` 세 파일) |

`argos ci`: 점검 전부 → 수정 검증 → `out/report.md`, `out/pr-body.md`, `out/ci-summary.json` → (수정이 있으면) **새 브랜치를 만들어 PR**. 종료 코드는 **원본 코드** 기준(`block`이고 🔴이 있으면 2): PR에 수정이 있어도 main이 안전해지는 것은 아니다.

### 수정 PR 동작 (결정)
- **항상 새 브랜치.** `argos/fix-<커밋>-<시각>`을 만들어 검증된 패치만 커밋·push하고 `gh pr create`. 체크아웃된 브랜치는 건드리지 않고 끝나면 원래 브랜치로 돌아온다. 채택된 파일만 `git add`하며, 추적 중인 파일에 미커밋 변경이 있으면 거부한다.
- **기본값은 환경에 따른다.** CI(`CI=true`, GitHub Actions가 설정)에서는 수정이 있으면 **플래그 없이 PR을 만든다.** 개발자 로컬에서는 의도하지 않은 push를 막기 위해 꺼져 있고 `--pr`로 켠다. `--no-pr`은 CI에서도 끈다. 어느 쪽인지는 실행 로그에 출력한다.
- **PR 대상(base).** 사용자의 PR 이벤트면 그 PR의 **원본 브랜치**(`GITHUB_HEAD_REF`), push 이벤트면 그 브랜치(`GITHUB_REF_NAME`), 아니면 현재 브랜치. 수정 PR을 머지하면 사용자의 변경에 수정이 합쳐진다. (`GITHUB_BASE_REF`는 PR의 목적지라 쓰지 않는다.)
- **루프 방지.** 검사 대상이 이미 `argos/fix-*` 브랜치면 PR을 만들지 않는다.
- 검증된 패치가 없으면 PR도 없다(보고서만).
- `--apply`는 작업 트리에만 쓴다(git 없음).

### 워크플로에서 챙길 것
- `actions/checkout`은 `pull_request`에서 기본으로 **머지 커밋**을 체크아웃한다. 수정 브랜치가 머지 커밋에서 갈라지지 않게 `ref: ${{ github.event.pull_request.head.sha }}`로 PR의 head를 체크아웃한다.
- 포크에서 온 PR은 쓰기 권한이 없어 push가 실패한다(보고서만 만들고 PR은 건너뛰는 처리가 필요).


## 이 흐름의 핵심 위험: 순환 논리
**설정의 `expect`("누가 무엇을 봐야 하는가")를 시험 대상 코드에서 LLM이 추정하면 버그를 규칙으로 학습한다.** 예: 코드가 모든 로그인 사용자에게 모든 데이터셋을 보여 주면, 코드만 본 LLM은 "로그인 사용자는 데이터셋을 읽을 수 있다"를 규칙으로 정의하고, 동적 탐지는 🟢을 낸다. 대응:
- 규칙의 근거를 코드 밖에서도 찾는다(스키마의 소유 컬럼, OpenAPI 보안 정의, README·역할 문서, 이전에 사람이 확인한 설정).
- 필드마다 출처를 둔다(`confirmed` / `ai-draft`). **AI가 만든 `expect`는 사람이 확인하기 전까지 리포트에 "미확인 기대 규칙"으로 표시**하고, 확인된 `expect`를 AI가 자동으로 바꾸지 못하게 한다.
- 처음 한 번은 사람이 확인하고 설정을 커밋한다. 이후 커밋에서는 차이만 제안한다.

## 비개발자용 PR 메시지
PR 본문과 보고서 상단에 **전문 용어 없이** 다음을 담는다: 무슨 일이 있었나(예: "벤더 B가 벤더 A의 데이터를 볼 수 있었습니다"), 왜 문제인가, 무엇을 고쳤나(변경 줄 수), 어떻게 확인했나("같은 공격을 다시 해 봤고 더 이상 통하지 않습니다"), 사람이 해야 할 일. 사실은 발견(findings)에서 **템플릿으로 만든다**(LLM이 없는 사실을 지어내지 않게). LLM은 문장을 다듬는 데만 쓰고 숫자·이름은 바꾸지 못하게 한다. 기술 상세는 보고서에 둔다.

## GitHub Actions에서 PR 권한
**가능하지만 세 가지가 맞아야 한다.** (GitHub 문서에 있는 동작에 대한 정리이며, 이 저장소에서는 로컬 bare 저장소와 가짜 `gh`로만 시험했다. 실제 GitHub에서의 확인은 아직 하지 않았다.)
1. 워크플로의 `permissions:`에 `contents: write`(브랜치 push)와 `pull-requests: write`(PR 생성)를 명시한다. 기본 `GITHUB_TOKEN` 권한은 저장소·조직 설정에 따라 읽기 전용일 수 있다.
2. 저장소(또는 조직) 설정 **Settings → Actions → General → Workflow permissions → "Allow GitHub Actions to create and approve pull requests"**가 켜져 있어야 한다. 꺼져 있으면 브랜치는 push되지만 `gh pr create`가 실패한다. 조직 관리자가 막아 둔 경우가 흔하다. 이때 `argos ci`는 실패하지 않고 "브랜치는 push됐고 PR은 직접 열어야 한다"는 경고를 남긴다(시험됨).
3. `gh`가 토큰을 쓰도록 `env: GH_TOKEN: ${{ github.token }}`, 체크아웃은 PR의 head 커밋.

| 상황 | 결과 |
|---|---|
| 포크에서 온 PR | 읽기 전용 토큰이라 push 불가 → 검사와 보고서만, PR은 건너뜀. `pull_request_target`(쓰기 토큰 + 포크 코드 실행)은 쓰지 않는다 |
| `GITHUB_TOKEN`으로 만든 push·PR | **다른 워크플로를 트리거하지 않는다.** 루프 방지에는 유리하지만 수정 PR에 사용자의 CI가 돌지 않는다. 돌리려면 GitHub App 토큰이나 PAT가 필요하다 |
| 브랜치 보호·서명 커밋 요구 같은 조직 정책 | push·PR이 막힐 수 있다 |
| GitHub App 방식 | App에 Contents/Pull requests 쓰기 권한을 주므로 위 설정이 필요 없고 트리거 문제도 없다 |

**권한 분리:** 고객 코드를 실행하는 검사 job은 `contents: read` + `persist-credentials: false`로, 게시 job만 쓰기 권한을 갖게 한다. `argos ci prepare` / `argos ci publish`로 구현했다(아래). 위 세 조건(권한 명시, 저장소 설정, `GH_TOKEN`)은 publish job에 그대로 적용된다.

## 설정 없는 저장소: `argos ci prepare` → `argos ci publish`
고객이 `argos.config.yaml`을 쓰지 않아도 CI가 전용 브랜치와 보고 PR을 만든다(SPRING_SUPPORT_PLAN "CI 연결"). 두 명령, 두 신뢰 수준으로 나눈다.

```
prepare (고객 코드 실행, 쓰기 자격증명 없음)            publish (쓰기 토큰, 고객 코드 실행 없음)
  쓰기 자격증명 제거(GITHUB_TOKEN, GH_TOKEN, ...)        artifact 검증(스키마·경로·패치·비밀·마커)
  재귀 가드(argos/ 브랜치, Argos-Result 트레일러)        작업 트리 없는 임시 저장소에 git 객체만 fetch
  설정 없음 → runInit(Spring/Node, verify 생략)         커밋 1: 설정 초안 + .argos/ 보고서
  runFix: 스캔 + 같은 설정으로 수정 재검증(컨테이너)     커밋 2: 검증된 수정(fix.patch, git apply --cached)
  정책 고정 가드(아래) → fix.patch                       argos/report-<브랜치>에 force-with-lease push
  artifact: pr.json, body.md, files/, fix.patch          PR 생성 또는 숨은 마커로 찾은 기존 PR 수정
```

- **항상 PR이 남는다.** 설정이 이미 있으면 그대로 쓰고(재생성하지 않음, 사람이 확인한 규칙 보호), 없으면 init이 만든 AI 초안을 커밋한다. 미지원 스택·init 실패·빌드/기동 실패여도 상태(`unsupported`/`failed`)와 이유를 담은 보고서 PR을 만든다. 상태: `verified`(전부 실행) / `partial`(미검증 범위나 설정에 넣지 않은 경로가 있음) / `failed` / `unsupported` / `skipped`(재귀).
- **보고서(`.argos/report.md`, 언어는 설정 `report.lang`(기본 en) 또는 `--lang`, 문구는 `src/ci-text.ts`의 en/ko 표).** 무엇이 문제였나(발견을 템플릿 문장으로 + 근거 요청·상태·마커 앞 6자), 수정과 재검증(전후 🔴 수), **발견한 API 전체 대비 실행/실행 못함/설정에 넣지 않음**, "확인되지 않은 정책(취약점 아님)", "환경 오류·미검증(취약점 아님)", 사람이 할 일. 기술 증빙은 `.argos/evidence.md`, 초안 근거는 `.argos/init-report.md`, 기계용 요약은 `.argos/result.json`. 고객 코드에서 나온 오류는 첫 줄만 싣고 비밀 패턴을 지운다(로그 꼬리는 싣지 않음).
- **정책 고정 가드.** 수정 재검증은 같은 설정 파일·같은 매트릭스로만 한다. 수정 전후로 설정의 `mode/checks/personas/resources/auth/seed/db/provenance` 중 하나라도 달라지거나, 설정 파일 내용·체크아웃의 추적 파일이 바뀌었거나, 수정이 `.github/`·Argos 설정/보고서·테스트·migration/SQL을 건드리면 그 수정은 PR에서 빼고 이유를 보고서에 쓴다. publish도 같은 경로 규칙으로 패치를 다시 검사한다.
- **재귀·중복 방지.** prepare는 `argos/` 브랜치(체크아웃 또는 `GITHUB_HEAD_REF`/`GITHUB_REF_NAME`)와 `Argos-Result:` 트레일러가 있는 HEAD에서 `skipped` artifact만 만들고 publish는 아무것도 하지 않는다. 브랜치 이름은 대상 브랜치별로 고정(`argos/report-<브랜치>`)이고, PR은 그 브랜치 + 본문의 숨은 마커(`<!-- argos-ci:v1 branch=… -->`, publish만 씀)로 찾아 **수정**한다. 브랜치 끝 커밋의 `Argos-Source:`가 이번 커밋이면 push도 PR 수정도 하지 않는다. 브랜치 끝에 Argos가 쓰지 않은 커밋(사람이 push)이 있으면 덮어쓰지 않고 경고한다.
- **publish가 거부하는 artifact.** `pr.json` 스키마 위반(브랜치는 `argos/…`만), `argos.config.yaml`·`.argos/*.md|json` 밖으로 쓰는 파일, 심볼릭 링크·artifact 밖 경로, 패치가 `.github/`·테스트·Argos 설정·migration을 건드리거나 바이너리/심링크/서브모듈 변경, 제목·본문·파일·패치 어디든 JWT·전체 `ARGOS_…` 마커·GitHub 토큰·개인 키·AWS 키·긴 Bearer 값·Argos PR 마커가 있는 경우.
- **워크플로.** `examples/github-workflow.yml`. prepare job은 `permissions: contents: read`, 체크아웃 `persist-credentials: false`, env에 토큰 없음(있어도 prepare가 지움; 앱 프로세스·컨테이너는 원래 호스트 env를 받지 않는다: `runner.buildEnv`, `container.ts`). publish job만 `contents: write`, `pull-requests: write`와 `GH_TOKEN`을 갖고, Argos 도구만 체크아웃하며 고객 저장소는 체크아웃·빌드하지 않는다. 포크 PR에서는 publish를 건너뛴다.
- **한계(미구현).** 같은 커밋 재실행 시 prepare(스캔)는 다시 돈다(중복 검사는 publish에서만). 코드 수정과 설정·보고서가 한 PR에 함께 있다(위 "설정·보고서 PR"과 달리 분리하지 않음). 실제 GitHub에서의 권한·`gh` 동작은 아직 확인하지 않았다(로컬 bare 저장소와 가짜 `gh`로만 시험).

## 설정·보고서 PR
검증된 코드 수정이 없어도 설정과 보고서를 PR로 올린다(위 prepare/publish로 구현). 설정 PR이 사람이 `ai-draft` 규칙을 확인하는 절차가 되고, 확인되지 않은 규칙은 보고서에 "미확인"으로 남는다.

## CI에서 지켜야 할 것
- **PR 쓰기 자격증명(`GITHUB_TOKEN`, `gh` 인증)은 고객 코드·빌드·LLM에 전달하지 않는다.** 앱 환경은 비워서 실행하고, PR 게시는 고객 코드 실행이 끝난 뒤 한다.
- 고객 코드는 `--isolation container`(CI 러너에 도커 필요). 도커가 없으면 오류.
- PR 권한: `contents: write`, `pull-requests: write`. `GITHUB_TOKEN`으로 만든 PR은 워크플로를 다시 트리거하지 않는다. 다른 토큰으로 만들면 트리거되므로, argos 브랜치에서 PR을 만들지 않는 보호장치를 코드에 두었다.
- LLM으로 나가는 소스 범위는 출력·기록하고(`.env`·키 파일 제외, 비밀 패턴 마스킹), 끌 수 있어야 한다(`--llm-data none`).
- 수정 PR이 있어도 원본 PR의 상태 표시는 원본 코드 기준으로 한다.
