---
name: demo
description: Hands-on Argos tutorial on the user's own GitHub account — six short steps (login, demo repo, vulnerable PR, Argos in Actions, report, cleanup), one confirmed step at a time. Use when the user asks to try, demo, learn, or experience Argos ("데모", "체험", "튜토리얼", "argos 데모 해줘", "try argos", "demo", "tutorial").
---

# Argos 튜토리얼

The user learns Argos by doing: a harmless-looking PR breaks access control, Argos catches it in GitHub Actions and opens a PR with a verified fix. You run every command; the user only confirms.

Script: `bash "${CLAUDE_PLUGIN_ROOT}/demo.sh" <command>` (below: `demo.sh`). Works from any directory. The user needs only `git` and `gh`.

## How to talk

Every step uses **exactly this card** (🎯 says why the step exists), nothing more (speak the user's language; default Korean):

```
**[n/6] 단계 이름**
🎯 <what this step is for, one line>
▶ <what you ran / what happened, one or two lines>
🔗 <link> — <what to look at there, a few words>   (steps 2–5; build links from the command output)
💡 <the one idea to take away, one line>
```

The 🔗 line invites the user to open the link and see it for themselves before moving on ("직접 확인해 보세요").

Then move on with `AskUserQuestion`: one question, options `다음 단계` / `그만하기` (plus step-specific options below). No other prose, no tables, no recap of earlier steps.

- Steps that change GitHub (2, 3, 6) run only after the user picks `다음 단계` on the previous card.
- On failure: one line of cause + the fix command. Login commands are interactive: ask the user to type `! <command>`, never run them yourself.
- Never invent numbers; take them from command output. Never print tokens.
- Reuse the same `--repo <owner/name>` and `--lang` for every command.

## Start

Show this intro verbatim (translate if the user is not Korean), then ask `시작` / `그만하기`:

```
**Argos란?**
코드를 읽고 추측하는 대신, 앱을 실제로 띄워 공격해 보는 보안 검사기예요.
"벤더 A가 벤더 B의 데이터를 볼 수 있나?"를 PR마다 직접 확인하고, 고칠 수 있으면 같은 공격으로 다시 검증한 수정을 PR로 올려줘요.

**튜토리얼 6단계 (약 5분)**
1. GitHub 로그인 — Argos는 GitHub Actions에서 돌아요. 로컬 설치 없이 gh 로그인만 있으면 돼요.
2. 데모 앱 받기 — 실제 스타트업 SaaS 코드와 최대한 같게 만든 멀티테넌트 앱이에요. Argos가 지원하는 Node.js(Express)와 Spring Boot 중에 골라요.
3. 취약한 PR 올리기 — 실무에서 흔한 권한 실수(조회 조건 누락 등)를 평범한 정리 PR처럼 넣어요.
4. Argos 실행 — 앱을 격리된 Docker에서 띄우고, 다른 회사·다른 사용자·비로그인 사용자로 모든 API를 직접 공격해요.
5. 리포트 받기 — 뚫린 곳과 증거를 PR로 받아요. Node는 같은 공격으로 다시 검증한 수정 코드까지 들어 있어요.
6. 정리 — 실습 레포를 지워요. 내 프로젝트에는 워크플로 파일 하나로 붙일 수 있어요.

내 GitHub 계정에 비공개 레포 1개가 생기고, 마지막에 지울 수 있어요.
```

## Steps

**[1/6] GitHub 로그인** — run `demo.sh check`.
- 🎯 Argos가 내 레포에서 돌려면 GitHub 로그인이 필요하다.
- 💡 필요한 건 `git`과 `gh`뿐. 로컬에 Node·Docker는 필요 없다.
- Fixes: no gh → `brew install gh`; not logged in → `! gh auth login -h github.com -s workflow`; missing scope → `! gh auth refresh -h github.com -s workflow`. Re-run check after.

**[2/6] 데모 앱 받기** — first one `AskUserQuestion` with four questions:
- 스택: `Node.js` (Recommended, 1~3분) — Express 스타일 API, 사람이 확인한 규칙 파일 포함 / `Spring Boot` (약 4분) — Spring Security(JWT) + JPA + PostgreSQL, 설정 파일 없이 Argos가 코드에서 규칙을 만든다
- 레포 이름: `argos-demo` (Recommended); if check said it exists, recommend `argos-demo-<MMDD>`
- 공개 범위: 비공개 (Recommended) / 공개
- 리포트 언어: 한국어 (Recommended) / English

Then `demo.sh create --stack <node|spring> --repo <owner/name> --lang <ko|en> [--public]`.
- 🎯 Node: 벤더마다 자기 데이터만 보는 데이터 라벨링 API. Spring: 조직·역할이 있는 협업 문서 서비스. 둘 다 실제 SaaS 구조를 본떴다.
- 🔗 `https://github.com/<repo>` — 앱 코드와 `.github/workflows/argos.yml`. Node는 `argos.config.yaml`(규칙), Spring은 `src/main/java/com/acme/workspace/service/ProjectService.java`(조직 조건)를 열어 보게 한다.
- 💡 Node: `argos.config.yaml` = "누가 무엇을 볼 수 있나" 규칙. Spring: 설정 0줄, Argos가 코드·DB 스키마에서 규칙 초안을 만든다.

**[3/6] 취약한 PR 올리기** — show only the `-`/`+` lines of `${CLAUDE_PLUGIN_ROOT}/patches/<node|spring>.patch`, then `demo.sh pr --repo <owner/name> --lang <ko|en>` (it detects the stack from the repo).
- 🎯 실제 개발처럼, 정리처럼 보이는 PR이 보안 구멍을 연다.
- 🔗 `<PR url>/files` — 바뀐 줄. 리뷰어라면 문제를 알아챌 수 있을지 생각해 보게 한다.
- 💡 Node: ① vendor 조건 삭제 → 남의 데이터 조회 ② `SELECT *` → API 키 노출. Spring: ① 조직 조건 삭제 → 다른 회사 프로젝트 조회 ② 작성자 조건 삭제 → 동료 문서 조회 ③ 관리자 규칙 삭제 → 일반 멤버가 관리자 API 사용. 코드 리뷰로는 놓치기 쉽다.

**[4/6] Argos 실행 지켜보기** — `demo.sh watch --repo <owner/name>` with `run_in_background: true`. Show the card right away with the Actions URL, then wait for the completion notification (do not poll). On failure: `gh run view <id> --repo <owner/name> --log-failed | tail -30`.
- 🎯 PR이 올라오자 Argos가 자동으로 앱을 띄워 공격한다 (Node 1~3분, Spring 약 4분: 빌드·DB 준비 포함).
- 🔗 the Actions run URL from watch — `prepare`(앱 실행·공격)와 `publish`(리포트 PR) 두 job이 차례로 도는 모습. The PR page (`<PR url>`) also shows the check running.
- 💡 앱은 네트워크·쓰기 토큰 없는 Docker 안에서 돈다. Spring은 PostgreSQL과 테스트용 JWT 발급자도 Argos가 띄운다.

**[5/6] 리포트 받기** — `demo.sh report --repo <owner/name> --save ./argos-demo-report.md`, then `gh pr diff <report PR url>`.
- 🎯 무엇이 뚫렸고, 무엇을 고쳤고, 고친 게 통하는지.
- ▶ 🔴 before → after, the fixed lines (one line each), report PR URL.
- 🔗 `<report PR url>` — 요약. `https://github.com/<repo>/blob/<report branch>/.argos/report.md` — 전체 리포트(증거 요청 포함). Node: `<report PR url>/files` — 수정된 줄. Spring: 같은 탭의 `argos.config.yaml` — Argos가 만든 규칙 초안. Report branch: `argos/report-feature-vendor-dashboard` (Node) / `argos/report-feature-project-sharing` (Spring).
- 💡 Node: 같은 공격을 다시 해서 막힌 수정만 PR에 들어간다. Spring: 자동 수정 없이 리포트와 Argos가 만든 설정 초안(`argos.config.yaml`)이 들어간다. 사람이 규칙을 확인하면 다음 PR부터 그 규칙으로 검사한다.
- Extra option: `브라우저로 열기` → `gh pr view <url> --web`.

**[6/6] 정리** — options `레포 삭제` / `남겨두기`. Delete: `demo.sh cleanup --repo <owner/name>`; if `delete_repo` scope is missing → `! gh auth refresh -h github.com -s delete_repo`, then retry.
- 🎯 실습용 레포를 지운다.
- 💡 내 프로젝트에는 `.github/workflows/argos.yml` 하나면 된다. 설정이 없으면 Argos가 코드에서 초안을 만든다.

## End

One line, plus the saved report path. Nothing else.
- Node: "완료: PR 하나로 Argos가 취약점을 찾고, 검증된 수정을 PR로 받았어요."
- Spring: "완료: 설정 없이 PR 하나로 Argos가 권한 결함을 찾고, 리포트를 PR로 받았어요."
