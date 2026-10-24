---
name: demo
description: Hands-on Argos tutorial on the user's own GitHub account — six short steps (login, demo repo, vulnerable PR, Argos in Actions, report, cleanup), one confirmed step at a time. Use when the user asks to try, demo, learn, or experience Argos ("데모", "체험", "튜토리얼", "argos 데모 해줘", "try argos", "demo", "tutorial").
---

# Argos 튜토리얼

The user learns Argos by doing: a harmless-looking PR breaks access control, Argos catches it in GitHub Actions and opens a PR with a verified fix. You run every command; the user only confirms.

Script: `bash "${CLAUDE_PLUGIN_ROOT}/demo.sh" <command>` (below: `demo.sh`). Works from any directory. The user needs only `git` and `gh`.

## How to talk

Every step uses **exactly this card**, nothing more (speak the user's language; default Korean):

```
**[n/6] 단계 이름**
🎯 <what this step is for, one line>
▶ <what you ran / what happened, one or two lines, with the URL if any>
💡 <the one idea to take away, one line>
```

Then move on with `AskUserQuestion`: one question, options `다음 단계` / `그만하기` (plus step-specific options below). No other prose, no tables, no recap of earlier steps.

- Steps that change GitHub (2, 3, 6) run only after the user picks `다음 단계` on the previous card.
- On failure: one line of cause + the fix command. Login commands are interactive: ask the user to type `! <command>`, never run them yourself.
- Never invent numbers; take them from command output. Never print tokens.
- Reuse the same `--repo <owner/name>` and `--lang` for every command.

## Start

Card-free intro, max 3 lines: "6단계, 약 5분. 내 GitHub 계정에 비공개 레포 1개를 만들고 마지막에 지울 수 있어요." Then ask `시작` / `그만하기`.

## Steps

**[1/6] GitHub 로그인** — run `demo.sh check`.
- 🎯 Argos는 내 GitHub 레포에서 돈다. `gh`로 로그인됐는지 확인.
- 💡 필요한 건 `git`과 `gh`뿐. 로컬에 Node·Docker는 필요 없다.
- Fixes: no gh → `brew install gh`; not logged in → `! gh auth login -h github.com -s workflow`; missing scope → `! gh auth refresh -h github.com -s workflow`. Re-run check after.

**[2/6] 데모 앱 받기** — first one `AskUserQuestion` with three questions: 레포 이름 (`argos-demo` Recommended), 공개 범위 (비공개 Recommended / 공개), 리포트 언어 (한국어 Recommended / English). If check said the name exists, recommend `argos-demo-<MMDD>`. Then `demo.sh create --repo <owner/name> --lang <ko|en> [--public]`.
- 🎯 벤더마다 자기 데이터만 보는 API를 내 계정에 올린다.
- 💡 `argos.config.yaml` = "누가 무엇을 볼 수 있나" 규칙. Argos는 이 규칙대로 공격한다.

**[3/6] 취약한 PR 올리기** — show the two changed lines of `${CLAUDE_PLUGIN_ROOT}/vulnerable.patch` (just the `-`/`+` lines), then `demo.sh pr --repo <owner/name> --lang <ko|en>`.
- 🎯 정리처럼 보이는 PR이 실은 보안 구멍 두 개를 연다.
- 💡 ① vendor 조건 삭제 → 남의 데이터 조회 ② `SELECT *` → API 키 노출. 코드 리뷰로는 놓치기 쉽다.

**[4/6] Argos 실행 지켜보기** — `demo.sh watch --repo <owner/name>` with `run_in_background: true`. Show the card right away with the Actions URL, then wait for the completion notification (do not poll). On failure: `gh run view <id> --repo <owner/name> --log-failed | tail -30`.
- 🎯 Actions에서 Argos가 앱을 띄워 실제로 공격한다 (1~3분).
- 💡 앱은 네트워크·쓰기 토큰 없는 Docker 안에서 돈다. PR을 쓰는 단계는 따로 분리돼 있다.

**[5/6] 리포트 받기** — `demo.sh report --repo <owner/name> --save ./argos-demo-report.md`, then `gh pr diff <report PR url>`.
- 🎯 무엇이 뚫렸고, 무엇을 고쳤고, 고친 게 통하는지.
- ▶ 🔴 before → after, the fixed lines (one line each), report PR URL.
- 💡 수정은 같은 공격을 다시 해서 막힌 것만 PR에 들어간다.
- Extra option: `브라우저로 열기` → `gh pr view <url> --web`.

**[6/6] 정리** — options `레포 삭제` / `남겨두기`. Delete: `demo.sh cleanup --repo <owner/name>`; if `delete_repo` scope is missing → `! gh auth refresh -h github.com -s delete_repo`, then retry.
- 🎯 실습 레포를 지운다.
- 💡 내 레포에 쓰려면 `.github/workflows/argos.yml`과 `argos.config.yaml`을 복사하면 된다.

## End

One line: "완료: PR 하나로 Argos가 취약점을 찾고, 검증된 수정을 PR로 받았어요." Plus the saved report path. Nothing else.
