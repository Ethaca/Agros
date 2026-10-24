---
name: demo
description: Guide the user through the Argos GitHub Actions demo one confirmed step at a time — check gh login, create a demo repo on their account, open a PR with planted access-control flaws, wait for Argos in CI, then show the report PR with the verified fix, and clean up. Use when the user asks to try, demo, or experience Argos ("데모", "체험", "argos 데모 해줘", "try argos", "demo").
---

# Argos GitHub Actions demo

The user experiences, on their own GitHub account: **demo app → GitHub login → PR → Argos in CI → report PR with a verified fix**. You run every command; the user only confirms. Everything is done by the plugin's script: run it as `bash "${CLAUDE_PLUGIN_ROOT}/demo.sh" <command>` from any directory (below, `demo.sh` means that). Read `${CLAUDE_PLUGIN_ROOT}/README.md` if you need details. The user needs only `git` and `gh`; Node and Docker are not needed locally.

## Rules

- **One step at a time.** Before every step that changes something on GitHub (create, pr, cleanup), ask with `AskUserQuestion` (options: proceed / skip or stop). Read-only steps (check, watch, report) need no confirmation.
- **Short messages.** Each step: one line on what happens, run it, two or three lines on what came out. No walls of text. Speak the user's language (default Korean).
- Show the step header as `[n/6] 단계 이름` so the user sees where they are.
- Never print tokens. Never run `gh auth login`/`refresh` yourself: they are interactive. Ask the user to type `! <command>` in the prompt.
- If a command fails, show its last lines, explain the cause in one sentence, give the fix, and retry only after the user confirms.
- Pass the same `--repo <owner/name>` (and `--lang`) to every command once chosen.

## Steps

### Opening
In 3–4 lines: what they will see (a harmless-looking PR breaks access control; Argos attacks the app in Docker inside GitHub Actions and opens a PR with the report and a re-verified fix), that it takes about 5 minutes, and that it creates **one repository on their account** (private by default; deletable at the end). Then the six steps as a short list:
1. 준비 확인 (GitHub 로그인)  2. 데모 앱 받기  3. PR 올리기  4. Argos 실행 대기  5. 리포트 받기  6. 정리

### [1/6] 준비 확인 — GitHub 로그인
Run `demo.sh check`.
- `GitHub CLI is required` → tell them `brew install gh` (or https://cli.github.com), then re-run.
- `not logged in` → ask them to type `! gh auth login -h github.com -s workflow` and finish the browser login, then re-run.
- `lacks the 'workflow' scope` → `! gh auth refresh -h github.com -s workflow`, then re-run.
- Note the login it prints; the default repo is `<login>/argos-demo`. If check says it already exists, offer a different name.

### [2/6] 데모 앱 받기
Ask in one `AskUserQuestion` call (three questions):
- 레포 이름: `argos-demo` (Recommended) / `argos-demo-<today's MMDD>` (user can type another via Other)
- 공개 범위: 비공개 (Recommended) / 공개 — private uses their Actions minutes; public shows the planted flaws publicly
- 리포트 언어: 한국어 (Recommended) / English

Then confirm and run `demo.sh create --repo <owner/name> --lang <ko|en> [--public]`.
Afterwards explain briefly what the repo contains: `app.mjs` (multi-tenant API: each vendor sees only its own data), `argos.config.yaml` (the rules a person confirmed: who may read what), `.github/workflows/argos.yml` (Argos runs on every PR). Give the repo URL.

### [3/6] PR 올리기
Show `${CLAUDE_PLUGIN_ROOT}/vulnerable.patch` as a compact diff and explain: it looks like a harmless cleanup, but (1) dropping the vendor filter lets any vendor read other vendors' datasets (BOLA), (2) `SELECT *` leaks the API key in the vendor profile. Ask whether to open it, then run `demo.sh pr --repo <owner/name> --lang <ko|en>` and give the PR URL.

### [4/6] Argos 실행 대기
Run `demo.sh watch --repo <owner/name>` with `run_in_background: true` (1–3 minutes). Tell the user the Actions URL it prints and what is happening: the `prepare` job runs the app in Docker with no network and no write token, attacks every route as each vendor and anonymously, and re-verifies a fix; the `publish` job opens the report PR. Wait for the completion notification; do not poll.
If it fails, run `gh run view <id> --repo <owner/name> --log-failed | tail -40` and explain.

### [5/6] 리포트 받기
Run `demo.sh report --repo <owner/name> --save ./argos-demo-report.md` and `gh pr diff <report PR url>`.
Summarize in plain words (no jargon), from the actual output only — never invent numbers:
- 무엇이 문제였나: the 🔴 counts and what they mean (e.g. "vendor1이 vendor2의 데이터셋을 읽을 수 있었다", "벤더 프로필에 API 키가 노출됐다").
- 무엇을 고쳤나: the lines changed in the report PR's diff.
- 어떻게 확인했나: the same attacks were re-run on the fix (🔴 before → after).
- 사람이 할 일: review and merge the report PR into the feature branch.
Give the report PR URL and the saved file path. Offer `gh pr view <url> --web` to open it in the browser.

### [6/6] 정리
Ask: delete the demo repository / keep it. If delete: `demo.sh cleanup --repo <owner/name>`. If it says the `delete_repo` scope is missing, ask them to type `! gh auth refresh -h github.com -s delete_repo` and retry, or delete it from the repo's Settings page.
End with one line: what they saw, and where to read more (https://github.com/Ethaca/Agros, `prd/11-ci-flow.md` there).
