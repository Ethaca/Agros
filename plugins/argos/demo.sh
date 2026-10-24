#!/usr/bin/env bash
# Argos GitHub Actions demo: a real repository on your account, a PR that breaks access control,
# Argos in CI attacks the app in Docker, and you get a report PR with a verified fix.
#
#   demo.sh check                      # gh installed, logged in, scopes
#   demo.sh create [--public] [--lang ko|en]
#   demo.sh pr                         # open the PR with the planted flaws
#   demo.sh watch                      # wait for the Argos workflow
#   demo.sh report [--save <file>]     # the report PR and .argos/report.md
#   demo.sh cleanup                    # delete the demo repository
#
# Every command takes --repo <owner/name> (default: <your login>/argos-demo).
# Needs: git and an authenticated GitHub CLI (gh). Node and Docker are NOT needed locally: Argos runs in Actions.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# The Argos tool the demo workflow checks out. Pinned so the demo does not change under you.
ARGOS_TOOL_REPO="${ARGOS_TOOL_REPO:-Ethaca/Agros}"
ARGOS_TOOL_REF="${ARGOS_TOOL_REF:-641f49055cfd06c4b23fed899307b72cdddc3109}"
PR_BRANCH="feature/vendor-dashboard"
REPORT_BRANCH="argos/report-feature-vendor-dashboard"

WORK=""
trap '[ -z "$WORK" ] || rm -rf "$WORK"' EXIT

fail() { echo "❌ $1" >&2; exit 1; }
step() { echo "▶ $1"; }

cmd="${1:-}"; [ $# -gt 0 ] && shift
REPO=""; PUBLIC=0; LANG_OPT="ko"; SAVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --public) PUBLIC=1; shift ;;
    --lang) LANG_OPT="$2"; shift 2 ;;
    --save) SAVE="$2"; shift 2 ;;
    *) fail "unknown option: $1" ;;
  esac
done
case "$LANG_OPT" in ko|en) ;; *) fail "--lang: expected ko or en" ;; esac

need_gh() {
  command -v git >/dev/null || fail "git is required"
  command -v gh >/dev/null || fail "GitHub CLI is required: brew install gh (https://cli.github.com)"
  gh auth status -h github.com >/dev/null 2>&1 || fail "not logged in to GitHub. Run: gh auth login -h github.com -s workflow"
}
resolve_repo() {
  [ -n "$REPO" ] || REPO="$(gh api user --jq .login)/argos-demo"
}
scopes() { gh auth status -h github.com 2>&1 | sed -n "s/.*Token scopes: //p" | tr -d "'"; }

check() {
  need_gh
  local login s
  login="$(gh api user --jq .login)"
  s="$(scopes)"
  echo "✅ gh $(gh --version | head -1 | awk '{print $3}') · logged in as $login"
  # Fine-grained / app tokens print no scope line; only classic OAuth tokens are checked here.
  if [ -n "$s" ]; then
    echo "$s" | grep -qw repo || fail "token lacks the 'repo' scope. Run: gh auth refresh -h github.com -s repo"
    echo "$s" | grep -qw workflow || fail "token lacks the 'workflow' scope (needed to push .github/workflows). Run: gh auth refresh -h github.com -s workflow"
    echo "✅ scopes: $s"
  fi
  resolve_repo
  if gh repo view "$REPO" >/dev/null 2>&1; then
    echo "ℹ️  $REPO already exists (create will refuse; use --repo for another name, or cleanup first)"
  else
    echo "✅ $REPO is free"
  fi
}

create() {
  need_gh; resolve_repo
  gh repo view "$REPO" >/dev/null 2>&1 && fail "$REPO already exists. Pick another name with --repo, or run cleanup first."
  WORK="$(mktemp -d)"; local work="$WORK"

  step "building the demo app ($LANG_OPT report)"
  cp -R "$HERE/template/." "$work/"
  sed -i.bak "s/^  lang: .*/  lang: $LANG_OPT/" "$work/argos.config.yaml" && rm "$work/argos.config.yaml.bak"
  mkdir -p "$work/.github/workflows"
  # The workflow comes from the same pinned Argos commit as the tool, so the two always match.
  gh api "repos/$ARGOS_TOOL_REPO/contents/examples/github-workflow.yml?ref=$ARGOS_TOOL_REF" \
    -H "Accept: application/vnd.github.raw" > "$work/example-workflow.yml" \
    || fail "could not download examples/github-workflow.yml from $ARGOS_TOOL_REPO@$ARGOS_TOOL_REF"
  # The repository's example workflow, pointed at the pinned Argos tool. Demo changes: no push trigger (a push to
  # main would open a second report PR for main), and PRs into main only (the report PR targets the feature branch;
  # GitHub would otherwise queue an "approve and run" check on it).
  {
    echo "# Argos demo workflow, generated from $ARGOS_TOOL_REPO examples/github-workflow.yml (tool pinned at $ARGOS_TOOL_REF)."
    awk -v repo="$ARGOS_TOOL_REPO" -v ref="$ARGOS_TOOL_REF" '
      !body && /^#/ { next }                     # drop the original header comment
      { body = 1 }
      /^  push:$/ { skip = 1; next }               # drop the push trigger and everything under it
      skip { if (/^    /) next; skip = 0 }
      /^  pull_request:$/ { print; print "    branches: [main]"; print "  workflow_dispatch:"; next }
      { gsub(/ARGOS_TOOL_REPO/, repo); gsub(/ARGOS_TOOL_REF/, ref); print }
    ' "$work/example-workflow.yml"
  } > "$work/.github/workflows/argos.yml"
  rm "$work/example-workflow.yml"
  grep -q "ARGOS_TOOL_" "$work/.github/workflows/argos.yml" && fail "workflow template still has placeholders"
  printf 'node_modules/\n*.db\n' > "$work/.gitignore"

  step "creating $REPO ($([ $PUBLIC = 1 ] && echo public || echo private)) and pushing main"
  git -C "$work" init -q -b main
  git -C "$work" add -A
  git -C "$work" -c user.name="Argos Demo" -c user.email="argos-demo@users.noreply.github.com" commit -qm "Argos demo: multi-tenant API (safe baseline)"
  gh repo create "$REPO" "$([ $PUBLIC = 1 ] && echo --public || echo --private)" \
    --description "Argos demo: access-control checks in GitHub Actions" --source "$work" --push >/dev/null

  step "allowing GitHub Actions to open the report PR"
  # Settings -> Actions -> General -> Workflow permissions -> "Allow GitHub Actions to create and approve pull requests"
  # A brand-new repository sometimes accepts the PUT (204) without applying it, so read it back and retry.
  local i ok=""
  for i in 1 2 3 4 5; do
    gh api -X PUT "repos/$REPO/actions/permissions/workflow" \
      -f default_workflow_permissions=read -F can_approve_pull_request_reviews=true >/dev/null 2>&1 || true
    [ "$(gh api "repos/$REPO/actions/permissions/workflow" --jq .can_approve_pull_request_reviews 2>/dev/null)" = true ] && { ok=1; break; }
    sleep 2
  done
  [ -n "$ok" ] || echo "⚠️  could not change the Actions setting. Turn it on by hand: https://github.com/$REPO/settings/actions"

  echo "✅ https://github.com/$REPO"
}

pr() {
  need_gh; resolve_repo
  gh repo view "$REPO" >/dev/null 2>&1 || fail "$REPO does not exist. Run create first."
  local existing; existing="$(gh pr list --repo "$REPO" --head "$PR_BRANCH" --state open --json url --jq '.[0].url')"
  [ -n "$existing" ] && { echo "ℹ️  the demo PR is already open: $existing"; return; }
  WORK="$(mktemp -d)"; local work="$WORK"

  step "cloning $REPO and applying the demo change"
  gh repo clone "$REPO" "$work/repo" -- -q
  git -C "$work/repo" checkout -qb "$PR_BRANCH"
  git -C "$work/repo" apply "$HERE/vulnerable.patch"
  git -C "$work/repo" -c user.name="Argos Demo" -c user.email="argos-demo@users.noreply.github.com" \
    commit -qam "Vendor dashboard: simplify dataset lookup, return full vendor profile"
  git -C "$work/repo" push -q -u origin "$PR_BRANCH"

  step "opening the PR"
  local title body
  if [ "$LANG_OPT" = ko ]; then
    title="벤더 대시보드: 데이터셋 조회 단순화, 벤더 프로필 전체 반환"
    body=$'대시보드 작업을 위한 작은 정리입니다.\n\n- 데이터셋 id는 고유하니 조회 쿼리의 vendor 조건을 뺐습니다.\n- 대시보드가 모든 필드를 보여줄 수 있게 벤더 프로필을 통째로 반환합니다.\n\n> Argos 데모용 PR입니다. 두 변경 모두 실제로는 접근 제어를 깨뜨립니다. Argos가 CI에서 찾아내는지 확인하세요.'
  else
    title="Vendor dashboard: simplify dataset lookup, return full vendor profile"
    body=$'Small cleanup for the dashboard work.\n\n- Dataset ids are unique, so the lookup no longer filters by vendor.\n- The vendor profile is returned in full so the dashboard can show every field.\n\n> Argos demo PR. Both changes actually break access control. Watch Argos catch them in CI.'
  fi
  gh pr create --repo "$REPO" --base main --head "$PR_BRANCH" --title "$title" --body "$body"
}

watch() {
  need_gh; resolve_repo
  local sha id i
  sha="$(gh api "repos/$REPO/commits/$PR_BRANCH" --jq .sha 2>/dev/null)" || fail "no $PR_BRANCH branch on $REPO. Run pr first."
  step "waiting for the Argos workflow on ${sha:0:7}"
  for i in $(seq 1 30); do
    id="$(gh run list --repo "$REPO" --workflow argos.yml --commit "$sha" --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
    [ -n "$id" ] && break
    sleep 4
  done
  [ -n "$id" ] || fail "the workflow did not start. Check https://github.com/$REPO/actions"
  echo "   https://github.com/$REPO/actions/runs/$id"
  # prepare: build + attack in Docker, publish: push the report branch and open the PR. Usually 1-3 minutes.
  gh run watch "$id" --repo "$REPO" --interval 10 --exit-status \
    || fail "the workflow failed. Logs: gh run view $id --repo $REPO --log-failed"
  echo "✅ workflow finished"
}

report() {
  need_gh; resolve_repo
  local url
  url="$(gh pr list --repo "$REPO" --head "$REPORT_BRANCH" --state all --json url --jq '.[0].url')"
  [ -n "$url" ] || fail "no report PR yet (branch $REPORT_BRANCH). Run watch, or check https://github.com/$REPO/actions"
  echo "📝 report PR: $url"
  echo ""
  gh pr view "$url" --json title,body --jq '"# " + .title + "\n\n" + .body'
  if [ -n "$SAVE" ]; then
    mkdir -p "$(dirname "$SAVE")"
    gh api "repos/$REPO/contents/.argos/report.md?ref=$REPORT_BRANCH" -H "Accept: application/vnd.github.raw" > "$SAVE"
    echo ""
    echo "💾 full report saved: $SAVE"
  fi
  echo ""
  echo "Verified fix (diff of the report PR): gh pr diff $url"
}

cleanup() {
  need_gh; resolve_repo
  gh repo view "$REPO" >/dev/null 2>&1 || { echo "ℹ️  $REPO does not exist"; return; }
  if ! gh repo delete "$REPO" --yes 2>/dev/null; then
    fail "could not delete $REPO (deleting needs the 'delete_repo' scope). Run: gh auth refresh -h github.com -s delete_repo  then cleanup again, or delete it at https://github.com/$REPO/settings"
  fi
  echo "✅ deleted $REPO"
}

case "$cmd" in
  check|create|pr|watch|report|cleanup) "$cmd" ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
