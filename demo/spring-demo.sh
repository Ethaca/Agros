#!/usr/bin/env bash
# Argos Spring Boot demo: zero config. argos init drafts the config from the code, argos scan runs the
# app in a sandbox (build, PostgreSQL, test JWT issuer, synthetic data) and attacks it, argos report
# writes the evidence report.
#
#   bash demo/spring-demo.sh              # flawed demo app (demo/spring-workspace)
#   bash demo/spring-demo.sh --baseline   # also the correct app, to show there are no false alarms
#
# Needs: Node 22+, pnpm, a running Docker. No Java on the host (the build runs in a container).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="$ROOT/out/spring-demo"
BASELINE=0
[ "${1:-}" = "--baseline" ] && BASELINE=1

fail() { echo "❌ $1" >&2; exit 1; }
command -v node >/dev/null || fail "Node.js 22+ is required"
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ] || fail "Node.js 22+ is required (found $(node -v))"
command -v pnpm >/dev/null || fail "pnpm is required (npm i -g pnpm)"
docker info >/dev/null 2>&1 || fail "Docker is not running. Start Docker Desktop and try again."
[ -d node_modules ] || pnpm install --frozen-lockfile

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

run() { # <name> <app dir> <label>
  local name="$1" app="$WORK/$1" out="$OUT/$1"
  rm -rf "$out"; mkdir -p "$out"
  cp -R "$2" "$app"
  rm -f "$app/argos.config.yaml"   # start from nothing: no config, no test accounts, no seed data

  echo ""
  echo "━━━ $3 ━━━"
  echo "① argos init   코드를 읽고 설정 초안 작성 (몇 초)"
  pnpm -s argos init "$app" --report "$out" --no-verify > "$out/init.log" 2>&1 || { tail -20 "$out/init.log"; fail "init failed (log: $out/init.log)"; }
  grep -E "^  (found: API|likely finding)" "$out/init.log" | sed 's/^  /   /' || true
  cp "$app/argos.config.yaml" "$out/argos.config.yaml"

  echo "② argos scan   샌드박스에서 빌드·실행 후 권한 공격 (첫 실행은 의존성 다운로드로 몇 분)"
  pnpm -s argos scan --config "$app/argos.config.yaml" --out "$out" --timeout 1800 > "$out/scan.log" 2>&1 || { tail -20 "$out/scan.log"; fail "scan failed (log: $out/scan.log)"; }
  pnpm -s argos report --scan "$out" --lang ko > /dev/null 2>&1

  node -e '
    const f = require(process.argv[1]);
    const n = (v) => f.filter((x) => x.verdict === v).length;
    console.log(`   결과: 🔴 취약 ${n("VULNERABLE")} · 🟡 의심 ${n("SUSPECTED")} · 🟢 정상 ${n("OK")} · ⚪ 판단 불가 ${n("SKIPPED")}`);
    const red = f.filter((x) => x.verdict === "VULNERABLE");
    const kinds = [
      ["다른 조직의 데이터를 읽거나 바꿈", (x) => x.check === "bola" && !/in the same org|requires role/.test(x.detail)],
      ["같은 조직 동료의 데이터를 읽거나 바꿈", (x) => /in the same org/.test(x.detail)],
      ["권한 없는 사용자가 관리자 기능을 씀", (x) => /requires role/.test(x.detail)],
      ["로그인 없이 / 위조 토큰으로 접근", (x) => x.check === "unauth"],
      ["응답에 비밀값 노출", (x) => x.check === "secrets"],
    ];
    for (const [label, test] of kinds) {
      const hits = red.filter(test);
      if (!hits.length) continue;
      const ex = hits.find((h) => h.proof.request.startsWith("GET ")) ?? hits[0];
      console.log(`   🔴 ${label}: ${hits.length}건 (예: ${ex.persona} → ${ex.proof.request} → ${ex.proof.status})`);
    }
  ' "$out/findings.json"
  echo "   보고서: ${out#$ROOT/}/report.md"
}

run spring-workspace demo/spring-workspace "결함이 있는 데모 앱 (demo/spring-workspace)"
[ "$BASELINE" = 1 ] && run spring-baseline test/fixtures/spring/gradle-app "정상 앱 (비교용, 🔴 0이어야 함)"
echo ""
echo "완료. 생성된 설정: out/spring-demo/<app>/argos.config.yaml · 분석 보고서: init-report.md · 검증 보고서: report.md"
