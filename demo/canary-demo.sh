#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
node --import tsx src/canary/demo.ts "${1:-out/canary-demo}"
