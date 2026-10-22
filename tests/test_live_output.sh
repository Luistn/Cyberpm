#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
OUT=$(mktemp -d "$PWD/tests/runtime-live.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
bounded_tool 10 "$OUT/tool" bash -c 'echo finding; echo progress >&2; sleep 2; echo finished' > "$OUT/live.log" 2>&1 &
runner=$!
for attempt in {1..30}; do
  if grep -q finding "$OUT/live.log" && grep -q progress "$OUT/live.log"; then break; fi
  sleep 0.05
done
kill -0 "$runner"
! grep -q '^finished$' "$OUT/live.log"
wait "$runner"
grep -q '^finding$' "$OUT/tool.stdout"
grep -q '^progress$' "$OUT/tool.stderr"
grep -q '^finished$' "$OUT/live.log"
printf 'Live output checks passed\n'
