#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/07_params"
BASE=https://example.invalid
AUDIT_HELPER=unused
python3(){ cat "$OUT/07_params/com_param.txt"; }
have(){ return 0; }
bounded_tool(){
  printf '%s\n' "$1" >> "$OUT/durations"
  : > "$2.stdout"; : > "$2.stderr"
  SECONDS=$((SECONDS + ${MOCK_SECONDS:-$1}))
  return "$MOCK_RC"
}
prepare(){
  : > "$OUT/durations"
  : > "$OUT/07_params/com_param.txt"
  for ((i=0; i<$1; i++)); do
    printf 'https://example.invalid/?id=%s\n' "$i" >> "$OUT/07_params/com_param.txt"
  done
}
MODE=completo; MOCK_RC=0
prepare 10
if phase_11 > "$OUT/log"; then exit 1; fi
[[ $(paste -sd, "$OUT/durations") == 30,30,30 ]]
grep -q 'Limite total' "$OUT/11_sqli/interrupcao.txt"
[[ $(wc -l < "$OUT/11_sqli/cobertura.tsv") == 4 ]]
MOCK_RC=124
prepare 10
if phase_11 > "$OUT/log"; then exit 1; fi
[[ $(wc -l < "$OUT/durations") == 3 ]]
grep -q '3 timeouts consecutivos' "$OUT/11_sqli/interrupcao.txt"
MODE=rapido; MOCK_RC=0
prepare 10
if phase_11 > "$OUT/log"; then exit 1; fi
[[ $(paste -sd, "$OUT/durations") == 30,30,30 ]]
MODE=completo
prepare 2
phase_11 > "$OUT/log"
[[ ! -s "$OUT/11_sqli/interrupcao.txt" ]]
MOCK_SECONDS=0
prepare 20
if phase_11 > "$OUT/log"; then exit 1; fi
[[ $(wc -l < "$OUT/durations") == 5 ]]
grep -q 'Amostragem limitada' "$OUT/11_sqli/interrupcao.txt"
printf 'SQLi budget tests passed\n'
