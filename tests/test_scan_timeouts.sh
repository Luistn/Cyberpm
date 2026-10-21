#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
OUT="$(mktemp -d "$PWD/tests/runtime-timeouts.XXXXXX")"
mkdir -p "$OUT/controle"
printf 'Fixture evidence: %s\n' "$OUT"

# Zero must execute directly: a timeout wrapper would deliberately fail here.
timeout(){ return 99; }
bounded_tool 0 "$OUT/unlimited" bash -c 'sleep 0.1; printf "completed\n"'
grep -q completed "$OUT/unlimited.stdout"
grep -q 'limite_segundos=0' "$OUT/unlimited.exec.txt"
unset -f timeout

# A user-supplied deadline still interrupts the command and preserves output.
if bounded_tool 1 "$OUT/limited" bash -c 'printf "partial\n"; sleep 3'; then
  exit 1
else
  [[ $? == 124 ]]
fi
grep -q partial "$OUT/limited.stdout"
grep -q 'codigo=124' "$OUT/limited.exec.txt"
[[ "$(scan_timeout 0008)" == 8 ]]
if scan_timeout -1; then exit 1; fi
if scan_timeout invalid; then exit 1; fi

# Nuclei must receive the origin root and the selected page, scoped to one host.
SCRIPT_DIR="$PWD"
AUDIT_HELPER="$PWD/audit_helpers.py"
BASE=https://example.invalid/login.php
ROOT=https://example.invalid
HOST=example.invalid
python3(){ python -B "$@"; }
mkdir -p "$OUT/04_crawl"
printf 'https://example.invalid/page\nhttps://other.invalid/page\n' > "$OUT/04_crawl/urls.txt"
nuclei(){
  local output=''
  while (($#)); do
    if [[ "$1" == -o ]]; then output="$2"; shift; fi
    shift
  done
  : > "$output"
}
phase_9
grep -qx 'https://example.invalid/' "$OUT/09_vulns/alvos.txt"
grep -qx 'https://example.invalid/login.php' "$OUT/09_vulns/alvos.txt"
! grep -q other.invalid "$OUT/09_vulns/alvos.txt"
grep -q 'limite_segundos=0' "$OUT/09_vulns/nuclei.exec.txt"

# Both long-running phases remain skippable as a process group.
phase_2(){ sleep 30; touch "$OUT/unexpected_nmap_finish"; }
phase_9(){ sleep 30; touch "$OUT/unexpected_nuclei_finish"; }
for phase in 2 15; do
  (sleep 0.3; touch "$OUT/controle/pular_$phase") &
  request_pid=$!
  if run_phase_controlled "$phase"; then exit 1; else [[ $? == 3 ]]; fi
  wait "$request_pid"
done
[[ ! -f "$OUT/unexpected_nmap_finish" ]]
[[ ! -f "$OUT/unexpected_nuclei_finish" ]]
printf 'Scanner timeout checks passed\n'
