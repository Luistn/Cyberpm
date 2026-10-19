#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
mkdir -p "$OUT/controle"
phase_8(){ sleep 30; touch "$OUT/should_not_finish"; }
phase_1(){ touch "$OUT/next_phase"; }
# Pending phase: never starts.
touch "$OUT/controle/pular_5"
if run_phase_controlled 5; then exit 1; else [[ $? == 3 ]]; fi
[[ ! -f "$OUT/should_not_finish" ]]
rm "$OUT/controle/pular_5"
# Running phase: terminate its process group, keep the orchestrator alive.
(sleep 0.4; touch "$OUT/controle/pular_5") &
request_pid=$!
started=$SECONDS
if run_phase_controlled 5; then exit 1; else [[ $? == 3 ]]; fi
wait "$request_pid"
((SECONDS-started < 5))
[[ ! -f "$OUT/should_not_finish" ]]
run_phase_controlled 1
[[ -f "$OUT/next_phase" ]]
printf 'Phase skip tests passed\n'
