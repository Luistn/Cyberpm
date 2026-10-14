#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' pentest.sh)
AUDIT_HELPER="$PWD/audit_helpers.py"
SCRIPT_DIR="$PWD"
OUT=$(mktemp -d "$PWD/tests/runtime.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
FIND_FILE="$OUT/achados.tsv"; TREE_FILE="$OUT/arvore.txt"
touch "$FIND_FILE"
BASE=https://example.invalid; HOST=example.invalid; SCHEME=https
MODE=rapido; AUTH_MODE=none; HDRS=()
python3(){ python -B "$@"; }
# Transport fixture: only openapi.json is a real schema; all other paths are SPA HTML.
curl(){
  local body='' headers='' url='' emit=0
  while (($#)); do
    case "$1" in
      -o) body="$2"; shift;;
      -D) headers="$2"; shift;;
      -w) emit=1; shift;;
      https://*) url="$1";;
    esac
    shift
  done
  if [[ -n "$body" && "$body" != /dev/null ]]; then
    if [[ "$url" == */openapi.json ]]; then
      printf '{"openapi":"3.0.0","info":{},"paths":{}}' > "$body"
    else
      printf '<html>SPA fallback</html>' > "$body"
    fi
  fi
  [[ -z "$headers" ]] || printf 'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1000\r\nX-Frame-Options: DENY\r\n' > "$headers"
  ((emit==0)) || printf 200
  return 0
}
phase_6
[[ $(wc -l < "$OUT/06_api/apis.txt") == 1 ]]
grep -q '/openapi.json' "$OUT/06_api/apis.txt"
phase_10
phase_18
phase_22
phase_26
mkdir -p "$OUT/04_crawl"
printf '%s\n' 'https://example.invalid/users/123' > "$OUT/04_crawl/urls.txt"
phase_12
grep -q '^INFORMATIVO' "$FIND_FILE"
bounded_tool 2 "$OUT/expected_error" bash -c 'exit 7' && exit 1
grep -q $'bash\t7' "$OUT/ferramentas.tsv"
printf 'Shell regression checks passed\n'
