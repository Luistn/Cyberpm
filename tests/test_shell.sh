#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
AUDIT_HELPER="$PWD/audit_helpers.py"
SCRIPT_DIR="$PWD"
OUT=$(mktemp -d "$PWD/tests/runtime.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
FIND_FILE="$OUT/achados.tsv"; TREE_FILE="$OUT/arvore.txt"
touch "$FIND_FILE"
BASE=https://example.invalid; HOST=example.invalid; SCHEME=https
MODE=rapido; AUTH_MODE=none; HDRS=()
python3(){ python -B "$@"; }
# Keep automatic API execution offline in the transport fixture.
mkdir -p "$OUT/bin"
cat > "$OUT/bin/python3" <<'PYTHON_FIXTURE'
#!/usr/bin/env bash
if [[ "${1:-}" == -u && "${2:-}" == */api_probe.py ]]; then
  printf 'API fixture: verificacao automatica iniciada\n'
  exit 0
fi
exec python -B "$@"
PYTHON_FIXTURE
chmod +x "$OUT/bin/python3"
export PATH="$OUT/bin:$PATH"
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
grep -q 'API fixture' "$OUT/06_api/api_probe.stdout"
[[ -s "$OUT/06_api/requisicoes_candidatas.txt" ]]
[[ $(wc -l < "$OUT/06_api/apis.txt") == 1 ]]
grep -q '/openapi.json' "$OUT/06_api/apis.txt"
phase_10
mkdir -p "$OUT/09_vulns"
printf 'fixture CVE-2025-12345 and CVE-2025-12345\n' > "$OUT/09_vulns/fixture.txt"
phase_10 > "$OUT/cves.log"
grep -q 'CVE-2025-12345' "$OUT/cves.log"
[[ $(wc -l < "$OUT/10_cves/ids.txt") == 1 ]]
grep -q $'INFORMATIVO.*CVE potencial.*CVE-2025-12345' "$FIND_FILE"
PHASE_LIST='20 27 28'; choose_phases
[[ "${SELECTED[*]}" == '27 28 20' ]]
PHASE_LIST='27'; choose_phases
[[ "${SELECTED[*]}" == '27 20' ]]
PHASE_LIST='1'; choose_phases
[[ "${SELECTED[*]}" == '1' ]]
PHASE_LIST=''
phase_18
phase_22
phase_26
mkdir -p "$OUT/04_crawl"
printf '%s\n' 'https://example.invalid/users/123' > "$OUT/04_crawl/urls.txt"
phase_12
grep -q '^INFORMATIVO' "$FIND_FILE"
bounded_tool 2 "$OUT/expected_error" bash -c 'exit 7' && exit 1
grep -q $'bash\t7' "$OUT/ferramentas.tsv"
# These phases must explain absent headers, declared metadata and transport errors.
phase_16 > "$OUT/privacy.log"
grep -q 'HTTP 200' "$OUT/privacy.log"
grep -q 'nenhum cabeçalho' "$OUT/privacy.log"
phase_24 > "$OUT/methods.log"
grep -q 'não declarou' "$OUT/methods.log"
phase_5 > "$OUT/exposure.log"
grep -q '18 caminhos' "$OUT/exposure.log"
grep -q '2 recursos públicos' "$OUT/exposure.log"
grep -q '0 candidatos a revisar' "$OUT/exposure.log"
[[ -s "$OUT/05_exposicao/status.tsv" ]]
phase_14 > "$OUT/authz.log"
grep -q 'HTTP 200' "$OUT/authz.log"
grep -q 'acesso indevido não confirmado' "$OUT/authz.log"
[[ $(wc -l < "$OUT/14_authz/admin.txt") == 3 ]]
phase_14 > "$OUT/authz.log"
[[ $(wc -l < "$OUT/14_authz/admin.txt") == 3 ]]
phase_23 > "$OUT/redirect.log"
grep -q '0 candidatos' "$OUT/redirect.log"
phase_25 > "$OUT/ssrf.log"
grep -q '0 candidatos' "$OUT/ssrf.log"
printf '%s\n' 'https://example.invalid/?url=https://audit.invalid' >> "$OUT/04_crawl/urls.txt"
phase_23 > "$OUT/redirect.log"
grep -q '1 candidatos' "$OUT/redirect.log"
phase_25 > "$OUT/ssrf.log"
grep -q '1 candidatos' "$OUT/ssrf.log"
phase_27 > "$OUT/injection.log"
grep -q '0 ocorrências' "$OUT/injection.log"
grep -q 'LFI não confirmadas' "$OUT/injection.log"
phase_28 > "$OUT/host.log"
grep -q 'HTTP 200' "$OUT/host.log"
grep -q 'CRLF não foi testado' "$OUT/host.log"
mv "$OUT/04_crawl/urls.txt" "$OUT/04_crawl/urls.saved"
phase_23 > "$OUT/redirect-missing.log"
grep -q 'inventário de URLs indisponível' "$OUT/redirect-missing.log"
[[ ! -s "$OUT/23_redirect/candidatos.txt" ]]
phase_25 > "$OUT/ssrf-missing.log"
grep -q 'inventário de URLs indisponível' "$OUT/ssrf-missing.log"
[[ ! -s "$OUT/25_ssrf/candidatos.txt" ]]
mv "$OUT/04_crawl/urls.saved" "$OUT/04_crawl/urls.txt"
curl(){
  local headers=''
  while (($#)); do
    if [[ "$1" == -D ]]; then headers="$2"; shift; fi
    shift
  done
  printf 'HTTP/1.1 200 OK\r\nAllow: GET, HEAD, OPTIONS\r\nSet-Cookie: session=FIXTURE_PRIVATE\r\nReferrer-Policy: same-origin\r\n' > "$headers"
  printf 200
}
phase_16 > "$OUT/privacy.log"
grep -q 'Referrer-Policy' "$OUT/privacy.log"
! grep -q 'FIXTURE_PRIVATE' "$OUT/privacy.log"
phase_24 > "$OUT/methods.log"
grep -q 'GET, HEAD, OPTIONS' "$OUT/methods.log"
curl(){ printf 000; return 7; }
if phase_16 > "$OUT/privacy-error.log"; then exit 1; fi
grep -q 'consulta falhou' "$OUT/privacy-error.log"
[[ ! -s "$OUT/16_privacidade/headers.txt" ]]
if phase_24 > "$OUT/methods-error.log"; then exit 1; fi
grep -q 'consulta falhou' "$OUT/methods-error.log"
[[ ! -s "$OUT/24_metodos/metodos.txt" ]]
if phase_5 > "$OUT/exposure-error.log"; then exit 1; fi
grep -q '3 falhas/coletas inconclusivas' "$OUT/exposure-error.log"
grep -q 'interrompida apos 3 falhas consecutivas' "$OUT/exposure-error.log"
if phase_14 > "$OUT/authz-error.log"; then exit 1; fi
grep -q '2 falhas' "$OUT/authz-error.log"
if phase_27 > "$OUT/injection-error.log"; then exit 1; fi
grep -q 'inconclusiva' "$OUT/injection-error.log"
[[ ! -s "$OUT/27_injecao/ssti.txt" ]]
if phase_28 > "$OUT/host-error.log"; then exit 1; fi
grep -q 'consulta falhou' "$OUT/host-error.log"
printf 'Shell regression checks passed\n'
