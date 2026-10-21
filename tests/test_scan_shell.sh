#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
SCRIPT_DIR="$PWD"
AUDIT_HELPER="$PWD/audit_helpers.py"
OUT=$(mktemp -d "$PWD/tests/runtime.XXXXXX")
RUNTIME_ROOT=$OUT
trap 'rm -rf "$RUNTIME_ROOT"' EXIT
HOST=example.invalid
python3(){ python -B "$@"; }
mkdir -p "$OUT/bin"
export PATH="$OUT/bin:$PATH"
cat > "$OUT/bin/nmap" <<'FIXTURE'
#!/usr/bin/env bash
xml=''
while (($#)); do
  if [[ "$1" == -oX ]]; then xml="$2"; shift; fi
  shift
done
[[ "${SCAN_FIXTURE:-}" != empty ]] || exit 0
cat > "$xml" <<'XML'
<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports>
<extraports state="filtered" count="999"/>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host><runstats><finished exit="success"/></runstats></nmaprun>
XML
FIXTURE
chmod +x "$OUT/bin/nmap"
phase_2 > "$OUT/ports.log"
grep -q '443/tcp open https' "$OUT/02_portas/portas.txt"
grep -q 'filtered=999' "$OUT/02_portas/resumo.txt"
grep -q '^estado=encerrado' "$OUT/02_portas/nmap.exec.txt"
grep -q '^stdout_bytes=0' "$OUT/02_portas/nmap.exec.txt"
grep -q '^limite_segundos=900' "$OUT/02_portas/nmap.exec.txt"
! grep -q -- '--host-timeout' "$OUT/02_portas/nmap.exec.txt"
export SCAN_FIXTURE=empty
if phase_2 > "$OUT/empty.log"; then exit 1; fi
grep -q 'XML ausente/inválido' "$OUT/02_portas/resumo.txt"
[[ ! -s "$OUT/02_portas/portas.txt" ]]
# Preflight must classify HTTP separately from a TLS timeout.
cat > "$OUT/bin/curl" <<'CURL_FIXTURE'
#!/usr/bin/env bash
if [[ "${CURL_FIXTURE:-}" == ready && ! -f "${CURL_FAIL_FILE:-/nonexistent}" ]]; then
  printf '200\n192.0.2.1\n0.1\n0.2\n0.3\n0.4\n'
  exit 0
fi
printf '000\n192.0.2.1\n0.1\n0.2\n0\n0\n'
exit 28
CURL_FIXTURE
chmod +x "$OUT/bin/curl"
BASE=https://example.invalid; HDRS=()
if connection_preflight > "$OUT/preflight-failed.log"; then exit 1; fi
grep -q tls_timeout "$OUT/00_conexao/estado.json"
export CURL_FIXTURE=ready
connection_preflight > "$OUT/preflight-ready.log"
grep -q http_received "$OUT/00_conexao/estado.json"
# SQLi samples repeated route shapes; XSS retains existing coverage.
mkdir -p "$OUT/07_params"
for n in $(seq 1 17); do printf 'https://example.invalid/page?id=%s\n' "$n"; done > "$OUT/07_params/com_param.txt"
printf 'https://external.invalid/page?id=1\n' >> "$OUT/07_params/com_param.txt"
for tool in sqlmap dalfox; do
  printf '#!/usr/bin/env bash\nprintf "fixture completed\\n"\n' > "$OUT/bin/$tool"
  chmod +x "$OUT/bin/$tool"
done
BASE=https://example.invalid
MODE=completo
if phase_11 > "$OUT/sqli.log"; then exit 1; fi
phase_13 > "$OUT/xss.log"
[[ $(wc -l < "$OUT/11_sqli/cobertura.tsv") == 2 ]]
[[ $(wc -l < "$OUT/13_xss/cobertura.tsv") == 18 ]]
! grep -q external.invalid "$OUT/11_sqli/cobertura.tsv"
! grep -q external.invalid "$OUT/13_xss/cobertura.tsv"
AUTH_PASS=fixture_private_password
AUTH_SECRET=fixture_private_token
output=$(replay_text env AUTH_PASS="$AUTH_PASS" AUTH_SECRET="$AUTH_SECRET" python3 -u script.py --base 'https://example.invalid/a?q=a&b=c')
[[ "$output" == *'AUTH_PASS="${AUTH_PASS}"'* ]]
[[ "$output" != *fixture_private* ]]
[[ "$output" == *'python3 -u script.py'* ]]
# Failure must show a reusable command, even with empty stdout/stderr.
if bounded_tool 2 "$OUT/replay_failure" bash -c 'exit 7' > "$OUT/replay.log"; then exit 1; fi
grep -q 'REPRODUZIR' "$OUT/replay.log"
grep -q 'comando=bash' "$OUT/replay_failure.exec.txt"
# Missing CNAME must not be returned as an execution error.
mkdir -p "$OUT/01_recon"
printf 'www.example.invalid\n' > "$OUT/01_recon/subs.txt"
printf '#!/usr/bin/env bash\nexit 0\n' > "$OUT/bin/dig"
chmod +x "$OUT/bin/dig"
phase_21 > "$OUT/cname.log"
# A failed preflight must skip the web phase, retain recon and produce an isolated run.
install_missing_tools(){ :; }
phase_1(){ printf 'fixture recon completed\n'; }
phase_8(){ touch "$RUNTIME_ROOT/web_executed"; }
export CURL_FIXTURE=failed
TELEGRAM_TOKEN=''; TELEGRAM_CHAT=''; AUTH_MODE=none
TARGET=https://example.invalid; PHASE_LIST='1 5'; OUTROOT="$RUNTIME_ROOT/results"
if run_target > "$RUNTIME_ROOT/run.log"; then exit 1; fi
[[ ! -f "$RUNTIME_ROOT/web_executed" ]]
grep -q $'5\t3\t' "$OUT/fases_status.tsv"
grep -q nao_executada_sem_conexao "$OUT/fases_status.tsv"
grep -q 'fixture recon completed' "$RUNTIME_ROOT/run.log"
[[ "$OUT" != "$OUTROOT/example.invalid" ]]
# Connection may disappear after a successful initial preflight.
export CURL_FAIL_FILE="$RUNTIME_ROOT/connection_lost"
phase_8(){ touch "$CURL_FAIL_FILE"; return 1; }
phase_29(){ touch "$RUNTIME_ROOT/js_executed"; }
export CURL_FIXTURE=ready
PHASE_LIST='5 6'
if run_target > "$RUNTIME_ROOT/lost-connection.log"; then exit 1; fi
[[ ! -f "$RUNTIME_ROOT/js_executed" ]]
grep -q http_received "$OUT/00_conexao/estado.json"
grep -q tls_timeout "$OUT/00_conexao/rechecagem_fase_5/estado.json"
grep -q $'6\t3\t' "$OUT/fases_status.tsv"
grep -q 'Fases web seguintes suspensas' "$RUNTIME_ROOT/lost-connection.log"
printf 'Scan shell regression checks passed\n'
