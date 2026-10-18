#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source <(sed '/^while \[\[ \$# -gt 0 \]\]; do/,$d' cyberpm.sh)
SCRIPT_DIR="$PWD"
AUDIT_HELPER="$PWD/audit_helpers.py"
OUT=$(mktemp -d "$PWD/tests/runtime.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
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
export SCAN_FIXTURE=empty
if phase_2 > "$OUT/empty.log"; then exit 1; fi
grep -q 'XML ausente/inválido' "$OUT/02_portas/resumo.txt"
[[ ! -s "$OUT/02_portas/portas.txt" ]]
# Complete mode must not truncate to the old limits of 15/5 URLs.
mkdir -p "$OUT/07_params"
for n in $(seq 1 17); do printf 'https://example.invalid/page?id=%s\n' "$n"; done > "$OUT/07_params/com_param.txt"
printf 'https://external.invalid/page?id=1\n' >> "$OUT/07_params/com_param.txt"
for tool in sqlmap dalfox; do
  printf '#!/usr/bin/env bash\nprintf "fixture completed\\n"\n' > "$OUT/bin/$tool"
  chmod +x "$OUT/bin/$tool"
done
BASE=https://example.invalid
MODE=completo
phase_11 > "$OUT/sqli.log"
phase_13 > "$OUT/xss.log"
[[ $(wc -l < "$OUT/11_sqli/cobertura.tsv") == 18 ]]
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
printf 'Scan shell regression checks passed\n'
