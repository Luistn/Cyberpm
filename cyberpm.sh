#!/usr/bin/env bash
# Auditoria autorizada: fases ordenadas, evidências e ferramentas opcionais.
set -uo pipefail

VERSION="10.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_HELPER="$SCRIPT_DIR/audit_helpers.py"
[[ ! -f "$SCRIPT_DIR/VERSION" ]] || VERSION=$(cat "$SCRIPT_DIR/VERSION")
export PATH="$HOME/.local/bin:$PATH"
TARGET="${1:-}"
OUTROOT="${PWD}/cyberpm-out"
MODE="completo"
JS_MAX="${JS_MAX:-60}"
MAXRERUN="${MAXRERUN:-3}"
NMAP_TIMEOUT="${NMAP_TIMEOUT:-900}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-300}"
API_REQUEST_PLAN="${API_REQUEST_PLAN:-}"
API_EXECUTE_PLAN="${API_EXECUTE_PLAN:-0}"
THREADS="${THREADS:-10}"
DO_INSTALL=1
WORDPRESS=0
VERBOSE=1
TELEGRAM_TOKEN="${TELEGRAM_TOKEN:-}"
TELEGRAM_CHAT="${TELEGRAM_CHAT:-}"
AUTH_MODE="${AUTH_MODE:-none}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
AUTH_SECRET="${AUTH_SECRET:-}"
LOGIN_URL="${LOGIN_URL:-}"
HARVEST=1
VALIDATE=1
ZAP_SCAN=1
BRUTE=1
BRUTE_WORDLIST="${BRUTE_WORDLIST:-}"
PHASE_LIST="${PHASE_LIST:-}"

BASE=""; ROOT=""; HOST=""; SCHEME="https"; CUR_ASSET=""
OUT=""; FIND_FILE=""; TREE_FILE=""
declare -A RUNS=()
HDRS=()

R=$'\033[0m'; B=$'\033[1m'; RD=$'\033[31m'; GR=$'\033[32m'; YL=$'\033[33m'
BL=$'\033[34m'; MG=$'\033[35m'; CY=$'\033[36m'

hdr(){
  printf '\n%s══ %s ══%s\n' "$B$CY" "$*" "$R"
  if [[ "$*" =~ ^FASE\ ([0-9]+) ]]; then
    local phase_number="${BASH_REMATCH[1]}"
    local tools=('' 'whois, RDAP, dig, subfinder, assetfinder, curl (crt.sh)' 'nmap' 'whatweb, wafw00f, wpscan, curl' 'gau, waybackurls, katana, ffuf, curl' 'curl, parser HTML' 'js_downloader.py, Retire.js, análise local' 'curl, api_probe.py (GET/OPTIONS)' 'grep, Arjun' 'curl' 'dig' 'análise local de logins' 'curl' 'curl (OPTIONS)' 'curl, testssl.sh' 'nuclei' 'inventário local de CVEs' 'sqlmap' 'análise local' 'dalfox' 'curl' 'OWASP ZAP' 'curl' 'análise local' 'análise local' 'análise local' 'curl' 'análise local de dados sensíveis' 'análise local' 'Cyberpm / manual')
    info "Ferramentas da fase $phase_number (conforme disponibilidade): ${tools[$phase_number]:-consultar comandos abaixo}"
  fi
}
info(){ [[ "$VERBOSE" == 1 ]] && printf '%s[·]%s %s\n' "$BL" "$R" "$*"; }
ok(){ printf '%s[✓]%s %s\n' "$GR" "$R" "$*"; }
warn(){ printf '%s[!]%s %s\n' "$YL" "$R" "$*"; }
erro(){ printf '%s[x]%s %s\n' "$RD" "$R" "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
replay_text(){
  local arg quoted result='' name
  [[ "${LD_PRELOAD:-}" != *proxychains* ]] || result='proxychains4 '
  for arg in "$@"; do
    case "$arg" in
      AUTH_PASS=*|AUTH_SECRET=*|AUTH_USER=*|TELEGRAM_TOKEN=*|TELEGRAM_CHAT=*)
        name="${arg%%=*}"; quoted="$name=\"\${$name}\"";;
      *)
        if [[ -n "$AUTH_PASS" && "$arg" == *"$AUTH_PASS"* ]] || [[ -n "$AUTH_SECRET" && "$arg" == *"$AUTH_SECRET"* ]] || [[ -n "$TELEGRAM_TOKEN" && "$arg" == *"$TELEGRAM_TOKEN"* ]]; then
          quoted='"${CYBERPM_CREDENTIAL}"'
        else
          printf -v quoted '%q' "$arg"
        fi;;
    esac
    result+="$quoted "
  done
  printf '%s' "${result% }"
}
replay_hint(){
  local replay
  replay=$(replay_text "$@")
  warn "REPRODUZIR no terminal (diagnostico opcional, pasta $SCRIPT_DIR): $replay"
  if [[ "$replay" == *'${'* ]]; then
    info 'Credenciais foram substituídas por variáveis; defina-as no seu terminal quando necessário.'
  fi
}
bounded_tool(){ # segundos prefixo comando argumentos...
  local seconds="$1" prefix="$2" rc=0; shift 2
  printf 'ferramenta=%s\ninicio=%s\nlimite_segundos=%s\nestado=executando\n' "${1##*/}" "$(date -u +%FT%TZ)" "$seconds" > "$prefix.exec.txt"
  printf 'comando=%s\n' "$(replay_text "$@")" >> "$prefix.exec.txt"
  info "Executando: $(replay_text "$@")"
  # Keep evidence while forwarding both streams to the live log.
  local stdout_fd stderr_fd stdout_pid stderr_pid
  exec {stdout_fd}> >(tee "$prefix.stdout"); stdout_pid=$!
  exec {stderr_fd}> >(tee "$prefix.stderr" >&2); stderr_pid=$!
  if ((seconds == 0)); then
    "$@" >&$stdout_fd 2>&$stderr_fd || rc=$?
  else
    timeout -k 3s "$seconds" "$@" >&$stdout_fd 2>&$stderr_fd || rc=$?
  fi
  exec {stdout_fd}>&- {stderr_fd}>&-
  wait "$stdout_pid" || true
  wait "$stderr_pid" || true
  printf 'fim=%s\ncodigo=%s\nestado=encerrado\nstdout_bytes=%s\nstderr_bytes=%s\n' "$(date -u +%FT%TZ)" "$rc" "$(wc -c < "$prefix.stdout")" "$(wc -c < "$prefix.stderr")" >> "$prefix.exec.txt"
  printf '%s\t%s\t%s\n' "${1##*/}" "$rc" "$prefix" >> "$OUT/ferramentas.tsv"
  if ((rc == 124 || rc == 137)); then
    warn "${1##*/}: limite de ${seconds}s atingido; saída parcial: $prefix.stdout"
  elif ((rc != 0)); then
    warn "${1##*/}: código $rc; detalhes: $prefix.stderr e $prefix.stdout"
  fi
  ((rc == 0)) || replay_hint "$@"
  return "$rc"
}

tg(){
  [[ -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT" ]] || return 0
  curl -s -m 10 "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT}" -d parse_mode=Markdown \
    -d text="$1" >/dev/null 2>&1 || true
}

usage(){
  cat <<EOF
cyberpm.sh v$VERSION — uso: ./cyberpm.sh <alvo> [opções]
  -o, --out DIR        pasta de saída (default: ./cyberpm-out)
  -m, --mode M         rapido | completo | profundo
      --js-max N       máx. de arquivos .js a baixar (default 60)
      --threads N      paralelismo (default 10)
      --auth M         none|basic|bearer|cookie
      --user U         usuário (basic)
      --pass P         senha (basic)
      --secret S       token/cookie
      --login-url U    URL de login (para o Cyberpm)
      --wordlist W     wordlist p/ força bruta
      --telegram T     token do bot
      --chat C         chat id
      --phases "1 4 9" lista de fases (default: conforme --mode)
      --no-install     não instalar ferramentas
      --wordpress      inventário WordPress com WPScan na fase 3
  -q, --quiet          menos saída
EOF
}

# ── registro de achados + árvore ─────────────────────────────────────────────
tree_rebuild(){
  [[ -s "$FIND_FILE" ]] || { : > "$TREE_FILE"; return 0; }
  : > "$TREE_FILE"
  local a
  while IFS= read -r a; do
    [[ -z "$a" ]] && continue
    printf '%s\n' "$a" >> "$TREE_FILE"
    local total n=0
    total=$(awk -F'\t' -v a="$a" '$2==a{c++} END{print c+0}' "$FIND_FILE")
    while IFS=$'\t' read -r sev _ cat msg evid; do
      n=$((n+1))
      local br="├─"; [[ $n -eq $total ]] && br="└─"
      printf '  %s [%s] %s — %s\n' "$br" "$sev" "$cat" "$msg" >> "$TREE_FILE"
      [[ -n "$evid" ]] && printf '  %s   └─ evidência: %s\n' \
        "$([[ $n -eq $total ]] && echo ' ' || echo '│')" "$evid" >> "$TREE_FILE"
    done < <(awk -F'\t' -v a="$a" '$2==a' "$FIND_FILE")
  done < <(cut -f2 "$FIND_FILE" | sort -u)
}

register_finding(){ # sev cat msg [evid]
  local sev="$1" cat="$2" msg="$3" evid="${4:-}"
  printf '%s\t%s\t%s\t%s\t%s\n' "$sev" "${CUR_ASSET:-$HOST}" "$cat" "$msg" "$evid" >> "$FIND_FILE"
  printf "EVENT|FINDING|%s\n" "$sev"
  warn "[ACHADO $sev] $msg"
  tg "🔎 *[$sev]* ${CUR_ASSET:-$HOST}
$cat: $msg"
  tree_rebuild
}

in_list(){ local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }
artifact_hash(){
  local d; d=$(printf '%s/%02d_*' "$OUT" "$1")
  find $d -type f 2>/dev/null | sort | xargs -r md5sum 2>/dev/null | md5sum | awk '{print $1}'
}
legacy_retrigger_of(){
  case "$1" in
    1) echo "2 3 4 21";;
    3) echo "9 26";;
    4) echo "5 6 7 9 29";;
    5) echo "9 11";;
    6) echo "7 16 19";;
    8) echo "7 29";;
    18) echo "19";;
    19) echo "20";;
    29) echo "7 11 12";;
    *) echo "";;
  esac
}

# Identificadores públicos 1..29, implementação e diretórios legados preservados.
LEGACY_BY_NEW=(0 1 2 3 4 8 29 6 7 5 21 17 16 24 26 9 10 11 12 13 14 15 22 23 25 27 28 18 19 20)
declare -A NEW_BY_LEGACY=()
for i in $(seq 1 29); do NEW_BY_LEGACY[${LEGACY_BY_NEW[$i]}]=$i; done
retrigger_of(){
  local original=${LEGACY_BY_NEW[$1]} dep
  for dep in $(legacy_retrigger_of "$original"); do echo "${NEW_BY_LEGACY[$dep]}"; done
}

gurl(){ curl -sk -m "${1:-12}" -L "${HDRS[@]}" "$2"; }

# ═════════════════════════════ FASE 1 · RECON ═══════════════════════════════
phase_1(){
  hdr "FASE 1 · Reconhecimento"
  local f="$OUT/01_recon"; mkdir -p "$f"
  : > "$f/subs.txt"; : > "$f/ferramentas.tsv"
  local tool status count rc tmp partial=0
  for tool in whois dig subfinder assetfinder curl; do
    if ! have "$tool"; then
      printf '%s\tAUSENTE\t0\n' "$tool" >> "$f/ferramentas.tsv"
      warn "$tool: não instalado"; continue
    fi
    tmp="$f/${tool}.stderr"; : > "$tmp"
    rc=0; count=0
    case "$tool" in
      whois) bounded_tool 20 "$f/whois" whois "$HOST" || rc=$?; cp "$f/whois.stdout" "$f/whois.txt";;
      dig)
        : > "$f/dns.txt"
        local record
        for record in A MX TXT; do
          bounded_tool 15 "$f/dig_$record" dig +short "$HOST" "$record" || rc=$?
          cat "$f/dig_$record.stdout" >> "$f/dns.txt"
          cat "$f/dig_$record.stderr" >> "$tmp"
        done;;
      subfinder) bounded_tool 50 "$f/subfinder" subfinder -d "$HOST" -silent || rc=$?; cp "$f/subfinder.stdout" "$f/subfinder.txt"; cat "$f/subfinder.txt" >> "$f/subs.txt"; count=$(wc -l < "$f/subfinder.txt");;
      assetfinder) bounded_tool 45 "$f/assetfinder" assetfinder --subs-only "$HOST" || rc=$?; cp "$f/assetfinder.stdout" "$f/assetfinder.txt"; cat "$f/assetfinder.txt" >> "$f/subs.txt"; count=$(wc -l < "$f/assetfinder.txt");;
      curl)
        bounded_tool 35 "$f/curl" curl -fsS --connect-timeout 5 --max-time 12 --retry 1 --retry-delay 1 --retry-max-time 28 --dump-header "$f/crt.headers" "https://crt.sh/?q=%25.${HOST}&output=json" -o "$f/crt.json" || rc=$?
        if ((rc==0)); then
          python3 - "$f/crt.json" "$HOST" > "$f/crt_subs.txt" 2>>"$tmp" <<'PYJSON' || rc=$?
import json,sys
try:
    data=json.load(open(sys.argv[1])); domain=sys.argv[2].lower()
    names=set()
    for item in data:
        for name in item.get('name_value','').splitlines():
            name=name.strip().lower().lstrip('*.')
            if name.endswith('.'+domain) and name != domain: names.add(name)
    print('\n'.join(sorted(names))) if names else None
except (ValueError, OSError, TypeError) as e:
    print(e,file=sys.stderr); sys.exit(1)
PYJSON
          [[ -f "$f/crt_subs.txt" ]] && { cat "$f/crt_subs.txt" >> "$f/subs.txt"; count=$(wc -l < "$f/crt_subs.txt"); }
        fi;;
    esac
    if ((rc==0)); then status=OK; if [[ "$tool" == whois || "$tool" == dig ]]; then ok "$tool: consulta concluída (dados de registro/DNS)"; else ok "$tool: consulta concluída ($count subdomínios)"; fi; else status="ERRO:$rc"; if [[ "$tool" == curl ]]; then warn "crt.sh: consulta externa indisponível ou resposta inválida (código $rc); cobertura parcial de certificados. Detalhes: $tmp e $f/crt.headers"; else warn "$tool: falha ($rc); detalhes: $tmp"; fi; fi
    if ((rc != 0)); then
      partial=1
      case "$tool" in
        whois) replay_hint whois "$HOST";;
        dig) replay_hint dig +short "$HOST" A; replay_hint dig +short "$HOST" MX; replay_hint dig +short "$HOST" TXT;;
        subfinder) replay_hint subfinder -d "$HOST" -silent;;
        assetfinder) replay_hint assetfinder --subs-only "$HOST";;
        curl) replay_hint curl -fsS --max-time 30 "https://crt.sh/?q=%25.${HOST}&output=json";;
      esac
    fi
    printf '%s\t%s\t%s\n' "$tool" "$status" "$count" >> "$f/ferramentas.tsv"
  done
  # Metadados de registro: WHOIS tradicional + RDAP + DNS (somente leitura).
  python3 - "$HOST" "$f" <<'PYREG'
import json, re, subprocess, sys, urllib.request
from pathlib import Path
host=sys.argv[1].lower().strip('.'); folder=Path(sys.argv[2]); root=host
# Para subdomínios, tenta domínio registrável por aproximação; casos especiais ficam no WHOIS.
parts=host.split('.')
if len(parts)>2:
    root='.'.join(parts[-3:]) if len(parts[-2])<=3 and parts[-1] in ('br','uk','au','nz','jp') else '.'.join(parts[-2:])
raw=(folder/'whois.txt').read_text(errors='replace') if (folder/'whois.txt').exists() else ''
fields={}
patterns={
 'Titular / organização':r'^(?:Registrant Organization|org-name|owner|organisation|organization|Registrant Name|owner-c):\s*(.+)$',
 'Registradora':r'^(?:Registrar|registrar|Sponsoring Registrar):\s*(.+)$',
 'Criação':r'^(?:Creation Date|Created On|created|registered|Registration Time):\s*(.+)$',
 'Atualização':r'^(?:Updated Date|last-modified|changed|Last Updated On):\s*(.+)$',
 'Expiração':r'^(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|expires|paid-till):\s*(.+)$',
 'Situação':r'^(?:Domain Status|status):\s*(.+)$',
 'País':r'^(?:Registrant Country|country):\s*(.+)$',
 'Nameservers':r'^(?:Name Server|nserver|nameserver):\s*(.+)$',
 'Nome do titular':r'^(?:Registrant Name|owner|person|registrant):\s*(.+)$',
 'E-mail cadastrado':r'^(?:Registrant Email|owner-email|e-mail|email):\s*(.+)$',
 'E-mail administrativo':r'^(?:Admin Email|admin-email):\s*(.+)$',
 'E-mail técnico':r'^(?:Tech Email|tech-email):\s*(.+)$',
 'Telefone cadastrado':r'^(?:Registrant Phone|owner-phone|phone):\s*(.+)$',
 'Contato de abuso':r'^(?:Registrar Abuse Contact Email|abuse-mailbox|abuse-email):\s*(.+)$',
 'Organização':r'^(?:Registrant Organization|org-name|organisation|organization):\s*(.+)$',

}
for label,regex in patterns.items():
    values=[m.group(1).strip() for m in re.finditer(regex,raw,re.I|re.M)]
    if values: fields[label]='; '.join(dict.fromkeys(values[:8]))
rdap={}
try:
    req=urllib.request.Request('https://rdap.org/domain/'+root,headers={'User-Agent':'Recon-Inventory/1.0','Accept':'application/rdap+json'})
    with urllib.request.urlopen(req,timeout=12) as response:
        rdap=json.load(response)
    (folder/'rdap.json').write_text(json.dumps(rdap,ensure_ascii=False,indent=2),encoding='utf-8')
except Exception as exc:
    fields['RDAP']='Indisponível ('+str(exc)[:100]+')'
if rdap:
    fields['RDAP']='Consulta concluída'
    if rdap.get('ldhName'): fields['Domínio registrado']=rdap['ldhName']
    if rdap.get('status'): fields['Situação']='; '.join(rdap['status'])
    if rdap.get('nameservers'): fields['Nameservers']='; '.join(n.get('ldhName','') for n in rdap['nameservers'] if n.get('ldhName'))
    for event in rdap.get('events',[]):
        key={'registration':'Criação','expiration':'Expiração','last changed':'Atualização'}.get(event.get('eventAction'))
        if key and event.get('eventDate'): fields[key]=event['eventDate']
    def walk_entities(entities):
        for entity in entities:
            roles=entity.get('roles',[])
            props={}
            card=entity.get('vcardArray',[])
            if len(card)>1 and isinstance(card[1],list):
                for item in card[1]:
                    if len(item)>3 and isinstance(item[3],str):
                        props.setdefault(item[0].lower(),[]).append(item[3])
            mapping={'fn':'Nome do titular','org':'Organização','email':'E-mail cadastrado','tel':'Telefone cadastrado'}
            if 'registrant' in roles:
                for key,label in mapping.items():
                    if props.get(key): fields.setdefault(label,'; '.join(props[key][:3]))
                if props.get('org'): fields.setdefault('Titular / organização',props['org'][0])
            for role,label in [('administrative','E-mail administrativo'),('technical','E-mail técnico'),('abuse','Contato de abuso')]:
                if role in roles and props.get('email'): fields.setdefault(label,'; '.join(props['email'][:3]))
            if 'registrar' in roles:
                if props.get('fn'): fields.setdefault('Registradora',props['fn'][0])
                if props.get('email'): fields.setdefault('Contato da registradora',props['email'][0])
            walk_entities(entity.get('entities',[]))
    walk_entities(rdap.get('entities',[]))
    for entity in rdap.get('entities',[]):
        roles=entity.get('roles',[])
        if 'registrar' in roles and entity.get('handle'): fields.setdefault('Registradora',entity['handle'])
        if 'registrant' in roles:
            for card in entity.get('vcardArray',[None,[]])[1]:
                if len(card)>3 and card[0] in ('org','fn') and isinstance(card[3],str): fields.setdefault('Titular / organização',card[3])
for kind in ('A','AAAA','MX','NS','TXT','SOA'):
    try:
        result=subprocess.run(['dig','+short',host,kind],capture_output=True,text=True,timeout=8)
        values=[x.strip() for x in result.stdout.splitlines() if x.strip()]
        if values: fields['DNS '+kind]='; '.join(values[:12])[:700]
    except (OSError,subprocess.TimeoutExpired): pass
# Inventário DNS complementar: somente consultas públicas, sem transferência de zona.
import ipaddress
extra={}
def query_dns(name,kind,limit=12):
    try:
        result=subprocess.run(['dig','+time=3','+tries=1','+short',name,kind],capture_output=True,text=True,timeout=6)
        return [v.strip() for v in result.stdout.splitlines() if v.strip()][:limit]
    except (OSError,subprocess.TimeoutExpired):
        return []
for kind in ('CNAME','CAA','DS','DNSKEY','HTTPS','TLSA'):
    values=query_dns(root,kind)
    if values: extra['DNS '+kind]='; '.join(values)[:800]
for name,label in (('_dmarc.'+root,'DMARC'),('_mta-sts.'+root,'MTA-STS'),('_smtp._tls.'+root,'TLS-RPT')):
    values=query_dns(name,'TXT')
    if values: extra[label]='; '.join(values)[:800]
txt_records=query_dns(root,'TXT',30)
spf=[v for v in txt_records if 'v=spf1' in v.lower()]
if spf: extra['SPF']='; '.join(spf)[:800]
soa=query_dns(root,'SOA')
if soa:
    extra['SOA primário']=soa[0].split()[0]
    extra['SOA responsável']=soa[0].split()[1] if len(soa[0].split())>1 else 'Não divulgado'
ips=[]
for kind in ('A','AAAA'):
    for value in query_dns(host,kind):
        try:
            ip=ipaddress.ip_address(value)
            if ip.is_global and value not in ips: ips.append(value)
        except ValueError: pass
extra['IPs públicos']='; '.join(ips[:8]) if ips else 'Não encontrados'
for ip in ips[:2]:
    try:
        req=urllib.request.Request('https://rdap.org/ip/'+ip,headers={'User-Agent':'Recon-Inventory/1.0','Accept':'application/rdap+json'})
        with urllib.request.urlopen(req,timeout=7) as response: network=json.load(response)
        net=network.get('name') or network.get('handle') or 'Não identificado'
        extra['Rede '+ip]=str(net)[:180]+' | '+str(network.get('country','País não informado'))
    except Exception:
        extra['Rede '+ip]='RDAP de IP indisponível'
fields.update(extra)
(folder/'dns_avancado.json').write_text(json.dumps(extra,ensure_ascii=False,indent=2),encoding='utf-8')
lines=['INFORMAÇÕES DO DOMÍNIO','Alvo: '+host,'Domínio consultado: '+root,'']
for label in ('Nome do titular','Titular / organização','Organização','E-mail cadastrado','E-mail administrativo','E-mail técnico','Telefone cadastrado','Contato de abuso','Contato da registradora','Registradora','País','Criação','Atualização','Expiração','Situação','Nameservers','DNS A','DNS AAAA','DNS MX','DNS NS','DNS TXT','DNS SOA','DNS CNAME','DNS CAA','DNS DS','DNS DNSKEY','DNS HTTPS','DNS TLSA','SPF','DMARC','MTA-STS','TLS-RPT','SOA primário','SOA responsável','IPs públicos',*[k for k in fields if k.startswith('Rede ')],'RDAP'):
    lines.append(label+': '+fields.get(label,'Não divulgado / não encontrado'))
(folder/'dominio_resumo.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
(folder/'dominio_dados.json').write_text(json.dumps({'alvo':host,'dominio_consultado':root,'campos':fields},ensure_ascii=False,indent=2),encoding='utf-8')
print('[·] ══ INFORMAÇÕES DO DOMÍNIO ══',flush=True)
print('[·] Alvo: '+host,flush=True)
print('[·] Domínio consultado: '+root,flush=True)
for line in lines[4:]:
    print('[·] '+line[:400],flush=True)
print('[✓] Inventário salvo: 01_recon/dominio_resumo.txt e dominio_dados.json',flush=True)
PYREG
  grep -E "(^|\.)${HOST//./\.}$" "$f/subs.txt" | sort -u > "$f/subs.filtered" || true
  mv "$f/subs.filtered" "$f/subs.txt"
  local n; n=$(wc -l < "$f/subs.txt")
  info "Subdomínios únicos: $n"
  if ((n>0)); then register_finding "INFORMATIVO" "Recon" "$n subdomínio(s) descoberto(s)" "$f/subs.txt"; fi
  return "$partial"
}

# ═════════════════════════════ FASE 2 · PORTAS ══════════════════════════════
phase_2(){
  hdr "FASE 2 · Portas e serviços"
  local scan_rc=0
  local f="$OUT/02_portas"; mkdir -p "$f"; : > "$f/portas.txt"
  rm -f "$f/scan_status.json" "$f/resumo.txt"
  if have nmap; then
    rm -f "$f/nmap.txt" "$f/nmap.xml"
    local budget
    budget=$(scan_timeout "$NMAP_TIMEOUT") || return 1
    info "Nmap: conexão TCP nas 1000 portas mais comuns, com motivos dos estados e saída XML"
    if ((budget == 0)); then info "Nmap: aguardando conclusão, sem limite total; use Pular para interromper."
    else info "Nmap: limite total configurado de ${budget}s; interrupção indica cobertura parcial."; fi
    local -a address_options=()
    [[ "$HOST" == *:* ]] && address_options=(-6)
    bounded_tool "$budget" "$f/nmap" nmap "${address_options[@]}" -Pn -sT -T3 --top-ports 1000 --reason -sV --version-light "$HOST" -oN "$f/nmap.txt" -oX "$f/nmap.xml" || scan_rc=$?
    python3 "$SCRIPT_DIR/scan_inventory.py" --host "$HOST" --xml "$f/nmap.xml" --out "$f" --exit-code "$scan_rc" || scan_rc=1
    [[ ! -s "$f/resumo.txt" ]] || while IFS= read -r item; do info "$item"; done < "$f/resumo.txt"
  else
    warn "Nmap ausente: teste TCP limitado, sem identificação de serviços; consulte tcp_status.tsv"
    printf 'ferramenta=TCP fallback\nestado=executando\n' > "$f/nmap.exec.txt"
    printf 'porta\tcodigo\n' > "$f/tcp_status.tsv"
    : > "$f/nmap.stderr"
    local tcp_rc
    local p; for p in 21 22 25 53 80 110 143 443 445 465 587 993 995 3306 3389 5432 8080 8443; do
      tcp_rc=0
      timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$HOST" "$p" 2>>"$f/nmap.stderr" || tcp_rc=$?
      printf '%s\t%s\n' "$p" "$tcp_rc" >> "$f/tcp_status.tsv"
      ((tcp_rc != 0)) || echo "$p/tcp open" >> "$f/portas.txt"
    done
    printf 'estado=encerrado\n' >> "$f/nmap.exec.txt"
  fi
  local n; n=$(wc -l <"$f/portas.txt" 2>/dev/null || echo 0)
  python3 - "$HOST" "$f" <<'PYPORTS'
import json, re, sys
from pathlib import Path
host, folder = sys.argv[1], Path(sys.argv[2])
rows = []
for line in (folder / 'portas.txt').read_text().splitlines():
    match = re.match(r'^(\d+)/tcp\s+open\s*(.*)', line)
    if match and 0 < int(match[1]) < 65536:
        rows.append({'port': int(match[1]), 'service': match[2]})
(folder / 'portas.json').write_text(json.dumps({'host': host, 'ports': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
PYPORTS
  info "Portas abertas: $n"
  if ((n>0)); then
    info "Inventário de portas (porta / estado / serviço):"
    while IFS= read -r item; do info "  $item"; done < "$f/portas.txt"
  else
    if ((scan_rc == 0)) && [[ -s "$f/scan_status.json" ]]; then
      info "Nmap concluído sem portas abertas nas portas e endereços examinados; consulte os estados em resumo.txt."
      return 0
    fi
    warn "Nenhuma porta identificada: resultado inconclusivo; não significa ausência de serviços."
    warn "Tor/AnonSurf pode restringir conexões TCP e DNS; consulte nmap.txt, nmap.stdout e nmap.stderr."
    for p in "$f/nmap.stderr" "$f/nmap.stdout"; do
      [[ ! -s "$p" ]] || head -n 8 "$p" | while IFS= read -r item; do warn "Nmap: $item"; done
    done
    return 1
  fi
  ((scan_rc == 0)) || { warn "Nmap incompleto (código $scan_rc); inventário parcial"; return 1; }
  return 0
}

# ═════════════════════════ FASE 3 · TECNOLOGIAS/WAF ═════════════════════════
phase_3(){
  hdr "FASE 3 · Tecnologias e WAF"
  local partial=0
  local f="$OUT/03_tech"; mkdir -p "$f"
  if ((WORDPRESS==1)); then
    if have wpscan; then
      info "WordPress: WPScan, plugins/temas por detecção passiva; não confirma exploração"
      bounded_tool 180 "$f/wpscan" wpscan --url "$BASE" --no-update --ignore-main-redirect --detection-mode passive --plugins-detection passive --plugins-version-detection passive --enumerate vp,vt --max-threads 2 --connect-timeout 10 --request-timeout 10 --format json || partial=1
      info "WordPress: saída em $f/wpscan.stdout (dados de vulnerabilidades dependem de API configurada no WPScan)"
    else
      warn "WPScan ausente; consulte 00_dependencias/instalacao.log"
    fi
  fi
  if have whatweb; then
    bounded_tool 45 "$f/whatweb" whatweb "$BASE" || partial=1
    cp "$f/whatweb.stdout" "$f/whatweb.txt"
  else
    info "WhatWeb não instalado"
  fi
  if have wafw00f; then
    bounded_tool 45 "$f/waf" wafw00f "$BASE" || partial=1
    cp "$f/waf.stdout" "$f/waf.txt"
  else
    info "WAFW00F não instalado"
  fi
  gurl 12 "$BASE" | head -c 50000 > "$f/home.html" 2>/dev/null || true
  grep -oiE 'server:[^<]+|x-powered-by:[^<]+' "$f/home.html" >> "$f/tech.txt" 2>/dev/null || true
  if [[ -s "$f/whatweb.txt" ]]; then
    info "WhatWeb — tecnologias identificadas:"
    head -n 8 "$f/whatweb.txt" | while IFS= read -r item; do info "  ${item:0:300}"; done
  else
    warn "WhatWeb: sem resultado (não significa ausência de tecnologias)"
  fi
  if [[ -s "$f/waf.txt" ]]; then
    info "WAFW00F — resultado:"
    tail -n 10 "$f/waf.txt" | while IFS= read -r item; do info "  ${item:0:300}"; done
  else
    info "WAFW00F: sem dados; verificar ferramenta e conectividade"
  fi
  return "$partial"
}

# ════════════════════════════ FASE 4 · CRAWL ════════════════════════════════
phase_4(){
  hdr "FASE 4 · Páginas e conteúdo"
  local f="$OUT/04_crawl"; mkdir -p "$f"; : > "$f/urls.txt"
  local depth=3 partial=0
  [[ "$MODE" != profundo ]] || depth=5
  [[ "$MODE" != rapido ]] || depth=2
  have gau && { bounded_tool 60 "$f/gau" gau --timeout 10 --retries 1 --threads 2 "$HOST" || partial=1; cat "$f/gau.stdout" >> "$f/urls.txt"; }
  have waybackurls && { bounded_tool 60 "$f/wayback" waybackurls "$HOST" || partial=1; cat "$f/wayback.stdout" >> "$f/urls.txt"; }
  have katana && { bounded_tool 90 "$f/katana" katana -u "$BASE" -silent -d "$depth" -cs "^${ROOT//./\\.}(/|$)" -rl 3 -c 2 || partial=1; cat "$f/katana.stdout" >> "$f/urls.txt"; }
  # fallback: crawl simples
  gurl 12 "$BASE" | grep -oE 'href="[^"]+"|src="[^"]+"' 2>/dev/null \
    | sed -E 's/.*="//; s/"$//' >> "$f/urls.txt" 2>/dev/null || true
  if have ffuf; then
    bounded_tool 90 "$f/ffuf" ffuf -u "$ROOT/FUZZ" -w /usr/share/wordlists/dirb/common.txt -ac -rate 3 -t 2 -maxtime 85 -mc 200,301,302,403 -s || partial=1
    awk '{print $1}' "$f/ffuf.stdout" | sed "s#^#$ROOT/#" >> "$f/urls.txt"
  fi
  sort -u "$f/urls.txt" -o "$f/urls.txt" 2>/dev/null || true
  python3 "$AUDIT_HELPER" urls --base "$BASE" "$f/urls.txt" > "$f/urls_normalizadas.txt" || return 1
  mv "$f/urls_normalizadas.txt" "$f/urls.txt"
  local n; n=$(wc -l <"$f/urls.txt" 2>/dev/null || echo 0)
  info "URLs encontradas: $n"
  if ((n>0)); then
    info "Amostra das URLs (inventário, não vulnerabilidades):"
    head -n 15 "$f/urls.txt" | while IFS= read -r item; do info "  ${item:0:250}"; done
    register_finding "INFORMATIVO" "Crawl" "$n URL(s) mapeada(s)" "$f/urls.txt"
  else
    warn "Nenhuma URL coletada; verifique as ferramentas e a conectividade"
  fi
  ((n > 0)) || partial=1
  return "$partial"
}

# ════════════════════════ FASE 9 · EXPOSIÇÃO (.env/.git) ════════════════════
phase_5(){
  hdr "FASE 9 · Exposição de informações"
  local f="$OUT/05_exposicao"; mkdir -p "$f/conteudo"
  local paths=(.env .env.local .env.production .git/config .git/HEAD backup.zip site.zip
               www.zip robots.txt sitemap.xml phpinfo.php .DS_Store composer.json
               package.json config.php .svn/entries .htaccess web.config)
  local p url code name rc checked=0 public=0 candidates=0 generic=0 failures=0 other=0 consecutive_failures=0
  printf 'url\thttp_status\tcurl_exit\n' > "$f/status.tsv"
  info "Exposição: verificando ${#paths[@]} caminhos conhecidos; HTTP 200 sozinho não confirma vazamento"
  for p in "${paths[@]}"; do
    url="$ROOT/$p"
    name=$(printf '%s' "$p" | tr '/.' '__')
    rc=0; checked=$((checked+1))
    code=$(curl -sk -o /dev/null -w '%{http_code}' -m 10 "${HDRS[@]}" "$url" 2>"$f/$name.stderr") || rc=$?
    printf '%s\t%s\t%s\n' "$url" "${code:-indisponível}" "$rc" >> "$f/status.tsv"
    if ((rc != 0)) || [[ "$code" == 000 || -z "$code" ]]; then
      failures=$((failures+1)); warn "Exposição: consulta falhou: $url (curl $rc, HTTP ${code:-indisponível}); inconclusivo"
      consecutive_failures=$((consecutive_failures+1))
      if ((consecutive_failures >= 3)); then
        warn "Exposicao: interrompida apos 3 falhas consecutivas de transporte; cobertura parcial."
        break
      fi
      continue
    fi
    consecutive_failures=0
    info "Exposição: HTTP $code — $url"
    if [[ "$code" != 200 ]]; then other=$((other+1)); continue; fi
    case "$p" in
      robots.txt|sitemap.xml) public=$((public+1)); info "Recurso público encontrado: $url"; continue;;
    esac
    rc=0
    code=$(curl -sk -m 12 --max-filesize 2000000 -o "$f/conteudo/$name" -w '%{http_code}' "${HDRS[@]}" "$url" 2>"$f/$name.body.stderr") || rc=$?
    printf '%s\t%s\t%s\n' "$url" "${code:-indisponível}" "$rc" >> "$f/status.tsv"
    if ((rc != 0)) || [[ "$code" != 200 || ! -s "$f/conteudo/$name" ]]; then
      failures=$((failures+1)); info "Exposição: coleta de conteúdo não aproveitada: $url (HTTP ${code:-indisponível}, curl $rc ou corpo vazio); inconclusivo"
      continue
    fi
    # Evita classificar páginas HTML genéricas de fallback como arquivos expostos.
    if head -c 500 "$f/conteudo/$name" | grep -Eiq '<!doctype html|<html'; then
      generic=$((generic+1))
      info "Resposta HTML genérica; exposição não confirmada: $url"
      continue
    fi
    candidates=$((candidates+1))
    register_finding "MÉDIO" "Arquivos sensíveis" "Conteúdo potencialmente sensível acessível (HTTP 200): $url — validar manualmente" "$f/conteudo/$name"
  done
  info "Exposição: $checked caminhos · $public recursos públicos · $generic respostas HTML genéricas · $candidates candidatos a revisar · $other respostas diferentes de 200 · $failures falhas/coletas inconclusivas"
  info "Exposição: candidatos não confirmam vazamento; ausência de candidatos não comprova segurança. Evidências: $f/status.tsv e $f/conteudo"
  if ((failures > 0)); then return 1; fi
  return 0
}

# ═══════════════════════════ FASE 7 · DESCOBERTA API ════════════════════════
phase_6(){
  hdr "FASE 7 · Descoberta de API"
  local f="$OUT/06_api"; mkdir -p "$f"; : > "$f/apis.txt"
  local paths=(swagger.json swagger-ui.html openapi.json api-docs api/v1 api/v2 graphql api/graphql api/forgot-password api/reset-password auth/forgot-password)
  local p code kind
  : > "$f/candidatos.txt"
  : > "$f/rotas_get.txt"
  for p in "${paths[@]}"; do
    code=$(curl -sk -o "$f/${p//\//_}.body" -D "$f/${p//\//_}.headers" -w '%{http_code}' -m 10 --max-filesize 2000000 "${HDRS[@]}" "$ROOT/$p" 2>"$f/${p//\//_}.stderr")
    if [[ "$code" == 200 ]]; then
      if kind=$(python3 "$AUDIT_HELPER" api "$f/${p//\//_}.body"); then
        echo "$ROOT/$p" >> "$f/apis.txt"
        info "Documento $kind identificado: $ROOT/$p"
        python3 "$AUDIT_HELPER" schema-gets --base "$BASE" "$f/${p//\//_}.body" >> "$f/rotas_get.txt" || true
      else
        echo "$ROOT/$p" >> "$f/candidatos.txt"
        info "HTTP 200 sem documento API validado: $ROOT/$p (possível fallback HTML)"
      fi
    elif [[ "$code" == 401 || "$code" == 403 || "$code" == 405 ]]; then
      echo "$ROOT/$p" >> "$f/candidatos.txt"
      info "Candidato API com HTTP $code: $ROOT/$p"
    fi
  done
  info "Documentos API validados: $(wc -l < "$f/apis.txt") · candidatos: $(wc -l < "$f/candidatos.txt")"
  python3 "$SCRIPT_DIR/endpoint_inventory.py" --base "$BASE" --out "$OUT" || return 1
  info "API: inventário de rotas e métodos em 06_api/operacoes.tsv (inclui formulários e chamadas JS)"
  { cat "$f/rotas_get.txt" "$f/endpoints_get.txt";
    grep -E '/(api|graphql|auth)(/|$)' "$f/candidatos.txt" || true;
    cat "$f/apis.txt" "$f/candidatos.txt";
  } > "$f/requisicoes_candidatas.txt"
  rm -f "$f/api_resultados.json" "$f/api_resultados.tsv"
  local probe_rc=0
  local -a plan_args=()
  if [[ -n "$API_REQUEST_PLAN" ]]; then
    plan_args=(--request-plan "$API_REQUEST_PLAN")
    [[ "$API_EXECUTE_PLAN" != 1 ]] || plan_args+=(--execute-plan)
  fi
  bounded_tool 150 "$f/api_probe" env AUTH_MODE="$AUTH_MODE" AUTH_USER="$AUTH_USER" AUTH_PASS="$AUTH_PASS" AUTH_SECRET="$AUTH_SECRET" python3 -u "$SCRIPT_DIR/api_probe.py" --base "$BASE" --candidates "$f/requisicoes_candidatas.txt" --out "$f" --limit 8 --schemas-dir "$f" "${plan_args[@]}" || probe_rc=$?
  cat "$f/api_probe.stdout"
  info "API: resultados em 06_api/api_resultados.tsv; métodos descobertos em operacoes.tsv"
  [[ -n "$API_REQUEST_PLAN" ]] || info "API: revisão automática GET/OPTIONS; POST/PUT/PATCH/DELETE requerem plano explícito com dados de teste."
  return "$probe_rc"
}

# ═════════════════════════════ FASE 8 · PARÂMETROS ══════════════════════════
phase_7(){
  hdr "FASE 8 · Parâmetros"
  local f="$OUT/07_params"; mkdir -p "$f"
  : > "$f/com_param.txt"
  grep '?' "$OUT/04_crawl/urls.txt" 2>/dev/null > "$f/com_param.txt" || true
  if have arjun && [[ "$MODE" != rapido && "$AUTH_MODE" == none ]]; then
    : > "$f/arjun.json"
    bounded_tool 90 "$f/arjun" arjun -u "$BASE" -m GET -w small -t 1 -T 8 --rate-limit 2 --disable-redirects -oJ "$f/arjun.json" || true
    python3 "$AUDIT_HELPER" arjun --base "$BASE" "$f/arjun.json" >> "$f/com_param.txt" || warn "Arjun: saída não aproveitada"
  else
    info "Arjun: opcional, somente modo completo/profundo sem autenticação configurada"
  fi
  sort -u "$f/com_param.txt" -o "$f/com_param.txt"
  grep -oE '[?&][a-zA-Z0-9_]+=' "$f/com_param.txt" 2>/dev/null | tr -d '?&=' | sort -u > "$f/params.txt" || true
  info "Parâmetros: $(wc -l <"$f/params.txt" 2>/dev/null || echo 0)"
}

# ═══════════════════════════ FASE 5 · ANÁLISE CÓDIGO ════════════════════════
phase_8(){
  hdr "FASE 5 · Análise de código (front)"
  local f="$OUT/08_codigo"; mkdir -p "$f"
  local code rc=0
  : > "$f/js.txt"; : > "$f/comentarios.txt"; : > "$f/indicadores.txt"
  code=$(curl -sk -m 15 --max-filesize 2000000 "${HDRS[@]}" -D "$f/headers.txt" -o "$f/index.html" -w '%{http_code}' "$BASE" 2>"$f/curl.stderr") || rc=$?
  printf 'http_status=%s\ncurl_exit=%s\n' "$code" "$rc" > "$f/coleta_status.txt"
  if ((rc != 0)) || [[ "$code" != 2?? ]]; then
    warn "Front: HTTP ${code:-indisponível}, curl $rc; HTML não aproveitado. HTTP 403/429 pode indicar bloqueio; 3xx exige revisar a URL final dentro do escopo."
    replay_hint curl -sS --max-time 15 "${HDRS[@]}" -D - -o /dev/null "$BASE"
    return 1
  fi
  python3 "$SCRIPT_DIR/front_inventory.py" --base "$BASE" "$f/index.html" > "$f/js.txt" || return 1
  info "Front: $(wc -l < "$f/js.txt") scripts no escopo descobertos pelo parser HTML (inclui módulos e URLs sem extensão)"
  grep -oE '<!--.*-->' "$f/index.html" 2>/dev/null > "$f/comentarios.txt" || true
  grep -oiE '(api|token|key|secret)["'"'"':= ]+[A-Za-z0-9_-]{8,}' "$f/index.html" 2>/dev/null | sort -u > "$f/indicadores.txt" || true
}

# ════════════════════════════ FASE 15 · NUCLEI ═══════════════════════════════
phase_9(){
  hdr "FASE 15 · Vulnerabilidades (nuclei)"
  local nuclei_rc=0
  local f="$OUT/09_vulns"; mkdir -p "$f"
  if have nuclei; then
    : > "$f/nuclei.txt"
    { printf '%s\n' "$ROOT/" "$BASE"; cat "$OUT/04_crawl/urls.txt" 2>/dev/null || true; } > "$f/alvos_coletados.txt"
    python3 "$AUDIT_HELPER" urls --base "$BASE" "$f/alvos_coletados.txt" > "$f/alvos.txt" || return 1
    local budget
    budget=$(scan_timeout "$NUCLEI_TIMEOUT") || return 1
    info "Nuclei: $(wc -l < "$f/alvos.txt") URLs no escopo"
    if ((budget == 0)); then info "Nuclei: aguardando conclusão, sem limite total; use Pular para interromper."
    else info "Nuclei: limite total configurado de ${budget}s; interrupção indica cobertura parcial."; fi
    info "Nuclei: estatísticas em nuclei.stderr; sem repetição de requisições. NUCLEI_TIMEOUT ajusta o limite total (0 = sem limite)."
    bounded_tool "$budget" "$f/nuclei" nuclei -l "$f/alvos.txt" -stats -stats-interval 15 -severity low,medium,high,critical -rl 3 -c 2 -timeout 5 -retries 0 -o "$f/nuclei.txt" || nuclei_rc=$?
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      register_finding "MÉDIO" "Scanner — requer validação" "${line:0:200}" "$f/nuclei.txt"
    done < "$f/nuclei.txt"
  else
    warn "Nuclei ausente; fase não executada"
    return 1
  fi
  ((nuclei_rc == 0)) || { warn "Nuclei parcial/falhou: código $nuclei_rc; consultar nuclei.exec.txt e nuclei.stderr"; return 1; }
  info "Nuclei: execução encerrada; saída vazia não comprova ausência de vulnerabilidades."
  return 0
}

# ════════════════════════════ FASE 16 · CVEs ════════════════════════════════
phase_10(){
  hdr "FASE 16 · CVEs identificadas"
  local f="$OUT/10_cves"; mkdir -p "$f"
  local cve_rc=0
  printf 'CVEs: coleta ainda não concluída; consultar cve.exec.txt e cve.stderr.\n' > "$f/resumo.txt"
  : > "$f/ids.txt"; : > "$f/cves.txt"
  info "CVEs: examinando evidências locais por até 30s; limite externo de 35s."
  bounded_tool 35 "$f/cve" python3 "$SCRIPT_DIR/cve_inventory.py" --out "$OUT" || cve_rc=$?
  if ((cve_rc == 124 || cve_rc == 137)); then
    printf 'CVEs: coleta interrompida por tempo limite; resultado inconclusivo. Consulte cve.exec.txt e cve.stderr.\n' > "$f/resumo.txt"
  fi
  while IFS= read -r item; do info "$item"; done < "$f/resumo.txt"
  local n id; n=$(wc -l <"$f/ids.txt" 2>/dev/null || echo 0)
  if [[ "$n" -gt 0 ]]; then
    info "CVEs: $n identificadores únicos citados nas ferramentas; aplicabilidade e exploração não confirmadas"
    while IFS= read -r id; do
      register_finding "INFORMATIVO" "CVE potencial" "$id — referência da ferramenta; validar produto, versão e configuração afetados" "$f/cves.txt"
      info "CVE: $id · referência: https://www.cve.org/CVERecord?id=$id · fontes em $f/cves.txt"
    done < "$f/ids.txt"
    info "CVEs: o arquivo cves.txt mantém os identificadores e arquivos de origem. Correção depende da aplicabilidade e do aviso oficial do fornecedor; não executar PoC apenas pela citação."
  else
    info "CVEs: nenhuma referência encontrada nas saídas disponíveis"
  fi
  return "$cve_rc"
}

# ═════════════════════════════ FASE 17 · SQLi ═══════════════════════════════
phase_11(){
  hdr "FASE 17 · SQL Injection"
  local f="$OUT/11_sqli"; mkdir -p "$f"
  : > "$f/sqlmap.log"
  printf 'url\tcodigo\tevidencia\n' > "$f/cobertura.tsv"
  if [[ ! -s "$OUT/07_params/com_param.txt" ]]; then
    info "SQLi: sem URLs com parâmetros no inventário; teste não executado"
    return 3
  fi
  python3 "$AUDIT_HELPER" urls --base "$BASE" "$OUT/07_params/com_param.txt" > "$f/candidatos.txt" || return 1
  python3 "$AUDIT_HELPER" sqli-sample --base "$BASE" "$f/candidatos.txt" > "$f/selecionados.txt" || return 1
  if [[ ! -s "$f/selecionados.txt" ]]; then
    info "SQLi: nenhum candidato elegivel na amostra; inventario preservado, teste nao executado"
    return 3
  fi
  have sqlmap || { warn "SQLmap ausente; candidatos preservados, teste não executado"; return 1; }
  local u n=0 rc=0 failures=0 total limit=5 selected
  local budget=90 started=$SECONDS remaining per_url consecutive_timeouts=0
  total=$(wc -l < "$f/candidatos.txt")
  selected=$(wc -l < "$f/selecionados.txt")
  info "SQLi: amostra de $selected URLs, no maximo $limit de $total candidatos; limite total de ${budget}s, ate 30s por URL"
  : > "$f/interrupcao.txt"
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    ((limit == 0 || n < limit)) || break
    remaining=$((budget - (SECONDS - started)))
    if ((remaining <= 0)); then
      printf 'Limite total de %ss atingido; cobertura parcial.\n' "$budget" > "$f/interrupcao.txt"
      break
    fi
    per_url=30
    ((remaining >= per_url)) || per_url=$remaining
    n=$((n+1)); rc=0
    info "SQLi: $n/$total - $u (limite ${per_url}s; restante da etapa: ${remaining}s)"
    bounded_tool "$per_url" "$f/sqlmap_$n" sqlmap -u "$u" --batch --level=1 --risk=1 --threads=1 --timeout=8 --retries=1 --ignore-redirects --output-dir="$f/sm_$n" || rc=$?
    printf '%s\t%s\t%s\n' "$u" "$rc" "$f/sqlmap_$n.stdout" >> "$f/cobertura.tsv"
    cat "$f/sqlmap_$n.stdout" "$f/sqlmap_$n.stderr" >> "$f/sqlmap.log"
    ((rc == 0)) || failures=$((failures+1))
    if grep -Eqi 'Parameter: .*\(|is vulnerable' "$f/sqlmap_$n.stdout"; then
      register_finding "MÉDIO" "SQLi — requer validação" "Possível SQLi em $u (verificar evidência)" "$f/sqlmap_$n.stdout"
    fi
    if ((rc == 124 || rc == 137)); then
      consecutive_timeouts=$((consecutive_timeouts+1))
    else
      consecutive_timeouts=0
    fi
    if ((consecutive_timeouts >= 3)); then
      printf 'Interrompido apos 3 timeouts consecutivos; cobertura parcial.\n' > "$f/interrupcao.txt"
      break
    fi
  done < "$f/selecionados.txt"
  if ((n < total)); then
    [[ -s "$f/interrupcao.txt" ]] || printf 'Amostragem limitada a 5 URLs sem repeticao de rota e parametros; cobertura parcial.\n' > "$f/interrupcao.txt"
    warn "SQLi: $(cat "$f/interrupcao.txt") $((total-n)) URLs nao processadas; candidatos preservados em $f/candidatos.txt"
  fi
  info "SQLi: $n/$total URLs processadas · $failures falhas/parciais; evidência por URL em cobertura.tsv"
  ((failures == 0 && n == total))
}

# ═════════════════════════════ FASE 18 · IDOR ═══════════════════════════════
phase_12(){
  hdr "FASE 18 · Candidatos IDOR / BOLA"
  local f="$OUT/12_idor"; mkdir -p "$f"
  grep -oE '/[0-9]+(/|$)' "$OUT/04_crawl/urls.txt" 2>/dev/null | sort -u | head -n 40 > "$f/ids.txt" || true
  if [[ -s "$f/ids.txt" ]]; then
    register_finding "INFORMATIVO" "IDOR / BOLA" "IDs numéricos candidatos; falha de autorização não confirmada" "$f/ids.txt"
  else
    info "IDOR: nenhum candidato numérico encontrado"
  fi
  return 0
}

# ══════════════════════════════ FASE 19 · XSS ═══════════════════════════════
phase_13(){
  hdr "FASE 19 · XSS"
  local f="$OUT/13_xss"; mkdir -p "$f"
  : > "$f/xss_candidatos.txt"; : > "$f/dalfox.log"
  printf 'url\tcodigo\tevidencia\n' > "$f/cobertura.tsv"
  [[ -s "$OUT/07_params/com_param.txt" ]] || { info "XSS: sem URLs com parâmetros; teste não executado"; return 3; }
  python3 "$AUDIT_HELPER" urls --base "$BASE" "$OUT/07_params/com_param.txt" > "$f/xss_candidatos.txt" || return 1
  have dalfox || { warn "Dalfox ausente; candidatos preservados, teste não executado"; return 1; }
  local u n=0 rc=0 failures=0 total limit=0
  total=$(wc -l < "$f/xss_candidatos.txt")
  [[ "$MODE" != rapido ]] || limit=5
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    ((limit == 0 || n < limit)) || break
    n=$((n+1)); rc=0
    info "XSS: $n/$total — $u (limite 60s por URL)"
    bounded_tool 60 "$f/dalfox_$n" dalfox url "$u" --worker 2 --timeout 8 || rc=$?
    printf '%s\t%s\t%s\n' "$u" "$rc" "$f/dalfox_$n.stdout" >> "$f/cobertura.tsv"
    cat "$f/dalfox_$n.stdout" "$f/dalfox_$n.stderr" >> "$f/dalfox.log"
    ((rc == 0)) || failures=$((failures+1))
  done < "$f/xss_candidatos.txt"
  info "XSS: $n/$total URLs processadas · $failures falhas/parciais; revisar cobertura.tsv e dalfox.log"
  ((failures == 0 && n == total))
}

# ═══════════════════════════ FASE 20 · AUTORIZAÇÃO ══════════════════════════
phase_14(){
  hdr "FASE 20 · Revisão básica de autorização (final)"
  local f="$OUT/14_authz"; mkdir -p "$f"
  local route url code rc failures=0
  printf 'url\thttp_status\tcurl_exit\n' > "$f/admin.txt"
  info "Autorização: GET sem credenciais em /admin e /dashboard; redirecionamentos não são seguidos"
  for route in admin dashboard; do
    url="$ROOT/$route"; rc=0
    code=$(curl -sk -o /dev/null -w '%{http_code}' -m 10 "$url" 2>"$f/$route.stderr") || rc=$?
    printf '%s\t%s\t%s\n' "$url" "${code:-indisponível}" "$rc" >> "$f/admin.txt"
    if ((rc != 0)) || [[ "$code" == 000 || -z "$code" ]]; then
      failures=$((failures+1)); warn "Autorização: consulta falhou: $url (curl $rc, HTTP ${code:-indisponível}); inconclusivo"
      continue
    fi
    case "$code" in
      200) info "Autorização: HTTP 200 — $url; pode ser login ou HTML genérico, acesso indevido não confirmado";;
      401|403) info "Autorização: HTTP $code — $url; acesso recusado nesta requisição";;
      3??) info "Autorização: HTTP $code — $url; redirecionamento observado, destino não avaliado";;
      404) info "Autorização: HTTP 404 — $url; rota não encontrada nesta resposta";;
      *) info "Autorização: HTTP $code — $url; resposta requer revisão manual";;
    esac
  done
  info "Autorização: 2 rotas consultadas · $failures falhas. Não compara usuários/papéis nem confirma bypass. Evidência: $f/admin.txt"
  if ((failures > 0)); then return 1; fi
  return 0
}

# ═════════════════════════════ FASE 21 · ZAP ════════════════════════════════
phase_15(){
  hdr "FASE 21 · OWASP ZAP (CLI)"
  local rc=0
  local f="$OUT/15_zap"; mkdir -p "$f"
  if have zap-cli; then
    bounded_tool 120 "$f/zap" zap-cli quick-scan -s all -r "$BASE" || rc=$?
    cp "$f/zap.stdout" "$f/zap.txt"
  elif have docker; then
    bounded_tool 120 "$f/zap" docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t "$BASE" || rc=$?
    cp "$f/zap.stdout" "$f/zap.txt"
  else
    warn "ZAP indisponível: requer zap-cli ou Docker; fase não executada"
    return 3
  fi
  ((rc == 0)) || return 1
  return 0
}

# ═════════════════════════ FASE 12 · PRIVACIDADE API ════════════════════════
phase_16(){
  hdr "FASE 12 · Cabeçalhos de privacidade (URL base)"
  local f="$OUT/16_privacidade"; mkdir -p "$f"
  local code rc=0 names
  : > "$f/headers.txt"
  info "Privacidade: GET na URL base $BASE (não percorre endpoints de API)"
  code=$(curl -sk -D "$f/resposta.headers" -o /dev/null -w '%{http_code}' -m 10 "${HDRS[@]}" "$BASE" 2>"$f/curl.stderr") || rc=$?
  if ((rc != 0)) || [[ "$code" == 000 || -z "$code" ]]; then
    warn "Privacidade: consulta falhou (curl $rc, HTTP ${code:-indisponível}); avaliação inconclusiva. Detalhes: $f/curl.stderr"
    return 1
  fi
  grep -iE '^(access-control[^:]*|set-cookie|referrer-policy):' "$f/resposta.headers" > "$f/headers.txt" || true
  info "Privacidade: HTTP $code"
  if [[ -s "$f/headers.txt" ]]; then
    names=$(cut -d: -f1 "$f/headers.txt" | tr -d '\r' | sort -fu | paste -sd ',' -)
    info "Privacidade: cabeçalhos observados: $names (valores de cookies omitidos no log)"
  else
    info "Privacidade: nenhum cabeçalho CORS, Set-Cookie ou Referrer-Policy observado nesta resposta"
  fi
  info "Privacidade: coleta informativa; não confirma exposição de dados, permissões de API ou vulnerabilidade. Evidência: $f/headers.txt"
  return 0
}

# ═══════════════════════════ FASE 11 · INVENTÁRIO LOGIN ═════════════════════
phase_17(){
  hdr "FASE 11 · Inventário de logins"
  local f="$OUT/17_logins"; mkdir -p "$f"
  grep -iE 'login|signin|auth|session' "$OUT/04_crawl/urls.txt" 2>/dev/null | sort -u > "$f/logins.txt" || true
  info "Páginas de login: $(wc -l <"$f/logins.txt" 2>/dev/null || echo 0)"
}

# ═════════════════════════ FASE 27 · COLETA IDENTIFICADORES ═════════════════
phase_18(){
  hdr "FASE 27 · Coleta de identificadores"
  local f="$OUT/18_ident"; mkdir -p "$f"
  : > "$f/emails.txt"; : > "$f/cpfs.txt"
  python3 "$SCRIPT_DIR/sensitive_audit.py" --out "$OUT" || return 1
  local n; n=$(($(wc -l < "$f/dados_sensiveis_mascarados.tsv")-1))
  if [[ "$n" -gt 0 ]]; then
    register_finding "INFORMATIVO" "Identificadores" "$n exposição(ões) candidata(s); valores completos, revisar contexto" "$f/dados_sensiveis_mascarados.tsv"
  else
    info "Identificadores: nenhum encontrado nas URLs coletadas"
  fi
  return 0
}

# ═════════════════════════ FASE 28 · VALIDAÇÃO LOGINS ══════════════════════
phase_19(){
  hdr "FASE 28 · Orientação para validar contas"
  local f="$OUT/19_validacao"; mkdir -p "$f"
  printf 'Identificadores não comprovam existência de contas. Consulte o inventário de valores completos e os testes de login configurados na interface.\n' > "$f/validados.txt"
  info "Validação de contas: não inferida a partir de e-mails coletados"
  return 0
}

# ═════════════════════════════ FASE 29 · BRUTE ══════════════════════════════
phase_20(){
  hdr "FASE 29 · Teste de senhas (manual no Cyberpm)"
  local f="$OUT/20_brute"; mkdir -p "$f"
  info "Teste de senhas: não executado pela varredura. Configure a conta e a requisição na seção Teste de senhas do Cyberpm e inicie pelo botão próprio."
  return 0
}

# ══════════════════════════ FASE 10 · SUBDOMAIN TAKEOVER ════════════════════
phase_21(){
  hdr "FASE 10 · Subdomínio takeover"
  local f="$OUT/21_takeover"; mkdir -p "$f"
  : > "$f/cnames.txt"
  [[ -s "$OUT/01_recon/subs.txt" ]] || { info "Takeover: sem subdomínios para consultar"; return 3; }
  have dig || { warn "Takeover: dig ausente"; return 3; }
  local s cname failures=0
  while IFS= read -r s; do
    if cname=$(timeout 10 dig +short CNAME "$s" 2>>"$f/dig.stderr"); then
      [[ -z "$cname" ]] || printf '%s → %s\n' "$s" "$cname" >> "$f/cnames.txt"
    else
      failures=$((failures+1)); warn "CNAME: consulta falhou para $s"
    fi
  done < "$OUT/01_recon/subs.txt"
  info "CNAMEs: $(wc -l < "$f/cnames.txt"); ausência de CNAME não é falha de execução nem teste de takeover confirmado"
  ((failures == 0))
}

# ══════════════════════════════ FASE 22 · CORS ══════════════════════════════
phase_22(){
  hdr "FASE 22 · CORS mal configurado"
  local f="$OUT/22_cors"; mkdir -p "$f"
  local rc=0
  curl -sk -H 'Origin: https://evil.com' -D "$f/headers.txt" -o /dev/null -m 10 "$BASE" 2>"$f/curl.stderr" || rc=$?
  if (( rc != 0 )); then
    warn "CORS: consulta falhou ($rc); detalhes: $f/curl.stderr"
    return "$rc"
  fi
  grep -i '^access-control-allow-origin:' "$f/headers.txt" > "$f/cors.txt" || true
  if grep -qi '\*' "$f/cors.txt"; then
    info "CORS: origem curinga encontrada; validar se o recurso contém dados sensíveis: $f/cors.txt"
  else
    info "CORS: nenhuma origem curinga encontrada; resultado não comprova ausência de falhas"
  fi
  return 0
}

# ═════════════════════════════ FASE 23 · OPEN REDIRECT ══════════════════════
phase_23(){
  hdr "FASE 23 · Candidatos a redirecionamento"
  local f="$OUT/23_redirect"; mkdir -p "$f"
  : > "$f/candidatos.txt"
  if [[ ! -r "$OUT/04_crawl/urls.txt" ]]; then
    info "Redirecionamento: inventário de URLs indisponível; execute a fase 4. Avaliação inconclusiva"
    return 0
  fi
  grep -iE '[?&](url|redirect|next|return|dest)=' "$OUT/04_crawl/urls.txt" 2>/dev/null | sort -u | head -n 20 > "$f/candidatos.txt" || true
  info "Redirecionamento: $(wc -l < "$f/candidatos.txt") candidatos por nome de parâmetro (limite 20), no inventário da fase 4"
  info "Redirecionamento: não altera parâmetros nem segue destinos; nenhuma exploração confirmada. Evidência: $f/candidatos.txt"
  return 0
}

# ═════════════════════════════ FASE 13 · MÉTODOS ════════════════════════════
phase_24(){
  hdr "FASE 13 · Métodos HTTP"
  local f="$OUT/24_metodos"; mkdir -p "$f"
  local code rc=0 line
  : > "$f/metodos.txt"
  info "Métodos: OPTIONS na URL base $BASE"
  code=$(curl -sk -X OPTIONS -D "$f/resposta.headers" -o /dev/null -w '%{http_code}' -m 10 "${HDRS[@]}" "$BASE" 2>"$f/curl.stderr") || rc=$?
  if ((rc != 0)) || [[ "$code" == 000 || -z "$code" ]]; then
    warn "Métodos: consulta falhou (curl $rc, HTTP ${code:-indisponível}); avaliação inconclusiva. Detalhes: $f/curl.stderr"
    return 1
  fi
  grep -iE '^(allow|access-control-allow-methods):' "$f/resposta.headers" > "$f/metodos.txt" || true
  info "Métodos: HTTP $code"
  if [[ -s "$f/metodos.txt" ]]; then
    while IFS= read -r line; do info "Métodos declarados: ${line//$'\r'/}"; done < "$f/metodos.txt"
  else
    info "Métodos: servidor não declarou Allow/Access-Control-Allow-Methods nesta resposta; resultado inconclusivo"
  fi
  info "Métodos: declaração não comprova execução nem vulnerabilidade; PUT/DELETE não foram executados. Evidência: $f/metodos.txt"
  return 0
}

# ══════════════════════════════ FASE 24 · SSRF ══════════════════════════════
phase_25(){
  hdr "FASE 24 · SSRF (heurística)"
  local f="$OUT/25_ssrf"; mkdir -p "$f"
  : > "$f/candidatos.txt"
  if [[ ! -r "$OUT/04_crawl/urls.txt" ]]; then
    info "SSRF: inventário de URLs indisponível; execute a fase 4. Avaliação inconclusiva"
    return 0
  fi
  grep -iE '[?&](url|uri|src|path|dest|target|feed|host)=' "$OUT/04_crawl/urls.txt" 2>/dev/null | sort -u > "$f/candidatos.txt" || true
  info "SSRF: $(wc -l < "$f/candidatos.txt") candidatos por nome de parâmetro, no inventário da fase 4"
  info "SSRF: heurística local; não comprova requisição pelo servidor nem acessa endereços internos. Evidência: $f/candidatos.txt"
  return 0
}

# ═══════════════════════════ FASE 14 · HEADERS/TLS ══════════════════════════
phase_26(){
  hdr "FASE 14 · Cabeçalhos e TLS"
  local f="$OUT/26_headers"; mkdir -p "$f"
  local code rc=0 tls_tool=''
  code=$(curl -sk -D "$f/headers.txt" -o /dev/null -w '%{http_code}' -m 10 "${HDRS[@]}" "$BASE" 2>"$f/curl.stderr") || rc=$?
  if ((rc != 0)) || [[ "$code" == 000 ]]; then
    warn "Cabeçalhos: consulta falhou ($rc); não avaliar cabeçalhos ausentes"
    return 1
  fi
  if [[ "$code" == 2?? ]]; then
  if [[ "$SCHEME" == https ]]; then
    grep -qi '^strict-transport-security:' "$f/headers.txt" || register_finding "BAIXO" "Cabeçalhos" "HSTS ausente na resposta HTTP $code" "$f/headers.txt"
  fi
  grep -qi '^x-frame-options:' "$f/headers.txt" || grep -qiE '^content-security-policy:.*frame-ancestors' "$f/headers.txt" || register_finding "BAIXO" "Cabeçalhos" "X-Frame-Options/frame-ancestors ausente na resposta HTTP $code" "$f/headers.txt"
  else
    warn "Cabeçalhos: HTTP $code; resposta não aproveitada para achados de cabeçalhos ausentes. Revisar resposta da aplicação."
  fi
  have testssl.sh && tls_tool=testssl.sh
  [[ -n "$tls_tool" ]] || { have testssl && tls_tool=testssl; }
  if [[ -n "$tls_tool" && "$SCHEME" == https && "$MODE" != rapido ]]; then
    rm -f "$f/testssl.json"
    bounded_tool 120 "$f/testssl" "$tls_tool" --quiet --warnings batch --protocols --server-defaults --jsonfile "$f/testssl.json" "$BASE" || true
    info "TLS: protocolos e configuração coletados; consultar testssl.json e testssl.stdout"
  else
    info "TLS: testssl.sh opcional, executado em HTTPS no modo completo/profundo"
  fi
  return 0
}

# ═══════════════════════════ FASE 25 · INJEÇÃO ══════════════════════════════
phase_27(){
  hdr "FASE 25 · Indícios de template (sem teste LFI)"
  local f="$OUT/27_injecao"; mkdir -p "$f"
  local code rc=0
  : > "$f/ssti.txt"
  info "Injeção: GET na URL base $BASE e busca de delimitadores de template no HTML"
  code=$(curl -sk -m 12 --max-filesize 2000000 -o "$f/home.html" -w '%{http_code}' "${HDRS[@]}" "$BASE" 2>"$f/curl.stderr") || rc=$?
  if ((rc != 0)) || [[ "$code" != 200 ]]; then
    warn "Injeção: coleta não aproveitada (curl $rc, HTTP ${code:-indisponível}); avaliação inconclusiva. Detalhes: $f/curl.stderr"
    return 1
  fi
  grep -oE '\{\{.*\}\}|\$\{.*\}' "$f/home.html" 2>/dev/null | head -n 10 > "$f/ssti.txt" || true
  info "Injeção: HTTP $code · $(wc -l < "$f/ssti.txt") ocorrências de delimitadores (limite 10), que podem pertencer a templates do navegador"
  info "Injeção: não executa expressões nem testa inclusão de arquivos (LFI); SSTI/LFI não confirmadas. Evidência: $f/ssti.txt"
  return 0
}

# ═══════════════════════════ FASE 26 · HOSTHDR/CRLF ═════════════════════════
phase_28(){
  hdr "FASE 26 · Resposta a Host alterado (sem CRLF)"
  local f="$OUT/28_hosthdr"; mkdir -p "$f"
  local code rc=0
  info "Host header: GET na URL base com Host: audit.invalid, sem seguir redirecionamentos"
  code=$(curl -sk -H 'Host: audit.invalid' -D "$f/hosthdr.txt" -o /dev/null -w '%{http_code}' -m 10 "$BASE" 2>"$f/curl.stderr") || rc=$?
  if ((rc != 0)) || [[ "$code" == 000 || -z "$code" ]]; then
    warn "Host header: consulta falhou (curl $rc, HTTP ${code:-indisponível}); avaliação inconclusiva. Detalhes: $f/curl.stderr"
    return 1
  fi
  info "Host header: HTTP $code"
  if grep -qiE '^location:.*audit\.invalid' "$f/hosthdr.txt"; then
    info "Host header: marcador observado em Location; candidato a revisão, impacto não confirmado"
  else
    info "Host header: marcador não observado em Location; isso não exclui outras formas de uso indevido do cabeçalho"
  fi
  info "Host header: não compara com resposta de controle; bypass não confirmado. CRLF não foi testado. Evidência: $f/hosthdr.txt"
  return 0
}

# ══════════════════════════ FASE 6 · JS & SEGREDOS ═════════════════════════
phase_29(){
  hdr "FASE 6 · JavaScript: endpoints, chaves e segredos"
  local f="$OUT/29_js" p; mkdir -p "$f/arquivos"
  : > "$f/lista.txt"
  { grep -Ei '\.js(\?|$)' "$OUT/04_crawl/urls.txt" 2>/dev/null; \
    cat "$OUT/08_codigo/js.txt" 2>/dev/null; } | sort -u | head -n "$JS_MAX" > "$f/lista.txt"
  if [[ ! -s "$f/lista.txt" ]]; then
    info "JS: nenhum script descoberto; quatro caminhos convencionais serão tentados como candidatos, sem existência confirmada."
    for p in static/js/main.js app.js main.js bundle.js; do echo "$ROOT/$p" >> "$f/lista.txt"; done
  fi
  sort -u "$f/lista.txt" -o "$f/lista.txt"
  python3 "$AUDIT_HELPER" urls --base "$BASE" "$f/lista.txt" > "$f/lista_normalizada.txt" || return 1
  mv "$f/lista_normalizada.txt" "$f/lista.txt"
  # Não reaproveitar arquivos JS antigos em uma nova execução.
  find "$f/arquivos" -maxdepth 1 -type f -name '*.js' -delete
  printf 'Endpoint\tArquivo\n' > "$f/endpoints.tsv"
  printf 'Tipo\tValor\tArquivo\n' > "$f/segredos.tsv"
  local js_rc=0
  local u name body
  local helper="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/js_downloader.py"
  if [[ -f "$helper" ]] && command -v python3 >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=3s 95s python3 -u "$helper" --base "$BASE" --list "$f/lista.txt" --out "$f/arquivos" --manifest "$f/manifest.tsv" --workers 5 --timeout 8 || { js_rc=$?; warn "Download JS interrompido ou parcial; consultar download_erros.tsv e manifest.tsv"; }
  else
    warn "js_downloader.py ausente: usando download sequencial"
    : > "$f/manifest.tsv"
    local fallback_count=0
    while IFS= read -r u; do
      ((fallback_count++)) || true
      ((fallback_count>12)) && { warn "Fallback JS limitado a 12 URLs"; break; }
      [[ -z "$u" ]] && continue
      [[ "$u" == http* ]] || u="$ROOT/${u#/}"
      name="$(printf '%s' "$u" | md5sum | cut -c1-10).js"
      curl -fsSk --connect-timeout 3 --max-time 8 --max-filesize 2000000 "$u" -o "$f/arquivos/$name" 2>/dev/null || continue
      printf '%s\t%s\n' "$u" "$name" >> "$f/manifest.tsv"
    done < "$f/lista.txt"
  fi
  python3 "$SCRIPT_DIR/endpoint_inventory.py" --base "$BASE" --out "$OUT" --js || return 1
  python3 "$SCRIPT_DIR/sensitive_audit.py" --out "$OUT" --js-only || return 1
  local ns ne
  ns=$(tail -n +2 "$f/segredos.tsv" 2>/dev/null | wc -l)
  ne=$(tail -n +2 "$f/endpoints.tsv" 2>/dev/null | wc -l)
  info "JS baixados: $(ls -1 "$f/arquivos" 2>/dev/null | wc -l) · endpoints: $ne"
  if have retire && [[ "$MODE" != rapido ]] && [[ -s "$f/manifest.tsv" ]]; then
    rm -f "$f/retire.json"
    bounded_tool 60 "$f/retire" retire --path "$f/arquivos" --outputformat json --outputpath "$f/retire.json" --exitwith 0 || true
    info "Retire.js: análise local das bibliotecas; revisar retire.json (a base de vulnerabilidades pode exigir internet)"
  else
    info "Retire.js: opcional; requer arquivos JS baixados e modo completo/profundo"
  fi
  [[ "$ns" -gt 0 ]] && register_finding "INFORMATIVO" "Possíveis segredos (não confirmados)" "$ns padrão(ões) candidato(s) em JS; revisar falsos positivos" "$f/segredos.tsv"
  if grep -qiE 'siteassets\.parastorage\.com|static\.parastorage\.com' "$f/endpoints.tsv"; then
    info "Recurso público Wix/Thunderbolt detectado: classificado como tecnologia, não vulnerabilidade"
    grep -iE 'siteassets\.parastorage\.com|static\.parastorage\.com' "$f/endpoints.tsv" > "$f/wix_recursos_publicos.tsv" || true
  fi
  [[ "$ne" -gt 0 ]] && register_finding "INFORMATIVO" "Inventário de endpoints JS" "$ne URL(s)/endpoint(s) identificados; não indica vulnerabilidade" "$f/endpoints.tsv"
  if [[ ! -s "$f/manifest.tsv" ]]; then
    warn "Coleta JS inconclusiva: nenhum arquivo baixado; não comprova ausência de endpoints ou segredos."
    return 1
  fi
  ((js_rc == 0)) || return 1
  return 0
}

# ══════════════════════════════ ORQUESTRAÇÃO ════════════════════════════════
SELECTED=()
choose_phases(){
  case "$MODE" in
    rapido) SELECTED=(1 2 3 4 5 6 7 8 9 15);;
    *) SELECTED=($(seq 1 29)); [[ "$ZAP_SCAN" == 0 ]] && SELECTED=($(printf '%s\n' "${SELECTED[@]}" | grep -v '^21$'));;
  esac
  if [[ -n "$PHASE_LIST" ]]; then
    SELECTED=()
    for phase in $(seq 1 29); do [[ " $PHASE_LIST " == *" $phase "* ]] && SELECTED+=("$phase"); done
  fi
  # Review authorization after discovery, once, rather than asking to go back.
  local ordered=() phase final_auth=0
  for phase in "${SELECTED[@]}"; do
    case "$phase" in 20) final_auth=1; continue;; 27|28) final_auth=1;; esac
    ordered+=("$phase")
  done
  if ((final_auth)); then ordered+=(20); fi
  SELECTED=("${ordered[@]}")
}

install_missing_tools(){
  local f="$OUT/00_dependencias"; mkdir -p "$f"
  : > "$f/status.tsv"
  local pairs=("curl:curl" "whois:whois" "dig:dnsutils" "nmap:nmap" "whatweb:whatweb" "wafw00f:wafw00f" "ffuf:ffuf" "sqlmap:sqlmap" "nuclei:nuclei" "subfinder:subfinder" "assetfinder:assetfinder" "jq:jq" "arjun:arjun" "testssl:testssl.sh" "katana:katana" "dalfox:dalfox" "gau:gau" "waybackurls:waybackurls" "npm:npm")
  local pair tool pkg
  ((WORDPRESS==0)) || pairs+=("wpscan:wpscan")
  local sudo_cmd=() privilege=1 updated=0
  if ((EUID!=0)); then
    if have sudo && sudo -n true 2>/dev/null; then
      sudo_cmd=(sudo -n)
    elif have pkexec && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
      sudo_cmd=(pkexec)
    else
      privilege=0
    fi
  fi
  for pair in "${pairs[@]}"; do
    tool="${pair%%:*}"; pkg="${pair#*:}"
    [[ "$tool" != npm ]] || ! have retire || continue
    if have "$tool"; then printf '%s\tINSTALADO\n' "$tool" >> "$f/status.tsv"; continue; fi
    if ((DO_INSTALL==0)); then warn "$tool ausente (instalação desativada)"; printf '%s\tAUSENTE\n' "$tool" >> "$f/status.tsv"; continue; fi
    if ! have apt-get || ((privilege==0)); then
      warn "$tool ausente: apt/privilégio indisponível; no Kali execute sudo -v antes de abrir a interface"
      printf '%s\tSEM_PRIVILEGIO_OU_APT\n' "$tool" >> "$f/status.tsv"
      continue
    fi
    if ((updated==0)); then
      info "Atualizando índice de pacotes (limite 120s); o Kali pode solicitar autenticação do sistema"
      timeout -k 3s 120 "${sudo_cmd[@]}" apt-get update >> "$f/instalacao.log" 2>&1 || warn "Índice apt não atualizado; usando dados disponíveis"
      updated=1
    fi
    info "Instalando $tool (pacote $pkg), limite de 90 segundos..."
    if timeout -k 3s 90 "${sudo_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >> "$f/instalacao.log" 2>&1 && have "$tool"; then
      ok "$tool instalado"; printf '%s\tINSTALADO\n' "$tool" >> "$f/status.tsv"
    else
      local module=''
      case "$tool" in
        gau) module='github.com/lc/gau/v2/cmd/gau@latest';;
        katana) module='github.com/projectdiscovery/katana/cmd/katana@latest';;
        nuclei) module='github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest';;
        subfinder) module='github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest';;
        dalfox) module='github.com/hahwul/dalfox/v2@latest';;
        waybackurls) module='github.com/tomnomnom/waybackurls@latest';;
      esac
      if [[ -n "$module" ]]; then
        have go || timeout -k 3s 120 "${sudo_cmd[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y golang >> "$f/instalacao.log" 2>&1 || true
        if have go; then
          info "$tool: tentando instalação oficial via Go em ~/.local/bin (limite 120s)"
          mkdir -p "$HOME/.local/bin"
          timeout -k 3s 120 env GOBIN="$HOME/.local/bin" go install "$module" >> "$f/instalacao.log" 2>&1 || true
        fi
      fi
      if have "$tool"; then
        printf '%s\tINSTALADO\n' "$tool" >> "$f/status.tsv"
      else
        warn "Não foi possível instalar $tool; veja $f/instalacao.log"
        printf '%s\tFALHOU\n' "$tool" >> "$f/status.tsv"
      fi
    fi
  done
  if ! have retire && ((DO_INSTALL==1)) && have npm; then
    info "Instalando Retire.js em ~/.local (limite 90s)"
    timeout -k 3s 90 npm install --global --prefix "$HOME/.local" retire >> "$f/instalacao.log" 2>&1 || warn "Retire.js: instalação falhou; consultar instalacao.log"
  fi
  if have retire; then printf 'retire\tINSTALADO\n' >> "$f/status.tsv"; else printf 'retire\tAUSENTE\n' >> "$f/status.tsv"; fi
}

connection_preflight(){
  local f="${1:-$OUT/00_conexao}" rc=0 health_rc=0
  mkdir -p "$f"
  info "Verificando disponibilidade HTTP/TLS (maximo 25s)..."
  bounded_tool 28 "$f/curl" curl -sSk --max-filesize 2000000 --connect-timeout 15 --max-time 25 "${HDRS[@]}" -o /dev/null -w $'%{http_code}\n%{remote_ip}\n%{time_namelookup}\n%{time_connect}\n%{time_appconnect}\n%{time_starttransfer}\n' "$BASE" || rc=$?
  python3 "$SCRIPT_DIR/connection_health.py" --base "$BASE" --metrics "$f/curl.stdout" --exit-code "$rc" --out "$f/estado.json" || health_rc=$?
  if ((health_rc != 0)); then
    warn "Sem resposta HTTP: fases web serão marcadas como não executadas. Reconhecimento e portas continuam independentes."
    replay_hint curl -vI --connect-timeout 30 --max-time 60 "$BASE"
  fi
  return "$health_rc"
}

terminate_phase_group(){
  local phase_pid="$1"
  kill -TERM -- "-$phase_pid" 2>/dev/null || true
  sleep 0.2
  kill -KILL -- "-$phase_pid" 2>/dev/null || true
  wait "$phase_pid" 2>/dev/null || true
}

scan_timeout(){
  # Decimal seconds; zero lets the tool finish or be skipped by the user.
  if [[ ! "$1" =~ ^[0-9]{1,7}$ ]]; then
    printf 'Limite inválido: use segundos inteiros de 0 a 9999999.\n' >&2
    return 1
  fi
  printf '%s\n' "$((10#$1))"
}

run_phase_controlled(){
  local phase_id="$1" phase_pid rc=0 monitor_was_on=0
  local phase_started=$SECONDS phase_budget=240
  case "$MODE" in rapido) phase_budget=120;; profundo) phase_budget=360;; esac
  case "$phase_id" in
    2) phase_budget=$(scan_timeout "$NMAP_TIMEOUT") || return 1;;
    15) phase_budget=$(scan_timeout "$NUCLEI_TIMEOUT") || return 1;;
    16) phase_budget=45;;
  esac
  # Allow the tool timeout to flush diagnostics before the phase watchdog fires.
  if [[ "$phase_id" == 2 || "$phase_id" == 15 ]] && ((phase_budget > 0)); then
    phase_budget=$((phase_budget+15))
  fi
  local progress_at=$SECONDS
  local request="$OUT/controle/pular_$phase_id"
  [[ ! -f "$request" ]] || return 3
  [[ $- != *m* ]] || monitor_was_on=1
  # Give this phase its own group, so skipping cannot terminate the orchestrator.
  set -m
  (set +m; "phase_${LEGACY_BY_NEW[$phase_id]}") &
  phase_pid=$!
  ((monitor_was_on)) || set +m
  trap 'terminate_phase_group "$phase_pid"; exit 143' TERM
  trap 'terminate_phase_group "$phase_pid"; exit 130' INT
  while kill -0 "$phase_pid" 2>/dev/null; do
    if [[ -f "$request" ]]; then
      terminate_phase_group "$phase_pid"
      trap - TERM INT
      return 3
    fi
    if ((phase_budget > 0 && SECONDS-phase_started >= phase_budget)); then
      terminate_phase_group "$phase_pid"
      printf 'Limite total de %ss atingido na fase %s; resultados parciais preservados.\n' "$phase_budget" "$phase_id" > "$OUT/controle/limite_$phase_id.txt"
      warn "$(cat "$OUT/controle/limite_$phase_id.txt")"
      trap - TERM INT
      return 124
    fi
    if [[ "$phase_id" == 2 || "$phase_id" == 15 ]] && ((SECONDS-progress_at >= 30)); then
      info "Fase $phase_id em execução há $((SECONDS-phase_started))s; aguardando a ferramenta."
      progress_at=$SECONDS
    fi
    sleep 0.2
  done
  wait "$phase_pid" || rc=$?
  trap - TERM INT
  return "$rc"
}

run_target(){
  have python3 && have timeout && [[ -f "$AUDIT_HELPER" ]] || { erro "Requisitos: python3, timeout e audit_helpers.py na pasta do projeto"; return 1; }
  BASE="$TARGET"; [[ "$BASE" == http* ]] || BASE="https://$BASE"
  HOST=$(python3 "$AUDIT_HELPER" target "$BASE") || { erro "Alvo inválido"; return 1; }
  ROOT=$(python3 "$AUDIT_HELPER" origin "$BASE") || return 1
  SCHEME="${BASE%%://*}"
  CUR_ASSET="$HOST"
  OUT="$OUTROOT/${HOST}_$(date -u +%Y%m%dT%H%M%SZ)_$$"
  mkdir -p "$OUT/controle"
  FIND_FILE="$OUT/achados.tsv"; : > "$FIND_FILE"
  TREE_FILE="$OUT/arvore.txt"; : > "$TREE_FILE"
  printf 'Ferramenta\tCodigo\tEvidencia\n' > "$OUT/ferramentas.tsv"
  printf 'Fase\tCodigo\tDuracao_segundos\tEstado\n' > "$OUT/fases_status.tsv"
  HDRS=(-A "Mozilla/5.0 (PentestOrchestrator/$VERSION)")
  case "$AUTH_MODE" in
    bearer) HDRS+=(-H "Authorization: Bearer $AUTH_SECRET");;
    cookie) HDRS+=(-H "Cookie: $AUTH_SECRET");;
    basic)  HDRS+=(-u "$AUTH_USER:$AUTH_PASS");;
  esac
  choose_phases

  printf "EVENT|OUTPUT|%s\n" "$OUT"
  install_missing_tools
  have curl || { erro "curl indisponível após verificar dependências; varredura não iniciada"; return 1; }

  printf "EVENT|TOTAL|%s\n" "${#SELECTED[@]}"
  hdr "INÍCIO · alvo=$HOST · modo=$MODE · fases=${SELECTED[*]}"
  if [[ -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT" ]]; then
    env TELEGRAM_TOKEN="$TELEGRAM_TOKEN" TELEGRAM_CHAT="$TELEGRAM_CHAT" python3 "$SCRIPT_DIR/startup_art.py" --telegram-start --target "$HOST" --mode "$MODE" || warn "Telegram: falha ao preparar a mensagem de início"
  fi

  info "Ordem planejada: ${SELECTED[*]} (fase 20, quando incluída, executa por último)"
  local web_ready=0
  connection_preflight || web_ready=$?
  local queue=() p q failed_phases=0 skipped_phases=0
  RUNS=()
  for p in "${SELECTED[@]}"; do queue+=("$p"); done
  while ((${#queue[@]})); do
    p="${queue[0]}"; queue=("${queue[@]:1}")
    (( ${RUNS[$p]:-0} >= MAXRERUN )) && { info "fase $p já executada ${RUNS[$p]}x (limite)"; continue; }
    RUNS[$p]=$(( ${RUNS[$p]:-0}+1 ))
    local phase_id="$p"
    printf "EVENT|START|%s\n" "$phase_id"
    local phase_rc=0 phase_start=$SECONDS phase_state=processada
    if [[ -f "$OUT/controle/pular_$phase_id" ]]; then
      phase_rc=3
    elif ((web_ready != 0)) && [[ " 3 4 5 6 7 8 9 11 12 13 14 15 17 18 19 20 21 22 23 24 25 26 27 " == *" $phase_id "* ]]; then
      phase_rc=3
      phase_state=nao_executada_sem_conexao
      warn "Fase $phase_id nao executada: a ultima verificacao nao recebeu resposta HTTP. Consulte 00_conexao. Nao significa ausencia de falhas."
    else
      run_phase_controlled "$phase_id" || phase_rc=$?
    fi
    if [[ -f "$OUT/controle/pular_$phase_id" ]]; then
      phase_rc=3
      phase_state=pulada_pelo_usuario
      warn "Fase $phase_id pulada pelo usuario; resultados parciais preservados."
      printf 'EVENT|SKIPPED|%s\n' "$phase_id"
    fi
    if ((web_ready == 0 && phase_rc != 0 && phase_rc != 3)) && [[ " 3 4 5 6 7 8 9 11 12 13 14 15 17 18 19 20 21 22 23 24 25 26 27 " == *" $phase_id "* ]]; then
      info "Fase $phase_id parcial: verificando se a conexao permanece disponivel antes de continuar."
      connection_preflight "$OUT/00_conexao/rechecagem_fase_$phase_id" || web_ready=$?
      if ((web_ready != 0)); then
        warn "Fases web seguintes suspensas nesta execucao para evitar novas tentativas sem resposta. Evidencias anteriores preservadas. A causa pode ser rede, servidor ou restricao de acesso; bloqueio de IP nao confirmado."
      fi
    fi
    if ((phase_rc == 3)); then
      skipped_phases=$((skipped_phases+1))
      [[ "$phase_state" != processada ]] || phase_state=nao_executada
    elif ((phase_rc != 0)); then
      phase_state=erro_ou_parcial
    fi
    printf '%s\t%s\t%s\t%s\n' "$phase_id" "$phase_rc" "$((SECONDS-phase_start))" "$phase_state" >> "$OUT/fases_status.tsv"
    if ((phase_rc != 0 && phase_rc != 3)); then
      failed_phases=$((failed_phases+1))
      warn "fase $phase_id retornou erro ($phase_rc); consultar evidências"
      local -a phase_replay=(bash "$SCRIPT_DIR/cyberpm.sh" "$BASE" --mode "$MODE" --phases "$phase_id" --no-install --out "$OUTROOT")
      case "$AUTH_MODE" in
        basic) phase_replay+=(--auth basic --user "$AUTH_USER" --pass "$AUTH_PASS");;
        bearer|cookie) phase_replay+=(--auth "$AUTH_MODE" --secret "$AUTH_SECRET");;
      esac
      replay_hint "${phase_replay[@]}"
    fi
    printf 'EVENT|STATUS|%s|%s\n' "$phase_id" "$phase_rc"
    printf "EVENT|END|%s\n" "$phase_id"
    # Cada fase selecionada executa apenas uma vez; sem reinserção automática.

  done

  tree_rebuild
  local final_code=0
  ((failed_phases == 0 && skipped_phases == 0)) || final_code=1
  printf 'EVENT|FINISH|%s\n' "$final_code"
  hdr "FIM · achados: $(wc -l <"$FIND_FILE" 2>/dev/null || echo 0) · árvore: $TREE_FILE"
  info "Fases não executadas: $skipped_phases. Fases com erro/resultado parcial: $failed_phases; fases sem erro podem conter apenas inventário ou testes não executados (consulte o log)"
  tg "Fim em *$HOST*. Achados: $(wc -l <"$FIND_FILE" 2>/dev/null || echo 0). Fases com erro/parcial: $failed_phases"
  return "$final_code"
}

# ── args ─────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    -o|--out) OUTROOT="$2"; shift 2;;
    -m|--mode) MODE="$2"; shift 2;;
    --js-max) JS_MAX="$2"; shift 2;;
    --threads) THREADS="$2"; shift 2;;
    --no-install) DO_INSTALL=0; shift;;
    --wordpress) WORDPRESS=1; shift;;
    -q|--quiet) VERBOSE=0; shift;;
    --auth) AUTH_MODE="$2"; shift 2;;
    --user) AUTH_USER="$2"; shift 2;;
    --pass) AUTH_PASS="$2"; shift 2;;
    --secret) AUTH_SECRET="$2"; shift 2;;
    --login-url) LOGIN_URL="$2"; shift 2;;
    --wordlist) BRUTE_WORDLIST="$2"; shift 2;;
    --telegram) TELEGRAM_TOKEN="$2"; shift 2;;
    --chat) TELEGRAM_CHAT="$2"; shift 2;;
    --phases) PHASE_LIST="$2"; shift 2;;
    --) shift; break;;
    --*) shift;;
    *) [[ -z "$TARGET" ]] && TARGET="$1"; shift;;
  esac
done

[[ -z "$TARGET" ]] && { usage; exit 1; }
run_target
