#!/usr/bin/env python3
"""Cyberpm Precision Pack - inventario e instalacao de ferramentas.

`status` mostra o que existe; `install` instala o que falta respeitando o que ja
esta presente. Somente stdlib.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

# nome -> (como instalar, pacote, para que serve, substitui)
TOOLS = {
    # ProjectDiscovery (go)
    'subfinder':   ('go', 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest', 'descoberta de subdominios', 'assetfinder/crt.sh'),
    'dnsx':        ('go', 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest', 'resolucao DNS paralela', 'dig em loop'),
    'httpx':       ('go', 'github.com/projectdiscovery/httpx/cmd/httpx@latest', 'sondagem HTTP + tech + jarm', 'curl em loop / whatweb'),
    'naabu':       ('go', 'github.com/projectdiscovery/naabu/v2/cmd/naabu@latest', 'port scan rapido', 'nmap nas 1000 portas'),
    'katana':      ('go', 'github.com/projectdiscovery/katana/cmd/katana@latest', 'crawler com JS', 'katana antigo'),
    'nuclei':      ('go', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest', 'motor de templates', 'grep'),
    'interactsh':  ('go', 'github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest', 'OOB (blind)', '-'),
    'cdncheck':    ('go', 'github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest', 'detecao de CDN/WAF', '-'),
    'asnmap':      ('go', 'github.com/projectdiscovery/asnmap/cmd/asnmap@latest', 'ASN/CIDR', 'whois manual'),
    'dalfox':      ('go', 'github.com/hahwul/dalfox/v2@latest', 'XSS', 'dalfox antigo'),
    'ffuf':        ('go', 'github.com/ffuf/ffuf/v2@latest', 'fuzzing', 'ffuf antigo'),
    'qsreplace':   ('go', 'github.com/tomnomnom/qsreplace@latest', 'injecao em todos os parametros', '-'),
    'uro':         ('pipx', 'uro', 'dedupe de URLs', '-'),
    'gospider':    ('go', 'github.com/jaeles-project/gospider@latest', 'crawler', '-'),
    'crlfuzz':     ('go', 'github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest', 'CRLF injection', 'grep'),
    'openredirex': ('go', 'github.com/devanshbatham/openredirex@latest', 'open redirect', 'grep'),
    'jsluice':     ('go', 'github.com/BishopFox/jsluice/cmd/jsluice@latest', 'endpoints/segredos em JS', 'regex'),
    'trufflehog':  ('go', 'github.com/trufflesecurity/trufflehog/v3@latest', 'segredos com entropia', 'regex'),
    'smuggler':    ('pipx', 'smuggler', 'request smuggling', '-'),
    # Python
    'ghauri':      ('pipx', 'ghauri', 'SQLi rapido', 'sqlmap (complementa)'),
    'corsy':       ('pipx', 'corsy', 'CORS', 'curl manual'),
    'SSTImap':     ('pipx', 'sstimap', 'SSTI', 'curl+grep'),
    'git-dumper':  ('pipx', 'git-dumper', 'dump de .git', 'curl loop'),
    'graphw00f':   ('pipx', 'graphw00f', 'fingerprint GraphQL', '-'),
    'arjun':       ('pipx', 'arjun', 'descoberta de parametros', 'arjun antigo'),
    'x8':          ('cargo', 'x8', 'descoberta de parametros', '-'),
    'sslyze':      ('pipx', 'sslyze', 'TLS preciso com JSON', 'testssl parcial'),
    # apt
    'nmap':        ('apt', 'nmap', 'portas e scripts', 'nmap'),
    'sqlmap':      ('apt', 'sqlmap', 'SQLi profundo', 'sqlmap'),
    'feroxbuster': ('apt', 'feroxbuster', 'content discovery recursivo', 'ffuf em loop'),
    'nikto':       ('apt', 'nikto', 'checagens web classicas', 'zap-cli'),
    'whatweb':     ('apt', 'whatweb', 'fingerprint', 'whatweb'),
    'wafw00f':     ('apt', 'wafw00f', 'detecao de WAF', 'wafw00f'),
    'testssl.sh':  ('apt', 'testssl.sh', 'TLS profundo', 'testssl.sh'),
    'searchsploit':('apt', 'exploitdb', 'CVEs -> exploits', 'grep'),
    'jq':          ('apt', 'jq', 'parsing JSON', '-'),
}


def have(name):
    return shutil.which(name) is not None


def install(name, spec, dry=False):
    kind, package = spec[0], spec[1]
    if kind == 'go':
        cmd = ['go', 'install', package]
    elif kind == 'pipx':
        cmd = ['pipx', 'install', package]
    elif kind == 'cargo':
        cmd = ['cargo', 'install', package]
    else:
        cmd = ['sudo', 'apt-get', 'install', '-y', package]
    if dry:
        return cmd
    try:
        subprocess.run(cmd, check=True, timeout=600,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        print(f'[!] falha ao instalar {name}: {str(exc)[:160]}', flush=True)
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('status', 'install', 'json', 'commands'))
    parser.add_argument('--only', default='')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    alvos = {n: s for n, s in TOOLS.items() if not args.only or n in args.only.split(',')}

    if args.action in ('status', 'json'):
        estado = {n: {'presente': have(n), 'instala': s[0], 'pacote': s[1],
                      'para': s[2], 'substitui': s[3]} for n, s in alvos.items()}
        if args.action == 'json':
            print(json.dumps(estado, ensure_ascii=False, indent=2))
        else:
            for nome, info in estado.items():
                print(('[ok] ' if info['presente'] else '[--] ') + f'{nome:<14} {info["para"]}')
            faltam = [n for n, i in estado.items() if not i['presente']]
            print(f'\n[·] {len(estado) - len(faltam)}/{len(estado)} presentes; faltam {len(faltam)}')
        return 0

    if args.action == 'commands':
        for nome, spec in alvos.items():
            if not have(nome):
                print(f'{nome}: {" ".join(install(nome, spec, dry=True))}')
        return 0

    for nome, spec in alvos.items():
        if have(nome):
            print(f'[ok] {nome} ja instalado', flush=True)
            continue
        print(f'[..] instalando {nome} ({spec[0]})', flush=True)
        install(nome, spec, dry=args.dry_run)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())