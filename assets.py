#!/usr/bin/env python3
"""Cyberpm Precision Pack - descoberta unificada de ativos.

subfinder -> dnsx -> httpx, com fallback stdlib quando as ferramentas faltam.
Saida: assets.json, urls.txt, tech.tsv. Alimenta todas as fases web.
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, Request, build_opener


def have(name):
    return shutil.which(name) is not None


def run(cmd, timeout=180, stdin=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
        return proc.stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return []


def subdomains(domain):
    if have('subfinder'):
        return sorted({l.strip() for l in run(['subfinder', '-d', domain, '-all', '-silent'], 180) if l.strip()})
    return []


def resolve(hosts):
    if have('dnsx'):
        linhas = run(['dnsx', '-silent', '-a', '-aaaa', '-cname', '-resp', '-json'],
                     120, stdin='\n'.join(hosts))
        dados = {}
        for linha in linhas:
            try:
                item = json.loads(linha)
            except ValueError:
                continue
            nome = item.get('host')
            if nome:
                dados[nome] = {'a': item.get('a', []), 'aaaa': item.get('aaaa', []),
                               'cname': item.get('cname', [])}
        return dados
    dados = {}
    for host in hosts:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            dados[host] = {'a': ips, 'aaaa': [], 'cname': []}
        except (socket.gaierror, OSError):
            continue
    return dados


def probe_stdlib(hosts, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = build_opener(HTTPSHandler(context=ctx))
    saida = []
    for host in hosts:
        for scheme in ('https', 'http'):
            url = f'{scheme}://{host}'
            try:
                resp = opener.open(Request(url, headers={'User-Agent': 'Cyberpm-Recon/1.0'}), timeout=timeout)
                with resp:
                    body = resp.read(65536).decode('utf-8', errors='replace')
                    title = ''
                    if '<title' in body.lower():
                        trecho = body.lower().split('<title', 1)[1].split('>', 1)[-1].split('</title>', 1)[0]
                        title = trecho.strip()[:120]
                    saida.append({'url': resp.geturl(), 'input': host, 'status': resp.code,
                                  'title': title, 'webserver': resp.headers.get('Server', ''),
                                  'tech': [], 'cdn': False, 'jarm': ''})
                break
            except (URLError, TimeoutError, OSError, ValueError):
                continue
    return saida


def probe_httpx(hosts, timeout=240):
    linhas = run(['httpx', '-silent', '-json', '-tech-detect', '-title', '-web-server',
                  '-status-code', '-cdn', '-jarm', '-favicon', '-hash', 'md5',
                  '-follow-redirects', '-ports', '80,443,8080,8443,8000,3000,5000,8888',
                  '-timeout', '6', '-retries', '1'],
                 timeout, stdin='\n'.join(hosts))
    saida = []
    for linha in linhas:
        try:
            item = json.loads(linha)
        except ValueError:
            continue
        saida.append({'url': item.get('url'), 'input': item.get('input'),
                      'status': item.get('status_code'), 'title': item.get('title', ''),
                      'webserver': item.get('webserver', ''), 'tech': item.get('tech', []),
                      'cdn': item.get('cdn', False), 'jarm': item.get('jarm_hash', ''),
                      'hash': item.get('hash', {})})
    return saida


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dominio', '-d', required=True)
    parser.add_argument('--out', default='assets')
    parser.add_argument('--timeout', type=int, default=240)
    args = parser.parse_args()
    dominio = args.dominio.replace('https://', '').replace('http://', '').split('/')[0]
    pasta = Path(args.out)
    pasta.mkdir(parents=True, exist_ok=True)

    subs = subdomains(dominio)
    hosts = sorted(set(subs + [dominio]))
    print(f'[·] subdominios: {len(subs)} (fonte: {"subfinder" if have("subfinder") else "fallback"})', flush=True)
    dns = resolve(hosts)
    vivos = sorted(dns.keys()) or hosts
    print(f'[·] hosts com DNS: {len(dns)}', flush=True)

    if have('httpx'):
        ativos = probe_httpx(vivos, args.timeout)
        motor = 'httpx'
    else:
        ativos = probe_stdlib(vivos)
        motor = 'stdlib'
    print(f'[·] hosts HTTP vivos: {len(ativos)} (motor: {motor})', flush=True)

    (pasta / 'assets.json').write_text(json.dumps(
        {'dominio': dominio, 'motor': motor, 'subdominios': subs, 'dns': dns, 'http': ativos},
        ensure_ascii=False, indent=2), encoding='utf-8')
    urls = sorted({a['url'] for a in ativos if a.get('url') and a.get('status')})
    (pasta / 'urls.txt').write_text('\n'.join(urls) + '\n', encoding='utf-8')
    with (pasta / 'tech.tsv').open('w', encoding='utf-8') as stream:
        stream.write('url\tstatus\tservidor\ttitulo\ttecnologias\tcdn\tjarm\n')
        for a in ativos:
            stream.write('\t'.join(str(a.get(k, '')).replace('\t', ' ') for k in
                                   ('url', 'status', 'webserver', 'title', 'tech', 'cdn', 'jarm')) + '\n')
    print(f'[·] saidas: {pasta}/assets.json, urls.txt, tech.tsv', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())