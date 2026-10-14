"""Verificação segura de releases públicos no GitHub; não executa código remoto."""
import json
import os
from pathlib import Path
import sys
import urllib.request
import webbrowser

def _version_tuple(value):
    try:
        return tuple(int(p) for p in value.lstrip('v').split('.')[:3])
    except (TypeError, ValueError):
        return (0, 0, 0)

def check_updates(base, interactive=False, force=False):
    base = Path(base)
    try:
        config = json.loads((base / 'update_config.json').read_text(encoding='utf-8'))
        repo = config.get('github_repo', '').strip().strip('/')
        if not repo or '/' not in repo:
            if force:
                print('[Atualizações] Configure github_repo em update_config.json (usuario/repositorio).')
            return 0
        current = (base / 'VERSION').read_text().strip()
        url = f'https://api.github.com/repos/{repo}/releases/latest'
        req = urllib.request.Request(url, headers={'Accept':'application/vnd.github+json','User-Agent':'OP-Cybernetica-I-updater'})
        with urllib.request.urlopen(req, timeout=3) as response:
            info = json.load(response)
        latest = info.get('tag_name', '').lstrip('v')
        page = info.get('html_url', '')
        if _version_tuple(latest) <= _version_tuple(current):
            if force: print(f'[Atualizações] Você já está na versão mais recente: {current}')
            return 0
        print(f'\n[Atualizações] OP Cybernetica I {latest} disponível (instalada: {current}).')
        print(f'[Atualizações] Página oficial: {page}')
        if interactive and sys.stdin.isatty():
            answer = input('Abrir página da atualização no navegador? [s/N] ').strip().lower()
            if answer in ('s','sim','y','yes') and page.startswith('https://github.com/'):
                webbrowser.open(page)
    except Exception as exc:
        if force: print(f'[Atualizações] Não foi possível consultar o GitHub: {exc}')
    return 0
