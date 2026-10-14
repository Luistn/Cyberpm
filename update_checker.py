"""Atualização consentida do CyberOps usando releases oficiais do GitHub."""
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = 'Luistn/Pentest-cyberops'

def _version_tuple(value):
    try:
        return tuple(int(x) for x in str(value).lstrip('v').split('.')[:3])
    except (ValueError, TypeError):
        return (0, 0, 0)

def _git(base, *args):
    return subprocess.run(['git', '-C', str(base), *args], capture_output=True, text=True, timeout=90)

def install_release(base, tag):
    """Fail closed on dirty working trees, detached HEAD and divergent histories."""
    if not (base / '.git').exists():
        print('[Atualizações] Instalação sem Git: atualização automática indisponível. Use a instalação manual da Release.')
        return False
    branch = _git(base, 'branch', '--show-current')
    if branch.returncode or branch.stdout.strip() != 'main':
        print('[Atualizações] Atualização automática requer a branch main. Nenhum arquivo foi alterado.')
        return False
    status = _git(base, 'status', '--porcelain', '--untracked-files=no')
    if status.returncode or status.stdout.strip():
        print('[Atualizações] Existem alterações locais. Salve-as antes de atualizar; nada foi alterado.')
        return False
    print(f'[Atualizações] Baixando tag oficial {tag}...')
    fetched = _git(base, 'fetch', '--no-tags', 'origin', f'refs/tags/{tag}:refs/tags/{tag}')
    if fetched.returncode:
        print('[Atualizações] Falha ao obter a tag:', fetched.stderr.strip()[:300]); return False
    # A tagged release must be reachable by fast-forward; never reset user work.
    merged = _git(base, 'merge', '--ff-only', tag)
    if merged.returncode:
        print('[Atualizações] Não foi possível atualizar por fast-forward. Atualize manualmente.')
        print(merged.stderr.strip()[:300]); return False
    installed = subprocess.run(['bash', str(base / 'instalar.sh')], cwd=base)
    if installed.returncode:
        print('[Atualizações] Arquivos baixados, mas o instalador falhou. Verifique o terminal.')
        return False
    print(f'[Atualizações] CyberOps atualizado para {tag}. Abra o programa novamente.')
    return True

def check_updates(base, interactive=False, force=False):
    base = Path(base)
    try:
        cfg = json.loads((base / 'update_config.json').read_text(encoding='utf-8'))
        repo = cfg.get('github_repo', '').strip().strip('/')
        if repo != REPO:
            if force: print('[Atualizações] Repositório não configurado como oficial.')
            return 0
        current = (base / 'VERSION').read_text(encoding='utf-8').strip()
        req = urllib.request.Request(f'https://api.github.com/repos/{repo}/releases/latest',
            headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'CyberOps-updater'})
        with urllib.request.urlopen(req, timeout=3) as response:
            info = json.load(response)
        tag = info.get('tag_name', '')
        if not tag or not tag.startswith('v') or not all(p.isdigit() for p in tag[1:].split('.')):
            if force: print('[Atualizações] Tag da release inválida.')
            return 0
        if _version_tuple(tag) <= _version_tuple(current):
            if force: print(f'[Atualizações] Versão atual: {current}. Nenhuma atualização disponível.')
            return 0
        print(f'\n[Atualizações] CyberOps {tag} disponível (instalada: {current}).')
        if interactive and sys.stdin.isatty():
            answer = input('Deseja baixar e instalar a atualização agora? [s/N] ').strip().lower()
            if answer in ('s', 'sim', 'y', 'yes'):
                if install_release(base, tag):
                    # Stop startup: process has loaded old Python modules.
                    print('[Atualizações] Reinicie o CyberOps para carregar a nova versão.')
                    raise SystemExit(0)
        elif force:
            print('[Atualizações] Execute em um terminal interativo para confirmar a instalação.')
    except SystemExit:
        raise
    except Exception as exc:
        if force: print(f'[Atualizações] Consulta indisponível: {exc}')
    return 0
